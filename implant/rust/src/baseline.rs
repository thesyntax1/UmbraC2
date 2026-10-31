//! The baseline of a host: the paths the team watches and what the
//! last look saw of them.
//!
//! A hunt looks for the indicators of somebody else.  A baseline asks
//! a different question: is this host the host we saw yesterday?  The
//! team names the paths that matter -- the configuration of the
//! service, the script that starts it, the key that opens it -- and
//! the implant reads each of them and reports the size, the time of
//! the last change and the digest.
//!
//! The rules are the same as everywhere else:
//!
//!   * **the baseline only reads.**  A baseline that rewrote the file
//!     it watches would destroy the very thing it is watching;
//!   * **what is not there is a finding.**  A path that is gone is
//!     reported as gone, because "no file" is what the team wanted to
//!     be told;
//!   * **the findings travel with the answer.**  The snapshots travel
//!     in the metadata of the answer as one short JSON string, so the
//!     ledger of the server and the answer the operator reads cannot
//!     disagree.
//!
//! The look is signed like every other report of the engagement: a
//! look that goes into the evidence file has to be provable.

use crate::upk::{self, Value};
use std::fs;
use std::path::PathBuf;

/// Look at the paths the server named and say what is there.
pub fn look(args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let paths = wanted(args);
    if paths.is_empty() {
        return Err("baseline.look: no path was named".to_string());
    }
    let mut snaps: Vec<Snapshot> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    let mut gone: u64 = 0;
    for path in &paths {
        let snap = snap(path);
        let note = if snap.exists {
            format!("{} bytes, digest {}", snap.size, snap.sha256)
        } else {
            gone += 1;
            "the file is gone".to_string()
        };
        lines.push(format!("  {path:<48} {}", if snap.exists { "present" } else { "missing" }));
        lines.push(format!("    {note}"));
        snaps.push(snap);
    }
    let mut text = String::new();
    text.push_str(&format!(
        "baseline.look: {} paths looked at, {} of them are gone\n",
        paths.len(),
        gone
    ));
    for line in &lines {
        text.push_str(line);
        text.push('\n');
    }
    let raw = serde_json::to_string(&snaps).unwrap_or_else(|_| "[]".to_string());
    let extra = vec![
        ("baseline_snaps", upk::s(&raw)),
        ("baseline_looked", upk::u(snaps.len() as u64)),
        ("baseline_missing", upk::u(gone)),
    ];
    Ok((text, extra))
}

/// One look at one path.
///
/// The digest is the SHA-256 of the content, the time is the time of
/// the last change in seconds, and the file is either there or it is
/// not: a path that was never looked at is a path the ledger learns
/// about with the first look.
#[derive(Debug)]
pub struct Snapshot {
    pub path: String,
    pub size: u64,
    pub mtime: u64,
    pub sha256: String,
    pub exists: bool,
}

/// The paths the server asked about.
fn wanted(args: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match args.get("paths") {
        Some(Value::Arr(items)) => {
            for item in items {
                if let Some(path) = item.as_str() {
                    let path = path.trim();
                    if !path.is_empty() && !out.contains(&path.to_string()) {
                        out.push(path.to_string());
                    }
                }
            }
        }
        Some(Value::Str(paths)) => {
            // A single string of paths, one per line: a console that
            // does not carry a list can still name the paths.
            for line in paths.lines() {
                let path = line.trim();
                if !path.is_empty() && !out.contains(&path.to_string()) {
                    out.push(path.to_string());
                }
            }
        }
        _ => {}
    }
    out
}

/// One look at one path, from the disk of the implant.
fn snap(path: &str) -> Snapshot {
    let full = PathBuf::from(path);
    let meta = match fs::metadata(&full) {
        Ok(meta) => meta,
        Err(_) => {
            return Snapshot {
                path: path.to_string(),
                size: 0,
                mtime: 0,
                sha256: String::new(),
                exists: false,
            }
        }
    };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let data = fs::read(&full).unwrap_or_default();
    let digest = crate::crypto::sha256(&data);
    Snapshot {
        path: path.to_string(),
        size: meta.len(),
        mtime,
        sha256: crate::config::hex_encode(&digest),
        exists: true,
    }
}

// The serializer of the snapshots is hand-written: the crate of the
// protocol has no dependency on serde, and the snapshots are a list of
// small objects with fields that are always the same.
mod serde_json {
    use super::Snapshot;

    pub fn to_string(snaps: &[Snapshot]) -> Result<String, ()> {
        let mut out = String::from("[");
        for (i, snap) in snaps.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"path\":{},\"size\":{},\"mtime\":{},\"sha256\":{},\"exists\":{}}}",
                escape(&snap.path),
                snap.size,
                snap.mtime,
                escape(&snap.sha256),
                snap.exists,
            ));
        }
        out.push(']');
        Ok(out)
    }

    fn escape(text: &str) -> String {
        let mut out = String::with_capacity(text.len() + 2);
        out.push('"');
        for ch in text.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }
}
