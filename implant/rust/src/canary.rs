//! The tripwires of the engagement: small files that nobody touches.
//!
//! A canary is a small file with a secret in it.  The implant plants it
//! in a place where nothing of the engagement belongs, and nobody knows
//! that it is there -- so nobody touches it.  When the file changes or
//! disappears, somebody else was on the machine, and the operator
//! learns about it while the engagement is still running.
//!
//! The rules of the module are three:
//!
//!   * **the implant remembers what it planted.**  The size, the time
//!     of the last change and the digest of the file are written next
//!     to the canary, because the implant is the only one that knows
//!     what it wrote.
//!   * **the check never changes the host.**  It reads the file and
//!     says whether it is as it was planted; a check that repairs the
//!     canary would hide the very thing it is looking for.
//!   * **the verdict travels with the answer.**  The states of the
//!     canaries travel in the metadata of the answer as one short
//!     string ("c-0001=intact;c-0002=changed"), so the ledger of the
//!     server and the answer the operator reads cannot disagree.
//!
//! The states are the three a tripwire can be in:
//!
//! | state     | what it means                                  |
//! |-----------|------------------------------------------------|
//! | `intact`  | the file is as it was planted                   |
//! | `changed` | the file was touched                           |
//! | `missing` | the file is gone                               |

use crate::upk::{self, Value};
use std::fs;
use std::path::PathBuf;

/// The state of a canary that is as it was planted.
const STATE_INTACT: &str = "intact";
/// The state of a canary that was touched.
const STATE_CHANGED: &str = "changed";
/// The state of a canary that is gone.
const STATE_MISSING: &str = "missing";

/// The name of the directory where the implant keeps the canaries and
/// the facts of them.
const STATE_DIR: &str = "canaries";

/// The facts of one canary: what the implant wrote and where.
struct Facts {
    id: String,
    path: PathBuf,
    size: u64,
    mtime: u64,
    sha256: String,
}

/// Plant one canary on this host.
///
/// The file carries the token of the canary and nothing else.  The
/// facts of it are written next to it, so the check knows what to
/// compare against.
pub fn plant(args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let id = args.str_or("id", "");
    if id.is_empty() {
        return Err("canary.plant: the canary has no id".to_string());
    }
    let token = args.str_or("token", "");
    if token.is_empty() {
        return Err("canary.plant: the canary has no token".to_string());
    }
    let label = args.str_or("label", "");
    let dir = canary_dir();
    fs::create_dir_all(&dir)
        .map_err(|e| format!("canary.plant: {}: {e}", dir.display()))?;
    // The operator may name the place of the canary; without a name the
    // canary goes into the state of the implant, which is a place where
    // nothing of the engagement belongs.
    let named = args.str_or("path", "");
    let path = if named.trim().is_empty() {
        dir.join(format!("{id}.dat"))
    } else {
        PathBuf::from(named.trim().to_string())
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("canary.plant: {}: {e}", parent.display()))?;
        }
    }
    fs::write(&path, token.as_bytes())
        .map_err(|e| format!("canary.plant: {}: {e}", path.display()))?;
    let meta = fs::metadata(&path)
        .map_err(|e| format!("canary.plant: {}: {e}", path.display()))?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let digest = crate::crypto::sha256(token.as_bytes());
    let hex = crate::config::hex_encode(&digest);
    let facts = Facts {
        id: id.clone(),
        path: path.clone(),
        size: meta.len(),
        mtime,
        sha256: hex,
    };
    write_facts(&facts)?;
    let mut text = String::new();
    text.push_str(&format!("canary.plant: {id} is planted\n"));
    if !label.is_empty() {
        text.push_str(&format!("  the label is {label}\n"));
    }
    text.push_str(&format!("  the file is {}\n", path.display()));
    text.push_str(&format!(
        "  {} bytes, written at {mtime}, digest {}\n",
        facts.size, facts.sha256
    ));
    let extra = vec![
        ("canary_planted", upk::u(1)),
        ("canary_id", upk::s(&id)),
        ("canary_path", upk::s(&path.to_string_lossy())),
    ];
    Ok((text, extra))
}

/// Look at the canaries of this host and say whether they are as they
/// were planted.
///
/// The check reads and reads only.  The verdicts travel in the metadata
/// of the answer, and the server writes them into its ledger.
pub fn check(args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let ids = wanted(args);
    if ids.is_empty() {
        return Err("canary.check: no canary was named".to_string());
    }
    let mut verdicts: Vec<String> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    let mut touched: u64 = 0;
    for id in &ids {
        let (state, note) = look(id);
        if state == STATE_CHANGED || state == STATE_MISSING {
            touched += 1;
        }
        verdicts.push(format!("{id}={state}:{note}"));
        lines.push(format!("  {id:<10} {state:<8} {note}"));
    }
    let states = verdicts.join(";");
    let mut text = String::new();
    text.push_str(&format!(
        "canary.check: {} canaries looked at, {touched} of them are not as they were\n",
        ids.len()
    ));
    for line in &lines {
        text.push_str(line);
        text.push('\n');
    }
    let extra = vec![
        ("canary_states", upk::s(&states)),
        ("canary_checked", upk::u(ids.len() as u64)),
        ("canary_touched", upk::u(touched)),
    ];
    Ok((text, extra))
}

/// The canaries the server asked about.
fn wanted(args: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let items = match args.get("canaries") {
        Some(Value::Arr(items)) => items.clone(),
        _ => Vec::new(),
    };
    for item in items {
        let map = match item {
            Value::Map(map) => map,
            _ => continue,
        };
        let id = map
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if id.is_empty() || out.contains(&id) {
            continue;
        }
        out.push(id);
    }
    out
}

/// Look at one canary and say what state it is in.
fn look(id: &str) -> (&'static str, String) {
    let facts = match read_facts(id) {
        Some(facts) => facts,
        None => {
            return (
                STATE_MISSING,
                "the implant does not know this canary".to_string(),
            )
        }
    };
    let meta = match fs::metadata(&facts.path) {
        Ok(meta) => meta,
        Err(_) => {
            return (
                STATE_MISSING,
                "the file of the canary is gone".to_string(),
            )
        }
    };
    if meta.len() != facts.size {
        return (
            STATE_CHANGED,
            format!("the file of the canary is {} bytes now", meta.len()),
        );
    }
    let data = match fs::read(&facts.path) {
        Ok(data) => data,
        Err(_) => {
            return (
                STATE_MISSING,
                "the file of the canary could not be read".to_string(),
            )
        }
    };
    let digest = crate::crypto::sha256(&data);
    let hex = crate::config::hex_encode(&digest);
    if hex != facts.sha256 {
        return (
            STATE_CHANGED,
            "the file of the canary was touched".to_string(),
        );
    }
    // The content is the same.  The time of the last change is not part
    // of the verdict, but it is worth saying: a file that was written
    // again with the same content was written again.
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if mtime != facts.mtime {
        return (
            STATE_INTACT,
            format!("the file is as it was planted but it was written again at {mtime}"),
        );
    }
    (STATE_INTACT, "the file is as it was planted".to_string())
}

/// The directory where the canaries and their facts are kept.
fn canary_dir() -> PathBuf {
    home().join(".umbra").join(STATE_DIR)
}

/// The home of the user the implant runs as.
fn home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// The file where the facts of one canary are kept.
fn facts_path(id: &str) -> PathBuf {
    canary_dir().join(format!("{id}.state"))
}

/// Write the facts of one canary.
fn write_facts(facts: &Facts) -> Result<(), String> {
    let mut text = String::new();
    text.push_str(&format!("id={}\n", facts.id));
    text.push_str(&format!("path={}\n", facts.path.display()));
    text.push_str(&format!("size={}\n", facts.size));
    text.push_str(&format!("mtime={}\n", facts.mtime));
    text.push_str(&format!("sha256={}\n", facts.sha256));
    let path = facts_path(&facts.id);
    fs::write(&path, text).map_err(|e| format!("canary: write {}: {e}", path.display()))
}

/// Read the facts of one canary.
fn read_facts(id: &str) -> Option<Facts> {
    let path = facts_path(id);
    let raw = fs::read_to_string(path).ok()?;
    let mut facts = Facts {
        id: id.to_string(),
        path: PathBuf::new(),
        size: 0,
        mtime: 0,
        sha256: String::new(),
    };
    for line in raw.lines() {
        let (key, value) = match line.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        match key.trim() {
            "id" => facts.id = value.trim().to_string(),
            "path" => facts.path = PathBuf::from(value.trim().to_string()),
            "size" => facts.size = value.trim().parse::<u64>().unwrap_or(0),
            "mtime" => facts.mtime = value.trim().parse::<u64>().unwrap_or(0),
            "sha256" => facts.sha256 = value.trim().to_string(),
            _ => {}
        }
    }
    if facts.path.as_os_str().is_empty() {
        return None;
    }
    Some(facts)
}
