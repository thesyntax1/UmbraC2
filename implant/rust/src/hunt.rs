//! The hunt: the indicators of the team, looked for on this host.
//!
//! A wipe takes the traces of the engagement away; a hunt looks for the
//! traces of somebody else.  The team keeps a catalogue of indicators --
//! a hash, a path, a mutex, a registry key, a process -- and asks every
//! host of the fleet whether it carries one of them.
//!
//! The rules of the module are the rules of the engagement:
//!
//!   * **the hunt never changes the host.**  It reads, it reports, and
//!     the operator decides what to do with what it found.  An implant
//!     that removes a file while it hunts is an implant that destroys
//!     evidence.
//!   * **an indicator is matched exactly.**  A "possible match" is a
//!     finding the operator cannot act on.
//!   * **a limit is reported as a limit.**  The hash of a file is
//!     expensive to compute, so the number of files that are hashed is
//!     bounded; when the bound is reached the report says so, because a
//!     hunt that silently looked at half the disk is a hunt that says
//!     "not found" when it means "not looked at".
//!
//! The kinds of indicator the module understands:
//!
//! | kind          | what it is                                    |
//! |---------------|-----------------------------------------------|
//! | `path`        | a path on the disk of the host                 |
//! | `hash`        | the SHA-256 of a file                          |
//! | `process`     | the name of a process                          |
//! | `service`     | the name of a system service                   |
//! | `mutex`       | the name of a mutex (Windows)                  |
//! | `registry`    | a key of the registry (Windows)                |
//! | `certificate` | a thumbprint of the certificate store (Windows)|
//!
//! The last three are Windows concepts.  On the other platforms the
//! report says that the kind does not apply to the machine, instead of
//! pretending that the host was checked.

use crate::upk::{self, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// How many files are hashed in one hunt.
///
/// Hashing a file costs its whole content, so the hunt is bounded: it
/// walks the roots it was given and stops at the bound.
const MAX_HASHED_FILES: u64 = 20_000;

/// How many bytes are hashed in one hunt.
const MAX_HASHED_BYTES: u64 = 256 * 1024 * 1024;

/// How deep the walk goes.
///
/// A directory tree of a machine can be very deep, and a hunt that
/// follows every symlink is a hunt that never ends.
const MAX_DEPTH: usize = 24;

/// How many files are visited in one hunt, counted and hashed alike.
const MAX_VISITED_FILES: u64 = 200_000;

/// One indicator of the catalogue.
#[derive(Clone, Debug)]
pub struct Indicator {
    pub id: String,
    pub kind: String,
    pub value: String,
    pub label: String,
}

/// One finding: an indicator that is on this host.
#[derive(Clone, Debug)]
pub struct Finding {
    pub id: String,
    pub kind: String,
    pub value: String,
    pub label: String,
    /// Where it was found.
    pub place: String,
    /// Why it matters.
    pub note: String,
}

/// The result of one hunt.
pub struct Report {
    pub findings: Vec<Finding>,
    /// The indicators that do not apply to this machine.
    pub skipped: Vec<(String, String)>,
    /// How many files were visited.
    pub visited: u64,
    /// How many files were hashed.
    pub hashed: u64,
    /// How many bytes were hashed.
    pub bytes: u64,
    /// The limits that were reached.
    pub limits: Vec<String>,
    /// The roots the hunt walked.
    pub roots: Vec<String>,
}

/// Read the indicators of a task.
///
/// The server sends the catalogue the operator chose and nothing else.
pub fn indicators(args: &Value) -> Vec<Indicator> {
    let mut out = Vec::new();
    let items = match args.get("indicators") {
        Some(Value::Arr(items)) => items.clone(),
        _ => Vec::new(),
    };
    for item in items {
        let map = match item {
            Value::Map(map) => map,
            _ => continue,
        };
        let get = |key: &str| -> String {
            map.get(key)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        let kind = get("kind").to_lowercase();
        let value = get("value").trim().to_string();
        if value.is_empty() {
            continue;
        }
        out.push(Indicator {
            id: get("id"),
            kind,
            value,
            label: get("label"),
        });
    }
    out
}

/// The roots the hunt walks.
///
/// Without a root the hunt looks in the home of the user, in the
/// temporary directory and in the working directory of the implant.  The
/// whole of the disk is a decision the operator has to make explicitly:
/// it is slow, and it reads the material of the user.
pub fn roots(args: &Value) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    // A closure that owns the vector would hold the mutable borrow until the
    // end of the function, and `out.is_empty()` below needs it back.  A
    // helper takes the borrow for the length of one call instead.
    fn push(out: &mut Vec<PathBuf>, path: PathBuf) {
        if !path.as_os_str().is_empty() && !out.contains(&path) {
            out.push(path);
        }
    }
    let named = args.str_list("roots");
    for root in named {
        let trimmed = root.trim();
        if trimmed.is_empty() {
            continue;
        }
        push(&mut out, PathBuf::from(trimmed));
    }
    if out.is_empty() {
        if let Ok(home) = std::env::var("HOME") {
            push(&mut out, PathBuf::from(home));
        }
        if let Ok(home) = std::env::var("USERPROFILE") {
            push(&mut out, PathBuf::from(home));
        }
        push(&mut out, PathBuf::from(std::env::temp_dir()));
        if let Ok(cwd) = std::env::current_dir() {
            push(&mut out, cwd);
        }
    }
    out
}

/// Look for every indicator of the catalogue on this host.
pub fn scan(args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let items = indicators(args);
    if items.is_empty() {
        return Err("the hunt has no indicators".to_string());
    }
    let roots = roots(args);
    let mut report = Report {
        findings: Vec::new(),
        skipped: Vec::new(),
        visited: 0,
        hashed: 0,
        bytes: 0,
        limits: Vec::new(),
        roots: roots.iter().map(|p| p.display().to_string()).collect(),
    };

    // The paths and the processes are cheap, so they are checked first:
    // an operator waiting for the answer gets the easy findings at once.
    for ind in &items {
        match ind.kind.as_str() {
            "path" => check_path(&mut report, ind),
            "process" => check_process(&mut report, ind),
            "service" => check_service(&mut report, ind),
            "mutex" | "registry" | "certificate" => {
                report.skipped.push((
                    ind.id.clone(),
                    format!("the kind {:?} is a concept of windows", ind.kind),
                ));
            }
            "hash" => {}
            other => {
                report.skipped.push((
                    ind.id.clone(),
                    format!("the kind {other:?} is not one this implant knows"),
                ));
            }
        }
    }

    // The hashes are the expensive ones: every file under the roots is
    // hashed and compared.
    let hashes: Vec<&Indicator> = items.iter().filter(|i| i.kind == "hash").collect();
    if !hashes.is_empty() {
        for root in &roots {
            walk(root, 0, &mut report, &hashes);
        }
    }

    let text = render(&report, &items);
    let mut extra: Vec<(&'static str, Value)> = vec![
        ("hunt_found", upk::u(report.findings.len() as u64)),
        ("hunt_visited", upk::u(report.visited)),
        ("hunt_hashed", upk::u(report.hashed)),
        ("hunt_bytes", upk::u(report.bytes)),
    ];
    if !report.skipped.is_empty() {
        let mut skipped: Vec<Value> = Vec::new();
        for (id, why) in &report.skipped {
            skipped.push(upk::map(vec![
                ("id", upk::s(id)),
                ("why", upk::s(why)),
            ]));
        }
        extra.push(("hunt_skipped", upk::arr(skipped)));
    }
    if !report.limits.is_empty() {
        let mut limits: Vec<Value> = Vec::new();
        for why in &report.limits {
            limits.push(upk::s(why));
        }
        extra.push(("hunt_limits", upk::arr(limits)));
    }
    Ok((text, extra))
}

/// Check a path indicator.
///
/// The path is checked as it is and as a directory: an indicator that
/// names a folder is looking for the folder.
fn check_path(report: &mut Report, ind: &Indicator) {
    let path = Path::new(&ind.value);
    if path.exists() {
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let note = if path.is_dir() {
            "the path is a directory of this host"
        } else {
            "the path is a file of this host"
        };
        report.findings.push(Finding {
            id: ind.id.clone(),
            kind: ind.kind.clone(),
            value: ind.value.clone(),
            label: ind.label.clone(),
            place: path.display().to_string(),
            note: format!("{note}, {size} bytes"),
        });
    }
}

/// Check a process indicator.
///
/// The name is compared without regard to case, and the executable and
/// the command line are read too: an implant is often renamed.
fn check_process(report: &mut Report, ind: &Indicator) {
    let processes = match crate::proc::processes() {
        Ok(list) => list,
        Err(_) => {
            report.limits.push(
                "the process table of this host could not be read".to_string(),
            );
            return;
        }
    };
    let needle = ind.value.to_lowercase();
    for p in processes {
        let name = p.name.to_lowercase();
        let exe = p.exe.to_lowercase();
        if name == needle || exe == needle || exe.ends_with(&format!("/{needle}")) {
            report.findings.push(Finding {
                id: ind.id.clone(),
                kind: ind.kind.clone(),
                value: ind.value.clone(),
                label: ind.label.clone(),
                place: format!("pid {} ({})", p.pid, p.exe),
                note: format!("the process {} is running on this host", p.name),
            });
        }
    }
}

/// Check a service indicator.
///
/// The unit files of systemd are read on Linux; on the other platforms
/// the kind is reported as one that does not apply.
fn check_service(report: &mut Report, ind: &Indicator) {
    #[cfg(target_os = "linux")]
    {
        let name = ind.value.trim();
        let stem = name.strip_suffix(".service").unwrap_or(name);
        let mut found = false;
        for dir in ["/etc/systemd/system", "/lib/systemd/system", "/run/systemd/system"] {
            let candidate = Path::new(dir).join(format!("{stem}.service"));
            if candidate.exists() {
                report.findings.push(Finding {
                    id: ind.id.clone(),
                    kind: ind.kind.clone(),
                    value: ind.value.clone(),
                    label: ind.label.clone(),
                    place: candidate.display().to_string(),
                    note: "the service is installed on this host".to_string(),
                });
                found = true;
                break;
            }
        }
        if !found {
            // A service that is not installed is still a fact the
            // operator wants: it says the host does not carry it.
            report.skipped.push((
                ind.id.clone(),
                "the service is not installed on this host".to_string(),
            ));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        report.skipped.push((
            ind.id.clone(),
            "the kind \"service\" is looked for in the units of systemd, and this host does not have them"
                .to_string(),
        ));
    }
}

/// Walk a tree and hash the files, looking for the hash indicators.
fn walk(
    dir: &Path,
    depth: usize,
    report: &mut Report,
    hashes: &[&Indicator],
) {
    if depth > MAX_DEPTH {
        report
            .limits
            .push(format!("the tree below {} is deeper than {MAX_DEPTH} levels", dir.display()));
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk(&path, depth + 1, report, hashes);
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        report.visited += 1;
        if report.visited > MAX_VISITED_FILES {
            report.limits.push(format!(
                "the hunt stopped after {MAX_VISITED_FILES} files"
            ));
            return;
        }
        if report.hashed >= MAX_HASHED_FILES {
            report
                .limits
                .push(format!("the hunt hashed {MAX_HASHED_FILES} files and stopped"));
            return;
        }
        if report.bytes + meta.len() > MAX_HASHED_BYTES {
            report
                .limits
                .push(format!("the hunt hashed {MAX_HASHED_BYTES} bytes and stopped"));
            return;
        }
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(_) => continue,
        };
        report.hashed += 1;
        report.bytes += data.len() as u64;
        let digest = crate::crypto::sha256(&data);
        let hex = crate::config::hex_encode(&digest);
        for ind in hashes {
            if ind.value.eq_ignore_ascii_case(&hex) {
                report.findings.push(Finding {
                    id: ind.id.clone(),
                    kind: ind.kind.clone(),
                    value: ind.value.clone(),
                    label: ind.label.clone(),
                    place: path.display().to_string(),
                    note: format!("the file carries the hash, {} bytes", data.len()),
                });
            }
        }
    }
}

/// Render the report of the hunt.
///
/// The format is the format of the other reports of the implant: one
/// line per finding, and the limits at the end.
fn render(report: &Report, items: &[Indicator]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "hunt.scan: {} indicators, {} found on this host\n",
        items.len(),
        report.findings.len()
    ));
    for f in &report.findings {
        let label = if f.label.is_empty() {
            String::new()
        } else {
            format!(" ({})", f.label)
        };
        out.push_str(&format!(
            "  {:<10} {:<40} {}{}\n",
            f.kind, f.value, f.place, label
        ));
        if !f.note.is_empty() {
            out.push_str(&format!("             {}\n", f.note));
        }
    }
    for (id, why) in &report.skipped {
        out.push_str(&format!("  skipped    {id:<10} {why}\n"));
    }
    for limit in &report.limits {
        out.push_str(&format!("  limit      {limit}\n"));
    }
    out.push_str(&format!(
        "hunt.scan: {} files visited, {} hashed, {} bytes read\n",
        report.visited, report.hashed, report.bytes
    ));
    out
}
