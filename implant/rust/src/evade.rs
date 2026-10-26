//! Environment awareness: is this an analyst's machine?
//!
//! Two questions the implant can answer without a task, and both of them are
//! asked by every sandbox and every debugging session in the world:
//!
//!   * is a debugger attached to this process right now?
//!   * does this machine look like an analysis sandbox?
//!
//! Neither answer is a verdict.  A developer debugging the implant, a
//! virtual machine used for malware staging and a real target can all look
//! suspicious.  The implant therefore *reports* what it sees and leaves the
//! judgement to the operator: the findings end up in the `sysinfo` report and
//! in the `recon` output, where they are one line of context next to the
//! rest of the reconnaissance.
//!
//! Nothing here changes the behaviour of the beacon.  The checks are cheap,
//! read-only and never touch the network.

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
            out.push(format!("the sandbox module {dll} is loaded"));
        }
    }
    out
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
}
