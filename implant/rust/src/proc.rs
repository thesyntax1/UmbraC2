//! The process table of the host.
//!
//! The `ps` task used to shell out to the platform's own tool.  That is
//! portable, but the shell hides the things an operator actually asks
//! about: the parent of a process, the exact command line and the moment
//! the process started.  This module reads the table the operating system
//! keeps, so the answer is the system's own.
//!
//! The Windows half is plain Win32 through the FFI: the toolhelp snapshot
//! walks the processes, and terminating one is `OpenProcess` plus
//! `TerminateProcess`.  No crate is needed for any of it.

use std::fs;

use crate::upk::Value;

/// One process of the host.
pub struct Process {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: String,
    pub cmd: String,
    pub user: String,
    /// When the process started, as a Unix timestamp (0 when unknown).
    pub started: i64,
}

/// The process table of the host, as a table the operator can read.
pub fn list() -> Result<String, String> {
    let processes = collect()?;
    let mut out = String::new();
    out.push_str(&format!(
        "{:<8} {:<8} {:<12} {:<20} {}\n",
        "PID", "PPID", "USER", "STARTED", "COMMAND"
    ));
    for p in processes {
        let started = if p.started > 0 {
            format_ts(p.started)
        } else {
            "-".to_string()
        };
        let cmd = if p.cmd.is_empty() { p.name.clone() } else { p.cmd.clone() };
        out.push_str(&format!(
            "{:<8} {:<8} {:<12} {:<20} {}\n",
            p.pid, p.ppid, p.user, started, cmd
        ));
    }
    Ok(out)
}

/// Every process of the host.
///
/// The callers that need the raw table use this: the posture engine looks
/// for the analyst's tools in it, and the process hygiene reads the parent
/// of the beacon out of it.  `list` is the same table, formatted for the
/// operator.
pub fn processes() -> Result<Vec<Process>, String> {
    collect()
}

/// Find the processes whose name or command line matches a pattern.
///
/// The pattern is matched case-insensitively as a substring, which is what
/// an operator typing "whoami" expects.
pub fn find(pattern: &str) -> Result<Vec<Process>, String> {
    let needle = pattern.to_lowercase();
    Ok(collect()?
        .into_iter()
        .filter(|p| {
            p.name.to_lowercase().contains(&needle)
                || p.cmd.to_lowercase().contains(&needle)
                || p.exe.to_lowercase().contains(&needle)
        })
        .collect())
}

/// Kill a process by its pid, or every process whose name matches.
///
/// The pid wins over the name: an operator who gives a pid means that one
/// process.
pub fn kill(args: &Value) -> Result<String, String> {
    let pid = args.u64_or("pid", 0) as u32;
    let name = args.str_or("name", "");
    if pid <= 0 && name.is_empty() {
        return Err("proc.kill needs a pid or a name".to_string());
    }
    let mut killed: Vec<String> = Vec::new();
    if pid > 0 {
        if !terminate(pid)? {
            return Err(format!("the process {pid} could not be terminated"));
        }
        killed.push(pid.to_string());
    } else {
        for p in find(name)? {
            if terminate(p.pid)? {
                killed.push(format!("{} ({})", p.pid, p.name));
            }
        }
        if killed.is_empty() {
            return Err(format!("no process matches {name:?}"));
        }
    }
    Ok(format!("terminated: {}\n", killed.join(", ")))
}

/// Format a Unix timestamp as a readable time.
pub fn format_ts(ts: i64) -> String {
    let days = ts.div_euclid(86400);
    let secs = ts.rem_euclid(86400);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

/// The civil date of a day number since the epoch.
///
/// The arithmetic is the one the C library uses (Howard Hinnant's
/// `civil_from_days`), so the answer is the same everywhere and no crate
/// is needed for it.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// -----------------------------------------------------------------------
// the platform halves
// -----------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn collect() -> Result<Vec<Process>, String> {
    let boot = boot_time();
    let mut out: Vec<Process> = Vec::new();
    let entries = fs::read_dir("/proc").map_err(|e| format!("the process table: {e}"))?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // The name of the executable is in parentheses and may hold spaces,
        // so the fields after it are counted from the closing parenthesis.
        let open = match stat.find('(') {
            Some(i) => i,
            None => continue,
        };
        let close = match stat.rfind(')') {
            Some(i) if i > open => i,
            _ => continue,
        };
        // The name may hold a character that is not one byte, so the slice
        // is taken safely: a process with an exotic name must not take the
        // beacon down with it.
        let comm = match stat.get(open + 1..close) {
            Some(name) => name.to_string(),
            None => continue,
        };
        let rest: Vec<&str> = stat[close + 1..].split_whitespace().collect();
        let ppid = rest.first().and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
        let ticks = rest.get(19).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let cmd = String::from_utf8_lossy(&cmdline)
            .replace('\0', " ")
            .trim()
            .to_string();
        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let user = fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|text| {
                text.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .map(|v| format!("uid:{}", v))
            })
            .unwrap_or_else(|| "-".to_string());
        out.push(Process {
            pid,
            ppid,
            name: comm,
            exe,
            cmd,
            user,
            // The start time is counted in clock ticks since the boot.
            started: if ticks > 0 {
                boot + (ticks as i64) / 100
            } else {
                0
            },
        });
    }
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

/// When the machine booted, as a Unix timestamp.
#[cfg(target_os = "linux")]
fn boot_time() -> i64 {
    let uptime = fs::read_to_string("/proc/uptime").unwrap_or_default();
    let seconds: f64 = uptime
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    now - seconds as i64
}

#[cfg(target_os = "linux")]
fn terminate(pid: u32) -> Result<bool, String> {
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("kill -9 {pid} 2>/dev/null"))
        .status()
        .map_err(|e| format!("the kill: {e}"))?;
    Ok(status.success())
}

#[cfg(windows)]
mod sys {
    use std::os::raw::c_void;

    pub type HANDLE = *mut c_void;
    pub type BOOL = i32;
    pub type DWORD = u32;
    pub type UINT = u32;
    pub type WORD = u16;
    pub type LONG = i32;
    pub type SIZE_T = usize;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct PROCESSENTRY32W {
        pub dwSize: DWORD,
        pub cntUsage: DWORD,
        pub th32ProcessID: DWORD,
        pub th32DefaultHeapID: usize,
        pub th32ModuleID: DWORD,
        pub cntThreads: DWORD,
        pub th32ParentProcessID: DWORD,
        pub pcPriClassBase: LONG,
        pub dwFlags: DWORD,
        pub szExeFile: [u16; 260],
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn CreateToolhelp32Snapshot(flags: DWORD, pid: DWORD) -> HANDLE;
        pub fn Process32FirstW(snapshot: HANDLE, entry: *mut PROCESSENTRY32W) -> BOOL;
        pub fn Process32NextW(snapshot: HANDLE, entry: *mut PROCESSENTRY32W) -> BOOL;
        pub fn CloseHandle(handle: HANDLE) -> BOOL;
        pub fn OpenProcess(access: DWORD, inherit: BOOL, pid: DWORD) -> HANDLE;
        pub fn TerminateProcess(handle: HANDLE, code: UINT) -> BOOL;
    }

    pub const TH32CS_SNAPPROCESS: DWORD = 0x0000_0002;
    pub const PROCESS_TERMINATE: DWORD = 0x0000_0001;
    pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
}

#[cfg(windows)]
fn collect() -> Result<Vec<Process>, String> {
    let mut out: Vec<Process> = Vec::new();
    unsafe {
        let snapshot = sys::CreateToolhelp32Snapshot(sys::TH32CS_SNAPPROCESS, 0);
        if snapshot == sys::INVALID_HANDLE_VALUE {
            return Err("the process table could not be opened".to_string());
        }
        let mut entry = sys::PROCESSENTRY32W {
            dwSize: std::mem::size_of::<sys::PROCESSENTRY32W>() as u32,
            cntUsage: 0,
            th32ProcessID: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            cntThreads: 0,
            th32ParentProcessID: 0,
            pcPriClassBase: 0,
            dwFlags: 0,
            szExeFile: [0; 260],
        };
        if sys::Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let mut name: Vec<u16> = entry.szExeFile.to_vec();
                while name.last() == Some(&0) {
                    name.pop();
                }
                out.push(Process {
                    pid: entry.th32ProcessID,
                    ppid: entry.th32ParentProcessID,
                    name: String::from_utf16_lossy(&name),
                    exe: String::from_utf16_lossy(&name),
                    cmd: String::new(),
                    user: "-".to_string(),
                    started: 0,
                });
                if sys::Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        sys::CloseHandle(snapshot);
    }
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

#[cfg(windows)]
fn terminate(pid: u32) -> Result<bool, String> {
    unsafe {
        let handle = sys::OpenProcess(sys::PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return Ok(false);
        }
        let done = sys::TerminateProcess(handle, 1) != 0;
        sys::CloseHandle(handle);
        Ok(done)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn collect() -> Result<Vec<Process>, String> {
    // The other platforms get the shell's own answer.
    let out = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("ps -eo pid,ppid,user,comm")
        .output()
        .map_err(|e| format!("the process table: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index == 0 {
            continue;
        }
        let mut parts = line.split_whitespace();
        let pid = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let ppid = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let user = parts.next().unwrap_or("-").to_string();
        let name: Vec<&str> = parts.collect();
        rows.push(Process {
            pid,
            ppid,
            name: name.join(" "),
            exe: String::new(),
            cmd: String::new(),
            user,
            started: 0,
        });
    }
    Ok(rows)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn terminate(pid: u32) -> Result<bool, String> {
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("kill -9 {pid} 2>/dev/null"))
        .status()
        .map_err(|e| format!("the kill: {e}"))?;
    Ok(status.success())
}
