//! File triage and search.
//!
//! Triage is what an operator asks about a file they found: how big is it,
//! what does it hash to, does it look like a program, is it packed?  The
//! answers come from the file itself, so they work on a machine where the
//! operator has no shell yet.
//!
//! The search walks a tree and reports the files that match, by name or by
//! content.  Both are bounded: a walk that never ends on a mounted share is
//! worse than no walk at all.

use std::fs;
use std::path::Path;

/// How much of a file is read for the statistics.
const SAMPLE: usize = 1024 * 1024;

/// The largest file that is hashed in one go.
const MAX_TRIAGE: u64 = 64 * 1024 * 1024;

/// How deep the search walks.
const MAX_DEPTH: usize = 32;

/// The report of one file.
pub struct Report {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub entropy: f64,
    pub magic: String,
    pub strings: usize,
    pub modified: String,
    pub notes: Vec<String>,
}

/// Triage one file.
///
/// The report is plain text: the operator reads it in the console, and the
/// fields are stable enough to grep.
pub fn triage(path: &str) -> Result<String, String> {
    let meta = fs::metadata(path).map_err(|e| format!("triage {path}: {e}"))?;
    if meta.is_dir() {
        return Err(format!("triage {path}: it is a directory"));
    }
    if meta.len() > MAX_TRIAGE {
        return Err(format!("triage {path}: the file is too large to hash"));
    }
    let data = fs::read(path).map_err(|e| format!("triage {path}: {e}"))?;
    let sample = &data[..data.len().min(SAMPLE)];
    let digest = crate::crypto::sha256(&data);
    let magic = magic_of(sample);
    let entropy = shannon(sample);
    let strings = count_strings(sample);
    let modified = match meta.modified() {
        Ok(t) => match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => format!("{}s", d.as_secs()),
            Err(_) => "unknown".to_string(),
        },
        Err(_) => "unknown".to_string(),
    };

    let mut notes: Vec<String> = Vec::new();
    if entropy > 7.2 {
        notes.push("high entropy: packed or encrypted".to_string());
    }
    if magic == "PE" {
        notes.push("windows executable".to_string());
    }
    if magic == "ELF" {
        notes.push("linux executable".to_string());
    }
    if magic == "ZIP" {
        notes.push("archive".to_string());
    }
    if strings < 5 && data.len() > 4096 {
        notes.push("almost no readable strings".to_string());
    }

    let mut out = String::new();
    out.push_str(&format!("path: {path}\n"));
    out.push_str(&format!("size: {}\n", meta.len()));
    out.push_str(&format!("sha256: {}\n", crate::config::hex_encode(&digest)));
    out.push_str(&format!("magic: {magic}\n"));
    out.push_str(&format!("entropy: {entropy:.2}\n"));
    out.push_str(&format!("strings: {strings}\n"));
    out.push_str(&format!("modified: {modified}\n"));
    for note in &notes {
        out.push_str(&format!("note: {note}\n"));
    }
    Ok(out)
}

/// A file the search found.
pub struct Hit {
    pub path: String,
    pub size: u64,
    pub content_hit: bool,
}

/// Search for files under a root.
///
/// `name` is a case-insensitive name filter: a pattern with a `*` or a `?`
/// is a glob, everything else is a substring.  `content` is a needle that is
/// searched in the first bytes of the file (text files only).
pub fn find(root: &str, name: &str, content: &str, max: usize) -> Result<String, String> {
    let start = Path::new(root);
    if !start.exists() {
        return Err(format!("find {root}: no such path"));
    }
    let limit = if max == 0 { 500 } else { max };
    let mut hits: Vec<Hit> = Vec::new();
    let mut scanned: u64 = 0;
    let mut dirs: Vec<(std::path::PathBuf, usize)> = vec![(start.to_path_buf(), 0)];
    while let Some((dir, depth)) = dirs.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();
            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                // A symlink can point anywhere, including back into the tree.
                continue;
            }
            if meta.is_dir() {
                dirs.push((path, depth + 1));
                continue;
            }
            scanned += 1;
            if name.is_empty() && content.is_empty() {
                hits.push(Hit { path: path.to_string_lossy().to_string(), size: meta.len(), content_hit: false });
            } else {
                let name_hit = name.is_empty() || name_matches(name, &file_name);
                let content_hit = if content.is_empty() {
                    false
                } else {
                    contains_bytes(&path, content.as_bytes())
                };
                if name_hit || content_hit {
                    hits.push(Hit {
                        path: path.to_string_lossy().to_string(),
                        size: meta.len(),
                        content_hit,
                    });
                }
            }
            if hits.len() >= limit {
                let mut out = String::new();
                out.push_str(&format!("scanned {scanned} files, {} hits\n", hits.len()));
                for hit in &hits {
                    out.push_str(&format!("{}\t{}\t{}\n", hit.size, hit.path,
                        if hit.content_hit { "content" } else { "name" }));
                }
                return Ok(out);
            }
        }
    }
    let mut out = String::new();
    out.push_str(&format!("scanned {scanned} files, {} hits\n", hits.len()));
    for hit in &hits {
        out.push_str(&format!("{}\t{}\t{}\n", hit.size, hit.path,
            if hit.content_hit { "content" } else { "name" }));
    }
    Ok(out)
}

/// The name filter: a glob when it contains a wildcard, a substring
/// otherwise.
fn name_matches(pattern: &str, name: &str) -> bool {
    if pattern.contains('*') || pattern.contains('?') {
        glob_match(pattern, name)
    } else {
        name.to_lowercase().contains(&pattern.to_lowercase())
    }
}

/// A small glob matcher: `*` matches anything, `?` matches one character.
fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    let mut table = vec![vec![false; n.len() + 1]; p.len() + 1];
    table[0][0] = true;
    for i in 1..=p.len() {
        if p[i - 1] == '*' {
            table[i][0] = table[i - 1][0];
        }
    }
    for i in 1..=p.len() {
        for j in 1..=n.len() {
            table[i][j] = if p[i - 1] == '*' {
                table[i - 1][j] || table[i][j - 1]
            } else if p[i - 1] == '?' || p[i - 1] == n[j - 1] {
                table[i - 1][j - 1]
            } else {
                false
            };
        }
    }
    table[p.len()][n.len()]
}

/// Whether the first bytes of a file contain the needle.
fn contains_bytes(path: &Path, needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let head = &data[..data.len().min(256 * 1024)];
    head.windows(needle.len()).any(|window| window == needle)
}

/// The Shannon entropy of a byte sample, in bits per byte.
fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for count in counts.iter() {
        if *count == 0 {
            continue;
        }
        let p = *count as f64 / total;
        entropy -= p * p.log2();
    }
    entropy
}

/// The number of printable ASCII runs of at least four characters.
fn count_strings(data: &[u8]) -> usize {
    let mut count = 0;
    let mut run = 0;
    for byte in data {
        if *byte >= 0x20 && *byte < 0x7f {
            run += 1;
            if run == 4 {
                count += 1;
            }
        } else {
            run = 0;
        }
    }
    count
}

/// The file format the magic bytes announce.
fn magic_of(data: &[u8]) -> String {
    if data.starts_with(b"MZ") {
        return "PE".to_string();
    }
    if data.starts_with(b"\x7fELF") {
        return "ELF".to_string();
    }
    if data.starts_with(b"PK\x03\x04") {
        return "ZIP".to_string();
    }
    if data.starts_with(b"%PDF") {
        return "PDF".to_string();
    }
    if data.starts_with(b"\x1f\x8b") {
        return "GZIP".to_string();
    }
    if data.starts_with(b"\xd0\xcf\x11\xe0") {
        return "OLE".to_string();
    }
    if data.len() >= 4 && &data[0..2] == b"#!" {
        return "SCRIPT".to_string();
    }
    "unknown".to_string()
}
