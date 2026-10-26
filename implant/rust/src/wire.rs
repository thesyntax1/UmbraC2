//! Frame format of umbra/v1 (see server/internal/wire/wire.go).
//!
//!   prelude (12B, cleartext, AEAD AAD) | nonce (12B) | ciphertext | tag (16B)
//!   prelude: magic(2) version(1) flags(1) type(1) suite(1) reserved(2) len(4)

use std::io::{self, Read};

pub const VERSION: u8 = 1;
pub const PRELUDE_LEN: usize = 12;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = PRELUDE_LEN + NONCE_LEN;
pub const MAX_BODY: usize = 1 << 20;
pub const MAX_FRAME: usize = HEADER_LEN + MAX_BODY + TAG_LEN;

pub const MAGIC: [u8; 2] = [0x55, 0x43];

pub const SUITE_AES256_GCM: u8 = 1;
pub const SUITE_CHACHA20_POLY1305: u8 = 2;

pub const FLAG_BOOTSTRAP: u8 = 0x01;

// message types (stable wire constants)
pub const MSG_HELLO: u8 = 0x01;
pub const MSG_HELLO_ACK: u8 = 0x02;
pub const MSG_CHECKIN: u8 = 0x10;
pub const MSG_TASK_BATCH: u8 = 0x11;
pub const MSG_RESULT: u8 = 0x12;
pub const MSG_CONFIG: u8 = 0x13;
pub const MSG_PING: u8 = 0x14;
pub const MSG_PONG: u8 = 0x15;
pub const MSG_REKEY: u8 = 0x16;
pub const MSG_KILL: u8 = 0x17;
pub const MSG_TASK_CANCEL: u8 = 0x18;
pub const MSG_BYE: u8 = 0x19;
pub const MSG_ERROR: u8 = 0x1F;

pub const MARKER_HELLO: u8 = 0x01;
pub const MARKER_HELLO_ACK: u8 = 0x02;

#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    BadMagic,
    BadVersion(u8),
    ReservedSet,
    UnknownSuite(u8),
    TooLarge(usize),
    Truncated,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::BadMagic => write!(f, "bad magic"),
            WireError::BadVersion(v) => write!(f, "unsupported version {v}"),
            WireError::ReservedSet => write!(f, "reserved prelude bytes set"),
            WireError::UnknownSuite(s) => write!(f, "unknown suite {s}"),
            WireError::TooLarge(n) => write!(f, "frame too large ({n})"),
            WireError::Truncated => write!(f, "truncated frame"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<WireError> for io::Error {
    fn from(e: WireError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e.to_string())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub version: u8,
    pub flags: u8,
    pub msg_type: u8,
    pub suite: u8,
    pub length: u32,
}

pub fn make_nonce(prefix: &[u8; 4], counter: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[0..4].copy_from_slice(prefix);
    n[4..12].copy_from_slice(&counter.to_be_bytes());
    n
}

pub fn build_header(flags: u8, msg_type: u8, suite: u8, plaintext_len: usize) -> [u8; PRELUDE_LEN] {
    let mut p = [0u8; PRELUDE_LEN];
    p[0] = MAGIC[0];
    p[1] = MAGIC[1];
    p[2] = VERSION;
    p[3] = flags;
    p[4] = msg_type;
    p[5] = suite;
    p[8..12].copy_from_slice(&(plaintext_len as u32).to_be_bytes());
    p
}

pub fn parse_prelude(p: &[u8]) -> Result<Header, WireError> {
    if p.len() < PRELUDE_LEN {
        return Err(WireError::Truncated);
    }
    if p[0] != MAGIC[0] || p[1] != MAGIC[1] {
        return Err(WireError::BadMagic);
    }
    if p[2] != VERSION {
        return Err(WireError::BadVersion(p[2]));
    }
    if p[6] != 0 || p[7] != 0 {
        return Err(WireError::ReservedSet);
    }
    if p[5] != SUITE_AES256_GCM && p[5] != SUITE_CHACHA20_POLY1305 {
        return Err(WireError::UnknownSuite(p[5]));
    }
    let length = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
    if length as usize > MAX_BODY {
        return Err(WireError::TooLarge(length as usize));
    }
    Ok(Header {
        version: p[2],
        flags: p[3],
        msg_type: p[4],
        suite: p[5],
        length,
    })
}

/// Total wire size of a frame carrying `body_len` plaintext bytes.
pub fn frame_len(body_len: usize) -> usize {
    HEADER_LEN + body_len + TAG_LEN
}

/// Read exactly one complete frame (header + ciphertext + tag).
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut prelude = [0u8; PRELUDE_LEN];
    r.read_exact(&mut prelude)?;
    let h = parse_prelude(&prelude)?;
    let mut rest = vec![0u8; NONCE_LEN + h.length as usize + TAG_LEN];
    r.read_exact(&mut rest)?;
    let mut out = Vec::with_capacity(PRELUDE_LEN + rest.len());
    out.extend_from_slice(&prelude);
    out.extend_from_slice(&rest);
    Ok(out)
}

/// Parse all frames contained in a buffer (used by the HTTP transport).
pub fn split_frames(buf: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        if pos + PRELUDE_LEN > buf.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated prelude"));
        }
        let h = parse_prelude(&buf[pos..pos + PRELUDE_LEN])?;
        let total = frame_len(h.length as usize);
        if pos + total > buf.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated frame"));
        }
        out.push(buf[pos..pos + total].to_vec());
        pos += total;
    }
    Ok(out)
}

pub fn type_name(t: u8) -> &'static str {
    match t {
        MSG_HELLO => "HELLO",
        MSG_HELLO_ACK => "HELLO_ACK",
        MSG_CHECKIN => "CHECKIN",
        MSG_TASK_BATCH => "TASK_BATCH",
        MSG_RESULT => "RESULT",
        MSG_CONFIG => "CONFIG",
        MSG_PING => "PING",
        MSG_PONG => "PONG",
        MSG_REKEY => "REKEY",
        MSG_KILL => "KILL",
        MSG_BYE => "BYE",
        MSG_ERROR => "ERROR",
        _ => "UNKNOWN",
    }
}
