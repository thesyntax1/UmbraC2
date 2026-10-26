//! Encrypted session state machine (mirror of server/internal/session).

use crate::crypto::{self, CryptoError, KeyMaterial};
use crate::upk::{self, Value};
use crate::wire;

pub const REKEY_AFTER: u64 = 1 << 20;

#[derive(Debug)]
pub enum SessionError {
    Crypto(CryptoError),
    Wire(wire::WireError),
    Upk(upk::Error),
    Replay,
    Flags,
    Suite,
    Size,
    NoPrk,
    Length,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Crypto(e) => write!(f, "crypto: {e}"),
            SessionError::Wire(e) => write!(f, "wire: {e}"),
            SessionError::Upk(e) => write!(f, "upk: {e}"),
            SessionError::Replay => write!(f, "nonce mismatch (replay, reorder or desync)"),
            SessionError::Flags => write!(f, "unexpected frame flags"),
            SessionError::Suite => write!(f, "unexpected aead suite"),
            SessionError::Size => write!(f, "frame size mismatch"),
            SessionError::NoPrk => write!(f, "session has no PRK"),
            SessionError::Length => write!(f, "length mismatch after decryption"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<CryptoError> for SessionError {
    fn from(e: CryptoError) -> Self {
        SessionError::Crypto(e)
    }
}

impl From<wire::WireError> for SessionError {
    fn from(e: wire::WireError) -> Self {
        SessionError::Wire(e)
    }
}

impl From<upk::Error> for SessionError {
    fn from(e: upk::Error) -> Self {
        SessionError::Upk(e)
    }
}

struct Direction {
    key: [u8; 32],
    prefix: [u8; 4],
    counter: u64,
    frames: u64,
}

impl Direction {
    fn nonce(&self) -> [u8; wire::NONCE_LEN] {
        wire::make_nonce(&self.prefix, self.counter)
    }
    fn advance(&mut self) {
        self.counter += 1;
        self.frames += 1;
    }
    fn rotate(&mut self, key: [u8; 32], prefix: [u8; 4]) {
        self.key = key;
        self.prefix = prefix;
        self.counter = 0;
        self.frames = 0;
    }
}

pub struct Session {
    pub suite: u8,
    pub is_server: bool,
    pub bootstrap: bool,
    flags: u8,
    prk: Option<[u8; 32]>,
    send: Direction,
    recv: Direction,
}

impl Session {
    pub fn new(
        suite: u8,
        km: KeyMaterial,
        is_server: bool,
        bootstrap: bool,
        prk: Option<[u8; 32]>,
    ) -> Result<Self, CryptoError> {
        let (c2s_prefix, s2c_prefix) = if bootstrap {
            (
                crypto::bootstrap_nonce_prefix(&km.c2s_key)?,
                crypto::bootstrap_nonce_prefix(&km.s2c_key)?,
            )
        } else {
            (km.c2s_prefix, km.s2c_prefix)
        };
        let (send, recv) = if is_server {
            (
                Direction { key: km.s2c_key, prefix: s2c_prefix, counter: 0, frames: 0 },
                Direction { key: km.c2s_key, prefix: c2s_prefix, counter: 0, frames: 0 },
            )
        } else {
            (
                Direction { key: km.c2s_key, prefix: c2s_prefix, counter: 0, frames: 0 },
                Direction { key: km.s2c_key, prefix: s2c_prefix, counter: 0, frames: 0 },
            )
        };
        Ok(Session {
            suite,
            is_server,
            bootstrap,
            flags: if bootstrap { wire::FLAG_BOOTSTRAP } else { 0 },
            prk,
            send,
            recv,
        })
    }

    /// Build the PSK-phase session used for HELLO / HELLO_ACK.
    pub fn from_bootstrap(psk: &[u8], suite: u8, is_server: bool) -> Result<Self, CryptoError> {
        let km = KeyMaterial {
            c2s_key: crypto::derive_bootstrap_key(psk, "c2s", suite)?,
            s2c_key: crypto::derive_bootstrap_key(psk, "s2c", suite)?,
            c2s_prefix: [0u8; 4],
            s2c_prefix: [0u8; 4],
        };
        Session::new(suite, km, is_server, true, None)
    }

    pub fn seal(&mut self, msg_type: u8, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if plaintext.len() > wire::MAX_BODY {
            return Err(SessionError::Size);
        }
        let prelude = wire::build_header(self.flags, msg_type, self.suite, plaintext.len());
        let nonce = self.send.nonce();
        let sealed = crypto::aead_encrypt(self.suite, &self.send.key, &nonce, &prelude, plaintext)?;
        self.send.advance();

        let mut out = Vec::with_capacity(wire::HEADER_LEN + sealed.len());
        out.extend_from_slice(&prelude);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub fn seal_value(&mut self, msg_type: u8, value: &Value) -> Result<Vec<u8>, SessionError> {
        let body = upk::encode(value)?;
        self.seal(msg_type, &body)
    }

    pub fn open(&mut self, frame: &[u8]) -> Result<(u8, Vec<u8>), SessionError> {
        if frame.len() < wire::HEADER_LEN {
            return Err(SessionError::Size);
        }
        let h = wire::parse_prelude(&frame[..wire::PRELUDE_LEN])?;
        let want_len = wire::frame_len(h.length as usize);
        if frame.len() != want_len {
            return Err(SessionError::Size);
        }
        if h.flags != self.flags {
            return Err(SessionError::Flags);
        }
        if h.suite != self.suite {
            return Err(SessionError::Suite);
        }
        let nonce = self.recv.nonce();
        if frame[wire::PRELUDE_LEN..wire::HEADER_LEN] != nonce {
            return Err(SessionError::Replay);
        }
        let plain = crypto::aead_decrypt(
            self.suite,
            &self.recv.key,
            &nonce,
            &frame[..wire::PRELUDE_LEN],
            &frame[wire::HEADER_LEN..],
        )?;
        if plain.len() != h.length as usize {
            return Err(SessionError::Length);
        }
        self.recv.advance();
        Ok((h.msg_type, plain))
    }

    pub fn open_value(&mut self, frame: &[u8]) -> Result<(u8, Value), SessionError> {
        let (t, plain) = self.open(frame)?;
        let v = upk::decode_exact(&plain)?;
        Ok((t, v))
    }

    pub fn needs_rekey(&self) -> bool {
        self.send.frames >= REKEY_AFTER || self.recv.frames >= REKEY_AFTER
    }

    pub fn apply_rekey(&mut self, seed: &[u8]) -> Result<(), SessionError> {
        let prk = self.prk.ok_or(SessionError::NoPrk)?;
        let (new_prk, km) = crypto::derive_rekey(&prk, seed)?;
        self.prk = Some(new_prk);
        if self.is_server {
            self.send.rotate(km.s2c_key, km.s2c_prefix);
            self.recv.rotate(km.c2s_key, km.c2s_prefix);
        } else {
            self.send.rotate(km.c2s_key, km.c2s_prefix);
            self.recv.rotate(km.s2c_key, km.s2c_prefix);
        }
        Ok(())
    }

    pub fn counters(&self) -> (u64, u64) {
        (self.send.frames, self.recv.frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Session, Session) {
        let km = KeyMaterial {
            c2s_key: [1u8; 32],
            s2c_key: [2u8; 32],
            c2s_prefix: [3u8; 4],
            s2c_prefix: [4u8; 4],
        };
        let server = Session::new(1, km.clone(), true, false, Some([9u8; 32])).unwrap();
        let client = Session::new(1, km, false, false, Some([9u8; 32])).unwrap();
        (server, client)
    }

    #[test]
    fn roundtrip() {
        let (mut server, mut client) = pair();
        let frame = client.seal_value(wire::MSG_CHECKIN, &upk::map(vec![("ts", upk::u(5))])).unwrap();
        let (t, v) = server.open_value(&frame).unwrap();
        assert_eq!(t, wire::MSG_CHECKIN);
        assert_eq!(v.get("ts").and_then(|x| x.as_u64()), Some(5));
    }

    #[test]
    fn rejects_replay() {
        let (mut server, mut client) = pair();
        let frame = client.seal(wire::MSG_CHECKIN, b"x").unwrap();
        assert!(server.open(&frame).is_ok());
        assert!(server.open(&frame).is_err());
    }

    #[test]
    fn rekey_keeps_peers_in_sync() {
        let (mut server, mut client) = pair();
        let seed = [7u8; 32];
        server.apply_rekey(&seed).unwrap();
        client.apply_rekey(&seed).unwrap();
        let frame = client.seal(wire::MSG_PING, b"p").unwrap();
        assert!(server.open(&frame).is_ok());
    }
}
