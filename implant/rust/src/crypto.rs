//! Key schedule and AEAD layer for the umbra/v1 protocol.
//!
//! Identical to `server/internal/crypt` (Go) and `operator/umbra_cli/crypto.py`;
//! contracts/vectors.json pins every derived value.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::wire::{SUITE_AES256_GCM, SUITE_CHACHA20_POLY1305};

pub const ROLE_AGENT: u8 = 1;
pub const ROLE_OPERATOR: u8 = 2;

pub const LABEL_BOOTSTRAP: &[u8] = b"umbra/v1/bootstrap";
pub const LABEL_SESSION: &[u8] = b"umbra/v1/session";
pub const LABEL_REKEY: &[u8] = b"umbra/v1/rekey";

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    UnsupportedSuite(u8),
    BadKeyLength,
    AuthFailed,
    Kdf,
    Exchange,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::UnsupportedSuite(s) => write!(f, "unsupported suite {s}"),
            CryptoError::BadKeyLength => write!(f, "invalid key length"),
            CryptoError::AuthFailed => write!(f, "authentication failed"),
            CryptoError::Kdf => write!(f, "key derivation failed"),
            CryptoError::Exchange => write!(f, "key exchange failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

type Result<T> = std::result::Result<T, CryptoError>;

/// Directional keys plus their 4-byte nonce prefixes.
#[derive(Clone)]
pub struct KeyMaterial {
    pub c2s_key: [u8; 32],
    pub s2c_key: [u8; 32],
    pub c2s_prefix: [u8; 4],
    pub s2c_prefix: [u8; 4],
}

// ---------------------------------------------------------------------------
// hashes / MACs / KDFs
// ---------------------------------------------------------------------------

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&out);
    res
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut res = [0u8; 32];
    res.copy_from_slice(&out);
    res
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CryptoError::Kdf)?;
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    hkdf_expand(&hkdf_extract(salt, ikm), info, len)
}

/// Overwrite a buffer with zeroes.
///
/// The compiler is allowed to drop a write that is never read again, so a
/// plain `buf.fill(0)` can be optimised away.  A volatile write cannot: the
/// memory is written whether the program looks at it or not.  Every buffer
/// that holds key material or a module image goes through this on the way
/// out.
pub fn zeroize(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    b
}

fn material_from_okm(okm: &[u8]) -> KeyMaterial {
    let mut km = KeyMaterial {
        c2s_key: [0u8; 32],
        s2c_key: [0u8; 32],
        c2s_prefix: [0u8; 4],
        s2c_prefix: [0u8; 4],
    };
    km.c2s_key.copy_from_slice(&okm[0..32]);
    km.s2c_key.copy_from_slice(&okm[32..64]);
    km.c2s_prefix.copy_from_slice(&okm[64..68]);
    km.s2c_prefix.copy_from_slice(&okm[68..72]);
    km
}

/// Bind the PSK to the negotiated suite.
fn normalise_psk(psk: &[u8], suite: u8) -> Vec<u8> {
    let mut salt = LABEL_BOOTSTRAP.to_vec();
    salt.extend_from_slice(b"/psk");
    hkdf_sha256(psk, &salt, &[b's', b'u', b'i', b't', b'e', b':', suite], 32)
        .expect("hkdf expand of 32 bytes cannot fail")
}

/// PSK-phase directional key (handshake only, never used for data).
pub fn derive_bootstrap_key(psk: &[u8], direction: &str, suite: u8) -> Result<[u8; 32]> {
    let normalized = normalise_psk(psk, suite);
    let info = format!("{}/{}", String::from_utf8_lossy(LABEL_BOOTSTRAP), direction);
    let okm = hkdf_sha256(&normalized, LABEL_BOOTSTRAP, info.as_bytes(), 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    Ok(key)
}

pub fn bootstrap_nonce_prefix(key: &[u8]) -> Result<[u8; 4]> {
    let okm = hkdf_sha256(key, LABEL_BOOTSTRAP, b"nonce-prefix", 4)?;
    let mut p = [0u8; 4];
    p.copy_from_slice(&okm);
    Ok(p)
}

/// Derive the session PRK and first key set from a fresh X25519 secret.
pub fn derive_session(
    shared: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> Result<([u8; 32], KeyMaterial)> {
    if client_nonce.len() != 16 || server_nonce.len() != 16 {
        return Err(CryptoError::Kdf);
    }
    let mut salt_input = LABEL_SESSION.to_vec();
    salt_input.extend_from_slice(client_nonce);
    salt_input.extend_from_slice(server_nonce);
    let salt = sha256(&salt_input);
    let prk = hkdf_extract(&salt, shared);
    let mut info = LABEL_SESSION.to_vec();
    info.extend_from_slice(b"/keys");
    let okm = hkdf_expand(&prk, &info, 72)?;
    Ok((prk, material_from_okm(&okm)))
}

/// Mix a fresh 32-byte seed into the PRK; returns the new PRK and key set.
pub fn derive_rekey(prk: &[u8], seed: &[u8]) -> Result<([u8; 32], KeyMaterial)> {
    if seed.len() != 32 {
        return Err(CryptoError::Kdf);
    }
    let new_prk = hkdf_extract(seed, prk);
    let mut info = LABEL_REKEY.to_vec();
    info.extend_from_slice(b"/keys");
    let okm = hkdf_expand(&new_prk, &info, 72)?;
    Ok((new_prk, material_from_okm(&okm)))
}

// ---------------------------------------------------------------------------
// handshake transcript authentication
// ---------------------------------------------------------------------------

pub fn hello_auth(
    psk: &[u8],
    role: u8,
    ident: &[u8],
    client_pub: &[u8],
    client_nonce: &[u8],
    timestamp: u64,
    suite: u8,
) -> Result<[u8; 32]> {
    if ident.len() > 255 {
        return Err(CryptoError::AuthFailed);
    }
    let mut msg = Vec::with_capacity(128);
    msg.extend_from_slice(LABEL_BOOTSTRAP);
    msg.extend_from_slice(b"/auth/hello");
    msg.push(role);
    msg.push(ident.len() as u8);
    msg.extend_from_slice(ident);
    msg.extend_from_slice(client_pub);
    msg.extend_from_slice(client_nonce);
    msg.extend_from_slice(&timestamp.to_be_bytes());
    msg.push(suite);
    Ok(hmac_sha256(psk, &msg))
}

pub fn ack_auth(
    psk: &[u8],
    ident: &[u8],
    client_pub: &[u8],
    server_pub: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
    session_id: &[u8],
    suite: u8,
) -> Result<[u8; 32]> {
    if ident.len() > 255 {
        return Err(CryptoError::AuthFailed);
    }
    let mut msg = Vec::with_capacity(160);
    msg.extend_from_slice(LABEL_BOOTSTRAP);
    msg.extend_from_slice(b"/auth/ack");
    msg.push(ident.len() as u8);
    msg.extend_from_slice(ident);
    msg.extend_from_slice(client_pub);
    msg.extend_from_slice(server_pub);
    msg.extend_from_slice(client_nonce);
    msg.extend_from_slice(server_nonce);
    msg.extend_from_slice(session_id);
    msg.push(suite);
    Ok(hmac_sha256(psk, &msg))
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

pub fn x25519_keypair() -> (x25519_dalek::EphemeralSecret, [u8; 32]) {
    let secret = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret, public.to_bytes())
}

pub fn x25519_shared(
    secret: &x25519_dalek::EphemeralSecret,
    peer_pub: &[u8],
) -> Result<[u8; 32]> {
    if peer_pub.len() != 32 {
        return Err(CryptoError::Exchange);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(peer_pub);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(pk));
    if !shared.was_contributory() {
        return Err(CryptoError::Exchange);
    }
    Ok(shared.to_bytes())
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

/// Suites compiled into this beacon, in preference order.
pub fn supported_suites() -> Vec<u8> {
    let mut v = Vec::new();
    #[cfg(feature = "chacha")]
    v.push(SUITE_CHACHA20_POLY1305);
    v.push(SUITE_AES256_GCM);
    v
}

pub fn aead_encrypt(suite: u8, key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(CryptoError::BadKeyLength);
    }
    match suite {
        SUITE_AES256_GCM => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::BadKeyLength)?;
            cipher
                .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
                .map_err(|_| CryptoError::AuthFailed)
        }
        SUITE_CHACHA20_POLY1305 => {
            #[cfg(feature = "chacha")]
            {
                use chacha20poly1305::aead::Aead as _;
                use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce as CNonce};
                let cipher =
                    ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::BadKeyLength)?;
                cipher
                    .encrypt(CNonce::from_slice(nonce), Payload { msg: pt, aad })
                    .map_err(|_| CryptoError::AuthFailed)
            }
            #[cfg(not(feature = "chacha"))]
            {
                let _ = (pt, aad);
                Err(CryptoError::UnsupportedSuite(suite))
            }
        }
        other => Err(CryptoError::UnsupportedSuite(other)),
    }
}

pub fn aead_decrypt(suite: u8, key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(CryptoError::BadKeyLength);
    }
    match suite {
        SUITE_AES256_GCM => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::BadKeyLength)?;
            cipher
                .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
                .map_err(|_| CryptoError::AuthFailed)
        }
        SUITE_CHACHA20_POLY1305 => {
            #[cfg(feature = "chacha")]
            {
                use chacha20poly1305::aead::Aead as _;
                use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce as CNonce};
                let cipher =
                    ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::BadKeyLength)?;
                cipher
                    .decrypt(CNonce::from_slice(nonce), Payload { msg: ct, aad })
                    .map_err(|_| CryptoError::AuthFailed)
            }
            #[cfg(not(feature = "chacha"))]
            {
                let _ = (ct, aad);
                Err(CryptoError::UnsupportedSuite(suite))
            }
        }
        other => Err(CryptoError::UnsupportedSuite(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_rfc5869() {
        // RFC 5869, test case 1.
        let ikm = vec![0x0b; 22];
        let salt = (0u8..=0x0c).collect::<Vec<u8>>();
        let info = (0xf0u8..=0xf9).collect::<Vec<u8>>();
        let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        let want = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        assert_eq!(hex_encode(&okm), want);
    }

    #[test]
    fn aead_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let aad = b"prelude";
        let ct = aead_encrypt(SUITE_AES256_GCM, &key, &nonce, aad, b"secret").unwrap();
        assert_eq!(
            aead_decrypt(SUITE_AES256_GCM, &key, &nonce, aad, &ct).unwrap(),
            b"secret"
        );
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(aead_decrypt(SUITE_AES256_GCM, &key, &nonce, aad, &bad).is_err());
    }

    #[test]
    fn the_zeroizer_clears_the_buffer() {
        let mut buf = vec![0xaau8; 64];
        super::zeroize(&mut buf);
        assert!(buf.iter().all(|b| *b == 0));
    }

    pub fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
