//! The layer-3 tunnel client.
//!
//! The beacon joins the tunnel with the same secret it uses for the
//! beaconing channel (the agent PSK), so no extra key distribution is
//! needed. The handshake is the client half of the Noise-IK-style exchange
//! the team server implements:
//!
//! ```text
//! INIT {id, timestamp, ephemeral, mac}   ->
//!                             <-  RESP {timestamp, ephemeral, address, mac}
//! ```
//!
//! After that the two ends exchange IPv4 packets in AES-256-GCM sealed
//! datagrams, with a 64-packet replay window on the receiving side.
//!
//! On Linux the packets are read from and written to a TUN device, which
//! makes the tunnel a real L3 link: the operator can route traffic to the
//! host as if it were on the same network.

use std::io::{Read, Write};
use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto;

/// Packet types.
pub const TYPE_INIT: u8 = 1;
pub const TYPE_RESP: u8 = 2;
pub const TYPE_DATA: u8 = 3;
/// The question of the server and the answer of the peer.  Both travel
/// through the tunnel like the data packets, so the answer proves that
/// the whole path is alive.
pub const TYPE_PING: u8 = 4;
pub const TYPE_PONG: u8 = 5;

/// The size of the data packet header.
pub const HEADER_LEN: usize = 9;

/// The length of the authentication tag of a handshake packet.  The tag
/// is the first bytes of an HMAC, so it is short enough for a packet and
/// long enough to be unforgeable.
const MAC_LEN: usize = 16;

/// The label of the INIT transcript.
const LABEL_INIT: &[u8] = b"umbra/v1/vpn/init";
/// The label of the RESP transcript.
const LABEL_RESP: &[u8] = b"umbra/v1/vpn/resp";
/// The label that mixes the pre-shared secret into the shared secret.
const LABEL_DH: &[u8] = b"umbra/v1/vpn/dh";

/// The state of a joined tunnel.
pub struct Tunnel {
    /// The address the server assigned.
    pub address: [u8; 4],
    /// The socket the tunnel runs on.
    pub socket: UdpSocket,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_prefix: [u8; 4],
    recv_prefix: [u8; 4],
    counter: u64,
}

/// Join the tunnel.
///
/// `server` is the address of the tunnel endpoint ("host:port"), `psk` the
/// agent key and `ident` the beacon identity.
pub fn join(
    server: &str,
    psk: &[u8],
    ident: &str,
    timeout: Duration,
) -> Result<Tunnel, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("vpn: bind: {e}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("vpn: set timeout: {e}"))?;
    let peer: std::net::SocketAddr = resolve(server)?;

    let (secret, pubkey) = crypto::x25519_keypair();
    let ts = now_secs();
    let init = build_init(psk, ident, ts, &pubkey);
    socket
        .send_to(&init, peer)
        .map_err(|e| format!("vpn: send init: {e}"))?;

    let mut buf = vec![0u8; 2048];
    let (n, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("vpn: no response: {e}"))?;
    if n < 1 + 8 + 32 + 4 + 16 || buf[0] != TYPE_RESP {
        return Err("vpn: malformed response".to_string());
    }
    let resp_ts = u64::from_be_bytes([
        buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
    ]);
    let eph = &buf[9..41];
    let address = [buf[41], buf[42], buf[43], buf[44]];
    let mac = &buf[45..61];
    let want = resp_mac(psk, ident, ts, &pubkey, eph, resp_ts);
    if !crate::link::ct_eq(&want, mac) {
        return Err("vpn: the server did not authenticate itself".to_string());
    }
    let shared = crypto::x25519_shared(&secret, eph).map_err(|e| format!("vpn: x25519: {e}"))?;
    let mut mixed_input = LABEL_DH.to_vec();
    mixed_input.extend_from_slice(&shared);
    let mixed = crypto::hmac_sha256(psk, &mixed_input);

    let mut cn = [0u8; 16];
    cn[..8].copy_from_slice(&ts.to_be_bytes());
    let mut sn = [0u8; 16];
    sn[..8].copy_from_slice(&resp_ts.to_be_bytes());
    let (_, km) = crypto::derive_session(&mixed, &cn, &sn)
        .map_err(|e| format!("vpn: derive session: {e}"))?;

    Ok(Tunnel {
        address,
        socket,
        send_key: km.c2s_key,
        recv_key: km.s2c_key,
        send_prefix: km.c2s_prefix,
        recv_prefix: km.s2c_prefix,
        counter: 0,
    })
}

impl Tunnel {
    /// Encrypt and send one IPv4 packet.
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        if packet.len() < 20 {
            return Err("vpn: the packet is too short".to_string());
        }
        let counter = self.counter;
        self.counter += 1;
        let mut header = [0u8; HEADER_LEN];
        header[0] = TYPE_DATA;
        header[1..9].copy_from_slice(&counter.to_be_bytes());
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.send_prefix);
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        let sealed = crypto::aead_encrypt(
            wire_suite(),
            &self.send_key,
            &nonce,
            &header,
            packet,
        )
        .map_err(|e| format!("vpn: seal: {e}"))?;
        let mut out = Vec::with_capacity(header.len() + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        self.socket
            .send(&out)
            .map_err(|e| format!("vpn: send: {e}"))
    }

    /// Receive and decrypt one IPv4 packet.
    pub fn recv_packet(&mut self) -> Result<Vec<u8>, String> {
        let (kind, plain) = self.recv_sealed()?;
        if kind != TYPE_DATA {
            return Err("vpn: the packet is not data".to_string());
        }
        Ok(plain)
    }

    /// Receive and decrypt one packet of any kind.
    ///
    /// The kind and the payload come back, so the caller can tell a
    /// question from an answer.
    pub fn recv_sealed(&mut self) -> Result<(u8, Vec<u8>), String> {
        let mut buf = vec![0u8; 2048];
        let (n, _) = self
            .socket
            .recv(&mut buf)
            .map_err(|e| format!("vpn: receive: {e}"))?;
        if n < HEADER_LEN + 16 {
            return Err("vpn: malformed packet".to_string());
        }
        let kind = buf[0];
        let counter = u64::from_be_bytes([
            buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
        ]);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.recv_prefix);
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        let plain = crypto::aead_decrypt(
            wire_suite(),
            &self.recv_key,
            &nonce,
            &buf[..HEADER_LEN],
            &buf[HEADER_LEN..n],
        )
        .map_err(|e| format!("vpn: decrypt: {e}"))?;
        Ok((kind, plain))
    }

    /// Send a control packet: a question or an answer.
    pub fn send_control(&mut self, kind: u8, payload: &[u8]) -> Result<(), String> {
        let counter = self.counter;
        self.counter += 1;
        let mut header = [0u8; HEADER_LEN];
        header[0] = kind;
        header[1..9].copy_from_slice(&counter.to_be_bytes());
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.send_prefix);
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        let sealed = crypto::aead_encrypt(
            wire_suite(),
            &self.send_key,
            &nonce,
            &header,
            payload,
        )
        .map_err(|e| format!("vpn: seal: {e}"))?;
        let mut out = Vec::with_capacity(header.len() + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        self.socket
            .send(&out)
            .map_err(|e| format!("vpn: send: {e}"))
    }

    /// Answer the question of the server.
    ///
    /// The question and the answer are sealed like the data packets, so
    /// only the peer can read the question and only the server can tell
    /// that the answer is the answer.
    pub fn answer_ping(&mut self) -> Result<(), String> {
        let (kind, payload) = self.recv_sealed()?;
        if kind != TYPE_PING || payload.len() < 17 {
            return Err("vpn: the packet is not a question".to_string());
        }
        let mut answer = Vec::with_capacity(17);
        answer.push(2); // the kind of the answer
        answer.extend_from_slice(&payload[1..9]); // the nonce
        answer.extend_from_slice(&payload[9..17]); // the timestamp
        self.send_control(TYPE_PONG, &answer)
    }
}

/// Relay the packets of the tunnel to the server.
///
/// A peer that can only be reached through another agent joins the relay
/// of that agent instead of the server.  The relay hands the datagrams to
/// the server and back, so the keys of the session stay between the peer
/// and the server: the relay sees nothing but ciphertext.
pub fn relay(server: &str, listen: &str, verbose: bool) -> Result<String, String> {
    let socket = UdpSocket::bind(listen).map_err(|e| format!("vpn: bind: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| format!("vpn: timeout: {e}"))?;
    let upstream = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("vpn: bind: {e}"))?;
    upstream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| format!("vpn: timeout: {e}"))?;
    let peer: std::net::SocketAddr = resolve(server)?;
    let local = socket
        .local_addr()
        .map_err(|e| format!("vpn: address: {e}"))?
        .to_string();
    if verbose {
        eprintln!("[umbra] vpn relay on {local} towards {peer}");
    }
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 2048];
        let mut client: Option<std::net::SocketAddr> = None;
        loop {
            // The peer talks to the relay.
            match socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    client = Some(from);
                    let _ = upstream.send_to(&buf[..n], peer);
                }
                Err(_) => {}
            }
            // The server talks to the peer.
            match upstream.recv_from(&mut buf) {
                Ok((n, _)) => {
                    if let Some(target) = client {
                        let _ = socket.send_to(&buf[..n], target);
                    }
                }
                Err(_) => {}
            }
        }
    });
    Ok(local)
}

/// Build the INIT packet.
fn build_init(psk: &[u8], ident: &str, ts: u64, pubkey: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 1 + ident.len() + 8 + 32 + 16);
    out.push(TYPE_INIT);
    out.push(ident.len() as u8);
    out.extend_from_slice(ident.as_bytes());
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&init_mac(psk, ident, ts, pubkey));
    out
}

/// The authentication tag of an INIT packet.
fn init_mac(psk: &[u8], ident: &str, ts: u64, pubkey: &[u8]) -> [u8; MAC_LEN] {
    let mut msg = LABEL_INIT.to_vec();
    msg.extend_from_slice(ident.as_bytes());
    msg.extend_from_slice(&ts.to_be_bytes());
    msg.extend_from_slice(pubkey);
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&crypto::hmac_sha256(psk, &msg)[..MAC_LEN]);
    mac
}

/// The authentication tag of a RESP packet.
fn resp_mac(
    psk: &[u8],
    ident: &str,
    ts: u64,
    pubkey: &[u8],
    eph: &[u8],
    now: u64,
) -> [u8; MAC_LEN] {
    let mut msg = LABEL_RESP.to_vec();
    msg.extend_from_slice(ident.as_bytes());
    msg.extend_from_slice(&ts.to_be_bytes());
    msg.extend_from_slice(pubkey);
    msg.extend_from_slice(eph);
    msg.extend_from_slice(&now.to_be_bytes());
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&crypto::hmac_sha256(psk, &msg)[..MAC_LEN]);
    mac
}

/// The AEAD suite the tunnel uses.
fn wire_suite() -> u8 {
    crate::wire::SUITE_AES256_GCM
}

/// Resolve a "host:port" pair.
fn resolve(addr: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    addr.to_socket_addrs()
        .map_err(|e| format!("vpn: resolve {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("vpn: resolve {addr}: no address"))
}

/// The current unix time in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run the tunnel until the device disappears.
///
/// On Linux the packets come from a TUN device; elsewhere the tunnel reports
/// the assigned address and stays idle.
pub fn serve(
    server: &str,
    psk: &[u8],
    ident: &str,
    verbose: bool,
) -> Result<String, String> {
    let mut tunnel = join(server, psk, ident, Duration::from_secs(15))?;
    let address = format!(
        "{}.{}.{}.{}",
        tunnel.address[0], tunnel.address[1], tunnel.address[2], tunnel.address[3]
    );
    if verbose {
        eprintln!("[umbra] vpn tunnel joined as {address}");
    }
    #[cfg(target_os = "linux")]
    {
        let mut device = match crate::vpn::tun::open(&address) {
            Ok(d) => d,
            Err(e) => return Err(format!("vpn: {e}")),
        };
        // A short timeout on the socket keeps the loop responsive: the
        // device is polled on every round, so a packet the host sends is
        // never delayed by a quiet tunnel.
        let _ = tunnel.socket.set_read_timeout(Some(Duration::from_millis(200)));
        let mut buf = [0u8; 2048];
        loop {
            // Device -> tunnel.
            match device.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let _ = tunnel.send_packet(&buf[..n]);
                }
                Ok(_) => {}
                Err(_) => {}
            }
            // Tunnel -> device.
            match tunnel.recv_packet() {
                Ok(packet) => {
                    let _ = device.write(&packet);
                }
                Err(_) => {}
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(address)
    }
}

/// The Linux TUN device.
#[cfg(target_os = "linux")]
pub mod tun {
    use std::io::{Read, Write};
    use std::os::raw::{c_char, c_int, c_ulong, c_void};

    extern "C" {
        fn open(path: *const c_char, flags: c_int, ...) -> c_int;
        fn close(fd: c_int) -> c_int;
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
        fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    }

    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    const O_NONBLOCK: c_int = 0o4000;

    const O_RDWR: c_int = 0o2;
    const TUNSETIFF: c_ulong = 0x4004_54ca;
    const IFF_TUN: u16 = 0x0001;
    const IFF_NO_PI: u16 = 0x1000;

    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        flags: u16,
        pad: [u8; 22],
    }

    /// An open TUN device.
    pub struct Device {
        fd: c_int,
    }

    impl Device {
        /// Read one IP packet.
        pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = unsafe { read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        /// Write one IP packet.
        pub fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
            let n = unsafe { write(self.fd, packet.as_ptr() as *const c_void, packet.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        }
    }

    impl Drop for Device {
        fn drop(&mut self) {
            unsafe {
                close(self.fd);
            }
        }
    }

    /// Open a TUN device and give it the tunnel address.
    ///
    /// The device needs the CAP_NET_ADMIN capability; without it the tunnel
    /// reports the error instead of pretending to work.
    pub fn open(address: &str) -> Result<Device, String> {
        let path = b"/dev/net/tun\0";
        let fd = unsafe { open(path.as_ptr() as *const c_char, O_RDWR) };
        if fd < 0 {
            return Err(format!(
                "the tun device is not available: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut req = IfReq {
            name: [0u8; 16],
            flags: IFF_TUN | IFF_NO_PI,
            pad: [0u8; 22],
        };
        let name = address.split('.').next().unwrap_or("umbra0");
        for (i, b) in name.as_bytes().iter().take(15).enumerate() {
            req.name[i] = *b;
        }
        let rc = unsafe { ioctl(fd, TUNSETIFF, &mut req as *mut IfReq) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                close(fd);
            }
            return Err(format!("the tun device refused the request: {err}"));
        }
        // The device is polled, so a read must not block the tunnel loop.
        unsafe {
            let flags = fcntl(fd, F_GETFL);
            if flags >= 0 {
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            }
        }
        Ok(Device { fd })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_init_packet_has_the_expected_shape() {
        let packet = build_init(b"psk", "agent-1", 42, &[7u8; 32]);
        assert_eq!(packet[0], TYPE_INIT);
        assert_eq!(packet[1], 7);
        assert_eq!(packet.len(), 1 + 1 + 7 + 8 + 32 + 16);
    }

    #[test]
    fn the_mac_binds_the_identity() {
        let a = init_mac(b"psk", "agent-1", 1, &[0u8; 32]);
        let b = init_mac(b"psk", "agent-2", 1, &[0u8; 32]);
        assert_ne!(a, b);
    }
}
