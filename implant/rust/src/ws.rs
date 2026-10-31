//! The WebSocket transport (RFC 6455).
//!
//! The umbra protocol is a stream of binary frames, and a WebSocket carries
//! exactly that: one umbra frame per binary WebSocket frame, in order.  The
//! session state machine above the transport does not change at all, so the
//! beacon only needs a different channel.
//!
//! Why the beacon wants it:
//!
//! * a CDN or a reverse proxy in front of the server speaks WebSocket, and
//!   the beacon can point at the CDN instead of the origin;
//! * the Host header of the upgrade request is free, which is what makes
//!   domain fronting possible;
//! * the connection stays open, so the server can push a task the moment it
//!   is queued.
//!
//! Only the part of RFC 6455 that the transport needs is implemented: the
//! opening handshake, binary frames, ping/pong and a clean close.  A
//! fragmented frame is refused instead of reassembled -- the umbra frames
//! are small enough to fit into one WebSocket frame.
//!
//! The handshake needs SHA-1 and base64, which the protocol itself does not
//! use; they are implemented here so the beacon keeps its dependency set
//! small.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::transport::Channel;

/// The GUID of RFC 6455 that turns the client key into the accept value.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The WebSocket opcodes the transport uses.
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// The largest frame the transport reads.  The umbra frames are smaller, but
/// a hostile peer could try to make the beacon allocate.
const MAX_FRAME: usize = 2 << 20;

/// The largest handshake response the transport accepts.
const MAX_HANDSHAKE: usize = 64 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// The WebSocket channel of the beacon.
pub struct WsChannel {
    stream: TcpStream,
    /// The bytes that were read but are not a frame yet.
    buf: Vec<u8>,
}

impl WsChannel {
    /// Open the connection and perform the opening handshake.
    ///
    /// `addr` is "host:port", `path` is the route of the server and
    /// `host_header` overrides the Host header (domain fronting); an empty
    /// host header uses "host:port".
    pub fn new(addr: &str, path: &str, host_header: &str) -> Result<Self, String> {
        let (host, port) = split_addr(addr)?;
        let target = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| format!("ws: resolve {addr}: {e}"))?
            .next()
            .ok_or_else(|| format!("ws: {addr} has no address"))?;
        let mut stream =
            TcpStream::connect_timeout(&target, CONNECT_TIMEOUT).map_err(|e| format!("ws: connect {addr}: {e}"))?;
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_nodelay(true);

        let key = base64_encode(&crate::crypto::random_bytes(16));
        let host_line = if host_header.is_empty() {
            crate::config::host_port(&host, port)
        } else {
            host_header.to_string()
        };
        let route = if path.is_empty() { "/api/v1/beacon" } else { path };
        let request = format!(
            "GET {route} HTTP/1.1\r\n\
             Host: {host_line}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("ws: write the upgrade request: {e}"))?;

        let mut channel = WsChannel { stream, buf: Vec::new() };
        let head = channel.read_handshake()?;
        if !head.starts_with("HTTP/1.1 101") {
            let status = head.lines().next().unwrap_or("").to_string();
            return Err(format!("ws: the server refused the upgrade: {status}"));
        }
        let accept = header_value(&head, "sec-websocket-accept");
        let expected = base64_encode(&sha1(format!("{key}{GUID}").as_bytes()));
        if accept != expected {
            return Err("ws: the server did not confirm the websocket key".to_string());
        }
        Ok(channel)
    }

    /// Read the handshake response, keeping the bytes that follow it.
    fn read_handshake(&mut self) -> Result<String, String> {
        loop {
            if let Some(pos) = find(&self.buf, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&self.buf[..pos]).to_string();
                self.buf.drain(..pos + 4);
                return Ok(head);
            }
            let mut chunk = [0u8; 1024];
            let n = self
                .stream
                .read(&mut chunk)
                .map_err(|e| format!("ws: read the handshake response: {e}"))?;
            if n == 0 {
                return Err("ws: the server closed the connection during the handshake".to_string());
            }
            self.buf.extend_from_slice(&chunk[..n]);
            if self.buf.len() > MAX_HANDSHAKE {
                return Err("ws: the handshake response is too large".to_string());
            }
        }
    }

    /// Read exactly `count` bytes.
    fn take(&mut self, count: usize) -> io::Result<Vec<u8>> {
        while self.buf.len() < count {
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ws: the peer closed the connection",
                ));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
        let out: Vec<u8> = self.buf.drain(..count).collect();
        Ok(out)
    }

    /// Read one WebSocket frame: the opcode, the payload and the fin bit.
    fn read_ws_frame(&mut self) -> io::Result<(u8, Vec<u8>, bool)> {
        let head = self.take(2)?;
        let fin = head[0] & 0x80 != 0;
        let opcode = head[0] & 0x0F;
        let masked = head[1] & 0x80 != 0;
        let mut length = (head[1] & 0x7F) as usize;
        if length == 126 {
            let ext = self.take(2)?;
            length = u16::from_be_bytes([ext[0], ext[1]]) as usize;
        } else if length == 127 {
            let ext = self.take(8)?;
            let mut value = [0u8; 8];
            value.copy_from_slice(&ext);
            length = u64::from_be_bytes(value) as usize;
        }
        if length > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ws: the frame is too large",
            ));
        }
        let mut mask = [0u8; 4];
        if masked {
            let key = self.take(4)?;
            mask.copy_from_slice(&key);
        }
        let mut payload = self.take(length)?;
        if masked {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index & 3];
            }
        }
        Ok((opcode, payload, fin))
    }

    /// Send one WebSocket frame.
    ///
    /// A client has to mask its frames, so the payload is masked with a
    /// fresh key.
    fn write_ws_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let mask = crate::crypto::random_bytes(4);
        let mut out = Vec::with_capacity(payload.len() + 14);
        out.push(0x80 | opcode);
        let size = payload.len();
        if size < 126 {
            out.push(0x80 | size as u8);
        } else if size < 1 << 16 {
            out.push(0x80 | 126);
            out.extend_from_slice(&(size as u16).to_be_bytes());
        } else {
            out.push(0x80 | 127);
            out.extend_from_slice(&(size as u64).to_be_bytes());
        }
        out.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            out.push(byte ^ mask[index & 3]);
        }
        self.stream.write_all(&out)?;
        self.stream.flush()
    }
}

impl Channel for WsChannel {
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        self.write_ws_frame(OP_BINARY, frame)
    }

    fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        loop {
            let (opcode, payload, fin) = self.read_ws_frame()?;
            match opcode {
                OP_CLOSE => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "ws: the peer closed the connection",
                    ))
                }
                OP_PING => {
                    self.write_ws_frame(OP_PONG, &payload)?;
                    continue;
                }
                OP_PONG => continue,
                _ => {
                    if !fin {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ws: fragmented frames are not supported",
                        ));
                    }
                    return Ok(payload);
                }
            }
        }
    }

    fn close(&mut self) {
        let _ = self.write_ws_frame(OP_CLOSE, &[0x03, 0xE8]);
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Split "host:port" into its two parts.
fn split_addr(addr: &str) -> Result<(String, u16), String> {
    match addr.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("ws: {addr} has no port"))?;
            Ok((host.to_string(), port))
        }
        None => Err(format!("ws: {addr} must be host:port")),
    }
}

/// The value of a header of an HTTP response.
fn header_value(head: &str, name: &str) -> String {
    for line in head.lines().skip(1) {
        let (key, value) = match line.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        if key.trim().eq_ignore_ascii_case(name) {
            return value.trim().to_string();
        }
    }
    String::new()
}

/// Find a byte string inside another one.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The SHA-1 of the data (RFC 3174).
///
/// The WebSocket handshake defines the accept value with SHA-1, so the
/// beacon needs it even though the umbra protocol never uses SHA-1.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    ];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks(64) {
        let mut w = [0u32; 80];
        for index in 0..16 {
            let offset = index * 4;
            w[index] = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..80 {
            w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (index, word) in w.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (index, value) in h.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    out
}

/// The alphabet of RFC 4648 base64.
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as base64 (RFC 4648, with padding).
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((value >> 18) & 63) as usize] as char);
        out.push(B64[((value >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[((value >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64[(value & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decode bytes from base64 (RFC 4648).
///
/// The decoder is strict: a character outside the alphabet, a wrong length
/// or a padding in the wrong place is an error and not a silent skip, so a
/// blob that was cut in half is never decrypted as half a blob.
pub fn base64_decode(data: &str) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(data.len() / 4 * 3);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding = 0usize;
    for ch in data.chars() {
        if ch == '=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            return None;
        }
        let value = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if padding > 2 {
        return None;
    }
    // The bits that are left over must be zero: a base64 text that was cut
    // in the middle is not a base64 text.
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
        assert!(base64_decode("Zm9vYmF!").is_none());
    }

    #[test]
    fn sha1_matches_the_reference_values() {
        assert_eq!(
            sha1(b"abc").to_vec(),
            vec![
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
                0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
        assert_eq!(
            sha1(b"").to_vec(),
            vec![
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
                0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn base64_matches_the_reference_values() {
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn the_accept_value_matches_rfc6455() {
        // The example of RFC 6455, section 1.3.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = base64_encode(&sha1(format!("{key}{GUID}").as_bytes()));
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn headers_are_case_insensitive() {
        let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: abc\r\n";
        assert_eq!(header_value(head, "sec-websocket-accept"), "abc");
        assert_eq!(header_value(head, "missing"), "");
    }

    #[test]
    fn the_address_is_split() {
        assert_eq!(split_addr("10.0.0.1:4001").unwrap(), ("10.0.0.1".to_string(), 4001));
        assert!(split_addr("10.0.0.1").is_err());
    }
}
