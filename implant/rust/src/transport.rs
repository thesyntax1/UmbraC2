//! Transports. Every transport carries whole umbra/v1 frames; the session and
//! message handling above this layer is identical for all of them.
//!
//! * `TcpChannel`  -- one connection per beacon cycle, frames in both directions.
//! * `HttpChannel` -- frames inside HTTP POST bodies (plain HTTP/1.1 written by
//!   hand, so no TLS/async runtime dependency; put it behind a TLS-terminating
//!   reverse proxy or an HTTPS redirector for production).

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

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
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

pub struct TcpChannel {
    addr: String,
    stream: Option<TcpStream>,
}

impl TcpChannel {
    pub fn new(addr: &str) -> Self {
        TcpChannel { addr: addr.to_string(), stream: None }
    }

    pub fn connect(&mut self) -> io::Result<()> {
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
    sid: Option<String>,
    out: Vec<u8>,
    pending: std::collections::VecDeque<Vec<u8>>,
}

impl HttpChannel {
    /// `addr` is "host:port"; `path` defaults to /api/v1/beacon.
    pub fn new(addr: &str, path: &str) -> io::Result<Self> {
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
            sid: None,
            out: Vec::new(),
            pending: std::collections::VecDeque::new(),
        })
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
        let mut stream = TcpStream::connect_timeout(
            &(self.host.as_str(), self.port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no address"))?,
            CONNECT_TIMEOUT,
        )?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;

        let header = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\
             Content-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            target,
            self.host,
            self.port,
            body.len()
        );
        stream.write_all(header.as_bytes())?;
        stream.write_all(&body)?;
        stream.flush()?;

        let (status, payload) = read_http_response(&mut stream)?;
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
    }

    fn set_session_id(&mut self, sid: &str) {
        self.sid = Some(sid.to_string());
    }
}

/// Read one HTTP/1.1 response and return (status, body).
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
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse::<usize>().ok();
        }
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
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
        return Ok((status, dechunk(&body)?));
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
        }
        None => loop {
            let n = r.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        },
    }
    Ok((status, body))
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

    #[test]
    fn finds_header_terminator() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(find_subslice(buf, b"\r\n\r\n"), Some(buf.len() - 4));
    }
}
