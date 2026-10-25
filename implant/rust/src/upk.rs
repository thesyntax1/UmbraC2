//! Umbra Pack (upk) -- canonical binary encoding, Rust port.
//!
//! Byte-for-byte identical to `operator/umbra_cli/upk.py` and
//! `server/internal/upk`. See contracts/vectors.json for the pinned vectors.

use std::collections::BTreeMap;

pub const MAX_DEPTH: usize = 16;
pub const MAX_ITEMS: u64 = 1 << 20;
pub const MAX_STRING: usize = 1 << 20;
pub const MAX_TOTAL: usize = 4 << 20;

const T_NULL: u8 = 0x00;
const T_FALSE: u8 = 0x01;
const T_TRUE: u8 = 0x02;
const T_UINT: u8 = 0x03;
const T_INT: u8 = 0x04;
const T_F64: u8 = 0x05;
const T_STR: u8 = 0x06;
const T_BIN: u8 = 0x07;
const T_ARR: u8 = 0x08;
const T_MAP: u8 = 0x09;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Uint(u64),
    Int(i64),
    F64(f64),
    Str(String),
    Bin(Vec<u8>),
    Arr(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn as_bin(&self) -> Option<&[u8]> {
        match self {
            Value::Bin(b) => Some(b.as_slice()),
            Value::Str(s) => Some(s.as_bytes()),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Uint(n) => Some(*n),
            Value::Int(n) if *n >= 0 => Some(*n as u64),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Uint(n) => Some(*n as i64),
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.get(key),
            _ => None,
        }
    }
    pub fn str_or(&self, key: &str, default: &str) -> String {
        self.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_string()
    }
    pub fn u64_or(&self, key: &str, default: u64) -> u64 {
        self.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
    }
    pub fn i64_or(&self, key: &str, default: i64) -> i64 {
        self.get(key).and_then(|v| v.as_i64()).unwrap_or(default)
    }
    pub fn bin_or(&self, key: &str, default: &[u8]) -> Vec<u8> {
        self.get(key)
            .and_then(|v| v.as_bin())
            .map(|b| b.to_vec())
            .unwrap_or_else(|| default.to_vec())
    }
}

/// Build a canonical map value from key/value pairs.
pub fn map(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = BTreeMap::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Map(m)
}

pub fn arr(items: Vec<Value>) -> Value {
    Value::Arr(items)
}

pub fn s(v: &str) -> Value {
    Value::Str(v.to_string())
}

pub fn bin(v: &[u8]) -> Value {
    Value::Bin(v.to_vec())
}

pub fn u(v: u64) -> Value {
    Value::Uint(v)
}

pub fn i(v: i64) -> Value {
    Value::Int(v)
}

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upk: {}", self.0)
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

fn err<T>(msg: &str) -> Result<T> {
    Err(Error(msg.to_string()))
}

// ---------------------------------------------------------------------------
// encoder
// ---------------------------------------------------------------------------

pub fn encode(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    write_value(v, &mut out, 0)?;
    if out.len() > MAX_TOTAL {
        return err("value exceeds limit");
    }
    Ok(out)
}

/// `depth` is the number of containers already entered (0 at the top level), so
/// the check lives in the container arms. Counting scalars was an off-by-one
/// against the Python/Go reference and is pinned by vectors.json ("depth-max").
fn write_value(v: &Value, out: &mut Vec<u8>, depth: usize) -> Result<()> {
    if out.len() > MAX_TOTAL {
        return err("value exceeds limit");
    }
    match v {
        Value::Null => out.push(T_NULL),
        Value::Bool(false) => out.push(T_FALSE),
        Value::Bool(true) => out.push(T_TRUE),
        Value::Uint(n) => {
            out.push(T_UINT);
            write_uvarint(*n, out);
        }
        Value::Int(n) => {
            if *n >= 0 {
                out.push(T_UINT);
                write_uvarint(*n as u64, out);
            } else {
                out.push(T_INT);
                write_uvarint(zigzag(*n), out);
            }
        }
        Value::F64(f) => {
            out.push(T_F64);
            out.extend_from_slice(&f.to_be_bytes());
        }
        Value::Str(s) => {
            if s.len() > MAX_STRING {
                return err("string too long");
            }
            out.push(T_STR);
            write_uvarint(s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Bin(b) => {
            if b.len() > MAX_STRING {
                return err("binary too long");
            }
            out.push(T_BIN);
            write_uvarint(b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Arr(items) => {
            let level = depth + 1;
            if level > MAX_DEPTH {
                return err("nesting too deep");
            }
            if items.len() as u64 > MAX_ITEMS {
                return err("array too long");
            }
            out.push(T_ARR);
            write_uvarint(items.len() as u64, out);
            for item in items {
                write_value(item, out, level)?;
            }
        }
        Value::Map(m) => {
            let level = depth + 1;
            if level > MAX_DEPTH {
                return err("nesting too deep");
            }
            if m.len() as u64 > MAX_ITEMS {
                return err("map too large");
            }
            out.push(T_MAP);
            write_uvarint(m.len() as u64, out);
            // BTreeMap iterates in byte-wise ascending key order, which is
            // exactly the canonical order for UTF-8 string keys.
            for (k, val) in m {
                if k.len() > MAX_STRING {
                    return err("map key too long");
                }
                out.push(T_STR);
                write_uvarint(k.len() as u64, out);
                out.extend_from_slice(k.as_bytes());
                write_value(val, out, level)?;
            }
        }
    }
    Ok(())
}

fn write_uvarint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            out.push(b | 0x80);
        } else {
            out.push(b);
            return;
        }
    }
}

fn zigzag(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

// ---------------------------------------------------------------------------
// decoder
// ---------------------------------------------------------------------------

pub fn decode(input: &[u8]) -> Result<(Value, usize)> {
    let mut r = Reader { buf: input, pos: 0 };
    let v = r.read_value(0)?;
    Ok((v, r.pos))
}

pub fn decode_exact(input: &[u8]) -> Result<Value> {
    let (v, n) = decode(input)?;
    if n != input.len() {
        return err("trailing bytes after value");
    }
    Ok(v)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn need(&self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            return err("truncated input");
        }
        Ok(())
    }

    fn uvarint(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        for i in 0..10 {
            self.need(1)?;
            let b = self.buf[self.pos];
            self.pos += 1;
            if shift == 63 && b > 1 {
                return err("uvarint overflow");
            }
            result |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                if i > 0 && b == 0 {
                    return err("non-minimal uvarint");
                }
                return Ok(result);
            }
            shift += 7;
        }
        err("uvarint too long")
    }

    /// `depth` is the number of containers already entered (see `write_value`).
    fn read_value(&mut self, depth: usize) -> Result<Value> {
        self.need(1)?;
        let tag = self.buf[self.pos];
        self.pos += 1;
        match tag {
            T_NULL => Ok(Value::Null),
            T_FALSE => Ok(Value::Bool(false)),
            T_TRUE => Ok(Value::Bool(true)),
            T_UINT => Ok(Value::Uint(self.uvarint()?)),
            T_INT => {
                let z = self.uvarint()?;
                Ok(Value::Int(((z >> 1) as i64) ^ -((z & 1) as i64)))
            }
            T_F64 => {
                self.need(8)?;
                let mut b = [0u8; 8];
                b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
                self.pos += 8;
                Ok(Value::F64(f64::from_be_bytes(b)))
            }
            T_STR => {
                let n = self.uvarint()? as usize;
                if n > MAX_STRING {
                    return err("string too long");
                }
                self.need(n)?;
                let raw = &self.buf[self.pos..self.pos + n];
                self.pos += n;
                match std::str::from_utf8(raw) {
                    Ok(s) => Ok(Value::Str(s.to_string())),
                    Err(_) => err("invalid utf-8 string"),
                }
            }
            T_BIN => {
                let n = self.uvarint()? as usize;
                if n > MAX_STRING {
                    return err("binary too long");
                }
                self.need(n)?;
                let out = self.buf[self.pos..self.pos + n].to_vec();
                self.pos += n;
                Ok(Value::Bin(out))
            }
            T_ARR => {
                let level = depth + 1;
                if level > MAX_DEPTH {
                    return err("nesting too deep");
                }
                let n = self.uvarint()?;
                if n > MAX_ITEMS {
                    return err("array too long");
                }
                let mut items = Vec::with_capacity(n.min(64) as usize);
                for _ in 0..n {
                    items.push(self.read_value(level)?);
                }
                Ok(Value::Arr(items))
            }
            T_MAP => {
                let level = depth + 1;
                if level > MAX_DEPTH {
                    return err("nesting too deep");
                }
                let n = self.uvarint()?;
                if n > MAX_ITEMS {
                    return err("map too large");
                }
                let mut m: BTreeMap<String, Value> = BTreeMap::new();
                let mut prev: Option<String> = None;
                for _ in 0..n {
                    self.need(1)?;
                    if self.buf[self.pos] != T_STR {
                        return err("map key must be a string");
                    }
                    self.pos += 1;
                    let klen = self.uvarint()? as usize;
                    if klen > MAX_STRING {
                        return err("map key too long");
                    }
                    self.need(klen)?;
                    let raw = &self.buf[self.pos..self.pos + klen];
                    self.pos += klen;
                    let key = match std::str::from_utf8(raw) {
                        Ok(s) => s.to_string(),
                        Err(_) => return err("invalid utf-8 map key"),
                    };
                    if let Some(p) = &prev {
                        if key.as_bytes() <= p.as_bytes() {
                            return err("map keys not ascending");
                        }
                    }
                    prev = Some(key.clone());
                    let val = self.read_value(level)?;
                    m.insert(key, val);
                }
                Ok(Value::Map(m))
            }
            other => err(&format!("unknown type tag 0x{other:02x}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_primitives() {
        for v in [
            Value::Null,
            Value::Bool(true),
            Value::Uint(0),
            Value::Uint(u64::MAX),
            Value::Int(-65),
            Value::Int(i64::MIN),
            Value::Str("şifreli".into()),
            Value::Bin(vec![0, 1, 0xfe, 0xff]),
        ] {
            let enc = encode(&v).unwrap();
            let dec = decode_exact(&enc).unwrap();
            assert_eq!(v, dec, "roundtrip failed for {v:?}");
        }
    }

    #[test]
    fn canonical_map_order() {
        let a = map(vec![("b", u(1)), ("a", u(2))]);
        let b = map(vec![("a", u(2)), ("b", u(1))]);
        assert_eq!(encode(&a).unwrap(), encode(&b).unwrap());
    }

    #[test]
    fn rejects_trailing_and_bad_tags() {
        assert!(decode_exact(&[0x03, 0x05, 0x00]).is_err());
        assert!(decode_exact(&[0xff]).is_err());
        assert!(decode_exact(&[0x03, 0x80, 0x00]).is_err());
    }
}
