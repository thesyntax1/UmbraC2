"""Umbra Pack (upk) -- the canonical binary value encoding used on the wire.

`upk` is a deliberately tiny, deterministic, dependency-free TLV-free encoding:

    type byte | payload

Types
    0x00  null
    0x01  false          0x02  true
    0x03  uvarint   (unsigned LEB128, < 2**64)
    0x04  svarint   (zigzag LEB128, |v| < 2**63)
    0x05  f64       (IEEE-754 big endian, 8 bytes)
    0x06  str       (uvarint length + UTF-8 bytes)
    0x07  bin       (uvarint length + raw bytes)
    0x08  array     (uvarint count + values)
    0x09  map       (uvarint count + (key, value) pairs)

Rules that make upk *canonical* (every value has exactly one encoding):

  * map keys are always strings, sorted byte-wise ascending, no duplicates;
  * uvarint/svarint use the shortest possible encoding;
  * integers: negatives must use svarint, non-negatives must use uvarint
    (the decoder accepts either form, the encoder always canonicalises);
  * no trailing bytes are allowed after a top-level value.

This module is the *reference* implementation; the Go and Rust ports are
verified against the shared vectors in ``contracts/vectors.json``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

__all__ = [
    "encode",
    "decode",
    "UpkError",
    "MAX_DEPTH",
    "MAX_ITEMS",
    "MAX_STRING",
    "MAX_TOTAL",
]

MAX_DEPTH = 16
MAX_ITEMS = 1 << 20
MAX_STRING = 1 << 20
MAX_TOTAL = 4 << 20

T_NULL = 0x00
T_FALSE = 0x01
T_TRUE = 0x02
T_UINT = 0x03
T_INT = 0x04
T_F64 = 0x05
T_STR = 0x06
T_BIN = 0x07
T_ARR = 0x08
T_MAP = 0x09


class UpkError(ValueError):
    """Raised for malformed or non-canonical upk data."""


def _put_uvarint(out: bytearray, n: int) -> None:
    if n < 0 or n >= 1 << 64:
        raise UpkError("uvarint out of range")
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return


def _put_svarint(out: bytearray, n: int) -> None:
    if n < -(1 << 63) or n >= 1 << 63:
        raise UpkError("svarint out of range")
    if n >= 0:
        _put_uvarint(out, n << 1)
    else:
        _put_uvarint(out, ((-n) << 1) - 1)


class _Writer:
    __slots__ = ("buf", "depth")

    def __init__(self) -> None:
        self.buf = bytearray()
        self.depth = 0

    def value(self, v: Any) -> None:
        if len(self.buf) > MAX_TOTAL:
            raise UpkError("encoded value too large")
        if v is None:
            self.buf.append(T_NULL)
        elif v is False:
            self.buf.append(T_FALSE)
        elif v is True:
            self.buf.append(T_TRUE)
        elif isinstance(v, int):
            if v >= 0:
                self.buf.append(T_UINT)
                _put_uvarint(self.buf, v)
            else:
                self.buf.append(T_INT)
                _put_svarint(self.buf, v)
        elif isinstance(v, float):
            import struct

            self.buf.append(T_F64)
            self.buf += struct.pack(">d", v)
        elif isinstance(v, str):
            raw = v.encode("utf-8")
            if len(raw) > MAX_STRING:
                raise UpkError("string too long")
            self.buf.append(T_STR)
            _put_uvarint(self.buf, len(raw))
            self.buf += raw
        elif isinstance(v, (bytes, bytearray, memoryview)):
            raw = bytes(v)
            if len(raw) > MAX_STRING:
                raise UpkError("binary value too long")
            self.buf.append(T_BIN)
            _put_uvarint(self.buf, len(raw))
            self.buf += raw
        elif isinstance(v, (list, tuple)):
            self._enter()
            if len(v) > MAX_ITEMS:
                raise UpkError("array too long")
            self.buf.append(T_ARR)
            _put_uvarint(self.buf, len(v))
            for item in v:
                self.value(item)
            self.depth -= 1
        elif isinstance(v, dict):
            self._enter()
            if len(v) > MAX_ITEMS:
                raise UpkError("map too large")
            items: List[Tuple[bytes, Any]] = []
            for k, val in v.items():
                if not isinstance(k, str):
                    raise UpkError("map keys must be strings")
                items.append((k.encode("utf-8"), val))
            items.sort(key=lambda kv: kv[0])
            for i in range(1, len(items)):
                if items[i - 1][0] == items[i][0]:
                    raise UpkError("duplicate map key")
            self.buf.append(T_MAP)
            _put_uvarint(self.buf, len(items))
            for kb, val in items:
                if len(kb) > MAX_STRING:
                    raise UpkError("map key too long")
                self.buf.append(T_STR)
                _put_uvarint(self.buf, len(kb))
                self.buf += kb
                self.value(val)
            self.depth -= 1
        else:
            raise UpkError(f"unsupported type: {type(v).__name__}")

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise UpkError("nesting too deep")


def encode(value: Any) -> bytes:
    """Encode ``value`` into its canonical upk representation."""
    w = _Writer()
    w.value(value)
    if len(w.buf) > MAX_TOTAL:
        raise UpkError("encoded value too large")
    return bytes(w.buf)


class _Reader:
    __slots__ = ("buf", "pos", "end", "depth")

    def __init__(self, buf: bytes, start: int = 0) -> None:
        self.buf = buf
        self.pos = start
        self.end = len(buf)
        self.depth = 0

    def need(self, n: int) -> None:
        if n < 0 or self.pos + n > self.end:
            raise UpkError("truncated input")

    def uvarint(self) -> int:
        result = 0
        shift = 0
        for i in range(10):
            self.need(1)
            b = self.buf[self.pos]
            self.pos += 1
            if shift == 63 and b > 1:
                raise UpkError("uvarint overflow")
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                if i > 0 and b == 0:
                    raise UpkError("non-minimal uvarint")
                return result
            shift += 7
        raise UpkError("uvarint too long")

    def svarint(self) -> int:
        z = self.uvarint()
        return (z >> 1) ^ -(z & 1)

    def value(self) -> Any:
        self.need(1)
        t = self.buf[self.pos]
        self.pos += 1
        if t == T_NULL:
            return None
        if t == T_FALSE:
            return False
        if t == T_TRUE:
            return True
        if t == T_UINT:
            return self.uvarint()
        if t == T_INT:
            return self.svarint()
        if t == T_F64:
            import struct

            self.need(8)
            v = struct.unpack(">d", self.buf[self.pos : self.pos + 8])[0]
            self.pos += 8
            return v
        if t == T_STR:
            n = self.uvarint()
            if n > MAX_STRING:
                raise UpkError("string too long")
            self.need(n)
            raw = self.buf[self.pos : self.pos + n]
            self.pos += n
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:  # pragma: no cover
                raise UpkError("invalid utf-8 string") from exc
        if t == T_BIN:
            n = self.uvarint()
            if n > MAX_STRING:
                raise UpkError("binary value too long")
            self.need(n)
            raw = self.buf[self.pos : self.pos + n]
            self.pos += n
            return raw
        if t == T_ARR:
            n = self.uvarint()
            if n > MAX_ITEMS:
                raise UpkError("array too long")
            self._enter()
            out = [self.value() for _ in range(n)]
            self.depth -= 1
            return out
        if t == T_MAP:
            n = self.uvarint()
            if n > MAX_ITEMS:
                raise UpkError("map too large")
            self._enter()
            out: Dict[str, Any] = {}
            prev: bytes | None = None
            for _ in range(n):
                self.need(1)
                if self.buf[self.pos] != T_STR:
                    raise UpkError("map key must be a string")
                self.pos += 1
                klen = self.uvarint()
                if klen > MAX_STRING:
                    raise UpkError("map key too long")
                self.need(klen)
                kb = self.buf[self.pos : self.pos + klen]
                self.pos += klen
                if prev is not None and kb <= prev:
                    raise UpkError("map keys not strictly ascending")
                prev = kb
                try:
                    key = kb.decode("utf-8")
                except UnicodeDecodeError as exc:  # pragma: no cover
                    raise UpkError("invalid utf-8 map key") from exc
                out[key] = self.value()
            self.depth -= 1
            return out
        raise UpkError(f"unknown type tag 0x{t:02x}")

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise UpkError("nesting too deep")


def decode(buf: bytes, offset: int = 0) -> Tuple[Any, int]:
    """Decode one upk value from ``buf`` starting at ``offset``.

    Returns ``(value, next_offset)`` so that callers can decode packed
    sequences of values from a stream.
    """
    r = _Reader(buf, offset)
    v = r.value()
    return v, r.pos


def decode_exact(buf: bytes) -> Any:
    """Decode exactly one value and fail on any trailing bytes."""
    v, off = decode(buf, 0)
    if off != len(buf):
        raise UpkError("trailing bytes after value")
    return v
