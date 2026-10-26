"""Wire format of the UmbraC2 v1 agent protocol.

Every byte that crosses the network is wrapped in an authenticated, encrypted
frame.  There is no cleartext path in the protocol at all; even the handshake
messages are encrypted (under a bootstrap key derived from the pre-shared key).

Frame layout (all integers big endian)::

    prelude (12 bytes, cleartext, authenticated as AEAD AAD)
    +---------------------------------------------------+
    | 0..1  magic 0x55 0x43 ("UC")                      |
    | 2     protocol version (1)                        |
    | 3     flags (bit0: 1 = bootstrap/PSK phase)        |
    | 4     message type                                 |
    | 5     AEAD suite id                                |
    | 6..7  reserved, must be zero                       |
    | 8..11 payload length (plaintext size, u32 BE)       |
    +---------------------------------------------------+
    | 12..23 nonce (4-byte per-direction prefix + 8-byte counter) |
    | 24..   ciphertext || 16-byte tag                    |

The length field is cleartext on purpose: transports need framing without
holding keys, and bounds checking can happen before any crypto work.  The
length is bound into the AAD so it cannot be tampered with.

Nonces are never random per frame; each direction owns a 32-bit prefix and a
monotonically increasing 64-bit counter.  Reusing a nonce under the same key is
therefore impossible as long as a key is retired after ``REKEY_AFTER`` frames
(the session enforces this automatically).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Tuple

from . import upk

__all__ = [
    "MAGIC",
    "VERSION",
    "PRELUDE_LEN",
    "NONCE_LEN",
    "HEADER_LEN",
    "TAG_LEN",
    "MAX_BODY",
    "MAX_FRAME",
    "SUITE_AES256_GCM",
    "SUITE_CHACHA20_POLY1305",
    "SUITE_NAMES",
    "FLAG_BOOTSTRAP",
    "FRAME_VERSION",
    "Frame",
    "build_frame",
    "parse_header",
    "MsgType",
    "make_nonce",
]

MAGIC = b"\x55\x43"
VERSION = 1
PRELUDE_LEN = 12
NONCE_LEN = 12
TAG_LEN = 16
HEADER_LEN = PRELUDE_LEN + NONCE_LEN

MAX_BODY = 1 << 20  # 1 MiB of plaintext per frame
MAX_FRAME = HEADER_LEN + MAX_BODY + TAG_LEN

SUITE_AES256_GCM = 1
SUITE_CHACHA20_POLY1305 = 2
SUITE_NAMES = {
    SUITE_AES256_GCM: "aes-256-gcm",
    SUITE_CHACHA20_POLY1305: "chacha20-poly1305",
}

FLAG_BOOTSTRAP = 0x01


class MsgType:
    """Message type registry. Values are stable wire constants."""

    # handshake (bootstrap keys)
    HELLO = 0x01
    HELLO_ACK = 0x02

    # agent <-> server (session keys)
    CHECKIN = 0x10
    TASK_BATCH = 0x11
    RESULT = 0x12
    CONFIG = 0x13
    PING = 0x14
    PONG = 0x15
    REKEY = 0x16
    KILL = 0x17
    TASK_CANCEL = 0x18
    BYE = 0x19

    # pivoting tunnel frames (agent dials back, streams are multiplexed)
    TUNNEL_OPEN = 0x1A
    TUNNEL_DATA = 0x1B
    TUNNEL_CLOSE = 0x1C

    # padding frames: random bytes, ignored by the receiver
    PADDING = 0x1E

    # errors / control
    ERROR = 0x1F

    # operator <-> server (session keys, same framing)
    OP_REQUEST = 0x20
    OP_RESPONSE = 0x21
    OP_EVENT = 0x22

    # payload markers inside the handshake frames
    FRAME_VERSION = 0x01
    FRAME_HELLO_ACK = 0x02


# Payload marker understood by peers as "handshake body version 1".
FRAME_VERSION = MsgType.FRAME_VERSION

TYPE_NAMES = {
    v: k
    for k, v in vars(MsgType).items()
    if not k.startswith("_") and isinstance(v, int)
}


@dataclass(frozen=True)
class Frame:
    version: int
    flags: int
    type: int
    suite: int
    length: int
    nonce: bytes
    prelude: bytes
    body: bytes  # ciphertext + tag

    @property
    def aad(self) -> bytes:
        return self.prelude


def make_nonce(prefix4: bytes, counter: int) -> bytes:
    if len(prefix4) != 4:
        raise ValueError("nonce prefix must be 4 bytes")
    if counter < 0 or counter >= 1 << 64:
        raise ValueError("nonce counter out of range")
    return prefix4 + struct.pack(">Q", counter)


def build_frame(
    *,
    suite: int,
    flags: int,
    msg_type: int,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aead_encrypt,
) -> bytes:
    """Assemble one encrypted frame.

    ``aead_encrypt(key, nonce, aad, plaintext) -> ciphertext||tag`` is injected
    so this module stays free of crypto implementations.
    """
    if len(plaintext) > MAX_BODY:
        raise ValueError("payload too large")
    if suite not in SUITE_NAMES:
        raise ValueError("unknown suite")
    prelude = (
        MAGIC
        + bytes([VERSION, flags & 0xFF, msg_type & 0xFF, suite & 0xFF, 0, 0])
        + struct.pack(">I", len(plaintext))
    )
    assert len(prelude) == PRELUDE_LEN
    body = aead_encrypt(key, nonce, prelude, plaintext)
    return prelude + nonce + body


def parse_header(raw: bytes) -> Tuple[Frame, int]:
    """Parse and validate a frame header; returns ``(frame, offset_of_body)``."""
    if len(raw) < HEADER_LEN:
        raise ValueError("truncated frame header")
    if raw[0:2] != MAGIC:
        raise ValueError("bad magic")
    version, flags, msg_type, suite = raw[2], raw[3], raw[4], raw[5]
    if version != VERSION:
        raise ValueError(f"unsupported protocol version {version}")
    if raw[6] or raw[7]:
        raise ValueError("reserved prelude bytes must be zero")
    if suite not in SUITE_NAMES:
        raise ValueError(f"unknown suite {suite}")
    (length,) = struct.unpack(">I", raw[8:12])
    if length > MAX_BODY:
        raise ValueError("frame body too large")
    nonce = raw[PRELUDE_LEN:HEADER_LEN]
    return (
        Frame(
            version=version,
            flags=flags,
            type=msg_type,
            suite=suite,
            length=length,
            nonce=nonce,
            prelude=raw[:PRELUDE_LEN],
            body=b"",
        ),
        HEADER_LEN,
    )


def encode_body(msg: dict) -> bytes:
    """Encode a protocol message body (upk map, optionally prefixed)."""
    return upk.encode(msg)


def decode_body(raw: bytes) -> dict:
    v = upk.decode_exact(raw)
    if not isinstance(v, dict):
        raise ValueError("protocol body must be a map")
    return v
