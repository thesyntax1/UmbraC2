"""Encrypted session state machine (shared by the operator client and tests).

A ``Session`` owns both directions of one connection:

* outgoing direction: key + 4-byte nonce prefix + 64-bit counter
* incoming direction: same, and the counter must match *exactly* what the peer
  should have used -- any replay, reorder or gap is a protocol error.

Keys are retired after ``REKEY_AFTER`` frames (the peer drives rotation by
sending ``REKEY``), which guarantees nonce uniqueness for the lifetime of a key.
"""

from __future__ import annotations

import struct
import threading
from dataclasses import dataclass, field
from typing import Optional, Tuple

from . import crypto, upk, wire

__all__ = [
    "Session",
    "SessionError",
    "Direction",
    "REKEY_AFTER",
    "frame_length",
    "MAX_CLOCK_SKEW",
]

REKEY_AFTER = 1 << 20  # frames per key, ~1M * 1MiB headroom
MAX_CLOCK_SKEW = 300  # seconds tolerated between client and server clocks


class SessionError(Exception):
    """Protocol level failure (bad frame, replay, wrong suite, ...)."""


@dataclass
class Direction:
    """One half of a session.

    The counter is guarded by ``lock``.  Encrypting and advancing must be a
    single atomic reservation: if two threads peeked the same counter the
    connection would seal two frames under the *same* (key, nonce) pair, which
    destroys AES-GCM/ChaCha20-Poly1305 (keystream reuse and, for GCM, recovery
    of the authentication key).  Always take a nonce with :meth:`reserve_nonce`.
    """

    key: bytes
    prefix: bytes
    counter: int = 0
    frames: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def peek_nonce(self) -> bytes:
        with self.lock:
            return wire.make_nonce(self.prefix, self.counter)

    def reserve_nonce(self) -> bytes:
        """Atomically take the next nonce and burn it. Not for reuse on retry."""
        key, nonce = self.reserve_frame()
        return nonce

    def reserve_frame(self) -> Tuple[bytes, bytes]:
        """Atomically snapshot the current key and burn the next nonce.

        Taking both together matters: a concurrent :meth:`rotate` between the
        key read and the counter bump would seal a frame under the new key with
        a counter the peer has already consumed.
        """
        with self.lock:
            key = self.key
            nonce = wire.make_nonce(self.prefix, self.counter)
            self.counter += 1
            self.frames += 1
            return key, nonce

    def advance(self) -> None:
        with self.lock:
            self.counter += 1
            self.frames += 1

    def rotate(self, key: bytes, prefix: bytes) -> None:
        with self.lock:
            self.key = key
            self.prefix = prefix
            self.counter = 0
            self.frames = 0


def frame_length(header: bytes) -> int:
    """Total on-wire size of the frame whose header starts with ``header``."""
    if len(header) < wire.PRELUDE_LEN:
        raise SessionError("truncated prelude")
    if header[0:2] != wire.MAGIC:
        raise SessionError("bad magic")
    (length,) = struct.unpack(">I", header[8:12])
    if length > wire.MAX_BODY:
        raise SessionError("frame too large")
    return wire.HEADER_LEN + length + wire.TAG_LEN


class Session:
    """One encrypted link. ``is_server`` flips the direction of the keys."""

    def __init__(
        self,
        *,
        suite: int,
        material: crypto.KeyMaterial,
        is_server: bool,
        bootstrap: bool = False,
        prk: bytes = b"",
    ) -> None:
        self.suite = suite
        self.is_server = is_server
        self.bootstrap = bootstrap
        self.prk = prk
        self.flags = wire.FLAG_BOOTSTRAP if bootstrap else 0
        if bootstrap:
            # The PSK phase has no nonces on the wire yet; derive the
            # per-direction prefixes from the directional bootstrap keys.
            material = crypto.KeyMaterial(
                c2s_key=material.c2s_key,
                s2c_key=material.s2c_key,
                c2s_prefix=crypto.bootstrap_nonce_prefix(material.c2s_key),
                s2c_prefix=crypto.bootstrap_nonce_prefix(material.s2c_key),
            )
        if is_server:
            self.send_dir = Direction(material.s2c_key, material.s2c_prefix)
            self.recv_dir = Direction(material.c2s_key, material.c2s_prefix)
        else:
            self.send_dir = Direction(material.c2s_key, material.c2s_prefix)
            self.recv_dir = Direction(material.s2c_key, material.s2c_prefix)

    # -- framing ---------------------------------------------------------
    def encrypt(self, msg_type: int, body) -> bytes:
        if isinstance(body, dict):
            body = upk.encode(body)
        # Reserve before sealing: the nonce is burned even if sealing fails, so a
        # retry can never reuse it, and key + counter are snapshotted together so
        # a concurrent rekey cannot mix an old counter with a new key.
        key, nonce = self.send_dir.reserve_frame()
        frame = wire.build_frame(
            suite=self.suite,
            flags=self.flags,
            msg_type=msg_type,
            key=key,
            nonce=nonce,
            plaintext=body,
            aead_encrypt=lambda k, n, a, p: crypto.aead_encrypt(self.suite, k, n, a, p),
        )
        return frame

    def decrypt(self, raw: bytes) -> Tuple[int, bytes]:
        frame, off = wire.parse_header(raw)
        expected_len = off + frame.length + wire.TAG_LEN
        if len(raw) != expected_len:
            raise SessionError(f"frame size mismatch: got {len(raw)} want {expected_len}")
        if frame.flags != self.flags:
            raise SessionError("unexpected frame flags (bootstrap/session mixup)")
        if frame.suite != self.suite:
            raise SessionError("unexpected AEAD suite")
        expected_nonce = self.recv_dir.peek_nonce()
        if not crypto.constant_time_eq(frame.nonce, expected_nonce):
            raise SessionError("nonce mismatch (replay, reorder or desync)")
        body = raw[off:]
        try:
            pt = crypto.aead_decrypt(self.suite, self.recv_dir.key, frame.nonce, frame.aad, body)
        except crypto.AeadError as exc:
            raise SessionError(str(exc)) from exc
        if len(pt) != frame.length:
            raise SessionError("length mismatch after decryption")
        self.recv_dir.advance()
        return frame.type, pt

    def decrypt_message(self, raw: bytes) -> Tuple[int, dict]:
        msg_type, pt = self.decrypt(raw)
        return msg_type, wire.decode_body(pt)

    # -- rekey -----------------------------------------------------------
    def needs_rekey(self, threshold: Optional[int] = None) -> bool:
        """True once either direction has carried ``threshold`` frames."""
        limit = REKEY_AFTER if threshold is None else int(threshold)
        return max(self.send_dir.frames, self.recv_dir.frames) >= limit

    def apply_rekey(self, seed: bytes) -> None:
        if not self.prk:
            raise SessionError("session has no PRK (bootstrap sessions cannot rekey)")
        self.prk, material = crypto.derive_rekey(self.prk, seed)
        if self.is_server:
            self.send_dir.rotate(material.s2c_key, material.s2c_prefix)
            self.recv_dir.rotate(material.c2s_key, material.c2s_prefix)
        else:
            self.send_dir.rotate(material.c2s_key, material.c2s_prefix)
            self.recv_dir.rotate(material.s2c_key, material.s2c_prefix)


@dataclass
class BootstrapState:
    """Everything needed to build/verify the handshake for one connection."""

    suite: int
    psk: bytes
    priv: bytes
    pub: bytes
    client_nonce: bytes = field(default_factory=lambda: crypto.random_bytes(16))

    @classmethod
    def new(cls, psk: bytes, suite: int) -> "BootstrapState":
        priv, pub = crypto.x25519_keypair()
        return cls(suite=suite, psk=psk, priv=priv, pub=pub)

    def _psk_session(self, is_server: bool) -> Session:
        material = crypto.KeyMaterial(
            c2s_key=crypto.derive_bootstrap_key(self.psk, "c2s", self.suite),
            s2c_key=crypto.derive_bootstrap_key(self.psk, "s2c", self.suite),
            c2s_prefix=b"",
            s2c_prefix=b"",
        )
        return Session(
            suite=self.suite, material=material, is_server=is_server, bootstrap=True
        )

    def session_for_server(self) -> Session:
        return self._psk_session(is_server=True)

    def session_for_client(self) -> Session:
        return self._psk_session(is_server=False)
