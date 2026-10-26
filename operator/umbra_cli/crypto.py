"""Cryptographic primitives of the UmbraC2 v1 protocol.

Design summary
--------------
* **Key exchange**  X25519 (RFC 7748) ephemeral-ephemeral per connection.
* **Authentication** HMAC-SHA256 over a canonical transcript, keyed by the
  pre-shared key.  The PSK is never transmitted and never used as a data key.
* **Key derivation** HKDF-SHA256 (RFC 5869) with fixed, versioned labels.
* **Transport encryption** AEAD, either AES-256-GCM or ChaCha20-Poly1305
  (suite negotiation decides; the frame header *is* the AAD).
* **Forward secrecy** every rekey mixes a fresh random seed into the running
  HKDF PRK, so past/future keys are not derivable from the current key.

Everything here is byte-for-byte mirrored by the Go server (``crypto`` package)
and the Rust implant (``crypto`` module) and pinned by ``contracts/vectors.json``.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.exceptions import InvalidTag

from .wire import SUITE_AES256_GCM, SUITE_CHACHA20_POLY1305

__all__ = [
    "LABEL_BOOTSTRAP",
    "LABEL_SESSION",
    "LABEL_REKEY",
    "KeyMaterial",
    "AeadError",
    "aead_encrypt",
    "aead_decrypt",
    "hmac_sha256",
    "hkdf_sha256",
    "sha256",
    "random_bytes",
    "x25519_keypair",
    "x25519_shared",
    "derive_bootstrap_key",
    "derive_session",
    "bootstrap_nonce_prefix",
    "derive_rekey",
    "hello_auth",
    "ack_auth",
    "ROLE_AGENT",
    "ROLE_OPERATOR",
]

ROLE_AGENT = 1
ROLE_OPERATOR = 2

LABEL_BOOTSTRAP = b"umbra/v1/bootstrap"
LABEL_SESSION = b"umbra/v1/session"
LABEL_REKEY = b"umbra/v1/rekey"


class AeadError(Exception):
    """Raised when authentication of an encrypted frame fails."""


# --------------------------------------------------------------------------
# hashes / mac / kdf
# --------------------------------------------------------------------------
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return _hmac.new(salt if salt else b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * 32:
        raise ValueError("hkdf output too long")
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


# --------------------------------------------------------------------------
# AEAD suites
# --------------------------------------------------------------------------
def aead_encrypt(suite: int, key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
    if suite == SUITE_AES256_GCM:
        return AESGCM(key).encrypt(nonce, pt, aad)
    if suite == SUITE_CHACHA20_POLY1305:
        return ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
    raise ValueError(f"unsupported suite {suite}")


def aead_decrypt(suite: int, key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
    try:
        if suite == SUITE_AES256_GCM:
            return AESGCM(key).decrypt(nonce, ct, aad)
        if suite == SUITE_CHACHA20_POLY1305:
            return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise AeadError("frame authentication failed") from exc
    raise ValueError(f"unsupported suite {suite}")


# --------------------------------------------------------------------------
# X25519
# --------------------------------------------------------------------------
def x25519_keypair() -> tuple[bytes, bytes]:
    priv = x25519.X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def x25519_shared(priv: bytes, peer_pub: bytes) -> bytes:
    if len(peer_pub) != 32:
        raise ValueError("x25519 public key must be 32 bytes")
    key = x25519.X25519PrivateKey.from_private_bytes(priv)
    return key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pub))


# --------------------------------------------------------------------------
# key schedule
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class KeyMaterial:
    """Directional keys + nonce prefixes produced by the key schedule."""

    c2s_key: bytes
    s2c_key: bytes
    c2s_prefix: bytes
    s2c_prefix: bytes

    @classmethod
    def from_okm(cls, okm: bytes) -> "KeyMaterial":
        if len(okm) != 72:
            raise ValueError("okm must be 72 bytes")
        return cls(
            c2s_key=okm[0:32],
            s2c_key=okm[32:64],
            c2s_prefix=okm[64:68],
            s2c_prefix=okm[68:72],
        )


def derive_bootstrap_key(psk: bytes, direction: str, suite: int) -> bytes:
    """PSK-derived one-way key used before a session exists.

    ``direction`` is ``"c2s"`` or ``"s2c"``; the direction-specific info string
    means the two directions can never share a keystream.
    """
    if direction not in ("c2s", "s2c"):
        raise ValueError("direction must be c2s or s2c")
    info = LABEL_BOOTSTRAP + b"/" + direction.encode()
    psk = _normalise_psk(psk, suite)
    return hkdf_sha256(ikm=psk, salt=LABEL_BOOTSTRAP, info=info, length=32)


def derive_session(
    shared: bytes, client_nonce: bytes, server_nonce: bytes
) -> tuple[bytes, KeyMaterial]:
    """Derive the master PRK and the first directional key set of a session."""
    if len(client_nonce) != 16 or len(server_nonce) != 16:
        raise ValueError("handshake nonces must be 16 bytes")
    salt = sha256(LABEL_SESSION + client_nonce + server_nonce)
    prk = hkdf_extract(salt, shared)
    okm = hkdf_expand(prk, LABEL_SESSION + b"/keys", 72)
    return prk, KeyMaterial.from_okm(okm)


def bootstrap_nonce_prefix(key: bytes) -> bytes:
    """Directional 4-byte nonce prefix for the PSK/bootstrap phase."""
    return hkdf_sha256(ikm=key, salt=LABEL_BOOTSTRAP, info=b"nonce-prefix", length=4)


def derive_rekey(prk: bytes, seed: bytes) -> tuple[bytes, KeyMaterial]:
    """Mix a fresh 32-byte seed into the running PRK and derive new keys."""
    if len(seed) != 32:
        raise ValueError("rekey seed must be 32 bytes")
    new_prk = hkdf_extract(salt=seed, ikm=prk)
    okm = hkdf_expand(new_prk, LABEL_REKEY + b"/keys", 72)
    return new_prk, KeyMaterial.from_okm(okm)


def _normalise_psk(psk: bytes, suite: int) -> bytes:
    """The PSK is any byte string; it is bound to the negotiated suite."""
    return hkdf_sha256(
        ikm=psk,
        salt=LABEL_BOOTSTRAP + b"/psk",
        info=b"suite:" + struct.pack(">B", suite),
        length=32,
    )


# --------------------------------------------------------------------------
# handshake authentication transcript
# --------------------------------------------------------------------------
def hello_auth(
    psk: bytes,
    *,
    role: int,
    ident: bytes,
    client_pub: bytes,
    client_nonce: bytes,
    timestamp: int,
    suite: int,
) -> bytes:
    if len(ident) > 255:
        raise ValueError("identity too long")
    msg = (
        LABEL_BOOTSTRAP
        + b"/auth/hello"
        + bytes([role & 0xFF, len(ident)])
        + ident
        + client_pub
        + client_nonce
        + struct.pack(">Q", timestamp)
        + bytes([suite])
    )
    return hmac_sha256(psk, msg)


def ack_auth(
    psk: bytes,
    *,
    ident: bytes,
    client_pub: bytes,
    server_pub: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
    session_id: bytes,
    suite: int,
) -> bytes:
    if len(ident) > 255:
        raise ValueError("identity too long")
    msg = (
        LABEL_BOOTSTRAP
        + b"/auth/ack"
        + bytes([len(ident)])
        + ident
        + client_pub
        + server_pub
        + client_nonce
        + server_nonce
        + session_id
        + bytes([suite])
    )
    return hmac_sha256(psk, msg)


def constant_time_eq(a: Optional[bytes], b: Optional[bytes]) -> bool:
    if a is None or b is None:
        return False
    return _hmac.compare_digest(a, b)
