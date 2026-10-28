"""The UmbraC2 v1 handshake, client and server side.

Wire flow (both messages are AEAD protected under PSK-derived bootstrap keys)::

    client                                  server
      |  HELLO {v,role,id,pub,cn,ts,suite,auth} |
      | --------------------------------------> |
      |                                         | verify auth HMAC + clock skew
      |  HELLO_ACK {v,pub,sn,sid,suite,auth,cfg}|
      | <-------------------------------------- |
      | verify auth HMAC                        |
      |                                         |
      |  === switch to X25519/HKDF session keys ===

``auth`` is HMAC-SHA256(PSK, transcript).  The transcript binds both role and
identity, both public keys, both nonces, the session id and the negotiated
suite, so it cannot be replayed into a different context.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from . import crypto, netio, session, upk, wire

__all__ = [
    "HandshakeError",
    "HandshakeResult",
    "KeyringEntry",
    "client_handshake",
    "server_handshake",
    "server_config",
]

MAX_SKEW = session.MAX_CLOCK_SKEW


class HandshakeError(Exception):
    pass


@dataclass(frozen=True)
class KeyringEntry:
    """One accepted pre-shared key and the role it is allowed to claim."""

    name: str
    psk: bytes
    role: int


@dataclass
class HandshakeResult:
    session: session.Session
    peer_id: str
    session_id: bytes
    suite: int
    meta: dict
    cfg: dict


def _negotiate(client_suite: int, server_suites: Sequence[int]) -> int:
    if client_suite not in server_suites:
        raise HandshakeError(f"suite {client_suite} not offered by server")
    return client_suite


def server_config() -> dict:
    """Server-side beacon policy handed to agents at handshake time."""
    return {"sleep": 5, "jitter": 20}


# --------------------------------------------------------------------------
# client
# --------------------------------------------------------------------------
def client_handshake(
    stream: netio.Stream,
    *,
    psk: bytes,
    role: int,
    ident: str,
    suite: int = wire.SUITE_AES256_GCM,
    meta: Optional[dict] = None,
) -> HandshakeResult:
    priv, pub = crypto.x25519_keypair()
    cn = crypto.random_bytes(16)
    ts = int(time.time())
    ident_b = ident.encode()

    auth = crypto.hello_auth(
        psk,
        role=role,
        ident=ident_b,
        client_pub=pub,
        client_nonce=cn,
        timestamp=ts,
        suite=suite,
    )
    hello = {
        "v": 1,
        "role": role,
        "id": ident,
        "pub": pub,
        "cn": cn,
        "ts": ts,
        "suite": suite,
        "auth": auth,
        "meta": meta or {},
    }
    boot = session.Session(
        suite=suite,
        material=crypto.KeyMaterial(
            c2s_key=crypto.derive_bootstrap_key(psk, "c2s", suite),
            s2c_key=crypto.derive_bootstrap_key(psk, "s2c", suite),
            c2s_prefix=b"",
            s2c_prefix=b"",
        ),
        is_server=False,
        bootstrap=True,
    )
    stream.send_frame(boot.encrypt(wire.MsgType.HELLO, b"\x01" + upk.encode(hello)))

    raw = stream.recv_frame()
    msg_type, pt = boot.decrypt(raw)
    if msg_type != wire.MsgType.HELLO_ACK:
        raise HandshakeError(f"expected HELLO_ACK, got 0x{msg_type:02x}")
    if not pt or pt[0] != wire.MsgType.FRAME_HELLO_ACK:
        raise HandshakeError("bad HELLO_ACK payload marker")
    ack = upk.decode_exact(pt[1:])
    if not isinstance(ack, dict) or ack.get("v") != 1:
        raise HandshakeError("bad HELLO_ACK body")

    server_pub = ack["pub"]
    sn = ack["sn"]
    sid = ack["sid"]
    neg_suite = ack["suite"]
    if len(server_pub) != 32 or len(sn) != 16 or len(sid) != 16:
        raise HandshakeError("malformed HELLO_ACK fields")
    if neg_suite != suite:
        raise HandshakeError("server changed suite without negotiation")

    want = crypto.ack_auth(
        psk,
        ident=ident_b,
        client_pub=pub,
        server_pub=server_pub,
        client_nonce=cn,
        server_nonce=sn,
        session_id=sid,
        suite=neg_suite,
    )
    if not crypto.constant_time_eq(want, ack.get("auth")):
        raise HandshakeError("server authentication failed (bad PSK?)")

    prk, material = crypto.derive_session(crypto.x25519_shared(priv, server_pub), cn, sn)
    sess = session.Session(
        suite=neg_suite, material=material, is_server=False, bootstrap=False, prk=prk
    )
    return HandshakeResult(
        session=sess,
        peer_id=str(ack.get("name", "")),
        session_id=sid,
        suite=neg_suite,
        meta=ack.get("meta", {}) or {},
        cfg=ack.get("cfg", {}) or {},
    )


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------
def server_handshake(
    stream: netio.Stream,
    *,
    keyring: "Sequence[KeyringEntry]",
    suites: Sequence[int] = (wire.SUITE_AES256_GCM,),
    cfg: Optional[dict] = None,
    on_peer: Optional[Callable[[str, int, dict], None]] = None,
) -> HandshakeResult:
    """Server side of the handshake.

    ``keyring`` is a list of ``KeyringEntry`` (agent PSK, or one operator token
    per operator). The HELLO is encrypted under a key the server cannot know in
    advance, so every (suite, key) pair is tried; the key that authenticates the
    HELLO decides the caller's role, and an operator token only works for the
    identity it was issued to.

    ``on_peer`` is called once the peer is authenticated and *before* the
    HELLO_ACK goes out.  A server that pushes events to the peer (the
    operator console) subscribes it there: the console believes it is
    connected as soon as the HELLO_ACK arrives, so an event that is emitted in
    the same breath must already have a subscriber.
    """
    raw = stream.recv_frame()

    hello = None
    boot = None
    chosen = None
    last_err = None
    for suite in suites:
        for entry in keyring:
            try:
                candidate = session.Session(
                    suite=suite,
                    material=crypto.KeyMaterial(
                        c2s_key=crypto.derive_bootstrap_key(entry.psk, "c2s", suite),
                        s2c_key=crypto.derive_bootstrap_key(entry.psk, "s2c", suite),
                        c2s_prefix=b"",
                        s2c_prefix=b"",
                    ),
                    is_server=True,
                    bootstrap=True,
                )
                msg_type, pt = candidate.decrypt(raw)
                if msg_type != wire.MsgType.HELLO:
                    raise HandshakeError("expected HELLO")
                if not pt or pt[0] != wire.MsgType.FRAME_VERSION:
                    raise HandshakeError("bad HELLO payload marker")
                body = upk.decode_exact(pt[1:])
                if not isinstance(body, dict) or body.get("v") != 1:
                    raise HandshakeError("bad HELLO body")
                hello, boot, chosen = body, candidate, (suite, entry)
                break
            except (session.SessionError, upk.UpkError, crypto.AeadError, ValueError) as exc:
                last_err = exc
                continue
        if hello is not None:
            break
    if hello is None or boot is None or chosen is None:
        raise HandshakeError(f"no key/suite accepted HELLO: {last_err}")

    suite, entry = chosen
    role = hello.get("role")
    ident = str(hello.get("id", ""))
    client_pub = hello.get("pub")
    cn = hello.get("cn")
    ts = hello.get("ts")
    if role not in (crypto.ROLE_AGENT, crypto.ROLE_OPERATOR):
        raise HandshakeError("invalid role")
    if not ident or len(ident) > 128:
        raise HandshakeError("invalid identity")
    if isinstance(client_pub, (bytes, bytearray)) is False or len(client_pub) != 32:
        raise HandshakeError("invalid client public key")
    if not isinstance(cn, (bytes, bytearray)) or len(cn) != 16:
        raise HandshakeError("invalid client nonce")
    if not isinstance(ts, int) or abs(time.time() - ts) > MAX_SKEW:
        raise HandshakeError("handshake timestamp outside allowed skew")
    if role != entry.role:
        raise HandshakeError(f"role {role} not allowed for key {entry.name!r}")
    if entry.role == crypto.ROLE_OPERATOR and ident != entry.name:
        raise HandshakeError("operator token used by a different identity")
    if hello.get("suite") != suite:
        raise HandshakeError("suite mismatch in HELLO")

    want = crypto.hello_auth(
        entry.psk,
        role=role,
        ident=ident.encode(),
        client_pub=bytes(client_pub),
        client_nonce=bytes(cn),
        timestamp=ts,
        suite=suite,
    )
    if not crypto.constant_time_eq(want, hello.get("auth")):
        raise HandshakeError("client authentication failed (bad PSK?)")

    priv, pub = crypto.x25519_keypair()
    sn = crypto.random_bytes(16)
    sid = crypto.random_bytes(16)
    shared = crypto.x25519_shared(priv, bytes(client_pub))
    prk, material = crypto.derive_session(shared, bytes(cn), sn)
    ack_mac = crypto.ack_auth(
        entry.psk,
        ident=ident.encode(),
        client_pub=bytes(client_pub),
        server_pub=pub,
        client_nonce=bytes(cn),
        server_nonce=sn,
        session_id=sid,
        suite=suite,
    )
    ack = {
        "v": 1,
        "pub": pub,
        "sn": sn,
        "sid": sid,
        "suite": suite,
        "auth": ack_mac,
        "cfg": cfg or server_config(),
        "name": "umbra-server",
        "meta": {"ver": "0.1.0"},
    }
    if on_peer is not None:
        on_peer(ident, role, hello.get("meta", {}) or {})
    stream.send_frame(boot.encrypt(wire.MsgType.HELLO_ACK, b"\x02" + upk.encode(ack)))

    sess = session.Session(
        suite=suite, material=material, is_server=True, bootstrap=False, prk=prk
    )
    return HandshakeResult(
        session=sess,
        peer_id=ident,
        session_id=sid,
        suite=suite,
        meta=hello.get("meta", {}) or {},
        cfg=ack["cfg"],
    )
