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

Two handshake versions exist, and a server speaks both:

``v=1``
    The original shape.  The capability list travels inside the metadata,
    the implant version is inside the metadata, and the server answers with
    the original HELLO_ACK.

``v=2``
    The capability list, the implant version, the module ABI version and
    the platform details are first-class fields of the HELLO, and the
    answer carries the ABI the server speaks, the handshake versions the
    server accepts and the limits of the queue.  A beacon that only knows
    ``v=1`` keeps working: the server answers in the version it was asked
    for.  The matrix is in docs/PROTOCOL.md.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
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

# The handshake versions this build speaks, newest first.
#
# The server accepts every version in this list; the answer is always in
# the version the peer asked for, so an old beacon never sees a field it
# does not understand.
HELLO_VERSIONS = (wire.HELLO_VERSION, 1)

# The module ABI version this build speaks.
#
# The ABI is the contract between the host and the modules it loads: a
# module that was built for another ABI is refused by the host, so the
# server has to know what the beacon understands.
ABI_VERSION = wire.ABI_VERSION


class HandshakeError(Exception):
    pass


@dataclass(frozen=True)
class KeyringEntry:
    """One accepted pre-shared key and the role it is allowed to claim.

    ``bound_id`` is the agent id the key may claim.  It is empty for a
    fleet key, which may claim any name, and it names one host for a key
    that belongs to that host: the identity of the beacon is then proved
    by the key and not only by the name it says.
    """

    name: str
    psk: bytes
    role: int
    bound_id: str = ""


@dataclass
class HandshakeResult:
    session: session.Session
    peer_id: str
    session_id: bytes
    suite: int
    meta: dict
    cfg: dict
    # The handshake version that was used, and the fields the newer
    # handshake carries.
    version: int = 1
    caps: tuple = ()
    implant_version: str = ""
    abi: int = 0
    platform: dict = field(default_factory=dict)
    # What the server said about itself: the ABI it speaks, the versions
    # it accepts and the limits of the queue.
    server_abi: int = 0
    compat: tuple = ()
    limits: dict = field(default_factory=dict)


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
    version: int = 1,
    caps: Optional[Sequence[str]] = None,
    implant_version: str = "",
    abi: int = 0,
    platform: Optional[dict] = None,
) -> HandshakeResult:
    """The client side of the handshake.

    ``version`` is the handshake version to speak.  Version 2 adds the
    first-class fields: the capability list, the implant version, the
    module ABI version and the platform details.
    """
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
    if version not in HELLO_VERSIONS:
        raise HandshakeError(f"unsupported handshake version {version}")
    hello = {
        "v": version,
        "role": role,
        "id": ident,
        "pub": pub,
        "cn": cn,
        "ts": ts,
        "suite": suite,
        "auth": auth,
        "meta": meta or {},
    }
    if version >= 2:
        # The capability list is a first-class field now: the server
        # refuses work the beacon cannot do, and it needs the list before
        # it looks at the metadata.
        hello["caps"] = list(caps or [])
        hello["iver"] = implant_version
        hello["abi"] = int(abi)
        hello["plat"] = dict(platform or {})
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
    if not isinstance(ack, dict) or ack.get("v") not in HELLO_VERSIONS:
        raise HandshakeError("bad HELLO_ACK body")
    ack_version = int(ack.get("v", 1))

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
        version=version,
        caps=tuple(str(c) for c in (caps or [])),
        implant_version=implant_version,
        abi=int(abi),
        platform=dict(platform or {}),
        server_abi=int(ack.get("abi", 0) or 0),
        compat=tuple(int(v) for v in (ack.get("compat", []) or [])),
        limits=dict(ack.get("limits", {}) or {}),
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
    limits: Optional[dict] = None,
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
                if not isinstance(body, dict):
                    raise HandshakeError("bad HELLO body")
                # The server speaks every version it knows: the answer is
                # always in the version the peer asked for.
                if body.get("v") not in HELLO_VERSIONS:
                    raise HandshakeError(f"unsupported HELLO version {body.get('v')}")
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
    if entry.role == crypto.ROLE_AGENT and entry.bound_id and ident != entry.bound_id:
        raise HandshakeError(
            f"the key is bound to agent {entry.bound_id!r}, not {ident!r}"
        )
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
    version = int(hello.get("v", 1))
    ack = {
        "v": version,
        "pub": pub,
        "sn": sn,
        "sid": sid,
        "suite": suite,
        "auth": ack_mac,
        "cfg": cfg or server_config(),
        "name": "umbra-server",
        "meta": {"ver": "0.1.0"},
    }
    if version >= 2:
        # What the server speaks, what it accepts and the limits of the
        # queue: a beacon that knows the limits can pace itself.
        ack["abi"] = ABI_VERSION
        ack["compat"] = list(HELLO_VERSIONS)
        ack["limits"] = dict(limits or {})
    if on_peer is not None:
        on_peer(ident, role, hello.get("meta", {}) or {})
    stream.send_frame(boot.encrypt(wire.MsgType.HELLO_ACK, b"\x02" + upk.encode(ack)))

    sess = session.Session(
        suite=suite, material=material, is_server=True, bootstrap=False, prk=prk
    )
    caps = hello.get("caps")
    if not isinstance(caps, (list, tuple)):
        # A version 1 beacon keeps the capability list in the metadata.
        caps = (hello.get("meta", {}) or {}).get("caps", [])
    platform = hello.get("plat")
    if not isinstance(platform, dict):
        platform = {}
    return HandshakeResult(
        session=sess,
        peer_id=ident,
        session_id=sid,
        suite=suite,
        meta=hello.get("meta", {}) or {},
        cfg=ack["cfg"],
        version=version,
        caps=tuple(str(c) for c in caps),
        implant_version=str(hello.get("iver", "") or ""),
        abi=int(hello.get("abi", 0) or 0),
        platform=dict(platform),
        server_abi=int(ack.get("abi", 0) or 0),
        compat=tuple(int(v) for v in (ack.get("compat", []) or [])),
        limits=dict(ack.get("limits", {}) or {}),
    )
