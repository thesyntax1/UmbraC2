#!/usr/bin/env python3
"""Generate contracts/vectors.json -- the cross-language conformance vectors.

The Go server, the Rust implant and the Python operator CLI must all produce
(and accept) exactly these bytes.  Run this script only when the protocol
changes; the file is committed so every implementation can test itself offline:

    python3 tools/gen_vectors.py
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "operator"))

from umbra_cli import crypto, upk, wire  # noqa: E402

PSK = bytes(range(32))
CLIENT_PRIV = bytes.fromhex("77" * 32)
SERVER_PRIV = bytes.fromhex("3a" * 32)
CLIENT_PUB = bytes.fromhex(
    "b0f9f2e1e0d3e1cd51bb9e5f39f9ecb7f5d4f4b6c38b8c5ad2c7d1e5a1c3f9b7"
)
CNONCE = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
SNONCE = bytes.fromhex("1112131415161718191a1b1c1d1e1f20")
SID = bytes.fromhex("aabbccddeeff00112233445566778899")
SEED = bytes.fromhex("5e" * 32)
TS = 1735689600  # 2025-01-01T00:00:00Z


def b(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr)


def main() -> None:
    out = {
        "meta": {
            "protocol": "umbra/v1",
            "generated_by": "tools/gen_vectors.py",
            "suites": {"aes-256-gcm": wire.SUITE_AES256_GCM,
                       "chacha20-poly1305": wire.SUITE_CHACHA20_POLY1305},
            "roles": {"agent": crypto.ROLE_AGENT, "operator": crypto.ROLE_OPERATOR},
            "frame": {
                "magic": wire.MAGIC.hex(),
                "version": wire.VERSION,
                "prelude_len": wire.PRELUDE_LEN,
                "nonce_len": wire.NONCE_LEN,
                "tag_len": wire.TAG_LEN,
                "header_len": wire.HEADER_LEN,
                "max_body": wire.MAX_BODY,
            },
        },
        "psk": PSK.hex(),
    }

    # ---- upk canonical encoding ----------------------------------------
    upk_cases = [
        ("null", None),
        ("false", False),
        ("true", True),
        ("uint-0", 0),
        ("uint-127", 127),
        ("uint-128", 128),
        ("uint-300", 300),
        ("uint-max", (1 << 64) - 1),
        ("int--1", -1),
        ("int--65", -65),
        ("int-min", -(1 << 63)),
        ("str-empty", ""),
        ("str-ascii", "umbra"),
        ("str-utf8", "şifreli"),
        ("bin", b("0001feff")),
        ("array", [1, "a", None, True]),
        ("map-order", {"b": 1, "a": 2}),
        ("nested", {"k": [{"x": -2}, b""]}),
        ("f64", 1.5),
        # Exactly MAX_DEPTH nested containers is legal; one more is not. This
        # pins the depth convention, which is easy to get off by one (Rust and
        # Kotlin both allowed 17 levels before this vector existed).
        ("depth-max", _nested(upk.MAX_DEPTH)),
    ]
    out["upk"] = [{"name": n, "json": _jsonable(v), "hex": upk.encode(v).hex()}
                  for n, v in upk_cases]

    # ---- key schedule --------------------------------------------------
    # public keys derived from the fixed private keys (RFC 7748 base point)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519

    def pub_of(priv: bytes) -> bytes:
        return (
            x25519.X25519PrivateKey.from_private_bytes(priv)
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )

    cpub, spub = pub_of(CLIENT_PRIV), pub_of(SERVER_PRIV)
    shared = crypto.x25519_shared(CLIENT_PRIV, spub)
    assert shared == crypto.x25519_shared(SERVER_PRIV, cpub)

    prk, km = crypto.derive_session(shared, CNONCE, SNONCE)
    out["session"] = {
        "client_priv": CLIENT_PRIV.hex(),
        "client_pub": cpub.hex(),
        "server_priv": SERVER_PRIV.hex(),
        "server_pub": spub.hex(),
        "shared": shared.hex(),
        "client_nonce": CNONCE.hex(),
        "server_nonce": SNONCE.hex(),
        "prk": prk.hex(),
        "c2s_key": km.c2s_key.hex(),
        "s2c_key": km.s2c_key.hex(),
        "c2s_prefix": km.c2s_prefix.hex(),
        "s2c_prefix": km.s2c_prefix.hex(),
    }

    prk2, km2 = crypto.derive_rekey(prk, SEED)
    out["rekey"] = {
        "prk_in": prk.hex(),
        "seed": SEED.hex(),
        "prk_out": prk2.hex(),
        "c2s_key": km2.c2s_key.hex(),
        "s2c_key": km2.s2c_key.hex(),
        "c2s_prefix": km2.c2s_prefix.hex(),
        "s2c_prefix": km2.s2c_prefix.hex(),
    }

    out["bootstrap"] = {
        "suite": wire.SUITE_AES256_GCM,
        "c2s_key": crypto.derive_bootstrap_key(PSK, "c2s", wire.SUITE_AES256_GCM).hex(),
        "s2c_key": crypto.derive_bootstrap_key(PSK, "s2c", wire.SUITE_AES256_GCM).hex(),
        "c2s_prefix": crypto.bootstrap_nonce_prefix(
            crypto.derive_bootstrap_key(PSK, "c2s", wire.SUITE_AES256_GCM)).hex(),
        "s2c_prefix": crypto.bootstrap_nonce_prefix(
            crypto.derive_bootstrap_key(PSK, "s2c", wire.SUITE_AES256_GCM)).hex(),
    }

    out["auth"] = {
        "role": crypto.ROLE_AGENT,
        "ident": "agent-7f3a",
        "client_pub": cpub.hex(),
        "server_pub": spub.hex(),
        "client_nonce": CNONCE.hex(),
        "server_nonce": SNONCE.hex(),
        "session_id": SID.hex(),
        "timestamp": TS,
        "suite": wire.SUITE_AES256_GCM,
        "hello": crypto.hello_auth(
            PSK,
            role=crypto.ROLE_AGENT,
            ident=b"agent-7f3a",
            client_pub=cpub,
            client_nonce=CNONCE,
            timestamp=TS,
            suite=wire.SUITE_AES256_GCM,
        ).hex(),
        "ack": crypto.ack_auth(
            PSK,
            ident=b"agent-7f3a",
            client_pub=cpub,
            server_pub=spub,
            client_nonce=CNONCE,
            server_nonce=SNONCE,
            session_id=SID,
            suite=wire.SUITE_AES256_GCM,
        ).hex(),
    }

    # ---- frames --------------------------------------------------------
    frames = []
    for suite, key, prefix, counter, mtype, payload in [
        (wire.SUITE_AES256_GCM, km.c2s_key, km.c2s_prefix, 0,
         wire.MsgType.CHECKIN, {"ts": TS, "n": 2}),
        (wire.SUITE_AES256_GCM, km.s2c_key, km.s2c_prefix, 7,
         wire.MsgType.TASK_BATCH, {"tasks": [
             {"id": "t-1", "kind": "shell", "args": {"cmd": "id"}},
             {"id": "t-2", "kind": "sysinfo", "args": {}},
         ]}),
        (wire.SUITE_CHACHA20_POLY1305, km.c2s_key, km.c2s_prefix, 129,
         wire.MsgType.RESULT, {"id": "t-1", "code": -1, "out": b"\x00binary\xff"}),
        (wire.SUITE_AES256_GCM, km.s2c_key, km.s2c_prefix, 3,
         wire.MsgType.HEARTBEAT, {"v": 1, "iver": "0.1.0", "abi": 1,
                                  "busy": 2, "up": 900}),
    ]:
        plaintext = upk.encode(payload)
        nonce = wire.make_nonce(prefix, counter)
        frame = wire.build_frame(
            suite=suite, flags=0, msg_type=mtype, key=key, nonce=nonce,
            plaintext=plaintext,
            aead_encrypt=lambda k, n, a, p, s=suite: crypto.aead_encrypt(s, k, n, a, p),
        )
        frames.append({
            "suite": suite,
            "key": key.hex(),
            "prefix": prefix.hex(),
            "counter": counter,
            "nonce": nonce.hex(),
            "type": mtype,
            "plaintext_hex": plaintext.hex(),
            "frame_hex": frame.hex(),
        })
    out["frames"] = frames

    # bootstrap handshake frame (fixed client nonce, PSK phase)
    hello = {
        "v": 1, "role": crypto.ROLE_AGENT, "id": "agent-7f3a", "pub": cpub,
        "cn": CNONCE, "ts": TS, "suite": wire.SUITE_AES256_GCM,
        "auth": bytes(32), "meta": {"os": "linux", "arch": "x86_64"},
    }
    bkey = crypto.derive_bootstrap_key(PSK, "c2s", wire.SUITE_AES256_GCM)
    bprefix = crypto.bootstrap_nonce_prefix(bkey)
    plaintext = b"\x01" + upk.encode(hello)
    frame = wire.build_frame(
        suite=wire.SUITE_AES256_GCM, flags=wire.FLAG_BOOTSTRAP,
        msg_type=wire.MsgType.HELLO, key=bkey,
        nonce=wire.make_nonce(bprefix, 0), plaintext=plaintext,
        aead_encrypt=lambda k, n, a, p: crypto.aead_encrypt(wire.SUITE_AES256_GCM, k, n, a, p),
    )
    out["bootstrap_frame"] = {
        "key": bkey.hex(), "prefix": bprefix.hex(), "counter": 0,
        "plaintext_hex": plaintext.hex(), "frame_hex": frame.hex(),
        "msg_type": wire.MsgType.HELLO, "flags": wire.FLAG_BOOTSTRAP,
    }

    # The second version of the handshake: the capability list, the version
    # of the implant, the module ABI and the platform details are fields of
    # their own.  The frame is the same bootstrap frame as above, with the
    # new body, so a decoder that only knows the first version still reads
    # the frame and ignores the fields it does not know.
    hello_v2 = {
        "v": 2, "role": crypto.ROLE_AGENT, "id": "agent-7f3a", "pub": cpub,
        "cn": CNONCE, "ts": TS, "suite": wire.SUITE_AES256_GCM,
        "auth": bytes(32), "meta": {"os": "linux", "arch": "x86_64"},
        "caps": ["shell", "sysinfo"], "iver": "0.1.0", "abi": 1,
        "plat": {"os": "linux", "arch": "x86_64", "family": "unix"},
    }
    plaintext_v2 = b"\x01" + upk.encode(hello_v2)
    frame_v2 = wire.build_frame(
        suite=wire.SUITE_AES256_GCM, flags=wire.FLAG_BOOTSTRAP,
        msg_type=wire.MsgType.HELLO, key=bkey,
        nonce=wire.make_nonce(bprefix, 0), plaintext=plaintext_v2,
        aead_encrypt=lambda k, n, a, p: crypto.aead_encrypt(wire.SUITE_AES256_GCM, k, n, a, p),
    )
    out["bootstrap_frame_v2"] = {
        "key": bkey.hex(), "prefix": bprefix.hex(), "counter": 0,
        "plaintext_hex": plaintext_v2.hex(), "frame_hex": frame_v2.hex(),
        "msg_type": wire.MsgType.HELLO, "flags": wire.FLAG_BOOTSTRAP,
    }
    # The versions of the handshake, and the fields each of them carries.
    out["handshake"] = {
        "versions": [2, 1],
        "abi_version": 1,
        "v1_fields": ["v", "role", "id", "pub", "cn", "ts", "suite", "auth", "meta"],
        "v2_fields": ["v", "role", "id", "pub", "cn", "ts", "suite", "auth", "meta",
                      "caps", "iver", "abi", "plat"],
        "ack_v2_fields": ["v", "pub", "sn", "sid", "suite", "auth", "cfg", "name",
                           "meta", "abi", "compat", "limits"],
    }

    # ---- negative cases (must be rejected) -----------------------------
    good = bytearray(b(frames[0]["frame_hex"]))
    tampered = bytearray(good)
    tampered[-1] ^= 0x01
    bad_len = bytearray(good)
    bad_len[11] = (bad_len[11] + 1) % 256
    bad_magic = bytearray(good)
    bad_magic[0] = 0x00
    out["rejects"] = {
        "tampered_tag": tampered.hex(),
        "tampered_length": bad_len.hex(),
        "bad_magic": bad_magic.hex(),
        "truncated": bytes(good[: wire.HEADER_LEN + 3]).hex(),
        "replayed": frames[0]["frame_hex"],
        "upk_unsorted_map": "090202016202010161020301",  # b before a
        "upk_trailing": (upk.encode(1) + b"\x00").hex(),
        "upk_unknown_tag": "ff",
        "upk_nonminimal": "038000",
        # The same rule one level down: a non-minimal length prefix inside an
        # array, and a non-minimal key length inside a map. A decoder that only
        # checks minimality at the top level accepts both.
        "upk_nonminimal_nested": "0801038000",          # [ 0x80 0x00 ]
        "upk_nonminimal_key_len": "0901068100610301",   # { "\x81\x00"+"a": 1 }
        # Duplicate keys must be refused even though the bytes "re-encode" to
        # something: {a:1, a:2} would silently drop one entry.
        "upk_duplicate_key": "090206016103010601610302",
        # UTF-8 is validated, not substituted: a loner 0xff, a UTF-8-encoded
        # surrogate and an overlong "/" must all be refused rather than turned
        # into U+FFFD (which would re-encode to different bytes).
        "upk_invalid_utf8": "0601ff",
        "upk_surrogate_utf8": "0603eda080",
        "upk_overlong_utf8": "0602c0af",
        # Hand-built so a *decoder* must reject it: MAX_DEPTH+1 nested arrays
        # (0x08 0x01) around one uvarint (0x03 0x01). The encoder refuses to
        # produce this at all, which is why it is spelled out byte by byte.
        "upk_depth_exceeded": ("0801" * (upk.MAX_DEPTH + 1)) + "0301",
    }

    path = os.path.join(ROOT, "contracts", "vectors.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")


def _nested(levels: int):
    """``levels`` nested single-element arrays around a leaf integer."""
    value = 1
    for _ in range(levels):
        value = [value]
    return value


def _jsonable(v):
    if isinstance(v, (bytes, bytearray)):
        return {"$bin": bytes(v).hex()}
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_jsonable(x) for x in v]
    return v


if __name__ == "__main__":
    main()
