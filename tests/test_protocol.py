"""Protocol conformance tests for the Python reference implementation.

They pin the umbra/v1 encoding, key schedule and framing to contracts/vectors.json
(the same file the Go and Rust test-suites read), and exercise the handshake and
framing against a live socket pair.

Run:  python -m pytest tests -q
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import json
import re
import os
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

    def serve() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    seen.append(data)
                    conn.sendall(data)

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

        # A second allocation must not hand out the same address.
        other = client.vpn_allocate("agent-vpn")
        assert other != address
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
                                         server="10.0.0.5:4001", agent_id="abc")
        assert "10.0.0.5:4001" in script
        assert "abc" in script
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
        client.submit("agent-report", "sysinfo", {})
        time.sleep(0.6)
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
        time.sleep(0.6)

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
        time.sleep(0.4)
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
        client.submit("agent-engagement", "sysinfo", {})
        time.sleep(0.6)
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
