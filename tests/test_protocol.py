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
