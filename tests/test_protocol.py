"""Protocol conformance tests for the Python reference implementation.

They pin the umbra/v1 encoding, key schedule and framing to contracts/vectors.json
(the same file the Go and Rust test-suites read), and exercise the handshake and
framing against a live socket pair.

Run:  python -m pytest tests -q
"""

from __future__ import annotations

import hashlib
import hmac
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
                                 "upk_unsorted_map"])
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
    deep = "x"
    for _ in range(upk.MAX_DEPTH + 2):
        deep = [deep]
    with pytest.raises(upk.UpkError):
        upk.encode(deep)


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
