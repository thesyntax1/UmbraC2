#!/usr/bin/env python3
"""Development server + reference agent for UmbraC2.

This is a *test double*, not the team server: it implements enough of the
server side of umbra/v1 (handshake, check-in, task queue, operator RPC) to
exercise the operator console and the protocol without building Go.

It is also imported by the test-suite:

    python3 tools/mock_server.py --port 4002 --operator alice:<token>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import socket
import ssl
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "operator"))

from umbra_cli import crypto, handshake, netio, session, upk, wire, ws  # noqa: E402


# How long an agent stays online after its last check-in.  Mirrors
# store.OfflineGrace in the Go server.
OFFLINE_GRACE = 90


def _substitute_output(args: Dict[str, Any], output: bytes) -> Dict[str, Any]:
    """Replace the {{output}} placeholder in the arguments of a stage."""
    text = output.decode("utf-8", "replace")[:65536]

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return value.replace("{{output}}", text)
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value

    return {k: walk(v) for k, v in args.items()}


def _now() -> int:
    return int(time.time())


def new_id(prefix: str) -> str:
    return f"{prefix}-{crypto.random_bytes(4).hex()}"


# ---------------------------------------------------------------------------
# pivoting
#
# The test double implements the same callback protocol as the Go server:
# the agent dials back, announces the session id in the HELLO metadata and
# then serves logical streams.
# ---------------------------------------------------------------------------
def socks5_connect(conn: socket.socket) -> Tuple[Optional[str], int]:
    """Read a SOCKS5 CONNECT request.

    Returns ``(host, port)`` or ``(None, 0)`` when the client did not ask
    for a plain TCP connection.  Only the no-authentication variant and the
    CONNECT command are supported, exactly like the Go implementation.
    """
    try:
        head = conn.recv(2)
        if len(head) < 2:
            return None, 0
        conn.recv(head[1])  # the offered authentication methods
        conn.sendall(b"\x05\x00")  # "no authentication required"
        request = conn.recv(4)
        if len(request) < 4 or request[1] != 0x01:
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return None, 0
        atyp = request[3]
        if atyp == 0x01:
            host = socket.inet_ntoa(conn.recv(4))
        elif atyp == 0x03:
            length = conn.recv(1)
            if not length:
                return None, 0
            host = conn.recv(length[0]).decode("ascii", "replace")
        else:
            conn.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return None, 0
        raw_port = conn.recv(2)
        if len(raw_port) < 2:
            return None, 0
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        return host, int.from_bytes(raw_port, "big")
    except OSError:
        return None, 0


class TunnelStream:
    """One logical stream inside a tunnel session."""

    def __init__(self, stream_id: str) -> None:
        self.id = stream_id
        # The answer to the open request: None means "connected".
        self.result: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=1)
        self.data: "queue.Queue[bytes]" = queue.Queue(maxsize=64)
        self.closed = threading.Event()


class TunnelSession:
    """One agent callback connection.

    The server drives the session: it asks the agent to open a connection to
    a target and relays the bytes over the callback.
    """

    def __init__(
        self,
        server: "MockServer",
        agent_id: str,
        sid: str,
        stream: netio.Stream,
        sess: session.Session,
    ) -> None:
        self.server = server
        self.agent_id = agent_id
        self.sid = sid
        self.stream = stream
        self.sess = sess
        self.gate = netio.SendGate(sess, stream)
        self.streams: Dict[str, TunnelStream] = {}
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.done = threading.Event()

    def send(self, msg_type: int, body: Dict[str, Any]) -> None:
        self.gate.send(msg_type, body)

    def read_loop(self) -> None:
        try:
            while not self.server._stop.is_set():
                msg_type, body = self.sess.decrypt_message(self.stream.recv_frame())
                if msg_type == wire.MsgType.TUNNEL_OPEN:
                    self._on_open(body)
                elif msg_type == wire.MsgType.TUNNEL_DATA:
                    self._on_data(body)
                elif msg_type == wire.MsgType.TUNNEL_CLOSE:
                    self._on_close(body)
        except Exception:
            pass
        finally:
            self.close()

    def _on_open(self, body: Dict[str, Any]) -> None:
        op = str(body.get("op", ""))
        sid = str(body.get("stream", ""))
        if op == "ready":
            self.ready.set()
            return
        if op != "result":
            return
        with self.lock:
            st = self.streams.get(sid)
        if st is None:
            return
        ok = bool(body.get("ok"))
        err = str(body.get("err", ""))
        st.result.put(None if ok else (err or "the agent refused the stream"))

    def _on_data(self, body: Dict[str, Any]) -> None:
        sid = str(body.get("stream", ""))
        data = body.get("data") or b""
        with self.lock:
            st = self.streams.get(sid)
        if st is None:
            return
        try:
            st.data.put_nowait(bytes(data))
        except queue.Full:
            st.closed.set()

    def _on_close(self, body: Dict[str, Any]) -> None:
        sid = str(body.get("stream", ""))
        with self.lock:
            st = self.streams.get(sid)
        if st is not None:
            st.closed.set()

    def open_stream(self, host: str, port: int, timeout: float = 20.0) -> TunnelStream:
        """Ask the agent to connect to ``host:port`` and wait for the answer."""
        sid = new_id("s")
        st = TunnelStream(sid)
        with self.lock:
            self.streams[sid] = st
        self.send(
            wire.MsgType.TUNNEL_OPEN,
            {"stream": sid, "op": "open", "host": host, "port": int(port)},
        )
        try:
            err = st.result.get(timeout=timeout)
        except queue.Empty:
            err = "the agent did not answer the stream request"
        if err:
            with self.lock:
                self.streams.pop(sid, None)
            raise RuntimeError(err)
        return st

    def close(self) -> None:
        if self.done.is_set():
            return
        self.done.set()
        with self.lock:
            streams = list(self.streams.values())
            self.streams.clear()
        for st in streams:
            st.closed.set()
        with self.server._lock:
            if self.server.tunnel_sessions.get(self.agent_id) is self:
                del self.server.tunnel_sessions[self.agent_id]
        self.server.emit("pivot.session_closed", self.agent_id, data={"session": self.sid})


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------
class MockServer:
    """Minimal threaded umbra/v1 server used for tests and local development."""

    def __init__(
        self,
        agent_psk: bytes,
        operators: Dict[str, bytes],
        host: str = "127.0.0.1",
        port: int = 0,
        rekey_after: Optional[int] = None,
        roles: Optional[Dict[str, str]] = None,
        tls_cert: str = "",
        tls_key: str = "",
        tls_client_ca: str = "",
        websocket: bool = False,
        alerts: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.agent_psk = agent_psk
        self.operators = dict(operators)
        # Roles mirror server/internal/rbac: everything defaults to admin so
        # existing tests keep working, and `roles=` narrows a specific console.
        self.roles = {name: (roles or {}).get(name, "admin") for name in self.operators}
        # Test hook: force a key rotation once a session has sent this many
        # frames in either direction (real servers use REKEY_AFTER).
        self.rekey_after = rekey_after
        self.host = host
        self.port = port
        # The mutual TLS listener of the Go server, mirrored here so the
        # operator console can be tested against a real certificate.
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.tls_client_ca = tls_client_ca
        self._tls_ctx: Optional[ssl.SSLContext] = None
        # The WebSocket transport: the same protocol, but every frame travels
        # in a binary WebSocket frame.
        self.websocket = websocket
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._lock = threading.Lock()
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        # The multi-stage tasks that are still running, and the alert rules
        # the server watches the event stream with.
        self.chains: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[Dict[str, Any]] = list(alerts or [])
        # The journal of the recent events: a console that was not
        # watching asks for the ones it missed.
        self.events: List[Dict[str, Any]] = []
        self._event_seq = 0
        # The interactive sessions that are open, per agent.
        self.open_sessions: Dict[str, Dict[str, Any]] = {}
        # Mirrors the Go server's audit trail: one entry per operator RPC.
        self.audit_entries: List[Dict[str, Any]] = []
        self.chat: List[Dict[str, Any]] = []
        self.schedules: Dict[str, Dict[str, Any]] = {}
        # Named subscriber queues, so a directed event can be addressed to one
        # console (the Go hub filters on the operator name the same way).
        self.subscribers: List[Tuple[str, "queue.Queue[Dict[str, Any]]"]] = []
        # Presence per operator identity: which agent they are looking at and
        # when they last did anything.
        self.op_sessions: Dict[str, Dict[str, Any]] = {}
        # task ids cancelled after delivery; the next check-in carries one
        # TASK_CANCEL frame each, before TASK_BATCH (same order as the server).
        self.pending_cancels: Dict[str, List[str]] = {}
        # Callback sessions: agent id -> session.  A session is opened by the
        # agent (it dials back), the server only asks for one.
        self.tunnel_sessions: Dict[str, TunnelSession] = {}
        self.pending_tunnels: Dict[str, Tuple[str, threading.Event]] = {}
        # Open pivots: tunnel id -> description.
        self.pivots: Dict[str, Dict[str, Any]] = {}
        # The layer-3 tunnel: agent id -> peer record.
        self.vpn_peers: Dict[str, Dict[str, Any]] = {}
        # The extension store.  The test double keeps the blobs in memory; the
        # Go server keeps them on disk and verifies their signature.
        self.armory: Dict[str, Dict[str, Any]] = {}
        # The command namespace: saved commands the team shares.
        self.aliases: Dict[str, Dict[str, Any]] = {}
        self._install_default_armory()
        self._install_default_aliases()
        self.sleep = 5
        self.jitter = 20

    def _install_default_armory(self) -> None:
        """Register the two modules the test double knows about."""
        for name, description, args in (
            ("whoami", "print the token of the current user", ["domain"]),
            ("lsecrets", "list the secrets of the machine", []),
        ):
            blob = f"UMBRA-MODULE:{name}".encode()
            self.armory[name] = {
                "name": name,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": len(blob),
                "description": description,
                "args": args,
                "data": blob,
            }

    def _install_default_aliases(self) -> None:
        """Register the saved commands the test double knows about."""
        self.aliases["whoami"] = {
            "name": "whoami",
            "kind": "ext",
            "extension": "whoami",
            "args": {},
            "args_spec": ["domain"],
            "description": "who am i, with the token of the current user",
            "by": "mock",
            "created": _now(),
        }
        self.aliases["ls"] = {
            "name": "ls",
            "kind": "ls",
            "extension": "",
            "args": {"path": "."},
            "args_spec": ["path"],
            "description": "list a directory",
            "by": "mock",
            "created": _now(),
        }
        # The built-in templates of the real server, so a console that works
        # against the test double works against the team server.
        for name, kind, args, spec, description in (
            ("hostname", "exec", {"cmd": "hostname"}, [], "the name of the host"),
            ("system", "sysinfo", {}, [], "the system information of the host"),
            ("processes", "ps", {}, [], "the running processes"),
            ("network", "netinfo", {}, [], "the interfaces, the routes and the neighbours"),
            ("screenshot", "screenshot", {}, [], "a picture of the desktop"),
            ("listening", "exec",
             {"cmd": "ss -tulpn 2>/dev/null || netstat -anb 2>/dev/null"}, [],
             "the listening sockets"),
            ("routes", "exec",
             {"cmd": "ip route 2>/dev/null || route print 2>/dev/null"}, [],
             "the routing table"),
            ("services", "exec",
             {"cmd": "systemctl list-units --type=service --state=running 2>/dev/null"},
             [], "the running services"),
            ("triage", "triage", {}, ["path"],
             "the hash, the entropy and the file type of a file"),
            ("find", "find", {}, ["name", "path", "content"],
             "a search by name or by content"),
        ):
            self.aliases[name] = {
                "name": name,
                "kind": kind,
                "extension": "",
                "args": dict(args),
                "args_spec": list(spec),
                "description": description,
                "by": "mock",
                "created": _now(),
            }

    # -- lifecycle -------------------------------------------------------
    def start(self) -> Tuple[str, int]:
        if self.tls_cert and self.tls_key:
            self._tls_ctx = self._build_tls_context()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(32)
        self._sock.settimeout(0.2)
        self.host, self.port = self._sock.getsockname()
        ticker = threading.Thread(target=self._schedule_loop, name="mock-schedule", daemon=True)
        ticker.start()
        self._threads.append(ticker)

        t = threading.Thread(target=self._accept_loop, name="mock-accept", daemon=True)
        t.start()
        self._threads.append(t)
        return self.host, self.port

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=1.0)

    def __enter__(self) -> "MockServer":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    # -- accept / dispatch ----------------------------------------------
    def _build_tls_context(self) -> ssl.SSLContext:
        """Build the server side of the mutual TLS listener.

        The Go server requires a client certificate when a client CA is
        configured; the test double does the same, so a console that works
        here works there.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(self.tls_cert, self.tls_key)
        if self.tls_client_ca:
            ctx.load_verify_locations(self.tls_client_ca)
            ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if self._tls_ctx is not None:
                try:
                    conn = self._tls_ctx.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError):
                    # A peer that fails the TLS handshake is not a session.
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
            t = threading.Thread(target=self._serve, args=(conn, addr), daemon=True)
            t.start()
            self._threads.append(t)

    def _keyring(self) -> List[handshake.KeyringEntry]:
        ring = [handshake.KeyringEntry("agent", self.agent_psk, crypto.ROLE_AGENT)]
        for name, token in self.operators.items():
            ring.append(handshake.KeyringEntry(name, token, crypto.ROLE_OPERATOR))
        return ring

    def _serve(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        if self.websocket:
            # The WebSocket transport: the opening handshake comes first, then
            # every umbra frame travels in a binary WebSocket frame.  A peer
            # that does not ask for an upgrade (the operator console) is
            # served the plain protocol, exactly like the Go server does.
            try:
                head = conn.recv(4, socket.MSG_PEEK)
            except OSError:
                return
            if head.startswith(b"GET "):
                server = ws.WebSocketServer(conn)
                try:
                    if not server.handshake():
                        server.close()
                        return
                except (OSError, ws.WebSocketError):
                    return
                stream = ws.WebSocketStream(server)
            else:
                stream = netio.Stream(conn, timeout=30)
        else:
            stream = netio.Stream(conn, timeout=30)
        try:
            result = handshake.server_handshake(
                stream, keyring=self._keyring(),
                cfg={"sleep": self.sleep, "jitter": self.jitter, "obf": True}
            )
        except (handshake.HandshakeError, netio.StreamError, OSError):
            stream.close()
            return

        if result.peer_id in self.operators:
            self._operator_loop(stream, result, str(addr))
        elif result.meta.get("tunnel"):
            # A callback session: the agent dialled back to serve a pivot.
            self._tunnel_loop(stream, result)
        else:
            self._agent_loop(stream, result, str(addr))

    # -- pivoting -------------------------------------------------------
    def _tunnel_loop(self, stream: netio.Stream, result: handshake.HandshakeResult) -> None:
        """Serve one agent callback connection."""
        agent_id = result.peer_id
        sid = str(result.meta.get("tunnel", ""))
        ts = TunnelSession(self, agent_id, sid, stream, result.session)
        with self._lock:
            self.tunnel_sessions[agent_id] = ts
            pending = self.pending_tunnels.pop(agent_id, None)
        if pending is not None and pending[0] == sid:
            pending[1].set()
        self.emit("pivot.session_open", agent_id, data={"session": sid})
        try:
            ts.read_loop()
        finally:
            ts.close()

    def _tunnel_session(self, agent_id: str, timeout: float = 30.0) -> TunnelSession:
        """Return the callback session of an agent, asking for one if needed."""
        with self._lock:
            ts = self.tunnel_sessions.get(agent_id)
        if ts is not None and ts.ready.is_set():
            return ts
        sid = new_id("sid")
        event = threading.Event()
        with self._lock:
            self.pending_tunnels[agent_id] = (sid, event)
        task = {
            "id": new_id("t"),
            "agent_id": agent_id,
            "kind": "tunnel",
            "args": {"stream": sid},
            "state": "queued",
            "code": 0,
            "out": b"",
            "err": "",
            "created": _now(),
        }
        with self._lock:
            self.tasks[task["id"]] = task
        if not event.wait(timeout):
            with self._lock:
                self.pending_tunnels.pop(agent_id, None)
            raise RuntimeError("the agent did not open a tunnel session in time")
        with self._lock:
            ts = self.tunnel_sessions.get(agent_id)
        if ts is None:
            raise RuntimeError("the agent opened an unknown tunnel session")
        return ts

    def _pivot_accept(
        self,
        listener: socket.socket,
        ts: TunnelSession,
        mode: str,
        host: str,
        port: int,
        tunnel_id: str,
        agent_id: str,
    ) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            t = threading.Thread(
                target=self._pivot_handle,
                args=(conn, ts, mode, host, port, tunnel_id, agent_id),
                daemon=True,
            )
            t.start()

    def _pivot_handle(
        self,
        conn: socket.socket,
        ts: TunnelSession,
        mode: str,
        host: str,
        port: int,
        tunnel_id: str,
        agent_id: str,
    ) -> None:
        """Turn one local connection into a stream through the agent."""
        try:
            if mode == "forward":
                target_host, target_port = host, port
            else:
                target_host, target_port = socks5_connect(conn)
                if not target_host:
                    return
            st = ts.open_stream(target_host, target_port)
            with self._lock:
                info = self.pivots.get(tunnel_id)
                if info is not None:
                    info["streams"] = info.get("streams", 0) + 1

            def pump_in() -> None:
                try:
                    while True:
                        data = conn.recv(32768)
                        if not data:
                            break
                        ts.send(wire.MsgType.TUNNEL_DATA, {"stream": st.id, "data": data})
                except OSError:
                    pass
                finally:
                    try:
                        ts.send(
                            wire.MsgType.TUNNEL_CLOSE,
                            {"stream": st.id, "reason": "the local side closed"},
                        )
                    except Exception:
                        pass

            t = threading.Thread(target=pump_in, daemon=True)
            t.start()
            while True:
                if st.closed.is_set():
                    break
                try:
                    chunk = st.data.get(timeout=0.5)
                except queue.Empty:
                    continue
                if not chunk:
                    break
                conn.sendall(chunk)
        except Exception as exc:
            self.emit("pivot.error", agent_id, data={"tunnel": tunnel_id, "err": str(exc)})
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # -- agents ----------------------------------------------------------
    def _schedule_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._due_schedules()
            except Exception:  # pragma: no cover - dev helper
                pass
            self._stop.wait(0.1)

    def _agent_loop(self, stream: netio.Stream, result: handshake.HandshakeResult, addr: str) -> None:
        sess = result.session
        agent_id = result.peer_id
        meta = result.meta
        with self._lock:
            is_new = agent_id not in self.agents
            record = self.agents.setdefault(agent_id, {})
            record.update(
                {
                    "id": agent_id,
                    "host": meta.get("host", "?"),
                    "os": meta.get("os", "?"),
                    "arch": meta.get("arch", "?"),
                    "user": meta.get("user", "?"),
                    "pid": meta.get("pid", 0),
                    "version": meta.get("ver", "?"),
                    "transport": "tcp",
                    "addr": addr,
                    "state": "online",
                    # The cadence the operator configured survives a
                    # re-registration: the beacon reconnects every cycle.
                    "sleep": record.get("sleep", self.sleep),
                    "jitter": record.get("jitter", self.jitter),
                    "last_seen": _now(),
                    "first_seen": record.get("first_seen", _now()),
                }
            )
        self.emit("agent.new" if is_new else "agent.online", agent_id, data={"host": record["host"], "os": record["os"]})

        try:
            while not self._stop.is_set():
                raw = stream.recv_frame()
                msg_type, msg = sess.decrypt_message(raw)
                if msg_type == wire.MsgType.CHECKIN:
                    with self._lock:
                        record = self.agents.get(agent_id)
                        if record is not None:
                            record["last_seen"] = _now()
                            record["state"] = "online"
                    batch = self._take_tasks(agent_id)
                    # The cadence the server pushes is the one the operator
                    # configured for this agent.
                    with self._lock:
                        record = self.agents.get(agent_id) or {}
                        sleep = int(record.get("sleep", self.sleep))
                        jitter = int(record.get("jitter", self.jitter))
                        obfuscate = bool(record.get("obfuscate", True))
                    body = {
                        "tasks": batch,
                        "sleep": sleep,
                        "jitter": jitter,
                        "obf": obfuscate,
                        "server_time": _now(),
                    }
                    # Rotation order is part of the protocol: the REKEY frame is
                    # sealed with the OLD key set, written first, and only then
                    # does the server switch. The peer sees REKEY at the old
                    # counter, applies it, resets to 0 and opens TASK_BATCH with
                    # the new key set as its first frame.
                    if self.rekey_after and sess.needs_rekey(self.rekey_after):
                        seed = crypto.random_bytes(32)
                        stream.send_frame(sess.encrypt(wire.MsgType.REKEY, {"seed": seed}))
                        sess.apply_rekey(seed)
                    # Cancels sit between REKEY and TASK_BATCH: they are sealed
                    # with whatever keys are current, and must arrive before the
                    # batch whose tasks they refer to.
                    with self._lock:
                        cancels = self.pending_cancels.pop(agent_id, [])
                    for task_id in cancels:
                        stream.send_frame(sess.encrypt(wire.MsgType.TASK_CANCEL, {"id": task_id}))
                    stream.send_frame(sess.encrypt(wire.MsgType.TASK_BATCH, body))
                elif msg_type == wire.MsgType.RESULT:
                    self._complete_task(msg)
                elif msg_type == wire.MsgType.BYE:
                    break
                elif msg_type == wire.MsgType.PING:
                    stream.send_frame(sess.encrypt(wire.MsgType.PONG, {"ts": msg.get("ts", 0)}))
                elif msg_type == wire.MsgType.REKEY:
                    seed = msg.get("seed", b"")
                    if isinstance(seed, (bytes, bytearray)) and len(seed) == 32:
                        sess.apply_rekey(bytes(seed))
                elif msg_type == wire.MsgType.PADDING:
                    # Padding frames carry random bytes and are ignored.
                    pass
                else:
                    break
        except (netio.StreamError, session.SessionError, OSError, ValueError):
            pass
        finally:
            # The beacon closes its connection after every cycle, so a closed
            # link does not mean a dead agent: it is offline once it has been
            # quiet for longer than the grace period.
            went_offline = False
            with self._lock:
                record = self.agents.get(agent_id)
                if record is not None:
                    record["last_seen"] = _now()
                    if _now() - int(record.get("last_seen", 0)) > OFFLINE_GRACE:
                        record["state"] = "offline"
                        went_offline = True
            if went_offline:
                self.emit("agent.offline", agent_id)
            stream.close()

    def _take_tasks(self, agent_id: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        with self._lock:
            for task in self.tasks.values():
                if task["agent_id"] == agent_id and task["state"] == "queued" and len(out) < 32:
                    task["state"] = "delivered"
                    task["delivered"] = _now()
                    out.append({"id": task["id"], "kind": task["kind"], "args": task["args"]})
        for t in out:
            self.emit("task.delivered", agent_id, task_id=t["id"])
        return out

    def sweep_tasks(self, timeout_s: int) -> List[str]:
        """Fail the tasks that were delivered but never completed.

        Mirrors the Go server's sweep: a beacon that dies in the middle of
        a task leaves it in the "delivered" state, and the operator has to
        learn that instead of waiting forever.
        """
        if timeout_s <= 0:
            return []
        cutoff = _now() - timeout_s
        failed: List[str] = []
        with self._lock:
            for task in self.tasks.values():
                if task["state"] != "delivered":
                    continue
                delivered = int(task.get("delivered", 0))
                if delivered == 0 or delivered > cutoff:
                    continue
                task["state"] = "failed"
                task["err"] = "the agent never answered"
                task["completed"] = _now()
                failed.append(task["id"])
        for task_id in failed:
            self.emit("task.timeout", task_id=task_id, data={})
        return failed

    def _queue_task(self, agent_id: str, kind: str,
                    task_args: Dict[str, Any]) -> Dict[str, Any]:
        """Queue a task and announce it."""
        task = {
            "id": new_id("t"),
            "agent_id": agent_id,
            "kind": kind,
            "args": task_args,
            "state": "queued",
            "code": 0,
            "out": b"",
            "err": "",
            "created": _now(),
        }
        with self._lock:
            self.tasks[task["id"]] = task
        self.emit("task.queued", agent_id, task_id=task["id"], data={"kind": kind})
        return task

    def _advance_chain(self, task_id: str, output: bytes) -> None:
        """Hand the output of a finished stage to the next one."""
        with self._lock:
            task = self.tasks.get(task_id)
            if task is None:
                return
            chain_id = task.get("chain_id")
            if not chain_id:
                return
            chain = self.chains.get(chain_id)
            if chain is None:
                return
            chain["stage"] += 1
            stage = chain["stage"]
            stages = chain["stages"]
            agent_id = chain["agent_id"]
            if stage >= len(stages):
                self.chains.pop(chain_id, None)
                finished = True
                next_task = None
                next_kind = ""
            else:
                finished = False
                nxt = stages[stage]
                args = _substitute_output(nxt.get("args") or {}, output)
                next_kind = str(nxt.get("kind", ""))
                next_task = None
        if not finished and next_task is None:
            # The lock is released before the task is queued: the queue
            # helper takes it itself.
            next_task = self._queue_task(agent_id, next_kind, args)
            with self._lock:
                next_task["chain_id"] = chain_id
                next_task["stage"] = stage
        if finished:
            self.emit("chain.done", task.get("agent_id", ""), task_id=task_id,
                      data={"chain": chain_id, "stages": stage})
        elif next_task is not None:
            self.emit("chain.stage", next_task["agent_id"], task_id=next_task["id"],
                      data={"chain": chain_id, "stage": stage,
                            "kind": next_task["kind"]})

    def _complete_task(self, msg: Dict[str, Any]) -> None:
        task_id = str(msg.get("id", ""))
        out = msg.get("out", b"")
        if isinstance(out, (bytes, bytearray)):
            out = bytes(out)
        if bool(msg.get("partial", False)):
            # A streamed chunk: the task is still running, so the chunk is
            # appended and the consoles are told about it.
            with self._lock:
                task = self.tasks.get(task_id)
                if task is None:
                    return
                previous = task.get("out", b"")
                if not isinstance(previous, (bytes, bytearray)):
                    previous = str(previous).encode()
                task["out"] = bytes(previous) + out
                meta = {
                    k: v
                    for k, v in msg.items()
                    if k not in ("id", "code", "out", "err", "partial")
                    and isinstance(v, (str, bool, int, float))
                }
                if meta:
                    task["meta"] = meta
                size = len(task["out"])
                # A streamed chunk may carry the id of the session it
                # belongs to: the server keeps the list of open sessions.
                session_id = str(meta.get("session", "") or "")
                if session_id:
                    agent_id = str(task.get("agent_id", ""))
                    entry = self.open_sessions.get(session_id)
                    if entry is None:
                        entry = {"id": session_id, "agent_id": agent_id,
                                 "task_id": task_id, "opened": _now(),
                                 "last": _now(), "bytes": 0}
                        self.open_sessions[session_id] = entry
                    entry["last"] = _now()
                    entry["bytes"] = int(entry["bytes"]) + len(out)
            data: Dict[str, Any] = {"size": size}
            if meta:
                data["meta"] = meta
            if out:
                try:
                    data["output"] = out.decode()
                except UnicodeDecodeError:
                    data["binary"] = True
            self.emit("task.output", task_id=task_id, data=data)
            return
        with self._lock:
            task = self.tasks.get(task_id)
            if task is None:
                return
            if task["state"] != "cancelled":
                task["state"] = "done" if int(msg.get("code", 0)) == 0 else "failed"
            task["code"] = int(msg.get("code", 0))
            task["out"] = out
            # A finished "session.close" means the session is gone.
            if str(task.get("kind", "")) == "session.close":
                session_id = str((task.get("args") or {}).get("session", "") or "")
                if session_id:
                    self.open_sessions.pop(session_id, None)
            task["err"] = str(msg.get("err", ""))
            meta = {
                k: v
                for k, v in msg.items()
                if k not in ("id", "code", "out", "err") and isinstance(v, (str, bool, int, float))
            }
            if meta:
                task["meta"] = meta
            task["completed"] = _now()
            snapshot = dict(task)
        raw = snapshot["out"]
        if not isinstance(raw, (bytes, bytearray)):
            raw = str(raw).encode()
        raw = bytes(raw)
        data = {
            "code": snapshot["code"],
            "state": snapshot["state"],
            "err": snapshot["err"],
            # Bounded preview, exactly like the Go server: a binary chunk is not
            # pushed to every watching console, and task.get has the real bytes.
            "size": len(raw),
        }
        if raw:
            preview = raw[:EVENT_OUTPUT_MAX]
            try:
                data["output"] = preview.decode("utf-8")
            except UnicodeDecodeError:
                data["binary"] = True
            if len(raw) > EVENT_OUTPUT_MAX:
                data["truncated"] = True
        if snapshot.get("meta"):
            data["meta"] = snapshot["meta"]
        self.emit("task.result", snapshot["agent_id"], task_id=task_id, data=data)
        # A stage of a multi-stage task hands its output to the next stage.
        self._advance_chain(task_id, raw)

    # -- operators -------------------------------------------------------
    def _operator_loop(self, stream: netio.Stream, result: handshake.HandshakeResult, addr: str) -> None:
        sess = result.session
        inbox: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=512)
        with self._lock:
            self.subscribers.append((result.peer_id, inbox))
            self.op_sessions[result.peer_id] = {
                "name": result.peer_id,
                "role": self.roles.get(result.peer_id, "operator"),
                "peer": addr,
                "transport": "tcp/operator",
                "since": _now(),
                "focus": "",
                "focus_at": "",
                "last_seen": time.time(),
            }
        self.emit("operator.connected", result.peer_id)

        # Both the event pusher and the request handler write to this
        # connection, so they must share one gate: see netio.SendGate.
        gate = netio.SendGate(sess, stream)

        def writer() -> None:
            while not self._stop.is_set():
                try:
                    ev = inbox.get(timeout=0.2)
                except queue.Empty:
                    continue
                try:
                    gate.send(wire.MsgType.OP_EVENT, ev)
                except (OSError, netio.StreamError, session.SessionError):
                    return

        wt = threading.Thread(target=writer, daemon=True)
        wt.start()
        try:
            while not self._stop.is_set():
                raw = stream.recv_frame()
                msg_type, req = sess.decrypt_message(raw)
                if msg_type == wire.MsgType.PADDING:
                    # Padding frames carry random bytes and are ignored.
                    continue
                if msg_type != wire.MsgType.OP_REQUEST:
                    break
                with self._lock:
                    # NB: `session` is the module; do not shadow it here.
                    presence = self.op_sessions.get(result.peer_id)
                    if presence is not None:
                        presence["last_seen"] = time.time()
                resp = self.dispatch(req, operator=result.peer_id, peer=addr)
                gate.send(wire.MsgType.OP_RESPONSE, resp)
        except (netio.StreamError, session.SessionError, OSError, ValueError):
            pass
        finally:
            with self._lock:
                self.subscribers = [(n, q) for (n, q) in self.subscribers if q is not inbox]
                self.op_sessions.pop(result.peer_id, None)
            stream.close()

    # Mirrors server/internal/rbac/resources.go: minimum role per command.
    ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}
    REQUIREMENTS = {
        "ping": "viewer",
        "whoami": "viewer",
        "server.stats": "viewer",
        "audit.tail": "viewer",
        "operators.list": "viewer",
        "agents.list": "viewer",
        "agents.info": "viewer",
        "task.get": "viewer",
        "task.list": "viewer",
        "chat.history": "viewer",
        "schedule.list": "viewer",
        "task.submit": "operator",
        "task.cancel": "operator",
        "task.retry": "operator",
        "events.list": "viewer",
        "engagement.wipe": "admin",
        "sessions.list": "viewer",
        "task.bulk": "operator",
        "task.chain": "operator",
        "alerts.list": "viewer",
        "agents.kill": "operator",
        "agents.exit": "operator",
        "agents.sleep": "operator",
        "agents.policy": "operator",
        "agents.tag": "operator",
        "chat.send": "operator",
        "schedule.add": "operator",
        "task.claim": "operator",
        "task.release": "operator",
        "operators.focus": "operator",
        "schedule.remove": "admin",
        "events.test": "admin",
        "pivot.list": "viewer",
        "pivot.open": "operator",
        "pivot.close": "operator",
        "vpn.status": "viewer",
        "vpn.peers": "viewer",
        "vpn.allocate": "operator",
        "armory.list": "viewer",
        "armory.install": "operator",
        "armory.run": "operator",
        "armory.remove": "admin",
        "alias.list": "viewer",
        "alias.run": "operator",
        "team.sync": "viewer",
        "stager.generate": "admin",
    }

    def min_role(self, cmd: str) -> str:
        return self.REQUIREMENTS.get(cmd, "admin")

    def allowed(self, role: str, cmd: str) -> bool:
        return self.ROLE_RANK.get(role, 0) >= self.ROLE_RANK.get(self.min_role(cmd), 99)

    def _due_schedules(self) -> None:
        """Fire recurring tasks; the mock uses the same rules as the hub."""
        now = time.time()
        fired = []
        with self._lock:
            for sc in self.schedules.values():
                if sc["next_run"] > now:
                    continue
                sc["next_run"] = now + sc["every"]
                sc["runs"] += 1
                fired.append(dict(sc))
        for sc in fired:
            with self._lock:
                agent = self.agents.get(sc["agent_id"])
                if agent is None:
                    continue
                task = {
                    "id": new_id("t"),
                    "agent_id": sc["agent_id"],
                    "kind": sc["kind"],
                    "args": sc["args"],
                    "state": "queued",
                    "code": 0,
                    "out": b"",
                    "err": "",
                    "created": _now(),
                }
                self.tasks[task["id"]] = task
                sc["last_task"] = task["id"]
            self.emit("schedule.fired", sc["agent_id"], task_id=task["id"],
                      data={"schedule_id": sc["id"], "kind": sc["kind"]})

    def dispatch(self, req: Dict[str, Any], operator: str = "mock", peer: str = "") -> Dict[str, Any]:
        """Handle one RPC and record it in the in-memory audit trail."""
        started = time.monotonic()
        resp = self._handle(req, operator)
        entry = {
            "at": _now(),
            "operator": operator,
            "peer": peer,
            "transport": "tcp/operator",
            "cmd": str(req.get("cmd", "")),
            "ok": bool(resp.get("ok")),
            "err": str(resp.get("err", "")),
            "agent_id": str((req.get("args") or {}).get("id", "")),
            "task_id": str((req.get("args") or {}).get("task_id", "")
                           or (resp.get("data") or {}).get("task_id", "")),
            "detail": " ".join(f"{k}={v}" for k, v in sorted((req.get("args") or {}).items())),
            "ms": int((time.monotonic() - started) * 1000),
        }
        with self._lock:
            self.audit_entries.append(entry)
            if len(self.audit_entries) > 2000:
                del self.audit_entries[:1000]
        return resp

    def _handle(self, req: Dict[str, Any], operator: str = "mock") -> Dict[str, Any]:
        rid = req.get("rid", 0)
        cmd = str(req.get("cmd", ""))
        args = req.get("args") or {}
        resp: Dict[str, Any] = {"rid": rid, "ok": False, "data": {}}

        def ok(data: Dict[str, Any]) -> Dict[str, Any]:
            resp["ok"] = True
            resp["data"] = data
            return resp

        def fail(msg: str) -> Dict[str, Any]:
            resp["err"] = msg
            return resp

        role = self.roles.get(operator, "operator")
        if not self.allowed(role, cmd):
            return fail(
                f"permission denied: {cmd!r} requires role {self.min_role(cmd)} (you are {role})"
            )

        if cmd == "ping":
            return ok({"pong": _now()})

        if cmd == "whoami":
            caps = sorted(c for c in self.REQUIREMENTS if self.allowed(role, c))
            return ok(
                {
                    "name": operator,
                    "role": role,
                    "peer": "127.0.0.1:0",
                    "transport": "tcp/operator",
                    "since": _now(),
                    "focus": (self.op_sessions.get(operator) or {}).get("focus", ""),
                    "capabilities": caps,
                }
            )

        if cmd == "chat.send":
            text = str(args.get("text", "")).strip()
            if not text:
                return fail("chat.send needs non-empty text")
            to = str(args.get("to", "") or "").strip()
            with self._lock:
                if to and to not in self.op_sessions:
                    return fail(f"chat.send: {to!r} is not a connected operator")
                message = {"from": operator, "role": role, "text": text[:2000], "at": _now()}
                if to:
                    message["to"] = to
                self.chat.append(message)
                del self.chat[:-200]
            self.emit("chat", data=dict(message), to=to, sender=operator)
            out = {"at": message["at"], "from": operator}
            if to:
                out["to"] = to
            return ok(out)

        if cmd == "chat.history":
            limit = int(args.get("limit", 50) or 50)
            with self._lock:
                return ok({"messages": [dict(m) for m in self.chat[-limit:]]})

        if cmd == "schedule.add":
            agent_id = str(args.get("id", ""))
            kind = str(args.get("kind", ""))
            every = int(args.get("every", 0) or 0)
            with self._lock:
                if agent_id not in self.agents:
                    return fail(f"schedule.add: unknown agent {agent_id!r}")
                if every < 5 or every > 86400:
                    return fail("schedule.add: interval out of range")
                schedule = {
                    "id": new_id("s"),
                    "agent_id": agent_id,
                    "kind": kind,
                    "args": args.get("args") or {},
                    "every": every,
                    "enabled": True,
                    "runs": 0,
                    "next_run": time.time() + every,
                    "created": _now(),
                    "last_task": "",
                    "by": operator,
                }
                self.schedules[schedule["id"]] = schedule
            self.emit("schedule.created", agent_id, data={"schedule_id": schedule["id"]})
            return ok(
                {
                    "schedule_id": schedule["id"],
                    "agent_id": agent_id,
                    "kind": kind,
                    "every": every,
                    "next_run": int(schedule["next_run"]),
                }
            )

        if cmd == "schedule.list":
            with self._lock:
                items = [dict(sc) for sc in self.schedules.values()]
            return ok({"schedules": items})

        if cmd == "schedule.remove":
            schedule_id = str(args.get("schedule_id", ""))
            with self._lock:
                if schedule_id not in self.schedules:
                    return fail(f"schedule.remove: unknown schedule {schedule_id!r}")
                del self.schedules[schedule_id]
            self.emit("schedule.removed", data={"schedule_id": schedule_id})
            return ok({"schedule_id": schedule_id, "removed": True})

        if cmd == "server.stats":
            with self._lock:
                return ok(
                    {
                        "agents_total": len(self.agents),
                        "agents_online": sum(
                            1 for a in self.agents.values() if a["state"] == "online"
                        ),
                        "tasks_total": len(self.tasks),
                        "tasks_pending": sum(
                            1 for t in self.tasks.values() if t["state"] in ("queued", "delivered")
                        ),
                        "operators": len(self.subscribers),
                        "schedules": len(self.schedules),
                        "protocol": "umbra/v1",
                        "note": "mock server (test double)",
                    }
                )

        if cmd == "operators.list":
            with self._lock:
                backlog: Dict[str, int] = {}
                for name, q in self.subscribers:
                    backlog[name] = backlog.get(name, 0) + q.qsize()
                ops = []
                for i, (name, live) in enumerate(sorted(self.op_sessions.items())):
                    ops.append(
                        {
                            "id": i + 1,
                            "name": name,
                            "role": live.get("role", ""),
                            "peer": live.get("peer", ""),
                            "transport": live.get("transport", ""),
                            "since": live.get("since", ""),
                            "backlog": backlog.get(name, 0),
                            "focus": live.get("focus", ""),
                            "focus_at": live.get("focus_at", ""),
                            "idle_sec": int(max(0.0, time.time() - live.get("last_seen", time.time()))),
                        }
                    )
            return ok({"operators": ops, "count": len(ops)})

        if cmd == "agents.list":
            with self._lock:
                rows = [dict(a) for a in self.agents.values()
                        if _agent_matches(a, args)]
            return ok({"agents": rows, "count": len(rows)})

        if cmd == "agents.tag":
            tags = _string_list(args.get("tags") or args.get("tag"))
            if not tags:
                return fail("agents.tag needs at least one tag")
            mode = str(args.get("mode", "add") or "add")
            if mode not in ("add", "remove", "set"):
                return fail("agents.tag: mode must be add, remove or set")
            if not _has_targets(args):
                return fail("agents.tag: no targets")
            targets = _select_agents(self.agents, args)
            updated = []
            with self._lock:
                for rec in targets:
                    current = [str(t) for t in rec.get("tags", [])]
                    if mode == "set":
                        current = list(tags)
                    elif mode == "remove":
                        current = [t for t in current if t not in tags]
                    else:
                        for tag in tags:
                            if tag not in current:
                                current.append(tag)
                    rec["tags"] = sorted(current)
                    updated.append(rec["id"])
            self.emit("agent.tags", updated[0] if updated else "",
                      data={"tags": tags, "mode": mode})
            return ok({"updated": updated, "tags": tags, "mode": mode})

        if cmd == "agents.policy":
            if "sleep" not in args or "jitter" not in args:
                return fail("agents.policy needs numeric sleep and jitter")
            sleep = int(args.get("sleep"))
            jitter = int(args.get("jitter"))
            obfuscate = args.get("obfuscate")
            if not _has_targets(args):
                return fail("agents.policy: no targets")
            targets = _select_agents(self.agents, args)
            updated = []
            with self._lock:
                for rec in targets:
                    rec["sleep"] = sleep
                    rec["jitter"] = jitter
                    if isinstance(obfuscate, bool):
                        rec["obfuscate"] = obfuscate
                    updated.append(rec["id"])
            for agent_id in updated:
                self.emit("agent.policy", agent_id,
                          data={"sleep": sleep, "jitter": jitter})
            out = {"updated": updated, "sleep": sleep, "jitter": jitter}
            if isinstance(obfuscate, bool):
                out["obfuscate"] = obfuscate
            return ok(out)

        if cmd == "agents.info":
            with self._lock:
                rec = self.agents.get(str(args.get("id", "")))
                if rec is None:
                    return fail("unknown agent")
                data = dict(rec)
                data["tasks"] = [dict(t) for t in self.tasks.values() if t["agent_id"] == rec["id"]][-20:]
                return ok(data)

        if cmd == "task.submit":
            agent_id = str(args.get("id", ""))
            with self._lock:
                if agent_id not in self.agents:
                    return fail("unknown agent")
                task = {
                    "id": new_id("t"),
                    "agent_id": agent_id,
                    "kind": str(args.get("kind", "")),
                    "args": args.get("args") or {},
                    "state": "queued",
                    "code": 0,
                    "out": b"",
                    "err": "",
                    "created": _now(),
                }
                self.tasks[task["id"]] = task
                task_id, kind = task["id"], task["kind"]
            self.emit("task.queued", agent_id, task_id=task_id, data={"kind": kind})
            return ok({"task_id": task_id, "agent_id": agent_id, "state": "queued"})

        if cmd == "task.get":
            with self._lock:
                task = self.tasks.get(str(args.get("task_id", "")))
                if task is None:
                    return fail("unknown task")
                return ok(_task_out(dict(task)))

        if cmd == "task.list":
            agent_id = str(args.get("id", ""))
            kind = str(args.get("kind", "") or "")
            state = str(args.get("state", "") or "")
            limit = int(args.get("limit", 50))
            with self._lock:
                items = [t for t in self.tasks.values()
                         if (not agent_id or t["agent_id"] == agent_id)
                         and (not kind or t["kind"] == kind)
                         and (not state or t["state"] == state)]
            return ok({"tasks": [_task_out(t) for t in items[-limit:]],
                       "count": len(items[-limit:])})

        if cmd == "task.bulk":
            kind = str(args.get("kind", "") or "")
            if not kind:
                return fail("task.bulk needs a task kind")
            task_args = args.get("args") or {}
            if not _has_targets(args):
                return fail("task.bulk: no targets")
            targets = _select_agents(self.agents, args)
            rows = []
            with self._lock:
                for rec in targets:
                    task = {
                        "id": new_id("t"),
                        "agent_id": rec["id"],
                        "kind": kind,
                        "args": task_args,
                        "state": "queued",
                        "code": 0,
                        "out": b"",
                        "err": "",
                        "created": _now(),
                    }
                    self.tasks[task["id"]] = task
                    rows.append({"agent_id": rec["id"], "task_id": task["id"],
                                 "state": "queued"})
            for row in rows:
                self.emit("task.queued", row["agent_id"],
                          task_id=row["task_id"], data={"kind": kind})
            return ok({"tasks": rows, "count": len(rows)})

        if cmd == "task.chain":
            agent_id = str(args.get("id", "") or "")
            stages = args.get("stages") or []
            if not isinstance(stages, list) or not stages:
                return fail("task.chain: a chain needs at least one stage")
            with self._lock:
                if agent_id not in self.agents:
                    return fail(f"unknown agent {agent_id!r}")
                chain_id = new_id("chain")
                self.chains[chain_id] = {
                    "id": chain_id,
                    "agent_id": agent_id,
                    "stages": [dict(stage) for stage in stages],
                    "stage": 0,
                }
            first = stages[0]
            task = self._queue_task(agent_id, str(first.get("kind", "")),
                                    first.get("args") or {})
            with self._lock:
                task["chain_id"] = chain_id
                task["stage"] = 0
            self.emit("chain.started", agent_id, task_id=task["id"],
                      data={"chain": chain_id, "stages": len(stages)})
            return ok({"chain_id": chain_id, "task_id": task["id"],
                       "agent_id": agent_id, "stages": len(stages),
                       "state": task["state"]})

        if cmd == "alerts.list":
            rules = self.alerts
            return ok({"alerts": rules, "count": len(rules)})

        if cmd in ("task.claim", "task.release"):
            task_id = str(args.get("task_id", ""))
            with self._lock:
                task = self.tasks.get(task_id)
                if task is None:
                    return fail(f"{cmd}: no such task")
                holder = str(task.get("claimed_by", ""))
                if cmd == "task.claim":
                    if task.get("state") in ("done", "failed", "cancelled"):
                        return fail(f"task.claim: task {task_id} is already {task['state']}")
                    if holder and holder != operator:
                        return fail(f"task.claim: task {task_id} is claimed by {holder}")
                    if not holder:
                        task["claimed_by"] = operator
                        task["claimed_at"] = _now()
                else:
                    if holder and holder != operator:
                        return fail(f"task.release: task {task_id} is claimed by {holder}")
                    task.pop("claimed_by", None)
                    task.pop("claimed_at", None)
                snapshot = dict(task)
            kind = "task.claimed" if cmd == "task.claim" else "task.released"
            self.emit(kind, snapshot["agent_id"], task_id=task_id, data={"by": operator})
            return ok(
                {
                    "task_id": task_id,
                    "agent_id": snapshot["agent_id"],
                    "claimed_by": snapshot.get("claimed_by", ""),
                    "state": snapshot.get("state", ""),
                }
            )

        if cmd == "operators.focus":
            agent_id = str(args.get("id", ""))
            with self._lock:
                if agent_id and agent_id not in self.agents:
                    return fail(f"operators.focus: unknown agent {agent_id!r}")
                presence = self.op_sessions.get(operator)
                if presence is None:
                    return fail(f"operators.focus: {operator!r} is not connected")
                previous = presence.get("focus", "")
                presence["focus"] = agent_id
                presence["focus_at"] = _now() if agent_id else ""
            self.emit(
                "operator.focus",
                data={"operator": operator, "agent_id": agent_id},
                sender=operator,
            )
            return ok({"operator": operator, "agent_id": agent_id, "previous": previous})

        if cmd == "task.cancel":
            task_id = str(args.get("task_id", ""))
            with self._lock:
                task = self.tasks.get(task_id)
                if task is None:
                    return fail("unknown task")
                # Same rule as the Go server: a finished or already cancelled
                # task cannot be cancelled again.
                if task["state"] in ("done", "failed", "cancelled"):
                    return fail(f"task {task_id!r} cannot be cancelled")
                previous = task["state"]
                task["state"] = "cancelled"
                agent_id = task["agent_id"]
                if previous == "delivered":
                    queue = self.pending_cancels.setdefault(agent_id, [])
                    if len(queue) < 4:
                        queue.append(task_id)
            self.emit("task.cancelled", agent_id, task_id=task_id, data={"was": previous})
            return ok({"task_id": task_id, "state": "cancelled"})

        if cmd == "engagement.wipe":
            # The end of an engagement: the record of the machines that
            # were touched stops existing on the server.
            with self._lock:
                agents = len(self.agents)
                tasks = len(self.tasks)
                schedules = len(self.schedules)
                self.agents.clear()
                self.tasks.clear()
                self.schedules.clear()
                self.open_sessions.clear()
            self.emit("engagement.wiped", data={"agents": agents, "tasks": tasks,
                                                "schedules": schedules})
            return ok({"agents": agents, "tasks": tasks, "schedules": schedules})

        if cmd == "sessions.list":
            with self._lock:
                rows = [dict(row) for row in self.open_sessions.values()]
            rows.sort(key=lambda row: row.get("last", 0), reverse=True)
            return ok({"sessions": rows, "count": len(rows)})

        if cmd == "events.list":
            after = int(args.get("after", 0) or 0)
            limit = int(args.get("limit", 100) or 100)
            with self._lock:
                rows = [dict(e) for e in self.events if int(e.get("seq", 0)) > after]
            if limit > 0 and len(rows) > limit:
                rows = rows[-limit:]
            last = int(rows[-1].get("seq", 0)) if rows else after
            return ok({"events": rows, "count": len(rows), "seq": last})

        if cmd == "task.retry":
            task_id = str(args.get("task_id", ""))
            with self._lock:
                task = self.tasks.get(task_id)
                if task is None:
                    return fail("unknown task")
                if task["state"] in ("queued", "delivered"):
                    return fail(f"task {task_id!r} has not finished yet")
                agent_id = task["agent_id"]
                kind = task["kind"]
                task_args = dict(task.get("args") or {})
            new_task = self._queue_task(agent_id, kind, task_args)
            return ok({"task_id": new_task["id"], "agent_id": agent_id,
                       "kind": kind, "retried": task_id})

        if cmd == "audit.tail":
            # The mock keeps the same append-only JSONL format in memory so the
            # CLI path can be exercised without a Go server.
            limit = int(args.get("limit", 50) or 50)
            with self._lock:
                entries = list(self.audit_entries)[-limit:][::-1]
            return ok({"entries": entries, "enabled": True})

        if cmd == "agents.sleep":
            agent_id = str(args.get("id", ""))
            sleep = int(args.get("sleep", self.sleep))
            jitter = int(args.get("jitter", self.jitter))
            with self._lock:
                if agent_id not in self.agents:
                    return fail("unknown agent")
                self.agents[agent_id]["sleep"] = sleep
                self.agents[agent_id]["jitter"] = jitter
            self.emit("agent.policy", agent_id, data={"sleep": sleep, "jitter": jitter})
            return ok({"id": agent_id, "sleep": sleep, "jitter": jitter})

        if cmd in ("agents.kill", "agents.exit"):
            agent_id = str(args.get("id", ""))
            with self._lock:
                if agent_id not in self.agents:
                    return fail("unknown agent")
                task = {
                    "id": new_id("t"),
                    "agent_id": agent_id,
                    "kind": "exit",
                    "args": {},
                    "state": "queued",
                    "code": 0,
                    "out": b"",
                    "err": "",
                    "created": _now(),
                }
                self.tasks[task["id"]] = task
            return ok({"task_id": task["id"], "agent_id": agent_id})

        # ---- pivoting ---------------------------------------------------
        if cmd == "pivot.list":
            with self._lock:
                tunnels = [dict(t) for t in self.pivots.values()]
                sessions = len(self.tunnel_sessions)
            return ok({"tunnels": tunnels, "sessions": sessions})

        if cmd == "pivot.open":
            agent_id = str(args.get("id", ""))
            mode = str(args.get("mode", "socks")) or "socks"
            host = str(args.get("host", ""))
            port = int(args.get("port", 0) or 0)
            listen = str(args.get("listen", "")) or "127.0.0.1:0"
            with self._lock:
                known = agent_id in self.agents
            if not known:
                return fail(f"unknown agent {agent_id!r}")
            try:
                ts = self._tunnel_session(agent_id)
            except RuntimeError as exc:
                return fail(str(exc))
            lhost, _, lport = listen.rpartition(":")
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                listener.bind((lhost or "127.0.0.1", int(lport or 0)))
            except OSError as exc:
                listener.close()
                return fail(f"pivot.open: listen {listen}: {exc}")
            listener.listen(16)
            bound = listener.getsockname()
            address = f"{bound[0]}:{bound[1]}"
            tunnel_id = new_id("tun")
            with self._lock:
                self.pivots[tunnel_id] = {
                    "stream": tunnel_id,
                    "agent_id": agent_id,
                    "mode": mode,
                    "listen": address,
                    "host": host,
                    "port": port,
                    "opened": _now(),
                    "streams": 0,
                    "bytes_up": 0,
                    "bytes_down": 0,
                    "state": "open",
                }
            t = threading.Thread(
                target=self._pivot_accept,
                args=(listener, ts, mode, host, port, tunnel_id, agent_id),
                daemon=True,
            )
            t.start()
            self.emit("pivot.opened", agent_id, data={"tunnel": tunnel_id, "listen": address})
            return ok({
                "stream": tunnel_id,
                "agent_id": agent_id,
                "mode": mode,
                "listen": address,
                "host": host,
                "port": port,
            })

        if cmd == "pivot.close":
            tunnel_id = str(args.get("stream", ""))
            with self._lock:
                info = self.pivots.pop(tunnel_id, None)
            if info is None:
                return fail(f"unknown tunnel {tunnel_id!r}")
            info["state"] = "closed"
            self.emit("pivot.closed", str(info.get("agent_id", "")), data={"tunnel": tunnel_id})
            return ok({"stream": tunnel_id, "closed": True})

        # ---- layer-3 tunnel ----------------------------------------------
        if cmd == "vpn.status":
            with self._lock:
                peers = list(self.vpn_peers.values())
            return ok({
                "enabled": True,
                "listen": "127.0.0.1:0",
                "network": "10.77.0.0/24",
                "peers": len(peers),
                "allocated": len(peers),
                "bytes_in": sum(int(p.get("bytes_in", 0)) for p in peers),
                "bytes_out": sum(int(p.get("bytes_out", 0)) for p in peers),
            })

        if cmd == "vpn.peers":
            with self._lock:
                peers = [dict(p) for p in self.vpn_peers.values()]
            return ok({"peers": peers, "count": len(peers)})

        if cmd == "vpn.allocate":
            agent_id = str(args.get("id", ""))
            with self._lock:
                known = agent_id in self.agents
            if not known:
                return fail(f"unknown agent {agent_id!r}")
            with self._lock:
                used = {p["address"] for p in self.vpn_peers.values()}
                index = 2
                while f"10.77.0.{index}" in used:
                    index += 1
                address = f"10.77.0.{index}"
                self.vpn_peers[agent_id] = {
                    "id": agent_id,
                    "address": address,
                    "endpoint": "",
                    "agent": agent_id,
                    "live": False,
                    "bytes_in": 0,
                    "bytes_out": 0,
                    "last_seen": _now(),
                }
            return ok({"id": agent_id, "address": address})

        # ---- extension store ----------------------------------------------
        if cmd == "armory.list":
            with self._lock:
                installed = [dict(e) for e in self.armory.values()]
            return ok({
                "entries": [
                    {
                        "name": e["name"],
                        "version": "1.0",
                        "os": "windows",
                        "arch": "amd64",
                        "format": "coff",
                        "sha256": e["sha256"],
                        "size": e["size"],
                        "description": e.get("description", ""),
                        "args": e.get("args", []),
                    }
                    for e in installed
                ],
                "installed": installed,
                "verified": True,
            })

        if cmd == "armory.install":
            name = str(args.get("name", ""))
            if not name:
                return fail("armory.install needs a name")
            with self._lock:
                entry = self.armory.get(name)
            if entry is None:
                return fail(f"unknown extension {name!r}")
            return ok({
                "name": entry["name"],
                "sha256": entry["sha256"],
                "size": entry["size"],
                "installed": _now(),
            })

        if cmd == "armory.remove":
            name = str(args.get("name", ""))
            with self._lock:
                entry = self.armory.pop(name, None)
            if entry is None:
                return fail(f"unknown extension {name!r}")
            return ok({"name": name, "removed": True})

        if cmd == "armory.run":
            name = str(args.get("name", ""))
            agent_id = str(args.get("id", ""))
            with self._lock:
                entry = self.armory.get(name)
                known = agent_id in self.agents
            if entry is None:
                return fail(f"unknown extension {name!r}")
            if not known:
                return fail(f"unknown agent {agent_id!r}")
            task = {
                "id": new_id("t"),
                "agent_id": agent_id,
                "kind": "ext",
                "args": {"name": name, "data": entry["data"], "args": args.get("args") or {}},
                "state": "queued",
                "code": 0,
                "out": b"",
                "err": "",
                "created": _now(),
            }
            with self._lock:
                self.tasks[task["id"]] = task
            return ok({"task_id": task["id"], "agent_id": agent_id, "name": name})

        # ---- command namespace ---------------------------------------------
        if cmd == "alias.list":
            with self._lock:
                aliases = [dict(a) for a in self.aliases.values()]
            return ok({"aliases": aliases, "count": len(aliases)})

        if cmd == "alias.run":
            name = str(args.get("name", ""))
            agent_id = str(args.get("id", ""))
            with self._lock:
                entry = self.aliases.get(name)
                known = agent_id in self.agents
            if entry is None:
                return fail(f"unknown alias {name!r}")
            if not known:
                return fail(f"unknown agent {agent_id!r}")
            task = {
                "id": new_id("t"),
                "agent_id": agent_id,
                "kind": entry["kind"],
                "args": {**entry.get("args", {}), **(args.get("args") or {})},
                "state": "queued",
                "code": 0,
                "out": b"",
                "err": "",
                "created": _now(),
            }
            with self._lock:
                self.tasks[task["id"]] = task
            return ok({"task_id": task["id"], "agent_id": agent_id, "name": name})

        # ---- team ------------------------------------------------------------
        if cmd == "team.sync":
            with self._lock:
                agents = [dict(a) for a in self.agents.values()]
                operators = [dict(o) for o in self.op_sessions.values()]
                chat = [dict(m) for m in self.chat[-50:]]
            return ok({
                "server_time": _now(),
                "version": "mock",
                "agents": agents,
                "operators": operators,
                "chat": chat,
            })

        # ---- stagers ----------------------------------------------------------
        if cmd == "stager.generate":
            platform = str(args.get("platform", "windows"))
            transport = str(args.get("transport", "tcp"))
            server = str(args.get("server", "")) or "127.0.0.1:4001"
            url = str(args.get("url", ""))
            digest = str(args.get("sha256", ""))
            agent_id = str(args.get("agent_id", ""))
            script = (
                "# umbra stager (mock)\n"
                f"$UMBRA_SERVER = '{server}'\n"
                f"$UMBRA_TRANSPORT = '{transport}'\n"
                f"$UMBRA_AGENT_ID = '{agent_id}'\n"
                f"$UMBRA_URL = '{url}'\n"
                f"$UMBRA_SHA256 = '{digest}'\n"
            )
            return ok({
                "platform": platform,
                "transport": transport,
                "server": server,
                "stager": script,
            })

        return fail(f"unknown command {cmd!r}")

    # -- events ----------------------------------------------------------
    def emit(
        self,
        kind: str,
        agent_id: str = "",
        *,
        task_id: str = "",
        data: Optional[Dict[str, Any]] = None,
        to: str = "",
        sender: str = "",
    ) -> None:
        """Publish an event; `to` addresses it to one console (empty = team)."""
        ev = {"kind": kind, "at": _now(), "agent_id": agent_id, "task_id": task_id, "data": data or {}}
        if sender:
            ev["from"] = sender
        if to:
            ev["to"] = to
        with self._lock:
            self._event_seq += 1
            ev["seq"] = self._event_seq
            self.events.append(ev)
            if len(self.events) > 2000:
                del self.events[:len(self.events) - 2000]
            subs = list(self.subscribers)
        for name, q in subs:
            if to and name not in (to, sender):
                continue
            try:
                q.put_nowait(ev)
            except queue.Full:
                pass


def _string_list(value: Any) -> List[str]:
    """Read a list of strings; a comma separated string counts as one."""
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
        return out
    return []


def _filter_of(args: Dict[str, Any]) -> Dict[str, Any]:
    """The filter of an RPC: a nested map or the flat arguments."""
    raw = args.get("filter")
    if isinstance(raw, dict):
        merged = dict(raw)
        for key in ("state", "transport", "os", "arch", "tag", "user"):
            if key not in merged and key in args:
                merged[key] = args[key]
        return merged
    return {key: args[key] for key in ("state", "transport", "os", "arch", "tag", "user")
            if key in args}


def _agent_matches(agent: Dict[str, Any], args: Dict[str, Any]) -> bool:
    """Does the agent match the filter of the call?"""
    filt = _filter_of(args)
    for key in ("state", "transport", "os", "arch", "user"):
        want = filt.get(key)
        if want in (None, ""):
            continue
        if str(agent.get(key, "")).lower() != str(want).lower():
            return False
    tag = filt.get("tag")
    if tag:
        tags = [str(t).lower() for t in agent.get("tags", [])]
        if str(tag).lower() not in tags:
            return False
    return True


def _has_targets(args: Dict[str, Any]) -> bool:
    """Did the call name any target at all?"""
    if _string_list(args.get("agents")) or _string_list(args.get("ids")):
        return True
    return bool(_filter_of(args))


def _select_agents(agents: Dict[str, Any], args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The agents an operation applies to: the named ones, narrowed by the filter."""
    named = _string_list(args.get("agents")) or _string_list(args.get("ids"))
    out = []
    for rec in agents.values():
        if named and rec["id"] not in named:
            continue
        if not _agent_matches(rec, args):
            continue
        out.append(rec)
    return out


def _task_out(task: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a task record for the wire (bytes stay bytes, upk encodes them)."""
    out = dict(task)
    if isinstance(out.get("out"), (bytes, bytearray)):
        out["out"] = bytes(out["out"])
    return out


# Mirrors store.CHUNK_MAX / the Rust beacon's output budget: one transfer step
# never carries more than this, so it always fits in a single RESULT frame.
CHUNK_MAX = 900 * 1024
# Mirrors hub.maxEventOutput: events carry a preview, not the payload.
EVENT_OUTPUT_MAX = 4096


# ---------------------------------------------------------------------------
# reference agent (Python stand-in for the Rust beacon)
# ---------------------------------------------------------------------------
class FakeAgent(threading.Thread):
    """A minimal, well-behaved beacon used to develop without the Rust build."""

    def __init__(
        self,
        server: str,
        psk: bytes,
        agent_id: str = "",
        *,
        transport_meta: Optional[Dict[str, Any]] = None,
        execute_shell: bool = True,
        interval: float = 0.3,
        websocket: bool = False,
    ) -> None:
        super().__init__(daemon=True, name="mock-agent")
        self.server = server
        self.psk = psk
        self.agent_id = agent_id or new_id("agent")
        # The WebSocket transport talks to the same server, but through an
        # HTTP upgrade instead of a raw socket.
        self.websocket = websocket
        self.meta = transport_meta or {
            "host": "lab-host",
            "os": sys.platform,
            "arch": "x86_64",
            "user": os.environ.get("USER", "lab"),
            "pid": os.getpid(),
            "integ": "medium",
            "ver": "py-ref",
        }
        self.execute_shell = execute_shell
        self.interval = interval
        self._stop = threading.Event()
        self.completed = threading.Event()
        self.sent_bye = False
        self.rekeys = 0
        self.cancelled_ids: List[str] = []
        # Control frames actually received (proves 0x18 is on the wire).
        self.cancels_received: List[str] = []
        # The last policy the server pushed (sleep, jitter, obfuscation).
        self.policy: Dict[str, Any] = {}
        # The interactive sessions the agent has open.
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self._cycle()
            except Exception:  # pragma: no cover - dev helper
                pass
            self._stop.wait(self.interval)

    def _cycle(self) -> None:
        host, _, port = self.server.rpartition(":")
        if self.websocket:
            client = ws.WebSocketClient(host, int(port), path="/ws", timeout=5)
            client.connect()
            stream = ws.WebSocketStream(client)
        else:
            sock = socket.create_connection((host, int(port)), timeout=5)
            stream = netio.Stream(sock, timeout=5)
        try:
            result = handshake.client_handshake(
                stream,
                psk=self.psk,
                role=crypto.ROLE_AGENT,
                ident=self.agent_id,
                meta=self.meta,
            )
            sess = result.session
            stream.send_frame(sess.encrypt(wire.MsgType.CHECKIN, {"ts": _now(), "n": 0}))
            # A REKEY frame may precede the batch; it is sealed with the old key
            # set, so apply it and keep reading until TASK_BATCH arrives.
            batch: Dict[str, Any] = {}
            cancelled: set = set()
            for _ in range(8):
                msg_type, frame_body = sess.decrypt_message(stream.recv_frame())
                if msg_type == wire.MsgType.TASK_CANCEL:
                    task_id = str(frame_body.get("id", ""))
                    cancelled.add(task_id)
                    self.cancels_received.append(task_id)
                    continue
                if msg_type == wire.MsgType.REKEY:
                    seed = frame_body.get("seed", b"")
                    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
                        raise ValueError("malformed REKEY seed")
                    sess.apply_rekey(bytes(seed))
                    self.rekeys += 1
                    continue
                if msg_type == wire.MsgType.TASK_BATCH:
                    batch = frame_body
                    # The cadence travels with the batch: remember it so a
                    # test can prove the policy reached the beacon.
                    self.policy = {
                        "sleep": batch.get("sleep"),
                        "jitter": batch.get("jitter"),
                        "obf": batch.get("obf"),
                    }
                    break
                return
            if not batch:
                return
            for task in batch.get("tasks", []):
                kind = str(task.get("kind", ""))
                if kind in ("session.open", "session.input", "session.close"):
                    # The interactive session: the id travels with the first
                    # chunk, the input is echoed back as a chunk of the
                    # session, and closing the session ends the open task.
                    self._session_task(kind, task, sess, stream)
                    continue
                if str(task.get("id", "")) in cancelled:
                    # The command is still reported so the server can show that
                    # it was cancelled and that nothing ran.
                    self.cancelled_ids.append(str(task.get("id", "")))
                    outcome = (125, b"", "cancelled before execution", {})
                else:
                    outcome = self._execute(task)
                body: Dict[str, Any] = {
                    "id": task.get("id", ""),
                    "code": outcome[0],
                    "out": outcome[1],
                    "err": outcome[2],
                }
                if len(outcome) > 3 and outcome[3]:
                    body.update(outcome[3])
                stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))
                self.completed.set()
            stream.send_frame(sess.encrypt(wire.MsgType.BYE, {}))
            self.sent_bye = True
        finally:
            stream.close()

    def _session_task(self, kind: str, task: Dict[str, Any], sess: Any,
                      stream: Any) -> None:
        """Run one of the interactive session tasks."""
        task_id = str(task.get("id", ""))
        args = task.get("args") or {}
        if kind == "session.open":
            sid = new_id("s")
            self.sessions[sid] = {"task_id": task_id, "buffer": b""}
            body = {
                "id": task_id, "code": 0, "out": b"", "err": "",
                "partial": True, "session": sid,
            }
            stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))
            return
        sid = str(args.get("session", ""))
        session = self.sessions.get(sid)
        if session is None:
            body = {"id": task_id, "code": 1, "out": b"",
                    "err": f"unknown session {sid}"}
            stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))
            return
        if kind == "session.input":
            data = args.get("data", b"")
            if isinstance(data, str):
                data = data.encode()
            session["buffer"] += bytes(data)
            # The echo belongs to the session, not to the input task: the
            # operator reads one stream.
            body = {
                "id": session["task_id"], "code": 0, "out": bytes(data),
                "err": "", "partial": True, "session": sid,
            }
            stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))
            body = {"id": task_id, "code": 0, "out": b"", "err": "", "session": sid}
            stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))
            return
        # session.close
        buffer = session["buffer"]
        self.sessions.pop(sid, None)
        body = {"id": session["task_id"], "code": 0, "out": buffer, "err": "",
                "session": sid}
        stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))
        body = {"id": task_id, "code": 0, "out": b"", "err": "", "session": sid}
        stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))

    def _execute(self, task: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """Run one task, returning (code, stdout, stderr, meta).

        `meta` mirrors the Rust beacon's extra RESULT fields, so chunked
        transfers behave identically against the test double.
        """
        kind = str(task.get("kind", ""))
        args = task.get("args") or {}
        if kind == "shell" and self.execute_shell:
            cmd = str(args.get("cmd", ""))
            try:
                proc = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    timeout=30,
                    text=False,
                )
                return proc.returncode, proc.stdout + proc.stderr, "", {}
            except subprocess.SubprocessError as exc:
                return 1, b"", f"exec failed: {exc}", {}
        if kind == "sysinfo":
            report = "\n".join(f"{k}: {v}" for k, v in sorted(self.meta.items()))
            return 0, report.encode(), "", {}
        if kind == "recon":
            # Mirrors the Rust beacon's recon report: the host facts, the
            # environment findings and the domain edges, in that order.
            report = "\n".join(f"{k}: {v}" for k, v in sorted(self.meta.items()))
            lines = [
                report,
                "environment: nothing unusual",
                "domain    : (not in a domain)",
                "edges     : none",
            ]
            return 0, ("\n".join(lines) + "\n").encode(), "", {}
        if kind in ("exit", "kill"):
            self._stop.set()
            return 0, b"bye\n", "", {}
        if kind in ("download", "cat"):
            return self._download(args)
        if kind == "upload":
            return self._upload(args)
        if kind == "tunnel":
            return self._tunnel(args)
        if kind in ("ext", "bof"):
            data = args.get("data") or b""
            name = str(args.get("name", "module"))
            return 0, f"module {name} ran in memory ({len(bytes(data))} bytes)\n".encode(), "", {}
        if kind == "triage":
            path = str(args.get("path", ""))
            try:
                data = open(path, "rb").read()
            except OSError as exc:
                return 1, b"", f"triage {path}: {exc}", {}
            digest = hashlib.sha256(data).hexdigest()
            magic = "PE" if data[:2] == b"MZ" else (
                "ELF" if data[:4] == b"\x7fELF" else "unknown")
            report = (f"path: {path}\nsize: {len(data)}\nsha256: {digest}\n"
                      f"magic: {magic}\n")
            return 0, report.encode(), "", {}
        if kind == "find":
            root = str(args.get("path", "."))
            name = str(args.get("name", "")).lower()
            hits = []
            for base, _dirs, files in os.walk(root):
                for entry in files:
                    if not name or name in entry.lower():
                        hits.append(os.path.join(base, entry))
                    if len(hits) >= 50:
                        break
                if len(hits) >= 50:
                    break
            report = f"scanned files, {len(hits)} hits\n" + "\n".join(hits)
            return 0, report.encode(), "", {}
        if kind == "proc.kill":
            pid = int(args.get("pid", 0) or 0)
            name = str(args.get("name", ""))
            return 0, f"mock agent: the process {pid or name} would be terminated\n".encode(), "", {}
        if kind == "persist":
            return 0, b"mock agent: the implant would be installed\n", "", {}
        if kind == "update":
            path = str(args.get("path", ""))
            return 0, f"mock agent: the implant would be replaced with {path}\n".encode(), "", {}
        if kind == "netinfo":
            report = "source: mock\ninterfaces:\n  lo 127.0.0.1\n"
            return 0, report.encode(), "", {}
        if kind in ("vpn", "p2p"):
            return 0, f"the mock agent cannot run {kind!r}\n".encode(), "", {}
        return 0, f"mock agent cannot run {kind!r}\n".encode(), "", {}

    # -- pivoting (mirrors implant/rust/src/tunnel.rs) --------------------
    def _tunnel(self, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """Open a callback session with the team server."""
        sid = str(args.get("stream", ""))
        if not sid:
            return 1, b"", "tunnel requires args.stream", {}
        t = threading.Thread(target=self._tunnel_callback, args=(sid,), daemon=True)
        t.start()
        return 0, f"tunnel session {sid} opened\n".encode(), "", {}

    def _tunnel_callback(self, sid: str) -> None:
        host, _, port = self.server.rpartition(":")
        try:
            sock = socket.create_connection((host, int(port)), timeout=5)
        except OSError:
            return
        stream = netio.Stream(sock, timeout=30)
        try:
            meta = dict(self.meta)
            meta["tunnel"] = sid
            result = handshake.client_handshake(
                stream,
                psk=self.psk,
                role=crypto.ROLE_AGENT,
                ident=self.agent_id,
                meta=meta,
            )
            sess = result.session
            gate = netio.SendGate(sess, stream)
            gate.send(wire.MsgType.TUNNEL_OPEN, {"stream": sid, "op": "ready"})
            targets: Dict[str, socket.socket] = {}
            while True:
                msg_type, body = sess.decrypt_message(stream.recv_frame())
                if msg_type == wire.MsgType.TUNNEL_OPEN and str(body.get("op", "")) == "open":
                    stream_id = str(body.get("stream", ""))
                    target_host = str(body.get("host", ""))
                    target_port = int(body.get("port", 0) or 0)
                    threading.Thread(
                        target=self._tunnel_stream,
                        args=(gate, stream_id, target_host, target_port, targets),
                        daemon=True,
                    ).start()
                elif msg_type == wire.MsgType.TUNNEL_DATA:
                    stream_id = str(body.get("stream", ""))
                    target = targets.get(stream_id)
                    if target is not None:
                        try:
                            target.sendall(bytes(body.get("data") or b""))
                        except OSError:
                            pass
                elif msg_type == wire.MsgType.TUNNEL_CLOSE:
                    stream_id = str(body.get("stream", ""))
                    target = targets.pop(stream_id, None)
                    if target is not None:
                        try:
                            target.close()
                        except OSError:
                            pass
        except Exception:
            pass
        finally:
            stream.close()

    def _tunnel_stream(
        self,
        gate: netio.SendGate,
        stream_id: str,
        host: str,
        port: int,
        targets: Dict[str, socket.socket],
    ) -> None:
        """Connect to the target the server asked for and relay it."""
        try:
            target = socket.create_connection((host, port), timeout=5)
            # The connect timeout must not turn into an idle timeout: a quiet
            # target is normal.
            target.settimeout(None)
        except OSError as exc:
            gate.send(
                wire.MsgType.TUNNEL_OPEN,
                {"stream": stream_id, "op": "result", "ok": False, "err": str(exc)},
            )
            return
        targets[stream_id] = target
        gate.send(
            wire.MsgType.TUNNEL_OPEN,
            {"stream": stream_id, "op": "result", "ok": True},
        )

        def pump() -> None:
            try:
                while True:
                    data = target.recv(32768)
                    if not data:
                        break
                    gate.send(wire.MsgType.TUNNEL_DATA, {"stream": stream_id, "data": data})
            except OSError:
                pass
            finally:
                try:
                    gate.send(
                        wire.MsgType.TUNNEL_CLOSE,
                        {"stream": stream_id, "reason": "the target closed the connection"},
                    )
                except Exception:
                    pass

        t = threading.Thread(target=pump, daemon=True)
        t.start()

    # -- chunked transfer (mirrors implant/rust/src/task.rs) --------------
    def _download(self, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        path = str(args.get("path", ""))
        if not path:
            return 1, b"", "download requires args.path", {}
        offset = int(args.get("offset", 0) or 0)
        limit = int(args.get("limit", CHUNK_MAX) or CHUNK_MAX)
        limit = max(1, min(limit, CHUNK_MAX))
        try:
            size = os.path.getsize(path)
            if offset > size:
                return 1, b"", f"download {path}: offset {offset} past end ({size})", {}
            with open(path, "rb") as fh:
                fh.seek(offset)
                chunk = fh.read(limit)
        except OSError as exc:
            return 1, b"", f"download {path}: {exc}", {}
        eof = offset + len(chunk) >= size
        return 0, chunk, "", {
            "total": size,
            "offset": offset,
            "eof": eof,
            "sha256": hashlib.sha256(chunk).hexdigest(),
        }

    def _upload(self, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        path = str(args.get("path", ""))
        data = args.get("data", b"")
        data = bytes(data) if isinstance(data, (bytes, bytearray)) else bytes(str(data), "utf-8")
        offset = int(args.get("offset", 0) or 0)
        eof = bool(args.get("eof", True))
        if not path:
            return 1, b"", "upload requires args.path", {}
        try:
            mode = "wb" if offset == 0 else "r+b"
            with open(path, mode) as fh:
                fh.seek(offset)
                fh.write(data)
        except OSError as exc:
            return 1, b"", f"upload {path}: {exc}", {}
        written = offset + len(data)
        meta: Dict[str, Any] = {"written": written, "eof": eof}
        if eof:
            try:
                with open(path, "rb") as fh:
                    whole = fh.read()
            except OSError as exc:
                return 1, b"", f"upload {path}: verify: {exc}", {}
            meta["total"] = len(whole)
            meta["sha256"] = hashlib.sha256(whole).hexdigest()
        return 0, f"wrote {len(data)} bytes at offset {offset} to {path}\n".encode(), "", meta


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="UmbraC2 development server (test double)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4002)
    parser.add_argument("--psk", default=os.environ.get("UMBRA_AGENT_PSK", ""), help="agent PSK (hex)")
    parser.add_argument(
        "--operator",
        action="append",
        default=[],
        metavar="NAME:TOKEN",
        help="operator credentials (repeatable)",
    )
    parser.add_argument("--spawn-agent", action="store_true", help="also start a fake agent")
    parser.add_argument("--tls-cert", default="", help="PEM certificate of the TLS listener")
    parser.add_argument("--tls-key", default="", help="PEM key of the TLS listener")
    parser.add_argument(
        "--tls-ca",
        default="",
        help="PEM bundle of the client CA (the listener then requires a client certificate)",
    )
    parser.add_argument(
        "--agent-interval",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="fake agent beacon interval (default 2.0; tests use 0.3 directly)",
    )
    args = parser.parse_args(argv)

    psk = bytes.fromhex(args.psk) if args.psk else crypto.random_bytes(32)
    operators: Dict[str, bytes] = {}
    for item in args.operator:
        name, _, token = item.partition(":")
        if not name or not token:
            parser.error("--operator must be NAME:TOKEN")
        operators[name] = token.encode()
    if not operators:
        token = crypto.random_bytes(16).hex()
        operators["operator"] = token.encode()

    server = MockServer(
        psk,
        operators,
        args.host,
        args.port,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        tls_client_ca=args.tls_ca,
    )
    host, port = server.start()
    print(f"[mock] agent PSK   : {psk.hex()}")
    for name, token in operators.items():
        print(f"[mock] operator    : {name}:{token.decode()}")
    print(f"[mock] listening   : {host}:{port}")
    if args.tls_cert:
        print("[mock] tls         : mutual TLS is on")

    agent: Optional[FakeAgent] = None
    if args.spawn_agent:
        # 2 s keeps the operator event stream readable; the test-suite builds
        # FakeAgent directly with a much shorter interval.
        agent = FakeAgent(f"{host}:{port}", psk, "agent-mock-1", interval=args.agent_interval)
        agent.start()
        print(f"[mock] fake agent  : {agent.agent_id}")

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[mock] shutting down")
    finally:
        if agent:
            agent.stop()
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
