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
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "operator"))

from umbra_cli import crypto, handshake, netio, session, upk, wire  # noqa: E402


def _now() -> int:
    return int(time.time())


def new_id(prefix: str) -> str:
    return f"{prefix}-{crypto.random_bytes(4).hex()}"


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
    ) -> None:
        self.agent_psk = agent_psk
        self.operators = dict(operators)
        # Test hook: force a key rotation once a session has sent this many
        # frames in either direction (real servers use REKEY_AFTER).
        self.rekey_after = rekey_after
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._lock = threading.Lock()
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.events: List[Dict[str, Any]] = []
        # Mirrors the Go server's audit trail: one entry per operator RPC.
        self.audit_entries: List[Dict[str, Any]] = []
        self.subscribers: List["queue.Queue[Dict[str, Any]]"] = []
        self.sleep = 5
        self.jitter = 20

    # -- lifecycle -------------------------------------------------------
    def start(self) -> Tuple[str, int]:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(32)
        self._sock.settimeout(0.2)
        self.host, self.port = self._sock.getsockname()
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
    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            t = threading.Thread(target=self._serve, args=(conn, addr), daemon=True)
            t.start()
            self._threads.append(t)

    def _keyring(self) -> List[handshake.KeyringEntry]:
        ring = [handshake.KeyringEntry("agent", self.agent_psk, crypto.ROLE_AGENT)]
        for name, token in self.operators.items():
            ring.append(handshake.KeyringEntry(name, token, crypto.ROLE_OPERATOR))
        return ring

    def _serve(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        stream = netio.Stream(conn, timeout=30)
        try:
            result = handshake.server_handshake(
                stream, keyring=self._keyring(), cfg={"sleep": self.sleep, "jitter": self.jitter}
            )
        except (handshake.HandshakeError, netio.StreamError, OSError):
            stream.close()
            return

        if result.peer_id in self.operators:
            self._operator_loop(stream, result, str(addr))
        else:
            self._agent_loop(stream, result, str(addr))

    # -- agents ----------------------------------------------------------
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
                    "sleep": self.sleep,
                    "jitter": self.jitter,
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
                    batch = self._take_tasks(agent_id)
                    body = {
                        "tasks": batch,
                        "sleep": self.sleep,
                        "jitter": self.jitter,
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
                else:
                    break
        except (netio.StreamError, session.SessionError, OSError, ValueError):
            pass
        finally:
            with self._lock:
                if agent_id in self.agents:
                    self.agents[agent_id]["state"] = "offline"
            self.emit("agent.offline", agent_id)
            stream.close()

    def _take_tasks(self, agent_id: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        with self._lock:
            for task in self.tasks.values():
                if task["agent_id"] == agent_id and task["state"] == "queued" and len(out) < 32:
                    task["state"] = "delivered"
                    out.append({"id": task["id"], "kind": task["kind"], "args": task["args"]})
        for t in out:
            self.emit("task.delivered", agent_id, task_id=t["id"])
        return out

    def _complete_task(self, msg: Dict[str, Any]) -> None:
        task_id = str(msg.get("id", ""))
        out = msg.get("out", b"")
        if isinstance(out, (bytes, bytearray)):
            out = bytes(out)
        with self._lock:
            task = self.tasks.get(task_id)
            if task is None:
                return
            task["state"] = "done" if int(msg.get("code", 0)) == 0 else "failed"
            task["code"] = int(msg.get("code", 0))
            task["out"] = out
            task["err"] = str(msg.get("err", ""))
            task["completed"] = _now()
            snapshot = dict(task)
        self.emit(
            "task.result",
            snapshot["agent_id"],
            task_id=task_id,
            data={
                "code": snapshot["code"],
                "state": snapshot["state"],
                "output": snapshot["out"].decode("utf-8", "replace")
                if isinstance(snapshot["out"], (bytes, bytearray))
                else str(snapshot["out"]),
                "err": snapshot["err"],
            },
        )

    # -- operators -------------------------------------------------------
    def _operator_loop(self, stream: netio.Stream, result: handshake.HandshakeResult, addr: str) -> None:
        sess = result.session
        inbox: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=512)
        with self._lock:
            self.subscribers.append(inbox)
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
                if msg_type != wire.MsgType.OP_REQUEST:
                    break
                resp = self.dispatch(req, operator=result.peer_id, peer=addr)
                gate.send(wire.MsgType.OP_RESPONSE, resp)
        except (netio.StreamError, session.SessionError, OSError, ValueError):
            pass
        finally:
            with self._lock:
                if inbox in self.subscribers:
                    self.subscribers.remove(inbox)
            stream.close()

    def dispatch(self, req: Dict[str, Any], operator: str = "mock", peer: str = "") -> Dict[str, Any]:
        """Handle one RPC and record it in the in-memory audit trail."""
        started = time.monotonic()
        resp = self._handle(req)
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
            "detail": str(req.get("args") or ""),
            "ms": int((time.monotonic() - started) * 1000),
        }
        with self._lock:
            self.audit_entries.append(entry)
            if len(self.audit_entries) > 2000:
                del self.audit_entries[:1000]
        return resp

    def _handle(self, req: Dict[str, Any]) -> Dict[str, Any]:
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

        if cmd == "ping":
            return ok({"pong": _now()})

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
                        "protocol": "umbra/v1",
                        "note": "mock server (test double)",
                    }
                )

        if cmd == "agents.list":
            with self._lock:
                return ok({"agents": [dict(a) for a in self.agents.values()]})

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
            limit = int(args.get("limit", 50))
            with self._lock:
                items = [t for t in self.tasks.values() if t["agent_id"] == agent_id]
            return ok({"tasks": [_task_out(t) for t in items[-limit:]]})

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
                task["state"] = "cancelled"
            self.emit("task.cancelled", task["agent_id"], task_id=task_id)
            return ok({"task_id": task_id, "state": "cancelled"})

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

        return fail(f"unknown command {cmd!r}")

    # -- events ----------------------------------------------------------
    def emit(self, kind: str, agent_id: str = "", *, task_id: str = "", data: Optional[Dict[str, Any]] = None) -> None:
        ev = {"kind": kind, "at": _now(), "agent_id": agent_id, "task_id": task_id, "data": data or {}}
        with self._lock:
            self.events.append(ev)
            subs = list(self.subscribers)
        for q in subs:
            try:
                q.put_nowait(ev)
            except queue.Full:
                pass


def _task_out(task: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a task record for the wire (bytes stay bytes, upk encodes them)."""
    out = dict(task)
    if isinstance(out.get("out"), (bytes, bytearray)):
        out["out"] = bytes(out["out"])
    return out


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
    ) -> None:
        super().__init__(daemon=True, name="mock-agent")
        self.server = server
        self.psk = psk
        self.agent_id = agent_id or new_id("agent")
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
            for _ in range(4):
                msg_type, frame_body = sess.decrypt_message(stream.recv_frame())
                if msg_type == wire.MsgType.REKEY:
                    seed = frame_body.get("seed", b"")
                    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
                        raise ValueError("malformed REKEY seed")
                    sess.apply_rekey(bytes(seed))
                    self.rekeys += 1
                    continue
                if msg_type == wire.MsgType.TASK_BATCH:
                    batch = frame_body
                    break
                return
            if not batch:
                return
            for task in batch.get("tasks", []):
                outcome = self._execute(task)
                stream.send_frame(
                    sess.encrypt(
                        wire.MsgType.RESULT,
                        {
                            "id": task.get("id", ""),
                            "code": outcome[0],
                            "out": outcome[1],
                            "err": outcome[2],
                        },
                    )
                )
                self.completed.set()
            stream.send_frame(sess.encrypt(wire.MsgType.BYE, {}))
            self.sent_bye = True
        finally:
            stream.close()

    def _execute(self, task: Dict[str, Any]) -> Tuple[int, bytes, str]:
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
                return proc.returncode, proc.stdout + proc.stderr, ""
            except subprocess.SubprocessError as exc:
                return 1, b"", f"exec failed: {exc}"
        if kind == "sysinfo":
            report = "\n".join(f"{k}: {v}" for k, v in sorted(self.meta.items()))
            return 0, report.encode(), ""
        if kind in ("exit", "kill"):
            self._stop.set()
            return 0, b"bye\n", ""
        return 0, f"mock agent cannot run {kind!r}\n".encode(), ""


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

    server = MockServer(psk, operators, args.host, args.port)
    host, port = server.start()
    print(f"[mock] agent PSK   : {psk.hex()}")
    for name, token in operators.items():
        print(f"[mock] operator    : {name}:{token.decode()}")
    print(f"[mock] listening   : {host}:{port}")

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
