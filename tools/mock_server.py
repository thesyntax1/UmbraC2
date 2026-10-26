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
        roles: Optional[Dict[str, str]] = None,
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
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._lock = threading.Lock()
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.events: List[Dict[str, Any]] = []
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
            if task["state"] != "cancelled":
                task["state"] = "done" if int(msg.get("code", 0)) == 0 else "failed"
            task["code"] = int(msg.get("code", 0))
            task["out"] = out
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
        "agents.kill": "operator",
        "agents.exit": "operator",
        "agents.sleep": "operator",
        "chat.send": "operator",
        "schedule.add": "operator",
        "task.claim": "operator",
        "task.release": "operator",
        "operators.focus": "operator",
        "schedule.remove": "admin",
        "events.test": "admin",
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
            self.events.append(ev)
            subs = list(self.subscribers)
        for name, q in subs:
            if to and name not in (to, sender):
                continue
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
        self.cancelled_ids: List[str] = []
        # Control frames actually received (proves 0x18 is on the wire).
        self.cancels_received: List[str] = []

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
                    break
                return
            if not batch:
                return
            for task in batch.get("tasks", []):
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
        if kind in ("exit", "kill"):
            self._stop.set()
            return 0, b"bye\n", "", {}
        if kind in ("download", "cat"):
            return self._download(args)
        if kind == "upload":
            return self._upload(args)
        return 0, f"mock agent cannot run {kind!r}\n".encode(), "", {}

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
