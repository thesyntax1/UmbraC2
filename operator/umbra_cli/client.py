"""Operator-side client for the UmbraC2 team server.

The operator authenticates with its own token (never the agent PSK), which the
server maps to an operator identity.  All RPC traffic rides the same encrypted
frame format the implants use.
"""

from __future__ import annotations

import queue
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from . import crypto, handshake, netio, session, upk, wire

__all__ = ["OperatorClient", "OperatorError", "RpcResult"]


class OperatorError(Exception):
    pass


class RpcResult:
    """Result of one operator RPC."""

    __slots__ = ("ok", "data", "error")

    def __init__(self, ok: bool, data: Dict[str, Any], error: str = "") -> None:
        self.ok = ok
        self.data = data
        self.error = error

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"RpcResult(ok={self.ok}, error={self.error!r})"


class OperatorClient:
    """Thread-safe RPC client with an asynchronous event stream."""

    def __init__(
        self,
        server: str,
        token: str,
        operator: str,
        *,
        timeout: float = 15.0,
        on_event: Optional[Callable[[Dict[str, Any]], None]] = None,
        verbose: bool = False,
    ) -> None:
        self.server = server
        self.operator = operator
        self._token = token.encode() if isinstance(token, str) else token
        self.timeout = timeout
        self.on_event = on_event
        self.verbose = verbose

        self._stream: Optional[netio.Stream] = None
        self._session: Optional[session.Session] = None
        self._pending: Dict[int, "queue.Queue[Dict[str, Any]]"] = {}
        self._rid = 0
        self._lock = threading.Lock()
        self._reader: Optional[threading.Thread] = None
        self._closing = threading.Event()
        # Events are pushed to a bounded queue as well as to the callback, so
        # `umbra watch` can block on them without polling or a second thread.
        self._events: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=1024)
        self.session_id = b""
        self.server_meta: Dict[str, Any] = {}

    # -- lifecycle -------------------------------------------------------
    def connect(self) -> None:
        host, _, port = self.server.rpartition(":")
        if not host:
            raise OperatorError("server must be host:port")
        try:
            sock = socket.create_connection((host, int(port)), timeout=self.timeout)
        except OSError as exc:
            raise OperatorError(f"connect {self.server}: {exc}") from exc
        sock.settimeout(self.timeout)
        self._stream = netio.Stream(sock, timeout=self.timeout)

        result = handshake.client_handshake(
            self._stream,
            psk=self._token,
            role=crypto.ROLE_OPERATOR,
            ident=self.operator,
            suite=wire.SUITE_AES256_GCM,
            meta={"client": "umbra-cli", "ver": "0.1.0"},
        )
        self._session = result.session
        self.session_id = result.session_id
        self.server_meta = result.meta
        self._stream.sock.settimeout(None)  # the reader thread owns the socket
        # Requests are written by the calling thread today, but routing them
        # through a gate keeps the "seal+write is one step" invariant explicit
        # if a background writer is ever added. See netio.SendGate.
        self._gate = netio.SendGate(self._session, self._stream)

        self._reader = threading.Thread(target=self._read_loop, name="umbra-events", daemon=True)
        self._reader.start()

    def close(self) -> None:
        self._closing.set()
        if self._stream:
            self._stream.close()
        if self._reader and self._reader.is_alive():
            self._reader.join(timeout=2)

    def __enter__(self) -> "OperatorClient":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- rpc -------------------------------------------------------------
    def rpc(self, cmd: str, args: Optional[Dict[str, Any]] = None) -> RpcResult:
        if self._session is None or self._stream is None:
            raise OperatorError("not connected")
        with self._lock:
            self._rid += 1
            rid = self._rid
            inbox: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=1)
            self._pending[rid] = inbox
        request = {"rid": rid, "cmd": cmd, "args": args or {}}
        try:
            self._gate.send(wire.MsgType.OP_REQUEST, request)
            try:
                resp = inbox.get(timeout=self.timeout)
            except queue.Empty:
                raise OperatorError(f"timeout waiting for {cmd!r}") from None
        finally:
            with self._lock:
                self._pending.pop(rid, None)
        data = resp.get("data") or {}
        return RpcResult(bool(resp.get("ok")), data, str(resp.get("err", "")))

    # -- events ----------------------------------------------------------
    def _read_loop(self) -> None:
        assert self._stream is not None and self._session is not None
        while not self._closing.is_set():
            try:
                raw = self._stream.recv_frame()
            except (OSError, netio.StreamError):
                break
            try:
                msg_type, body = self._session.decrypt_message(raw)
            except (session.SessionError, ValueError, upk.UpkError):
                break
            if msg_type == wire.MsgType.OP_RESPONSE:
                rid = body.get("rid")
                with self._lock:
                    inbox = self._pending.get(rid if isinstance(rid, int) else int(rid or 0))
                if inbox is not None:
                    inbox.put(body)
            elif msg_type == wire.MsgType.OP_EVENT:
                try:
                    self._events.put_nowait(body)
                except queue.Full:
                    # A console that is not consuming events (a slow terminal)
                    # must not stall the reader: drop the oldest queued event.
                    try:
                        self._events.get_nowait()
                        self._events.put_nowait(body)
                    except queue.Empty:  # pragma: no cover - racy but harmless
                        pass
                if self.on_event:
                    try:
                        self.on_event(body)
                    except Exception:  # pragma: no cover - UI must never crash the link
                        pass
        self._closing.set()

    # -- convenience wrappers -------------------------------------------
    def agents(self) -> List[Dict[str, Any]]:
        res = self.rpc("agents.list")
        if not res.ok:
            raise OperatorError(res.error)
        return list(res.data.get("agents", []))

    def whoami(self) -> Dict[str, Any]:
        res = self.rpc("whoami")
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def say(self, text: str) -> Dict[str, Any]:
        res = self.rpc("chat.send", {"text": text})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def chat_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        res = self.rpc("chat.history", {"limit": limit})
        if not res.ok:
            raise OperatorError(res.error)
        return list(res.data.get("messages", []))

    def schedules(self) -> List[Dict[str, Any]]:
        res = self.rpc("schedule.list")
        if not res.ok:
            raise OperatorError(res.error)
        return list(res.data.get("schedules", []))

    def add_schedule(self, agent_id: str, kind: str, every: int, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        res = self.rpc("schedule.add", {"id": agent_id, "kind": kind, "every": every, "args": args or {}})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def remove_schedule(self, schedule_id: str) -> None:
        res = self.rpc("schedule.remove", {"schedule_id": schedule_id})
        if not res.ok:
            raise OperatorError(res.error)

    def operators(self) -> List[Dict[str, Any]]:
        res = self.rpc("operators.list")
        if not res.ok:
            raise OperatorError(res.error)
        return list(res.data.get("operators", []))

    def agent_info(self, agent_id: str) -> Dict[str, Any]:
        res = self.rpc("agents.info", {"id": agent_id})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def submit(self, agent_id: str, kind: str, args: Optional[Dict[str, Any]] = None) -> str:
        res = self.rpc("task.submit", {"id": agent_id, "kind": kind, "args": args or {}})
        if not res.ok:
            raise OperatorError(res.error)
        return str(res.data.get("task_id", ""))

    def task(self, task_id: str) -> Dict[str, Any]:
        res = self.rpc("task.get", {"task_id": task_id})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def tasks(self, agent_id: str, limit: int = 25) -> List[Dict[str, Any]]:
        res = self.rpc("task.list", {"id": agent_id, "limit": limit})
        if not res.ok:
            raise OperatorError(res.error)
        return list(res.data.get("tasks", []))

    def stats(self) -> Dict[str, Any]:
        res = self.rpc("server.stats")
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def next_event(self, timeout: Optional[float] = 3600.0) -> Optional[Dict[str, Any]]:
        """Return the next pushed event, or None if none arrives in time."""
        try:
            return self._events.get(timeout=timeout)
        except queue.Empty:
            return None

    def cancel(self, task_id: str) -> None:
        res = self.rpc("task.cancel", {"task_id": task_id})
        if not res.ok:
            raise OperatorError(res.error)

    def audit(self, limit: int = 50) -> Dict[str, Any]:
        """Recent operator actions, newest first.

        Returns the whole payload (``entries`` + ``enabled``) so the caller can
        tell "nothing has happened yet" from "auditing is switched off".
        """
        res = self.rpc("audit.tail", {"limit": limit})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def set_sleep(self, agent_id: str, sleep: int, jitter: int) -> None:
        res = self.rpc("agents.sleep", {"id": agent_id, "sleep": sleep, "jitter": jitter})
        if not res.ok:
            raise OperatorError(res.error)

    def wait_for_result(self, task_id: str, timeout: float = 60.0, poll: float = 1.0) -> Dict[str, Any]:
        """Poll until a task leaves the queued/delivered state."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data = self.task(task_id)
            if data.get("state") in ("done", "failed", "cancelled"):
                return data
            time.sleep(poll)
        raise OperatorError(f"timeout waiting for task {task_id}")
