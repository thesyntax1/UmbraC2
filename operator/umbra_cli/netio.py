"""Framed stream I/O over a socket (TCP transport).

A stream carries whole UmbraC2 frames.  Two shapes of it exist:

* a plain TCP socket, and
* a TLS socket.

They are not the same thing to work with.  A plain socket has two
independent directions, so one thread may read while another writes.  A TLS
socket is *one* OpenSSL session: the record layer keeps state in it (the
sequence numbers, the write buffer, a pending key update), and OpenSSL --
like CPython's ``ssl`` module -- does not allow a read and a write to overlap
on it.  Two threads inside the same session at once scramble the stream: the
peer sees a bad record MAC, or the connection dies half way through a frame.

The operator control channel *does* read and write at the same time: one
thread waits for requests, another one pushes events.  So a TLS stream
serialises every operation on the session with one lock, and it waits for the
socket *outside* of that lock: a reader that blocks inside the lock would
freeze the writer, and a writer that blocks inside the lock would freeze the
reader.
"""

from __future__ import annotations

import select
import socket
import ssl
import struct
import threading
import time
from typing import Any, Optional

from . import wire

__all__ = ["Stream", "ByteStream", "SocketBytes", "StreamError", "SendGate"]


class StreamError(Exception):
    pass


class Stream:
    """Reads/writes whole UmbraC2 frames over a byte stream.

    ``timeout`` is how long one read or one write waits for the socket.  It
    is honoured the same way for a plain and for a TLS socket: a plain socket
    waits inside ``recv``/``sendall``, a TLS socket waits in ``select`` while
    the lock is free.
    """

    def __init__(self, sock: socket.socket, timeout: Optional[float] = None) -> None:
        self.sock = sock
        self.timeout = timeout
        # One lock per connection.  It keeps the OpenSSL session to one
        # operation at a time.
        self._lock = threading.Lock()
        # Set when a write could not be finished: the frame on the wire is
        # half written, so the session cannot carry anything else.
        self._broken = False
        self._tls = isinstance(sock, ssl.SSLSocket)
        if self._tls:
            # The socket itself never blocks: the waiting happens in select(),
            # outside of the lock.
            sock.settimeout(0)
        else:
            sock.settimeout(timeout)

    # -- lifecycle -------------------------------------------------------
    def set_timeout(self, timeout: Optional[float]) -> None:
        """Change how long a read or a write waits for the socket."""
        self.timeout = timeout
        if not self._tls:
            self.sock.settimeout(timeout)

    def close(self) -> None:
        try:
            # A shutdown wakes a thread that waits in select(); without it
            # the reader sleeps until its timeout before it notices.
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    # -- writing ---------------------------------------------------------
    def send_frame(self, frame: bytes) -> None:
        if not self._tls:
            self.sock.sendall(frame)
            return
        view = memoryview(frame)
        sent = 0
        deadline = self._deadline()
        while sent < len(view):
            with self._lock:
                if self._broken:
                    raise StreamError("the TLS session is broken")
                try:
                    count = self.sock.send(view[sent:])
                except (ssl.SSLWantWriteError, BlockingIOError):
                    # The socket cannot take the record yet.  OpenSSL keeps
                    # the plaintext, so the very same buffer is sent again
                    # below -- never a fresh copy of it.
                    count = 0
                else:
                    sent += count
                    continue
            # Waiting happens outside of the lock, so a reader (or another
            # writer) can use the session while the socket is full.
            if not self._wait(writable=True, deadline=deadline):
                self._broken = True
                raise socket.timeout("timed out writing to the TLS session")

    # -- reading ---------------------------------------------------------
    def _read_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._recv(n - len(buf))
            if not chunk:
                raise StreamError("connection closed by peer")
            buf += chunk
        return bytes(buf)

    def _recv(self, n: int) -> bytes:
        """Read up to n bytes.  An empty result means the peer closed."""
        if not self._tls:
            return self.sock.recv(n)
        deadline = self._deadline()
        while True:
            with self._lock:
                if self._broken:
                    raise StreamError("the TLS session is broken")
                try:
                    pending = self.sock.pending()
                except (OSError, ValueError):
                    pending = 0
                if pending:
                    # OpenSSL already decrypted a record: no socket wait.
                    return self.sock.recv(min(n, pending))
                try:
                    return self.sock.recv(n)
                except ssl.SSLWantReadError:
                    writable = False
                except ssl.SSLWantWriteError:
                    # The session wants to send something (a key update, a
                    # renegotiation): it needs a socket it can write to.
                    writable = True
                except BlockingIOError:
                    writable = False
            if not self._wait(writable=writable, deadline=deadline):
                raise socket.timeout("timed out reading from the TLS session")

    def recv_frame(self) -> bytes:
        prelude = self._read_exact(wire.PRELUDE_LEN)
        if prelude[0:2] != wire.MAGIC:
            raise StreamError("bad magic on stream")
        (length,) = struct.unpack(">I", prelude[8:12])
        if length > wire.MAX_BODY:
            raise StreamError("frame too large")
        rest = self._read_exact(wire.NONCE_LEN + length + wire.TAG_LEN)
        return prelude + rest

    # -- waiting ---------------------------------------------------------
    def _deadline(self) -> Optional[float]:
        if self.timeout is None:
            return None
        return time.monotonic() + self.timeout

    def _wait(self, writable: bool, deadline: Optional[float]) -> bool:
        """Wait until the socket is ready.  False when the deadline passed."""
        if deadline is None:
            remaining = None
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
        rlist = [] if writable else [self.sock]
        wlist = [self.sock] if writable else []
        try:
            ready_r, ready_w, _ = select.select(rlist, wlist, [], remaining)
        except (OSError, ValueError) as exc:
            raise StreamError(f"the socket is gone: {exc}") from exc
        return bool(ready_r or ready_w)


class SocketBytes:
    """The byte stream of a socket.

    ``read(n)`` returns exactly ``n`` bytes or raises, and ``write`` sends
    everything.  That is the contract every byte stream in the framework
    follows, so the peer handshake can run over a socket, over a tunnel
    stream or over a pipe.
    """

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def read(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise StreamError("connection closed by peer")
            buf += chunk
        return bytes(buf)

    def write(self, data: bytes) -> int:
        if data:
            self.sock.sendall(data)
        return len(data)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class ByteStream:
    """The umbra frame layer over a byte stream.

    A byte stream is anything with ``read(n)`` -- exactly ``n`` bytes or an
    exception -- and ``write(data)`` -- all of it: a socket, a tunnel
    stream, a pipe.  The frames are the ordinary umbra frames, so anything
    that speaks them can run over anything that carries bytes.

    This is what makes a *chained* pivot possible: the far end of a hop
    only sees bytes, and the frames of the next hop travel inside them.
    """

    def __init__(self, rw: Any, timeout: Optional[float] = None) -> None:
        self.rw = rw
        self.timeout = timeout
        self._buf = bytearray()
        self._lock = threading.Lock()

    def send_frame(self, frame: bytes) -> None:
        with self._lock:
            self.rw.write(frame)

    def _fill(self, n: int) -> None:
        while len(self._buf) < n:
            chunk = self.rw.read(n - len(self._buf))
            if not chunk:
                raise StreamError("connection closed by peer")
            self._buf += chunk

    def recv_frame(self) -> bytes:
        self._fill(wire.PRELUDE_LEN)
        prelude = bytes(self._buf[: wire.PRELUDE_LEN])
        if prelude[0:2] != wire.MAGIC:
            raise StreamError("bad magic on stream")
        (length,) = struct.unpack(">I", prelude[8:12])
        if length > wire.MAX_BODY:
            raise StreamError("frame too large")
        total = wire.PRELUDE_LEN + wire.NONCE_LEN + length + wire.TAG_LEN
        self._fill(total)
        frame = bytes(self._buf[:total])
        del self._buf[:total]
        return frame

    def close(self) -> None:
        closer = getattr(self.rw, "close", None)
        if closer is None:
            return
        try:
            closer()
        except OSError:
            pass


class SendGate:
    """Serialises *sealing and writing* so frames leave in nonce order.

    ``Session.encrypt`` reserves a nonce atomically, but that alone is not
    enough: if two threads seal frames (getting counters 5 and 6) and then race
    to ``send_frame``, the peer may see 6 before 5 and drop the link with
    "nonce mismatch".  The protocol requires strictly increasing counters, so
    the seal+write pair has to be one critical section -- exactly one writer at
    a time, per connection.

    Any connection with more than one potential writer (a request handler plus
    an event/heartbeat pusher) must send through a single gate.
    """

    def __init__(self, session: Any, stream: Stream) -> None:
        self._session = session
        self._stream = stream
        self._lock = threading.Lock()

    def send(self, msg_type: int, body: Any) -> None:
        with self._lock:
            frame = self._session.encrypt(msg_type, body)
            self._stream.send_frame(frame)

    def send_frame(self, frame: bytes) -> None:
        """Send an already sealed frame (handshake / test paths)."""
        with self._lock:
            self._stream.send_frame(frame)
