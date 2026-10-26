"""Framed stream I/O over a socket (TCP transport)."""

from __future__ import annotations

import socket
import struct
import threading
from typing import Any, Optional

from . import wire

__all__ = ["Stream", "StreamError", "SendGate"]


class StreamError(Exception):
    pass


class Stream:
    """Reads/writes whole UmbraC2 frames over a byte stream."""

    def __init__(self, sock: socket.socket, timeout: Optional[float] = None) -> None:
        self.sock = sock
        self.sock.settimeout(timeout)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send_frame(self, frame: bytes) -> None:
        self.sock.sendall(frame)

    def _read_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise StreamError("connection closed by peer")
            buf += chunk
        return bytes(buf)

    def recv_frame(self) -> bytes:
        prelude = self._read_exact(wire.PRELUDE_LEN)
        if prelude[0:2] != wire.MAGIC:
            raise StreamError("bad magic on stream")
        (length,) = struct.unpack(">I", prelude[8:12])
        if length > wire.MAX_BODY:
            raise StreamError("frame too large")
        rest = self._read_exact(wire.NONCE_LEN + length + wire.TAG_LEN)
        return prelude + rest


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
