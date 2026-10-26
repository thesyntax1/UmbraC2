"""The WebSocket transport (RFC 6455).

The umbra protocol is a stream of binary frames.  A WebSocket carries exactly
that: every umbra frame becomes one binary WebSocket frame, and the frames
keep their order.  The transport is therefore a thin layer over the same
``FrameStream`` contract the TCP transport uses, and everything above it --
the handshake, the session state machine, the task queue -- does not change.

Why it exists:

* a CDN or a reverse proxy in front of the server speaks WebSocket, and a
  beacon that only knows HTTP has to poll;
* a long-lived connection beats a poll per cycle: the server can push a task
  the moment it is queued;
* the traffic looks like an ordinary browser session.

Only what the transport needs is implemented: the opening handshake, binary
frames, ping/pong and a clean close.  There is no extension negotiation and
no fragmentation on the send side -- the umbra frames are small enough to fit
into one WebSocket frame (the server accepts frames up to ``wire.MaxFrame``).

The masking rule of RFC 6455 is honoured: a client masks its frames, a server
does not.
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
from typing import Dict, Optional, Tuple

# The GUID of RFC 6455 that turns the client key into the accept value.
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# The WebSocket opcodes the transport uses.
OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

# The largest frame the transport reads.  The umbra frames are smaller, but a
# hostile peer could try to make the server allocate.
MAX_FRAME = 1 << 21

# The largest mask offset the transport accepts (RFC 6455 allows any value,
# but a huge offset only wastes CPU).
MAX_MASK_OFFSET = 1 << 24


class WebSocketError(Exception):
    """A framing or handshake error."""


def accept_value(key: str) -> str:
    """The ``Sec-WebSocket-Accept`` value for a client key.

    RFC 6455 defines it as the base64 of the SHA-1 of the key concatenated
    with the protocol GUID.  The example of the RFC is the test vector of the
    test-suite.
    """
    digest = hashlib.sha1((key + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def client_key() -> str:
    """A fresh client key: 16 random bytes in base64."""
    return base64.b64encode(os.urandom(16)).decode("ascii")


def encode_frame(payload: bytes, opcode: int = OP_BINARY, mask: Optional[bytes] = None) -> bytes:
    """Build one WebSocket frame.

    ``mask`` is the four byte masking key of a client frame.  A server frame
    is sent without a mask.
    """
    header = bytearray()
    header.append(0x80 | (opcode & 0x0F))
    length = len(payload)
    masked = 0x80 if mask is not None else 0x00
    if length < 126:
        header.append(masked | length)
    elif length < (1 << 16):
        header.append(masked | 126)
        header += struct.pack("!H", length)
    else:
        header.append(masked | 127)
        header += struct.pack("!Q", length)
    if mask is None:
        return bytes(header) + payload
    if len(mask) != 4:
        raise WebSocketError("a masking key is four bytes long")
    header += mask
    masked_payload = bytearray(payload)
    for index in range(length):
        masked_payload[index] ^= mask[index & 3]
    return bytes(header) + bytes(masked_payload)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly ``count`` bytes."""
    chunks = bytearray()
    while len(chunks) < count:
        block = sock.recv(count - len(chunks))
        if not block:
            raise WebSocketError("the peer closed the connection")
        chunks += block
    return bytes(chunks)


def _decode_frame(read, send) -> Tuple[int, bytes]:
    """Decode one frame with the given reader.

    ``read(count)`` returns exactly ``count`` bytes, ``send(bytes)`` writes
    them.  Both sides of the connection use this, so the framing rules live in
    one place: a client and a server can never disagree about a frame.
    """
    while True:
        first, second = read(2)
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", read(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", read(8))[0]
        if length > MAX_FRAME:
            raise WebSocketError(f"the frame is too large ({length} bytes)")
        mask = read(4) if masked else b""
        payload = read(length) if length else b""
        if masked:
            payload = bytes(byte ^ mask[index & 3] for index, byte in enumerate(payload))
        if opcode == OP_CLOSE:
            raise WebSocketError("the peer closed the connection")
        if opcode == OP_PING:
            send(encode_frame(payload, OP_PONG))
            continue
        if opcode == OP_PONG:
            continue
        if not fin:
            raise WebSocketError("fragmented frames are not supported")
        return opcode, payload


def read_frame(sock: socket.socket) -> Tuple[int, bytes]:
    """Read one WebSocket frame and return its opcode and payload.

    Control frames (ping, pong, close) are handled here: a ping is answered
    with a pong, a close ends the connection.
    """
    return _decode_frame(lambda count: _recv_exact(sock, count), sock.sendall)


class WebSocketClient:
    """A WebSocket client for the umbra transport."""

    def __init__(self, host: str, port: int, path: str = "/", host_header: str = "",
                 extra_headers: Optional[Dict[str, str]] = None, timeout: float = 30.0) -> None:
        self.host = host
        self.port = port
        self.path = path or "/"
        self.host_header = host_header or f"{host}:{port}"
        self.extra_headers = dict(extra_headers or {})
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        # Bytes of the handshake response that belong to the frame reader.
        self._pending = b""

    def connect(self) -> None:
        """Open the connection and perform the opening handshake."""
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        key = client_key()
        lines = [
            f"GET {self.path} HTTP/1.1",
            f"Host: {self.host_header}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        for name, value in self.extra_headers.items():
            lines.append(f"{name}: {value}")
        request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
        sock.sendall(request)
        head = b""
        while b"\r\n\r\n" not in head:
            block = sock.recv(4096)
            if not block:
                sock.close()
                raise WebSocketError("the server closed the connection during the handshake")
            head += block
            if len(head) > 16384:
                sock.close()
                raise WebSocketError("the handshake response is too large")
        header, _, rest = head.partition(b"\r\n\r\n")
        text = header.decode("latin-1")
        status = text.split("\r\n", 1)[0]
        if " 101 " not in status:
            sock.close()
            raise WebSocketError(f"the server refused the upgrade: {status}")
        accept = ""
        for line in text.split("\r\n")[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "sec-websocket-accept":
                accept = value.strip()
        if accept != accept_value(key):
            sock.close()
            raise WebSocketError("the server did not confirm the WebSocket key")
        # The rest of the response (if any) belongs to the frame reader.
        self._sock = sock
        self._pending = rest

    def _read(self, count: int) -> bytes:
        assert self._sock is not None
        pending = self._pending
        if pending:
            self._pending = b""
            if len(pending) >= count:
                # The rest belongs to the next frame: it arrived in the same
                # segment as the handshake response and must not be dropped.
                self._pending = pending[count:]
                return pending[:count]
            return pending + _recv_exact(self._sock, count - len(pending))
        return _recv_exact(self._sock, count)

    def write_frame(self, payload: bytes) -> None:
        """Send one binary frame (masked, as a client has to)."""
        assert self._sock is not None
        self._sock.sendall(encode_frame(payload, OP_BINARY, os.urandom(4)))

    def read_frame(self) -> bytes:
        """Read the payload of the next binary frame."""
        assert self._sock is not None
        while True:
            opcode, payload = self._read_ws_frame()
            if opcode == OP_BINARY or opcode == OP_TEXT:
                return payload

    def _read_ws_frame(self) -> Tuple[int, bytes]:
        assert self._sock is not None
        return _decode_frame(self._read, self._sock.sendall)

    def close(self) -> None:
        """Close the connection, politely."""
        sock = self._sock
        self._sock = None
        if sock is None:
            return
        try:
            sock.sendall(encode_frame(b"", OP_CLOSE))
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


class WebSocketStream:
    """Carries umbra frames inside WebSocket frames.

    It has the same three methods as ``netio.Stream``, so the session state
    machine does not know which transport it runs on.
    """

    def __init__(self, transport) -> None:
        self._ws = transport

    def send_frame(self, frame: bytes) -> None:
        """Send one umbra frame."""
        self._ws.write_frame(frame)

    def recv_frame(self) -> bytes:
        """Read one umbra frame."""
        return self._ws.read_frame()

    def close(self) -> None:
        """Close the transport."""
        self._ws.close()


class WebSocketServer:
    """The server side of the opening handshake.

    It is used by the test double and by the tests; the Go server implements
    the same handshake on its own HTTP listener.
    """

    def __init__(self, sock: socket.socket, path: str = "/") -> None:
        self.sock = sock
        self.path = path
        # Bytes that arrived with the upgrade request and belong to the
        # frame reader.
        self._pending = b""

    def _read(self, count: int) -> bytes:
        pending = self._pending
        if pending:
            self._pending = b""
            if len(pending) >= count:
                self._pending = pending[count:]
                return pending[:count]
            return pending + _recv_exact(self.sock, count - len(pending))
        return _recv_exact(self.sock, count)

    def handshake(self) -> bool:
        """Read the upgrade request and answer it.

        Returns False when the request is not a WebSocket upgrade; the
        caller then treats the connection as a normal HTTP request.
        """
        head = b""
        while b"\r\n\r\n" not in head:
            block = self.sock.recv(4096)
            if not block:
                return False
            head += block
            if len(head) > 16384:
                return False
        head, _, rest = head.partition(b"\r\n\r\n")
        text = head.decode("latin-1")
        # A client that is quick enough sends its first frame in the same
        # segment as the upgrade request; those bytes belong to the frame
        # reader, not to the handshake.
        self._pending = rest
        lines = text.split("\r\n")
        request = lines[0]
        if not request.startswith("GET "):
            return False
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        if "websocket" not in headers.get("upgrade", "").lower():
            return False
        key = headers.get("sec-websocket-key", "")
        if not key:
            return False
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_value(key)}\r\n"
            "\r\n"
        )
        self.sock.sendall(response.encode("ascii"))
        return True

    def write_frame(self, payload: bytes) -> None:
        """Send one binary frame (a server frame is never masked)."""
        self.sock.sendall(encode_frame(payload, OP_BINARY))

    def read_frame(self) -> bytes:
        """Read the payload of the next binary frame."""
        while True:
            opcode, payload = _decode_frame(self._read, self.sock.sendall)
            if opcode in (OP_BINARY, OP_TEXT):
                return payload

    def close(self) -> None:
        """Close the connection."""
        try:
            self.sock.sendall(encode_frame(b"", OP_CLOSE))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
