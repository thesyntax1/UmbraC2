"""The DNS tunnel.

The tunnel lets an implant talk to the team server when every other channel
is blocked: the agent asks a resolver for a name that belongs to the tunnel
domain and the answer carries the next frame.

The wire format is the same on the server (server/internal/dnstun), on the
beacon (implant/rust/src/dns.rs) and here:

    query   <seq>.<chunk>.<agent>.<domain>
    answer  TXT records, each one base32 of a slice of the frame

* ``seq``    is the sequence number of the query, eight hex characters.
* ``chunk``  is the base32 of the bytes the agent sends in this query.
* ``agent``  is the base32 of the agent id.

Both directions are length prefixed: a four byte big endian length in front
of every frame, so a chunk that ends in the middle of a frame is reassembled
instead of breaking the stream.

This module is the reference implementation of that format: the tests use it
to prove that the framing round-trips, and a lab can use the server half to
try the transport without building the Go server.
"""

from __future__ import annotations

import base64
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple

__all__ = [
    "DnsTunnelClient",
    "DnsTunnelServer",
    "base32_encode",
    "base32_decode",
    "build_query",
    "parse_txt",
    "encode_name",
]

# The DNS record types the tunnel uses.
TYPE_TXT = 16
CLASS_IN = 1

# The number of payload bytes in one query label.
CHUNK = 32

# The number of TXT records one answer carries.
MAX_RECORDS = 8

# The label that stands for "no payload".  A DNS label cannot be empty, so
# the query needs a placeholder for the polls that carry nothing.
EMPTY_LABEL = "-"


def base32_encode(data: bytes) -> str:
    """Encode bytes as base32 (RFC 4648, no padding, upper case)."""
    return base64.b32encode(data).decode("ascii").rstrip("=")


def base32_decode(text: str) -> bytes:
    """Decode a base32 string; the padding is optional."""
    padded = text.upper()
    padded += "=" * (-len(padded) % 8)
    return base64.b32decode(padded)


def encode_name(name: str) -> bytes:
    """Encode a domain name into DNS labels."""
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        raw = label.encode("ascii", "replace")[:63]
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_query(query_id: int, name: str) -> bytes:
    """Build a DNS query for one name."""
    header = struct.pack(">HHHHHH", query_id & 0xFFFF, 0x0100, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack(">HH", TYPE_TXT, CLASS_IN)
    return header + question


def skip_name(data: bytes, offset: int) -> int:
    """Skip a (possibly compressed) name and return the offset behind it."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def parse_txt(data: bytes) -> List[str]:
    """Read the TXT records of an answer."""
    out: List[str] = []
    if len(data) < 12:
        return out
    _, _, questions, answers, _, _ = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    for _ in range(questions):
        offset = skip_name(data, offset) + 4
        if offset > len(data):
            return out
    for _ in range(answers):
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype = struct.unpack(">H", data[offset:offset + 2])[0]
        rdlength = struct.unpack(">H", data[offset + 8:offset + 10])[0]
        offset += 10
        if offset + rdlength > len(data):
            break
        if rtype == TYPE_TXT:
            rdata = data[offset:offset + rdlength]
            if rdata:
                length = rdata[0]
                out.append(rdata[1:1 + length].decode("ascii", "replace"))
        offset += rdlength
    return out


def build_response(query_id: int, name: str, texts: List[str], ttl: int = 5) -> bytes:
    """Build the answer of a query."""
    header = struct.pack(">HHHHHH", query_id & 0xFFFF, 0x8180, 1, len(texts), 0, 0)
    question = encode_name(name) + struct.pack(">HH", TYPE_TXT, CLASS_IN)
    answers = bytearray()
    for text in texts:
        raw = text.encode("ascii", "replace")
        answers += b"\xc0\x0c"  # the answer points at the question name
        answers += struct.pack(">HHI", TYPE_TXT, CLASS_IN, ttl)
        answers += struct.pack(">H", len(raw) + 1)
        answers += bytes([len(raw)])
        answers += raw
    return header + question + bytes(answers)


class DnsTunnelClient:
    """The agent side of the tunnel."""

    def __init__(self, resolver: str, domain: str, agent_id: str, *, timeout: float = 10.0) -> None:
        host, _, port = resolver.rpartition(":")
        self.resolver = (host or "127.0.0.1", int(port or 53))
        self.domain = domain.rstrip(".").lower()
        self.agent = base32_encode(agent_id.encode())
        self.timeout = timeout
        self.seq = 0
        self._out = bytearray()
        self._inbound = bytearray()

    # -- framing ---------------------------------------------------------
    def write_frame(self, frame: bytes) -> None:
        """Queue a frame for the server."""
        self._out += struct.pack(">I", len(frame))
        self._out += frame

    def _take_frame(self) -> Optional[bytes]:
        if len(self._inbound) < 4:
            return None
        (size,) = struct.unpack(">I", bytes(self._inbound[:4]))
        if size == 0 or size > 8 * 1024 * 1024:
            self._inbound.clear()
            return None
        if len(self._inbound) < 4 + size:
            return None
        frame = bytes(self._inbound[4:4 + size])
        del self._inbound[:4 + size]
        return frame

    def read_frame(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Poll until a frame arrives."""
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
        while True:
            frame = self._take_frame()
            if frame is not None:
                return frame
            self.poll()
            frame = self._take_frame()
            if frame is not None:
                return frame
            if time.monotonic() > deadline:
                return None
            time.sleep(0.05)

    def poll(self) -> None:
        """Send one query and read the answer."""
        chunk = bytes(self._out[:CHUNK])
        del self._out[:len(chunk)]
        label = base32_encode(chunk) if chunk else EMPTY_LABEL
        name = f"{self.seq:08x}.{label}.{self.agent}.{self.domain}"
        self.seq = (self.seq + 1) & 0xFFFFFFFF
        query = build_query(self.seq, name)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.timeout)
            sock.sendto(query, self.resolver)
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        for text in parse_txt(data):
            try:
                self._inbound += base32_decode(text)
            except Exception:
                continue


class DnsTunnelServer:
    """The server side of the tunnel (the reference for the Go package)."""

    def __init__(self, domain: str, *, host: str = "127.0.0.1", port: int = 0) -> None:
        self.domain = domain.rstrip(".").lower()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((host, port))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._channels: Dict[str, Dict[str, object]] = {}
        self._lock = threading.Lock()

    @property
    def address(self) -> str:
        host, port = self._sock.getsockname()
        return f"{host}:{port}"

    def start(self) -> "DnsTunnelServer":
        self._thread = threading.Thread(target=self._serve, daemon=True, name="dns-tunnel")
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def __enter__(self) -> "DnsTunnelServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- the agent facing side ------------------------------------------
    def send(self, agent_id: str, frame: bytes) -> None:
        """Queue a frame for an agent.

        The frame is length prefixed, exactly like the bytes the agent sends:
        both ends then agree on where a frame ends even when a chunk boundary
        falls in the middle of one.
        """
        with self._lock:
            channel = self._channels.setdefault(agent_id, {"inbound": bytearray(), "out": None})
            channel["out"] = struct.pack(">I", len(frame)) + frame

    def receive(self, agent_id: str) -> Optional[bytes]:
        """Take the next frame an agent sent."""
        with self._lock:
            channel = self._channels.setdefault(agent_id, {"inbound": bytearray(), "out": None})
            inbound: bytearray = channel["inbound"]  # type: ignore[assignment]
            if len(inbound) < 4:
                return None
            (size,) = struct.unpack(">I", bytes(inbound[:4]))
            if size == 0 or size > 8 * 1024 * 1024:
                inbound.clear()
                return None
            if len(inbound) < 4 + size:
                return None
            frame = bytes(inbound[4:4 + size])
            del inbound[:4 + size]
            return frame

    # -- the wire ---------------------------------------------------------
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except OSError:
                return
            response = self.handle(data)
            if response:
                try:
                    self._sock.sendto(response, addr)
                except OSError:
                    pass

    def handle(self, query: bytes) -> Optional[bytes]:
        """Answer one query."""
        if len(query) < 12:
            return None
        query_id, flags = struct.unpack(">HH", query[:4])
        if flags & 0x8000:
            return None
        name, offset = self._parse_question(query, 12)
        if name is None:
            return None
        if self.domain and not (name == self.domain or name.endswith("." + self.domain)):
            return None
        agent_id, chunk = self._parse_name(name)
        if agent_id is None:
            return None
        with self._lock:
            channel = self._channels.setdefault(agent_id, {"inbound": bytearray(), "out": None})
            inbound: bytearray = channel["inbound"]  # type: ignore[assignment]
            inbound += chunk
            out = channel["out"]
            if out is not None:
                channel["out"] = None
        texts: List[str] = []
        if out:
            for i in range(0, len(out), CHUNK):
                texts.append(base32_encode(out[i:i + CHUNK]))
                if len(texts) >= MAX_RECORDS:
                    break
        return build_response(query_id, name, texts)

    def _parse_question(self, data: bytes, offset: int) -> Tuple[Optional[str], int]:
        labels: List[str] = []
        while offset < len(data):
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0:
                return None, offset
            labels.append(data[offset:offset + length].decode("ascii", "replace"))
            offset += length
        return ".".join(labels), offset

    def _parse_name(self, name: str) -> Tuple[Optional[str], bytes]:
        trimmed = name.rstrip(".").lower()
        if self.domain:
            if trimmed == self.domain:
                return None, b""
            trimmed = trimmed[: -(len(self.domain) + 1)]
        labels = trimmed.split(".")
        if len(labels) < 3:
            return None, b""
        seq_label, chunk_label, agent_label = labels[-3], labels[-2], labels[-1]
        try:
            agent = base32_decode(agent_label).decode("utf-8", "replace")
        except Exception:
            return None, b""
        chunk = b""
        if chunk_label and chunk_label != EMPTY_LABEL:
            try:
                chunk = base32_decode(chunk_label)
            except Exception:
                return None, b""
        return agent, chunk
