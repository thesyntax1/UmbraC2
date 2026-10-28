"""The peer link: one beacon carrying a pivot for another.

The link is a handshake, a key exchange and then the umbra session, carried
over a byte stream.  Two things ride on it:

* the server plays it when a pivot is *chained*: it asks the first agent for
  a stream to the next one and then speaks the peer protocol on that
  stream, so the operator only names the far end;
* two beacons play it with each other, so a host that cannot reach the
  server can still be reached through its neighbour.

The handshake is deliberately small.  It is not the umbra handshake: the
peer link runs over a byte stream that may be a tunnel, a pipe or a socket,
so the messages cannot be umbra frames.  They are length prefixed maps:

    peer hello   {id, pub, nonce, mac}
    peer ack     {id, pub, nonce, mac}

The hello proves that the sender owns the pre-shared key and the key it
claims.  The answer proves the same for the other side and covers *both*
hellos, so the transcript cannot be rearranged and neither half can be
replayed into another link.

The session that follows is the ordinary umbra session, so the frames that
ride on it are the ordinary frames: a pivot stream is asked for with
``TUNNEL_OPEN`` and the bytes travel in ``TUNNEL_DATA``.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, Optional, Tuple

from . import crypto, netio, session, upk, wire

__all__ = [
    "PeerError",
    "PeerHello",
    "MAX_PEER_FRAME",
    "peer_hello_mac",
    "peer_ack_mac",
    "dial_peer",
    "accept_peer",
    "PeerLink",
]

# The largest handshake message that is accepted.
MAX_PEER_FRAME = 4096


class PeerError(Exception):
    """The peer link could not be established."""


class PeerHello:
    """One half of the peer handshake."""

    __slots__ = ("id", "pub", "nonce", "mac")

    def __init__(self, ident: str, pub: bytes, nonce: bytes, mac: bytes) -> None:
        self.id = ident
        self.pub = pub
        self.nonce = nonce
        self.mac = mac

    def to_map(self) -> Dict[str, Any]:
        return {"id": self.id, "pub": self.pub, "nonce": self.nonce, "mac": self.mac}

    @staticmethod
    def from_map(body: Dict[str, Any]) -> "PeerHello":
        ident = str(body.get("id", ""))
        pub = body.get("pub") or b""
        nonce = body.get("nonce") or b""
        mac = body.get("mac") or b""
        if not ident or len(pub) != 32 or len(nonce) != 16 or len(mac) != 32:
            raise PeerError("malformed peer hello")
        return PeerHello(ident, bytes(pub), bytes(nonce), bytes(mac))


def peer_hello_mac(psk: bytes, ident: str, pub: bytes, nonce: bytes) -> bytes:
    """The tag of a peer hello.

    It binds the identity to the key and the nonce of the sender, so a
    hello cannot be replayed into another link.
    """
    msg = b"umbra/v1/p2p/hello" + ident.encode() + pub + nonce
    return crypto.hmac_sha256(psk, msg)


def peer_ack_mac(
    psk: bytes,
    hello_id: str,
    hello_pub: bytes,
    hello_nonce: bytes,
    ack_id: str,
    ack_pub: bytes,
    ack_nonce: bytes,
) -> bytes:
    """The tag of the answer.

    It covers both hellos: the transcript cannot be rearranged, and the
    answer cannot be replayed into another link.
    """
    msg = (
        b"umbra/v1/p2p/ack"
        + hello_id.encode()
        + hello_pub
        + hello_nonce
        + ack_id.encode()
        + ack_pub
        + ack_nonce
    )
    return crypto.hmac_sha256(psk, msg)


def _write_peer(rw: Any, payload: bytes) -> None:
    if not payload or len(payload) > MAX_PEER_FRAME:
        raise PeerError("the peer hello has a bad size")
    rw.write(len(payload).to_bytes(4, "big") + payload)


def _read_peer(rw: Any) -> Dict[str, Any]:
    head = rw.read(4)
    if len(head) != 4:
        raise PeerError("the peer closed the link during the handshake")
    size = int.from_bytes(head, "big")
    if size == 0 or size > MAX_PEER_FRAME:
        raise PeerError("the peer hello has a bad size")
    payload = rw.read(size)
    if len(payload) != size:
        raise PeerError("the peer closed the link during the handshake")
    body = upk.decode_exact(payload)
    if not isinstance(body, dict):
        raise PeerError("the peer hello is not a map")
    return body


def dial_peer(rw: Any, psk: bytes, ident: str) -> session.Session:
    """Play the initiator of a peer link over an open byte stream.

    The initiator speaks first.  Both sides derive the same session keys:
    the shared secret of the key exchange is mixed with the pre-shared key,
    so the link is only as good as the key both beacons already hold.
    """
    priv, pub = crypto.x25519_keypair()
    nonce = crypto.random_bytes(16)
    hello = PeerHello(ident, pub, nonce, peer_hello_mac(psk, ident, pub, nonce))
    _write_peer(rw, upk.encode(hello.to_map()))

    ack = PeerHello.from_map(_read_peer(rw))
    want = peer_ack_mac(psk, hello.id, hello.pub, hello.nonce, ack.id, ack.pub, ack.nonce)
    if not crypto.constant_time_eq(want, ack.mac):
        raise PeerError("the peer did not authenticate the transcript")

    shared = crypto.x25519_shared(priv, ack.pub)
    mixed = crypto.hmac_sha256(psk, shared)
    prk, material = crypto.derive_session(mixed, hello.nonce, ack.nonce)
    return session.Session(
        suite=wire.SUITE_AES256_GCM,
        material=material,
        is_server=False,
        bootstrap=False,
        prk=prk,
    )


def accept_peer(rw: Any, psk: bytes, ident: str) -> session.Session:
    """Play the responder of a peer link over an open byte stream."""
    hello = PeerHello.from_map(_read_peer(rw))
    want = peer_hello_mac(psk, hello.id, hello.pub, hello.nonce)
    if not crypto.constant_time_eq(want, hello.mac):
        raise PeerError("the peer did not authenticate")

    priv, pub = crypto.x25519_keypair()
    nonce = crypto.random_bytes(16)
    ack = PeerHello(ident, pub, nonce, peer_ack_mac(psk, hello.id, hello.pub, hello.nonce, ident, pub, nonce))
    _write_peer(rw, upk.encode(ack.to_map()))

    shared = crypto.x25519_shared(priv, hello.pub)
    mixed = crypto.hmac_sha256(psk, shared)
    prk, material = crypto.derive_session(mixed, hello.nonce, ack.nonce)
    return session.Session(
        suite=wire.SUITE_AES256_GCM,
        material=material,
        is_server=True,
        bootstrap=False,
        prk=prk,
    )


class PeerLink:
    """The tunnel protocol over a peer link.

    The frames are the ordinary umbra frames: the server asks the peer for a
    stream and the bytes travel in ``TUNNEL_DATA``.  The class is the
    *asking* side; the peer answers with ``TUNNEL_OPEN {op: result}`` and
    then the data frames of the stream.
    """

    def __init__(self, sess: session.Session, rw: Any, ident: str = "") -> None:
        self.sess = sess
        self.rw = rw
        self.ident = ident
        self.streams: Dict[str, "PeerStream"] = {}
        self.lock = threading.Lock()
        # The seal and the write are one critical section: the peer insists
        # on strictly increasing nonces (SEND-SERIAL).
        self.send_lock = threading.Lock()
        self.done = threading.Event()
        self._reader: Optional[threading.Thread] = None
        self._frames = netio.ByteStream(rw)

    # -- writing ---------------------------------------------------------
    def send(self, msg_type: int, body: Dict[str, Any]) -> None:
        """Seal one frame and write it."""
        with self.send_lock:
            frame = self.sess.encrypt(msg_type, body)
            self._frames.send_frame(frame)
            self._maybe_rekey()

    def _maybe_rekey(self) -> None:
        """Rotate the keys of the link when it carried enough frames.

        The REKEY frame is sealed with the old keys and carries the seed:
        both ends derive the same keys from it, so the link keeps running
        on its own.
        """
        if not self.sess.needs_rekey():
            return
        seed = crypto.random_bytes(32)
        frame = self.sess.encrypt(wire.MsgType.REKEY, {"seed": seed})
        self._frames.send_frame(frame)
        self.sess.apply_rekey(seed)

    # -- lifecycle -------------------------------------------------------
    def start(self) -> "PeerLink":
        """Read the answers of the peer in the background."""
        self._reader = threading.Thread(target=self.read_loop, name="umbra-peer", daemon=True)
        self._reader.start()
        return self

    def read_loop(self) -> None:
        frames = self._frames
        try:
            while not self.done.is_set():
                msg_type, body = self.sess.decrypt_message(frames.recv_frame())
                if msg_type == wire.MsgType.TUNNEL_OPEN:
                    self._on_open(body)
                elif msg_type == wire.MsgType.TUNNEL_DATA:
                    self._on_data(body)
                elif msg_type == wire.MsgType.TUNNEL_CLOSE:
                    self._on_close(body)
                elif msg_type == wire.MsgType.REKEY:
                    # The other end rotates the keys: the seed travels
                    # with the frame.
                    seed = body.get("seed") or b""
                    if len(seed) != 32:
                        raise PeerError("malformed REKEY seed")
                    self.sess.apply_rekey(bytes(seed))
        except Exception:
            pass
        finally:
            self.close()

    def close(self) -> None:
        if self.done.is_set():
            return
        self.done.set()
        with self.lock:
            streams = list(self.streams.values())
            self.streams.clear()
        for stream in streams:
            stream.closed.set()

    # -- the peer answers ------------------------------------------------
    def _on_open(self, body: Dict[str, Any]) -> None:
        if str(body.get("op", "")) != "result":
            return
        sid = str(body.get("stream", ""))
        with self.lock:
            stream = self.streams.get(sid)
        if stream is None:
            return
        ok = bool(body.get("ok"))
        err = str(body.get("err", ""))
        stream.result.put(None if ok else (err or "the peer refused the stream"))

    def _on_data(self, body: Dict[str, Any]) -> None:
        sid = str(body.get("stream", ""))
        data = body.get("data") or b""
        with self.lock:
            stream = self.streams.get(sid)
        if stream is None:
            return
        try:
            stream.data.put_nowait(bytes(data))
        except Exception:
            stream.closed.set()

    def _on_close(self, body: Dict[str, Any]) -> None:
        sid = str(body.get("stream", ""))
        with self.lock:
            stream = self.streams.get(sid)
        if stream is not None:
            stream.closed.set()

    # -- asking ----------------------------------------------------------
    def open_stream(self, host: str, port: int, timeout: float = 20.0) -> "PeerStream":
        """Ask the peer to connect to ``host:port`` and wait for the answer."""
        import queue
        import uuid

        from . import netio

        sid = "s-" + uuid.uuid4().hex[:12]
        stream = PeerStream(sid, self)
        with self.lock:
            self.streams[sid] = stream
        self.send(
            wire.MsgType.TUNNEL_OPEN,
            {"stream": sid, "op": "open", "host": host, "port": int(port)},
        )
        try:
            err = stream.result.get(timeout=timeout)
        except queue.Empty:
            err = "the peer did not answer the stream request"
        if err:
            with self.lock:
                self.streams.pop(sid, None)
            raise PeerError(err)
        return stream


class PeerStream:
    """One logical stream inside a peer link."""

    def __init__(self, sid: str, link: PeerLink) -> None:
        self.id = sid
        self.link = link
        import queue

        self.result: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=1)
        self.data: "queue.Queue[bytes]" = queue.Queue(maxsize=64)
        self.closed = threading.Event()
        # The bytes that were read but not asked for.
        self._buf = bytearray()
        self._buf_lock = threading.Lock()

    # -- the bytes -------------------------------------------------------
    def write(self, data: bytes) -> int:
        if not data:
            return 0
        self.link.send(wire.MsgType.TUNNEL_DATA, {"stream": self.id, "data": data})
        return len(data)

    def close_write(self) -> None:
        self.link.send(
            wire.MsgType.TUNNEL_CLOSE,
            {"stream": self.id, "reason": "local side closed"},
        )

    def read(self, count: int) -> bytes:
        """Read exactly ``count`` bytes; an empty result means the end."""
        import queue

        with self._buf_lock:
            while len(self._buf) < count:
                try:
                    chunk = self.data.get(timeout=0.2)
                except queue.Empty:
                    if self.closed.is_set():
                        try:
                            chunk = self.data.get_nowait()
                        except queue.Empty:
                            return b""
                    continue
                if not chunk:
                    return b""
                self._buf += chunk
            out = bytes(self._buf[:count])
            del self._buf[:count]
            return out
