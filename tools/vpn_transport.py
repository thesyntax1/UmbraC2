"""The layer-3 tunnel of the reference implementation.

The mock speaks the same tunnel as the Go server and the Rust beacon: the
same handshake, the same keys and the same sealed packets.  A test can
therefore join the tunnel, route a network through a peer and ask a peer
whether it is there.

The tunnel is a transport of its own: its own UDP socket, its own key
schedule and its own replay protection.  That matters because it keeps
working when the beaconing channel is blocked.

    initiator -> responder   INIT  {id, timestamp, ephemeral, mac}
    responder -> initiator   RESP  {timestamp, ephemeral, address, mac}

Both MACs are the first sixteen bytes of an HMAC-SHA256 over a
domain-separated transcript keyed with a secret both sides know, so a peer
that does not hold the secret cannot finish the handshake.  The keys
themselves come from an X25519 exchange mixed with that secret.

The data packets are IPv4 packets in AES-256-GCM:

    03 | counter (8, big endian) | ciphertext

The nine-byte header is the associated data of the AEAD, the nonce is the
four-byte direction prefix followed by the counter, and every peer keeps a
replay window of the last sixty-four counters.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
import queue
import socket
import struct
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(ROOT, "operator") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "operator"))

from umbra_cli.crypto import (  # noqa: E402
    aead_decrypt,
    aead_encrypt,
    derive_session,
    hmac_sha256,
    x25519_keypair,
    x25519_shared,
)
from umbra_cli.wire import SUITE_AES256_GCM  # noqa: E402

# The packet types.
TYPE_INIT = 1
TYPE_RESP = 2
TYPE_DATA = 3
TYPE_PING = 4
TYPE_PONG = 5

# The sizes of the tunnel.
HEADER_LEN = 9
MAC_LEN = 16
TAG_LEN = 16
MAX_PACKET = 1600
MAX_PAYLOAD = MAX_PACKET - HEADER_LEN - TAG_LEN
MAX_IDENTITY = 64
REPLAY_WINDOW = 64
MAX_PEERS = 256

# The timeouts.
HANDSHAKE_TIMEOUT = 30.0
SESSION_TIMEOUT = 180.0

# The labels of the transcripts.
LABEL_INIT = b"umbra/v1/vpn/init"
LABEL_RESP = b"umbra/v1/vpn/resp"
LABEL_DH = b"umbra/v1/vpn/dh"

# The kinds of the payload of a control packet.
PING_KIND = 1
PONG_KIND = 2
CONTROL_LEN = 1 + 8 + 8


def init_mac(key: bytes, ident: str, ts: int, eph: bytes) -> bytes:
    """The authentication tag of an INIT packet."""
    msg = LABEL_INIT + ident.encode() + struct.pack(">Q", ts) + eph
    return hmac_sha256(key, msg)[:MAC_LEN]


def resp_mac(key: bytes, ident: str, ts: int, eph: bytes,
             resp_eph: bytes, now: int) -> bytes:
    """The authentication tag of a RESP packet."""
    msg = (LABEL_RESP + ident.encode() + struct.pack(">Q", ts) + eph +
           resp_eph + struct.pack(">Q", now))
    return hmac_sha256(key, msg)[:MAC_LEN]


def _accept_counter(peer: Dict[str, Any], counter: int) -> bool:
    """The replay window of a peer.

    A counter that was seen before is refused, and so is one that is too
    far behind the highest one: that is a replay or a reordering.
    """
    if counter > peer["highest"]:
        shift = counter - peer["highest"]
        peer["replay"] = 0 if shift >= REPLAY_WINDOW else peer["replay"] << shift
        peer["highest"] = counter
        return True
    if counter <= peer["highest"] - REPLAY_WINDOW:
        return False
    window = 1 << (peer["highest"] - counter)
    if peer["replay"] & window:
        return False
    peer["replay"] |= window
    return True


class VpnServer:
    """The tunnel server of the reference implementation.

    The server hands out the addresses of the tunnel, keeps the routing
    table of the networks behind the peers and answers the questions of
    the operator.
    """

    def __init__(self, network: str = "10.77.0.0/24",
                 agent_keys: Tuple[bytes, ...] = (),
                 operator_keys: Tuple[bytes, ...] = ()) -> None:
        self.network = network
        self.agent_keys = tuple(k for k in agent_keys if k)
        self.operator_keys = tuple(k for k in operator_keys if k)
        net = ipaddress.ip_network(network, strict=False)
        self.base = int(net.network_address)
        self.mask = (0xFFFFFFFF << (32 - net.prefixlen)) & 0xFFFFFFFF
        self.next = self.base + 2
        self._lock = threading.Lock()
        self._peers: Dict[str, Dict[str, Any]] = {}
        # The reservations are the addresses that were handed out; they
        # stay with the peer, so the rules that point at them do not have
        # to follow it around.
        self._reserved: Dict[str, int] = {}
        self._routes: List[Dict[str, Any]] = []
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    # -- the lifecycle ---------------------------------------------------
    def start(self, listen: str = "127.0.0.1:0") -> str:
        """Bind the socket of the tunnel and serve it."""
        host, _, port = listen.rpartition(":")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host or "127.0.0.1", int(port or 0)))
        sock.settimeout(0.2)
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return sock.getsockname()[0] + ":" + str(sock.getsockname()[1])

    def stop(self) -> None:
        """Stop the tunnel."""
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)

    def address(self) -> str:
        """The address the tunnel listens on."""
        if self._sock is None:
            return ""
        host, port = self._sock.getsockname()[:2]
        return f"{host}:{port}"

    # -- the peers -------------------------------------------------------
    def allocate(self, peer_id: str) -> str:
        """Reserve the address of a peer."""
        with self._lock:
            addr = self._allocate_locked(peer_id)
        return self._format(addr)

    def _allocate_locked(self, peer_id: str) -> int:
        peer = self._peers.get(peer_id)
        if peer is not None and peer["address"]:
            return peer["address"]
        if peer_id in self._reserved:
            return self._reserved[peer_id]
        for _ in range(256):
            addr = self.next
            self.next += 1
            if self.next > (self.base | (0xFFFFFFFF ^ self.mask)):
                self.next = self.base + 2
            if addr in (self.base, self.base + 1):
                continue
            if any(p["address"] == addr for p in self._peers.values()):
                continue
            self._reserved[peer_id] = addr
            if peer is not None:
                peer["address"] = addr
            return addr
        raise RuntimeError("vpn: no free tunnel address")

    def _format(self, addr: int) -> str:
        return ".".join(str((addr >> shift) & 0xFF) for shift in (24, 16, 8, 0))

    def peers(self) -> List[Dict[str, Any]]:
        """The peers of the tunnel, as the operator sees them.

        The reservations are peers that have an address but have not
        joined yet: the operator has to see them, because the rules that
        point at the address are already in place.
        """
        with self._lock:
            out = []
            for ident, addr in self._reserved.items():
                if ident in self._peers:
                    continue
                out.append({
                    "id": ident,
                    "address": self._format(addr),
                    "endpoint": "",
                    "agent": True,
                    "live": False,
                    "bytes_in": 0,
                    "bytes_out": 0,
                    "last_seen": "",
                })
            for peer in self._peers.values():
                out.append({
                    "id": peer["id"],
                    "address": self._format(peer["address"]) if peer["address"] else "",
                    "endpoint": "%s:%d" % (peer["endpoint"][0], peer["endpoint"][1])
                    if peer["endpoint"] else "",
                    "agent": peer["agent"],
                    "live": (time.time() - peer["last_seen"]) < SESSION_TIMEOUT,
                    "bytes_in": peer["bytes_in"],
                    "bytes_out": peer["bytes_out"],
                    "last_seen": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(peer["last_seen"])),
                })
            return out

    def status(self) -> Dict[str, Any]:
        """The summary of the tunnel."""
        with self._lock:
            live = sum(1 for p in self._peers.values()
                       if (time.time() - p["last_seen"]) < SESSION_TIMEOUT)
            return {
                "listening": self.address(),
                "network": self.network,
                "peers": len(self._peers),
                "live": live,
                "reserved": len([p for p in self._peers.values() if p["address"]]),
                "routes": len(self._routes),
                "enabled": True,
            }

    # -- the routing table -----------------------------------------------
    def set_route(self, peer_id: str, network: str) -> Dict[str, Any]:
        """Send the traffic of a network to a peer."""
        net = ipaddress.ip_network(network, strict=False)
        base = int(net.network_address)
        mask = (0xFFFFFFFF << (32 - net.prefixlen)) & 0xFFFFFFFF
        with self._lock:
            if peer_id not in self._peers:
                raise KeyError(peer_id)
            for route in self._routes:
                if route["base"] == base and route["mask"] == mask:
                    route["peer"] = peer_id
                    route["bytes"] = 0
                    route["packets"] = 0
                    return dict(route)
            route = {"peer": peer_id, "network": network, "bytes": 0,
                     "packets": 0, "base": base, "mask": mask}
            self._routes.append(route)
            return dict(route)

    def remove_route(self, network: str) -> bool:
        """Forget a network."""
        net = ipaddress.ip_network(network, strict=False)
        base = int(net.network_address)
        mask = (0xFFFFFFFF << (32 - net.prefixlen)) & 0xFFFFFFFF
        with self._lock:
            for route in list(self._routes):
                if route["base"] == base and route["mask"] == mask:
                    self._routes.remove(route)
                    return True
        return False

    def routes(self) -> List[Dict[str, Any]]:
        """The routing table of the tunnel."""
        with self._lock:
            return [dict(route) for route in self._routes]

    def _route_peer(self, dst: int) -> Tuple[Optional[Dict[str, Any]],
                                            Optional[Dict[str, Any]]]:
        """The peer that owns a destination; the longest prefix wins."""
        best = None
        for route in self._routes:
            if dst & route["mask"] != route["base"]:
                continue
            if best is None or route["mask"] > best["mask"]:
                best = route
        if best is None:
            return None, None
        return self._peers.get(best["peer"]), best

    # -- the ping --------------------------------------------------------
    def ping(self, peer_id: str, timeout: float = 5.0) -> float:
        """Ask a peer whether it is there and how far away it is."""
        with self._lock:
            peer = self._peers.get(peer_id)
        if peer is None:
            raise KeyError(peer_id)
        nonce = os.urandom(8)
        now = time.time()
        payload = bytes([PING_KIND]) + nonce + struct.pack(">Q", int(now * 1e9))
        self._send_control(peer, TYPE_PING, payload)
        deadline = now + timeout
        while time.time() < deadline:
            try:
                return peer["pongs"].get(timeout=0.05)
            except queue.Empty:
                continue
        raise TimeoutError("vpn: the peer did not answer the ping")

    # -- the packets -----------------------------------------------------
    def _match_mac(self, ident: str, ts: int, eph: bytes,
                   mac: bytes) -> Optional[bytes]:
        for key in self.agent_keys:
            if hmac.compare_digest(init_mac(key, ident, ts, eph), mac):
                return key
        for key in self.operator_keys:
            if hmac.compare_digest(init_mac(key, ident, ts, eph), mac):
                return key
        return None

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(MAX_PACKET)
            except (socket.timeout, OSError):
                continue
            if not data:
                continue
            kind = data[0]
            try:
                if kind == TYPE_INIT:
                    self._handle_init(data, addr)
                elif kind == TYPE_DATA:
                    self._handle_data(data, addr)
                elif kind == TYPE_PONG:
                    self._handle_pong(data, addr)
            except (OSError, ValueError, KeyError):
                continue

    def _handle_init(self, pkt: bytes, addr: Tuple[str, int]) -> None:
        if len(pkt) < 2 + 8 + 32 + MAC_LEN:
            return
        id_len = pkt[1]
        offset = 2
        if id_len <= 0 or id_len > MAX_IDENTITY:
            return
        if offset + id_len + 8 + 32 + MAC_LEN > len(pkt):
            return
        ident = pkt[offset:offset + id_len].decode("utf-8", "replace")
        offset += id_len
        ts = struct.unpack(">Q", pkt[offset:offset + 8])[0]
        offset += 8
        eph = pkt[offset:offset + 32]
        offset += 32
        mac = pkt[offset:offset + MAC_LEN]
        if abs(time.time() - ts) > HANDSHAKE_TIMEOUT:
            return
        key = self._match_mac(ident, ts, eph, mac)
        if key is None:
            return
        now = int(time.time())
        priv, pub = x25519_keypair()
        dh = x25519_shared(priv, eph)
        shared = hmac_sha256(key, LABEL_DH + dh)
        cn = struct.pack(">Q", ts) + b"\x00" * 8
        sn = struct.pack(">Q", now) + b"\x00" * 8
        _, km = derive_session(shared, cn, sn)
        with self._lock:
            peer = self._peers.get(ident)
            if peer is None:
                if len(self._peers) >= MAX_PEERS:
                    return
                peer = {
                    "id": ident,
                    "address": 0,
                    "endpoint": addr,
                    "agent": True,
                    "bytes_in": 0,
                    "bytes_out": 0,
                    "last_seen": time.time(),
                    "send_key": b"",
                    "recv_key": b"",
                    "send_prefix": b"",
                    "recv_prefix": b"",
                    "counter": 0,
                    "highest": 0,
                    "replay": 0,
                    "established": False,
                    "pongs": queue.Queue(),
                }
                self._peers[ident] = peer
            if not peer["address"]:
                peer["address"] = self._allocate_locked(ident)
            peer["endpoint"] = addr
            peer["last_seen"] = time.time()
            peer["send_key"] = km.s2c_key
            peer["send_prefix"] = km.s2c_prefix
            peer["recv_key"] = km.c2s_key
            peer["recv_prefix"] = km.c2s_prefix
            peer["counter"] = 0
            peer["highest"] = 0
            peer["replay"] = 0
            peer["established"] = True
            address = peer["address"]
        resp = (bytes([TYPE_RESP]) + struct.pack(">Q", now) + pub +
                struct.pack(">I", address))
        resp += resp_mac(key, ident, ts, eph, pub, now)
        self._sock.sendto(resp, addr)

    def _peer_by_endpoint(self, addr: Tuple[str, int]) -> Optional[Dict[str, Any]]:
        with self._lock:
            for peer in self._peers.values():
                if peer["endpoint"] == addr:
                    return peer
        return None

    def _handle_data(self, pkt: bytes, addr: Tuple[str, int]) -> None:
        if len(pkt) < HEADER_LEN + TAG_LEN:
            return
        peer = self._peer_by_endpoint(addr)
        if peer is None or not peer["established"]:
            return
        header = pkt[:HEADER_LEN]
        counter = struct.unpack(">Q", header[1:9])[0]
        with self._lock:
            if not _accept_counter(peer, counter):
                return
            key = peer["recv_key"]
            prefix = peer["recv_prefix"]
        nonce = prefix + struct.pack(">Q", counter)
        try:
            plain = aead_decrypt(SUITE_AES256_GCM, key, nonce, header,
                                 pkt[HEADER_LEN:])
        except Exception:  # noqa: BLE001 - a bad packet is simply dropped
            return
        if len(plain) < 20 or (plain[0] >> 4) != 4:
            return
        dst = struct.unpack(">I", plain[16:20])[0]
        with self._lock:
            target = None
            for candidate in self._peers.values():
                if candidate["address"] == dst:
                    target = candidate
                    break
            route = None
            if target is None:
                target, route = self._route_peer(dst)
        if target is None or target is peer:
            return
        self._send(target, plain)
        with self._lock:
            peer["bytes_in"] += len(plain)
            peer["last_seen"] = time.time()
            if route is not None:
                route["bytes"] += len(plain)
                route["packets"] += 1

    def _handle_pong(self, pkt: bytes, addr: Tuple[str, int]) -> None:
        if len(pkt) < HEADER_LEN + TAG_LEN:
            return
        peer = self._peer_by_endpoint(addr)
        if peer is None or not peer["established"]:
            return
        header = pkt[:HEADER_LEN]
        counter = struct.unpack(">Q", header[1:9])[0]
        with self._lock:
            key = peer["recv_key"]
            prefix = peer["recv_prefix"]
        nonce = prefix + struct.pack(">Q", counter)
        try:
            plain = aead_decrypt(SUITE_AES256_GCM, key, nonce, header,
                                 pkt[HEADER_LEN:])
        except Exception:  # noqa: BLE001
            return
        if len(plain) < CONTROL_LEN or plain[0] != PONG_KIND:
            return
        sent = struct.unpack(">Q", plain[9:17])[0]
        rtt = time.time() - sent / 1e9
        try:
            peer["pongs"].put_nowait(rtt)
        except queue.Full:
            pass

    def _send(self, peer: Dict[str, Any], plain: bytes) -> None:
        """Seal a payload for a peer and write it out."""
        with self._lock:
            if not peer["established"]:
                return
            counter = peer["counter"]
            peer["counter"] += 1
            key = peer["send_key"]
            prefix = peer["send_prefix"]
        header = bytes([TYPE_DATA]) + struct.pack(">Q", counter)
        nonce = prefix + struct.pack(">Q", counter)
        sealed = aead_encrypt(SUITE_AES256_GCM, key, nonce, header, plain)
        self._sock.sendto(header + sealed, peer["endpoint"])
        with self._lock:
            peer["bytes_out"] += len(plain)
            peer["last_seen"] = time.time()

    def _send_control(self, peer: Dict[str, Any], kind: int,
                      payload: bytes) -> None:
        """Seal a question or an answer and write it out."""
        with self._lock:
            if not peer["established"]:
                return
            counter = peer["counter"]
            peer["counter"] += 1
            key = peer["send_key"]
            prefix = peer["send_prefix"]
        header = bytes([kind]) + struct.pack(">Q", counter)
        nonce = prefix + struct.pack(">Q", counter)
        sealed = aead_encrypt(SUITE_AES256_GCM, key, nonce, header, payload)
        self._sock.sendto(header + sealed, peer["endpoint"])


class VpnPeer:
    """One end of the tunnel: the side of the beacon.

    The peer joins the tunnel with the secret it uses for the beaconing
    channel, so no extra key distribution is needed.
    """

    def __init__(self, endpoint: str, psk: bytes, ident: str,
                 timeout: float = 15.0) -> None:
        self.endpoint = endpoint
        self.psk = psk
        self.ident = ident
        self.timeout = timeout
        self.address = b""
        self._sock: Optional[socket.socket] = None
        self._send_key = b""
        self._recv_key = b""
        self._send_prefix = b""
        self._recv_prefix = b""
        self._counter = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def join(self) -> str:
        """Join the tunnel and return the address of the peer."""
        host, _, port = self.endpoint.rpartition(":")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        sock.connect((host, int(port or 0)))
        self._sock = sock
        priv, pub = x25519_keypair()
        ts = int(time.time())
        init = (bytes([TYPE_INIT, len(self.ident)]) + self.ident.encode() +
                struct.pack(">Q", ts) + pub +
                init_mac(self.psk, self.ident, ts, pub))
        sock.send(init)
        data = sock.recv(2048)
        if len(data) < 1 + 8 + 32 + 4 + MAC_LEN or data[0] != TYPE_RESP:
            raise RuntimeError("vpn: malformed response")
        resp_ts = struct.unpack(">Q", data[1:9])[0]
        eph = data[9:41]
        address = data[41:45]
        mac = data[45:45 + MAC_LEN]
        if not hmac.compare_digest(
                resp_mac(self.psk, self.ident, ts, pub, eph, resp_ts), mac):
            raise RuntimeError("vpn: the server did not authenticate itself")
        dh = x25519_shared(priv, eph)
        shared = hmac_sha256(self.psk, LABEL_DH + dh)
        cn = struct.pack(">Q", ts) + b"\x00" * 8
        sn = struct.pack(">Q", resp_ts) + b"\x00" * 8
        _, km = derive_session(shared, cn, sn)
        self._send_key = km.c2s_key
        self._send_prefix = km.c2s_prefix
        self._recv_key = km.s2c_key
        self._recv_prefix = km.s2c_prefix
        self.address = address
        self._thread = threading.Thread(target=self._answer_pings, daemon=True)
        self._thread.start()
        return ".".join(str(b) for b in address)

    def close(self) -> None:
        """Leave the tunnel."""
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def send_packet(self, packet: bytes) -> None:
        """Send one IPv4 packet into the tunnel."""
        if len(packet) < 20:
            raise ValueError("vpn: the packet is too short")
        counter = self._counter
        self._counter += 1
        header = bytes([TYPE_DATA]) + struct.pack(">Q", counter)
        nonce = self._send_prefix + struct.pack(">Q", counter)
        sealed = aead_encrypt(SUITE_AES256_GCM, self._send_key, nonce, header,
                              packet)
        self._sock.send(header + sealed)

    def recv_packet(self, timeout: float = 5.0) -> bytes:
        """Wait for one IPv4 packet out of the tunnel."""
        self._sock.settimeout(timeout)
        while True:
            data = self._sock.recv(2048)
            if len(data) < HEADER_LEN + TAG_LEN:
                continue
            kind, payload = self._open(data)
            if kind == TYPE_DATA:
                return payload

    def _open(self, data: bytes) -> Tuple[int, bytes]:
        header = data[:HEADER_LEN]
        counter = struct.unpack(">Q", header[1:9])[0]
        nonce = self._recv_prefix + struct.pack(">Q", counter)
        plain = aead_decrypt(SUITE_AES256_GCM, self._recv_key, nonce, header,
                             data[HEADER_LEN:])
        return header[0], plain

    def _answer_pings(self) -> None:
        """Answer the questions of the server.

        The question and the answer are sealed like the data packets, so
        the answer proves that the whole path is alive.
        """
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data = self._sock.recv(2048)
            except (socket.timeout, OSError):
                continue
            if len(data) < HEADER_LEN + TAG_LEN:
                continue
            try:
                kind, payload = self._open(data)
            except Exception:  # noqa: BLE001 - a bad packet is dropped
                continue
            if kind != TYPE_PING or len(payload) < CONTROL_LEN:
                continue
            counter = self._counter
            self._counter += 1
            header = bytes([TYPE_PONG]) + struct.pack(">Q", counter)
            nonce = self._send_prefix + struct.pack(">Q", counter)
            answer = (bytes([PONG_KIND]) + payload[1:9] + payload[9:17])
            sealed = aead_encrypt(SUITE_AES256_GCM, self._send_key, nonce,
                                  header, answer)
            try:
                self._sock.send(header + sealed)
            except OSError:
                return
