#!/usr/bin/env python3
"""The transports without a connection: the mail and the object store.

The mail transport mails a batch of frames out and fetches the answer
from the mailbox of the agent.  The object transport writes the batch into
one bucket and reads the work of the agent from another one.  Neither of
them keeps a connection, so a batch is delivered in one go and the answer
comes back in the next exchange.

The module holds the two ends of the transports: the client side (used by
the reference agent) and the server side (used by the mock server).  The
Go server and the Rust beacon have their own implementations, and the three
of them have to agree on every byte: the SMTP and the POP3 dialogue, the
base64 of the body of a mail and the AWS Signature Version 4 header.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import smtplib
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from umbra_cli import netio, wire

# The buckets of the object transport.
TASKS_BUCKET = "umbra-tasks"
RESULTS_BUCKET = "umbra-results"

# The region of the buckets.  It is part of the signature, so the client
# and the server have to name the same one.
REGION = "us-east-1"


def agent_secret(psk: bytes, agent_id: str) -> str:
    """The password of an agent on the mail and the object transport.

    It is derived from the team key, so the id of the agent is bound to
    the key: a password that is seen somewhere else does not open the
    mailbox of another agent.
    """
    mac = hmac.new(psk, b"umbra/v1/mail/secret\x00" + agent_id.encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()


def split_frames(data: bytes) -> List[bytes]:
    """Split a buffer of concatenated frames into the frames themselves."""
    frames: List[bytes] = []
    pos = 0
    while pos < len(data):
        if pos + wire.PRELUDE_LEN > len(data):
            raise netio.StreamError("the batch holds a truncated frame")
        prelude = data[pos : pos + wire.PRELUDE_LEN]
        (length,) = struct.unpack(">I", prelude[8:12])
        total = wire.PRELUDE_LEN + wire.NONCE_LEN + length + wire.TAG_LEN
        if pos + total > len(data):
            raise netio.StreamError("the batch holds a truncated frame")
        frames.append(data[pos : pos + total])
        pos += total
    return frames


class BufferStream:
    """A stream that carries a batch of frames in memory.

    It is the server side of a transport without a connection: the frames
    of the batch are read from the buffer and the answer is written into
    it.
    """

    def __init__(self, data: bytes = b"") -> None:
        self._buf = bytearray(data)
        self.out = bytearray()
        self.closed = False

    def recv_frame(self) -> bytes:
        if len(self._buf) < wire.PRELUDE_LEN:
            raise netio.StreamError("the batch holds no more frames")
        prelude = bytes(self._buf[: wire.PRELUDE_LEN])
        (length,) = struct.unpack(">I", prelude[8:12])
        total = wire.PRELUDE_LEN + wire.NONCE_LEN + length + wire.TAG_LEN
        if len(self._buf) < total:
            raise netio.StreamError("the batch holds a truncated frame")
        frame = bytes(self._buf[:total])
        del self._buf[:total]
        return frame

    def send_frame(self, frame: bytes) -> None:
        self.out += frame

    def close(self) -> None:
        self.closed = True


class BatchStream:
    """The client side of a transport without a connection.

    The frames the beacon writes are collected until it reads: the read
    delivers the batch to the server and takes the answer out of it.
    """

    def __init__(self, backend: "BatchBackend") -> None:
        self.backend = backend
        self.pending = bytearray()
        self.inbox: List[bytes] = []
        self.closed = False

    def send_frame(self, frame: bytes) -> None:
        self.pending += frame

    def recv_frame(self) -> bytes:
        if not self.inbox:
            self._pump()
        if not self.inbox:
            raise netio.StreamError("the batch transport has no answer")
        return self.inbox.pop(0)

    def _pump(self) -> None:
        if not self.pending:
            return
        batch = bytes(self.pending)
        self.pending = bytearray()
        answer = self.backend.exchange(batch)
        for frame in split_frames(answer):
            self.inbox.append(frame)

    def close(self) -> None:
        # The answer of the beacon (the result of the task) is still in
        # the buffer: it is delivered before the session ends, exactly
        # like a frame on a socket.
        try:
            self._pump()
        except Exception:
            pass
        self.closed = True


class BatchBackend:
    """What a batch transport needs from the world."""

    def exchange(self, frames: bytes) -> bytes:
        raise NotImplementedError


class MailBackend(BatchBackend):
    """The mail backend: the frames go out as a mail, the answer comes
    back from the mailbox of the agent.

    The client is the standard library of Python, so the server is proved
    against a real mail client and not only against the mock of the
    framework.
    """

    def __init__(self, smtp_addr: str, pop3_addr: str, user: str, password: str) -> None:
        self.smtp_addr = smtp_addr
        self.pop3_addr = pop3_addr
        self.user = user
        self.password = password

    def exchange(self, frames: bytes) -> bytes:
        body = encode_body(frames)
        self._send(body)
        return self._fetch()

    def _send(self, body: str) -> None:
        host, _, port = self.smtp_addr.rpartition(":")
        client = smtplib.SMTP(host or "127.0.0.1", int(port or 25), timeout=30)
        try:
            client.ehlo("umbra.local")
            try:
                client.login(self.user, self.password)
            except smtplib.SMTPException:
                # The server only speaks PLAIN: the credential is sent in
                # one line, the way the Rust beacon sends it.
                secret = base64.b64encode(
                    b"\x00" + self.user.encode() + b"\x00" + self.password.encode()
                ).decode()
                client.docmd("AUTH", "PLAIN " + secret)
            message = (
                f"From: {self.user}@umbra.local\r\n"
                f"To: {self.user}@umbra.local\r\n"
                "Subject: umbra\r\n"
                "Content-Transfer-Encoding: base64\r\n"
                "\r\n" + body + "\r\n"
            )
            client.sendmail(f"{self.user}@umbra.local", [f"{self.user}@umbra.local"], message)
        finally:
            try:
                client.quit()
            except smtplib.SMTPException:
                client.close()

    def _fetch(self) -> bytes:
        import poplib

        host, _, port = self.pop3_addr.rpartition(":")
        client = poplib.POP3(host or "127.0.0.1", int(port or 110), timeout=30)
        try:
            client.user(self.user)
            client.pass_(self.password)
            _, listing, _ = client.list()
            out = bytearray()
            for line in listing:
                index = int(line.split()[0])
                raw = b"\n".join(client.retr(index)[1])
                body = raw.split(b"\r\n\r\n", 1)[-1].split(b"\n\n", 1)[-1]
                out += decode_body(body)
                client.dele(index)
            client.quit()
            return bytes(out)
        finally:
            try:
                client.close()
            except Exception:  # pragma: no cover - the socket is gone
                pass


class S3Backend(BatchBackend):
    """The object backend: the batch goes into the results bucket and the
    work of the agent comes from the tasks bucket."""

    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        tasks_bucket: str = TASKS_BUCKET,
        results_bucket: str = RESULTS_BUCKET,
        region: str = REGION,
    ) -> None:
        self.endpoint = endpoint
        self.access_key = access_key
        self.secret_key = secret_key
        self.tasks_bucket = tasks_bucket
        self.results_bucket = results_bucket
        self.region = region
        self.counter = 0

    def exchange(self, frames: bytes) -> bytes:
        self.counter += 1
        key = str(self.counter)
        self._put(self.results_bucket, key, frames)
        return self._get(self.tasks_bucket, self.access_key)

    def _put(self, bucket: str, key: str, body: bytes) -> None:
        import http.client

        host, _, port = self.endpoint.rpartition(":")
        conn = http.client.HTTPConnection(host or "127.0.0.1", int(port or 80), timeout=30)
        try:
            path = f"/{bucket}/{key}"
            headers = sign_request(
                "PUT", path, body, self.endpoint, self.access_key, self.secret_key, self.region
            )
            headers["Content-Length"] = str(len(body))
            conn.request("PUT", path, body=body, headers=headers)
            answer = conn.getresponse()
            answer.read()
            if answer.status < 200 or answer.status > 299:
                raise netio.StreamError(f"the store refused the object: {answer.status}")
        finally:
            conn.close()

    def _get(self, bucket: str, key: str) -> bytes:
        import http.client

        host, _, port = self.endpoint.rpartition(":")
        conn = http.client.HTTPConnection(host or "127.0.0.1", int(port or 80), timeout=30)
        try:
            path = f"/{bucket}/{key}"
            headers = sign_request(
                "GET", path, b"", self.endpoint, self.access_key, self.secret_key, self.region
            )
            conn.request("GET", path, headers=headers)
            answer = conn.getresponse()
            body = answer.read()
            if answer.status == 404:
                return b""
            if answer.status < 200 or answer.status > 299:
                raise netio.StreamError(f"the store answered {answer.status}")
            return body
        finally:
            conn.close()


def encode_body(frames: bytes) -> str:
    """Render the frames of a batch as the body of a mail."""
    encoded = base64.b64encode(frames).decode()
    lines = [encoded[i : i + 76] for i in range(0, len(encoded), 76)]
    return "\r\n".join(lines)


def split_message(raw: bytes) -> bytes:
    """The body of a mail: everything after the empty line.

    A client that sends the body alone has no headers, and then the
    whole message is the body.
    """
    for separator in (b"\r\n\r\n", b"\n\n"):
        if separator in raw:
            return raw.split(separator, 1)[1]
    return raw


def decode_body(body: bytes) -> bytes:
    """Read the frames of a batch from the body of a mail."""
    text = b"".join(body.split())
    if not text:
        return b""
    return base64.b64decode(text)


# -- AWS Signature Version 4 ---------------------------------------------

SIGNED_HEADERS = "host;x-amz-content-sha256;x-amz-date"


def amz_date(now: Optional[int] = None) -> Tuple[str, str]:
    """The date of the scope and the timestamp of the request."""
    stamp = time.gmtime(now if now is not None else time.time())
    date = time.strftime("%Y%m%d", stamp)
    return date, time.strftime("%Y%m%dT%H%M%SZ", stamp)


def sign_request(
    method: str,
    path: str,
    body: bytes,
    host: str,
    access_key: str,
    secret_key: str,
    region: str = REGION,
    now: Optional[int] = None,
) -> Dict[str, str]:
    """Sign a request the way the object store expects it."""
    date, timestamp = amz_date(now)
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_headers = (
        f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{timestamp}\n"
    )
    canonical_request = (
        f"{method}\n{path}\n\n{canonical_headers}\n{SIGNED_HEADERS}\n{payload_hash}"
    )
    scope = f"{date}/{region}/s3/aws4_request"
    string_to_sign = (
        "AWS4-HMAC-SHA256\n"
        f"{timestamp}\n{scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )
    key = _signing_key(secret_key, date, region)
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "Host": host,
        "x-amz-date": timestamp,
        "x-amz-content-sha256": payload_hash,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
            f"SignedHeaders={SIGNED_HEADERS}, Signature={signature}"
        ),
    }


def _signing_key(secret: str, date: str, region: str) -> bytes:
    key = hmac.new(f"AWS4{secret}".encode(), date.encode(), hashlib.sha256).digest()
    key = hmac.new(key, region.encode(), hashlib.sha256).digest()
    key = hmac.new(key, b"s3", hashlib.sha256).digest()
    return hmac.new(key, b"aws4_request", hashlib.sha256).digest()


def verify_request(
    method: str,
    path: str,
    query: str,
    headers: Dict[str, str],
    body: bytes,
    secret_of: Any,
    region: str = REGION,
) -> Optional[str]:
    """Check the signature of a request.

    `secret_of` gives the secret of an access key; the function returns
    the access key when the signature is right and None when it is not.
    """
    auth = headers.get("authorization", "")
    if not auth.startswith("AWS4-HMAC-SHA256 "):
        return None
    fields: Dict[str, str] = {}
    for part in auth[len("AWS4-HMAC-SHA256 ") :].split(","):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            fields[key] = value
    credential = fields.get("Credential", "")
    signed = fields.get("SignedHeaders", "")
    signature = fields.get("Signature", "")
    if not credential or not signed or not signature:
        return None
    parts = credential.split("/")
    if len(parts) != 5:
        return None
    access_key, date, req_region, service, terminator = parts
    if service != "s3" or terminator != "aws4_request" or req_region != region:
        return None
    timestamp = headers.get("x-amz-date", "")
    if not timestamp.startswith(date):
        return None
    payload_hash = headers.get("x-amz-content-sha256", "")
    if payload_hash.lower() != hashlib.sha256(body).hexdigest():
        return None
    secret = secret_of(access_key)
    if secret is None:
        return None
    canonical_headers = "".join(
        f"{name}:{headers.get(name, '').strip()}\n" for name in signed.split(";")
    )
    canonical_request = (
        f"{method}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}"
    )
    scope = f"{date}/{region}/s3/aws4_request"
    string_to_sign = (
        "AWS4-HMAC-SHA256\n"
        f"{timestamp}\n{scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )
    key = _signing_key(secret, date, region)
    want = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, signature):
        return None
    return access_key
