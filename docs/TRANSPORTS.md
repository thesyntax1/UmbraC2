# Transports

> A transport carries **whole umbra/v1 frames**. Everything above it — the
> handshake, the session state machine, the task queue, the operator RPCs — is
> identical on every transport. That is the reason the feature set can grow
> without touching the protocol: a new transport is a new `FrameStream`
> implementation and nothing else.

## 1. The contract

Every transport implements the same three operations:

| operation | meaning |
|---|---|
| `ReadFrame()` | the next frame the peer sent, blocking until one arrives |
| `WriteFrame(frame)` | send one frame; the frames must leave in order |
| `Close()` | end the session |

A frame is the unit of the protocol: a 12-byte prelude, a nonce, the
encrypted body and the authentication tag (see `docs/PROTOCOL.md`). A
transport never looks inside a frame, so it cannot read or forge traffic —
the AEAD does that.

Three rules hold on every transport:

* **one writer at a time** — the nonce counter is strictly increasing, so
  the seal and the write have to be one critical section;
* **one frame at a time on the wire** — a transport that multiplexes (HTTP
  bodies, WebSocket frames, DNS chunks) keeps the order of the frames;
* **a frame is a frame** — no transport may split a frame across two
  messages in a way the receiver cannot reassemble.

## 2. The transports at a glance

| transport | used by | server side | beacon side | operator side |
|---|---|---|---|---|
| TCP | agent, operator | `server.agent_listen`, `server.operator_listen` | `UMBRA_TRANSPORT=tcp` | `--server` |
| HTTP | agent | `server.http_listen` | `UMBRA_TRANSPORT=http` | – |
| HTTPS | agent | `server.http_listen` + `http_tls_cert`/`http_tls_key` | `UMBRA_TRANSPORT=http` behind a TLS proxy | – |
| WebSocket | agent | `server.http_listen` (upgrade) | `UMBRA_TRANSPORT=ws` | – |
| DNS | agent | `server.dns_listen`, `server.dns_domain` | `UMBRA_TRANSPORT=dns` | – |
| mutual TLS | agent, operator | `server.tls_listen` + `tls_cert`/`tls_key`/`tls_client_ca` | – | `--tls` |

Two more things carry traffic but are **not** transports: the pivot callback
(session) and the layer-3 tunnel. They are described in
`docs/PIVOTING.md`.

## 3. TCP

The default and the simplest. The agent opens a connection per beacon cycle,
says HELLO, exchanges frames and says BYE. The operator console keeps one
connection open for the whole session and receives the event stream on it.

```
agent                     server
  |  TCP connect            |
  |  HELLO  (bootstrap)     |
  |  HELLO_ACK              |
  |  CHECKIN                |
  |  TASK_BATCH             |
  |  RESULT, BYE            |
  |  close                  |
```

The listener is protected by a small guard: too many failed handshakes from
one address and the address is refused for a while. Every connection has a
frame budget (`limits.max_frame_bytes_per_conn`), so a broken or hostile peer
cannot keep the server busy forever.

## 4. HTTP (and HTTPS)

The HTTP transport is stateless on the wire: every request carries whole
frames in its body.

```
POST /api/v1/beacon            ->  HELLO_ACK
POST /api/v1/beacon/<session>  ->  TASK_BATCH
POST /api/v1/beacon/<session>  ->  (nothing)
```

The `<session>` path component is the 128-bit session id both sides already
share from the HELLO_ACK. It selects the key set; it cannot be used to read
or forge traffic, because every frame is still AEAD-protected and
nonce-ordered.

* The route is `server.http_path` (default `/api/v1/beacon`).
* One body may carry several frames (a beacon reports a batch of results and
  its BYE in one request); the server accepts at most 16 frames per request.
* The beacon keeps the socket open for the whole cycle, so a cycle costs one
  TCP connect instead of three.

**HTTPS.** The Go server terminates TLS itself when `http_tls_cert` and
`http_tls_key` are set. The beacon itself only speaks plain HTTP/1.1 (it
carries no TLS stack, see `docs/SECURITY.md`), so the usual deployment is a
TLS-terminating reverse proxy in front of the listener: the proxy handles the
certificate, the beacon sends plain HTTP to the proxy.

### Domain fronting

Two knobs make the HTTP transport usable through a CDN:

| setting | effect |
|---|---|
| `UMBRA_HTTP_HOST_HEADER` (beacon) | the `Host` header of the request |
| `server.http_host_header` (server) | the `Host` header the server *requires* |

With both set, the beacon connects to the CDN but names the origin in the
`Host` header; the CDN routes the request to the origin, and the origin only
answers requests that carry exactly that name. A request that reaches the
server directly — without the fronting name — is refused with `421`.

## 5. WebSocket

The same protocol over RFC 6455. One umbra frame becomes one binary
WebSocket frame; the order is preserved.

```
GET /api/v1/beacon HTTP/1.1
Host: cdn.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64 of 16 random bytes>
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

After the upgrade the connection is a plain frame stream again: the same
`HELLO`, the same `CHECKIN`, the same task batches. The server answers the
upgrade on the *beacon route* (`/api/v1/beacon` by default), so a CDN needs
no extra configuration.

The implementation is deliberately small:

* binary frames only, no fragmentation (the umbra frames fit into one
  WebSocket frame), no extensions, no compression;
* the client masks its frames, the server does not — as RFC 6455 asks;
* ping is answered with pong, close ends the session;
* the client verifies `Sec-WebSocket-Accept`, so a server that is not a
  WebSocket endpoint is detected immediately.

Settings: `UMBRA_TRANSPORT=ws`, `UMBRA_WS_PATH` (the route) and
`UMBRA_WS_HOST_HEADER` (the fronting name, same idea as the HTTP one).

The Python reference implementation lives in `operator/umbra_cli/ws.py` and is
used by the test double (`tools/mock_server.py --websocket`).

## 6. DNS

The fallback for networks where nothing else gets through. The beacon asks a
resolver for a name that belongs to the tunnel domain, and the answer
carries the next frame.

```
query   <seq>.<chunk>.<agent>.<domain>
answer  TXT records, each one base32 of a slice of the frame
```

* `<seq>` is the sequence number of the query (eight hex characters),
* `<chunk>` is the base32 of the payload the beacon sends in this query
  (`-` when it only polls),
* `<agent>` is the base32 of the agent id.

Every frame is length-prefixed with four bytes in both directions, so a
chunk that ends in the middle of a frame is reassembled instead of breaking
the stream. The tunnel is a request/response transport: one query carries the
beacon's payload and picks up the server's answer in the same round trip.

Server side: `server.dns_listen` (UDP) and `server.dns_domain`. The server
answers only for its own domain; every other name is left alone, so the
server can sit behind a normal resolver.

Beacon side: `UMBRA_TRANSPORT=dns`, `UMBRA_DNS_RESOLVER` and
`UMBRA_DNS_DOMAIN`.

The format is pinned in `docs/PROTOCOL.md` §8 and implemented three times
(Go `internal/dnstun`, Rust `dns.rs`, Python `umbra_cli/dns.py`).

## 7. Mutual TLS

The TLS listener proves *who* the peer is; the umbra handshake still decides
*what* the peer may do. Both are needed:

* the certificate says the peer holds a key that the client CA signed;
* the handshake says which umbra identity the peer wants to use.

```
server.tls_listen      the address of the listener
server.tls_cert        the certificate of the server
server.tls_key         the private key of the server
server.tls_client_ca   the CA the client certificates are verified against
```

The client certificate is **required** (the configuration refuses to start
without a client CA), so a stolen operator token alone is not enough to take
over an operation.

The role in the HELLO decides what the connection does: an agent gets a
beacon session, an operator gets a control channel. One listener therefore
serves both kinds of peer.

The operator console speaks it with global flags:

```
umbra --server c2.example.com:4002 --tls \
      --tls-ca /etc/umbra/ca.pem --tls-server-name c2.example.com \
      --tls-cert /etc/umbra/console.pem --tls-key /etc/umbra/console.key \
      agents
```

`--tls-cert`/`--tls-key` are only needed when the server asks for a client
certificate, which it always does on the mutual TLS listener.

## 8. Traffic shaping

Three independent knobs change the *shape* of the traffic, not its content:

| knob | where | effect |
|---|---|---|
| sleep / jitter | server policy, per agent | the interval between two beacon cycles |
| `server.http_pad` | server | the reply body is padded to a bucket size |
| `UMBRA_HTTP_PAD` | beacon | the request body is padded to a bucket size |

The padding is a normal sealed `PADDING` frame (message type `0x1E`) with a
random body: the receiver steps over it, and the length of the request stops
telling how much work the cycle carried. The server and the beacon solve the
body length for the bucket size instead of guessing it, because the length
prefix of the body grows with the body.

The bucket has to be between 256 and 65536 bytes; `0` switches the padding
off.

## 9. Choosing a transport

| situation | transport |
|---|---|
| lab, full control | TCP |
| a CDN or a web server in front | WebSocket or HTTP with a Host header |
| an appliance that only speaks HTTP | HTTP behind a TLS proxy |
| only DNS leaves the network | DNS |
| the operator console may be remote | mutual TLS |
| a lot of traffic through a middlebox | HTTP or WebSocket with padding |

## 10. IPv6

Every transport dials a host and a port, and the family of the host is
carried by the address itself:

| the beacon is configured with | it dials |
|---|---|
| `10.0.0.5` and `8443` | `10.0.0.5:8443` |
| `2001:db8::5` and `8443` | `[2001:db8::5]:8443` |
| `[2001:db8::5]` and `8443` | `[2001:db8::5]:8443` |

The `Host:` header of the HTTP and the WebSocket transport carries the
same shape, so a proxy on the path sees a legal request. The DNS
transport is unaffected: a name is resolved by the resolver, and the
resolver may answer with an AAAA record.

A beacon that is told to listen (the peer link) binds an IPv6 socket when
it is given an IPv6 address, and the address it reports to the server is
bracketed, so the server can chain a pivot through it without guessing.

## 11. What is deliberately not here

* **No TLS in the beacon.** The Rust beacon carries no TLS stack: it would
  add a dependency and a few kilobytes to every implant. The operator
  console has one (the standard library of Python), and the server
  terminates TLS for both the HTTP and the mutual TLS listener.
* **No fragmentation, no extensions, no compression** in the WebSocket
  transport — only what the protocol needs.
* **No UDP in the frame protocol.** The DNS tunnel carries the frames over
  DNS, and the layer-3 tunnel has its own datagram format; the umbra frame
  itself is a stream format.
