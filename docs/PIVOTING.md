# Pivoting and tunnels

Three mechanisms let an operator reach a network the team server cannot see
directly.  All three share the same idea: the agent is the one that talks to
the inner network, and the server only ever sends instructions.

```
        operator console
              |
      team server (TCP / HTTP / DNS)
              |
        +-----+-----+-----------+
        |     |     |           |
     beacon beacon  beacon    tunnel session
        |     |     |           |
     pivot   p2p   vpn        (callback)
        |
   inner network
```

---

## 1. The callback session

A pivot needs a path from the server into the network the agent sits in.  The
server cannot open that path: the agent is behind NAT, in a different
network, or simply not routable.  So the agent opens it.

1. The operator asks for a pivot through an agent.
2. The server submits a `tunnel` task with the session id.
3. The beacon dials **back** to the server and sends a HELLO whose metadata
   carries `tunnel = <session id>`.
4. The link layer hands that connection to the pivot broker
   (`server/internal/pivot`), which now owns it.

The callback is an ordinary umbra/v1 connection: the same handshake, the same
session keys, the same framing.  Only the metadata differs.

The agent side of the handshake lives in `implant/rust/src/link.rs`; the
beacon and the pivot callback share it, so the two can never drift apart.

### The stream vocabulary

One callback carries many logical streams:

```
server -> agent   TUNNEL_OPEN  {stream, op:"open",   host, port}
agent  -> server  TUNNEL_OPEN  {stream, op:"result", ok, err}
both              TUNNEL_DATA  {stream, data}
both              TUNNEL_CLOSE {stream, reason}
```

`op:"open"` asks the agent to connect to `host:port`.  The agent answers with
`op:"result"` and `ok`, and only then does the server start to relay.  The
payload of one `TUNNEL_DATA` is at most 32 KiB.

Message ids: `0x1A` open, `0x1B` data, `0x1C` close, `0x1E` padding.

### The two shapes a pivot takes

| Mode | The client picks the target | Use it for |
|---|---|---|
| `socks` | yes, through SOCKS5 | browsing an internal web interface, pivoting into a range |
| `forward` | no, `host`/`port` are fixed | one service, one port, less to get wrong |

```bash
# a SOCKS5 proxy on the loopback of the server
umbra pivot open laptop-1 --mode socks
# -> pivot tun-8f2a1c on 127.0.0.1:41234

# a fixed forward
umbra pivot open laptop-1 --mode forward --host 10.0.0.5 --port 8080
```

Both listeners bind to `127.0.0.1` by default.  A pivot that listens on every
interface is an ingress into the internal network for anybody who can reach
the server, so the default is deliberately narrow.  Use `--listen` when the
operator console runs on another machine.

The SOCKS5 implementation is RFC 1928 with the "no authentication" method and
the `CONNECT` command only.  `server/internal/pivot/socks.go` is the
reference; the Python test double has the same code path so the behaviour can
be tested without Go.

### Limits

Every limit is a hard number in `server/internal/pivot/pivot.go`:

| Limit | Value | Why |
|---|---|---|
| `MaxSessions` | 64 | one callback per agent |
| `MaxStreamsPerSession` | 128 | one file descriptor per stream on the agent |
| `MaxPendingOpens` | 32 | unanswered stream requests |
| `OpenTimeout` | 30 s | how long the server waits for the callback |
| `ChunkSize` | 32 KiB | the payload of one `TUNNEL_DATA` |
| `StreamBuffer` | 64 | chunks that may queue for one stream |

---

## 2. Peer-to-peer pivoting

Two implants can talk to each other directly, without the team server
carrying the traffic.  That is what a chain looks like:

```
server -> agent A -> agent B -> agent C -> target
```

The link between two agents is encrypted with keys derived from the shared
agent PSK and an X25519 exchange, so the server does not have to be in the
path.  The frames that travel over it are the same `TUNNEL_*` frames, so the
server side has one implementation to reason about.

```bash
# on agent B: listen
umbra task agent-b p2p --args '{"action":"listen","host":"0.0.0.0","port":9001}'
# on agent A: connect through B
umbra task agent-a p2p --args '{"action":"connect","host":"10.0.0.9","port":9001}'
```

The peer link is a *pivot* link: once it is up, the server can open streams
through it exactly like it does through a callback session.

---

## 3. The layer-3 tunnel

The callback sessions give the operator *TCP* reachability.  The tunnel gives
them a *network*: every agent that joins it gets an address out of the tunnel
network, and the operator can route traffic to it as if it were on the same
segment.

```
  operator console
        |
   tunnel endpoint (UDP, X25519 + HKDF + AES-256-GCM)
        |
   10.77.0.2  10.77.0.3  10.77.0.4     <- the agents
```

The handshake is the client half of a Noise-IK-style exchange:

```
INIT {id, timestamp, ephemeral, mac}   ->
                             <-  RESP {timestamp, ephemeral, address, mac}
```

Both directions are authenticated with `HMAC-SHA256(psk, label || transcript)`
before any key is derived, and the shared secret is mixed with the PSK, so a
server that does not know the PSK cannot join the tunnel.  After the
handshake the packets travel in AES-256-GCM datagrams; the receiver keeps a
64-packet replay window and drops anything it has already seen.

On Linux the implant reads and writes the packets from a TUN device, which
makes the tunnel a real L3 link:

```bash
umbra vpn status
umbra vpn allocate laptop-1        # -> 10.77.0.2
umbra task laptop-1 vpn            # the agent joins the tunnel
```

Server side: `server/internal/vpn`.  Agent side: `implant/rust/src/vpn.rs`.

---

## 4. The DNS transport

When every other channel is blocked, the beacon can still talk to the server
through DNS.  The agent asks a resolver for a name that belongs to the tunnel
domain, and the answer carries the next frame.

```
query   <seq>.<chunk>.<agent>.<domain>
answer  TXT records, each one base32 of a slice of the frame
```

* `seq` is the sequence number of the query, eight hex characters.
* `chunk` is the base32 of the bytes the agent sends in this query.  The
  label `-` means "nothing this time".
* `agent` is the base32 of the agent id.

Both directions are length prefixed (a four byte big endian length in front
of every frame), so a chunk that ends in the middle of a frame is reassembled
instead of breaking the stream.

The frames that travel through the tunnel are ordinary umbra/v1 frames, so
the session state machine above the transport does not change at all: the DNS
tunnel is a transport, nothing more.  The handshake, the key schedule and the
task queue are the same code as on TCP.

```bash
# the server side
"dns_listen": "127.0.0.1:5353",
"dns_domain": "tunnel.example.com"

# the implant side
UMBRA_TRANSPORT=dns \
UMBRA_DNS_RESOLVER=10.0.0.53:53 \
UMBRA_DNS_DOMAIN=tunnel.example.com \
  cargo build --release
```

Server side: `server/internal/dnstun`.  Agent side:
`implant/rust/src/dns.rs`.  The reference implementation of the format is
`operator/umbra_cli/dns.py`, which the test-suite uses to prove that the
framing round-trips.

---

## 5. What is *not* pivoting

Two things look like pivoting but are not, and the operator console keeps
them apart on purpose:

* **The VPN tunnel** is a link between the *console* and the *agents*.  It
  does not reach a third-party network.
* **The peer-to-peer link** connects two implants.  It does not by itself
  give the operator a socket; a stream has to be opened over it.

Everything the operator can do with a pivot is visible in `umbra pivot list`:
the tunnel id, the agent, the mode, the listen address, the number of open
streams and the byte counters.
