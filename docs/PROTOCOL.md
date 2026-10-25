# umbra/v1 — protocol specification

Version 1, revision `0.1.0`. The normative test vectors live in
[`contracts/vectors.json`](../contracts/vectors.json); the three implementations
(Python, Go, Rust) are all tested against them.

Contents
1. [Design rules](#1-design-rules)
2. [Primitives](#2-primitives)
3. [Value encoding: upk](#3-value-encoding-upk)
4. [Frames](#4-frames)
5. [Handshake](#5-handshake)
6. [Session keys, nonces, rotation](#6-session-keys-nonces-rotation)
7. [Messages](#7-messages)
8. [Transports](#8-transports)
9. [Failure handling](#9-failure-handling)
10. [Change policy](#10-change-policy)

---

## 1. Design rules

1. **No cleartext.** Every byte after the TCP/HTTP envelope is inside a sealed
   frame. The handshake runs under a PSK-derived bootstrap key.
2. **No plaintext metadata.** Agent identity, host, OS and results are encrypted;
   the only visible bytes are the 12-byte prelude (which carries length and type
   so transports can frame without keys) and the 12-byte nonce.
3. **Deterministic encodings.** A value has exactly one valid encoding, and
   frames are compared byte-for-byte in tests. This is what makes three
   languages interoperable without a parser quirk breaking it.
4. **No nonce reuse.** Nonces are `prefix ‖ counter`, and a key set is retired
   after 2²⁰ frames.
5. **Fail closed.** Any authentication failure, unexpected nonce, unknown suite,
   oversized frame or malformed encoding terminates the connection.

## 2. Primitives

| Purpose | Primitive | Notes |
|---|---|---|
| Key exchange | X25519 (RFC 7748) | ephemeral-ephemeral, per connection |
| KDF | HKDF-SHA256 (RFC 5869) | fixed, versioned `info` strings |
| Auth MAC | HMAC-SHA256 | keyed by the PSK, over a canonical transcript |
| AEAD | AES-256-GCM (suite 1) mandatory; ChaCha20-Poly1305 (suite 2) optional | 12-byte nonce, 16-byte tag |
| Randomness | OS CSPRNG | `os.urandom`, `crypto/rand`, `OsRng`, `SecureRandom` |

Domain separation labels (ASCII, never reused for another purpose):

```
umbra/v1/bootstrap              HSKDF salt for PSK phase keys
umbra/v1/bootstrap/psk          HKDF salt used to bind the PSK to a suite
umbra/v1/bootstrap/c2s          info: PSK key, client → server
umbra/v1/bootstrap/s2c          info: PSK key, server → client
umbra/v1/bootstrap/auth/hello   HELLO transcript prefix
umbra/v1/bootstrap/auth/ack     HELLO_ACK transcript prefix
umbra/v1/session                session salt prefix
umbra/v1/session/keys           info: session key set
umbra/v1/rekey                  rekey PRK salt / info prefix
```

Suites: `1 = AES-256-GCM`, `2 = ChaCha20-Poly1305`. A peer only offers suites it
can actually use; the reference Go server compiles in suite 1 only (Go's standard
library has no ChaCha20-Poly1305), the Rust beacon offers suite 2 first when built
with `--features chacha`, and every participant accepts suite 1.

## 3. Value encoding: upk

A tiny canonical TLV encoding: `type byte | payload`.

| Tag | Type | Payload |
|---|---|---|
| `0x00` | null | — |
| `0x01` | false | — |
| `0x02` | true | — |
| `0x03` | uvarint | unsigned LEB128, < 2⁶⁴, minimal |
| `0x04` | svarint | zigzag LEB128, ≥ −2⁶³ |
| `0x05` | f64 | IEEE-754 big endian |
| `0x06` | str | uvarint length + UTF-8 bytes |
| `0x07` | bin | uvarint length + raw bytes |
| `0x08` | array | uvarint count + values |
| `0x09` | map | uvarint count + (str key, value) pairs |

Canonicalisation rules (a decoder MUST reject violations):

* map keys are strings, sorted **byte-wise ascending**, strictly (no duplicates);
* uvarint/svarint use the shortest form; a 10th byte is only allowed when the
  value needs it, and `0x80 0x00` is invalid;
* non-negative integers MUST use `0x03`, negative integers MUST use `0x04`
  (encoders canonicalise; decoders may accept either and re-encode canonically);
* no trailing bytes after the top-level value;
* strings and map keys MUST be **valid UTF-8** (well-formed shortest form, no
  surrogate code points): a decoder rejects bad bytes rather than
  substituting U+FFFD, because a substitution would re-encode to different
  bytes and silently break the key-order rule;
* limits: nesting ≤ 16, containers ≤ 2²⁰ items, strings/binary ≤ 1 MiB, total ≤ 4 MiB.

"Nesting ≤ 16" counts **containers**, not values: sixteen nested arrays/maps are
accepted and the seventeenth is rejected, on both encode and decode. The boundary
is pinned twice in `contracts/vectors.json` — `upk` case `depth-max` (accepted) and
reject case `upk_depth_exceeded` (hand-built bytes, so a decoder must refuse them).

The other negative cases are hand-built for the same reason — the reference
encoder cannot produce them, so they exercise the decoder only:
`upk_nonminimal_nested` (`0x80 0x00` inside an array), `upk_nonminimal_key_len`
(inside a map key), `upk_duplicate_key`, `upk_unsorted_map`, `upk_trailing`,
`upk_unknown_tag`, and `upk_invalid_utf8` / `upk_surrogate_utf8` /
`upk_overlong_utf8` (a loner `0xFF`, a UTF-8-encoded surrogate `ED A0 80`, and an
overlong `/` `C0 AF`).
That convention has to be spelled out because an off-by-one here is invisible
until a deeply nested message crosses between two implementations.

Example: `{"b": 1, "a": [1, -2]}` →
`09 02 06 01 61 08 02 03 01 04 03 06 01 62 03 01`
(map of 2 → key `a` → array of 2 → `1`, `-2`; key `b` → `1`).

## 4. Frames

```
prelude (12 B, cleartext, authenticated as AAD)
  0..1   magic 0x55 0x43  ("UC")
  2      version = 1
  3      flags: bit0 = bootstrap phase (PSK keys), all others zero
  4      message type
  5      AEAD suite
  6..7   reserved, must be zero
  8..11  plaintext length, u32 big endian
nonce (12 B) = 4-byte direction prefix ‖ 8-byte counter (big endian)
ciphertext (len bytes) ‖ tag (16 B)
```

Total on-wire size = `24 + len + 16`. Plaintext length ≤ 1 MiB.

Why the length is cleartext: stream transports must frame before they hold keys,
and bounds checking happens before any crypto work. It is bound into the AAD, so
it cannot be altered without failing authentication.

Nonces are deterministic, never random: each direction owns a 32-bit prefix
derived from the key schedule and a monotonically increasing 64-bit counter. A
receiver requires the nonce to equal the exact expected value, which makes
replay, reordering and "frame drops" detectable rather than silently accepted.

**Sender invariant (SEND-SERIAL).** Because the receiver insists on the exact
counter, frames must reach the wire in the order they were sealed. Sealing and
writing are therefore one critical section per connection: exactly one writer at
a time, and the counter is reserved *before* the ciphertext is produced so a
failed seal can never hand the same nonce to a retry. Any implementation with
more than one potential writer per connection (a request handler plus an event
or heartbeat pusher) must serialise seal+write, not just the counter:

| implementation | mechanism |
| --- | --- |
| Python | `netio.SendGate` |
| Go (server) | `link.Sender` |
| Rust (beacon) | single-threaded loop owns the session (`&mut self`) |
| Kotlin (Android) | single-threaded beacon loop owns the session |

Breaking this invariant does not weaken confidentiality by itself, but it does
desynchronise the link: the peer sees counter `n+1` while expecting `n`, fails
the nonce check and drops the connection. Reusing a nonce under one key is the
one thing that must never happen, and it is why both the reservation and the
write are serialised.

## 5. Handshake

```
client                                                    server
  |  HELLO        (bootstrap keys, encrypted)              |
  |  {v, role, id, pub, cn, ts, suite, auth, meta}         |
  | -----------------------------------------------------> |
  |                            verify ts skew, role/key    |
  |                            binding, HMAC transcript    |
  |  HELLO_ACK    (bootstrap keys, encrypted)              |
  |  {v, pub, sn, sid, suite, auth, cfg, name, meta}       |
  | <----------------------------------------------------- |
  |  verify HMAC, derive session keys                      |
  |  ================= session keys =====================  |
```

Both handshake frames carry a one-byte payload marker (`0x01` for HELLO,
`0x02` for HELLO_ACK) followed by a upk map.

Bootstrap keys (per direction, per suite):

```
psk_n  = HKDF-SHA256(ikm = psk, salt = "umbra/v1/bootstrap/psk",
                     info = "suite:" ‖ suite, L = 32)
k_c2s  = HKDF-SHA256(ikm = psk_n, salt = "umbra/v1/bootstrap",
                     info = "umbra/v1/bootstrap/c2s", L = 32)
k_s2c  = HKDF-SHA256(ikm = psk_n, salt = "umbra/v1/bootstrap",
                     info = "umbra/v1/bootstrap/s2c", L = 32)
prefix = HKDF-SHA256(ikm = k_dir, salt = "umbra/v1/bootstrap",
                     info = "nonce-prefix", L = 4)
```

Transcript MACs (PSK is never transmitted and never used as a data key):

```
hello_auth = HMAC-SHA256(psk,
    "umbra/v1/bootstrap/auth/hello" ‖ role(1) ‖ len(id)(1) ‖ id ‖ pub(32)
    ‖ cn(16) ‖ ts(8, BE) ‖ suite(1))

ack_auth   = HMAC-SHA256(psk,
    "umbra/v1/bootstrap/auth/ack" ‖ len(id)(1) ‖ id ‖ client_pub(32)
    ‖ server_pub(32) ‖ cn(16) ‖ sn(16) ‖ sid(16) ‖ suite(1))
```

HELLO fields:

| Field | Type | Meaning |
|---|---|---|
| `v` | uint | protocol version, must be 1 |
| `role` | uint | 1 = agent, 2 = operator |
| `id` | str | agent identity or operator name (≤ 128 bytes) |
| `pub` | bin[32] | client ephemeral X25519 public key |
| `cn` | bin[16] | client nonce |
| `ts` | uint | unix seconds; `|now − ts| ≤ max_clock_skew_s` |
| `suite` | uint | offered AEAD suite |
| `auth` | bin[32] | `hello_auth` |
| `meta` | map | agents: `host, os, arch, user, pid, integ, ver`; operators: `client, ver` |

HELLO_ACK fields: `v, pub, sn, sid, suite, auth, cfg{sleep,jitter}, name, meta`.

Server-side validation order: decrypt → marker → upk → version → role ↔ key
binding (an operator token only authenticates the identity it was issued for;
the agent PSK never authenticates an operator) → identity → key/nonce lengths →
clock skew → suite → HMAC (constant time) → key exchange.

An agent PSK compromise therefore cannot open the operator API, and an operator
token compromise cannot enrol new implants.

## 6. Session keys, nonces, rotation

```
salt     = SHA256("umbra/v1/session" ‖ cn ‖ sn)
prk      = HKDF-Extract(salt, shared_secret)
okm(72)  = HKDF-Expand(prk, "umbra/v1/session/keys", 72)
c2s_key  = okm[0:32]     s2c_key    = okm[32:64]
c2s_pref = okm[64:68]    s2c_pref   = okm[68:72]
```

Counter starts at 0 in each direction. A new connection always starts from a
fresh X25519 exchange, so keys never repeat across connections.

Key rotation (after 2²⁰ frames, or on demand):

```
new_prk = HKDF-Extract(salt = seed(32, random), ikm = prk)
okm(72) = HKDF-Expand(new_prk, "umbra/v1/rekey/keys", 72)
```

The seed is delivered in a `REKEY` message. Because the running PRK is mixed in,
an attacker who learns the current key set cannot derive past or future key sets.

Rotation ordering is forced by two rules that interact:

1. the `REKEY` frame is sealed with the **old** key set, because the peer cannot
   open anything sealed with keys it has not switched to yet, and
2. frames must be written in the order they were sealed (SEND-SERIAL), and a
   frame sealed after the rotation carries counter 0.

A `REKEY` frame therefore cannot follow a frame sealed with the new key set. The
server sends it **immediately before** `TASK_BATCH`:

```
server                                                  agent
  |  REKEY {seed}   (old keys, counter n)  ------------> |
  |                               apply(seed) -> counters reset to 0
  |  TASK_BATCH {…} (new keys, counter 0)  ------------> |
```

After a rotation both counters reset to 0 and both sides switch atomically.
Because the seed arrives before the batch, a beacon simply reads frames until it
sees `TASK_BATCH`, applying any `REKEY` on the way (implementations cap that at
four control frames). No length guessing, no timeouts — which matters for the
HTTP transport, where a body may hold several frames.

## 7. Messages

All bodies are upk maps. Types are stable wire constants.

| Type | Name | Direction | Body |
|---|---|---|---|
| `0x01` | HELLO | client → server | handshake (above) |
| `0x02` | HELLO_ACK | server → client | handshake (above) |
| `0x10` | CHECKIN | agent → server | `{ts, n}` — `n` = results still backlogged |
| `0x11` | TASK_BATCH | server → agent | `{tasks[], sleep, jitter, server_time}` |
| `0x12` | RESULT | agent → server | `{id, code, out, err}` |
| `0x13` | CONFIG | server → agent | reserved (policy is carried in TASK_BATCH today) |
| `0x14` | PING | either | `{ts}` |
| `0x15` | PONG | either | `{ts}` |
| `0x16` | REKEY | either | `{seed}` |
| `0x17` | KILL | server → agent | `{reason}` |
| `0x18` | TASK_CANCEL | server → agent | `{id}` (reserved) |
| `0x19` | BYE | agent → server | `{}` — end of the beacon cycle |
| `0x1F` | ERROR | either | `{code, msg}` — informational; the session stays up and the server emits a `beacon.error` operator event (message clipped to 512 bytes) |
| `0x20` | OP_REQUEST | operator → server | `{rid, cmd, args}` |
| `0x21` | OP_RESPONSE | server → operator | `{rid, ok, data, err}` |
| `0x22` | OP_EVENT | server → operator | `{kind, at, agent_id, task_id, data}` |

`tasks[]` entries: `{id, kind, args}` where `args` is a map defined per kind.

Task kinds understood by the reference implants:

| kind | args | result |
|---|---|---|
| `shell` | `cmd`, optional `timeout` (s) | stdout+stderr, exit code |
| `sysinfo` | — | text report |
| `ls` | `path` | directory listing |
| `download` | `path` | file bytes (≤ 900 KiB per task) |
| `upload` | `path`, `data` (bin) | confirmation text |
| `ps` | — | process listing |
| `sleep` | `sleep`, `jitter` | confirmation; beacon applies it |
| `exit` | — | beacon sends result, then BYE and terminates |
| `ping` | — | `pong` |

Operator RPC commands: `ping`, `server.stats`, `agents.list`, `agents.info`,
`agents.sleep`, `agents.kill`, `task.submit`, `task.get`, `task.list`,
`task.cancel`, `events.test`. Responses keep the `rid` of the request; events are
asynchronous and can arrive at any time.

## 8. Transports

**TCP** — one connection per beacon cycle:

```
connect → HELLO/HELLO_ACK → CHECKIN → TASK_BATCH → RESULT… → BYE → close
```

Everything after the handshake reuses the same connection, so a cycle costs a
single TCP handshake. Operators use the same listener type but keep the
connection open and multiplex RPCs by `rid`.

**HTTP** — the same frames inside POST bodies, one request per direction step:

```
POST /api/v1/beacon            body: HELLO       → body: HELLO_ACK   (+ sid)
POST /api/v1/beacon/<sid-hex>  body: CHECKIN     → body: TASK_BATCH
POST /api/v1/beacon/<sid-hex>  body: RESULT…,BYE → empty body (200)
```

`<sid-hex>` is the 128-bit session id from HELLO_ACK; it selects the server-side
session and acts as an unguessable routing capability. It cannot be used to read
or forge traffic because every frame is still AEAD-protected and nonce-ordered,
and it expires after `idle_timeout_s` of inactivity. The implant speaks plain
HTTP/1.1 by design (no TLS stack in the binary), so TLS termination in front of
this listener is not usable: run it inside an encrypted tunnel instead, with the
proxy providing access control and rate limiting (see
`deploy/nginx-http-transport.conf`).

A response body may contain several concatenated frames; a request body may also
carry several.

## 9. Failure handling

| Condition | Result |
|---|---|
| bad magic/version/reserved/suite, frame > 1 MiB | connection dropped before AEAD work |
| AEAD tag failure, nonce mismatch, size mismatch | connection dropped, frame counted as hostile |
| HELLO version/role/identity/skew/HMAC failure | handshake rejected, source address penalised |
| repeated handshake failures from one address (≥ 5) | address banned for 10 minutes |
| unknown message type | logged and ignored (forward compatibility) |
| bad upk (non-canonical, truncated, oversized) | connection dropped |
| task result for an unknown task id | logged, session continues |
| agent sends ERROR (0x1F) | surfaced as a `beacon.error` operator event, session continues |

The server never answers a failed handshake, so it cannot be used as an oracle
for PSK probing.

## 10. Change policy

* Message type numbers and suite ids are never reused.
* Any change to the key schedule, transcript, prelude layout or upk rules bumps
  the protocol version label (`umbra/v1` → `umbra/v2`) and regenerates
  `contracts/vectors.json` (`make vectors`).
* All three test-suites must pass before a protocol change merges.
