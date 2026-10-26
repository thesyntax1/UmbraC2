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

### Control frames before a batch

A check-in response may start with up to **8** control frames, in this order,
before the `TASK_BATCH` that ends the response:

```
[REKEY]  [TASK_CANCEL ×≤4]  TASK_BATCH
```

* `REKEY` is sealed with the **old** key set and resets both counters to 0, so
  it must come first; everything after it uses the new keys.
* `TASK_CANCEL` names a task the beacon already holds and must arrive before the
  batch that could still contain it. The beacon records the id, keeps reading,
  and skips that task if it appears — reporting `{code: 125, err: "cancelled
  before execution"}` rather than pretending the task never existed.
* The beacon therefore reads until it sees `TASK_BATCH` (bounded by the frame
  count above), not a fixed number of frames. A server that sends more, or
  something else entirely, gets the cycle dropped, not a hung beacon.

This window exists because cancels are taken *after* the batch is built: a task
can be delivered to the batch and cancelled before the frames are sealed.

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
| `0x12` | RESULT | agent → server | `{id, code, out, err}` plus optional scalar metadata (§7.1) |
| `0x13` | CONFIG | server → agent | reserved (policy is carried in TASK_BATCH today) |
| `0x14` | PING | either | `{ts}` |
| `0x15` | PONG | either | `{ts}` |
| `0x16` | REKEY | either | `{seed}` |
| `0x17` | KILL | server → agent | `{reason}` |
| `0x18` | TASK_CANCEL | server → agent | `{id}` — sent immediately before the `TASK_BATCH` it modifies (see §6); the beacon skips that task and reports `code 125` |
| `0x19` | BYE | agent → server | `{}` — end of the beacon cycle |
| `0x1A` | TUNNEL_OPEN | either | `{stream, op, host?, port?, ok?, err?}` — pivoting (§7.3) |
| `0x1B` | TUNNEL_DATA | either | `{stream, data}` — payload bytes of one pivot stream |
| `0x1C` | TUNNEL_CLOSE | either | `{stream, reason?}` — one pivot stream ended |
| `0x1E` | PADDING | either | `{data}` — random bytes, ignored by the receiver; used to shape traffic |
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
| `recon` | — | host report, environment findings (debugger, sandbox) and domain edges |
| `ls` | `path` | directory listing |
| `download` | `path`, optional `offset`, `limit` | file bytes (≤ 900 KiB per task) + transfer metadata (§7.1) |
| `upload` | `path`, `data` (bin), optional `offset`, `eof` | confirmation text + transfer metadata (§7.1) |
| `ps` | — | process listing |
| `sleep` | `sleep`, `jitter` | confirmation; beacon applies it (with sleep obfuscation, §7.5) |
| `exit` | — | beacon sends result, then BYE and terminates |
| `ping` | — | `pong` |
| `tunnel` | `stream` | opens a pivot callback session (§7.3) |
| `p2p` | `action` (`connect`/`listen`), `host`, `port`, `stream` | peer-to-peer pivot link (§7.3) |
| `bof` | `name`, `data` (bin, COFF object), `args` (list) | in-memory COFF execution: output + exit code |
| `ext` | `name`, `data` (bin, module), `args` (map) | in-memory extension execution |
| `inject` | `pid`, `mode` (`inject`/`migrate`/`reflect`), optional `data` (bin, PE) | process injection / migration / reflective load |
| `creds` | `mode` (`vault`/`dpapi`/`lsass`) | credential material found on the host |
| `token` | optional `pid` | duplicated access token of another user or service |
| `privesc` | `mode` | local privilege escalation attempt |
| `vpn` | `action` (`start`/`stop`), optional `addr` | layer-3 tunnel endpoint state |
| `session.open` | `cmd` (empty starts the platform shell) | an interactive session; the output streams as partial results (§7.2c) |
| `session.input` | `session`, `data` (text or bin) | writes to an open session |
| `session.close` | `session` | closes a session and ends its task |
| `keylog` | `seconds` | the pressed keys, streamed as partial results (Windows) |
| `screenshot` | — | the screen as a BMP file (Windows) |
| `clipboard` | — | the text on the clipboard (Windows) |
| `triage` | `path` | the size, the digest, the format and the entropy of a file |
| `find` | `path`, `name` (glob or substring), `content`, `max` | the files that match |
| `netinfo` | — | the interfaces, the routes, the neighbours and the resolvers |
| `persist` | optional `method` | installs the implant so it survives a reboot |
| `update` | `path`, optional `sha256` | replaces the running implant with a verified one |

### 7.1 Result metadata and chunked transfer

A RESULT body may carry extra keys next to `id`, `code`, `out` and `err`. The
server does not interpret them: it keeps the scalar ones (`string`, `bool`,
numbers) in the task record under `meta` and returns them from `task.get` /
`task.list`. Nested values are dropped, so a beacon cannot grow the state file
arbitrarily. The `task.result` event carries a bounded preview instead of the
payload: `size` always, `output` when the bytes are valid UTF-8 (clipped to
4 KiB with `truncated: true`), `binary: true` when they are not. `task.get`
remains the way to collect the full output.

That is what makes transfers chunked rather than hopeful. `download` takes a
byte range and answers with:

| key | meaning |
|---|---|
| `out` | the requested bytes |
| `total` | file size in bytes |
| `offset` | offset this chunk starts at |
| `eof` | `true` when this chunk reaches the end of the file |
| `sha256` | hex SHA-256 **of this chunk** |

`upload` writes at `offset` (offset `0` truncates the file first, so re-sending
a shorter file cannot leave an old tail behind) and answers with `written`,
`eof`, and — on the final chunk (`eof: true`) — `total` and a `sha256` of the
whole file.

The 900 KiB step size comes from the beacon's output budget: one chunk plus
framing always fits in a single 1 MiB frame, so a transfer needs no new message
type. The CLI drives the loop (`umbra download` / `umbra upload`) and verifies
each chunk hash, the final size and the whole-file hash before it renames
`<local>.part` into place.

### 7.2 Shared-work coordination

Three small pieces make a team on one server workable, and none of them change
what a beacon does:

* **Focus** — `operators.focus {id}` records which agent a console is looking
  at (`id` empty clears it) and pushes an `operator.focus` event, so a teammate
  opens `operators.list` and sees `focus`/`focus_at`/`idle_sec` instead of
  guessing. The interactive console sends it automatically on `use <agent>`.
* **Claims** — `task.claim {task_id}` records `claimed_by`/`claimed_at` on the
  task; a second operator gets `task is claimed by <name>` until the holder runs
  `task.release`. A claim is advisory: it orders human work and never delays or
  blocks the task. A finished task cannot be claimed; claiming twice is a no-op.
* **Directed chat** — `chat.send {text, to}` addresses one connected operator
  (`to` must be a live name, otherwise the call fails). The event is delivered
  only to that console and the sender, while `chat.history` keeps the message
  with its `to` field: on a shared engagement the record is shared too. It is
  addressing, not a private channel — do not put secrets in chat.

Operator RPC commands, with the minimum role each requires:

| Command | Role | Notes |
|---|---|---|
| `ping` | viewer | liveness |
| `whoami` | viewer | identity, role, peer, allowed commands |
| `server.stats` | viewer | counters, including `events_dropped` |
| `agents.list` | viewer | inventory; optional filters: `state`, `transport`, `os`, `arch`, `tag`, `user` |
| `agents.info` | viewer | one agent and its recent tasks |
| `operators.list` | viewer | connected consoles: focus agent, idle time, queue depth |
| `task.get` | viewer | one task |
| `task.list` | viewer | tasks; optional filters: `id` (agent), `kind`, `state` |
| `audit.tail` | viewer | recent operator actions |
| `chat.history` | viewer | recent chat |
| `schedule.list` | viewer | recurring tasks |
| `task.submit` | operator | queue a task |
| `task.bulk` | operator | queue one task on many agents: `agents` (list) and/or `filter` |
| `task.chain` | operator | queue a multi-stage task: `stages` is a list of `{kind, args}` |
| `alerts.list` | viewer | the alert rules the server watches the event stream with |
| `task.cancel` | operator | cancel a task (`TASK_CANCEL` if delivered) |
| `agents.sleep` | operator | change beacon cadence |
| `agents.policy` | operator | push the cadence and the sleep obfuscation to many agents |
| `agents.tag` | operator | label agents: `mode` is `add`, `remove` or `set` |
| `agents.kill` | operator | queue the exit task |
| `agents.exit` | operator | alias of `agents.kill` |
| `chat.send` | operator | team message; `to` addresses one operator |
| `schedule.add` | operator | recurring task (5–86400 s) |
| `task.claim` | operator | take ownership of a task |
| `task.release` | operator | drop your claim |
| `operators.focus` | operator | announce the agent you are working on |
| `schedule.remove` | admin | remove a recurring task |
| `events.test` | admin | emit a synthetic event |
| `pivot.list` | viewer | open pivots: agent, mode, listener, byte counters |
| `pivot.open` | operator | open a SOCKS5 proxy or a port forward through an agent |
| `pivot.close` | operator | close a pivot |
| `vpn.status` | viewer | tunnel state: listener, network, peer count |
| `vpn.peers` | viewer | tunnel peers and their addresses |
| `vpn.allocate` | operator | reserve a tunnel address for an agent |
| `armory.list` | viewer | catalogue and installed extensions |
| `armory.install` | operator | fetch, verify and install an extension |
| `armory.remove` | admin | delete an installed extension |
| `armory.run` | operator | run an extension on an agent |
| `alias.list` | viewer | the runtime command namespace |
| `alias.run` | operator | run a named template on an agent |
| `team.sync` | viewer | full state snapshot for a console that joins late |
| `stager.generate` | admin | build a stage-0 one-liner (it carries the agent PSK) |

### 7.2a Selecting agents

The bulk operations (`task.bulk`, `agents.policy`, `agents.tag`) take their
targets in one of two ways, and both can be combined:

* `agents` — an explicit list of agent ids (`["web-01", "web-02"]`; a comma
  separated string is accepted as well);
* `filter` — a description of the agents to select: `state` (`online` /
  `offline`), `transport`, `os`, `arch`, `tag`, `user`.

An operation with neither is refused. A bulk task that hits every agent in the
inventory because a filter was forgotten is not recoverable, so the server
makes the operator say what it means.

The filter is the same in `agents.list`, which makes the console's views
consistent: what an operator filters by to *find* an agent is what an
operator filters by to *act* on it.

The `state` of an agent describes its **check-in**, not its socket. The beacon
opens one connection per cycle and closes it again, so an agent stays `online`
while it keeps checking in and turns `offline` once it has been quiet for
longer than the grace period (90 s, or three of its own intervals —
whichever is longer).

### 7.2b The beacon policy

The server pushes the cadence with every check-in, and the policy RPC changes
what it pushes:

```json
{"cmd": "agents.policy", "args": {"filter": {"state": "online"}, "sleep": 60, "jitter": 35, "obfuscate": true}}
```

* `sleep` (1–86400 s) and `jitter` (0–90 %) are the interval and the jitter;
* `obfuscate` decides whether the beacon hides its check-in pattern. It is on
  by default and travels with the cadence in the `TASK_BATCH` body (`obf`),
  so the operator decides, not the environment of the implant.

Roles are `viewer` < `operator` < `admin`. Identities come from
`operator_token_env` entries formatted `name:token` (role defaults to
`operator`) or `name:role:token`. A command that is not in the table requires
`admin`, so a new RPC is closed by default. A refused call returns
`{ok:false, err:"permission denied: …"}` and is recorded in the audit log.

Responses keep the `rid` of the request; events are asynchronous and can arrive
at any time.

### 7.2c Streaming output and interactive sessions

A RESULT body may carry `partial: true`.  The server then **appends** the
chunk to the output of the task instead of completing it, and pushes a
`task.output` event with the chunk.  The task stays in the `delivered` state
until the final RESULT arrives, so a task that streams is visible as running.

That is what an interactive session is built on:

```json
{"kind": "session.open", "args": {"cmd": ""}}
```

The beacon starts the process with its input and output piped, answers with a
partial result that carries the session id (`session` in the result metadata)
and then streams the output of the process as partial results.  The operator
writes with `session.input` and ends the session with `session.close`, which
completes the task with the exit status of the process.

The session lives in the implant, not in the connection: a session survives a
re-connect, and the beacon keeps the connection open while a session is live,
so the operator types into a shell instead of queueing a line for the next
check-in.

### 7.2d Multi-stage tasks

A chain is a sequence of tasks where the output of a stage becomes the input
of the next one:

```json
{"cmd": "task.chain", "args": {"id": "web-01", "stages": [
  {"kind": "shell", "args": {"cmd": "ls /etc/umbra"}},
  {"kind": "shell", "args": {"cmd": "cat {{output}}"}}
]}}
```

`{{output}}` is replaced with the output of the previous stage in the string
values of the arguments.  The substitution only touches text: the output of a
stage is data, never code.  The chain lives in the server's memory, the
stages are ordinary tasks, and the events `chain.started`, `chain.stage` and
`chain.done` tell the consoles what is happening.

### 7.2e Alert rules

The server can watch its own event stream:

```json
{"alerts": [{"name": "dc-offline", "event": "agent.offline", "tag": "dc", "cooldown_s": 300}]}
```

A rule matches on the event kind, on a tag of the agent, on the beginning of
the agent id and on the kind of the task.  When a rule matches, the server
logs the event loudly and pushes an `alert` event of its own, so a console
that watches the alerts sees it even when the original event is noise.  The
cooldown keeps a noisy agent from producing an alert on every check-in.

### 7.3 Pivoting, tunnels and the layer-3 VPN

Pivoting is built on one rule: **the agent always dials out**. A beacon that
can reach the team server can open a *callback session* on demand, so a
network where the server cannot reach the host (NAT, a strict egress policy)
is still reachable in the other direction.

```
operator            server                       agent
  |  pivot.open       |                             |
  |------------------>|  task "tunnel" {stream}    |
  |                   |---------------------------->|
  |                   |                             |  dial back to the
  |                   |                             |  agent listener
  |                   |<----------------------------|  HELLO {meta:{tunnel}}
  |                   |  TUNNEL_OPEN {op:"ready"}   |
  |                   |---------------------------->|
  |                   |  TUNNEL_OPEN {op:"ok"}      |
  |                   |<----------------------------|
```

The callback is a normal agent handshake: the HELLO carries `meta.tunnel =
<stream>`, and the server pairs it with the queued `tunnel` task instead of
registering a second live beacon. The callback connection then carries the
tunnel frames and nothing else.

Logical streams are multiplexed over that one connection:

| direction | frame | meaning |
|---|---|---|
| server → agent | `TUNNEL_OPEN {stream, op:"open", host, port}` | open a connection to `host:port` |
| agent → server | `TUNNEL_OPEN {stream, op:"result", ok, err}` | the result of that request |
| either | `TUNNEL_DATA {stream, data}` | payload bytes (≤ 32 KiB per frame) |
| either | `TUNNEL_CLOSE {stream, reason}` | the stream ended |

Two local listeners sit in front of the streams:

* **SOCKS5** (`pivot.open {id, mode:"socks"}`) — RFC 1928, `CONNECT` only, no
  authentication, bound to loopback by default. The client picks the target.
* **port forward** (`pivot.open {id, mode:"forward", host, port}`) — every
  accepted connection is relayed to one fixed `host:port`.

**Peer-to-peer** pivoting chains two beacons: the `p2p` task makes one agent
open a TCP link to another agent (`action:"connect"` with `host`/`port`) or
listen for one (`action:"listen"`). The link is encrypted with keys derived
from the agent PSK and an X25519 exchange, and it carries the same
`TUNNEL_*` frames, so a third host can be reached through a chain of
beacons without the team server carrying the traffic.

**The layer-3 tunnel** (`vpn`) is a transport of its own: a UDP socket with a
Noise-IK-style handshake (`INIT`/`RESP`), AES-256-GCM data packets and a
64-packet replay window. It exists because it keeps working when the
beaconing channel does not: the console and the beacon exchange IPv4 packets
over it, and the server routes them by tunnel address (`10.77.0.0/24` by
default). The handshake MAC is keyed with a secret both sides already hold
(the agent PSK or an operator token), so no additional key distribution is
needed.

### 7.4 Traffic shaping

A `PADDING` frame (`0x1E`) carries random bytes and is ignored by the
receiver. It exists so a transport can pad its bodies to a coarse size bucket
(`http_pad`) without changing the frame format: the payload size of a frame
stays hidden behind the bucket, and the padding is part of the AEAD, so it
cannot be forged.

The body of a padding frame is a binary upk value. Its size is chosen so the
*whole* body reaches the bucket: the frame overhead is the prelude, the
nonce, the upk tag of the body, the length prefix of the body and the
authentication tag, and the length prefix grows with the body — so the length
is solved for, not guessed. A receiver steps over a padding frame exactly
like it steps over an unknown message type: it is ignored, and the session
continues.

### 7.5 Sleep obfuscation

The beacon does not check in on a fixed period.  The jitter spreads the
intervals around the configured sleep, and on top of that the beacon takes
an occasional long nap (roughly one check-in in four sleeps 1.5 to 3.5 times
longer).  A uniform distribution is a signature of its own: a beacon that
checks in every 60.4 seconds on average is easier to find than one that
sometimes sleeps for three minutes.

The obfuscation can be switched off with `UMBRA_SLEEP_OBFUSCATE=0` when a
fixed interval matters more than the traffic pattern (a lab test that needs
a predictable check-in, for instance).

## 8. Transports

**TCP** — one connection per beacon cycle:

```
connect → HELLO/HELLO_ACK → CHECKIN → TASK_BATCH → RESULT… → BYE → close
```

Everything after the handshake reuses the same connection, so a cycle costs a
single TCP handshake. Operators use the same listener type but keep the
connection open and multiplex RPCs by `rid`.

**HTTP** — the same frames inside POST bodies, one request per direction step,
over a kept-alive connection:

```
POST /api/v1/beacon            body: HELLO       → body: HELLO_ACK   (+ sid)
POST /api/v1/beacon/<sid-hex>  body: CHECKIN     → body: TASK_BATCH
POST /api/v1/beacon/<sid-hex>  body: RESULT…,BYE → empty body (200)
```

Every reply carries an explicit `Content-Length` and never uses chunked framing,
so the connection stays open: the three POSTs of a cycle share one TCP connection
(the Rust implant pools the socket for the cycle and retries once on a fresh one
if the pooled socket was already closed; the Android beacon leaves
`HttpURLConnection`'s keep-alive pool alone instead of calling `disconnect()`).

`<sid-hex>` is the 128-bit session id from HELLO_ACK; it selects the server-side
session and acts as an unguessable routing capability. It cannot be used to read
or forge traffic because every frame is still AEAD-protected and nonce-ordered,
and it expires after `idle_timeout_s` of inactivity. The implant speaks plain
HTTP/1.1 by design (no TLS stack in the binary), so TLS termination in front of
this listener is not usable: run it inside an encrypted tunnel instead, with the
proxy providing access control and rate limiting (see
`deploy/nginx-http-transport.conf`).

A response body may contain several concatenated frames; a request body may also
carry several (a beacon reports a whole batch of results and its next check-in in
one POST). The server splits the body into frames with the same length-prefix
walk the frames use on the wire, processes them **in order** under one per-session
lock (so the SEND-SERIAL rule still holds over HTTP), and rejects the whole
request if any frame fails. Limits: at most 16 frames per request, handshake
bodies exactly one frame, empty bodies are a 400. A session is dropped — and the
agent marked offline — on a bad frame, on BYE, or when it has not polled within
`idle_timeout`.

**DNS** — the same frames, carried by TXT records.  The transport is used when
every other channel is blocked; the name of the query is the envelope:

```
query   <seq>.<chunk>.<agent>.<domain>
answer  TXT records, each one base32 of a slice of the frame
```

| Label | Meaning |
|---|---|
| `seq` | the sequence number of the query, eight hex characters |
| `chunk` | base32 of the bytes the agent sends; `-` means "nothing this time" |
| `agent` | base32 of the agent id |

Both directions are length prefixed: a four byte big endian length in front of
every frame, so a chunk that ends in the middle of a frame is reassembled
instead of breaking the stream.  One answer carries at most eight TXT records
(8 × 32 bytes of payload), and a frame that is larger is continued in the next
query.

The frames that travel through the tunnel are ordinary umbra/v1 frames: the
handshake, the key schedule, the task batch and the results are unchanged.  A
DNS transport is therefore a *transport*, not a second protocol — a session
that was established over DNS has the same properties as one that was
established over TCP.

The server answers only for its own domain (`dns_domain`); every other name
is left to the resolver.  A query for a name outside the domain is not
answered at all, and the tunnel never forwards anything.

**WebSocket** — the same frames, carried by RFC 6455.  The client opens the
beacon route with an upgrade request, and the server answers it on the same
route the HTTP transport uses:

```
GET /api/v1/beacon HTTP/1.1
Host: <host>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64 of 16 random bytes>
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
```

After the upgrade the connection is a frame stream again: one umbra frame per
binary WebSocket frame, in order.  The rules are the ones of RFC 6455 with
two restrictions: only binary frames are used (no text, no continuation), and
a fragmented message is refused instead of reassembled — the umbra frames fit
into one WebSocket frame, and refusing keeps the parser small.  A client
masks its frames, a server does not; the client verifies the accept value, so
an endpoint that is not a WebSocket server is detected immediately.

The WebSocket transport carries the same handshake, the same key schedule and
the same messages as every other transport: it is a transport, not a second
protocol.

**Mutual TLS** — a listener of its own (`tls_listen`).  The TLS layer proves
*who* the peer is (a certificate signed by `tls_client_ca`, optionally pinned
to a common name); the umbra handshake still decides *what* the peer may do.
The role in the HELLO picks the session: an agent gets a beacon session, an
operator gets a control channel.  TLS 1.3 is the minimum.

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
| `task.cancel` for a finished/cancelled task | refused ("cannot be cancelled"), nothing is sent |
| `task.cancel` for a delivered task | a `TASK_CANCEL` frame goes out before the next `TASK_BATCH`; a result that arrives later keeps the `cancelled` state and its output is still stored |
| HTTP request with an empty body | `400`, session kept |
| HTTP request with more than 16 frames | `413`, request dropped before any AEAD work |
| HTTP request for an unknown or expired session id | `410 Gone`, beacon re-handshakes |

The server never answers a failed handshake, so it cannot be used as an oracle
for PSK probing.

## 10. Change policy

* Message type numbers and suite ids are never reused.
* Any change to the key schedule, transcript, prelude layout or upk rules bumps
  the protocol version label (`umbra/v1` → `umbra/v2`) and regenerates
  `contracts/vectors.json` (`make vectors`).
* All three test-suites must pass before a protocol change merges.
