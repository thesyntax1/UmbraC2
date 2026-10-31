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

**Transport invariant (TLS-ONE-SESSION).** A TLS connection is *one* record
layer, and that layer keeps its state in the session: the sequence numbers, the
write buffer, a pending key update. Two threads inside the same session at the
same time scramble the stream — the peer sees a bad record MAC, or the link
dies half way through a frame. The operator control channel reads and writes
the same session at once by design: one thread waits for requests, another
pushes events. So the transport has to keep them apart.

| implementation | mechanism |
| --- | --- |
| Python | `netio.Stream` serialises the session and waits for the socket *outside* the lock |
| Go (server) | `crypto/tls` allows one reader and one writer; the frames go through `link.Sender` |
| Rust (beacon) | the beacon speaks plain TCP; one loop owns the session (`&mut self`) |
| Kotlin (Android) | the beacon speaks plain TCP; one loop owns the session |

The rule is not "one writer": it is *one thread inside the TLS session*. A
reader that holds the lock while it waits for bytes freezes the writer, so the
wait happens outside of it. A write that cannot be finished marks the session
as broken instead of leaving half a frame on the wire, because the peer would
read the rest of it as the beginning of the next frame.

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

**The key of an agent is hex on the wire of the operator.**  The server
prints the agent key as hex and the beacons read it as hex, and both sides
decode it before the key is used: the bytes behind the hex are the key.
A configuration that holds something that is not hex is taken as it is,
which is what a lab with raw bytes in the environment needs.

**The key of an agent may be bound to one host.**  The server holds a fleet
key (every beacon that was built before the per-agent keys existed uses it)
and, next to it, keys that belong to one agent id.  A key that is bound to
an id may only claim that id: the server refuses a HELLO whose identity is
not the one the key belongs to, so a key that is stolen impersonates one
machine and not the whole fleet.  The binding does not change the wire
format -- the identity of the HELLO is inside the transcript MAC either
way -- and it is the server that enforces it, right where it verifies the
MAC.

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
| `v` | uint | handshake version: 1 or 2 (see §5.1) |
| `role` | uint | 1 = agent, 2 = operator |
| `id` | str | agent identity or operator name (≤ 128 bytes) |
| `pub` | bin[32] | client ephemeral X25519 public key |
| `cn` | bin[16] | client nonce |
| `ts` | uint | unix seconds; `|now − ts| ≤ max_clock_skew_s` |
| `suite` | uint | offered AEAD suite |
| `auth` | bin[32] | `hello_auth` |
| `meta` | map | agents: `host, os, arch, user, pid, integ, ver`; operators: `client, ver` |
| `caps` | list[str] | **version 2 only**: the task kinds the implant can run (§7.2f) |
| `iver` | str | **version 2 only**: the version of the implant |
| `abi` | uint | **version 2 only**: the module ABI the implant speaks (§7.2j) |
| `plat` | map | **version 2 only**: the platform details: `os, arch, family` |

HELLO_ACK fields: `v, pub, sn, sid, suite, auth, cfg{sleep,jitter}, name, meta`,
plus, **in version 2 only**:

| Field | Type | Meaning |
|---|---|---|
| `abi` | uint | the module ABI the server speaks |
| `compat` | list[uint] | the handshake versions the server accepts |
| `limits` | map | the limits of the queue: `max_in_flight_per_agent`, `max_deliver_per_minute_per_agent`, `max_deliver_per_second`, `max_attempts` (§7.2o) |

### 5.1 The handshake versions, and who speaks to whom

The server speaks two handshake versions at the same time, and the answer
is always in the version the peer asked for: an old beacon never sees a
field it does not understand.

| the HELLO says | the server accepts | the answer is | what the peer gets |
|---|---|---|---|
| `v = 1` | yes | `HELLO_ACK` with `v = 1` | the original shape: the policy, the server name and its version |
| `v = 2` | yes | `HELLO_ACK` with `v = 2` | the same, plus the ABI, the accepted versions and the limits of the queue |
| `v = 0` or `v ≥ 3` | no | — | the handshake is refused and the connection is closed |

The capability list is the reason the second version exists: in the first
version it travelled inside the metadata, and a metadata map is the wrong
place for a list the server has to read before anything else.  A version 1
beacon keeps the list in the metadata, and the server reads it from there
when the field is missing — the two versions interoperate in both
directions.

The frame layer is versioned separately: a beacon that speaks the version 2
handshake still uses the same frames, and a frame it does not know is
ignored.  The only new frame is `HEARTBEAT` (§7.2p), and a server that
receives one from a beacon that never heard of it still answers it, because
the frame type is the only thing that decides what a frame means.

Server-side validation order: decrypt → marker → upk → version → role ↔ key
binding (an operator token only authenticates the identity it was issued for;
the agent PSK never authenticates an operator) → identity → key/nonce lengths →
clock skew → suite → HMAC (constant time) → key exchange.

An agent PSK compromise therefore cannot open the operator API, and an operator
token compromise cannot enrol new implants.

An operator that connects is subscribed to the event stream **before** the
HELLO_ACK is written. The console believes it is connected as soon as the
answer arrives, so an event that is emitted in the same breath has to find a
subscriber already; otherwise the console misses the first moments of the
engagement — the first check-in of the beacon that just woke up, the first
message of the colleague who is already there.

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
| `0x1D` | HEARTBEAT | agent → server | `{v, iver, abi, busy, up}` — the cheap signal of a beacon that is alive between two check-ins (§7.2p) |
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
| `recon` | optional `profile` (`host`/`windows`/`linux`/`cloud`/`container`/`all`), optional `checks` (list, wins over the profile) | the findings of the profile: one record per finding (kind, name, detail, severity, source) |
| `recon.suggest` | optional `profile`, optional `findings` (list, the findings of an earlier recon) | what could be tried next: one record per suggestion (title, why, score, kind, args) |
| `domain.map` | optional `target` (a node of the graph; the domain controller by default) | the paths from the identity of the implant to the target: one record per path |
| `ls` | `path` | directory listing |
| `download` | `path`, optional `offset`, `limit` | file bytes (≤ 900 KiB per task) + transfer metadata (§7.1) |
| `cat` | `path` | the contents of a file (the same work as `download`, without the transfer) |
| `upload` | `path`, `data` (bin), optional `offset`, `eof` | confirmation text + transfer metadata (§7.1) |
| `ps` | — | the process table of the host: the pid, the parent, the user, the start time and the command line |
| `sleep` | `sleep`, `jitter` | confirmation; beacon applies it (with sleep obfuscation, §7.5) |
| `exit` | — | beacon sends result, then BYE and terminates |
| `ping` | — | `pong` |
| `tunnel` | `stream` | opens a pivot callback session (§7.3) |
| `p2p` | `action` (`connect`/`listen`), `host`, `port`, `stream` | peer-to-peer pivot link (§7.3) |
| `bof` | `name`, `data` (bin, COFF object), `args` (list), `manifest` | in-memory COFF execution: output + exit code |
| `ext` | `name`, `data` (bin, module), `args` (map), `manifest` | in-memory extension execution; the loader is named by the manifest (§7.2j) |
| `wasm` | `name`, `data` (bin, webassembly module), `args` (map), `manifest` | the webassembly module runs in the interpreter: its output + its exit code |
| `script` | `name`, `data` (bin, the script), `args` (map), `manifest` | the script runs in the sandbox: its log + its exit code |
| `shellcode` | `name`, `data` (bin, the machine code), `args` (map), `manifest` | the shellcode runs in an executable page: its output + its exit code |
| `inject` | `pid`, `mode` (`inject`/`migrate`/`reflect`), optional `data` (bin, PE) | process injection / migration / reflective load; with `mode: migrate` the arguments are `pid` (a process that runs) or `spawn` (a program the implant starts), optional `args` (list), `out` (the implant leaves its own process) and `resume` (the original program keeps running) |
| `creds` | `mode` (`vault`/`dpapi`/`lsass`/`local`/`all`), optional `raw` | the credential material of the host, one record per piece of material (§7.2i) |
| `token` | `mode` (`list`/`impersonate`/`become`/`restore`), optional `pid`, optional `session` | the tokens of the host, or the identity the implant became (§7.2i) |
| `privesc` | `mode` (`privileges`/`token`) | the privilege escalation attempts, one record per technique (§7.2i) |
| `wmi.exec` | `target`, `command`, optional `user`, `timeout` | the command runs on the remote host through the pivot (§7.2i) |
| `smb.exec` | `target`, `command`, optional `timeout` | the command runs through the service control manager of the remote host |
| `winrm.exec` | `target`, `command`, optional `user` | the command runs in the remote shell of the remote host |
| `dcom.exec` | `target`, `command`, optional `user` | the command runs as a remote scheduled task of the remote host |
| `ldap.query` | `target`, `command` (the query) | the directory query of the remote host |
| `ssh.exec` | `target`, `command`, optional `user` | the command runs in the secure shell of the remote host |
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
| `scan` | `host` (an address or a CIDR block), `ports`, optional `timeout_ms` | the hosts that answered: one line per open port, plus the number of probes |
| `resolve` | `host`, optional `port` | the addresses a name points at |
| `env` | optional `filter` | the environment of the implant, one `KEY=VALUE` per line |
| `pwd` | — | the working directory of the implant |
| `touch` | `path` | creates the file if it is missing and stamps it with the current time |
| `proc.kill` | `pid` or `name` | terminates a process of the host |
| `keylog.file` | `path`, optional `seconds` | the key logger writes into a file, to be fetched later |
| `registry` | `hive`, `key`, optional `value` | the Windows registry: a key, its values and its subkeys |
| `tail` | `path`, optional `lines` | the last lines of a file |
| `hash` | `path` | the SHA-256 of a file |
| `persist` | optional `method`, `name`, `silent`, `verify` | installs the implant so it survives a reboot, with a technique the manager picks |
| `unpersist` | optional `method` (`all` removes every entry) | removes the start-up entries that `persist` added |
| `persist.list` | — | the persistence entries of the host |
| `persist.verify` | — | reads every entry back and says whether it is still there |
| `persist.migrate` | `from`, `to` | moves from one technique to another without a gap |
| `persist.health` | — | one verdict for the host: covered, degraded or broken |
| `evade.report` | — | the posture of the host: what the implant thinks it is |
| `evade.posture` | optional `silence_on_sandbox`, `slow_on_sandbox`, `virtual_factor`, `sandbox_factor`, `lab_factor`, `developer_factor`, `jitter_bonus` | how the environment changes the behaviour of the implant |
| `evade.profile` | optional `base`, `busy_start`, `busy_end`, `busy_factor`, `night_factor`, `weekend_factor` | the schedule the beacon sleeps by |
| `evade.shape` | optional `mode` (`off`, `random`, `fixed`), `size`, `pad_every`, `reorder` | the shape of the traffic |
| `evade.killswitch` | one of `file`, `registry`, `at`, `uptime`, `marker`; `clear` disarms it | the moment the implant stops existing |
| `hygiene.memory` | — | the memory hygiene: what holds a secret and what was wiped |
| `hygiene.process` | optional `copy`, `name`, `cwd`, `clean_env`, `ppid` | the process hygiene: the name, the directory, the environment and the parent |
| `host.guide` | optional `action` (`report`, `show`), `step` | what keeps the implant alive on this host, and what stops it |
| `ui.screen` | — | the text of the window the user of the phone is looking at (accessibility) |
| `ui.tap` | `needle`, optional `index` | presses the button that carries the needle (accessibility) |
| `ui.text` | `needle`, `value` | writes a text into the editable field that carries the needle (accessibility) |
| `ui.scroll` | optional `direction` (`forward`, `back`) | scrolls the window of the phone (accessibility) |
| `ui.global` | `action` (`back`, `home`, `recents`, `notifications`, `power`, `volume_up`, `volume_down`, `screenshot`) | the system keys of the phone (accessibility) |
| `ui.events` | — | the windows that changed, oldest first (accessibility) |
| `gps.locate` | — | where the phone is: the fresh fix and the last known position, with the provider, the altitude, the speed and the accuracy |
| `wifi.dump` | — | the networks around the phone: the connection, the results of the scan and the saved networks |
| `bluetooth.scan` | — | the bluetooth devices around the phone: the paired ones and the ones the discovery heard |
| `contacts.dump` | optional `limit` | the address book of the phone: the name, the number and the mail address |
| `sms.dump` | optional `limit` | the messages of the phone: the sender, the kind, the date and the body |
| `call.logs` | optional `limit` | the call log of the phone: the number, the name, the duration and the kind |
| `emulator.detect` | — | the verdict of the laboratory: whether the phone looks like an emulator, and the reasons behind it |
| `sms.watch` | optional `action` (`start`/`stop`/`poll`/`status`) | the watcher of the messages: the message that arrives is queued for the operator |
| `clipboard.sniff` | optional `action` (`start`/`stop`/`poll`/`status`) | the watcher of the clipboard: what the user copied is queued for the operator |
| `media.mic` | optional `seconds` | the sound of the room: the file of the recording and its digest |
| `media.camera` | optional `facing` (`back`/`front`) | the picture of the camera: the file of the picture and its digest |
| `live.screen` | optional `action` (`request`/`capture`/`status`) | one picture of the screen of the phone |
| `ui.stream` | optional `action` (`request`/`start`/`frames`/`stop`/`status`), optional `fps`, `count` | the pictures of the screen of the phone, streamed as partial results |
| `phish.overlay` | optional `action` (`arm`/`dismiss`/`status`), optional `package`, `title`, `prompt`, `fields`, `button` | the false screen: the form that is drawn over the application the operator named |
| `app.dump` | `package`, optional `path` | the databases of an application: the files, and the copy of them when the phone is rooted |
| `anti.forensic` | — | removes the material of the engagement from the phone and keeps the implant alive |
| `evade.suicide` | optional `wipe` | ends the implant: the watchers, the capture, the persistence, the state and the application |
| `window.list` | — | the windows of the desktop: the process, the class, the title and whether the window is on the screen |
| `clipboard.watch` | optional `action` (`start`/`stop`/`poll`/`status`), optional `interval_ms` | the watcher of the clipboard of the desktop: what the user copied is queued for the operator |
| `screen.stream` | optional `frames` (1–30), optional `fps` (1–30) | the screen of the desktop, streamed as partial results |
| `wifi.profiles` | — | the saved networks of the desktop, and the keys of them that the user of the machine may read |
| `browser.creds` | optional `raw` | the material of the browsers of the desktop: the accounts, the services, and the secrets when the operator asks for them |
| `av.survey` | — | the security software of the desktop: the products of the security centre and the services that watch the machine |
| `usb.history` | — | the USB keys of the desktop: the history of the machine and the devices that are attached now |
| `proc.memory` | `pid` | the memory of a process: the dump of the process, and the strings that look like a credential |
| `wipe.survey` | — | what the engagement left on the host: every artefact, its size and the reason it is a trace (it changes nothing) |
| `wipe.run` | optional `what` (list of `state`, `history`, `recent`, `cache`, `log`, `system` or `all`), optional `dry_run` | removes the artefacts of the named families and reports what was removed, what was scrubbed and what could not be touched |
| `wipe.verify` | — | what is left on the host after the wipe, and what no process of a user can reach |
| `wipe.self` | optional `keep_state` | the self-destruction of the implant: its state, its journal and its binary |
| `forensics.report` | — | the surface of the host as an analyst sees it: the artefacts, the persistence entries, the process and the journal |
| `forensics.timeline` | optional `journal` (`on`/`off`) | the timeline of the engagement on the host; the journal is written only while it is on |
| `decommission` | optional `keep_state` | the end of the engagement on the host: the watchers stop, the persistence goes, the traces are wiped, the binary goes and the verification follows |
| `wipe.deadman` | optional `minutes` (zero disarms the switch) | arms the dead man's switch: the implant ends itself when the operator has not checked in for that many minutes |
| `hunt.scan` | `indicators` (list of `id`, `kind`, `value`, `label`), optional `roots` (list of directories) | the indicators of the team that are on this host: one line per finding, plus the kinds that do not apply to the platform and the limits of the walk (it changes nothing; the report is attested) |
| `canary.plant` | `id`, `token`, optional `label` and `path` | plants a tripwire: a file with the token of the canary in it, in a place where nothing of the engagement belongs; the implant keeps the facts of it (the size, the time, the digest) next to the canary |
| `canary.check` | `canaries` (list of `id`) | looks at the tripwires of the host and says whether they are as they were planted: `intact`, `changed` or `missing` (the verdicts travel in the metadata of the answer; the report is attested) |
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
| `operators.list` | viewer | connected consoles: role, scopes, focus agent, idle time, queue depth |
| `task.get` | viewer | one task |
| `task.list` | viewer | tasks; optional filters: `id` (agent), `kind`, `state` |
| `audit.tail` | viewer | recent operator actions |
| `audit.verify` | operator | walk the chain of hashes of the ledger and say where it breaks |
| `chat.history` | viewer | recent chat |
| `schedule.list` | viewer | recurring tasks |
| `task.submit` | operator | queue a task |
| `task.bulk` | operator | queue one task on many agents: `agents` (list) and/or `filter` |
| `task.chain` | operator | queue a multi-stage task: `stages` is a list of `{kind, args}` |
| `alerts.list` | viewer | the alert rules the server watches the event stream with |
| `task.cancel` | operator | cancel a task (`TASK_CANCEL` if delivered) |
| `task.retry` | operator | run a finished task again as a new task |
| `events.list` | viewer | the recent events of the journal (`after`, `limit`) |
| `sessions.list` | viewer | the interactive sessions that are open, per agent |
| `engagement.wipe` | admin | clears the agents, the tasks and the schedules of the server |
| `forensics.survey` | viewer | queue the survey of the traces of a host: `id` |
| `forensics.report` | viewer | queue the surface of a host, as an analyst sees it: `id` |
| `forensics.verify` | viewer | queue the verification of a host after a wipe: `id` |
| `forensics.timeline` | viewer | queue the timeline of the engagement on a host: `id`, optional `journal` (`on`/`off`) |
| `forensics.wipe` | operator | queue the removal of the traces of a host: `id`, optional `what` (list of families), optional `dry_run` |
| `forensics.self` | admin | queue the self-destruction of the implant on a host: `id` |
| `forensics.decommission` | admin | queue the end of the engagement on a host: `id` |
| `forensics.deadman` | admin | arm the dead man's switch of a host: `id`, `minutes` (zero disarms it) |
| `hunt.list` | viewer | the catalogue of the indicators of the team; optional `query` (the value, the label, the note or the source) and `kind` |
| `hunt.add` | operator | put an indicator into the catalogue: `kind`, `value`, optional `label`, `note` and `source` |
| `hunt.remove` | operator | take an indicator out of the catalogue: `id` |
| `hunt.sweep` | operator | send the catalogue to the hosts: `id` for one host, or `agents`/`filter`/`all` for a group; optional `roots` (the directories the hunt may walk) and `indicators` (the indicators of the moment, which are not written into the catalogue) |
| `health.fleet` | viewer | the score of every host, worst first: the score, the grade, the parts of the score with their reasons and the notes |
| `case.list` | viewer | the cases of the engagement, newest first |
| `case.get` | viewer | one case with its evidence and its chain of custody: the events, their hashes and the place the chain breaks, if it breaks |
| `case.create` | operator | open a case: `title`, optional `notes`; the chain of custody starts with it |
| `case.add` | operator | put a piece of evidence into a case: `id`, `kind`, `ref`, optional `sha256`, `agent_id`, `task_id`, `size` and `note` |
| `case.close` | operator | close a case: `id`, optional `note`; the last hand of the chain says who closed it |
| `approval.list` | viewer | the queue of the team: the requests that wait for a decision and the ones that were decided; optional `state` (`pending`, `approved`, `denied` or `expired`) |
| `approval.get` | viewer | one request of the queue: who asked, who decided, when, and why |
| `approval.request` | operator | ask for an operation that waits for a second pair of eyes: `kind`, optional `agent` (the host), `reason` and `args` (the arguments of the operation) |
| `approval.approve` | operator | say yes: the operation is queued on the host right away; `id` and optional `note`. The operator who asked for the request cannot decide it |
| `approval.deny` | operator | say no: the operation is not queued; `id` and optional `note` |
| `canary.list` | viewer | the tripwires of the engagement: the label, the host, the state and the verdict of the last look; optional `agent` (one host) |
| `canary.get` | viewer | one tripwire, with the verdict of the last look. The token of the canary never travels to the console |
| `canary.plant` | operator | plant a tripwire on a host: `agent`, `label`, optional `note`; the secret of the file is written by the implant and stays there |
| `canary.check` | operator | ask the hosts whether their tripwires are as they were planted: `agent` for one host, or `agents`/`filter`/`all` for a group |
| `canary.remove` | operator | stop watching a tripwire: `id`; the file on the host stays where it is |
| `dossier.get` | viewer | the file of one host: the identity, the health with its reasons, the work that was run, the persistence, the tripwires, the requests and what is not known |
| `dossier.list` | viewer | the files of every host, the weakest first |
| `operator.otp.status` | viewer | who has a second factor, whether it is on, and how old the secret is. The secrets are never in the answer |
| `operator.otp.rotate` | operator | make a new secret for an operator: optional `operator` (default: yourself) and `issuer` (the name the phone shows). The secret is in the answer once and never again |
| `operator.otp.remove` | operator | take the second factor of an operator away: optional `operator` (default: yourself). The console of that operator works with the token alone from then on |
| `agents.sleep` | operator | change beacon cadence |
| `agents.policy` | operator | push the cadence and the sleep obfuscation to many agents |
| `agents.tag` | operator | label agents: `mode` is `add`, `remove` or `set` |
| `agents.kill` | operator | queue the exit task |
| `agents.exit` | operator | alias of `agents.kill` |
| `agents.panic` | admin | tell the selected beacons to exit and stop the server from feeding them: `agents` (list) and/or `filter`, or `all: true` |
| `chat.send` | operator | team message; `to` addresses one operator; an `@name` in the text is a mention |
| `chat.operators` | viewer | who is in the channel: the console, its role, its focus, its idleness and whether its presence has expired |
| `schedule.add` | operator | recurring task (5–86400 s) |
| `task.claim` | operator | take ownership of a task |
| `task.release` | operator | drop your claim |
| `task.assign` | operator | hand a task to a colleague (`task_id`, `to`); an empty `to` takes the assignment back |
| `operators.focus` | operator | announce the agent you are working on |
| `schedule.remove` | admin | remove a recurring task |
| `events.test` | admin | emit a synthetic event |
| `transport.get` | viewer | the route of one agent: the transport it speaks, the fallback order, the front domain |
| `transport.list` | viewer | the routes of every agent that has one |
| `transport.set` | operator | set the route of one agent: `agent`, `primary`, `fallback`, `front`, `inspect`, `http_path`, `ws_path` |
| `pivot.list` | viewer | open pivots: agent, mode, listener, byte counters; the reply carries the topology (nodes, edges, clients, connections, claims) |
| `pivot.open` | operator | open a SOCKS5 proxy or a port forward through an agent; optional `dns`, `loopback`, `claim`, `through`, `user`, `password` |
| `pivot.close` | operator | close a pivot |
| `pivot.claim` | viewer | the claims of the engagement and the pivots they hold |
| `pivot.release` | operator | release a claim: every pivot of it is torn down |
| `vpn.status` | viewer | tunnel state: listener, network, peer count |
| `vpn.peers` | viewer | tunnel peers and their addresses |
| `vpn.allocate` | operator | reserve a tunnel address for an agent |
| `vpn.routes` | viewer | the routing table of the tunnel: the networks behind the peers |
| `vpn.route` | operator | send the traffic of a network to a peer; `remove` forgets it |
| `vpn.ping` | operator | ask a peer of the tunnel whether it is there; the answer carries the round trip |
| `armory.list` | viewer | catalogue and installed extensions, with the module ABI of every entry |
| `armory.search` | viewer | the catalogue entries that match a `query` (the name, the description, the platform, the format, the capabilities) |
| `armory.needs` | viewer | what a module needs: the `caps` of the host, the argument schema, the output schema and the dependencies |
| `armory.versions` | viewer | the versions of a module the catalogue knows about |
| `armory.resolve` | viewer | the modules that have to be installed first, in the order they have to be installed |
| `armory.install` | operator | fetch, verify and install an extension (`name` may carry the version: `whoami@1.2.0`) |
| `armory.import` | operator | import a remote catalogue over https; every entry is verified before it is merged |
| `armory.remove` | admin | delete an installed extension |
| `armory.run` | operator | run an extension on an agent; the server refuses a module the agent cannot run (§7.2j) |
| `alias.list` | viewer | the runtime command namespace |
| `alias.run` | operator | run a named template on an agent |
| `alias.add` | operator | write a template into the shared namespace: `name`, `kind` or `extension`, `args`, `args_spec`, `description` |
| `alias.remove` | operator | take a template out of the shared namespace |
| `team.sync` | viewer | full state snapshot for a console that joins late |
| `team.handover` | viewer | the handover of the engagement: the inventory, the open work, the findings, the persistence, the sessions, the artefacts, the team and the last moves |
| `stager.generate` | admin | build a stage-0 one-liner (it carries the agent PSK); `mode` is `download`, `store` (the beacon comes from the file store of the server), `offline` (the beacon travels inside the stager) or `shim` (the digest check on its own) |
| `artifact.list` | viewer | the artifacts the server holds: name, size, digest |
| `artifact.get` | viewer | read a chunk of a stored artifact: `offset`, `limit` |
| `artifact.put` | operator | write a chunk into the store: `name`, `data` (bin), `offset`, `eof` |
| `artifact.remove` | operator | delete an artifact from the store |
| `artifact.push` | operator | push a stored artifact to an agent: `name`, `agent`, optional `path` |
| `creds.list` | viewer | the credential vault: the shape of the material, without the value |
| `creds.search` | viewer | the records of the vault that match a `query` |
| `creds.export` | operator | the material with its value; the server needs a vault key |
| `server.quiet` | admin | the maintenance window: `on` (true or false), `until` (a unix time); the beacons keep checking in and get nothing |
| `server.queue` | viewer | the state of the queue: the policy, the depth and the dead letter queue |
| `task.priority` | operator | say how urgent a task is: `task_id`, `priority`; the queue delivers the urgent one first |
| `workflow.list` | viewer | the catalogue of the named sequences of steps, and the last runs |
| `workflow.add` | operator | write a workflow: `name`, `steps`, `description`, `params`; a workflow with the same name replaces the old one |
| `workflow.remove` | operator | take a workflow out of the catalogue |
| `workflow.run` | operator | start a workflow: `name`, `params`; the run happens on the server and the answer is a run id |
| `workflow.status` | viewer | the state of one run: the steps, their answers and the report they wrote |
| `keys.rotate` | admin | replace the key the beacons authenticate with: `target` (`agent`), optional `psk` (a key the operator brings, at least 16 characters); the new key is in the answer, the previous one keeps working for the overlap |
| `tokens.rotate` | admin | replace the token of one operator: `operator`, optional `role`, `scopes` (the commands it may call), `expires_at` (a unix time) and optional `token` (generated when empty) |
| `tokens.list` | viewer | the operator tokens and their state: the role, the scopes, the expiry, the last use; never the token itself |

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

### 7.2f Capabilities, the artifact store and burning an engagement

Three things belong together, because they are all about what the server is
allowed to do with an agent.

**Capabilities.** A beacon says in its HELLO metadata which task kinds it
implements:

```
meta: {host, os, arch, user, pid, integ, ver, family, caps: ["shell", "ls", …]}
```

The server stores the list with the agent, shows it in `agents.list` and
`agents.info`, and refuses to queue a task the agent did not say it can run.
The operator learns that a host is out of scope *before* the task fails, and
the answer is the same everywhere: the exact kind that was asked for has to
be in the list. Aliases are listed too (`exec`, `cat`, `kill`), so a console
that writes "cat" is not told that the host cannot read a file.

An agent that says nothing — a beacon from before this extension — is asked
for everything. The server fails open for old implants and closed for new
ones, so an upgrade never breaks an engagement that is already running.

The list is a promise, and it is kept honest twice: the server refuses a
kind that is not on the list, and the consistency checker of the repository
compares the list with the task table of the implant
(`tools/check_consistency.py`, the `TASK_KINDS` check). The Go implant is
the small one — twenty-four kinds — and everything it cannot do (the
modules, the persistence, the other transports) is answered with an error
and not with a silence.  The senses of the desktop are on it as well:
the window table, the clipboard, the screen, the networks, the browsers,
the security software, the USB keys and the memory.

**The artifact store.** The team server keeps files: a payload, a
configuration, a tool. The operator drops a file into the store once
(`artifact.put`, in chunks, because the frames are bounded) and pushes it to
every host that needs it (`artifact.push`). The store is content addressed:
the blob is written under the SHA-256 of its contents, so two uploads of the
same file share one copy, and the digest travels with the entry so a console
can prove what it is holding.

`artifact.push` does not invent a new beacon command. It builds a chain of
ordinary `upload` tasks, one per chunk, and lets the chain machinery run
them: the beacon writes the chunks one after the other, and the last one
(`eof: true`) closes the file and answers with the SHA-256 of the whole
file. A push is therefore verifiable in exactly the same way as a manual
upload is, and a chunk that fails stops the chain instead of leaving a hole
in the file.

**Burning an engagement.** `agents.panic` is the end of an operation on the
target side. It queues the exit task for every selected agent and marks them
as burned, so the server refuses every further task for them: work that was
queued while the operator is still cleaning up never reaches the machine.

The targets follow the usual selection rule — `agents` and/or `filter` — with
one deliberate override: `all: true` reaches every agent the server knows,
including the ones that are asleep. The exit command is delivered on their
next check-in, so a beacon that sleeps for an hour still dies. The server
cannot push a frame to an agent that is not connected, so the exit travels as
a task; that is also why the exit is queued *before* the agent is marked,
because a burned agent refuses every task.

The console asks for the word "panic" before it does any of this, exactly
like `wipe` asks for "wipe".

### 7.2g The persistence manager

`persist` is not one scheduled task: it is a manager around a catalogue of
techniques, and the whole lifecycle travels over the wire.

**The catalogue.** Every technique has an id, a platform, a trigger
(`logon`, `boot`, `schedule`, `service`, `update`), a flag for whether it
needs administrator rights and a score for how quiet it is. The desktop
beacon knows seventeen Windows techniques (the `Run` keys, `Winlogon`,
`AppInit_DLLs`, the Image File Execution Options, a COM hijack, a print
monitor, a shell extension, a scheduled task, a task from an XML definition,
a service, a service DLL shim, the startup folder, a boot execute entry, a
permanent WMI event subscription and a DLL search-order hijack), fifteen on
Linux (a systemd system unit, a systemd user unit, a systemd timer, a
drop-in that hooks into a unit that already exists, a user crontab, an
`/etc/cron.d` entry, `rc.local`, an init script, a shell profile hook, a
shell alias wrapper, an environment source in `/etc/profile`, the
`ld_preload` technique, an XDG autostart entry, an `at` job and a kernel
module) and six on macOS (a launch agent, a launch
daemon, a login item, a shell rc hook, a crontab and an XDG autostart
entry). The phone has seven: the boot receiver, the sticky foreground
service, the alarm, a job scheduler entry, the re-launch after an update of
the application, an accessibility service and the enrolment as the device
owner of the phone.

Two of them are loud on purpose, and the report says so: the kernel module
runs inside the kernel of the host, and the device owner of a phone means
the phone is no longer a personal device.  The accessibility service of the
phone is visible to the user of the phone -- Android shows it in the
settings -- and the report says that too, because an operator who does not
know it is visible is an operator whose technique breaks in the field.

**The selection.** `method: "auto"` lets the manager pick: the quietest
technique that needs no administrator rights, and one that is already
installed before one that is not. A technique that needs administrator rights
is only offered when the implant actually has them.

**Idempotence.** Installing twice leaves exactly one entry. The manager
records what it installed in a state file next to the implant's own
configuration, in the canonical `upk` encoding, so the record survives a
restart of the implant and the operator can ask what is on the host weeks
later.

**Verification.** An entry that cannot be read back is not an entry. The
manager reads the registry value, the unit file, the crontab line or the
scheduled task again and reports the truth; `verify` is the default after an
install, and `persist.verify` does it for every entry at once.

**Migration.** `persist.migrate` installs the new technique and verifies it
*before* the old one is removed, so the coverage never has a gap.

**Stealth.** The implant copies itself into a plausible location and points
the entry at that copy, because an entry that points at a temporary
directory is worthless. The label the operator gives becomes the value name,
the service display name and the task name, so nothing in the host says
"umbra". The install is silent by default: the report says what was done,
not what the platform tool printed.

**What the server keeps.** Every persistence task reports the entries with
the result (`persist`, `persist_total`, `persist_broken` in the result
metadata). The server stores them with the agent, shows them in
`agents.list` and `agents.info`, filters the inventory with
`persisted=yes`, and raises `persist.updated` and `persist.broken` on the
event stream when an entry was removed behind the operator's back.

### 7.2h The posture engine

`evade.report` is not a check for a debugger: it is a classification of the
host the implant runs on, and the classification changes the behaviour of
the implant.

**The four axes.** The engine states four independent things about the
host: whether it runs on virtual hardware, whether a person can sit in
front of it, whether it carries the tools of a developer, and whether it is
a lab machine, a production machine or an analyst's sandbox. It also says
how sure it is (a confidence from 0 to 100) and why it thinks so (one line
per signal). The report never says "this is a sandbox" and stops there: it
says what it saw.

**The artefacts.** The classic names (`VMwareTools`, `VBoxService`,
`SbieDll`, `wireshark`, `procmon`, `x64dbg`, `ollydbg`) are not a
blacklist. Every artefact carries a class (`virtualisation`, `sandbox`,
`analyst-tool`, `capture`, `instrumentation`), a severity and a
confidence, and the operator decides what the sum of them means. A virtual
machine is a hint; a sandbox that injects itself into every process is
nearly a proof.

**What the posture changes.** The sleep interval is multiplied with the
factor the posture implies, the jitter is raised, the sleep stays
obfuscated, and — when the operator armed it — the implant stops answering
altogether on a host that looks like an analyst's sandbox. The defaults are
conservative: the implant adapts, but it never falls silent on its own.
`evade.posture` is where the operator arms the behaviour.

**The schedule.** `evade.profile` replaces the flat interval with a
profile of the day: busy while the office is open (a short interval,
because that is when the operator is waiting for an answer), quiet at
night, lazier at the weekend. The factors are percentages, and the engine
multiplies them with the factor of the posture.

**The shape of the traffic.** `evade.shape` chooses how the frames are
padded: `off` (the transport decides), `random` (the bucket drifts with
the traffic) or `fixed` (every request is a multiple of the same number).
It also shuffles the order of the operations inside a cycle, because a
host that always runs the tasks in the order the server sent them has a
signature of its own.

**The kill switch.** `evade.killswitch` arms the moment the implant stops
existing. The trigger is a file that appears, a registry value that
appears, a date and time, a number of hours of uptime, or a marker the
operator sends in a task. When the trigger fires, the implant takes its
persistence entries with it, wipes its own state and stops: the machine is
left the way it was found. The panic task of the server is the sixth
trigger, and it needs no arming: the `exit` task takes the persistence
entries with it as well, so the last word of the operator always leaves
the target clean.

**The hygiene.** `hygiene.memory` reports what holds a secret (the
pre-shared key, the session keys, the keystrokes, the credentials, the
module images) and how many buffers were wiped; the buffers live in guards
that wipe themselves, including on the path where the work failed.
`hygiene.process` is the other half: it copies the implant under a
plausible name, sets the name the process reports, moves the working
directory, removes the tool from the environment, and — on Windows —
rewrites the parent the process claims to have.

**What the server keeps.** Every evasion task reports the posture with the
result (`posture`, `posture_sleep_factor`, `posture_silent` in the result
metadata). The server stores the last report with the agent, shows it in
`agents.list` and `agents.info`, and raises `posture.updated` and
`killswitch.armed` on the event stream.

### 7.2i Identity, credentials and remote execution

The framework treats an identity as a record, not as a wall of text.  Every
piece of material the implant finds has a kind, a source, an account, a
target and a confidence, and the value itself only travels when the operator
asked for it.

**The collection.**  `creds` answers with the records in the `creds` metadata
field, one map per record:

| key | meaning |
|---|---|
| `kind` | `password`, `hash`, `ticket`, `token` or `key` |
| `source` | where it was found (`vault`, `dpapi`, `lsass`, `kerberos`, `ssh`, `file`) |
| `account` | the account it belongs to |
| `target` | the service or the host it belongs to |
| `confidence` | how sure the implant is, from 0 to 100 |
| `secret` | the material itself; the implant sends it only when the task carried `raw: true`, and the server takes it out of the record before it stores it |
| `length` | the length of the material, so the shape is known even when the value is not |
| `redacted` | true when the value was left out |
| `note` | how it was found |

The counters travel next to it: `creds_total` and `creds_counts`, a map of
the kinds and how many of them there are.

**The vault.**  The server keeps the records of every host in one vault.  The
value is encrypted at rest with the key of `vault_key` (or of the environment
variable `vault_key_env`, `UMBRA_VAULT_KEY` by default); without a key the
server keeps the digest and the shape and drops the value, because a secret
on the disk in the clear is worse than no secret at all.  The digest is
always kept, so two hosts that share a credential can be seen to share it
without the key.

The value never reaches the task record and never reaches the event stream:
the server takes the value out of the result before it stores the task, the
`task.result` event and the task record keep the redacted form, and the
`creds.collected` event says how many records were collected and how many
were dropped.  The value travels exactly one way -- from the implant to the
vault -- and it comes out of the vault only through `creds.export`.

| RPC | role | what it answers |
|---|---|---|
| `creds.list` | viewer | the records of the vault; optional `agent`, `kind`, `query`, `limit` |
| `creds.search` | viewer | the records that match a `query` over the account, the target and the note |
| `creds.export` | operator | the same records with the value, decrypted with the vault key |

**The token work.**  `token` has four modes:

| mode | what it does |
|---|---|
| `list` | the tokens of the host: the pid, the process, the account and the session; optional `session` narrows the list to one session |
| `impersonate` | become the account of `pid` for the next task; the implant gives the account back when the task is done |
| `become` | become the account of `pid` until the operator sends `restore` |
| `restore` | go back to the identity the implant started with |

The identity travels with the check-in (`impersonation` and
`impersonation_session`), so the inventory shows the truth.  The server
drops it when the session of the agent ends.

**The escalation.**  `privesc` reports every attempt on its own, with the
technique, the outcome (`worked`, `failed`, `unavailable`), the detail and
the side effects it caused.  The records travel in `escalations`, with
`escalations_total` next to them.

**The remote execution.**  The command runs on a remote host, driven from
the agent that holds the network path to it; the output comes back through
that same agent.  The task names the target and the protocol:

| kind | the protocol | how it runs there |
|---|---|---|
| `winrm.exec` | the remote shell of Windows | `winrs` |
| `wmi.exec` | the management instrumentation | `wmic /node:` writes the output to the administrative share, the pivot reads it back |
| `dcom.exec` | the scheduler over DCOM | a remote task is created, started and deleted |
| `smb.exec` | the service control manager over SMB | a remote service is created, started and deleted |
| `ldap.query` | the directory services client | `dsquery` against the controller the operator named |
| `ssh.exec` | the secure shell | `ssh` with the keys of the account the implant runs as |

Every one of them cleans up after itself: the remote file, the remote task
and the remote service are removed when the output has been read.

### 7.2j The module ABI

A module is a blob and a manifest.  The manifest is what makes the blob
safe to push: it says what the module is, what it needs from the host and
what it takes.  The manifest travels inside the task, as an upk map:

```
{
  "magic": "UMBRAMOD1",
  "abi": 1,
  "name": "whoami",
  "version": "1.2.0",
  "description": "the user the implant runs as",
  "os": "windows", "arch": "x64",
  "format": "coff",
  "digest": "sha256:…",
  "caps": ["shell"],
  "args": [{"name": "domain", "type": "string", "required": false}],
  "output": {"type": "text", "description": "the account name"}
}
```

| field | meaning |
|---|---|
| `magic` | opens the manifest: `UMBRAMOD1` |
| `abi` | the version of the dialect: `1` |
| `name`, `version` | the identity of the module |
| `description` | one line, for the operator |
| `os`, `arch` | the platform the module is for (empty = every one) |
| `format` | the loader: `coff`, `pe`, `shellcode`, `wasm` or `script` |
| `digest` | the digest of the blob: `sha256:…` |
| `caps` | the capabilities the host must have |
| `args` | the argument schema: `name`, `type` (`string`, `int`, `bool`, `bytes`), `required`, `default`, `help` |
| `output` | the output schema: `type` and `description` |

**The refusal rules.**  Both sides refuse, and they refuse the same things:

* a manifest without the magic, or with another ABI, is not read at all;
* a module that declares a capability the host does not have is refused —
  the server refuses to queue it, the implant refuses to run it;
* a required argument that is missing, or a value of the wrong kind,
  stops the module before it runs.

The server keeps the capability list of every agent (it arrives in the
handshake) and compares it with the `caps` of the manifest before it queues
the task.  An agent that advertises no capabilities at all is allowed
everything: the list did not exist in the first version of the framework.

**The loaders.**  The format of the manifest names the loader:

| format | the loader | the notes |
|---|---|---|
| `coff` | the COFF loader | the object is mapped into the memory of the implant |
| `pe` | the reflective loader | the image is mapped and its entry point is called |
| `shellcode` | the shellcode loader | the code is copied into an executable page; the module is position independent and receives a pointer to its context |
| `wasm` | the webassembly interpreter | a small subset: `i32`/`i64`, one memory, the arithmetic, the loads and the stores, `block`/`loop`/`if`/`br` |
| `script` | the script dialect | integers and strings, `var`, `if`, `while`, `log`, `call` and `exit` |

**The host API of the sandboxed loaders.**  A webassembly module and a
script may call three things, and two of them need a capability:

| call | needs | what it does |
|---|---|---|
| `log` | — | writes bytes to the answer of the module |
| `sha256` | `hash` | the SHA-256 of a buffer |
| `decrypt` | `crypto` | AES-256-GCM, with the key the operator gave as the `key` argument |

A module that calls `sha256` without declaring the `hash` capability is
refused by the interpreter itself: the capability is checked where the call
happens, not only at the door.

**The migration.**  `inject` with `mode: migrate` moves the work of the
implant into another process: into a process the implant starts itself
(`spawn`), into a process that already runs (`pid`), or out of its own
process (`out`).  The process that takes over inherits the environment of
the implant, so it reports the same agent id and reconnects with the same
key.  The identity is what the server knows the agent by, so the task
stream survives the move: the tasks the operator queued while the move was
happening are delivered to the new process.  The answer of the migration
travels before the implant leaves, and it carries `migrated`, `migrate_pid`,
`migrate_spawned`, `migrate_threads` and `migrate_agent`.

### 7.2k The reconnaissance profiles, the domain map and the suggestions

`recon` answers in two ways.  Without arguments it is what it always was:
the host facts, the environment findings and the domain edges in one
report.  With a `profile` it runs a **profile** — a named bundle of checks —
and answers with the findings of the bundle.

| profile | the checks it runs |
|---|---|
| `host` | users, groups, shares, listeners, scheduled tasks, services, software, browser data, ssh keys, shell history, recent files |
| `windows` | the host profile and the windows only checks (the WMI subscriptions) and the drivers |
| `linux` | the host profile and the kernel modules and the eBPF programs |
| `cloud` | the cloud CLI configuration |
| `container` | the container escape surface |
| `all` | every check there is |

The operator may name the checks one by one instead; the list wins over
the profile:

```json
{"kind": "recon", "args": {"checks": ["users", "cloud", "container"]}}
```

Every finding is a record:

| field | meaning |
|---|---|
| `kind` | what the finding is about: `user`, `group`, `share`, `listener`, `scheduled`, `service`, `software`, `browser`, `sshkey`, `history`, `recent`, `wmi`, `module`, `ebpf`, `cloud`, `container` |
| `name` | the name of the thing that was found |
| `detail` | what is worth knowing about it |
| `severity` | `info`, `low`, `medium` or `high` |
| `source` | where it was found: a path, a command or a socket |

Two rules hold everywhere: **a check never reports a secret** (the cloud
configuration is reported by name and by path, never by content) and **a
check never writes to the host**.

The findings travel with the answer of the task, under `recon`, and the
count travels under `recon_total`.  The operator may send them back to the
implant with `recon.suggest`, and the implant scores them and says what
could be tried next:

```json
{"kind": "recon.suggest", "args": {"findings": [{"kind": "cloud", "name": "/root/.aws/credentials", "severity": "high"}]}}
```

The answer of `recon.suggest` is a list of suggestions: a title, the reason
(`why`), a score between 0 and 100, the task that would try it (`kind` and
`args`) and the action in words.  The framework collects and scores; the
decision stays with the operator.

`domain.map` walks the graph of the domain and answers with the **paths**
from the identity the implant runs as to a target.  The target is the name
of a node of the graph; an empty target means the domain controller.  Every
path is the chain of the edges in the order they have to be walked:

```
CORP\admin@corp.example -[MemberOf]-> CORP\Domain Admins@corp.example -[AdminTo]-> dc01.corp.example
```

The paths travel under `domain_map` and their number under `domain_paths`.

### 7.2l The collaboration model

A team works on one engagement, and the framework has to keep the team
from fighting itself. Four things carry the collaboration.

**The presence expires.**  Every console touches its presence on every
call. A console that has been quiet for **90 seconds** is *silent*, and one
that has been quiet for **120 seconds** is *stale*: its socket may still be
open, but the team does not wait for it any more. `operators.list` and
`chat.operators` both carry `silent`, `stale` and `expires_at`.

**A claim has a lease.**  A claim is a promise that somebody is working on
a task. The promise is only as good as the presence behind it: when the
holder goes stale, the claim expires, the task becomes available again and
the team is told with a `task.claim_expired` event. The task itself carries
`claimed_by`, `claimed_at`, `claimed_age`, `claim_state` (`live` or
`expired`) and `claim_expires_at`.

**An assignment is a handover, not a claim.**  `task.assign` says who is
expected to work on a task; it does not stop anybody else from taking it.
The colleague sees the task in their inbox (`task.list` with `assigned`),
and the event `task.assigned` tells the team who passed what to whom.

**The chat belongs to the team.**  `chat.send` puts a line in the channel,
or in one colleague's ear (`to`). An `@name` in the text is a *mention*:
the message carries the names it mentions, so a console can highlight them.
The chat never reaches the implants: the event stream the agents read
carries tasks and results, never a word of the team.

**The namespace and the schedules are shared.**  The file store is on the
server, so the artefacts of the engagement belong to everybody. The
command namespace (`alias.add`, `alias.remove`), the schedules and the
alert rules are shared too: every entry says who wrote it, and the change
is an event (`alias.created`, `alias.removed`, `schedule.created`).

**The handover.**  `team.handover` produces the document a colleague reads
when the operator who ran the engagement goes home: the inventory, the open
work, the findings of the reconnaissance, the persistence, the open
sessions, the artefacts, the team and the last moves of the journal. The
console renders it as Markdown and adds the notes of its own notebook.

### 7.2m The workflow layer

A workflow is a **named, parameterised sequence of steps**. It is the text
form of an engagement phase: "sweep every web server, collect the
reconnaissance of the ones that answer, write the report". The steps are
data, so the team writes them without touching the server, and everybody
runs the same one.

The steps the server knows:

| step | what it does |
|---|---|
| `task` | runs one task on one agent and waits for the answer |
| `chain` | runs a multi-stage task on one agent |
| `wait` | waits for a number of seconds |
| `condition` | looks at the answer of the step before it; the rest of the workflow stops when it is not met |
| `report` | collects what the workflow found so far |

A parameter is written `{{name}}` in the text of a step:

```json
{
  "name": "sweep",
  "description": "sweep the web tier",
  "params": ["target", "kind"],
  "steps": [
    {"kind": "task", "agent": "{{target}}", "task_kind": "{{kind}}",
     "args": {"cmd": "systeminfo"}},
    {"kind": "wait", "seconds": 5},
    {"kind": "condition", "condition": "ok"},
    {"kind": "report", "title": "The sweep"}
  ]
}
```

**The run happens on the server.** `workflow.run` starts it and answers with
a run id; the run walks the steps in the background, writes what each step
did into the run, and ends in `done`, `failed` or `stopped`. The console
watches it with `workflow.status`, and the dashboard runs it from the
panel. A run that is interrupted still says what it did: every step is
written to the run before the next one starts.

A workflow whose parameters nobody gave is **refused**, not run with the
placeholder still in it: a workflow that runs the wrong thing is worse than
no workflow at all.

The catalogue lives in the state file of the server, so a workflow written
by one operator is there for the next one and for the next run of the
server.

### 7.2n The shapes of the console's JSON

Every command of the console answers either a table for a human or a JSON
document for a program. The JSON is the contract a pipeline writes
against, so the shapes are written down here.

`--json` answers one of these:

| command | the JSON is |
|---|---|
| `agents` | a list of the agent records (§7.2) |
| `tasks` | a list of the task records (§7.2) |
| `result` | the task record, with `out` as the text of the answer |
| `events` | `{"events": [...], "count": n}` — the journal, oldest first |
| `operators` | a list of the presence records (§7.2l) |
| `creds-list` | a list of the vault records, without the value |
| `creds-export` | a list of the vault records, with the value |
| `workflow list` | `{"workflows": [...], "count": n, "runs": [...]}` |
| `workflow run` | `{"run_id": "...", "run": {...}}` |
| `workflow status` | `{"run": {...}}` — the steps, their answers and the report |
| `rpc` | `{"ok": true, "data": {...}}` — the raw answer of the command |
| `queue` | `{"policy": {...}, "dead_letter": [...], "dead_letter_count": n, ...}` |
| `quiet` | `{"quiet": true}` — and `until` when the window has an end |
| `priority` | `{"task_id": "...", "priority": n}` |
| `db export` | the whole notebook (§5a of the operations manual) |

The rules that hold for all of them:

* the **keys are sorted**, so a diff of two answers is a diff of the
  engagement and not of the hash order;
* the **bytes are text**: `out` is the answer as a string, so a pipeline
  does not have to guess whether it is base64;
* the **numbers are numbers**, and a missing field is missing rather than
  zero;
* **nothing is a secret** unless the command is one that hands out
  secrets (`creds-export`): the value of a credential is only in the
  answer of that command, and the server checks the role before it
  answers it.

`umbra rpc` is the raw form of all of it: it sends one command and prints
the answer of the server, so a pipeline that needs a command the console
does not have a button for is still one line away.

### 7.2o The queue, the breakers and the traces

The queue of the server is the part an operator trusts last and needs
first, so its rules are written down here.

**The order of the work.** A task has a `priority` (an integer, higher goes
first, the default is `0`). The queue hands out the tasks of a host by
priority first and by age second, so the urgent work goes first and nothing
starves behind a flood of low priority work. `task.priority {task_id,
priority}` changes the priority of a task that has not run yet; the value is
clamped to the range -100..100.

**The limits.** Four numbers decide how much work a host and the server
may carry at a time:

| the key | what it limits | the default |
|---|---|---|
| `queue.max_in_flight_per_agent` | the tasks that may run on one host at a time | 4 |
| `queue.max_deliver_per_minute_per_agent` | the tasks one host receives per minute | 60 |
| `queue.max_deliver_per_second` | the tasks the whole server hands out per second | 200 |
| `queue.max_attempts` | the deliveries of one task before it is parked | 3 |

**The deadline and the timeout.** A task may carry a `deadline` (the moment
after which the work is not worth running) and a `timeout` (how long it may
run). `task.submit {id, kind, args, deadline, timeout}` takes both: the
deadline is an RFC 3339 time or a unix timestamp, the timeout is a number of
seconds. The server keeps the promise: a task that passes its deadline is
*cancelled* with the reason "the deadline passed" and the `task.expired`
event, and a task whose beacon does not answer within its timeout is failed
with the `task.timeout` event. The timeout travels to the implant inside the
arguments of the task, so the beacon stops the work itself instead of
letting it run past its time. The console says it with `umbra task <agent>
<kind> --deadline 2026-01-01T00:00:00Z --task-timeout 30`.

**The dead letter queue.** A task that failed and cannot be run again
without a decision is *parked*: its state becomes `dead`, the reason is in
the record and in the `task.dead` event, and the task is not delivered
again. The dead letter queue is what `server.queue` returns and what
`umbra queue --dead` prints.

**The circuit breaker.** A host that fails too many times in a row
(`queue.breaker_threshold`, five by default) has its breaker opened: the
server stops handing work to it. After the cooldown
(`queue.breaker_cooldown_s`, sixty seconds) exactly one probe goes through,
and the answer of the probe decides whether the host is given work again.
The breaker of a host is open while `server.queue` says so.

**The maintenance window.** `server.quiet {on, until}` stops the traffic:
the beacons keep checking in and get nothing, and nothing new is queued.
The window may end by itself at `until` (a unix time in seconds). The
change is an event and an audit line.

**The trace.** Every task carries a `trace_id`: sixteen hexadecimal
characters that the server gives it when the task is queued. The trace is
in the task record, in the `task.result` and `task.timeout` events (`trace`)
and in the audit trail, so one identifier follows the work from the
operator to the implant and back. `umbra tasks --trace <id>` filters the
history by it.

The counters of all of this are served in the Prometheus text format at
`/metrics` of the dashboard listener: the depth of the queue, the latency
histogram, the rate of the check-ins, the rate of the failures, the mix of
the transports and the bytes that moved.

### 7.2p The heartbeat

A check-in is expensive: it carries the whole inventory, and the beacon
may be minutes apart.  The heartbeat (`0x1D`) is the small frame a beacon
sends in between, and it answers one question: *is the host there, and how
busy is it?*

The body is a map:

| key | type | meaning |
|---|---|---|
| `v` | uint | the version of the heartbeat body (1 today) |
| `iver` | str | the version of the implant |
| `abi` | uint | the module ABI the implant speaks |
| `busy` | uint | how many tasks the implant was carrying |
| `up` | uint | how long the implant has been running, in seconds |

The server records it (the inventory shows `heartbeat`, `busy`,
`implant_version` and `abi`) and emits an `agent.heartbeat` event with
the same fields.  Nothing else happens: the heartbeat asks for no work and
carries no inventory, so a beacon may send as many of them as it likes.

**The one rule.**  A heartbeat is sent *after* the `TASK_BATCH` of its
cycle, never between the `CHECKIN` and the batch.  The server may rotate
the session keys right after the check-in (§6), and a frame that is sent
in between is sealed with the old keys — the server cannot read it, and
the session is over.

### 7.2q The credentials of the server

The server holds three kinds of credential: the agent PSK, the operator
tokens and the TLS key pair.  All three can be replaced while the server
runs, and the replacement never locks the fleet out.

**The overlap.**  A rotation does not throw the old credential away: it
keeps working for a while (thirty minutes by default).  The reason is
practical — a beacon may sleep for five minutes and a console may have
been closed since the night before.  The old credential is accepted until
the overlap is over, and then it is not.

**The agent PSK.**  `keys.rotate {target: "agent"}` replaces the key the
beacons authenticate with.  The answer holds the new key; the operator
writes it into the configuration of the beacons (or into the route the
server pushes) and the fleet catches up on its own.  Until then the old
key still works.

The new key is a **text**: the random bytes are hex encoded, so what the
operator copies is exactly the bytes the server checks.  The optional
`psk` argument replaces the key with one the operator brings — a key
management system that hands it out — instead of a generated one; it
must be at least 16 characters.

**The operator tokens.**  `tokens.rotate {operator, role, scopes,
expires_at}` replaces the token of one operator.  The scopes are the
commands the token may call and the expiry is a unix time in seconds; the
new token is in the answer and the old one keeps working for the
overlap.  An operator that does not exist yet is created, so a new
analyst can be given a token without restarting the server.

**The scopes.**  A token without scopes is judged by its role alone
(`admin`, `operator`, `viewer`), which is the historical behaviour.  A
token with scopes is judged by both: it may call what is in the list
**and** what its role allows, and nothing else.  The scopes narrow the
role; they never widen it.  The scope `*` means "no narrowing", so the
role alone decides.  A scope that names a command nobody has heard of is
refused when it is set, not silently ignored later.

The scopes are read from the keyring on every call, so narrowing the
scopes of a token takes effect immediately: a console that is already
connected loses the permission the moment it is taken away.

`tokens.list` shows the state of the tokens — the role, the scopes, the
expiry, the last use and when they were rotated — and never the tokens
themselves.

**The last use.**  Every token carries the moment it was last used: the
last time it authenticated, or the last time it made a call.  A call
that was refused does not count.  A token that has not been used in a
month is a token nobody needs.

**The TLS key pair.**  The certificate of the mutual TLS listener is read
from the files at every handshake, so a renewed certificate is in use
after the next connection.  A file that is half written is refused and
the certificate that is already in use stays.

### 7.2r The events the server pushes

The server pushes an event to the operators when something happens.  An
event is a frame of its own (`OP_EVENT`, 0x0E) with this shape:

| field | type | what it is |
|---|---|---|
| `kind` | str | the kind of the event (the table below) |
| `at` | uint | when it happened, in seconds since the epoch |
| `seq` | uint | the number of the event in the journal: a console that reconnects asks for the events after the last one it saw |
| `agent_id` | str | the host it is about, when it is about one |
| `task_id` | str | the task it is about, when it is about one |
| `from` | str | the console it comes from |
| `to` | str | the console it is directed to; empty means everybody |
| `data` | map | what the event carries, per kind |

The kinds the server emits:

| kind | what it says | data |
|---|---|---|
| `agent.new` | a host checked in for the first time | the inventory of the host |
| `agent.online` | a host is back | the inventory of the host |
| `agent.offline` | a host has been quiet for longer than its grace window | — |
| `agent.heartbeat` | the host is alive between two check-ins | `version`, `busy`, `abi` |
| `agent.policy` | the cadence of the host was changed | `sleep`, `jitter` |
| `agent.route` | the route of the host was changed | `primary`, `fallback`, `front`, `inspect` |
| `agent.tags` | the labels of the host were changed | `tags`, `mode` |
| `agent.panic` | the host was told to stop existing | `agent` |
| `agent.unpanic` | the host was told to carry on | `agent` |
| `alert` | a rule of the server matched | `rule`, `event`, `detail` |
| `alerts.changed` | the rules of the server were changed | `count` |
| `alias.created` | a command of the namespace was saved | `name`, `kind`, `by`, `created` |
| `alias.removed` | a command of the namespace was taken away | `name`, `removed` |
| `beacon.error` | the host reported a frame level failure | `code`, `msg` |
| `chain.started` | a chain of tasks began | `chain`, `kind`, `stages` |
| `chain.stage` | a stage of the chain finished | `chain`, `stage`, `kind` |
| `chain.done` | the chain finished | `chain`, `stages` |
| `chain.failed` | the chain failed | `chain`, `err` |
| `chat` | a line of the team chat | the message |
| `claim.expired` | the claim of a task expired: the console that held it stopped talking | — |
| `creds.collected` | a credential task came back | `collected`, `dropped` |
| `engagement.wiped` | the record of the engagement was cleared | `agents`, `tasks`, `schedules` |
| `keys.rotated` | a key was rotated | `target`, `overlap` |
| `killswitch.armed` | the kill switch was armed | `armed` |
| `operator.focus` | a console took the focus on a host | `operator`, `agent_id` |
| `operator.test` | a console asked the team whether it is there | `from`, `emitted` |
| `pivot.opened` | a tunnel was opened | `tunnel`, `mode`, `listen`, `host`, `port`, `claim`, `through`, `dns`, `path`, `pipe` |
| `pivot.closed` | a tunnel was closed | `tunnel` |
| `pivot.denied` | the proxy refused a target | `tunnel`, `host`, `port` |
| `pivot.error` | a target of the tunnel could not be reached | `tunnel`, `host`, `port`, `err` |
| `pivot.session_closed` | a session of a tunnel ended | `session` |
| `persist.updated` | the persistence of a host was changed | `entries`, `broken`, `methods` |
| `persist.broken` | an entry of a host is broken | `broken`, `total` |
| `posture.updated` | the implant changed its mind about the host | `label`, `confidence`, `sandbox`, `lab`, `silent`, `virtual` |
| `schedule.created` | a recurring task was created | `schedule_id`, `kind`, `every` |
| `schedule.fired` | a recurring task ran | `schedule_id`, `kind` |
| `schedule.skipped` | a recurring task did not run | `schedule_id`, `reason` |
| `schedule.removed` | a recurring task was taken away | `schedule_id`, `removed` |
| `task.queued` | a task is in the queue | `kind`, `args`, `trace` |
| `task.delivered` | a task was handed to the host | — |
| `task.result` | the answer of a task came back | the fields of the result |
| `task.output` | a part of the output of a task came back | the chunk |
| `task.assigned` | a task was given to somebody | — |
| `task.claimed` | an operator took a task | `by` |
| `task.released` | an operator let a task go | `by` |
| `task.cancelled` | a task was cancelled | `was` |
| `task.timeout` | a task was not answered in time | `kind`, `trace`, `waited` |
| `task.expired` | a task passed its deadline and was cancelled | `kind`, `trace`, `deadline` |
| `task.dead` | a task failed too often and was parked in the dead letter queue | `kind`, `trace`, `attempts`, `reason` |
| `token.rotated` | an operator token was rotated | `target`, `role` |
| `workflow.created` | a workflow was saved | `workflow`, `steps` |
| `workflow.started` | a workflow began | `workflow`, `run` |
| `workflow.step` | a step of a workflow finished | `workflow`, `run`, `step`, `kind`, `state`, `ok` |
| `workflow.finished` | a workflow ended | `workflow`, `run`, `state` |
| `workflow.removed` | a workflow was taken away | `workflow`, `removed` |

The kinds are a promise in both directions: the console may rely on the
name of an event, and the server may not invent one without saying so in
this document.  The consistency checker of the repository compares the
table with the kinds the server emits (`tools/check_consistency.py`, the
`EVENTS` check), so an event that is not written down is a build failure.

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

* **SOCKS5** (`pivot.open {id, mode:"socks"}`) — RFC 1928, `CONNECT` only,
  bound to loopback by default. The client picks the target. When the
  operator configured `user` and `password`, the proxy asks for them with
  the username and password method (RFC 1929); without them the proxy is
  open to everybody who can reach its listener.
* **port forward** (`pivot.open {id, mode:"forward", host, port}`) — every
  accepted connection is relayed to one fixed `host:port`.

**The reach.** `pivot.list` answers with the tunnels *and* with the
topology of the engagement: the agents (`nodes`), the pivots between them
(`edges`), the clients of the proxy (`clients`) and the log of the last
connections (`connections`).

| key | meaning |
|---|---|
| `nodes[].agent_id` | the agent the node stands for |
| `nodes[].role` | `pivot` when the agent holds a tunnel, `host` otherwise |
| `nodes[].transport` | the transport the agent speaks |
| `nodes[].online` | the agent answered recently |
| `edges[].agent_id` | the agent the pivot runs on |
| `edges[].through` | the agent this pivot is chained through |
| `edges[].streams` | the streams that are open right now |
| `edges[].bytes_up` / `bytes_down` | the bytes that moved through it |
| `edges[].last_active` | when it moved bytes the last time (unix seconds) |
| `edges[].dns` | `remote` (the target resolves the name) or `local` |
| `edges[].path` | the hops the server walked to reach the target |
| `edges[].claim` | the name the operator gave to this pivot |
| `clients[].address` | the client of the proxy |
| `clients[].connections` | how many connections it made |
| `connections[].target` | where it went |
| `connections[].state` | `closed`, `denied` or `refused` |

The options of `pivot.open` decide how the pivot behaves:

| option | meaning |
|---|---|
| `dns` | `remote` (the default) hands the name to the target, so the name of an internal host never leaves the network; `local` resolves it on the server |
| `loopback` | forces the listener onto the loopback of the server, whatever the operator asked for |
| `claim` | names the pivot; `pivot.release` tears every pivot of the claim down |
| `through` | the agent this pivot is chained through; the topology shows the chain |
| `path` | the chain of hops after the first agent; the server resolves it (§7.3b) |
| `user` / `password` | the credentials the SOCKS5 proxy asks for |

A pivot outlives the session it was opened with: the listener stays bound
and the session of the agent is taken again when the next connection
arrives, so a forward survives the re-connect of its agent. The server
also keeps a deny list (`pivot_deny` in the configuration): a target on
the list is refused with the SOCKS5 "not allowed" answer and the refusal
is written in the connection log.

### 7.3c The route of an agent

The route tells a beacon how to reach the team server.  The operator knows
the network of the target, so the operator writes the route down and the
server pushes it with the task batch.

```
route = {primary: "ws", fallback: ["tcp"], front: "cdn.example.com",
         inspect: true, http_path: "", ws_path: "/api/v1/beacon"}
```

| key | meaning |
|---|---|
| `primary` | the transport the beacon uses first: `tcp`, `http`, `dns` or `ws` |
| `fallback` | the order the beacon tries when the primary fails |
| `front` | the domain the beacon puts in the `Host` header |
| `inspect` | the proxy in front of the beacon reads the traffic |
| `http_path` / `ws_path` | the routes of the HTTP and WebSocket transports |

The route is per agent: `transport.set` writes it, `transport.get` and
`transport.list` read it, and it travels with the `TASK_BATCH` frame.  A
beacon that cannot speak the named transport keeps the one it has, and the
next one of the fallback order is tried.

### 7.3a The peer link

The peer link is a link between two beacons, or between a beacon and the
server.  It is the road a *chain* of pivots runs on: the server asks the
first agent for a stream to the next one and then speaks the peer protocol
on that stream, so the traffic of a chained pivot does not have to travel
through the team server twice.

The handshake of the peer link is **not** the umbra handshake: the peer link
runs over a byte stream that may be a tunnel, a pipe or a socket, so its
messages are length prefixed upk maps and nothing else.

```
peer hello   4-byte length | {id, pub, nonce, mac}
peer ack     4-byte length | {id, pub, nonce, mac}
then the ordinary umbra frames
```

| field | meaning |
|---|---|
| `id` | the identity of the sender |
| `pub` | the 32-byte X25519 public key of the sender |
| `nonce` | the 16-byte nonce of the sender |
| `mac` | the tag that proves the sender owns the key |

The two tags are the whole authentication of the link:

```
hello.mac = HMAC(psk, "umbra/v1/p2p/hello" | hello.id | hello.pub | hello.nonce)
ack.mac   = HMAC(psk, "umbra/v1/p2p/ack"   | hello.id | hello.pub | hello.nonce
                                     | ack.id   | ack.pub   | ack.nonce)
```

The key is the **agent PSK**: the beacons of one team already hold it, so
no new key has to be distributed. The hello tag binds the identity to the
key and the nonce of the sender, so a hello cannot be replayed into another
link. The answer tag covers *both* hellos, so the transcript cannot be
rearranged and an answer cannot be replayed into another link either.

After the handshake both sides derive the same session keys:

```
mixed = HMAC(psk, x25519_shared)
prk, km = HKDF(mixed, salt = sha256("umbra/v1/session" | client_nonce | server_nonce))
```

The initiator is the client of the session (`is_server = false`), the
responder is the server of it (`is_server = true`). The frames that follow
are the ordinary umbra frames, so a pivot stream is asked for with
`TUNNEL_OPEN` and the bytes travel in `TUNNEL_DATA` — exactly like on a
callback session. The link rekeys on its own: when either direction carried
`REKEY_AFTER` frames, the side that noticed sends a `REKEY {seed}` frame
(sealed with the *old* keys) and both ends derive the new keys from the
seed.

A beacon that serves the peer link binds a listener and tells the server
where it waits: the address travels in the handshake metadata as `meta.p2p`
(`"host:port"`). The server resolves the chain of a pivot from it.

### 7.3b Chained pivots

`pivot.open` takes an optional `path`: the chain of hops *after* the agent
the pivot belongs to. The operator names the far end; the server resolves
the road.

```
pivot.open {id: "agent-a", mode: "socks", path: ["agent-b", "agent-c"]}
```

The server walks the path hop by hop: for every hop it asks the previous
agent for a stream to the address that agent reported (`meta.p2p`), speaks
the peer handshake on that stream (§7.3a) and continues with the peer link
as the new opener. The last hop opens the stream to the target.

When the peer link of a hop cannot be established, the server **falls back
to itself**: it asks that agent for a callback session and continues the
chain through the server. The pivot keeps working; only the road changes,
and the fallback is written in the log.

The topology shows the chain: `edges[].path` lists the hops the server
walked, and the dashboard draws them as a line from one agent to the next.

**The layer-3 tunnel** (`vpn`) is a transport of its own: a UDP socket with a
Noise-IK-style handshake (`INIT`/`RESP`), AES-256-GCM data packets and a
64-packet replay window. It exists because it keeps working when the
beaconing channel does not: the console and the beacon exchange IPv4 packets
over it, and the server routes them by tunnel address (`10.77.0.0/24` by
default). The handshake MAC is keyed with a secret both sides already hold
(the agent PSK or an operator token), so no additional key distribution is
needed.

The tag of the handshake is the first sixteen bytes of the HMAC over the
transcript; the packet carries sixteen bytes, so the tag of the two ends has
to be sixteen bytes long as well.

**The routing table.** A peer may be the gateway of a whole network: the
operator names the network and the peer (`vpn.route`), and the server sends
the packets of that network to the peer, which forwards them. The longest
prefix wins, so a small network inside a large one is reached the way the
operator meant it. Every route carries its own counters: the packets and the
bytes that went through it.

**The ping.** The question of the operator travels through the tunnel like a
data packet: it is sealed with the keys of the session, so only the peer can
read it and only the server can tell that the answer is the answer. The
answer carries the timestamp of the question, so the round trip is measured
by the server and not guessed. The kinds of the control packets are `PING`
(`0x04`) and `PONG` (`0x05`); the payload is the kind, a nonce of eight
bytes and the timestamp of the question.

**The peer behind another peer.** A peer that can only be reached through
another agent joins the relay of that agent instead of the server
(`vpn` with `action=relay`). The relay hands the datagrams to the server
and back, so the keys of the session stay between the peer and the server:
the relay sees nothing but ciphertext.

### 7.4 Traffic shaping

A `PADDING` frame (`0x1E`) carries random bytes and is ignored by the
receiver. It exists so a transport can pad its bodies to a coarse size bucket
(`http_pad`) without changing the frame format: the payload size of a frame
stays hidden behind the bucket, and the padding is part of the AEAD, so it
cannot be forged.

The `evade.shape` task takes this further: it chooses the bucket
(`off`, `random` or `fixed`) and may shuffle the order of the operations
inside a cycle, so the traffic of one host does not have a machine
signature of its own.

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

The window the interval is drawn from is chosen once per cycle and moves
from cycle to cycle, so the gaps arrive in clusters instead of spreading
evenly over the whole range; the value inside the window is stable for the
whole cycle, so two timers in the same cycle do not drift apart.

On top of that the `evade.profile` task replaces the flat interval with a
profile of the day (busy during the working hours, quiet at night, lazier
at the weekend), and the posture of the host stretches the result: a
virtual machine or a lab machine sleeps longer than a production server.

The obfuscation can be switched off with `UMBRA_SLEEP_OBFUSCATE=0` when a
fixed interval matters more than the traffic pattern (a lab test that needs
a predictable check-in, for instance).


### 7.2s The guide of the host

The `host.guide` task answers a question an operator asks before a
weekend: what will the operating system do to the implant while nobody
is looking?

On a **desktop** the answer is what the operating system can tell: how
long the machine has been idle (Windows answers with the time of the
last input), where the power comes from (the mains or the battery), and
how many persistence entries are installed.  A platform that cannot tell
says so -- "this platform cannot tell how long the machine has been
idle" -- and nothing changes.  A desktop has no vendor rules: what stops
the implant there is the deletion of its file and the replacement of its
binary.

On a **phone** the answer is the rules of the manufacturer.  A phone that
runs an ordinary application is killed by the system when the system
feels like it, and on the skins of Xiaomi a boot receiver alone is not
enough: the application has to be on the autostart list, it has to be
exempt from the battery optimisation, it has to be allowed to show its
notification, and it has to stay out of the rare standby bucket.  The
task answers with the state of each of those and with the steps that are
still open:

| step | what it asks | how it is checked |
|---|---|---|
| `battery` | the exemption from the battery optimisation | `PowerManager.isIgnoringBatteryOptimizations` |
| `autostart` | the autostart list of Xiaomi | not readable by an application: the state is "unknown" and the operator looks at the screen |
| `notifications` | the permission of the notification | `NotificationManager.areNotificationsEnabled` |
| `standby` | the standby bucket | `PowerManager.getStandbyBucket` |

The implant cannot take these permissions by itself: on those phones the
user of the phone has to press the button.  `host.guide` with
`action: "show"` and a `step` opens the screen that shows it -- and
because the phone blocks an application that opens a screen from the
background, the step also travels as a notification the user can tap.
The report says which of the two happened.

The state of the phone changes the traffic as well: a phone whose screen
is off stretches its check-in, because the screen of a phone is the
closest thing it has to the presence of a person in front of it.


### 7.2t The window of the phone

An application on a phone cannot see what the user is looking at.  The one
permission that can is the **accessibility service**, and the one that comes
with it is that the user of the phone sees it: it is listed in the settings
of Android, with the name of the application, and Android shows a
notification while it runs.  The technique is in the catalogue of the
persistence (`accessibility`) and the report of the persistence says that it
is visible.

With the service enabled the phone answers six tasks:

| kind | what it does | what the operator gets |
|---|---|---|
| `ui.screen` | walks the tree of the window in the foreground | the application in the foreground and the visible text of its window |
| `ui.events` | the log of the windows that changed | the package, the window and the text that came with the event |
| `ui.tap` | clicks the node that carries the needle | the node that was pressed and whether the window accepted it |
| `ui.text` | writes into the editable node that carries the needle | the field that was written into and whether the window accepted it |
| `ui.scroll` | scrolls the window | whether the window accepted it |
| `ui.global` | the system keys (back, home, recents, notifications, power, volume, screenshot) | whether the phone accepted it |

The answers are the truth of the phone: a task that could not be done says
so, and a task that was done says what was done.  The service is not asked
for anything it cannot do, and the operator is told in the guide of the
host (`host.guide`, step `accessibility`) whether it is on.

The work happens on the main thread of the phone, because that is where the
window lives; the task waits on its own thread and the answer travels back
through the bridge (`Ui.kt`).  A task that arrives while the service is off
fails with a clear message instead of pretending that nothing happened.

### 7.2u The senses of the phone

A phone is not a workstation, and the implant of a phone is not the
implant of a workstation.  It has a radio, an address book, a camera, a
microphone and a screen that belongs to the platform.  The seventeen tasks
of this section are the ones that only a phone can answer, and every one
of them reports the permission it needed:

| family | tasks | what the platform insists on |
|---|---|---|
| the place | `gps.locate`, `wifi.dump`, `bluetooth.scan` | the location permission, the wifi state, the bluetooth scan |
| the people and the words | `contacts.dump`, `sms.dump`, `call.logs` | the contacts, the messages, the call log |
| the watchers | `sms.watch`, `clipboard.sniff` | the message broadcast, the clipboard of the focused application |
| the ears and the eyes | `media.mic`, `media.camera` | the microphone, the camera, and a foreground service that says so |
| the screen | `live.screen`, `ui.stream` | the user has to press the button of the system dialog |
| the false screen | `phish.overlay` | the permission to draw over the other applications |
| the laboratory | `emulator.detect` | nothing: it only reads |
| the end | `app.dump`, `anti.forensic`, `evade.suicide` | root for the databases of the other applications |

**The watchers.**  A collector answers a question; a watcher waits for the
phone to have something to say.  The queue of the watchers lives in the
state of the implant, so it survives a reboot, and the phone asks the
beacon to connect again the moment something arrives: the operator reads
the code of the second factor while the person is still waiting for it.
The operator polls the queue with the `poll` action, and the queue of one
watcher does not empty the queue of the other.

**The screen.**  The capture of the screen is the one capability the
platform never gives away: the user of the phone has to press the button
of the system dialog, every time the capture starts.  The implant opens
that dialog, and the answer says that the user has to press it.  The
pictures travel as partial results (§7.2c), one frame at a time, so the
stream of a screen does not need a frame of the protocol to hold it.

**The false screen.**  The overlay waits for the application the operator
named and draws a form over it; what the user types travels to the queue
of the watchers.  The overlay needs the permission to draw over the other
applications, it is on the screen of the phone while it waits, and the
operator may dismiss it at any moment.

**The laboratory.**  The verdict of `emulator.detect` is a score with the
reasons behind it: the strings of the build, the properties of the
system, the files of the machine, the sensors (an emulator has no
accelerometer, or one that never moves), the battery (a plug that never
runs down) and the radio (the number of the simulator is the same on every
installation).

**The end.**  `anti.forensic` removes the material of the engagement and
keeps the implant alive.  `evade.suicide` ends everything: the watchers,
the capture of the screen, the persistence entries, the state and the
service -- and the application itself when the platform lets it, which is
only when the implant is the owner of the profile of the phone.

### 7.2v The senses of the desktop

A workstation is not a phone with a bigger screen: it has a window table, a
clipboard that belongs to the session, a screen that moves, a radio that
remembers the networks it was given, browsers that keep the passwords of
the user, security software that watches the machine and USB keys that
carry the identity of the person.  The eight tasks of this section are the
ones that answer for them:

| family | task | what the operator gets |
|---|---|---|
| the window table | `window.list` | one line per window: the process, the class, the title, and whether the window is on the screen |
| the clipboard | `clipboard.watch` | what the user copied, queued in a file that survives a reboot |
| the screen in motion | `screen.stream` | the pictures, one frame at a time, as partial results |
| the radio | `wifi.profiles` | the saved networks, and the keys of the ones the user may read |
| the browsers | `browser.creds` | the accounts and the services, and the material when `raw` is asked for |
| the watchmen | `av.survey` | the products of the security centre, and the services that watch the machine |
| the keys | `usb.history` | the history of the USB devices, and the ones that are attached now |
| the memory | `proc.memory` | the dump of a process, and the strings of it that look like a credential |

**One name, three platforms.**  The implant answers with the tool of the
platform, and where the platform has an API that says more than its tools
do, the API is used directly:

| family | Windows | macOS | Linux |
|---|---|---|---|
| the window table | `EnumWindows` (the API of the platform, through the FFI) | the accessibility of the system (`osascript`) | `wmctrl`, and `xdotool` when it is not there |
| the clipboard | the API of the platform | `pbpaste` | `xclip`, `wl-paste`, `xsel` |
| the screen | the API of the platform | `screencapture` | `import`, `scrot`, `maim` |
| the radio | `netsh wlan show profiles` | `networksetup` | `nmcli` |
| the browsers | the databases of the profile, and the blobs of DPAPI | the databases of the profile | the databases of the profile |
| the watchmen | the security centre (`SecurityCenter2`), `sc query` | the process table | the process table, `aa-status` |
| the keys | the registry (`USBSTOR`), `Get-PnpDevice` | `ioreg` | `/sys/bus/usb/devices` |
| the memory | `MiniDumpWriteDump` | `vmmap` | `/proc/<pid>/maps` and `/proc/<pid>/mem` |

**The truth of the machine.**  Every family says what it could not read.  A
wireless key that belongs to another user of the machine is not readable,
a browser that is locked is not readable, the memory of a process of
another user is not readable, and the report says so instead of pretending
that the machine has nothing to give.  The `raw` flag of `browser.creds`
is the only thing that puts a secret on the wire, and the secret of a
record is left out of the answer when the operator did not ask for it.

**The clipboard.**  The watcher of the desktop works like the watcher of
the phone: `start` begins it, `poll` takes what was copied since the last
poll, `stop` ends it.  The queue lives in the state of the implant
(`~/.umbra/watch.state`), so it survives a reboot, and the queue of one
watcher does not empty the queue of the other.

**The screen.**  The pictures of `screen.stream` travel as partial results
(§7.2c): the task stays open while the frames travel, and the final result
closes it.  The stream is bounded (thirty frames, thirty pictures a
second), because a screen that never stops is a channel that never stops.

**The phone answers these names too.**  The Android implant knows the eight
families and answers with the truth of the phone: the windows the
accessibility service saw (`window.list`), the watcher of the clipboard
(`clipboard.watch`), the pictures of the media projection (`screen.stream`),
the security software that is installed (`av.survey`), the USB devices
(`usb.history`), and the memory of a process when the phone is rooted
(`proc.memory`).  The two families the platform keeps to itself are refused
with the reason: the saved networks of the phone (`wifi.profiles`) and the
databases of its browsers (`browser.creds`).

### 7.2w The zero-footprint wipe

Every implant leaves something behind: a file in the state directory, a line
in the history of the shell, a prefetch entry, the name of the binary in
the table of the processes.  Some of it belongs to the implant and some of
it belongs to the platform, and the difference matters: the artefacts of
the implant go away with the implant, and the artefacts of the platform
need the tools of the platform.

The eight tasks of this section answer seven questions and refuse to answer
the eighth one:

| question | task | what the operator gets |
|---|---|---|
| what is here? | `wipe.survey` | every artefact, its size and the reason it is a trace; it changes nothing |
| take it away | `wipe.run` | what was removed, what was scrubbed, what could not be touched, and what is still there |
| is it gone? | `wipe.verify` | what is left, and what no process of a user can reach |
| what would an analyst find? | `forensics.report` | the artefacts, the persistence entries, the process and the journal |
| what did the implant do here? | `forensics.timeline` | the timeline of the engagement, and the switch of the journal |
| let the implant go | `wipe.self` | the state, the journal and the binary of the implant |
| end the engagement | `decommission` | all of it, in the order that leaves nothing behind |
| what if nobody comes back? | `wipe.deadman` | the window of the silence after which the implant ends itself |

**Three rules hold everywhere.**

1. *A wipe never destroys the material of the user that the implant did not
   create.*  The history of the shell is **scrubbed** of the lines that
   mention the implant; the rest of the file stays.  The trash of the user
   and the list of the recent files are cleaned the same way.
2. *The operator chooses the family, and the report says which family was
   touched.*  The families are `state`, `history`, `recent`, `cache`, `log`
   and `system`, or `all`.  A wipe that removes everything and a wipe that
   removes the history are not the same thing.
3. *A limit is reported as a limit.*  The MFT and the USN journal of
   Windows, the `utmp`/`wtmp`/`btmp` of a POSIX host, the free blocks of
   the disk, the swap of the machine, the buffer of the system log, the
   statistics of the use and the backups of the cloud are not reachable
   from a process of a user.  The report names them and says why, instead
   of pretending that the disk is clean.

**The families, per platform.**

| family | Windows | macOS | Linux | Android |
|---|---|---|---|---|
| `state` | the state of the implant, the journal | the same | the same | the state of the application, the journal |
| `history` | the lines of the consoles that name the implant | the shells of the user | the shells of the user | the clipboard of the system |
| `recent` | the shortcuts of the recent files | the recent documents | the recent files and the trash | the entry of the application in the recents |
| `cache` | the temporary directory | the caches of the user | the cache of the implant | the cache of the application |
| `log` | the prefetch, the event log, the unified log | the unified log | the journal of the system | the buffer of the system log (a limit) |
| `system` | the MFT, the USN journal, the amcache (limits) | the log of the system (a limit) | `utmp`, `wtmp`, `btmp`, the swap, the free blocks (limits) | the statistics of the use, the record of the installer, the backups (limits) |

**The order of the end.**  `decommission` is not a list of deletions but a
sequence: the watchers stop first (they would write into the state that is
about to go), then the persistence entries are taken away (a start-up entry
that points at a missing binary is a trace worse than the entry itself),
then the traces are wiped, then the binary goes, and the verification
closes the report.  The Rust and the Go implants delete their own binary
with a child that waits for the process to end; the Windows implant hands
the deletion to the session manager, because the file of a running process
cannot be removed while it runs.

**The journal.**  The implant can keep a journal of what it did on the host
(the tasks it ran, the handshakes it made).  It is **off until the
operator turns it on** (`forensics.timeline` with `journal: "on"`), because
an implant that writes a record of its own actions carries evidence that
it does not need to carry.  While it is on it lives in the state directory
(`~/.umbra/journal.state` on the desktop, the private directory of the
application on the phone), and the wipe removes it like any other artefact.

**The server guards the end.**  `forensics.self` and `forensics.decommission`
are admin commands, and the server refuses those two task kinds to every
role but the admin **whichever path they travel**: the dedicated command,
`task.submit`, `task.bulk`, `task.chain`, `schedule.add` and `alias.run`
are one door.  A task that burns a host does not become less destructive
because it was queued in another way.

**The attestation of a report.**  Every report of the wipe carries an
`attest` field: the HMAC-SHA256 of the report, under the key of the agent
and the label `umbra/w1/attest`.  The server checks the signature and
records `attested: true` in the metadata of the task, so the operator
keeps a proof of what the implant removed even when the host is gone.  The
comparison is constant time and the label keeps a signature over a report
from being a signature over a frame.  The label and one report of the
contract live in `contracts/vectors.json`, and the four implementations
prove against it that they produce the same bytes.

**The dead man's switch.**  An implant that outlives its engagement is an
implant nobody is watching.  `wipe.deadman` arms a window: every check-in
of the operator renews it, and when the team goes quiet for longer than
the window the implant wipes its traces, takes its persistence with it
and leaves.  The state of the switch lives in the state directory of the
implant (`~/.umbra/deadman.state`), so a reboot does not disarm it, and
arming it is an admin action: it is the end of an engagement waiting to
happen.

**A group of hosts.**  The eight commands name one host with `id`, or a
group with `agents` (a list) or with a filter (`state`, `os`, `tag`,
...).  A command with neither is refused: the end of an engagement must
never be a guess.

**The console.**  The operator talks to the eight commands with
`umbra survey`, `umbra forensics`, `umbra scrub`, `umbra verify`,
`umbra journal`, `umbra vanish`, `umbra decommission` and `umbra deadman`,
and with `umbra cleanup` for a group of hosts: the console walks the
group host by host -- the survey, the wipe and the verification -- and
prints the host that did not answer instead of hiding it.

**The machine of the operator.**  The end of an engagement also cleans
the machine the operator works on: `umbra clean` removes the notebook
of the console and the files of its state directory, and scrubs the
lines of the shell history that name the engagement while the rest of
the history stays.  The ledger of the server is not a trace of the
engagement: it is the record of it, and it is kept.

### 7.2x The hunt, the health and the evidence files

Three subsystems that look at the engagement from the outside.  They
share one rule: they describe, they never act on their own.

**The catalogue of the indicators.**  `hunt.add` puts an indicator into
the catalogue of the team: a `kind` (`hash`, `path`, `mutex`,
`registry`, `certificate`, `process` or `service`), the `value` itself,
and the words the team uses for it (`label`, `note`, `source`).  The
catalogue is shared and it lives next to the state file of the server,
so an indicator that was found once is still there for the next
engagement.  `hunt.list` searches it over the value, the label, the
note and the source -- the operator remembers the ticket and not the
hash -- and `hunt.remove` takes an indicator out of it.

**The sweep.**  `hunt.sweep` sends the catalogue to the hosts: one host
with `id`, or a group with `agents`/`filter`/`all`.  The task is
`hunt.scan`, and its arguments are the `indicators` (a list of `id`,
`kind`, `value` and `label`) and the optional `roots` -- the
directories the hunt may walk.  Without `roots` the implant walks the
home of the user, the temporary directory and its working directory;
the whole of the disk is a decision the operator has to write down.

The answer carries the findings, the `hunt_skipped` (the kinds that do
not apply to that platform) and the `hunt_limits` (the bounds the walk
reached).  The hunt only reads: no task hunts and writes in the same
breath, because an implant that removed a file while it hunted would
destroy the evidence it is looking for.

**The score of the fleet.**  `health.fleet` scores every host out of a
hundred and sorts them worst first.  The score is made of five parts --
reachability (30), cadence (15), capacity (20), persistence (20) and
posture (15) -- and every part travels with the sentence that explains
it.  The grades are `healthy` (90 and above), `fair` (70), `poor` (40)
and `lost`.  Two rules keep the scale honest: a host that has never
answered scores nothing, because nothing about it is known; and a host
that reports itself as a laboratory machine gets the grade `suspect` and
a score of at most 24, however well it works.

**The evidence files.**  `case.create` opens a case, `case.add` puts a
piece of evidence into it (with its `sha256`, the `agent_id` and the
`task_id` it came from), `case.get` shows it with its chain of
custody, `case.list` shows the cases, and `case.close` closes one.
Every hand the evidence passes through is an event with the hash of the
event before it, so an event that is edited or removed after the fact
breaks the chain, and the answer names the event where it breaks.  The
cases live next to the state file and they survive both the restart of
the server and the wipe of the engagement.

**The console.**  `umbra hunt list|add|remove|sweep`, `umbra health`,
`umbra case list|show|create|add|close`,
`umbra approval list|show|request|approve|deny`,
`umbra canary list|show|plant|check|remove`,
`umbra dossier list|show` and
`umbra otp status|rotate|remove|code`.

**The two-person rule.**  `approval.request` puts an operation into the
queue of the team: the kind of the operation, the host it is about,
the reason and the arguments of the work.  The request is not a task;
it is the promise that a task will be queued once somebody else says
yes.  `approval.list` and `approval.get` show the queue and one
request of it, `approval.deny` says no, and `approval.approve` says
yes -- and a "yes" queues the operation on the host right away.

Three rules hold.  The operator who asked for the operation cannot
decide it: the queue refuses that, and the refusal is the point of the
rule.  A request that nobody decided goes stale after thirty minutes,
and a stale request decides nothing.  The decision is written down:
who asked, who decided, when, and what was asked for.

The rule is a policy of the deployment and not a law of the framework.
The configuration names the kinds of task that need it
(`approval_required`); a deployment that names none has the rule off,
and the queue is still there, waiting.

**The tripwires.**  `canary.plant` plants a small file with a secret in
it on a host, in a place where nothing of the engagement belongs.  The
implant keeps the facts of what it wrote -- the size, the time of the
last change and the digest -- next to the canary, because the implant
is the only side that knows what it wrote.  `canary.check` asks the
hosts about their tripwires, and the answer says whether each file is
as it was planted: `intact`, `changed` or `missing`.

The verdicts travel in the metadata of the answer as one short string
(`c-0001=intact;c-0002=changed`), so the ledger of the server and the
answer the operator reads cannot disagree.  The check never changes the
host: a check that repaired the canary would hide the very thing it is
looking for.  The secret of the file never travels to the console --
`canary.list` and `canary.get` leave it out, and so does every answer
of the server.

**The file of a host.**  `dossier.get` puts everything the server knows
about one host on one page: the identity, the health with the reasons
of its score, the work that was run (counted, and as a histogram of the
kinds), the persistence with the entries that are broken, the tripwires,
the requests, and the things the server does not know.  `dossier.list`
does the same for every host and sorts them weakest first: the host
that needs attention comes before the host that does not.

**The second factor.**  The token of an operator is a secret that lives
in the configuration of the server and in the memory of the console.
The second factor is a secret that lives in the phone of the operator
and never travels: the console sends the six digits of the moment in
the metadata of the handshake and the server checks them before it
answers.

`operator.otp.rotate` makes a new secret for an operator and hands it
out once -- the base32 secret and the `otpauth://` address the phone of
the authenticator reads.  `operator.otp.status` says who has a secret,
whether it is on and how old it is, and it never carries the secret
itself.  `operator.otp.remove` takes the secret away, and the console
of that operator works with the token alone from then on, which is what
a team wants when a phone is lost.

The codes follow RFC 6238 with HMAC-SHA1 and six digits, which is what
the authenticator applications of every phone understand, and the
server accepts a window of one step (thirty seconds) on each side: the
clock of a phone is not the clock of the server.  The comparison is
constant time, the file of the secrets belongs to the server alone
(`0o600`), and an operator may rotate or remove its own second factor
while somebody else's is the work of an admin.

The console sends the code with `--otp` or `$UMBRA_OTP`, and
`umbra otp code --secret ...` prints the code of the moment for a lab
that has no phone.

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

**Certificate pinning** — on top of the chain, either side may pin the public
key of the peer.  A pin is the hex SHA-256 of the `SubjectPublicKeyInfo` of
the certificate: the fingerprint of the *key*, not of the certificate around
it, so a certificate that is renewed with the same key keeps its pin and a
certificate that only claims the same name does not have it.

| Where | What is pinned | How it is written |
|---|---|---|
| the server | the key of the console | `tls_client_spki` in the configuration of the server |
| the console | the key of the server | `--tls-pin` or `UMBRA_TLS_PIN` |

Both sides compare the fingerprint in constant time.  The pin replaces the
trust in the authority and never widens it: when a certificate authority is
configured as well, the chain is verified too, so a pin narrows the set of
peers that are welcome.  The name of the peer is checked by hand when a pin
is used, because a console that pins a key does not need a chain of
certificates to trust.

The console checks the pin **before** the umbra handshake, so a console that
refuses a server never sends its token to it.  The server pins the console in
the same way and refuses a client certificate that does not hold the pinned
key, even when the certificate is signed by the configured authority and
carries the expected name.

The pin of a certificate is printed by

```
umbra pin <certificate.pem>          # the console
umbra-server -gen-spki <certificate.pem>   # the server
```

and the value is pinned in `contracts/vectors.json` (`pin.spki_sha256`), so
every implementation agrees on it: the Go server, the console and the
reference tools compute the same fingerprint for the same certificate.

### 8.1 IPv6

An address family is never guessed: the family of a peer, of a listener and
of a target is carried by the address itself, and the implementations keep
the two apart.

| Place | Rule |
|-------|------|
| `host:port` | An IPv6 literal is bracketed: `[::1]:8443`. A host that contains a colon is an IPv6 literal, so `host:port` is split on the **last** colon and the left part is unwrapped from its brackets. |
| `Host:` header | The value of the header is the address without the port for IPv6 (`[::1]`) and `host:port` for IPv4, exactly as RFC 7230 asks. |
| SOCKS5 | The request carries the address type (`0x01` IPv4, `0x03` domain, `0x04` IPv6). The answer carries the address of the listener, in the family of the listener: a proxy on `[::1]` answers with `ATYP 0x04` and 16 bytes. |
| Scan | A target is parsed as an address, not as a string: `10.0.0.0/24` and `2001:db8::/120` are both expanded, and the probe list is `[(address, port)]`. A block is capped by the caller's limit, and the expansion of a block is done in the 128-bit space. |
| Listener | A listener that is asked for an IPv6 address binds an IPv6 socket and keeps the family when it is forced onto the loopback (`::1`, not `127.0.0.1`). |

The transport, the pivot and the scan are the three places where an address
travels from the operator to the host, and all three keep the family. A host
on an IPv6-only network is reachable with the same commands.

### 8.2 The mail transport

A network where nothing but the mail server gets through is a network the
framework has to work in.  The beacon then mails its frames out and picks
the answer up from its own mailbox.

| step | protocol | what travels |
|---|---|---|
| the beacon sends | SMTP (RFC 5321) | one mail: the headers, an empty line, the frames in base64 |
| the server answers | POP3 (RFC 1939) | one message per batch, the frames in base64 |
| the beacon deletes | POP3 `DELE` | the message is gone, so it is not delivered twice |

The two protocols are the ones a mail server speaks, so the transport works
wherever mail works.  The credentials of an agent are derived from the team
key: the user name is the id of the agent and the password is
`HMAC-SHA256(team key, "umbra/v1/mail/secret" || 0 || id)`, so a password
that leaks does not open the mailbox of another agent.

The mail transport has no connection to keep, so the frames of a cycle
travel in batches: the check-in is one batch, the answer of the server is
the next one.  The session of the agent lives on the server between the
batches, and a batch that begins with a HELLO starts a new one.

### 8.3 The object transport

The beacon reads its work from one bucket and writes its results into
another, the way a program that talks to an object store does.

| bucket | who writes | what it holds |
|---|---|---|
| `umbra-tasks` | the server | the work of the agents |
| `umbra-results` | the beacons | what the agents answer |

The requests carry an AWS Signature Version 4 header
(`AWS4-HMAC-SHA256`), so the same beacon can talk to a real S3 endpoint.
The access key is the id of the agent and the secret key is the password
of the mail transport, so one agent cannot read the work of another.

| request | what it does |
|---|---|
| `PUT /umbra-results/<n>` | the batch of frames of the beacon |
| `GET /umbra-tasks/<agent>` | the work of the agent, empty when there is none |
| `GET /umbra-tasks?list-type=2` | the listing of the bucket, in the XML of S3 |

The signature covers the method, the path, the headers and the body, so a
body that was changed on the way no longer verifies.

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
| `task.retry` for a queued or delivered task | refused ("has not finished yet"): a delivered task may still be running, and running it twice is worse than not running it |
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
