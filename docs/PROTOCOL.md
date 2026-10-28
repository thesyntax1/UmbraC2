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
| `task.retry` | operator | run a finished task again as a new task |
| `events.list` | viewer | the recent events of the journal (`after`, `limit`) |
| `sessions.list` | viewer | the interactive sessions that are open, per agent |
| `engagement.wipe` | admin | clears the agents, the tasks and the schedules of the server |
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
(`logon`, `boot`, `schedule`), a flag for whether it needs administrator
rights and a score for how quiet it is. The desktop beacon knows fifteen
Windows techniques (the `Run` keys, `Winlogon`, `AppInit_DLLs`, the Image
File Execution Options, a COM hijack, a print monitor, a shell extension, a
scheduled task, a task from an XML definition, a service, the startup
folder, a boot execute entry), thirteen on Linux (a systemd system unit, a
systemd user unit, a systemd timer, a user crontab, an `/etc/cron.d` entry,
`rc.local`, an init script, a shell profile hook, the `ld_preload`
technique, an XDG autostart entry, an `at` job) and five on macOS (a launch agent, a launch
daemon, a login item, a shell rc hook, a crontab). The phone has three: the
boot receiver, the sticky foreground service and the alarm.

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
