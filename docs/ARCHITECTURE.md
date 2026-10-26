# Architecture

## 1. Shape of the system

```
            operator console (Python)                    one process, N operators
                     │  OP_REQUEST / OP_RESPONSE / OP_EVENT
                     ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                       team server (Go)                       │
   │  link/        agent TCP · operator TCP · HTTP (beacon)       │
   │  session/     per-connection keys, nonces, rotation          │
   │  hub/         registry · task queue · operator fan-out       │
   │  store/       agents + tasks, atomic JSON snapshots          │
   │  crypt/ upk/ wire/   shared protocol core                    │
   └──────────────────────────────────────────────────────────────┘
                     ▲  CHECKIN / TASK_BATCH / RESULT / BYE
      ┌──────────────┴──────────────┬───────────────────────┐
      │                             │                       │
 Rust beacon (win/linux/macOS)  Android implant (Kotlin)   (future: Go/other)
```

Three properties drive the whole design:

* **one protocol core, three implementations** — `upk`, `wire`, `crypt` and
  `session` are mirrored in Go, Rust and Python/Kotlin, pinned by
  `contracts/vectors.json`;
* **one message pipeline, many transports** — TCP and HTTP handlers both feed
  the same frame-processing code, so behaviour cannot diverge;
* **server is the only stateful authority** — implants are dumb, sleeping
  clients; the server holds inventory, queue and history.

## 2. Team server (Go)

`server/cmd/umbra-server` is a thin shell around `internal/link`:

```
main: load config → build keyring → open store → start listeners
      → 1 s scheduler tick + debounced snapshot → wait for SIGINT/SIGTERM → graceful shutdown
```

### Packages

| Package | Responsibility | Notable decisions |
|---|---|---|
| `upk` | canonical encoding | hand-written, no reflection on data paths, hard limits |
| `wire` | prelude, framing, type registry | length in the prelude so transports can frame without keys |
| `crypt` | X25519, HKDF, AEAD, transcript MACs | stdlib only; suites are pluggable |
| `session` | direction state, nonce check, rekey | exact-nonce matching = replay/reorder detection |
| `config` | JSON config + keyring | secrets come from env or `0600` files, never from the config file |
| `store` | agents, tasks | in-memory + atomic snapshot (`tmp` + `rename`), bounded history |
| `hub` | broker | all state transitions in one place; transports never mutate state |
| `link` | transports + handshake | `FrameStream` abstraction shared by TCP/HTTP/WebSocket/DNS; per-operator RPC rate limit |
| `audit` | operator audit trail | JSON Lines, `fsync` per entry, size rotation, nil-safe |
| `rbac` | operator roles | one declarative command → minimum-role table; unknown commands are admin-only (fail closed) |
| `pivot` | agent callback sessions | SOCKS5 proxy and TCP forward; the agent dials back, the server only drives |
| `vpn` | layer-3 tunnel | X25519 + HKDF + AES-256-GCM datagrams, 64 packet replay window |
| `dnstun` | DNS transport | TXT records carry the frames; the session above the transport does not change |
| `armory` | extension store | Ed25519 signed catalogue; an unsigned catalogue installs nothing |
| `alias` | command namespace | named task templates, call-time arguments win |
| `stager` | stager generation | PowerShell and Bash; the agent key never reaches the audit log |
| `coff` | object inspection | the server parses a module before it is pushed to an agent |
| `mtls` | TLS configuration | mutual TLS for the operator listener, plain TLS for the agent listener |

### Connection handling

Every accepted connection gets its own goroutine, in this order:

1. `guard.Allow(addr)` — cheap per-source rate limit;
2. handshake deadline (`handshake_timeout_s`);
3. keyring probe: decrypt the HELLO with each `(suite, key)` candidate. The key
   that authenticates the HELLO decides the peer's role. With one agent PSK and
   a handful of operator tokens this is microseconds, and it removes the need for
   any identity on the wire in cleartext;
4. role check per listener (`agent` listener refuses operator keys, and vice
   versa);
5. register with `hub` (new agent → `agent.new` event, known agent →
   `agent.online`), then run the message loop with an idle timeout and a
   per-connection byte budget.

Operator connections additionally start an event pump: `hub.Emit` fans events out
to each subscriber's buffered channel, and a writer goroutine seals them as
`OP_EVENT`. Both directions write through one mutex-protected stream, so an event
can never interleave with an RPC response.

### Task lifecycle

```
operator: task.submit ──► store.AddTask(state=queued)  ──► event task.queued
agent:    CHECKIN     ──► hub.NextTasks ──► mark delivered ──► TASK_BATCH
agent:    RESULT      ──► store.Complete(state=done|failed) ──► event task.result
operator: task.get / event stream
```

Delivery is **pull-based**: the server never pushes work to a sleeping implant,
so an offline agent simply keeps its queue until it checks in again (the store
re-queues anything left `delivered` after a restart).

### The inventory and the selection rule

The agent list is the operator's map of the engagement, so it has to answer two
questions quickly: *what is alive* and *what do I want to act on*.

**What is alive.**  The beacon opens one connection per cycle and closes it
again, so the link is down most of the time.  "Online" therefore describes the
*check-in*, not the socket: an agent stays online while it keeps checking in
and turns offline once it has been quiet for longer than the grace period
(90 s, or three of its own intervals — whichever is longer).  The state is
recomputed whenever the inventory is read, so a beacon that died silently
disappears from the online view without anybody having to notice the socket
closing.

**What to act on.**  Every agent carries operator-owned tags (`finance`,
`dc-01`, `cobalt`); the server never derives a label from the target, it only
stores what an operator typed.  On top of that, a selection is a filter —
`state`, `transport`, `os`, `arch`, `tag`, `user` — that the same code path
uses for listing, for tagging, for pushing a policy and for queueing a task.

**One rule everywhere.**  An operation that acts on more than one agent must
name its targets: an explicit list of ids, a filter, or both.  A bulk
operation without either is refused, because "I forgot the filter and now it
runs on two hundred machines" is not a mistake an operator can take back.

### Long running work

Two things in the framework do not finish when the task is queued.

**A session** is a process the operator types into.  The beacon starts it
with its input and output piped and streams the output as *partial results*:
a RESULT body with `partial: true` is appended to the task instead of
completing it, so the task stays in `delivered` state while the session
lives and the console sees the output as it happens.  The session lives in the
implant, not in the connection, and the beacon holds the connection open
while a session is live — otherwise an interactive shell with a one-minute
check-in interval would feel like a mailbox.

**A chain** is several tasks in a row.  The chain state lives in the hub
(the stages themselves are ordinary tasks, so the history still shows them),
and the output of a finished stage is substituted into the `{{output}}`
placeholder of the arguments of the next one.  The substitution only touches
strings: the output of a stage is data, never code.

### Concurrency and safety

* one goroutine per connection, no shared mutable message state;
* `session` serialises its own send/recv directions; the stream serialises writes;
* `store` and `hub` hold short-lived mutexes and never call each other while
  holding one;
* `hub.Emit` never blocks a transport (bounded channel + drop + warn, with a
  running `events_dropped` counter exposed in `server.stats`);
* unregistering is **session-scoped** — a beacon that reconnects with the same
  id would otherwise have its predecessor's deferred cleanup delete the new live
  entry; only expiry uses the force variant;
* the online state is **derived from the last check-in**, not from the socket:
  a closed connection between two cycles is a sleeping beacon, and the
  `agent.offline` event is only emitted when the agent really went quiet;
* the beacon cadence is **owned by the operator** — a beacon that has not
  applied a pushed policy yet still reports its old interval, and the report
  is kept in its own field instead of overwriting the policy;
* all sizes are bounded before allocation (frame ≤ 1 MiB, upk limits, HTTP body
  cap, header cap, operator/agent caps).

## 3. Rust beacon

```
main → Config (compile-time defaults + env/flags) → Beacon::run
       loop { connect → handshake → checkin → execute → report → BYE → jitter sleep }
```

| Module | Responsibility |
|---|---|
| `upk` | encoding (`Value` enum, `BTreeMap` for canonical key order) |
| `crypto` | X25519 (`x25519-dalek`), HKDF-SHA256, AES-GCM, optional ChaCha20-Poly1305 |
| `wire` | frame read/write, `split_frames` for HTTP bodies |
| `session` | same state machine as the server |
| `transport` | `TcpChannel`, `HttpChannel` (hand-written HTTP/1.1, chunked decoding) |
| `ws` | the WebSocket transport (RFC 6455, hand-written SHA-1 and base64) |
| `task` | command execution with a hard timeout, output cap |
| `beacon` | handshake, check-in, task dispatch, jitter/obfuscated sleep/backoff |
| `link` | the client half of the handshake, shared by the beacon and the pivot callback |
| `tunnel` | pivot callbacks and peer-to-peer links |
| `vpn` | the layer-3 tunnel client (TUN device on Linux) |
| `dns` | the DNS transport: TXT records carry the frames |
| `bof` | in-memory COFF loader |
| `post` | reflective loading, injection, token and credential helpers |
| `domain` | active directory reconnaissance, BloodHound-style edges |
| `evade` | debugger and sandbox awareness |

Choices worth knowing:

* **one connection per cycle** — cheap for TCP, simple to reason about, and it
  means every cycle gets fresh ephemeral keys;
* **synchronous HTTP** — no async runtime, so a 1–2 MB static binary instead of a
  much larger one; latency is dominated by the sleep interval anyway;
* **no TLS in the beacon** — plain TCP and plain HTTP/1.1 only, because the
  payload is already AEAD-sealed per frame; the gap a tunnel closes is traffic
  *shape*, not content (see `deploy/nginx-http-transport.conf` and
  `docs/SECURITY.md` §4, limitation 1);
* **jitter** — uniform in `[sleep·(1−j), sleep·(1+j)]`, with exponential backoff
  (capped at 5 minutes) when a cycle fails;
* **sleep obfuscation** — on top of the jitter the beacon takes an occasional
  long nap (one check-in in four sleeps 1.5–3.5 times longer), because a
  perfectly uniform distribution is a signature of its own;
* **process execution** — `std::process::Command` with piped stdio: commands are
  never staged on disk (no temp scripts, no dropped helper binaries). The
  implant itself never writes to disk except for explicit `upload` tasks.

## 4. Android implant

Same protocol core in Kotlin (`Upk`, `Crypto`, `Wire`, `Session`), with these
platform differences:

* AES-256-GCM and HMAC-SHA256 come from the platform providers; X25519 uses the
  `XDH` provider, which is why `minSdk` is 33 (Android 13);
* the loop runs in a foreground service with a partial wake lock, because
  Android suspends background threads aggressively;
* a C++/JNI layer supplies the values Java cannot read (kernel release, machine
  type, real pid/uid);
* the UI is an explicit consent screen: nothing runs unless the device owner
  starts the service.

## 5. Operator console

`operator/umbra_cli` is both the console and the executable specification of the
protocol:

* `upk.py`, `wire.py`, `crypto.py`, `session.py`, `handshake.py` — reference
  implementation used to generate `contracts/vectors.json`;
* `client.py` — one reader thread, RPC responses matched by `rid`, events
  delivered through a callback;
* `cli.py` — sub-commands for scripting and an interactive shell for live work;
* `dns.py`, `ws.py` — reference implementations of the DNS tunnel and of the
  WebSocket transport, so both can be exercised without a Go build;
* `db.py` — the console's local notebook: a SQLite database with the tasks
  this operator ran, their results and the notes they left. It is local on
  purpose: the server stays dependency-free, and the engagement history
  belongs to the operator who collected it.

`tools/mock_server.py` implements the server side in Python (plus a reference
agent) so the console and the protocol can be exercised without a Go build. It is
a test double, not a production server.

## 6. Why these choices

| Decision | Reason | Trade-off |
|---|---|---|
| Custom upk encoding instead of JSON/Protobuf | deterministic bytes, tiny code in three languages, no dependencies, strict limits | no schema evolution tooling; version bumps are manual |
| X25519 + HKDF instead of a full Noise handshake | ~200 lines per language, easy to audit, no state machine complexity | no built-in rekey/transport binding; we implement rotation ourselves |
| AES-256-GCM as the mandatory suite | in every stdlib we target (Go, JVM, RustCrypto) | no ChaCha fallback on the reference server |
| Cleartext length in the prelude | framing without keys, cheap DoS bounds | leaks message sizes (mitigation: padding, on the roadmap) |
| Pull-based beaconing | implants are stateless clients; simple retry semantics | worst-case latency = sleep interval |
| JSON state file instead of a database | zero dependencies, easy to inspect and back up | not suitable beyond ~10⁴ agents/tasks (two generations on disk: `state.json` + `.bak`, schema version checked on load). The operator console keeps its own SQLite notebook (`umbra_cli/db.py`) for the history it collects |
| Python reference implementation | generates the vectors, drives e2e tests, teaches the protocol | must be kept in lockstep with Go/Rust |

## 7. Roadmap

Short term: `CONFIG` as a first-class policy push, per-agent authorisation
profiles.

Done: crash-safe state generations (`state.json` + `.bak`, schema version,
fallback load with a loud warning); shared-work coordination (operator focus/presence in `operators.list`,
advisory `task.claim`/`task.release` so a team does not duplicate work, directed
`chat.send`); HTTP transport keep-alive (length-delimited replies, a socket pooled for
the whole beacon cycle, one reconnect-and-retry on a stale pooled socket);
chunked `download`/`upload` (900 KiB steps, per-chunk SHA-256, `total`/
`offset`/`eof` result metadata stored with the task, `.part` plus rename on the
operator side); roles and authorisation (`rbac`: viewer/operator/admin per RPC, enforced
server-side and audited); operator chat and recurring tasks (`schedule.*` with a
1 s scheduler tick, persisted with the state file); operator audit log (`internal/audit`, `audit.tail`, `umbra audit`), which
records every RPC with operator, peer, transport, task/agent id and outcome, and
is rotated, fsynced per line, and readable from disk after a restart; and task
cancel end-to-end (`TASK_CANCEL` control frames read by both reference implants,
state preserved when a late result arrives).

Done (pivoting and extensions): agent callback sessions with a SOCKS5 proxy
and a TCP port forward (`internal/pivot`), peer-to-peer links between implants
(`implant/rust/src/tunnel.rs`), the layer-3 tunnel between the console and the
beacons (`internal/vpn`, `implant/rust/src/vpn.rs`), the DNS transport
(`internal/dnstun`, `implant/rust/src/dns.rs`), in-memory COFF execution and
reflective PE loading (`implant/rust/src/bof.rs`, `implant/rust/src/post.rs`),
the signed extension store (`internal/armory`), the shared command namespace
(`internal/alias`), stager generation (`internal/stager`) and mutual TLS for
the operator and agent listeners (`internal/mtls`).

Done (covert channels): the WebSocket transport (`server/internal/link/ws.go`,
`implant/rust/src/ws.rs`, `operator/umbra_cli/ws.py`), traffic padding with
sealed `PADDING` frames (`http_pad` on the server, `UMBRA_HTTP_PAD` in the
beacon), domain fronting through a configurable `Host` header on both the
HTTP and the WebSocket transport, and the operator console speaking mutual
TLS (`--tls`, `--tls-ca`, `--tls-server-name`, `--tls-cert`, `--tls-key`).
See `docs/TRANSPORTS.md`.

Done (reconnaissance and operator state): active directory reconnaissance
with BloodHound-style edges (`implant/rust/src/domain.rs`), debugger and
sandbox awareness (`implant/rust/src/evade.rs`), sleep obfuscation on top of
the jitter (`UMBRA_SLEEP_OBFUSCATE`), module images wiped from memory once
they have run (`crypto::zeroize`), and the console's local SQLite notebook
(`operator/umbra_cli/db.py`, `umbra db`).

Medium term: S3 and SMTP transports, named-pipe pivots, a Go implant,
per-operator ACLs on the chat, and a sandbox for task modules that are not
plain memory.

Long term: trait-object plugin ABI for implants (new tasks without rebuilding),
WASM-sandboxed task modules, automated detection-engineering fixtures.
