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
      → periodic snapshot (30 s) → wait for SIGINT/SIGTERM → graceful shutdown
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
| `link` | transports + handshake | `FrameStream` abstraction shared by TCP/HTTP; per-operator RPC rate limit |
| `audit` | operator audit trail | JSON Lines, `fsync` per entry, size rotation, nil-safe |
| `rbac` | operator roles | one declarative command → minimum-role table; unknown commands are admin-only (fail closed) |

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
| `task` | command execution with a hard timeout, output cap |
| `beacon` | handshake, check-in, task dispatch, jitter/backoff |

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
* `cli.py` — sub-commands for scripting and an interactive shell for live work.

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
| JSON state file instead of a database | zero dependencies, easy to inspect and back up | not suitable beyond ~10⁴ agents/tasks |
| Python reference implementation | generates the vectors, drives e2e tests, teaches the protocol | must be kept in lockstep with Go/Rust |

## 7. Roadmap

Short term: message padding, `CONFIG` as a first-class policy push, streaming file
transfer (chunked `download`/`upload`), per-agent authorisation profiles, HTTP
transport keep-alive.

Done: roles and authorisation (`rbac`: viewer/operator/admin per RPC, enforced
server-side and audited); operator chat and recurring tasks (`schedule.*` with a
1 s scheduler tick, persisted with the state file); operator audit log (`internal/audit`, `audit.tail`, `umbra audit`), which
records every RPC with operator, peer, transport, task/agent id and outcome, and
is rotated, fsynced per line, and readable from disk after a restart; and task
cancel end-to-end (`TASK_CANCEL` control frames read by both reference implants,
state preserved when a late result arrives).

Medium term: DNS/S3/SMTP transports, SOCKS5 pivot, named pipes, BOF/COFF
execution, in-memory reflection for Windows (`CreateProcess` + section-backed
payloads), Go implant, multi-player operator chat with per-operator ACLs.

Long term: trait-object plugin ABI for implants (new tasks without rebuilding),
WASM-sandboxed task modules, automated detection-engineering fixtures.
