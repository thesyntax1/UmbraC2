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
| `store` | agents, tasks, the credential vault | in-memory + atomic snapshot (`tmp` + `rename`), bounded history; the secrets of the vault are encrypted before they reach the disk |
| `hub` | broker | all state transitions in one place; transports never mutate state |
| `link` | transports + handshake | `FrameStream` abstraction shared by TCP/HTTP/WebSocket/DNS; per-operator RPC rate limit |
| `audit` | operator audit trail | JSON Lines, `fsync` per entry, size rotation, nil-safe |
| `rbac` | operator roles | one declarative command → minimum-role table; unknown commands are admin-only (fail closed) |
| `pivot` | agent callback sessions | SOCKS5 proxy and TCP forward; the agent dials back, the server only drives; the topology, the accounting, the deny list and the claims live here |
| `vpn` | layer-3 tunnel | X25519 + HKDF + AES-256-GCM datagrams, 64 packet replay window |
| `dnstun` | DNS transport | TXT records carry the frames; the session above the transport does not change |
| `armory` | extension store | Ed25519 signed catalogue; an unsigned catalogue installs nothing |
| `alias` | command namespace | named task templates, call-time arguments win; the namespace of the team is kept next to the state file |
| `store` (workflows) | the workflow catalogue | named, parameterised sequences of steps; the runner walks them in the background and writes what every step did into the run |
| `stager` | stager generation | PowerShell and Bash, one per transport; the download stager, the store stager, the offline stager and the digest shim; the agent key never reaches the audit log |
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

### The dashboard

The dashboard is a second face of the hub, not a second source of truth: it
reads the same store and the same journal the console does, and it queues
tasks through the same `SubmitTask`.  It is a small HTTP server of its own
(`internal/dash`), bound to a local address by default, and it accepts the
operator tokens — so it cannot be a way around the roles of the console.

### The sweep

A beacon that dies in the middle of a task leaves it in the `delivered`
state.  The hub sweeps the queue every 30 s and fails the tasks that were
delivered and never answered (`task_timeout_s`, zero disables it), so the
operator gets a `task.timeout` event instead of a task that never ends.

The sweep never re-queues anything.  A task that may have run must not run
twice: the same rule that re-queues on a *restart* (where the beacon is
known to be gone) does not apply to a timeout (where it is not).

### The queue layer

The delivery of the work is a layer of its own (`internal/hub/queue.go`),
between the store (what exists) and the link (what goes out).  It holds
four decisions:

* **the order** — the tasks of a host are handed out by priority first and
  by age second, so the urgent work goes first and nothing starves;
* **the limits** — the work in flight on one host, the rate one host
  receives work at, and the throughput of the whole server;
* **the breaker** — a host that fails in a row is taken out of the
  rotation until the cooldown is over and one probe succeeds;
* **the window** — the maintenance window stops the traffic without
  stopping the server.

The layer has its own lock (`hub.qmu`) and never calls into the store
while it holds it: the store has its own lock, and the two are never
nested in the other direction.

The metrics are a snapshot of the same state (`internal/hub/metrics.go`):
one pass over the store, one pass over the counters, and a histogram of
the latency of the finished tasks.  The dashboard serves them in the
Prometheus text format.

### Concurrency and safety

* one goroutine per connection, no shared mutable message state;
* `session` serialises its own send/recv directions; the stream serialises writes;
* the operator link is the one connection that reads and writes at the same
  time (requests below, events above), so the TLS session is entered by one
  thread at a time: the Go stack allows one reader and one writer, and the
  Python transport waits for the socket outside of its lock;
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
| `post` | reflective loading, injection, token work and privilege escalation |
| `creds` | the credential collection: one record per piece of material, with a kind, a source and a confidence |
| `remote` | the remote execution through the pivots: wmi, smb, winrm, dcom, ldap and ssh |
| `domain` | active directory reconnaissance, BloodHound-style edges, and the paths from the identity of the implant to a target |
| `profile` | the reconnaissance profiles: the named bundles of checks, the findings and the scored suggestions |
| `evade` | the posture engine: the environment, the schedule and the kill switch |
| `hygiene` | the memory and the process hygiene |
| `persist` | the persistence manager and its technique catalogue |

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

### The identity and the vault

An identity is a record, not a wall of text.  The implant collects material
and answers with one record per piece: the kind (`password`, `hash`,
`ticket`, `token`, `key`), the source it came from, the account it belongs
to, the target and the confidence the implant has.  The value itself is
only sent when the operator asked for it, because the value of a credential
is the one thing in this framework that must never end up in a log.

The server keeps those records in one vault per engagement.  The value is
encrypted with a key that comes from the configuration, and the digest is
always kept: an operator who wants to know whether two hosts share a
credential can find out without the key, and an operator who wants the value
has to ask for it explicitly (`creds.export`, an operator action).  The
event stream never carries the value: the task record keeps the redacted
form, and the vault keeps the rest.

The token work follows the same rule.  The implant can borrow the account of
a process for one task (`impersonate`) or until the operator takes it back
(`become`); the identity travels with the check-in, so the inventory shows
the truth, and the server drops it when the session ends.

The remote execution does not need a new tunnel: the agent that holds the
network path runs the command on the far host, with its own credentials and
its own reach, and the output comes back through that agent.  The protocols
are the ones a Windows domain speaks every day — WinRM, WMI, DCOM through
the scheduler, SMB through the service control manager, LDAP and SSH — and
each of them cleans up after itself.

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
* `netio.py` — the framed stream. One lock per connection keeps the TLS
  session to one thread at a time, and the wait for the socket happens outside
  of that lock, so a reader never freezes the writer;
* `cli.py` — sub-commands for scripting and an interactive shell for live work;
* `shell.py` — the shell around the commands: the history, the completion, the
  continuation of a command over several lines and the status line of the prompt;
* `flows.py` — the two things a single command cannot do: one task on many
  agents with a cap on the answers waited for, and a sequence of steps run from
  one line;
* `plan.py` — the plan file: a small YAML subset (JSON is a plan too) read by
  the console itself, so a workflow can be written without a dependency;
* `dns.py`, `ws.py` — reference implementations of the DNS tunnel and of the
  WebSocket transport, so both can be exercised without a Go build;
* `db.py` — the console's local notebook: a SQLite database with the tasks
  this operator ran, their results, the notes they left, the findings of the
  reconnaissance, the artefacts, the screenshots and the material they
  collected. It is local on purpose: the server stays dependency-free, and
  the engagement history belongs to the operator who collected it. It is
  written as JSON or as the Markdown document an operator hands over.

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
and a TCP port forward (`internal/pivot`), the picture of the reach
(`internal/pivot/topology.go`: the graph of the pivots, the accounting per
client, the log of the connections, the deny list and the claims), the peer
link between two implants with a real handshake, a key exchange and a rekey
(`internal/pivot/peer.go`, `implant/rust/src/tunnel.rs`,
`implant/android/.../Peer.kt`) and the chains of pivots the server resolves
from the far end (`internal/pivot/pivot.go`), the layer-3 tunnel between the console and the
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

Done (the operator's side): the inventory and the group work (tags,
filters, one task or one policy for a whole group), the interactive
sessions with partial results, the multi-stage task chains, the alert
rules on the event stream, the journal of the recent events with its
sequence numbers, the open sessions, the web dashboard (`internal/dash`),
the sweep that fails the tasks nobody answered, the command namespace with
its built-in templates, the reports for the handover, and the end of an
engagement with one command.

Done (the implant's side): the host triage (digest, entropy, file type),
the file search, the network configuration, the process table read from
the operating system, the Windows registry, the persistence and its
undo, the self-update with a verified digest, the key logger that
streams or writes into a file, and the list of servers the beacon falls
back to.

Done (the persistence engine): the start-up entries are a manager around a
catalogue of techniques instead of one scheduled task
(`implant/rust/src/persist.rs`): fourteen Windows techniques, thirteen on
Linux, five on macOS and three on the phone, each of which knows how to
install itself, how to read itself back and how to take itself away.  The
manager picks the quietest technique the host can carry, installs it
idempotently, verifies it, and keeps its own record in the canonical `upk`
encoding, so the operator can ask what is on a host weeks later.  The
lifecycle travels over the wire (`persist`, `unpersist`, `persist.list`,
`persist.verify`, `persist.migrate`, `persist.health`), the server keeps the
entries with the agent (`store.Agent.Persist`), the inventory filters on
them (`persisted=yes`), a broken entry raises `persist.broken` on the event
stream, and the console has the fleet report (`umbra persist-report`).

Done (the posture engine): the implant knows what the host looks like
(`implant/rust/src/evade.rs`) and says so, instead of only answering "is
a debugger attached".  The engine classifies the host on four axes (virtual
or real, a workstation or a server, a developer's box or a plain machine, a
lab machine or a production one), states how sure it is and why, and
classifies the artefacts it finds instead of blacklisting them: a virtual
machine is a hint, a sandbox that injects itself into every process is
nearly a proof.  The posture then changes the behaviour: the sleep is
multiplied with the factor of the host, the jitter is raised, and the
implant only falls silent when the operator armed it.  The schedule of the
day (busy in the working hours, quiet at night, lazier at the weekend), the
scheduled jitter whose window is drawn once per cycle, the traffic shaping
(the size of the frames, the order of the operations) and the kill switch
(the file, the registry value, the date, the uptime, the marker) are the
same engine.  The memory of the implant is cleaned on the way out
(`crypto::Zeroizing`, `implant/rust/src/hygiene.rs`), and the process can
run under a copied name, in a plausible directory, with a clean environment
and a rewritten parent.  The lifecycle travels over the wire
(`evade.report`, `evade.posture`, `evade.profile`, `evade.shape`,
`evade.killswitch`, `hygiene.memory`, `hygiene.process`), the server keeps
the last posture with the agent (`store.Agent.Posture`), the event stream
raises `posture.updated` and `killswitch.armed`, and the console has the
fleet report (`umbra evade-report`).

Done (capabilities, the file store and the end of an engagement): every
beacon says in its handshake which task kinds it implements, and the server
refuses to queue anything else (`store.Agent.Caps`, `hub.SubmitTask`); the
team server keeps files in a content-addressed store
(`server/internal/artifact`, `artifact.*`), and a push is a chain of
ordinary `upload` tasks, so it is verifiable in the same way as a manual
upload; `agents.panic` queues the exit and burns the agent, so a server
that is being torn down cannot feed it more work; the per-agent queue is
capped (`max_task_batch`, `max_queued_tasks`), so a backlog cannot grow
without a bound; and the binary arguments of a queued task survive a
restart of the team server instead of turning into a base64 string.

Medium term: S3 and SMTP transports, named-pipe pivots, a Go implant,
per-operator ACLs on the chat, and a sandbox for task modules that are not
plain memory.

Done: a versioned module ABI (the manifest of a module, its argument
schema, its output schema and the capabilities it needs), the sandboxed
loaders (a small webassembly interpreter, a script dialect and a raw
shellcode loader, all capability limited), the armory of the framework
finished (search, dependency resolver, versions, a "what does it need" view
and a remote catalogue import), the stagers finished (one one-liner per
transport, a loader that pulls the beacon from the file store of the server,
an offline variant and a digest shim) and the process migration done
properly (into a spawned process, into a running process and out of its own
process, with the task stream alive across the move).

Long term: trait-object plugin ABI for implants (new tasks without rebuilding),
automated detection-engineering fixtures.
