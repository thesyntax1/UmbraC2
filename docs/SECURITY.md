# Security notes

> **Scope.** UmbraC2 is a C2 framework for authorised adversary emulation,
> lab research and detection engineering. Using it against systems you do not own
> or have written permission to test is a criminal offence in most
> jurisdictions. The Android build deliberately requires an explicit
> user-initiated start and shows a permanent foreground notification.

## 1. What the cryptography gives you

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM over every byte after the frame prelude |
| Integrity | AEAD tag over ciphertext **and** the frame prelude (AAD) |
| Mutual authentication | HMAC-SHA256 transcript keyed by the PSK, both directions |
| Forward secrecy (per connection) | ephemeral-ephemeral X25519, keys destroyed with the connection |
| Forward secrecy (long sessions) | rekey mixes a fresh 32-byte seed into the running HKDF PRK every 2²⁰ frames |
| Replay resistance | exact nonce matching (prefix ‖ monotonic counter) per direction |
| Nonce uniqueness | counter reserved atomically before sealing, and seal+write serialised per connection (see PROTOCOL.md, SEND-SERIAL) |
| Key separation | distinct labels for bootstrap keys, session keys, rekey keys, and each direction |
| No PSK reuse on the wire | the PSK only ever feeds HKDF and HMAC, never an AEAD |
| No oracle | a failed handshake produces no response at all |

What it does **not** hide: that something is talking to the C2 (traffic
analysis), and the *timing* of the beacons. The message sizes are hidden on
the HTTP transport by the padding (`http_pad`), not on the other transports.

On top of that:

| Layer | What it adds |
|---|---|
| mutual TLS (`tls_listen`) | a client certificate is required, so a stolen token is not enough to take over an operation |
| WebSocket / HTTP | TLS is terminated by a proxy or by the server; the frames stay encrypted end to end |
| DNS tunnel | the traffic is ordinary name resolution; the resolver sees queries, not the payload |
| armory signatures | an extension that was not signed by the catalogue key never reaches an agent |

## 2. Threat model

Assumed capabilities of the adversary:

* full network visibility and the ability to modify, drop and replay traffic;
* the ability to make failed connections (probing, brute force);
* a captured implant binary (so the *agent* PSK is known);
* optionally a stolen operator token.

Explicitly out of scope for v0.1:

* a compromised team server host (it holds every key and the plaintext history);
* endpoint forensics on the implant host (strings, memory, process telemetry);
* side channels (timing of AEAD, power, cache);
* code-signing/EDR bypass — the implants are *not* stealthy by design in v0.1.

### Consequences of a compromise

| Stolen secret | Impact | Blast radius |
|---|---|---|
| Agent PSK | attacker can enrol fake implants, receive tasks, report fake results | **no operator access** — the operator API needs an operator token |
| Operator token | control of that operator identity, bounded by its role: a viewer reads, an operator queues tasks, an admin manages schedules | cannot enrol implants, cannot authenticate as another operator, cannot exceed its role |
| Operator certificate | the same as the token, but it is the *second* factor on the mutual TLS listener: a stolen token alone is refused | the certificate is useless without the token as well |
| `sid` (HTTP path) | can target the session with frames | cannot decrypt or forge: every frame is AEAD-sealed and nonce-ordered; wrong frames kill the session |
| Armory signing key | can publish modules that the server accepts | the modules still run on the *agents* of that server only, and every run is audited |
| TLS client CA | can issue certificates that the mutual TLS listener accepts | the operator handshake still needs a valid operator token |
| DNS tunnel domain | traffic to that domain can be observed and dropped | the payload stays encrypted; the tunnel can be denied, not read |
| Team server host | everything | rotate all secrets, rebuild implants |

Per-operator tokens are bound to the operator's name inside the authenticated
transcript, so having one token does not let you claim another identity.

Each identity also carries a role (`viewer` < `operator` < `admin`). The server
enforces the minimum role per RPC from a single table
(`server/internal/rbac`), refuses unknown commands to everyone but admins, and
audits every refusal. A compromised viewer token therefore exposes the
inventory and history (which is bad) but cannot queue commands, change beacon
cadence or kill implants.

Accountability is separate from authentication: every operator command is
written to the audit log with the operator name, source address, transport and
outcome, so a stolen token does not give the attacker an unattributable window.
The log is append-only from the server's point of view (`O_APPEND`, `0600`,
fsync per line, size rotation) and can be read back with `umbra audit`. See
`docs/OPERATIONS.md` §5b. Operators are also rate limited (120 burst / 40 s⁻¹)
so a runaway console cannot starve beacon traffic.

## 3. The attack surface of the new features

The pivoting, extension and transport features each add a way in. They are
listed here with the guard that keeps them from becoming the weakest link.

### 3.1 Pivoting (`internal/pivot`)

* The server never connects *into* the target network. It asks an agent that
  is already there to dial back, and the callback is bound to the session id
  the server generated: a peer that does not know the id cannot join the
  tunnel.
* The SOCKS5 proxy only implements `CONNECT` (RFC 1928). There is no UDP
  associate, so the proxy cannot be used for a reflective DNS tunnel.
* Every open tunnel is listed in `pivot.list` and closed with `pivot.close`;
  the server keeps a per-agent limit of open streams.
* The pivot callback runs on the **agent** listener, so it goes through the
  same guard, the same handshake and the same role check as a beacon.

### 3.2 The layer-3 tunnel (`internal/vpn`)

* The tunnel is encrypted and authenticated (X25519 + HKDF + AES-256-GCM) and
  has a replay window, so a captured datagram cannot be replayed into it.
* It is a *network*, not a proxy: every host that can reach the UDP port can
  ask for an address. Bind it to an interface that only the console and the
  agents can reach, and let the firewall do the rest.
* The operator side of the tunnel uses the operator tokens as credentials, so
  the same role separation applies.

### 3.3 The extension store (`internal/armory`)

* An extension is a manifest plus a blob. The manifest is signed with an
  Ed25519 key, and the signature covers the SHA-256 digest of the blob: a
  mirror that rewrites a module breaks the signature *and* the digest, and
  the install fails loudly.
* Without a configured `armory_key` the catalogue is unsigned. The server
  logs this loudly at start-up; do not run that way in production.
* Downloads are HTTPS only, size-capped, and the catalogue is bounded.
* The server parses a module before it is stored (`internal/coff`), so an
  object the loader cannot read never reaches an agent.
* An extension runs in the memory of the agent with the rights of the agent.
  The store is a distribution mechanism, not a sandbox.

### 3.4 The DNS tunnel (`internal/dnstun`)

* The server answers only for its own domain; every other name is left to the
  resolver, so it can sit behind a normal DNS server.
* The payload is encrypted like every other frame; the resolver sees the
  query names and the sizes of the answers.
* A query can carry at most 32 bytes of payload in one label and 256 KiB per
  frame, so a hostile resolver cannot make the server allocate without bound.
* The tunnel is a fallback, not a hiding place: the sizes and the timing of
  the queries are visible to the operator of the resolver.

### 3.5 Mutual TLS (`internal/mtls`)

* The client certificate is verified against the configured CA and the
  certificate chain is checked; the common name can be pinned on top.
* TLS 1.3 is the minimum on the mutual TLS listener.
* A failed TLS handshake is answered with a log line, never with a protocol
  error, so a probing peer learns nothing about the keyring.
* The certificates never replace the umbra handshake: the TLS layer proves
  *who*, the handshake decides *what*.

**The pin is stronger than the name.**  A certificate that carries the
expected common name proves nothing on its own: anybody who can ask the
authority for a certificate can ask for one with that name.  A pin is the
fingerprint of the public key itself — the hex SHA-256 of the
`SubjectPublicKeyInfo` — so a peer has to hold the key, not merely the name.
The server pins the console with `tls_client_spki`, the console pins the
server with `--tls-pin` (or `UMBRA_TLS_PIN`), and both compare the
fingerprint in constant time: the moment a peer is refused says something
about the pin, and a comparison that leaks the first differing byte leaks
it.

**A pin narrows the trust, it never widens it.**  When an authority is
configured as well, the chain is verified on top of the pin.  A console
that pins a key does not need a chain of certificates to trust, so the name
is checked by hand instead; the two checks are two checks — the pin says
which key, the name says which host.

**The console checks the pin before it speaks.**  The pin is verified right
after the TLS handshake and before the umbra handshake, so a console that
refuses a server never sends its token to it.  The token is the credential
that matters; the certificate only proves who is talking.

**The pin survives a renewal.**  Because the pin is the fingerprint of the
key and not of the certificate, a certificate that is renewed with the same
key keeps its pin.  The operator reads the new pin with `umbra pin
<certificate.pem>` (or `umbra-server -gen-spki`) and writes it into the
configuration of the other side.

### 3.6 The WebSocket transport (`internal/link/ws.go`)

* The upgrade is the standard RFC 6455 handshake, and the client verifies the
  accept value, so a non-WebSocket endpoint is detected at once.
* The frames are the same AEAD frames as on every other transport; the
  WebSocket layer adds no plaintext.
* Only the part of RFC 6455 that the protocol needs is implemented: no
  extensions, no compression, no fragmentation. A smaller surface is a
  smaller attack surface.
* The connection is a normal agent session: the same guard, the same frame
  budget, the same idle timeout.

### 3.7 The stagers (`internal/stager`)

* A stager is a template, not a binary: it carries the server address, the
  transport and the agent key, and it is rendered per engagement.
* The agent key is written into the stager, so a stager is a secret. It is
  never written to the audit log, and the templates do not contain it.
* Rendered stagers are text (PowerShell, Bash). Keep them in the deployment
  directory with `0600` and delete them when the engagement ends.
* The `store` mode keeps the payload on the team server: the stager pulls it
  from the file store of the server, so the beacon itself never has to live
  on a third party host.
* The `shim` mode is the digest check on its own: it proves what it
  downloaded and hands the path over. It is the only part of a stager that
  can be handed to somebody else, and it proves nothing else.
* The `offline` mode carries the beacon inside the stager. The script is
  then as secret as the beacon: treat it like the key.

### 3.8 The reconnaissance profiles (`implant/rust/src/profile.rs`)

* A profile **reads**. No check writes to the host, no check installs
  anything, and no check leaves a file behind. The worst a profile does is
  run the tools the operating system already carries (`net user`,
  `schtasks`, `sc query`, `wmic`, `driverquery`) with the rights of the
  account the implant runs as.
* A profile **never reports a secret**. The cloud configuration is reported
  by name and by path (`/root/.aws/credentials`, `AZURE_CLIENT_ID`), never
  by content: the value of a credential does not travel to the operator and
  does not travel to the server either. The same holds for the browser
  data and for the key files.
* The findings are the most sensitive part of a report: they say what the
  machine holds. They travel inside the result of the task, which is
  encrypted per frame and kept in the server's state like every other
  result. The operator's notebook keeps them too, so the notebook is a
  secret when the profile is a deep one.
* The suggestions name a path and a task. They do not run anything: the
  decision, and the task, stay with the operator.

### 3.9 The operator's notebook (`umbra_cli/db.py`)

* The console writes the tasks it submitted, their results and its own notes
  into a local SQLite file (`~/.umbra/state.db` by default).
* The notebook holds **task output** and, since the workflow pass, the
  material the operator collected: the findings of the reconnaissance, the
  artefacts that were pulled off a host, the screenshots and the value of
  the credentials that were collected. The operator token, the agent PSK
  and the session keys stay in memory: those are never written anywhere.
  The material in the notebook is the same material the server keeps in
  its vault -- the difference is that the notebook is on the operator's own
  disk, it is not encrypted, and nobody else knows it exists.
* The file is created with the permissions of the process that creates it
  (0600 under a normal umask). It is not encrypted: treat it like the
  server's state file and delete it when the engagement ends.
* `--db` (or `UMBRA_DB`) moves it; an empty value switches it off.

### 3.10 The collaboration (`internal/hub`, `internal/link/operator.go`)

* **The chat is for the team, not for the implants.** The event stream the
  agents read carries tasks and results. A line of chat never travels into
  it, and the chat history stays on the server.
* **A directed message is addressed, not encrypted.** The line reaches the
  console it is addressed to and the sender's own; the history stays
  complete, because a shared engagement needs a shared record. Treat the
  operator link as the boundary: it is encrypted per session, and the
  server sees everything in between.
* **The presence expires.** A console that stops talking goes silent after
  ninety seconds and stale after two, and the claims it held expire with
  it. A crashed console therefore cannot keep a task to itself, and a
  stale console cannot be mistaken for a working one.
* **The handover document is a secret.** It holds the inventory, the
  findings, the persistence and the artefacts of the engagement: the
  document that goes with the shift is the document that tells a
  colleague everything. Keep it with the same care as the report of the
  engagement.
* **The shared namespace is shared.** A template that everybody runs is
  written by one operator and used by all of them. The write is an event
  and the audit trail keeps it, so a template that does something nobody
  expected has an author.

## 3.11 The workflow layer, the plan and the notebook

**A workflow runs on the server.** The steps are data the team writes, and
the server walks them: a task, a chain, a wait, a condition, a report. A
workflow may not carry a parameter nobody gave, because a workflow that
runs the wrong thing is worse than no workflow at all. The catalogue lives
in the state file of the server, so it is as sensitive as the state file:
who may write a workflow is a role decision (`workflow.add` is an operator
action, `workflow.run` queues tasks, so it is one too).

**The plan file is read by the console, not by the server.** The reader is
a small YAML subset inside the console: no library, no dependency, and no
network. A plan is a local file; the operator decides what is in it.

**The notebook is a secret.** The operator's SQLite file holds the value of
the material that was collected — the passwords, the hashes, the tickets.
It is the operator's own file on the operator's own disk, but it is not
encrypted, and it is not in the vault of the server. Treat it like the
notebook it is: keep it out of shared directories, out of tickets and out
of backups that travel. The server's vault stays the authoritative copy,
and the value leaves it only with a role that may see it.

**The dashboard can change things.** The panels of the dashboard are
read-only by default, but the workflow runner and the alert rules editor
change the state of the engagement, so they are refused when the dashboard
runs read-only. The dashboard is behind the operator token, and the token
is compared in constant time on every request.

**The raw command line is the raw command line.** `umbra rpc` sends any
command the server knows, with the role of the operator attached. It is not
a way around the role table: the server checks the role of the command,
not the shape of the request.

## 3.12 The queue, the breakers and the maintenance window

The queue is a security boundary as much as a convenience: it decides
what the server does with a host that misbehaves, and it is the part an
attacker would try to abuse.

**The limits are a defence.** The per-host rate, the per-host work in
flight and the global throughput cap mean a beacon that has been turned
into a spam amplifier cannot make the server hand out work faster than
the fleet can take it.  The values are in the configuration and they are
validated: a negative limit is a configuration error and the server
refuses to start.

**The circuit breaker is a defence.** A host that fails in a row is taken
out of the rotation, so a dead host cannot make the server burn its
whole budget on a host that is not there.  The breaker opens after five
failures in a row, one probe goes through after the cooldown, and the
state of every breaker is visible to the operator.

**The maintenance window is a defence.** `server.quiet` stops the traffic
without stopping the server: the beacons keep checking in and get
nothing, which is what a host under maintenance should see.  The window
is an admin decision, it is an event and an audit line, and it ends by
itself at the moment the operator gave.

**The dead letter queue is a defence.** A task that failed too often is
parked instead of being retried for ever, so a task that never succeeds
cannot keep a worker busy.  A parked task is not run again without a
decision.

**The trace is a defence.** Every task carries a trace id, and the trace
is in the record, in the events and in the audit trail.  A task that a
host received without an answer can be followed without guessing, which
is what makes an incident review possible.

**What the queue does not do.** The limits are per server, not per
operator: a console that queues a thousand tasks occupies the queue, and
the operator's own rate limit (`rate limited` in a response) is what
stops a single console from looping.

## 3.13 The versions of the protocol

The handshake version is not a security boundary, and it is worth saying
so plainly: a version 2 beacon is not more trustworthy than a version 1
beacon.  The version decides which fields travel, not who is allowed in.

What the versions do buy:

* **the capability list is a field of its own.**  The server reads it
  before it looks at anything else, and it is the list it uses to refuse
  work the host cannot run.  In the first version it was buried in the
  metadata, where a change of the metadata could have changed the reach
  of a host;
* **the module ABI is named.**  A module built for another ABI is refused
  by the host, and the server knows what the beacon understands;
* **the answer is in the version the peer asked for.**  A beacon is never
  shown a field it does not understand, so a new server cannot break an
  old beacon by accident.

The heartbeat is a signal, not a channel: it carries the version of the
implant, the module ABI, how much work the host is carrying and its
uptime.  It asks for nothing and it carries no material, so it cannot
be used to move data out of a host.

**The rule about the keys.**  A heartbeat is sent after the batch of its
cycle, never between the check-in and the batch: the server may rotate
the session keys right after the check-in, and a frame that is sealed with
the old keys cannot be read.

## 4. Secret handling

* Secrets come from environment variables or `0600` files, never from the JSON
  config file.
* The server logs only SHA-256 fingerprints (first 16 hex chars) of operator
  tokens.
* The console prefers `--token-file` or `$UMBRA_OPERATOR_TOKEN`; `--token` leaks
  into the process list.
* PSK/token minimum length enforced at start-up: 16 bytes.
* Private keys (the TLS key, the armory signing key) are read from files with
  `0600` and are never logged.
* Rotate on personnel change: `tokens.rotate` replaces the token without a
  restart (the old one works for the overlap), and the entry can be removed
  from `UMBRA_OPERATOR_TOKENS` for the next start.  The same for the agent
  PSK: `keys.rotate` replaces it while the server runs.
* The rotation answers hold the new secret: they are shown once and are not
  written to the audit trail.

## 4.1 The credentials of the server, and how they are rotated

The server keeps three credentials: the agent PSK, the operator tokens and
the TLS key pair.  All three can be replaced while the server runs.

**The rotation has an overlap.**  A rotation does not throw the old
credential away at once: the old one keeps working for thirty minutes.
The reason is the fleet — a beacon may sleep for five minutes, a console
may have been closed since the night before.  After the overlap the old
credential is not accepted at all.

* `keys.rotate {target: "agent"}` replaces the agent PSK.  The answer
  holds the new key; the old one works until the overlap is over.
* `tokens.rotate {operator, role, scopes, expires_at}` replaces the token
  of one operator.  The scopes are the commands the token may call, the
  expiry is a unix time.
* `tokens.list` shows the role, the scopes, the expiry, the last use and
  the moment of the last rotation of every token — and never the tokens.

**The scopes are a second axis.**  A token without scopes is judged by
its role alone.  A token with scopes is judged by both: it may call what
is in the list **and** what its role allows, and nothing else.  The
scopes narrow the role; they never widen it.  A scope that names a
command nobody has heard of is refused when it is set, so a typo in a
scope does not quietly become an open door.

The scopes are read from the keyring on every call, so taking a
permission away takes effect at once — a console that is already
connected loses it the moment it is taken away.

**The keys are texts.**  A generated key is hex encoded, so the operator
can type it, copy it into the configuration of a beacon and paste it into
a ticket.  The hex is what the operator sees; the bytes behind it are what
the server checks and what the beacons read, and both sides decode the
hex the same way.  There is no "decode it first" step to get wrong, and
there is no step where one side takes the text and the other takes the
bytes -- that would leave the server and the implants without a shared
key, and the only symptom would be a beacon that never checks in.

**A key may belong to one host.**  The fleet key is a key of everybody:
whoever holds it may claim any name.  A key that is bound to one agent id
may not claim another one -- the server refuses the handshake -- so a key
that is stolen impersonates one machine and not the whole fleet.  The
binding changes nothing on the wire: the identity of the HELLO is inside
the transcript MAC either way, and the server enforces the binding where
it verifies the MAC.

**The comparison is constant time.**  A token is a secret, and the time
the server takes to refuse it says something about it.

**The TLS certificate is read at every handshake.**  A renewed certificate
is in use after the next connection, with no restart.  A file that is
half written is refused and the certificate that is already in use stays.

**The pinned key is read at every handshake too.**  A pin that is written
into the configuration of the server (`tls_client_spki`) or of the console
(`--tls-pin`, `UMBRA_TLS_PIN`) is checked on every connection, so taking a
pin away takes effect at once.  A pin that is not the hex of a SHA-256
fingerprint is refused when the configuration is read: a typo must not
leave the listener with a rule that never matches and a console that is
refused without a reason.

**A pin is rotated like a certificate.**  The operator prints the new
fingerprint of the new certificate, writes it into the configuration of the
other side and restarts the process that holds it.  Both sides may hold
the old pin and the new one during the handover: the server takes a list of
pins, the console takes one at a time.

## 4.2 The secrets that never reach the disk in the clear

**The audit trail is redacted.**  Every operator action is written to
`audit_file`, and the arguments are redacted before they are written: the
secret-bearing names (`token`, `password`, `secret`, `key`, `content`,
`data`, …) become `[redacted]`, and the arguments of the tasks that carry
material in full (`creds.add`, `file.read`, `upload`, …) are redacted as a
whole.  A task queued through `task.submit` is redacted as a whole when
its kind is one of those, so the payload never reaches the disk.  The log
still says *what* was attempted; it never says *with what*.

**The secrets are not in the process list.**  A secret that is typed on
the command line is a secret that every other program on the machine can
read out of `/proc`.  The console therefore takes the operator token
from `--token-file` or `$UMBRA_OPERATOR_TOKEN`, and the two commands that
hand out credentials (`keys rotate`, `tokens rotate`) take a file as well
(`--psk-file`, `--token-file`).  The value can still be given on the
command line for a lab; the file is the way to do it in earnest.

**The artifact store can be sealed.**  With `artifact_key` (or
`UMBRA_ARTIFACT_KEY`) the blobs and the index of the file store are
encrypted at rest with AES-256-GCM under a key derived from it.  A store
that cannot be opened with the key **refuses to open**: it does not
pretend to be empty, and it never hands out bytes it could not
authenticate.  A blob that does not authenticate is an error, not
garbage.

## 4.3 The limits of the server, one by one

This is the hardening pass over the server: what every limit is, where it
lives and what happens when it is reached.

| limit | value | what happens when it is reached |
|---|---|---|
| the frame body | 1 MiB (`wire.MaxBody`) | the frame is refused; the connection is not trusted with more |
| the frame in total | 1 MiB + header + tag | the same |
| the bytes one connection may send | 64 MiB (`max_frame_bytes_per_conn`) | the session is closed: a peer that floods is not a peer |
| the upk payload | 4 MiB (`upk.MaxTotal`) | the encoding fails; the value never reaches the wire |
| the items of one upk array or map | 1 Mi (`upk.MaxItems`) | the same |
| the length of one string | 1 Mi (`upk.MaxString`) | the same |
| the handshake | 15 s (`handshake_timeout_s`) | the connection is dropped before the first frame |
| an idle session | 120 s (`idle_timeout_s`) | the session is closed |
| the agents at the same time | 512 (`max_agents`) | the new agent is refused |
| the consoles at the same time | 16 (`max_operators`) | the new console is refused |
| the calls of one operator | 40/s, burst 120 | the call is refused; it is still audited |
| the tasks in flight for one host | 4 | the host is not given more work |
| the deliveries to one host | 60/min | the host is not given more work |
| the deliveries in the whole server | 200/s | the queue waits |
| the attempts of one task | 3 | the task goes to the dead letter queue |
| the failures of one host | 5 | the breaker of the host opens and the work is parked |
| the audit field | 512 runes | the field is cut and marked with `…` |
| the operator token | 16 bytes | the configuration is refused at start-up |
| the agent PSK | 16 bytes | the configuration is refused at start-up |
| the skew of the clock | 300 s | the handshake is refused |
| the artifact | 256 MiB | the upload is refused |
| the chunk of an artifact | 256 KiB | the chunk is refused |
| the entries of the artifact index | 4096 | the store is full |

Two rules hold everywhere: **a limit that is not set falls back to the
default** (a configuration that says nothing never means "no limit"), and
**a refused call is still audited** — "the operator tried to flood" is
exactly the kind of thing the log exists to show.

## 5. Known limitations (v0.1)

1. **No TLS in the implants.** The TCP and WebSocket transports of the Rust
   beacon are plain TCP: the payload is AEAD-sealed, but traffic shape and
   port are visible. Because the client side has no TLS stack, a
   *TLS-terminating* proxy in front of the listener cannot be used by a
   beacon -- run the transport inside an encrypted tunnel
   (WireGuard/IPsec/mTLS mesh) and keep the proxy for access control and rate
   limiting, or use the mutual TLS listener with a beacon that speaks TLS.
   Native TLS (rustls) is the natural next step and is deliberately not pulled
   in yet to keep the dependency set at "crypto only".
2. **Padding only on the HTTP transport.** `http_pad` rounds the request and
   reply bodies to a bucket; the TCP, WebSocket and DNS transports still
   expose the size of a frame.
3. **Server-side plaintext.** Agent metadata, task output and file transfers are
   stored in the clear in `data_file`. Encrypt-at-rest (e.g. age/SQLCipher) is
   not implemented.
4. **Single key hierarchy.** One agent PSK for all implants. Per-implant keys
   (with a server-side enrollment step) would contain a single leaked beacon.
5. **Server-side plaintext, again.** The state file holds the task queue, the
   chat history and the schedules; it is `0600` and written atomically, but it
   is not encrypted.
6. **Not stealthy.** Process execution uses the platform shell, the Android build
   shows a notification, and the in-memory modules leave traces in the memory
   of the process. The implant wipes the module image from its own memory once
   it has run, so a dump taken later does not hand the module back, but the
   module itself still executed in a process that a memory scanner can find.
   This is a *protocol and framework* foundation, not an evasion toolkit.
7. **The Go reference server supports only AES-256-GCM.** Go's standard library
   has no ChaCha20-Poly1305; the suite id is reserved and implemented in the Rust
   and Python clients, so enabling it server-side is a library addition rather
   than a protocol change.
8. **The reconnaissance is a snapshot, not a graph.** The `recon` task
   reports the groups of the current user, the users logged on to the machine
   and the domain controllers of the domain. It does not walk the directory,
   it does not enumerate the machines of the domain and it does not resolve
   group memberships recursively: it is what the logged on account can see
   with the tools the system already carries. A graph that is wrong because
   the account is wrong is worse than no graph, so the edges are reported as
   they were observed, not as a conclusion.
9. **The console trusts the server certificate it is given.** `--tls-ca` pins
   the authority; the operator has to check that the name matches. There is no
   certificate transparency and no pinning of a leaf certificate.
10. **The keylogger of a mac asks for a permission.** The event tap of macOS
    needs the accessibility permission of the user.  The implant says so
    instead of pretending to listen, and the tap is created listen-only, so
    the keyboard of the user is never taken away from them.
11. **The accessibility service of a phone sees the screen.** An enabled
    accessibility service may read the window of every application and act
    on it, so the operator of a phone with that service enabled can read
    what the user is looking at and press the buttons of the phone.  The
    technique is visible -- it is listed in the settings of Android and
    Android shows a notification while it runs -- and the report of the
    persistence says so, but a phone with that service enabled is no longer
    a private device.  The implant does not pretend otherwise: the guide of
    the host says whether the service is on, and a task that needs it fails
    with a clear message when it is off.
12. **The senses of a phone are the senses of a person.** The location, the
    messages, the call log, the address book, the clipboard, the microphone
    and the camera of a phone belong to the person who carries it, and the
    implant takes all of them when the user of the phone grants the
    permissions.  The platform limits what a phone can be made to do, and
    the implant says what the limit is instead of pretending that the
    phone has nothing to give:

    * the **call log** belongs to the default dialler and to the carrier
      applications since Android 10; an ordinary application asks the user
      for the permission, and the answer says "not granted" when it was
      refused;
    * the **messages** reach an application only when the platform still
      delivers the broadcast, which since Android 19 means the default
      messenger; the watcher says whether the phone is the default
      messenger;
    * the **clipboard** belongs to the application that has the focus since
      Android 10, so the watcher sees a copy only when the implant is in
      the foreground or when it is the keyboard of the phone;
    * the **capture of the screen** needs the button of the system dialog,
      every time it starts, and the phone shows a notification while it
      runs;
    * the **microphone** and the **camera** of a phone show an indicator in
      the status bar, and the foreground service that carries them says so
      in its own notification;
    * the **databases of the other applications** are not readable without
      root, and the answer says that instead of returning an empty list.

    The guide of the host lists every permission with its state, so the
    operator knows exactly what the user of the phone granted -- and an
    engagement that is not authorised has no business asking for them.
13. **The false screen is a deception.** The overlay of the `phish.overlay`
    task draws a form over the application the operator named, and what
    the user types into it travels to the operator.  The technique is in
    the catalogue of every mobile red team, and it is used here only
    against a phone the operator is authorised to test: the phone of the
    engagement, on the agreement of the owner of the device.  The overlay
    is on the screen of the phone while it waits, the operator may dismiss
    it at any moment, and the guide of the host says that the permission
    to draw over the other applications is one of the permissions the user
    of the phone grants.

## 6. Hardening advice

* Bind the operator listener to loopback; tunnel it.
* Use the mutual TLS listener for a remote console: `tls_client_ca` is
  mandatory there, so a stolen token alone is not enough.
* Run the HTTP transport inside a tunnel; in the proxy keep
  `proxy_request_buffering off` and a per-client rate limit.
* Set `http_pad` to a bucket that fits your biggest reply, so the length of a
  request does not tell what it carried.
* Keep the operator's notebook out of backups and out of shared machines
  (`umbra db export` produces a portable copy); delete it with the
  engagement.
* Leave the sleep obfuscation on (`UMBRA_SLEEP_OBFUSCATE=0` switches it off).
  A beacon that checks in on a metronome is a beacon that is easy to write a
  signature for.
* Keep both ends on NTP — a 300 s skew rejects handshakes.
* Rotate the agent PSK per engagement; treat it as a per-campaign secret.
* Watch the server log for `handshake failed` bursts (probing),
  `agent exceeded frame budget` (hostile or broken peer) and
  `http request with an unexpected host header` (a fronting request that
  reached the origin directly).
* Restrict implant egress to the single C2 host/port.
* Keep the armory key offline; sign the catalogue on a machine that does not
  run the server.
* Back up `data_file`; losing it loses the engagement history (and the queue).

## 7. Reporting a vulnerability

Open a private security advisory on the repository (or contact the maintainer
directly). Do not open a public issue for anything that could let an
unauthenticated peer decrypt traffic, bypass the handshake, or escape the frame
budget/limits.
