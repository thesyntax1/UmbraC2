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

### 3.8 The operator's notebook (`umbra_cli/db.py`)

* The console writes the tasks it submitted, their results and its own notes
  into a local SQLite file (`~/.umbra/state.db` by default).
* The notebook holds **task output**. It never holds a credential: the
  operator token, the agent PSK and the session keys stay in memory. The
  material in it is the same material the server already keeps in its state
  file -- the difference is that the notebook is on the operator's own disk
  and nobody else knows it exists.
* The file is created with the permissions of the process that creates it
  (0600 under a normal umask). It is not encrypted: treat it like the
  server's state file and delete it when the engagement ends.
* `--db` (or `UMBRA_DB`) moves it; an empty value switches it off.

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
* Rotate on personnel change: remove the entry from `UMBRA_OPERATOR_TOKENS`,
  restart, and delete the agent PSK if implants are retired.

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
