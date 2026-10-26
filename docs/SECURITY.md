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

What it does **not** hide: that something is talking to the C2 (traffic analysis),
and message sizes (the length lives in the prelude; padding is on the roadmap).

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
| Operator token | full control of that operator identity: list agents, queue tasks, read results | cannot enrol implants, cannot authenticate as another operator |
| `sid` (HTTP path) | can target the session with frames | cannot decrypt or forge: every frame is AEAD-sealed and nonce-ordered; wrong frames kill the session |
| Team server host | everything | rotate all secrets, rebuild implants |

Per-operator tokens are bound to the operator's name inside the authenticated
transcript, so having one token does not let you claim another identity.

Accountability is separate from authentication: every operator command is
written to the audit log with the operator name, source address, transport and
outcome, so a stolen token does not give the attacker an unattributable window.
The log is append-only from the server's point of view (`O_APPEND`, `0600`,
fsync per line, size rotation) and can be read back with `umbra audit`. See
`docs/OPERATIONS.md` §5a. Operators are also rate limited (120 burst / 40 s⁻¹)
so a runaway console cannot starve beacon traffic.

## 3. Secret handling

* Secrets come from environment variables or `0600` files, never from the JSON
  config file.
* The server logs only SHA-256 fingerprints (first 16 hex chars) of operator
  tokens.
* The console prefers `--token-file` or `$UMBRA_OPERATOR_TOKEN`; `--token` leaks
  into the process list.
* PSK/token minimum length enforced at start-up: 16 bytes.
* Rotate on personnel change: remove the entry from `UMBRA_OPERATOR_TOKENS`,
  restart, and delete the agent PSK if implants are retired.

## 4. Known limitations (v0.1)

1. **No TLS in the implants.** The TCP transport is plain TCP and the HTTP
   transport is plain HTTP/1.1; the payload is AEAD-sealed, but traffic shape and
   port are visible. Because the client side has no TLS stack, a *TLS-terminating*
   proxy in front of the listener cannot be used by a beacon -- run the transport
   inside an encrypted tunnel (WireGuard/IPsec/mTLS mesh) and keep the proxy for
   access control and rate limiting. Native TLS (rustls) is the natural next step
   and is deliberately not pulled in yet to keep the dependency set at
   "crypto only".
2. **No traffic padding.** Message sizes leak (`CHECKIN` is tiny, `RESULT` with a
   file download is huge).
3. **Server-side plaintext.** Agent metadata, task output and file transfers are
   stored in the clear in `data_file`. Encrypt-at-rest (e.g. age/SQLCipher) is
   not implemented.
4. **Single key hierarchy.** One agent PSK for all implants. Per-implant keys
   (with a server-side enrollment step) would contain a single leaked beacon.
5. **No authorisation granularity.** Every operator can do everything.
6. **Not stealthy.** Process execution uses the platform shell, the Android build
   shows a notification, and there is no loader, packer or injection. This is a
   *protocol and framework* foundation, not an evasion toolkit.
7. **The Go reference server supports only AES-256-GCM.** Go's standard library
   has no ChaCha20-Poly1305; the suite id is reserved and implemented in the Rust
   and Python clients, so enabling it server-side is a library addition rather
   than a protocol change.
8. **Python console has no certificate pinning.** Not applicable to v0.1 (plain
   TCP operator link, meant for loopback/SSH), but relevant if the operator link
   ever becomes network-exposed.

## 5. Hardening advice

* Bind the operator listener to loopback; tunnel it.
* Run the HTTP transport inside a tunnel; in the proxy keep
  `proxy_request_buffering off` and a per-client rate limit.
* Keep both ends on NTP — a 300 s skew rejects handshakes.
* Rotate the agent PSK per engagement; treat it as a per-campaign secret.
* Watch the server log for `handshake failed` bursts (probing) and
  `agent exceeded frame budget` (hostile or broken peer).
* Restrict implant egress to the single C2 host/port.
* Back up `data_file`; losing it loses the engagement history (and the queue).

## 6. Reporting a vulnerability

Open a private security advisory on the repository (or contact the maintainer
directly). Do not open a public issue for anything that could let an
unauthenticated peer decrypt traffic, bypass the handshake, or escape the frame
budget/limits.
