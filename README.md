# UmbraC2

Modular, high-performance command-and-control framework written from scratch:
a Go team server, Rust beacons for Windows/Linux/macOS, a Kotlin/Native-assisted
Android implant, and a Python operator console.

Everything on the wire is authenticated and encrypted with per-connection
X25519 + HKDF-SHA256 + AES-256-GCM. There is no cleartext path in the protocol —
not even the handshake.

> **Authorised testing only.** This code exists for red-team engagements, lab
> research and detection engineering on systems you own or have written
> permission to test. See [docs/SECURITY.md](docs/SECURITY.md).

## Status

| Component | Language | State |
|---|---|---|
| Team server (TCP + HTTP + WebSocket + DNS + mutual TLS, agent/operator links, task queue) | Go 1.22 (stdlib only) | v0.1 core |
| Beacon (beaconing, task execution, TCP + HTTP + WebSocket + DNS, pivots, tunnel) | Rust 1.75+ | v0.1 core |
| Implant (foreground service, JNI recon, task execution, pivot callback) | Kotlin + C++ (NDK) | v0.1 core |
| Operator console + protocol reference implementation | Python 3.9+ | v0.1 core |
| Protocol spec + cross-language conformance vectors | `docs/`, `contracts/` | v0.1 |

Implemented end-to-end in this version: mutual authentication, session
establishment, beacon check-in, task dispatch and result collection, beacon
sleep/jitter control, key rotation, live operator event stream, agent inventory
and task history persisted across restarts, TCP and HTTP transports, and an
append-only operator audit trail (`umbra audit`) with per-operator RPC rate
limiting.

Added on top of that core:

| Area | What works | Where |
|---|---|---|
| Pivoting | SOCKS5 proxy and TCP port forward through a compromised agent, agent-initiated callback sessions, peer-to-peer chains between implants | [docs/PIVOTING.md](docs/PIVOTING.md) |
| Layer-3 tunnel | An encrypted tunnel between the console and the implants: every agent gets an address in the tunnel network | [docs/PIVOTING.md](docs/PIVOTING.md#the-layer-3-tunnel) |
| DNS transport | The beacon talks to the server through TXT records when everything else is blocked | [docs/PIVOTING.md](docs/PIVOTING.md#the-dns-transport) |
| In-memory modules | COFF/BOF objects and PE images are loaded and executed without touching the disk | [docs/EXTENSIONS.md](docs/EXTENSIONS.md) |
| Post-exploitation | Reflective loading, process migration, token impersonation, credential collection, privilege helpers | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#post-exploitation) |
| Extension store | A signed catalogue of modules, installed on the server and pushed to the agents | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#the-extension-store) |
| Command namespace | Named task templates (`umbra alias`) shared by the whole team | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#the-command-namespace) |
| Stagers | One-line PowerShell and Bash stagers with the agent key baked in | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#stagers) |
| Team work | Focus/presence, task claims, directed chat, and one `team.sync` snapshot of the whole team | [docs/PROTOCOL.md](docs/PROTOCOL.md#operator-rpcs) |
| Covert channels | WebSocket and DNS transports, mutual TLS for the console, traffic padding, domain fronting through a configurable `Host` header | [docs/TRANSPORTS.md](docs/TRANSPORTS.md) |
| Reconnaissance | Host facts, BloodHound-style domain edges, and awareness of debuggers and sandboxes | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#reconnaissance) |
| Operator state | The console keeps its own SQLite notebook: the tasks it ran, their results and the notes it left | [docs/OPERATIONS.md](docs/OPERATIONS.md#the-operators-notebook) |
| Traffic hygiene | Sleep obfuscation on top of the jitter, and module images wiped from memory once they have run | [docs/SECURITY.md](docs/SECURITY.md) |
| Inventory and group work | The agent list is filtered by state, transport, OS, architecture, tag and user, hosts carry operator-owned tags, and one task or one policy reaches a whole group | [docs/OPERATIONS.md](docs/OPERATIONS.md#3a-working-on-groups-of-agents) |
| Interactive sessions | A real shell on the target: the operator types, the beacon streams, and the session survives a re-connect | [docs/OPERATIONS.md](docs/OPERATIONS.md#3b-interactive-sessions-chains-and-alerts) |
| Task chains | Several tasks in a row, where the output of one becomes the input of the next | [docs/PROTOCOL.md](docs/PROTOCOL.md#72d-multi-stage-tasks) |
| Alerts | The server watches its own event stream and raises an alert when a rule matches | [docs/PROTOCOL.md](docs/PROTOCOL.md#72e-alert-rules) |
| Host triage | Hashes, entropy and file type of a file on the target, a search by name or content, and the network configuration | [docs/OPERATIONS.md](docs/OPERATIONS.md#3b-interactive-sessions-chains-and-alerts) |

Not in this version (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#roadmap)):
S3 and SMTP transports, named-pipe pivots, a WASM sandbox for task modules,
TLS inside the implant binaries, and a Go implant.

## Quick start (5 commands, no Go/Rust needed)

The Python reference implementation can drive the whole protocol, which makes it
the fastest way to see the framework working:

```bash
python3 -m venv .venv && .venv/bin/pip install -e operator pytest

# terminal 1: development server + a fake agent that executes commands
UMBRA_PSK=$(python3 -c 'import os;print(os.urandom(32).hex())')
python3 tools/mock_server.py --port 4002 --psk "$UMBRA_PSK" \
        --operator alice:supersecret-operator-token-123 --spawn-agent

# terminal 2: operator console
UMBRA_OPERATOR_TOKEN=supersecret-operator-token-123 \
  .venv/bin/python -m umbra_cli --server 127.0.0.1:4002 --operator alice --watch
```

```
umbra[-]> agents
umbra[-]> use agent-mock-1
umbra[agent-mock-1]> run id
umbra[agent-mock-1]> exec sysinfo
umbra[agent-mock-1]> get /etc/hostname ./hostname   # chunked, hash-verified pull
```

## Quick start (real components)

```bash
# 1. secrets
export UMBRA_AGENT_PSK=$(openssl rand -hex 32)
export UMBRA_OPERATOR_TOKENS="alice:$(openssl rand -hex 32)"

# 2. team server (Go 1.22+)
make server
./build/umbra-server -config deploy/server.dev.json

# 3. beacon (Rust 1.75+), configuration is baked in at build time
UMBRA_SERVER=127.0.0.1:4001 UMBRA_PSK=$UMBRA_AGENT_PSK \
  UMBRA_AGENT_ID=laptop-1 cargo build --manifest-path implant/rust/Cargo.toml --release
./implant/rust/target/release/umbra-beacon --verbose

# 4. operator console (Python 3.9+)
make operator
umbra --server 127.0.0.1:4002 --operator alice \
      --token "${UMBRA_OPERATOR_TOKENS#alice:}" agents
```

Cross-compilation for every platform is documented in
[docs/BUILD.md](docs/BUILD.md) and automated by `make cross-linux`,
`make cross-windows`, `make cross-macos` and `make android-apk`.

## Repository layout

```
UmbraC2/
├── contracts/vectors.json        # THE cross-language contract (encoding, KDF, frame bytes)
├── server/                       # Go team server (stdlib only, no third-party modules)
│   ├── cmd/umbra-server/         #   entry point, flags, signal handling
│   └── internal/
│       ├── upk/                  #   canonical binary encoding
│       ├── wire/                 #   frame format + message registry
│       ├── crypt/                #   X25519, HKDF-SHA256, AES-256-GCM, handshake MACs
│       ├── session/              #   per-connection keys, nonces, rekey
│       ├── config/               #   JSON config + keyring
│       ├── store/                #   agents/tasks, atomic JSON snapshots
│       ├── hub/                  #   broker: registry, queue, operator events
│       └── link/                 #   transports: agent TCP, operator TCP, HTTP, WebSocket, DNS
├── implant/
│   ├── rust/                     # Rust beacon (Windows/Linux/macOS)
│   │   ├── src/{upk,crypto,wire,session,transport,task,beacon}.rs
│   │   ├── src/{link,tunnel,vpn,dns,ws,bof,post}.rs   # pivoting, tunnels, transports, modules
│   │   ├── src/{domain,evade}.rs                     # domain recon, debugger/sandbox awareness
│   │   └── tests/vectors.rs      #   same vectors as Go and Python
│   └── android/                  # Kotlin implant + C++/JNI recon helpers
├── operator/umbra_cli/           # Python reference implementation + operator console
│   └── db.py                     #   the console's local notebook (SQLite)
├── tools/                        # mock server, reference agent, vector generator
├── deploy/                       # configs, systemd unit, TLS reverse-proxy example
├── scripts/                      # cross-build + secret generation helpers
└── docs/                         # protocol, architecture, build, operations, security
```

## Documentation

| Document | Contents |
|---|---|
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | wire format, handshake, key schedule, every message type |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | component design, data flow, decisions, roadmap |
| [docs/BUILD.md](docs/BUILD.md) | build & cross-compilation for every target, testing |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | deployment, secrets, hardening, troubleshooting |
| [docs/TRANSPORTS.md](docs/TRANSPORTS.md) | every transport, the traffic-shaping knobs, how to choose one |
| [docs/PIVOTING.md](docs/PIVOTING.md) | SOCKS5, port forwards, peer-to-peer links, the layer-3 tunnel |
| [docs/EXTENSIONS.md](docs/EXTENSIONS.md) | the extension store, the command namespace, stagers, in-memory modules, reconnaissance |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, cryptographic choices, attack surface, limitations |

## Tests

```bash
make test          # cross-language checks + go test + cargo test + pytest
make doctor        # what toolchains are present; nothing here is fatal
make check         # static only: constant tables + symbol resolution (no toolchain)
make test-py       # protocol vectors + end-to-end (works with Python only)
make vectors       # regenerate contracts/vectors.json after a protocol change
```

`contracts/vectors.json` pins the canonical encoding, the key schedule, the
handshake transcripts and full frame bytes. The Go, Rust and Python suites all
read it, so the three implementations cannot drift apart silently.

Three checks cover the parts a single suite cannot see, and all of them run in
CI (`.github/workflows/ci.yml`):

* `tools/check_consistency.py` diffs the constant *tables* (message ids, limits,
  domain labels, task kinds, operator RPC commands) across Python, Go, Rust and
  Kotlin, and against `docs/PROTOCOL.md`;
* `tools/check_symbols.py` resolves every cross-package Go and Rust reference
  without a compiler;
* `tests/test_protocol.py` includes concurrency regressions for the two rules
  that are easy to break silently: a nonce is never reused, and frames leave in
  nonce order (see SEND-SERIAL in `docs/PROTOCOL.md`).

## License

MIT — see [LICENSE](LICENSE). The Rust crate is dual-licensed `MIT OR Apache-2.0`
to match the ecosystem default (see `implant/rust/Cargo.toml`).

This project exists for authorised security testing, red-team engagements and
protocol research. Running it against systems you do not own or have written
permission to test is illegal in most jurisdictions; you are responsible for how
you use it. See [docs/SECURITY.md](docs/SECURITY.md) §1.
