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
| Team server (TCP + HTTP transports, agent/operator links, task queue) | Go 1.22 (stdlib only) | v0.1 core |
| Beacon (beaconing, task execution, TCP + HTTP) | Rust 1.75+ | v0.1 core |
| Implant (foreground service, JNI recon, task execution) | Kotlin + C++ (NDK) | v0.1 core |
| Operator console + protocol reference implementation | Python 3.9+ | v0.1 core |
| Protocol spec + cross-language conformance vectors | `docs/`, `contracts/` | v0.1 |

Implemented end-to-end in this version: mutual authentication, session
establishment, beacon check-in, task dispatch and result collection, beacon
sleep/jitter control, key rotation, live operator event stream, agent inventory
and task history persisted across restarts, TCP and HTTP transports, and an
append-only operator audit trail (`umbra audit`) with per-operator RPC rate
limiting.

Not in this version (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#roadmap)):
peer-to-peer pivoting, SOCKS/proxy pivots, reflective loaders, process
injection, BOF/COFF execution, S3/DNS transports, multi-player chat.

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
│       └── link/                 #   transports: agent TCP, operator TCP, HTTP
├── implant/
│   ├── rust/                     # Rust beacon (Windows/Linux/macOS)
│   │   ├── src/{upk,crypto,wire,session,transport,task,beacon}.rs
│   │   └── tests/vectors.rs      #   same vectors as Go and Python
│   └── android/                  # Kotlin implant + C++/JNI recon helpers
├── operator/umbra_cli/           # Python reference implementation + operator console
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
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, cryptographic choices, limitations |

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
