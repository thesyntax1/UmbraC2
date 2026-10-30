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
| Pivoting | SOCKS5 proxy and TCP port forward through a compromised agent, agent-initiated callback sessions, peer links with a real handshake and a rekey, and chains of pivots that the server resolves from the far end | [docs/PIVOTING.md](docs/PIVOTING.md) |
| Layer-3 tunnel | An encrypted tunnel between the console and the implants: every agent gets an address in the tunnel network | [docs/PIVOTING.md](docs/PIVOTING.md#the-layer-3-tunnel) |
| DNS transport | The beacon talks to the server through TXT records when everything else is blocked | [docs/PIVOTING.md](docs/PIVOTING.md#the-dns-transport) |
| In-memory modules | COFF/BOF objects and PE images are loaded and executed without touching the disk | [docs/EXTENSIONS.md](docs/EXTENSIONS.md) |
| The module ABI | Every module carries a signed manifest: the version, the argument schema, the output schema and the capabilities it needs. A module that asks for more than the host has is never pushed to it | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#31-the-module-abi) |
| Sandboxed modules | A webassembly interpreter and a script dialect: a module computes, parses and decrypts without ever being native code, and the host API is capability limited | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#the-sandboxed-loaders) |
| Post-exploitation | Reflective loading, process migration, token impersonation, credential collection, privilege helpers | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#post-exploitation) |
| Extension store | A signed catalogue of modules, installed on the server and pushed to the agents | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#the-extension-store) |
| Command namespace | Named task templates (`umbra alias`) shared by the whole team | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#the-command-namespace) |
| Stagers | One-line PowerShell and Bash stagers for every transport, with the agent key baked in: the beacon comes from a url, from the file store of the server, from inside the stager, or behind a digest shim | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#stagers) |
| Team work | Focus/presence, task claims, directed chat, and one `team.sync` snapshot of the whole team | [docs/PROTOCOL.md](docs/PROTOCOL.md#operator-rpcs) |
| The presence that expires | A console that stops talking goes silent and then stale, and the claim it holds expires with it: a crashed console never keeps a task to itself | [docs/OPERATIONS.md](docs/OPERATIONS.md#5e1-the-presence-the-lease-and-the-handover) |
| Working as a team | A task is handed to a colleague, the namespace is shared, the chat carries mentions, and `umbra handover` writes the document that goes with the shift | [docs/OPERATIONS.md](docs/OPERATIONS.md#5e1-the-presence-the-lease-and-the-handover) |
| The workflow layer | A named, parameterised sequence of steps — a task, a chain, a wait, a condition, a report — written by the team and run on the server: `umbra workflow run sweep --param target=web-01` | [docs/PROTOCOL.md](docs/PROTOCOL.md#72m-the-workflow-layer) |
| The plan | The same thing as a file: a small YAML subset the console reads itself, no dependency: `umbra batch --file sweep.yaml` | [docs/OPERATIONS.md](docs/OPERATIONS.md#5g-the-operators-experience) |
| One task, many agents | `umbra run --group dc --kind sysinfo --cap 8 --wait` queues the task everywhere, waits with a cap, and shows the answer of every host | [docs/OPERATIONS.md](docs/OPERATIONS.md#5g-the-operators-experience) |
| The shell that remembers | The prompt says what the console is looking at, the history survives the session, the completion knows the agents by name, and a command may span several lines | [docs/OPERATIONS.md](docs/OPERATIONS.md#5g-the-operators-experience) |
| The notebook | The operator's own SQLite file holds the notes, the findings, the artefacts, the screenshots and the material, searchable and exportable as Markdown | [docs/OPERATIONS.md](docs/OPERATIONS.md#5g-the-operators-experience) |
| Covert channels | WebSocket and DNS transports, mutual TLS for the console, traffic padding, domain fronting through a configurable `Host` header | [docs/TRANSPORTS.md](docs/TRANSPORTS.md) |
| Certificate pinning | The console pins the key of the server and the server pins the key of the console: the fingerprint of the public key, compared in constant time, checked before the token leaves the console | [docs/OPERATIONS.md](docs/OPERATIONS.md#pinning-the-console) |
| The route of an agent | The operator says which transport an agent speaks, in which order it may fall back, and which front domain it hides behind; the beacon follows the route | [docs/OPERATIONS.md](docs/OPERATIONS.md#the-route-of-an-agent) |
| Reconnaissance | Host facts, BloodHound-style domain edges, and awareness of debuggers and sandboxes | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#reconnaissance) |
| Reconnaissance profiles | One task runs a named bundle of checks — the users, the shares, the listeners, the WMI subscriptions, the browser data, the cloud credentials, the container escape surface — and answers with the findings, scored | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#the-profiles) |
| The map of the domain | The paths from the identity the implant runs as to the domain controller, not the raw edges | [docs/EXTENSIONS.md](docs/EXTENSIONS.md#the-map-of-the-domain) |
| Operator state | The console keeps its own SQLite notebook: the tasks it ran, their results and the notes it left | [docs/OPERATIONS.md](docs/OPERATIONS.md#the-operators-notebook) |
| Traffic hygiene | Sleep obfuscation on top of the jitter, and module images wiped from memory once they have run | [docs/SECURITY.md](docs/SECURITY.md) |
| Inventory and group work | The agent list is filtered by state, transport, OS, architecture, tag and user, hosts carry operator-owned tags, and one task or one policy reaches a whole group | [docs/OPERATIONS.md](docs/OPERATIONS.md#3a-working-on-groups-of-agents) |
| Interactive sessions | A real shell on the target: the operator types, the beacon streams, and the session survives a re-connect | [docs/OPERATIONS.md](docs/OPERATIONS.md#3b-interactive-sessions-chains-and-alerts) |
| Task chains | Several tasks in a row, where the output of one becomes the input of the next | [docs/PROTOCOL.md](docs/PROTOCOL.md#72d-multi-stage-tasks) |
| Alerts | The server watches its own event stream and raises an alert when a rule matches | [docs/PROTOCOL.md](docs/PROTOCOL.md#72e-alert-rules) |
| Host triage | Hashes, entropy and file type of a file on the target, a search by name or content, and the network configuration | [docs/OPERATIONS.md](docs/OPERATIONS.md#3b-interactive-sessions-chains-and-alerts) |
| Staying alive | The implant installs itself so it survives a reboot, takes the start-up entries away again, replaces itself with a verified new build, and dials a list of servers through a proxy | [docs/OPERATIONS.md](docs/OPERATIONS.md#keeping-the-implant-alive) |
| Reliability | A task that is never answered fails instead of hanging forever, and the server sweeps the queue every 30 s | [docs/OPERATIONS.md](docs/OPERATIONS.md#5-state-and-recovery) |
| The predictable queue | The urgent task goes first, a host that is already busy is not given more work, the server hands out a bounded number of tasks per second, and a task that failed too often is parked in the dead letter queue | [docs/PROTOCOL.md](docs/PROTOCOL.md#72o-the-queue-the-breakers-and-the-traces) |
| Surviving a bad operator | The server counts the failures of a host and opens its circuit breaker, and a maintenance window stops the traffic without stopping the server | [docs/OPERATIONS.md](docs/OPERATIONS.md#5h-the-queue-the-breakers-and-the-metrics) |
| The metrics | The counters of the server in the Prometheus text format: the depth of the queue, the latency histogram, the rate of the check-ins, the rate of the failures, the mix of the transports and the bytes that moved | [docs/OPERATIONS.md](docs/OPERATIONS.md#5h-the-queue-the-breakers-and-the-metrics) |
| The trace | Every task carries a trace id from the operator to the implant and back: the record, the events and the audit trail all carry it | [docs/PROTOCOL.md](docs/PROTOCOL.md#72o-the-queue-the-breakers-and-the-traces) |
| The versions of the protocol | Two handshake versions are spoken at the same time: the capability list, the implant version, the module ABI and the platform details are fields of their own, and the answer is always in the version the peer asked for | [docs/PROTOCOL.md](docs/PROTOCOL.md#51-the-handshake-versions-and-who-speaks-to-whom) |
| The heartbeat | A small frame between two check-ins: the host is alive, and this is how busy it is | [docs/PROTOCOL.md](docs/PROTOCOL.md#72p-the-heartbeat) |
| The credentials | The agent key and the operator tokens are rotated while the server runs, the tokens carry scopes and an expiry, and the audit trail never writes a secret down | [docs/SECURITY.md](docs/SECURITY.md#41-the-credentials-of-the-server-and-how-they-are-rotated) |
| The state that survives | The snapshot is written at least once a minute, the write is atomic, the last three generations are kept, and the recovery procedure is written down | [docs/RUNBOOK.md](docs/RUNBOOK.md#the-recovery-procedure) |
| The deployment | A systemd unit, a container image, a compose file, a reverse-proxy sample and a hardened configuration with every key documented | [deploy/](deploy/), [docs/RUNBOOK.md](docs/RUNBOOK.md) |
| The way a team works | A command namespace of saved commands, a failed task that can be run again, and a report of an agent for the handover | [docs/OPERATIONS.md](docs/OPERATIONS.md#3-operator-workflow) |
| The journal | Every event is numbered and kept, so a console that was not watching can still ask what it missed | [docs/OPERATIONS.md](docs/OPERATIONS.md#3-operator-workflow) |
| The dashboard | A web view of the inventory, the tasks and the event stream, on the same tokens as the console | [docs/OPERATIONS.md](docs/OPERATIONS.md#3c-the-dashboard) |
| The open sessions | The interactive sessions that are running, with the moment they last said something | [docs/OPERATIONS.md](docs/OPERATIONS.md#3b-interactive-sessions-chains-and-alerts) |
| The end of it | One command clears the record of the engagement: the agents, the tasks and the schedules | [docs/OPERATIONS.md](docs/OPERATIONS.md#5-state-and-recovery) |
| The process table | The pid, the parent, the user, the start time and the command line of every process, read from the operating system, and a process killed by its pid or by its name | [docs/OPERATIONS.md](docs/OPERATIONS.md#3-operator-workflow) |
| The files | A directory with its permissions and timestamps, the end of a log, the digest of a file | [docs/OPERATIONS.md](docs/OPERATIONS.md#3-operator-workflow) |
| The Windows registry | A key with its values and its subkeys, read through the platform's own API | [docs/OPERATIONS.md](docs/OPERATIONS.md#3-operator-workflow) |
| The keyboard | The keys as they are pressed, streamed or written into a file to be fetched later | [docs/OPERATIONS.md](docs/OPERATIONS.md#3-operator-workflow) |
| What a host can do | Every beacon says which task kinds it implements, the server refuses the rest, and the operator sees the list in the inventory | [docs/PROTOCOL.md](docs/PROTOCOL.md#72f-capabilities-the-artifact-store-and-burning-an-engagement) |
| The server's file store | A file goes onto the server once and is pushed to every host that needs it, in verified chunks | [docs/OPERATIONS.md](docs/OPERATIONS.md#3d-the-artifact-store) |
| The network reach | A port scan of a range, a name resolution and the environment of the host, straight from the target | [docs/OPERATIONS.md](docs/OPERATIONS.md#3-operator-workflow) |
| The end of it, on the target | One command tells the beacons to exit and stops the server from feeding them any more work | [docs/OPERATIONS.md](docs/OPERATIONS.md#5-state-and-recovery) |
| Staying installed | A manager around a catalogue of start-up techniques — seventeen on Windows, fifteen on Linux, six on macOS, seven on the phone: it picks the quietest one the host can carry, verifies it, migrates between them and takes them all away again | [docs/OPERATIONS.md](docs/OPERATIONS.md#keeping-the-implant-alive) |
| Knowing the host | A posture engine that says what the machine is, adjusts the schedule and the traffic to it, and stops the implant when the operator says so | [docs/OPERATIONS.md](docs/OPERATIONS.md#knowing-the-host) |
| The credential vault | Every piece of material is a record with a kind, a source and a confidence; the value is redacted by default, encrypted at rest and only handed out when the operator asks for it | [docs/OPERATIONS.md](docs/OPERATIONS.md#the-material-and-the-vault) |
| The token work | The tokens of a host, an impersonation that lasts one task or until the operator takes it back, and the identity in the inventory | [docs/OPERATIONS.md](docs/OPERATIONS.md#the-material-and-the-vault) |
| The remote execution | A command that runs on a far host over WinRM, WMI, DCOM, SMB, LDAP or SSH, driven from the agent that holds the path to it | [docs/OPERATIONS.md](docs/OPERATIONS.md#running-a-command-on-a-far-host) |
| The reach | Every pivot drawn as a graph: the agents, the tunnels between them, the bytes that moved, the clients of the proxy, the targets it refuses and the claims that tear a group of tunnels down | [docs/OPERATIONS.md](docs/OPERATIONS.md#3e-the-reach) |
| IPv6 | The transports, the pivot, the scan and the peer link keep the family of the address: a host on an IPv6-only network is reached with the same commands | [docs/OPERATIONS.md](docs/OPERATIONS.md#ipv6) |
| The transports that keep no connection | The beacon mails its frames out and polls its mailbox, or reads its work from one bucket and writes its results into another: two transports for the networks where nothing else gets through | [docs/TRANSPORTS.md](docs/TRANSPORTS.md#10-the-transports-without-a-connection) |
| The pivot on a named pipe | On a Windows server the pivot may listen on a named pipe: no port, no firewall rule, nothing a scanner would see | [docs/PIVOTING.md](docs/PIVOTING.md#the-named-pipe) |
| The layer-3 tunnel, finished | The peers have their addresses, the networks behind them are routed to them, the operator can ask a peer whether it is there, and a peer behind another agent joins its relay | [docs/OPERATIONS.md](docs/OPERATIONS.md#the-layer-3-tunnel) |
| The Go implant | A fourth implementation of the protocol, in the standard library of Go and with nothing else: it checks in, runs the task kinds it advertises and answers the ones it does not know with an error instead of a silence | [implant/go/README.md](implant/go/README.md) |
| The phone | The Android implant is not a toy: a real foreground service with a notification, the persistence of the phone (boot receiver, foreground service, alarm, job scheduler, re-launch after an update, accessibility service, device owner) that is verified and can be taken away again, the tunnel, the senses of the phone (the place, the networks around it, the messages, the calls, the contacts, the microphone, the camera, the screen, the laboratory) with the watchers that keep what arrives, and a capability list that says what the phone can do | [docs/OPERATIONS.md](docs/OPERATIONS.md#3f-the-implants) |
| The senses of the desktop | A workstation is not a shell: the window table (the API of Windows, the accessibility of the mac, `wmctrl` on Linux), the clipboard in a queue that survives a reboot, the screen streamed frame by frame, the saved networks and their keys, the accounts of the browsers, the security software that watches the machine, the USB keys and the memory of a process -- every family saying what it could not read | [docs/PROTOCOL.md](docs/PROTOCOL.md#72v-the-senses-of-the-desktop) |
| Leaving nothing behind | The zero-footprint wipe: the survey of what the engagement left on a host, the removal of the traces family by family, the verification of what is left, the surface an analyst would find, the journal of the engagement, the dead man's switch and the self-destruction of the implant -- the history of the user scrubbed and never deleted, the limits of the platform named instead of pretended away, every report signed so the proof outlives the host | [docs/PROTOCOL.md](docs/PROTOCOL.md#72w-the-zero-footprint-wipe) |
| The mac as a first-class target | The persistence, the registry equivalents (property lists, the defaults of a domain, the jobs of launchd) and the desktop (the screen, the clipboard, the keys) work on a mac as well | [docs/OPERATIONS.md](docs/OPERATIONS.md#the-mac-is-a-first-class-target) |
| A key for every host | The fleet key is a key of everybody; a key that belongs to one agent id may not claim another name, so a key that is stolen impersonates one machine and not the whole fleet | [docs/OPERATIONS.md](docs/OPERATIONS.md#a-key-for-every-host) |
| The guide of the host | What keeps the implant alive on this machine, and what stops it: on a phone the rules of the manufacturer (the autostart list of Xiaomi, the battery optimisation, the notification, the standby bucket) with the screen that shows each of them, on a desktop how long the machine has been idle and where the power comes from | [docs/PROTOCOL.md](docs/PROTOCOL.md#72s-the-guide-of-the-host) |
| Work that has a time | A task may carry a deadline and a timeout: the server cancels the work that is no longer worth running, fails the work that ran out of time, and hands the bound to the beacon so the implant stops the command itself | [docs/PROTOCOL.md](docs/PROTOCOL.md#72o-the-queue-the-breakers-and-the-traces) |

Not in this version (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#roadmap)):
TLS inside the implant binaries.

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
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | the certificate rotation, the recovery procedure, the maintenance window, the stuck queue |

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

`tests/test_acceptance.py` is the acceptance test of the framework: one test
per sentence of the specification that says what a real command and control
is — the beacon that survives its host, the inventory of what was installed,
the task the host cannot run, the file that is pushed to a fleet, the chain of
pivots, two operators at the same time, the task with a deadline, the wire
that four implementations share, the green build, and the end of an
engagement.  The tests name the code that does the work, so a sentence that
stops being true fails the suite.

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
