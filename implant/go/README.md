# The Go implant

A small beacon that speaks the UmbraC2 protocol and does exactly what it says
it does.

It is the fourth implementation of the protocol, next to the Go server, the
Rust beacon and the Kotlin one.  It carries its own copy of the protocol
primitives — the frame format, the encoding, the key schedule and the link
state machine — the same way the Rust and the Kotlin implants carry theirs,
and it is proved against the same conformance vectors in
[`contracts/vectors.json`](../../contracts/vectors.json).  A byte that the
server writes and the Go beacon reads is a byte that the Rust beacon reads
too.

## What it does

* It checks in, it takes the batch of the server, it runs the tasks and it
  reports the outcome of each one.
* It rekeys when the server asks for it, it accepts a cancelled task, it
  stops when the server sends `KILL`, and it says goodbye before it closes
  the link.
* It draws the interval of the check-ins from a window around the base
  interval, so the gaps arrive in clusters instead of spreading evenly.
* It backs off when a cycle fails, and the backoff grows and is capped.
* It never keeps the output of a task in memory longer than it takes to send
  it.

## What it does not do

The list is short on purpose, and the beacon says so:

| It does not | Why |
| --- | --- |
| Load modules | There is no loader and no sandbox in this build. The Rust beacon has the module ecosystem. |
| Stay installed | There is no persistence manager here. The Rust beacon has the catalogue of techniques. |
| Touch the desktop | No screen, no clipboard, no keyboard. The Rust beacon has them on Windows and macOS. |
| Speak the other transports | The link is TCP. The Rust beacon has the HTTP, the WebSocket, the DNS, the mail and the object store transports. |
| Pivot | There is no tunnel and no peer link here. |
| Run on Windows | The shell task needs a POSIX shell, and the process table is read from `/proc`. |

A task that is not on the list is answered with an error, never with a
silence: the operator has to see that the task did not run.

## The task kinds

The capability list is what the beacon advertises in the handshake, and the
server refuses to queue work that is not on it.

| Kind | What it does |
| --- | --- |
| `shell` | Runs a command through `/bin/sh` and returns its output. |
| `sysinfo` | The inventory of the host: the system, the architecture, the user, the process, the kernel, the moment the machine came up. |
| `ls` | The entries of a directory with their size, their mode and their timestamp. |
| `cat` | The contents of a file. |
| `tail` | The last lines of a file. |
| `upload` | Writes a file on the host. |
| `hash` | The SHA-256 of a file. |
| `ps` | The process table of the host, read from `/proc`. On the systems that do not expose one, the beacon says so instead of making one up. |
| `env` | The environment of the implant. |
| `find` | The files whose name matches a pattern. |
| `pwd` | The working directory. |
| `resolve` | The addresses of a name, from the resolver of the host. |
| `netinfo` | The interfaces of the host with their addresses. |
| `sleep` | Changes the interval between two check-ins. |
| `ping` | The answer of a host that is alive. |
| `exit` | Stops the implant. |
| `window.list` | The windows of the desktop: the process, the class and the title. |
| `clipboard.watch` | The watcher of the clipboard: what the user copied is queued in a file that survives a reboot. |
| `screen.stream` | The screen of the machine, one picture at a time, as partial results. |
| `wifi.profiles` | The saved networks of the machine and the keys of them that the user may read. |
| `browser.creds` | The accounts and the services of the browsers; the secrets only when the operator asks for them. |
| `av.survey` | The security software of the machine: the products and the services that watch it. |
| `usb.history` | The USB keys of the machine: the history of the bus and the devices that are attached. |
| `proc.memory` | The memory of a process: the readable regions and the strings that look like a credential. |
| `wipe.survey` | What the engagement left on the host: every artefact, its size and the reason it is a trace. It changes nothing. |
| `wipe.run` | Removes the artefacts of the families the operator names (`state`, `history`, `recent`, `cache`, `log`, `system` or `all`) and reports what was removed, what was scrubbed and what could not be touched. |
| `wipe.verify` | What is left on the host after the wipe, and what no process of a user can reach. |
| `wipe.self` | The self-destruction of the implant: its state, its journal and its binary. |
| `forensics.report` | The surface of the host as an analyst sees it: the artefacts, the journal and the process. |
| `forensics.timeline` | The timeline of the engagement on the host; the journal is written only while it is on. |
| `decommission` | The end of the engagement on the host: the watchers stop, the traces are wiped, the binary goes and the verification follows. |
| `wipe.deadman` | The dead man's switch: the implant ends itself when the operator has not checked in for the number of minutes the operator named. Zero disarms the switch. |

## Building and running

The implant is the standard library of Go and nothing else: there is no
`go.sum`, and the CI refuses one.

```bash
cd implant/go
go build -trimpath -ldflags "-s -w" -o umbra-beacon ./cmd/umbra-beacon

# the key comes from "umbra-server -gen-psk"
UMBRA_SERVER=10.0.0.5:4001 \
UMBRA_PSK=$(cat /etc/umbra/key.hex) \
  ./umbra-beacon --id laptop-1 --verbose
```

The flags:

| Flag | Environment | What it is |
| --- | --- | --- |
| `--server` | `UMBRA_SERVER` | The address of the server, `host:port`. |
| `--psk` | `UMBRA_PSK` | The pre-shared key of the agent, in hex. At least sixteen bytes. |
| `--psk-file` | `UMBRA_PSK_FILE` | The file that holds the key, in hex. |
| `--id` | `UMBRA_AGENT_ID` | The name the implant registers under. Without one, the name of the host and three random bytes are used. |
| `--sleep` | — | The interval between two check-ins. |
| `--jitter` | — | The width of the jitter window, in percent. |
| `--verbose` | — | A line per event on the standard error. |
| `--selftest` | — | The offline protocol tests, without a server and without a network. |
| `--version` | — | The version of the implant. |

## The self test

`--selftest` proves that the implant speaks the protocol before it ever meets
a server:

1. The encoding round trip: the value comes back the way it went in.
2. The session round trip, and the refusal of a replayed frame.
3. **A whole cycle against a server that lives in the process.**  The server
   half of the handshake answers the greeting, sends a batch with one task,
   and the beacon answers with a heartbeat and with the result of the task.
   This is the check that matters: it proves that the implant is understood by
   a server and not only by itself.

## The tests

```bash
cd implant/go
go test ./... -race
```

The tests read the same conformance vectors as the server, the Rust beacon
and the Kotlin one, so a drift in the encoding, in the key schedule or in the
frame format fails here first.

## The layout

```
implant/go/
├── cmd/umbra-beacon/main.go     the command: the flags, the key, the signals
├── internal/beacon/              the implant
│   ├── beacon.go                 the cycle: check in, batch, heartbeat, tasks
│   ├── link.go                   the client half of the handshake
│   ├── tasks.go                  the task table and the capability list
│   ├── senses.go                the senses of the desktop: the windows, the
│   │                             clipboard, screen, networks, browsers, the
│   │                             security software, the USB keys, the memory
│   ├── forensics.go             the zero-footprint wipe: the survey of the
│   │                             artefacts, the wipe of the traces, the
│   │                             verification, the journal, the dead man's
│   │                             switch and the end
│   ├── sysinfo.go                the inventory, the network and the processes
│   ├── selftest.go               the offline tests and the built-in server
│   └── values.go                 the readers of the values that come off the wire
├── internal/wire/                the frame format
├── internal/upk/                 the encoding
├── internal/crypt/               the key schedule
└── internal/session/             the link state machine
```
