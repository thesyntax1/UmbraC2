# The state file of the persistence manager

> What `implant/rust/src/persist.rs` keeps on a host, what it promises about
> that file, and what it does not.  This page is the map the stage asked for
> before any fix: the format, every place the file is opened, and the failure
> matrix.  The stage itself is `docs/VERIFICATION-MATRIX.md` row 16.

## 1. What is stored, and where

The implant keeps one file, `persist.state`, in the directory that holds the
rest of its per-user state:

| Platform | Path |
|---|---|
| Linux | `$HOME/.umbra/persist.state` |
| macOS | `$HOME/.umbra/persist.state` |
| Windows | `%APPDATA%\.umbra\persist.state`, falling back to `%USERPROFILE%` |

The file is a `upk` value — the project's own encoding, the same one the wire
protocol uses — of one map:

```
{ "entries": [ { "technique": "registry.run",
                "name": "host-svc",
                "trigger": "logon",
                "location": "HKCU\\...\\Run",
                "detail": "...",
                "binary": "/home/user/.local/bin/host-svc",
                "state": "installed",
                "installed_at": "1700000000" } ] }
```

`entries` is the only key the reader insists on.  Every field of an entry is a
string; a missing or non-string field reads as `""`, which is how an entry
written by an older build keeps working.  **Unknown keys are ignored**, so a
newer build can add one without making an older build refuse the file.  There
is no version number inside the file: the version is the protocol version of
the upk encoding itself, and a file that does not decode as upk is not this
build's file.

`upk::decode_exact` is the validator: it rejects trailing bytes, truncation,
non-minimal varints, strings over 1 MiB, containers over 2^20 items, nesting
deeper than 16, invalid UTF-8 and map keys that are not ascending.  That is
the whole of the "is this a state file" question at the byte level; §4 is the
part above the bytes.

## 2. Every place the file is touched

| Operation | Task id | Reads | Writes | Lock |
|---|---|---|---|---|
| install a technique | `persist` | ✓ | ✓ | ✓ |
| remove every / one technique | `unpersist` | ✓ | ✓ | ✓ |
| install the new one, then remove the old | `persist.migrate` | ✓ (twice) | ✓ (twice) | ✓ per call |
| check what is still there | `persist.verify`, `persist.health` | ✓ | ✓ | ✓ |
| list | `persist.list` | ✓ | — | — |
| the end of an engagement | `forensics::decommission` → `unpersist` | ✓ | ✓ | ✓ |
| a broken persistence | `beacon.rs` health cycle → `persist.list` | ✓ | — | — |

`migrate` calls `install` and `remove` in sequence; each takes and releases
the lock itself, so the pair is two locked operations rather than one.  What
that means is in §5.

## 3. The write, step by step

1. Take the lock (`persist.lock`, `create_new`).  A second writer fails here,
   with the path of the lock file, and nothing is changed.
2. Read and decode the file.  Corrupt is not empty — see §4.
3. Encode the new value in memory.
4. Create the directory `0o700` on Unix (the platform's own permissions
   elsewhere) and narrow it if it exists wider.
5. Remove any leftover `persist.tmp`.
6. Create `persist.tmp` `0o600` (Unix), write the bytes, `sync_all()`.
7. `rename(persist.tmp, persist.state)`.
8. `fsync` the directory (where the platform allows it).
9. Drop the lock, which removes `persist.lock`.

A failure at 4, 5, 6 or 8 removes the temporary file and leaves the previous
state file exactly as it was.  A failure at 7 leaves the old file too: the
rename is what makes the new bytes visible.

## 4. When the file is not a state file

| What was found | What the reader does | What the operator sees |
|---|---|---|
| no file | empty list, no error | "nothing is installed on this host" — true, a fresh host |
| empty file | corrupt | the refusal, plus the kept copy |
| cut file | corrupt | same |
| trailing bytes after the value | corrupt | same |
| valid upk, but not a map | corrupt | same |
| a map without `entries` | corrupt | same |
| an `entries` array holding a non-map | corrupt | same |
| a symbolic link at the path | **refused without reading it** | "is a symbolic link to …" |
| a file the process may not read | I/O error | "it could not be read: …" |

Every "corrupt" row also **keeps the bytes**: the file is moved to
`persist.state.corrupt-<unix seconds>` before the error is returned, so the
list of what is installed survives the cleanup that follows.  The next
operation then starts from an empty record instead of refusing forever.

Recovery is by hand and the project does not pretend otherwise: the kept file
is a valid upk file *if* it is intact, and `upk` has no command-line decoder.
An operator recovers by reading it with the same decoder the implant uses
(`implant/rust/tests/vectors.rs` shows how), or by checking the host itself —
which is the ground truth the file was only ever a cache of.

## 5. Concurrency

| Case | What happens |
|---|---|
| two tasks on one host, same process | one takes `persist.lock`; the other fails at once with the lock's path |
| two processes, same user | same: `create_new` is atomic across processes |
| two users | not applicable: the state directory is per-user |
| a process dies holding the lock | the lock file stays; every later operation fails until it is removed.  Loud, and recoverable by deleting one file whose name is in the error |
| a read during a write | sees the old file or the new one: the replace is a rename |

What the lock does **not** do: it does not wait, retry or expire (§ "Why not a
timeout" in the source).  `migrate` is two locked operations, so a crash
between them leaves the new technique installed **and** the old one still
listed — the old entry is removed by a later `unpersist`, and the alternative
(one lock across both) would hold the file while the platform tools run.

## 6. Durability, per platform

| Platform | The bytes reach the disk | The rename reaches the disk |
|---|---|---|
| Linux | `sync_all` on the temporary file, error propagated | `fsync` on the directory, error propagated |
| macOS | same code path, `cargo check` for both targets in CI | attempted; `EINVAL` is treated as "this filesystem does not sync directories".  **No runtime test on a Mac has been run** |
| Windows | `FlushFileBuffers` through `sync_all`, error propagated | **not done**: `std` cannot open a directory for flushing.  Atomic rename, durability of the name NOT VERIFIED |

So the honest sentence is: on Linux a save that returns `Ok` has put the bytes
and the name on the disk; on macOS the bytes are flushed and the name is
best-effort; on Windows the bytes are flushed and the name's durability is
unknown until a Windows runtime test exists.

That is also why nothing above is called "crash-safe" in the code.  A power
cut between the flush and the rename loses the *new* state, not the old one,
which is the correct direction: the file goes back to what it said before the
operation began.

## 7. Permissions

| Platform | Directory | File | Existing wider file |
|---|---|---|---|
| Linux / macOS | created `0o700`, narrowed if wider | created `0o600`, replaced with the temporary file's mode | replaced on the next write |
| Windows | inherited from `%APPDATA%` | inherited from its directory | inherited |

Windows ACLs are **not** treated as equivalent to Unix modes.  What the file
gets on Windows is whatever the profile's ACL grants, which on a default
installation is the user and the administrators; that is a statement about
the default, not a guarantee this project enforces, and it is NOT VERIFIED.

A symbolic link is refused in two places: at the state file's path (reading
through a link would let another user choose what this build reads) and at
the state directory's path (writing through one would put the state where
somebody else owns the directory).

## 8. What is still not measured

* **Power loss.**  The sequence is the argument; no test in this repository
  removes power from a machine.  A test proves the old file survives a failed
  write, not that a disk honours `fsync`.
* **Windows runtime.**  Every Windows statement above comes from the
  documentation of the platform and from the code that compiles for the
  target.  The target compiles in CI (`rust beacon (the windows target
  compiles)`); nothing runs there.
* **macOS runtime.**  Same: both targets compile, none run.
* **Two processes racing.**  The tests exercise the lock primitive and the
  refusal, not two operating-system processes racing on one file.
* **A stale lock.**  Deliberately not recovered: the error names the file and
  the operator removes it.  No test drives a crashed process into that state.
