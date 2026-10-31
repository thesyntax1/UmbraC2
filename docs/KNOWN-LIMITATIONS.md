# Known limitations

> What UmbraC2 does not do, said before somebody discovers it in an
> engagement.  This page is deliberately the least flattering one in the
> repository; [`SECURITY.md`](SECURITY.md) §5 holds the twenty-nine-item
> cryptographic and operational list, and this page holds the four
> architectural ones an evaluator asks about first: tenancy, the single
> process, what has never been executed, and what the audit trail cannot
> prove.

Reviewed: 2026-10-31.

## 1. The tenancy and deployment model, declared

**UmbraC2 is a single-engagement server for a single organisation.**  It is
not multi-tenant, it does not isolate workspaces, and no part of the design
implies that it does.

| Question | The answer |
|---|---|
| One organisation, one workspace | **Yes.** Every deployment is one engagement with one team. |
| One organisation, several isolated workspaces | **No.** There is no workspace object, no per-workspace key, no per-workspace data file and no scoping of the store by anything but agent identity. |
| Several organisations on one server | **No.** A second customer needs a second server, a second PSK, a second vault key and a second audit ledger. Two servers on one host are fine; one server for two customers is not supported. |

What *is* separated inside a deployment, and what is not:

* **Separated:** operator identity and its token, the attribution of every
  audit line, the rate budget (40 calls/s per operator), the approval queue's
  requester binding (two-person rule), the presence lease of a console, and
  the second factor of each operator.
* **Not separated:** the data plane. A `viewer` sees every host, every task,
  every result, every artifact and every note of the engagement, because that
  is what a viewer is for. RBAC decides *what a role may do*, never *which
  rows a tenant may see*. There are no quotas per team, no per-team keys and
  no per-team export.

One consequence deserves its own line: **the dashboard authenticates as one
identity** — the first operator in the keyring (`firstOperatorToken` in
`cmd/umbra-server/main.go`). Everything done in the browser is attributed to
that operator, and it carries that operator's role. A deployment that wants
the dashboard to be its own audit identity should give it a dedicated
operator, which is the deployment's decision and not a feature of the code.

## 2. The single process: six questions, answered

The server is one Go process. There is no supervisor inside it, no
multi-process split and no worker pool that could outlive a crash of the
coordinator. The six questions an evaluator asks, with the answer the code
gives today:

1. **What does the main process do when a subcomponent fails?**
   It depends on *when* the failure happens.  At start-up, a listener that
   cannot bind, a TLS listener without a certificate, a store that cannot be
   opened and a config that does not validate are **fatal**: `link.Server.Start`
   returns the error, `run` returns it, and the process exits with the message
   (`listen … : bind: address already in use`).  After start-up the behaviour
   is per component: an `Accept` error ends that one listener and is logged
   (`accept failed`), while the others keep serving; the dashboard's `Serve`
   error is logged (`the dashboard stopped`) and the server continues; a
   background save failure calls the handler installed in `main`
   (`background state save failed`); a failed audit write is logged
   (`audit write failed`) and the RPC still succeeds.
2. **Is the failure logged?**  Yes, through `slog` to standard error, which
   the systemd unit collects.  The exceptions are the failures the code
   deliberately swallows: the hook runner's panic guard, and a shutdown
   error that is already a closed listener.
3. **Does it keep running in an inconsistent state?**  Yes, and the two
   dangerous cases are named.  State lives in memory and is written behind
   it, so a save that fails leaves the running server ahead of the disk until
   the next save succeeds.  The audit ledger can have **gaps**: `record()`
   documents that "auditing never fails an RPC", so a full disk costs a
   warning and a missing line, not a refused command.
4. **Is the state verified at restart?**  Partly.  The snapshot is
   schema-checked (`snapshotVersion`), a torn or unreadable current file falls
   back to one of three generations, an unreadable generation stops the open
   instead of starting empty, and a deployment with nothing on disk starts
   fresh.  On load, every agent is marked offline, every `delivered` task
   becomes `queued` again, and a schedule whose time passed while the server
   was down is pushed to the future.  What is **not** verified is the content:
   there is no checksum of `state.json` beyond JSON validity, and no `fsck`.
5. **What is the operator shown?**  The start-up warnings — armory signatures
   disabled, artifact store `encrypted=false`, second factor unsealed, ledger
   path, lab-use notice — and nothing live.  `/healthz` returns `ok`, and it
   is a liveness answer, not a readiness one: it does not know that the last
   save failed or that the ledger is not writable.  An operator without access
   to the server log cannot see the degradation.
6. **Is it the whole session or one component?**  The whole session.  A panic
   in the process takes every listener, every console and every queued task
   with it; there is no per-subsystem supervision.  The restart policy is the
   deployment's (`Restart=always` in the systemd unit), and it restarts the
   *whole* server: the consoles disconnect, the beacons reconnect on their
   next cycle, and the queue is recovered from the snapshot.  Measured cost of
   that restart is in [`BACKUP-RECOVERY.md`](BACKUP-RECOVERY.md) §3.

## 3. What has never been executed anywhere

| Thing | Why it is not verified | What would verify it |
|---|---|---|
| Rust beacon (44 files, 28.7k lines) | no `cargo` on the machine that wrote it; CI has never run | `cargo test` + `cargo build --release --target x86_64-pc-windows-gnu` in a job that is allowed to run |
| Android implant (40 Kotlin files) | no JDK, no Gradle, no emulator; no test source set | `./gradlew test assembleDebug` on a runner, and one instrumented test |
| Armory signature path | package has 0 test functions; the check is off without `armory_key` | a signed and an unsigned module in a test, with the check on |
| Load, concurrency, soak | nothing above 200 sequential calls has been run | a concurrent client, thousands of sessions, a multi-hour soak |
| Upgrade of a live server | no drain, no rolling restart, no test of a beacon meeting a newer server | two builds, one reconnecting beacon, a written procedure |
| Restore from off-machine storage | only a `SIGKILL` and a restart over the same directory was drilled | the drill in `BACKUP-RECOVERY.md` §5, executed and dated |
| External anchor of the audit head | `audit.jsonl.head` sits on the same disk as the ledger | shipping the head to a second system and comparing it |
| Per-test scope records | no harness writes them | an engagement log that records the authorisation per test |
| CI as evidence | every run of this branch has failed with zero steps (account billing block) | a green run whose log can be quoted |

## 4. The audit trail: two questions an auditor will ask

**"What happens when the audit record cannot be written?"**  The command
proceeds and the failure is logged
(`audit write failed … cmd=… operator=…`).  This is a deliberate trade-off —
refusing every operator command because the disk is full would turn a logging
fault into an outage — but it means the ledger can contain a gap that no
chain check can see.  Gaps are detectable by comparing the ledger against the
server log and against the operator's own recollection, and not otherwise.
A deployment that needs better must make the ledger's disk failure a
deployment-level alert (the warning is in the journal) and must export the
ledger off the host.

**"How does an auditor detect a changed record?"**  `umbra audit --verify`
recomputes the hash chain from the file and compares the head to
`audit.jsonl.head`; an edited line breaks every line after it, and a truncated tail
disagrees with the anchor.  What this cannot catch is an attacker who can
write the whole data directory: they can recompute the chain and rewrite the
anchor together.  The trail is tamper-*evident* against partial modification
and tamper-*proof* against nothing.  Exporting the head to a system the
server cannot write is the missing half, and it is not implemented.

## 5. The honest summary

UmbraC2 is a working, tested reference implementation of a C2 protocol with a
hardened operator plane and a verification trail that names its own holes.
It is not an enterprise product, and the distance is exactly this page plus
[`SECURITY.md`](SECURITY.md) §5: no tenancy, one process, no measured load, no
upgrade drill, no external audit anchor, and two beacons that have never been
compiled by this repository's own CI.
