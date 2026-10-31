# Backup and recovery

> Backup is a copy.  Restore is a command.  **Recovery is a proof** — and this
> page separates the three, because a deployment that has a backup script and
> has never restored it has a belief, not a plan.

## 1. What is on the disk

Everything a deployment owns lives under the data directory named in
`server.json` (`data_file`, default `data/state.json`).  One table:

| File | What it holds | Grows with | Reconstructible? |
|---|---|---|---|
| `state.json` (+ `.bak`, `.bak.1` …) | agents, tasks, chat, schedules, tags, notes, holds | time and work | **no** — this is the engagement |
| `audit.jsonl` (+ rotated generations) | the operator ledger, a hash chain | every operator call | **no** — this is the record |
| `audit.head` | the anchored head of the chain (`0600`) | constant | no, and it is what makes a truncation visible |
| `approval.json` | the queue of the two-person rule | decisions | no |
| `otp.json` | the sealed second factors of the operators | operators | no — and it must be restored with the vault key |
| `artifacts/` | the file store, optionally encrypted | uploads | no |
| `armory/` | imported extensions and their signatures | catalogue imports | yes, from the mirror |
| `baseline.json`, `canary.json`, `casefile/`, `silences.json`, `onboard.json` | the watches, the tripwires, the cases, the promises, the playbooks | operator work | no |
| the PSK file and the vault key | the keys | constant | **never** — a backup that contains them is a backup of the whole fleet |

**The rule that decides the backup set:** if the server can rebuild it, do not
back it (the armory catalogue).  If it cannot, it belongs in the backup — and
so does the vault key, in a *different* place from the data it opens.

## 2. How often, and what that costs

There is no scheduler in the server for backups: the deployment decides, and
two mechanisms make the answer cheap.

* **The snapshot rotates itself on every save.**  Each `Save` moves the
  current file to `state.json.bak`, `.bak` to `.bak.1` and `.bak.1` to
  `.bak.2`; `store.BackupGenerations` is 3 and is a constant rather than a
  setting, so a corrupted restore cannot be repeated into every generation.
  `SaveAsync` starts the write as soon as the hub reports a mutation and
  coalesces the ones that arrive while it runs, so the file follows the work
  instead of a timer; `StartScheduler` also forces a save every 60 s
  (`snapshot := time.NewTicker(time.Minute)`), so a quiet engagement is still
  durable.  A torn write cannot destroy all four files, and the recovery at
  startup walks `state.json`, `.bak`, `.bak.1`, `.bak.2` in that order.
* **The audit ledger is append-only and rotates by size** (`audit_max_mb`,
  default 8, and `audit_keep_files`, default 5), so copying it by *size* is
  wrong: copy the whole directory.

For an off-machine copy, the honest recommendation is a `restic`/`borg`
snapshot of the data directory every **15 minutes**, plus one copy after every
`umbra backup`-worthy decision (the end of a phase, the start of a new one).
The interval is a policy of the deployment and not a property of this code.

## 3. RPO and RTO, measured rather than chosen

Both numbers are properties of the deployment, so they are stated as
*what the code does* plus *what was measured on the reference machine*.

| Measure | Meaning | Measured | Where |
|---|---|---|---|
| **RPO (snapshot)** | work that a crash can lose | the mutation that was being written when the process died, plus anything the 60 s ticker had not yet flushed; measured cost of one save: **308 ms** for a 16.2 MB state.  The ledger is separate and fsynced per entry | `hub.StartScheduler`, `store.SaveAsync`, `audit.go` |
| **RPO (off-machine)** | work that losing the machine can lose | the backup interval, chosen by the deployment (15 min above) | this page |
| **RTO (process restart)** | kill → serving again, small state | **21 ms** cold start, **21 ms** after `SIGKILL`, 3705-byte state | `tests/test_real_server.py::test_a_sigkill_and_a_restart_keep_the_engagement` |
| **RTO (process restart)** | kill → state loaded again, 20 000 tasks | **103 ms** to load a **16.2 MB** snapshot (save of the same state: 308 ms) | `server/internal/store/store_test.go::TestRecoveryTimeAtScale` |
| **RTO (off-machine)** | a machine is gone | *not measured*: depends on the storage, the network and the operator | **Not Verified** |

The last row is the one an enterprise reader will ask about, and it is the
one this repository cannot answer: a restore from object storage has never
been drilled here.  It stays `Not Verified` until somebody runs §5 on the
real storage and writes the number down.

## 4. What a restore can lose

Said plainly, because an unstated loss is the loss that hurts:

* **The snapshot's tail.** The save that was in flight, plus at most the
  mutations since the last coalesced write.  A task that was delivered but
  not answered is **not** lost: it is re-queued on open
  (`store_test.go::TestDeliveredTasksAreRequeuedOnOpen`).
* **Nothing from the ledger, if it was copied.** The audit file is appended
  and fsynced per entry; a backup taken between two entries is consistent,
  and `umbra audit --verify` proves it after the restore.
* **Anything in memory.** The chains of a multi-stage task, the live pivots,
  the sessions of the operators and the beacons: a restart ends every
  session, and the beacons reconnect on their next cycle by design.
* **The second factors, if the vault key is not restored with them.** `otp.json`
  is sealed under `vault_key`; without the key it is a file of noise and every
  operator has to re-enrol.
* **`audit.head` if it is restored from an older copy than the ledger**: the
  ledger then looks like it grew after the anchor, which is exactly what a
  normal run looks like.  Restore the anchor *with* the ledger, or restore
  neither and re-anchor.

## 5. The drill (run this, write down the result)

The procedure a deployment should execute once per quarter, in a lab, with
the real backup storage:

1. **Take** a backup: `restic backup "$UMBRA_DATA"`.  Record the snapshot id
   and the time it finished.
2. **Record the reference**: `umbra audit --verify` and `umbra stats`, and save
   the output beside the backup id.
3. **Destroy** a copy: restore the machine image or delete the data directory
   of a *disposable* host — never the engagement's only copy.
4. **Restore**: `restic restore <id> --target "$UMBRA_DATA"`.  Start the clock.
5. **Start** the server and wait for the operator listener.  Stop the clock:
   that is the measured RTO.
6. **Verify**: `umbra audit --verify` must return the same head as step 2, and
   the inventory must match.  If the head differs, the ledger is older than
   the reference and the RPO for that run is the difference — write it down.
7. **Write the numbers** into the deployment's own copy of this page, with the
   date, the size of the state and the machine.

What has been run in this repository is steps 5 and 6 for the *process*
(recovery from a `SIGKILL` over the same directory, above), and the store's
own tests for a torn write and a fallback generation.  Steps 1–4 over a real
backup product have not been run: this page is the plan, and the numbers in
§3 are the part of the plan that has been measured.

## 6. The one-command restore of a snapshot generation

The store already restores itself.  For the case where the operator has to do
it by hand:

```bash
systemctl stop umbra-server

# The current file is unusable: keep it, do not delete it.
mv data/state.json data/state.json.broken

# The generation the store keeps behind it becomes the current one.
cp data/state.json.bak data/state.json

systemctl start umbra-server
journalctl -u umbra-server | grep -i "recovered"   # the server says so when it falls back
umbra audit --verify                                # the ledger is a separate file and must still verify
```

The server logs `state recovered from the backup generation` when it falls
back on its own; the manual copy is for the case where the operator wants to
choose the generation (`state.json.bak.1`, `.2` …) instead of the automatic
choice.

## 7. What is not true

* There is no point-in-time recovery and no continuous WAL: the snapshot is a
  document, and the granularity is one save (and its three generations).
* There is no replication: one server, one data directory.
* There is no encryption at rest for `state.json` ([SECURITY.md §5](SECURITY.md));
  the backup inherits that, so the backup storage must be encrypted by the
  backup tool.
* There is no restore command in the server binary: a restore is a file copy
  and a restart, which is why this page is mostly a runbook and not a feature
  list.
