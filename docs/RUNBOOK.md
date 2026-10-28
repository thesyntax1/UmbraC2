# The runbook

What to do when something breaks, and what to do before it does.

## The certificate rotation

The certificates of the server are the identity of the operator listener:
the console checks them, and a certificate that expires in the middle of an
engagement costs the operator their console.

**What has to be rotated**

| what | where | how often |
|---|---|---|
| the operator listener certificate | `tls_cert` / `tls_key` in the configuration | every 90 days, or when it is about to expire |
| the HTTP transport certificate | `http_tls_cert` / `http_tls_key` | every 90 days |
| the client CA of the mutual-TLS listener | `tls_client_ca` | when a console is retired, or every year |
| the agent PSK | `UMBRA_AGENT_PSK` / `secrets/agent.psk` | when an implant is burned, or every year |
| the vault key | `UMBRA_VAULT_KEY` | never, without re-encrypting the vault |

**The procedure**

1. Write the new certificate and its key where the configuration points,
   with mode 0600 and owned by the user of the service:

   ```bash
   install -m 600 new.crt /etc/umbra/tls.crt
   install -m 600 new.key /etc/umbra/tls.key
   ```

2. Check it before the server does:

   ```bash
   openssl x509 -in /etc/umbra/tls.crt -noout -subject -dates
   openssl verify -CAfile /etc/umbra/ca.crt /etc/umbra/tls.crt
   ```

3. Restart the server.  It reads the certificate when the listener starts,
   so a restart is the rotation:

   ```bash
   systemctl restart umbra-server
   systemctl status umbra-server
   ```

4. Check that the console comes back:

   ```bash
   umbra --server 127.0.0.1:4002 --operator alice whoami
   ```

5. The old certificate stays valid until it expires: the beacons that
   still use it keep working, and the console accepts both the old and the
   new certificate during the overlap.  Remove the old one from the chain
   after the longest sleep interval of the fleet has passed.

**When the agent PSK changes**

The PSK is the credential of the implant, and the server accepts the old
and the new one during the overlap (the keyring holds a list).  The
beacons pick the new one up on their next check-in, because the route
carries it.  A beacon that never checks in again is a beacon that is
gone: burn it (`umbra agents.panic`) and note it in the handover.

**When the vault key changes**

The vault key encrypts the material at rest.  It cannot be rotated in
place: the material has to be exported (`umbra creds-export`) with the old
key, re-encrypted with the new one and written back.  Do it at the end of
an engagement, not during one.

## The recovery procedure

The state of the server is one file: `/var/lib/umbra/state.json`.  The
writes are atomic (a temporary file and a rename), and the previous
generations are kept next to it:

```
state.json        the newest generation
state.json.bak    the one before it
state.json.bak.1  the one before that
state.json.bak.2  the one before that
```

**The server does not start**

1. Look at the log: `journalctl -u umbra-server -n 100`.
2. If the log says the snapshot is not readable, the file is broken.  The
   server already falls back to the previous generation; if it says
   `recovered`, the newest seconds of the engagement are gone and the
   operator has to be told.
3. If the file is broken in every generation, stop the service, keep the
   files (do not delete them: they are the evidence), and start the
   server with an empty state:

   ```bash
   systemctl stop umbra-server
   mv /var/lib/umbra/state.json /var/lib/umbra/state.json.broken
   systemctl start umbra-server
   ```

   The engagement starts empty; the beacons check in again and the
   inventory comes back, but the task history and the vault are gone.  That
   is the moment to read the backup generation by hand and to tell the
   operator what was lost.

**The state is stale**

The state is written at least once a minute, and on every change.  A
server that was killed with `SIGKILL` loses at most a minute of the
engagement.  The tasks that were delivered but not answered come back as
queued, because a task that may have run must not run a second time
without a decision: the operator sees them in the task list.

**The disk is full**

The server keeps the audit trail (`audit_max_mb` rotates it) and the
state.  The state is the one that matters: free space or the write fails
and the server keeps running with the state it has.  The error is in the
log: `the snapshot of the state failed`.

## The maintenance window

The quiet window stops the traffic of the server without stopping it:

```bash
umbra --server 127.0.0.1:4002 --operator alice quiet on --until 1780000000
```

The beacons keep checking in and get nothing; nothing new is queued.  The
window ends by itself at the given time, or with `quiet off`.  The change
is an event and an audit line: who stopped the traffic, and when.

Use it for a restart of the host, a change of the routing, a firewall
rule, or anything else that would make the beacons fail in a way that
looks like an attack.

## The queue is stuck

`umbra queue` says what the queue is doing: the policy, the depth and the
dead letter queue.

* **The depth does not go down** — the beacons are not checking in.  Look
  at `umbra agents` (the state of every host) and at the transport mix in
  the metrics.
* **The dead letter queue is not empty** — a task failed too many times.
  It is not run again without a decision: look at the reason, decide
  whether the task is still wanted, and queue it again with
  `umbra task <agent> <kind>`.
* **A host has an open circuit breaker** — the server stopped handing
  work to it after too many failures in a row.  The breaker opens again
  after the cooldown, and one probe goes through.  If the host is really
  gone, the breaker is the correct behaviour.
