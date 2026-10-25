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
| `agent_listen` | `0.0.0.0:4001` | reachable by implants (TCP beacon) |
| `operator_listen` | `127.0.0.1:4002` | **never** public; reach it through SSH or WireGuard |
| `http_listen` | `127.0.0.1:4003` | behind the tunnel-facing proxy (`deploy/nginx-http-transport.conf`) |

`server.http_tls_cert` / `http_tls_key` make the Go listener itself serve TLS.
Leave them empty for beacons: an implant has no TLS stack, so only a TLS-speaking
relay could use that listener. The supported shape is tunnel → plain listener.

Neither transport has a TLS layer: the beacons speak plain TCP and plain
HTTP/1.1, so **TLS termination in front of them does not work** — a plaintext
client cannot complete a TLS handshake. When implants must cross an untrusted
network, put the transport inside an encrypted tunnel (WireGuard, IPsec, an
mTLS mesh) and keep the listener bound to the tunnel interface. The frames are
individually AEAD-sealed, so a tunnel is about hiding *traffic shape* (ports,
cadence, sizes), not about protecting payload contents.

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

## 4. Beacon tuning

The server dictates cadence at handshake time (`beacon.sleep` / `beacon.jitter`)
and can change it per agent with `agents.sleep`; the implant applies it
immediately on the next check-in and keeps it until it is told otherwise.

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
* Anything that was `delivered` when the server stopped is re-queued on start, so
  a crash cannot lose a task — at the cost of possibly executing it twice. Task
  kinds are not idempotent by default, so check `task.list` after a restart.
* History is capped at 20 000 tasks (oldest completed tasks are pruned).
* To reset an engagement: stop the server, delete `data_file`, **and rotate the
  agent PSK and operator tokens** (delete the implants or they will simply
  re-register).

## 6. Monitoring

```bash
umbra --server 127.0.0.1:4002 --operator alice stats
journalctl -u umbra-server | grep -E "handshake failed|exceeded frame budget|queue full"
```

Signals that matter:

| Log line | Meaning |
|---|---|
| `handshake failed` (repeated, same peer) | wrong PSK, clock skew > 300 s, or scanning |
| `operator key used on the agent listener` | misconfigured implant (operator token in a beacon) |
| `agent exceeded frame budget` | runaway or hostile peer; connection dropped |
| `operator event queue full` | an operator console stopped reading; events are dropped, agent traffic is unaffected |
| `state save failed` | disk full/permissions — fix before restarting |

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
