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
import time
from typing import Any, Dict, List, Optional

from . import __version__, crypto, netio, wire
from .client import OperatorClient, OperatorError

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
            fmt_ts(a.get("last_seen") if not isinstance(a.get("last_seen"), int) else a.get("last_seen")),
        ]
        for a in agents
    ]
    print(table(["ID", "HOST", "OS", "USER", "STATE", "TRANSPORT", "BEACON", "LAST SEEN"], rows))


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
                t.get("code", "?"),
                short(decode_out(t.get("out", "")), 60) or "-",
                fmt_ts(t.get("created")),
            ]
        )
    print(table(["TASK", "KIND", "STATE", "CODE", "OUTPUT", "CREATED"], rows))


def print_task_result(task: Dict[str, Any]) -> None:
    print(f"task    : {task.get('id')}")
    print(f"agent   : {task.get('agent_id')}")
    print(f"kind    : {task.get('kind')}")
    print(f"state   : {task.get('state')}")
    print(f"exit    : {task.get('code')}")
    if task.get("err"):
        print(f"error   : {task['err']}")
    out = decode_out(task.get("out", ""))
    if out:
        print("--- output " + "-" * 50)
        print(out.rstrip())


def print_event(ev: Dict[str, Any], stream: Any = None) -> None:
    kind = ev.get("kind", "?")
    at = fmt_ts(ev.get("at"))
    agent = ev.get("agent_id", "")
    data = ev.get("data") or {}
    detail = ""
    if kind == "task.result":
        detail = f"task={ev.get('task_id')} exit={data.get('code')}"
        out = decode_out(data.get("output", ""))
        if out:
            detail += f" out={short(out, 60)!r}"
    elif kind in ("agent.new", "agent.online"):
        detail = f"host={data.get('host')} os={data.get('os')}"
    elif kind == "task.queued":
        detail = f"task={ev.get('task_id')} kind={data.get('kind')}"
    elif kind == "agent.policy":
        detail = f"sleep={data.get('sleep')} jitter={data.get('jitter')}"
    print(f"[{at}] {kind:<14} {agent:<20} {detail}".rstrip(), file=stream or sys.stdout)


# ---------------------------------------------------------------------------
# client wrapper
# ---------------------------------------------------------------------------
class Console:
    def __init__(self, client: OperatorClient, *, watch: bool = False) -> None:
        self.client = client
        self.watch = watch
        self.current_agent: Optional[str] = None

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
                print_agents(self.client.agents())
            elif cmd == "use":
                if not rest:
                    print(f"current agent: {self.current_agent or '(none)'}")
                else:
                    self.current_agent = rest[0]
                    print(f"current agent: {self.current_agent}")
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
            elif cmd == "tasks":
                limit = int(rest[0]) if rest else 20
                print_tasks(self.client.tasks(self._resolve(None), limit))
            elif cmd == "result":
                if not rest:
                    print("usage: result <task-id>")
                    return True
                print_task_result(self.client.task(rest[0]))
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
        print(f"queued {task_id} for {agent} ({kind})")
        if watch or self.watch:
            try:
                task = self.client.wait_for_result(task_id, timeout=120)
            except OperatorError as exc:
                print(f"error: {exc}")
                return
            print_task_result(task)
        else:
            print("use `result <task-id>` to collect the output")


def print_help() -> None:
    print(
        """commands:
  help                      show this help
  agents | ls               list agents
  use <agent-id>            select the current agent
  info [agent-id]           full agent record
  run <command>             queue a shell task and print its result
  exec <kind> [json]        queue arbitrary task (sysinfo, ls, download, ...)
  tasks [limit]             recent tasks for the current agent
  result <task-id>          print a task result
  watch [on|off]            toggle automatic result printing
  sleep <secs> [jitter%]    change the beacon interval
  kill [agent-id]           tell an agent to exit
  stats                     server statistics
  raw <cmd> [json]          send a raw RPC
  quit                      disconnect and exit"""
    )


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
    )
    p.add_argument("--server", "-s", default=os.environ.get("UMBRA_SERVER", "127.0.0.1:4002"),
                   help="team server operator listener (default 127.0.0.1:4002)")
    p.add_argument("--operator", "-o", default=os.environ.get("UMBRA_OPERATOR", "operator"),
                   help="operator identity (must match a server token entry)")
    p.add_argument("--token", "-k", default=None, help="operator token (prefer --token-file or env)")
    p.add_argument("--token-file", default=None, help="file containing the operator token")
    p.add_argument("--timeout", type=float, default=15.0, help="socket/RPC timeout in seconds")
    p.add_argument("--watch", action="store_true", help="print events as they arrive")
    p.add_argument("--quiet", action="store_true", help="do not print the event banner")
    p.add_argument("--json", action="store_true",
                   help="machine-readable output for agents/tasks/info/stats/result")
    p.add_argument("--version", action="version", version=f"umbra {__version__} ({wire.SUITE_NAMES[1]}, umbra/v1)")

    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("agents", help="list agents")
    sub.add_parser("stats", help="server statistics")

    info = sub.add_parser("info", help="show one agent")
    info.add_argument("agent")

    run = sub.add_parser("run", help="queue a shell command")
    run.add_argument("agent")
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.add_argument("--wait", action="store_true", help="wait for and print the result")
    run.add_argument("--timeout", type=float, default=120.0)

    task = sub.add_parser("task", help="queue an arbitrary task")
    task.add_argument("agent")
    task.add_argument("kind")
    task.add_argument("--args", default="{}", help="task arguments as JSON")
    task.add_argument("--wait", action="store_true")
    task.add_argument("--timeout", type=float, default=120.0)

    tasks = sub.add_parser("tasks", help="list tasks for an agent")
    tasks.add_argument("agent")
    tasks.add_argument("--limit", type=int, default=20)

    result = sub.add_parser("result", help="print a task result")
    result.add_argument("task_id")

    sleep = sub.add_parser("sleep", help="change beacon interval")
    sleep.add_argument("agent")
    sleep.add_argument("seconds", type=int)
    sleep.add_argument("--jitter", type=int, default=20)

    kill = sub.add_parser("kill", help="tell an agent to exit")
    kill.add_argument("agent")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    token = read_token(args)

    def on_event(ev: Dict[str, Any]) -> None:
        if args.watch:
            # Events arrive asynchronously; keep them off stdout so a piped
            # command's output is not corrupted.
            print_event(ev, stream=sys.stderr)

    client = OperatorClient(
        args.server, token, args.operator, timeout=args.timeout, on_event=on_event
    )
    try:
        client.connect()
    except (OperatorError, crypto.AeadError, netio.StreamError, OSError) as exc:
        # A refused connection, a closed socket mid-handshake or a bad token all
        # land here; print one line instead of a traceback.
        print(f"connection failed: {exc}", file=sys.stderr)
        return 2

    console = Console(client, watch=args.watch)
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

        def emit(payload: Any) -> None:
            """One canonical JSON shape: bytes as text, keys sorted."""
            print(json.dumps(payload, indent=2, sort_keys=True, default=json_default))

        if args.cmd == "agents":
            rows = client.agents()
            emit(rows) if args.json else print_agents(rows)
        elif args.cmd == "stats":
            emit(client.stats())
        elif args.cmd == "info":
            emit(client.agent_info(args.agent))
        elif args.cmd == "run":
            command = " ".join(args.command).strip()
            if not command:
                print("no command given", file=sys.stderr)
                return 2
            task_id = client.submit(args.agent, "shell", {"cmd": command})
            if args.json and not args.wait:
                emit({"task_id": task_id, "agent": args.agent, "kind": "shell"})
            else:
                print(f"queued {task_id}")
            if args.wait:
                result = client.wait_for_result(task_id, timeout=args.timeout)
                emit(result) if args.json else print_task_result(result)
        elif args.cmd == "task":
            try:
                task_args = json.loads(args.args)
            except json.JSONDecodeError as exc:
                print(f"invalid --args json: {exc}", file=sys.stderr)
                return 2
            task_id = client.submit(args.agent, args.kind, task_args)
            if args.json and not args.wait:
                emit({"task_id": task_id, "agent": args.agent, "kind": args.kind})
            else:
                print(f"queued {task_id}")
            if args.wait:
                result = client.wait_for_result(task_id, timeout=args.timeout)
                emit(result) if args.json else print_task_result(result)
        elif args.cmd == "tasks":
            rows = client.tasks(args.agent, args.limit)
            emit(rows) if args.json else print_tasks(rows)
        elif args.cmd == "result":
            task = client.task(args.task_id)
            if args.json:
                emit(task)
                # A failed task must fail the shell too, so scripts can branch
                # on the exit status instead of parsing output.
                return 0 if task.get("state") == "done" and not task.get("code") else 1
            print_task_result(task)
        elif args.cmd == "sleep":
            client.set_sleep(args.agent, args.seconds, args.jitter)
            if args.json:
                emit({"agent": args.agent, "sleep": args.seconds, "jitter": args.jitter})
            else:
                print("beacon policy updated")
        elif args.cmd == "kill":
            res = client.rpc("agents.kill", {"id": args.agent})
            print("kill task queued" if res.ok else f"error: {res.error}")
        else:  # pragma: no cover - argparse covers this
            print(f"unknown command {args.cmd}", file=sys.stderr)
            return 2
    except OperatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
