"""The shell of the console: the prompt, the history and the completion.

The console is a program an operator types into for hours, so the shell
around it matters as much as the commands: the history that remembers what
was done, the completion that knows the agents by name, the prompt that
says what the console is looking at right now, and the continuation that
lets a long command be written over several lines.
"""

from __future__ import annotations

import os
from typing import Any, List, Optional

__all__ = ["COMMANDS", "install_readline", "read_command", "status_line"]


# The commands of the console.  The completion offers them, and the help
# text is generated from the same list, so the two cannot drift apart.
COMMANDS = [
    "agents", "alias", "alert", "artifact", "audit", "batch", "bulk", "chat",
    "chain", "claim", "creds", "download", "env", "events", "exec", "focus",
    "get", "handover", "help", "inbox", "info", "kill", "operators", "panic",
    "persist", "persist-health", "persist-list", "persist-migrate",
    "persist-report", "persist-verify", "plan", "policy", "put", "quit",
    "raw", "recon", "releases", "report", "resolve", "result", "retry", "rpc",
    "run", "scan", "schedule", "session", "sessions", "sleep", "stats",
    "suggest", "tag", "tasks", "triage", "unpersist", "update", "upload",
    "use", "watch", "whoami", "workflow", "wipe",
]


def _history_path() -> str:
    """Where the history of the console is kept."""
    home = os.path.expanduser("~")
    return os.path.join(home, ".umbra", "history")


def _agent_ids(console: Any) -> List[str]:
    """The ids of the agents the console knows about."""
    ids: List[str] = []
    try:
        for agent in console.client.agents():
            ident = str(agent.get("id", ""))
            if ident:
                ids.append(ident)
    except Exception:  # noqa: BLE001 - the completion is a convenience
        return []
    return ids


def complete(console: Any, text: str) -> List[str]:
    """The completions of a word.

    The first word of a line is a command; after that it is an agent id,
    because that is what almost every command wants.
    """
    if " " not in text.strip():
        prefix = text.strip()
        return [name for name in COMMANDS if name.startswith(prefix)]
    parts = text.split()
    prefix = parts[-1]
    if not prefix:
        return []
    return [ident for ident in _agent_ids(console) if ident.startswith(prefix)]


def install_readline(console: Any) -> bool:
    """Set up the line editing of the console.

    The history is kept in the home directory of the operator, so the last
    session is where the next one starts.  A readline that is not there
    (Windows without the module, a pipe) is not an error: the console
    still works, it just does not remember.
    """
    try:
        import readline  # noqa: PLC0415 - the module is optional
    except ImportError:
        return False

    class _Completer:
        def __call__(self, text: str, state: int) -> Optional[str]:
            options = complete(console, text)
            if state < len(options):
                return options[state]
            return None

    try:
        readline.set_completer(_Completer())
        readline.set_completer_delims(" \t\n")
        readline.parse_and_bind("tab: complete")
        readline.parse_and_bind("history: searching")
        path = _history_path()
        directory = os.path.dirname(path)
        try:
            os.makedirs(directory, exist_ok=True)
            readline.read_history_file(path)
        except OSError:
            pass
        console._history_path = path  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - the console works without readline
        return False
    return True


def save_history(console: Any) -> None:
    """Write the history of the console back to the disk."""
    path = getattr(console, "_history_path", "")
    if not path:
        return
    try:
        import readline  # noqa: PLC0415 - the module is optional

        readline.write_history_file(path)
    except Exception:  # noqa: BLE001 - the history is a convenience
        return


def _unbalanced(text: str) -> bool:
    """Say whether a line is unfinished.

    A quote or a bracket that is still open means the operator is in the
    middle of writing something, and the console waits for the rest.
    """
    quote = ""
    depth = 0
    for char in text:
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth < 0:
                depth = 0
    return bool(quote) or depth > 0


def read_command(prompt: str, console: Any) -> str:
    """Read one command, over one line or over several.

    A line that is still open (a quote, a bracket) is continued with a
    continuation prompt, so a long JSON argument can be written the way it
    is read.
    """
    lines: List[str] = []
    while True:
        try:
            line = input(prompt if not lines else "... ")
        except EOFError:
            if lines:
                return "\n".join(lines)
            raise
        except KeyboardInterrupt:
            if lines:
                return ""
            raise
        lines.append(line)
        if not _unbalanced("\n".join(lines)):
            break
    return "\n".join(lines)


def status_line(console: Any) -> str:
    """The status of the console, on one line.

    It says what the console is looking at, whether the link is alive, how
    many hosts answer and how much work is waiting in the queue.  The
    numbers are the ones of the last refresh; a status line that blocks on
    a round trip is worse than no status line.
    """
    agent = console.current_agent or "-"
    stats = getattr(console, "_status", {}) or {}
    online = stats.get("agents_online")
    total = stats.get("agents_total")
    queued = stats.get("tasks_pending")
    sleep = stats.get("sleep")
    parts = [agent]
    if online is not None and total is not None:
        parts.append(f"{online}/{total} online")
    if queued is not None:
        parts.append(f"queue {queued}")
    if sleep:
        parts.append(f"sleep {sleep}s")
    if stats.get("server"):
        parts.append(str(stats["server"]))
    return " · ".join(parts)
