"""The hygiene of the operator's own machine.

The implant scrubs the traces of the engagement from the host it lives
on.  The machine of the operator is a host too: the notebook of the
console, the commands that were typed into the shell and the files that
were downloaded are traces of the engagement, and the end of an
engagement takes them away.

The rule is the rule of the implant: the material of the operator that
the engagement did not create is never destroyed.  The lines of the
shell history that name the console are taken out; the rest of the file
stays.  The notebook is removed whole, because a notebook with holes in
it is worse than no notebook.

Nothing here touches the server: the record of the engagement on the
server is the ledger of the operator, and it is kept.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from typing import Dict, Iterable, List, Optional, Tuple

# The names that mark a line of the shell history as a line of the
# engagement.  The console is one of them; the address of the server and
# the names of the hosts are added by the caller.
DEFAULT_MARKERS = ("umbra ",)

# The files that hold the history of the shell.  The list is short on
# purpose: the console scrubs what it knows, and it never guesses.
HISTORY_FILES = (
    os.path.join("~", ".bash_history"),
    os.path.join("~", ".zsh_history"),
)


def _expand(path: str) -> str:
    return os.path.expanduser(path)


def history_files() -> List[str]:
    """The files that hold the history of the shell, if they exist."""
    out: List[str] = []
    for path in HISTORY_FILES:
        full = _expand(path)
        if os.path.isfile(full):
            out.append(full)
    return out


def scrub_history(markers: Optional[Iterable[str]] = None,
                  dry_run: bool = False) -> Dict[str, object]:
    """Take the lines of the console out of the history of the shell.

    The lines that name the console (or the server, or a host of the
    engagement) go; the rest of the file stays exactly as it was.  The
    file keeps its mode and its owner, and a file that cannot be read
    is reported instead of being touched.
    """
    marks = [m for m in (markers or DEFAULT_MARKERS) if m]
    files = history_files()
    removed = 0
    scanned = 0
    touched: List[str] = []
    problems: List[str] = []
    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.read().splitlines(keepends=True)
        except OSError as exc:
            problems.append(f"{path}: {exc}")
            continue
        scanned += len(lines)
        kept = [line for line in lines
                if not any(mark in line for mark in marks)]
        dropped = len(lines) - len(kept)
        if not dropped:
            continue
        removed += dropped
        touched.append(path)
        if dry_run:
            continue
        try:
            # The history is written through a file in the same
            # directory: a half-written history is worse than a dirty
            # one.
            handle_dir = os.path.dirname(path) or "."
            tmp = tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=handle_dir, delete=False)
            with tmp:
                tmp.writelines(kept)
            try:
                shutil.copymode(path, tmp.name)
            except OSError:
                pass
            os.replace(tmp.name, path)
        except OSError as exc:
            problems.append(f"{path}: {exc}")
    return {
        "files": files,
        "touched": touched,
        "scanned": scanned,
        "removed": removed,
        "dry_run": dry_run,
        "problems": problems,
    }


def local_traces(db_path: str = "") -> List[str]:
    """The files of the engagement that live on the machine of the operator.

    The notebook of the console is one of them.  The rest of the state
    directory is one of them: the exports, the downloads and the
    temporary files the console leaves behind.
    """
    out: List[str] = []
    notebook = db_path or os.environ.get(
        "UMBRA_DB", os.path.join(os.path.expanduser("~"), ".umbra", "state.db"))
    notebook = _expand(notebook)
    if os.path.exists(notebook):
        out.append(notebook)
    root = os.path.dirname(notebook)
    if root and os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            if full in out:
                continue
            out.append(full)
    return out


def remove_traces(paths: Iterable[str], dry_run: bool = False) -> Dict[str, object]:
    """Remove the files of the engagement from the machine of the operator.

    The dry run says what would go; the real run takes it away and
    reports the ones it could not.
    """
    removed: List[str] = []
    problems: List[str] = []
    for path in paths:
        if not os.path.exists(path):
            continue
        if dry_run:
            removed.append(path)
            continue
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            removed.append(path)
        except OSError as exc:
            problems.append(f"{path}: {exc}")
    return {"removed": removed, "problems": problems, "dry_run": dry_run}


def summarise(history: Dict[str, object], traces: Dict[str, object]) -> str:
    """One line an operator can read at the end of the engagement."""
    removed = int(history.get("removed", 0) or 0)
    lines = int(history.get("scanned", 0) or 0)
    files = traces.get("removed") or []
    problems = list(history.get("problems") or []) + list(traces.get("problems") or [])
    out = (f"the history of the shell: {removed} of {lines} lines name the "
           f"engagement and are gone")
    out += f"; the files of the console: {len(files)} are gone"
    if problems:
        out += f"; {len(problems)} could not be touched"
    return out
