"""Local engagement state for the operator console (SQLite).

The team server owns the authoritative state; this database is the console's
own notebook.  It answers the questions an operator asks constantly and that
the server is a poor place to answer:

  * what did *I* run on that implant, and what did it print?
  * which task produced that output I am looking at three hours later?
  * what did the other operator leave me as a note?

Everything is kept in one SQLite file, so the console stays a single
dependency-free program: `sqlite3` ships with Python, no driver, no service.
The schema is deliberately small and boring:

    sessions   one row per console session (who, where, when)
    tasks      one row per task the console submitted
    results    one row per result the console collected
    notes      free-form notes the operator left for the team

The database never holds a credential: the operator token, the agent PSK and
the session keys stay in memory only.  What lands here is metadata and task
output, which is exactly what the server already keeps -- but on the
operator's own disk, where it survives a server restart and can be searched
offline.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

# The schema version is stored in the `meta` table.  Bump it when the schema
# changes; `open()` refuses to work with a newer file than it understands.
SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT    NOT NULL DEFAULT '',
    operator   TEXT    NOT NULL DEFAULT '',
    server     TEXT    NOT NULL DEFAULT '',
    started    INTEGER NOT NULL,
    ended      INTEGER
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id    TEXT    PRIMARY KEY,
    session    INTEGER,
    agent      TEXT    NOT NULL DEFAULT '',
    kind       TEXT    NOT NULL DEFAULT '',
    args       TEXT    NOT NULL DEFAULT '{}',
    submitted  INTEGER NOT NULL,
    state      TEXT    NOT NULL DEFAULT 'queued'
);

CREATE TABLE IF NOT EXISTS results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    -- One row per task: collecting the same result twice replaces it
    -- instead of piling up duplicates.
    task_id    TEXT    NOT NULL UNIQUE,
    code       INTEGER NOT NULL DEFAULT 0,
    output     BLOB,
    error      TEXT    NOT NULL DEFAULT '',
    finished   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent      TEXT NOT NULL DEFAULT '',
    body       TEXT NOT NULL,
    created    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS tasks_agent_idx ON tasks(agent);
CREATE INDEX IF NOT EXISTS results_task_idx ON results(task_id);
CREATE INDEX IF NOT EXISTS notes_agent_idx ON notes(agent);
"""


class StateError(Exception):
    """Raised when the local state database cannot be used."""


class StateStore:
    """A small SQLite-backed notebook for one operator console."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        self._conn: Optional[sqlite3.Connection] = None

    # -- lifecycle ------------------------------------------------------
    def open(self) -> "StateStore":
        """Open (and if needed create) the database."""
        directory = os.path.dirname(self.path)
        if directory:
            try:
                os.makedirs(directory, exist_ok=True)
            except OSError as exc:
                raise StateError(f"cannot create {directory}: {exc}") from exc
        try:
            conn = sqlite3.connect(self.path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            # WAL keeps a long running read (a search) from blocking the
            # write that happens when the next task result arrives.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA)
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
            if row is None:
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
            else:
                try:
                    found = int(row["value"])
                except (TypeError, ValueError):
                    found = -1
                if found > SCHEMA_VERSION:
                    conn.close()
                    raise StateError(
                        f"the database was written by a newer umbra "
                        f"(schema {found} > {SCHEMA_VERSION})")
            conn.commit()
        except sqlite3.Error as exc:
            raise StateError(f"cannot open {self.path}: {exc}") from exc
        self._conn = conn
        return self

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.commit()
            except sqlite3.Error:
                pass
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "StateStore":
        return self.open()

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise StateError("the state database is not open")
        return self._conn

    # -- writing --------------------------------------------------------
    def start_session(self, operator: str, server: str, session_id: str = "") -> int:
        """Record the start of a console session and return its row id."""
        cur = self.conn.execute(
            "INSERT INTO sessions(session_id, operator, server, started) "
            "VALUES(?, ?, ?, ?)",
            (session_id or "", operator or "", server or "", int(time.time())),
        )
        self.conn.commit()
        return int(cur.lastrowid or 0)

    def end_session(self, session: int) -> None:
        if not session:
            return
        self.conn.execute(
            "UPDATE sessions SET ended = ? WHERE id = ?", (int(time.time()), session))
        self.conn.commit()

    def record_task(self, task_id: str, agent: str, kind: str,
                    args: Any = None, session: int = 0) -> None:
        """Record that the console queued a task."""
        if not task_id:
            return
        try:
            blob = json.dumps(args or {}, sort_keys=True, default=str)
        except (TypeError, ValueError):
            blob = "{}"
        self.conn.execute(
            "INSERT OR REPLACE INTO tasks"
            "(task_id, session, agent, kind, args, submitted, state) "
            "VALUES(?, ?, ?, ?, ?, ?, 'queued')",
            (task_id, session or None, agent or "", kind or "", blob, int(time.time())),
        )
        self.conn.commit()

    def record_result(self, task_id: str, code: int = 0,
                      output: Any = b"", error: str = "") -> None:
        """Record the outcome of a task and mark the task as done."""
        if not task_id:
            return
        if isinstance(output, str):
            output = output.encode("utf-8", "replace")
        elif isinstance(output, (bytes, bytearray, memoryview)):
            output = bytes(output)
        elif output is None:
            output = b""
        else:
            output = str(output).encode("utf-8", "replace")
        now = int(time.time())
        self.conn.execute(
            "INSERT OR REPLACE INTO results(task_id, code, output, error, finished) "
            "VALUES(?, ?, ?, ?, ?)",
            (task_id, int(code or 0), output, error or "", now),
        )
        self.conn.execute(
            "UPDATE tasks SET state = ? WHERE task_id = ?",
            ("done" if not code and not error else "failed", task_id),
        )
        self.conn.commit()

    def add_note(self, body: str, agent: str = "") -> int:
        """Leave a note for the team (or for yourself tomorrow)."""
        if not body or not body.strip():
            raise StateError("a note needs a body")
        cur = self.conn.execute(
            "INSERT INTO notes(agent, body, created) VALUES(?, ?, ?)",
            (agent or "", body.strip(), int(time.time())),
        )
        self.conn.commit()
        return int(cur.lastrowid or 0)

    # -- reading --------------------------------------------------------
    def tasks(self, agent: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """The recorded tasks, newest first."""
        limit = max(1, min(int(limit or 50), 1000))
        if agent:
            cur = self.conn.execute(
                "SELECT * FROM tasks WHERE agent = ? ORDER BY submitted DESC LIMIT ?",
                (agent, limit))
        else:
            cur = self.conn.execute(
                "SELECT * FROM tasks ORDER BY submitted DESC LIMIT ?", (limit,))
        return [self._task_row(row) for row in cur.fetchall()]

    def task(self, task_id: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
        row = cur.fetchone()
        return self._task_row(row) if row else None

    def results(self, task_id: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """The recorded results, newest first."""
        limit = max(1, min(int(limit or 50), 1000))
        if task_id:
            cur = self.conn.execute(
                "SELECT * FROM results WHERE task_id = ? ORDER BY finished DESC LIMIT ?",
                (task_id, limit))
        else:
            cur = self.conn.execute(
                "SELECT * FROM results ORDER BY finished DESC LIMIT ?", (limit,))
        out = []
        for row in cur.fetchall():
            item = dict(row)
            item["output"] = bytes(item["output"] or b"")
            out.append(item)
        return out

    def notes(self, agent: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit or 50), 1000))
        if agent:
            cur = self.conn.execute(
                "SELECT * FROM notes WHERE agent = ? ORDER BY created DESC LIMIT ?",
                (agent, limit))
        else:
            cur = self.conn.execute(
                "SELECT * FROM notes ORDER BY created DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

    def search(self, needle: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search task arguments, task ids, notes and result output."""
        needle = (needle or "").strip()
        if not needle:
            return []
        limit = max(1, min(int(limit or 50), 1000))
        pattern = f"%{needle}%"
        out: List[Dict[str, Any]] = []
        cur = self.conn.execute(
            "SELECT task_id, agent, kind, args, submitted FROM tasks "
            "WHERE task_id LIKE ? OR args LIKE ? OR kind LIKE ? "
            "ORDER BY submitted DESC LIMIT ?",
            (pattern, pattern, pattern, limit))
        for row in cur.fetchall():
            out.append({
                "where": "task",
                "task_id": row["task_id"],
                "agent": row["agent"],
                "kind": row["kind"],
                "args": row["args"],
                "at": row["submitted"],
            })
        cur = self.conn.execute(
            "SELECT id, agent, body, created FROM notes "
            "WHERE body LIKE ? OR agent LIKE ? ORDER BY created DESC LIMIT ?",
            (pattern, pattern, limit))
        for row in cur.fetchall():
            out.append({
                "where": "note",
                "note_id": row["id"],
                "agent": row["agent"],
                "body": row["body"],
                "at": row["created"],
            })
        cur = self.conn.execute(
            "SELECT id, task_id, code, error, finished, output FROM results "
            "WHERE CAST(output AS TEXT) LIKE ? OR error LIKE ? "
            "ORDER BY finished DESC LIMIT ?",
            (pattern, pattern, limit))
        for row in cur.fetchall():
            out.append({
                "where": "result",
                "result_id": row["id"],
                "task_id": row["task_id"],
                "code": row["code"],
                "error": row["error"],
                "at": row["finished"],
                "excerpt": self._excerpt(bytes(row["output"] or b""), needle),
            })
        out.sort(key=lambda item: item.get("at") or 0, reverse=True)
        return out[:limit]

    def stats(self) -> Dict[str, Any]:
        """A small summary of the local notebook."""
        def count(sql: str) -> int:
            row = self.conn.execute(sql).fetchone()
            return int(row[0]) if row else 0

        agents = count("SELECT COUNT(DISTINCT agent) FROM tasks WHERE agent != ''")
        kinds = [
            {"kind": row["kind"], "count": int(row["n"])}
            for row in self.conn.execute(
                "SELECT kind, COUNT(*) AS n FROM tasks GROUP BY kind "
                "ORDER BY n DESC, kind ASC")
        ]
        first = self.conn.execute(
            "SELECT MIN(started) AS a, MAX(started) AS b FROM sessions").fetchone()
        return {
            "path": self.path,
            "sessions": count("SELECT COUNT(*) FROM sessions"),
            "tasks": count("SELECT COUNT(*) FROM tasks"),
            "results": count("SELECT COUNT(*) FROM results"),
            "notes": count("SELECT COUNT(*) FROM notes"),
            "agents": agents,
            "kinds": kinds,
            "first_session": int(first["a"]) if first and first["a"] else 0,
            "last_session": int(first["b"]) if first and first["b"] else 0,
        }

    def export(self, path: str) -> str:
        """Write the whole notebook to a JSON file and return its path."""
        payload = {
            "sessions": [dict(row) for row in self.conn.execute(
                "SELECT * FROM sessions ORDER BY id").fetchall()],
            "tasks": [self._task_row(row) for row in self.conn.execute(
                "SELECT * FROM tasks ORDER BY submitted").fetchall()],
            "results": [dict(row) for row in self.conn.execute(
                "SELECT id, task_id, code, error, finished FROM results "
                "ORDER BY finished").fetchall()],
            "notes": [dict(row) for row in self.conn.execute(
                "SELECT * FROM notes ORDER BY created").fetchall()],
        }
        target = os.path.abspath(os.path.expanduser(path))
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True, default=str)
        return target

    # -- helpers --------------------------------------------------------
    @staticmethod
    def _task_row(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        try:
            item["args"] = json.loads(item.get("args") or "{}")
        except (TypeError, ValueError):
            item["args"] = {}
        return item

    @staticmethod
    def _excerpt(blob: bytes, needle: str) -> str:
        text = blob.decode("utf-8", "replace")
        pos = text.lower().find(needle.lower())
        if pos < 0:
            return text[:160]
        start = max(0, pos - 60)
        return text[start:start + 200]
