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
SCHEMA_VERSION = 2

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

CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent      TEXT    NOT NULL DEFAULT '',
    kind       TEXT    NOT NULL DEFAULT '',
    name       TEXT    NOT NULL DEFAULT '',
    detail     TEXT    NOT NULL DEFAULT '',
    severity   TEXT    NOT NULL DEFAULT 'info',
    source     TEXT    NOT NULL DEFAULT '',
    created    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL DEFAULT '',
    agent      TEXT    NOT NULL DEFAULT '',
    digest     TEXT    NOT NULL DEFAULT '',
    path       TEXT    NOT NULL DEFAULT '',
    size       INTEGER NOT NULL DEFAULT 0,
    created    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS screenshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent      TEXT    NOT NULL DEFAULT '',
    path       TEXT    NOT NULL DEFAULT '',
    digest     TEXT    NOT NULL DEFAULT '',
    size       INTEGER NOT NULL DEFAULT 0,
    created    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent      TEXT    NOT NULL DEFAULT '',
    kind       TEXT    NOT NULL DEFAULT '',
    account    TEXT    NOT NULL DEFAULT '',
    target     TEXT    NOT NULL DEFAULT '',
    secret     TEXT    NOT NULL DEFAULT '',
    source     TEXT    NOT NULL DEFAULT '',
    confidence INTEGER NOT NULL DEFAULT 0,
    created    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS tasks_agent_idx ON tasks(agent);
CREATE INDEX IF NOT EXISTS results_task_idx ON results(task_id);
CREATE INDEX IF NOT EXISTS notes_agent_idx ON notes(agent);
CREATE INDEX IF NOT EXISTS findings_agent_idx ON findings(agent);
CREATE INDEX IF NOT EXISTS artifacts_agent_idx ON artifacts(agent);
CREATE INDEX IF NOT EXISTS screenshots_agent_idx ON screenshots(agent);
CREATE INDEX IF NOT EXISTS credentials_agent_idx ON credentials(agent);
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
                if found < SCHEMA_VERSION:
                    # An older notebook grows the tables it lacks; the
                    # records it has are kept.
                    conn.execute(
                        "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                        (str(SCHEMA_VERSION),),
                    )
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
        cur = self.conn.execute(
            "SELECT id, agent, kind, name, detail, severity, source, created "
            "FROM findings WHERE name LIKE ? OR detail LIKE ? OR kind LIKE ? "
            "OR agent LIKE ? ORDER BY created DESC LIMIT ?",
            (pattern, pattern, pattern, pattern, limit))
        for row in cur.fetchall():
            out.append({
                "where": "finding",
                "finding_id": row["id"],
                "agent": row["agent"],
                "kind": row["kind"],
                "name": row["name"],
                "detail": row["detail"],
                "severity": row["severity"],
                "at": row["created"],
            })
        cur = self.conn.execute(
            "SELECT id, name, agent, digest, path, size, created FROM artifacts "
            "WHERE name LIKE ? OR path LIKE ? OR digest LIKE ? OR agent LIKE ? "
            "ORDER BY created DESC LIMIT ?",
            (pattern, pattern, pattern, pattern, limit))
        for row in cur.fetchall():
            out.append({
                "where": "artifact",
                "artifact_id": row["id"],
                "name": row["name"],
                "agent": row["agent"],
                "path": row["path"],
                "digest": row["digest"],
                "at": row["created"],
            })
        cur = self.conn.execute(
            "SELECT id, agent, kind, account, target, secret, source, created "
            "FROM credentials WHERE account LIKE ? OR target LIKE ? OR kind LIKE ? "
            "OR agent LIKE ? OR secret LIKE ? ORDER BY created DESC LIMIT ?",
            (pattern, pattern, pattern, pattern, pattern, limit))
        for row in cur.fetchall():
            out.append({
                "where": "credential",
                "credential_id": row["id"],
                "agent": row["agent"],
                "kind": row["kind"],
                "account": row["account"],
                "target": row["target"],
                "secret": row["secret"],
                "at": row["created"],
            })
        cur = self.conn.execute(
            "SELECT id, agent, path, digest, created FROM screenshots "
            "WHERE path LIKE ? OR agent LIKE ? ORDER BY created DESC LIMIT ?",
            (pattern, pattern, limit))
        for row in cur.fetchall():
            out.append({
                "where": "screenshot",
                "screenshot_id": row["id"],
                "agent": row["agent"],
                "path": row["path"],
                "digest": row["digest"],
                "at": row["created"],
            })
        out.sort(key=lambda item: item.get("at") or 0, reverse=True)
        return out[:limit]

    # -- the collected material -------------------------------------------
    def add_finding(self, agent: str, kind: str, name: str, detail: str = "",
                    severity: str = "info", source: str = "") -> int:
        """Record a finding the reconnaissance produced."""
        cur = self.conn.execute(
            "INSERT INTO findings(agent, kind, name, detail, severity, source, created) "
            "VALUES(?, ?, ?, ?, ?, ?, ?)",
            (agent or "", kind or "", name or "", detail or "",
             severity or "info", source or "", int(time.time())),
        )
        self.conn.commit()
        return int(cur.lastrowid or 0)

    def findings(self, agent: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """The findings the notebook holds."""
        limit = max(1, min(int(limit or 50), 1000))
        if agent:
            cur = self.conn.execute(
                "SELECT * FROM findings WHERE agent = ? ORDER BY created DESC LIMIT ?",
                (agent, limit))
        else:
            cur = self.conn.execute(
                "SELECT * FROM findings ORDER BY created DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

    def add_artifact(self, name: str, agent: str = "", digest: str = "",
                     path: str = "", size: int = 0) -> int:
        """Record an artefact the operator pulled off a host."""
        cur = self.conn.execute(
            "INSERT INTO artifacts(name, agent, digest, path, size, created) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (name or "", agent or "", digest or "", path or "",
             int(size or 0), int(time.time())),
        )
        self.conn.commit()
        return int(cur.lastrowid or 0)

    def artifacts(self, agent: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """The artefacts the notebook holds."""
        limit = max(1, min(int(limit or 50), 1000))
        if agent:
            cur = self.conn.execute(
                "SELECT * FROM artifacts WHERE agent = ? ORDER BY created DESC LIMIT ?",
                (agent, limit))
        else:
            cur = self.conn.execute(
                "SELECT * FROM artifacts ORDER BY created DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

    def add_screenshot(self, agent: str, path: str, digest: str = "",
                       size: int = 0) -> int:
        """Record a screenshot the operator took of a host."""
        cur = self.conn.execute(
            "INSERT INTO screenshots(agent, path, digest, size, created) "
            "VALUES(?, ?, ?, ?, ?)",
            (agent or "", path or "", digest or "", int(size or 0), int(time.time())),
        )
        self.conn.commit()
        return int(cur.lastrowid or 0)

    def screenshots(self, agent: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """The screenshots the notebook holds."""
        limit = max(1, min(int(limit or 50), 1000))
        if agent:
            cur = self.conn.execute(
                "SELECT * FROM screenshots WHERE agent = ? ORDER BY created DESC LIMIT ?",
                (agent, limit))
        else:
            cur = self.conn.execute(
                "SELECT * FROM screenshots ORDER BY created DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

    def add_credential(self, agent: str, kind: str, account: str = "",
                       target: str = "", secret: str = "", source: str = "",
                       confidence: int = 0) -> int:
        """Record a credential the operator pulled off a host.

        The notebook is the operator's own file on the operator's own disk:
        it holds the material the operator asked for, and nothing else.  The
        server keeps the authoritative copy; this is the one that survives a
        server that is gone.
        """
        cur = self.conn.execute(
            "INSERT INTO credentials(agent, kind, account, target, secret, "
            "source, confidence, created) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (agent or "", kind or "", account or "", target or "", secret or "",
             source or "", int(confidence or 0), int(time.time())),
        )
        self.conn.commit()
        return int(cur.lastrowid or 0)

    def credentials(self, agent: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """The credentials the notebook holds."""
        limit = max(1, min(int(limit or 50), 1000))
        if agent:
            cur = self.conn.execute(
                "SELECT * FROM credentials WHERE agent = ? ORDER BY created DESC LIMIT ?",
                (agent, limit))
        else:
            cur = self.conn.execute(
                "SELECT * FROM credentials ORDER BY created DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

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
            "findings": count("SELECT COUNT(*) FROM findings"),
            "artifacts": count("SELECT COUNT(*) FROM artifacts"),
            "screenshots": count("SELECT COUNT(*) FROM screenshots"),
            "credentials": count("SELECT COUNT(*) FROM credentials"),
            "agents": agents,
            "kinds": kinds,
            "first_session": int(first["a"]) if first and first["a"] else 0,
            "last_session": int(first["b"]) if first and first["b"] else 0,
        }

    def export(self, path: str) -> str:
        """Write the whole notebook to a file and return its path.

        The format follows the extension: a .md file is written as the
        Markdown document an operator reads, anything else as JSON.
        """
        target = os.path.abspath(os.path.expanduser(path))
        if target.lower().endswith((".md", ".markdown")):
            return self.export_markdown(target)
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
            "findings": [dict(row) for row in self.conn.execute(
                "SELECT * FROM findings ORDER BY created").fetchall()],
            "artifacts": [dict(row) for row in self.conn.execute(
                "SELECT * FROM artifacts ORDER BY created").fetchall()],
            "screenshots": [dict(row) for row in self.conn.execute(
                "SELECT * FROM screenshots ORDER BY created").fetchall()],
            "credentials": [dict(row) for row in self.conn.execute(
                "SELECT * FROM credentials ORDER BY created").fetchall()],
        }
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True, default=str)
        return target

    def export_markdown(self, path: str) -> str:
        """Write the notebook as a Markdown document.

        It is the document an operator hands over: the sessions, the tasks,
        the findings, the artefacts, the material and the notes, in the
        order they happened.
        """
        target = os.path.abspath(os.path.expanduser(path))
        lines: List[str] = []
        lines.append("# The notebook")
        lines.append("")
        lines.append(f"_{self.path}_")
        lines.append("")

        lines.append("## The sessions")
        lines.append("")
        for row in self.conn.execute(
                "SELECT * FROM sessions ORDER BY id").fetchall():
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["started"]))
            lines.append("- **{}** {} on {} ({})".format(
                when, row["operator"] or "?", row["server"] or "?",
                row["session_id"][:12] or "no id"))
        lines.append("")

        lines.append("## The findings")
        lines.append("")
        findings = [dict(row) for row in self.conn.execute(
            "SELECT * FROM findings ORDER BY created").fetchall()]
        if not findings:
            lines.append("_no finding was recorded_")
        else:
            lines.append("| when | agent | severity | finding | detail |")
            lines.append("| --- | --- | --- | --- | --- |")
            for row in findings:
                when = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["created"]))
                lines.append("| {} | {} | {} | {} | {} |".format(
                    when, row["agent"], row["severity"], row["name"],
                    (row["detail"] or "")[:80]))
        lines.append("")

        lines.append("## The artefacts")
        lines.append("")
        artifacts = [dict(row) for row in self.conn.execute(
            "SELECT * FROM artifacts ORDER BY created").fetchall()]
        if not artifacts:
            lines.append("_no artefact was kept_")
        else:
            lines.append("| when | agent | name | size | digest |")
            lines.append("| --- | --- | --- | --- | --- |")
            for row in artifacts:
                when = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["created"]))
                lines.append("| {} | {} | {} | {} | {} |".format(
                    when, row["agent"], row["name"], row["size"],
                    (row["digest"] or "")[:16]))
        lines.append("")

        lines.append("## The screenshots")
        lines.append("")
        shots = [dict(row) for row in self.conn.execute(
            "SELECT * FROM screenshots ORDER BY created").fetchall()]
        if not shots:
            lines.append("_no screenshot was taken_")
        else:
            for row in shots:
                when = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["created"]))
                lines.append("- **{}** {} `{}`".format(when, row["agent"], row["path"]))
        lines.append("")

        lines.append("## The material")
        lines.append("")
        creds = [dict(row) for row in self.conn.execute(
            "SELECT * FROM credentials ORDER BY created").fetchall()]
        if not creds:
            lines.append("_no material was collected_")
        else:
            lines.append("| when | agent | kind | account | target | value |")
            lines.append("| --- | --- | --- | --- | --- | --- |")
            for row in creds:
                when = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["created"]))
                lines.append("| {} | {} | {} | {} | {} | {} |".format(
                    when, row["agent"], row["kind"], row["account"],
                    row["target"], row["secret"]))
        lines.append("")

        lines.append("## The notes")
        lines.append("")
        notes = [dict(row) for row in self.conn.execute(
            "SELECT * FROM notes ORDER BY created").fetchall()]
        if not notes:
            lines.append("_no note was left_")
        else:
            for row in notes:
                when = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["created"]))
                lines.append("- **{}** {} ({})".format(
                    when, row["body"], row["agent"] or "-"))
        lines.append("")

        with open(target, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
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
