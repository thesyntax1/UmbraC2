#!/usr/bin/env python3
"""Static cross-implementation consistency check.

The Go, Rust, Kotlin and Python implementations must agree on every wire
constant. ``contracts/vectors.json`` proves the *behaviour* is identical; this
script proves the *tables* are identical, which catches the "one language still
uses 0x1A" class of bug before it reaches a build.

    python3 tools/check_consistency.py
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "operator"))

try:  # the Python reference is the source of truth for the message registry
    from umbra_cli import wire as wire_module
except ImportError as exc:  # pragma: no cover - only if the tree is incomplete
    print(f"check_consistency: cannot import the Python reference: {exc}", file=sys.stderr)
    raise SystemExit(2)

SOURCES = {
    "python": [
        "operator/umbra_cli/wire.py",
        "operator/umbra_cli/upk.py",
        "operator/umbra_cli/crypto.py",
        "operator/umbra_cli/session.py",
    ],
    "go": [
        "server/internal/wire/wire.go",
        "server/internal/upk/upk.go",
        "server/internal/crypt/crypt.go",
        "server/internal/session/session.go",
    ],
    "rust": [
        "implant/rust/src/wire.rs",
        "implant/rust/src/upk.rs",
        "implant/rust/src/crypto.rs",
        "implant/rust/src/session.rs",
    ],
    "kotlin": [
        "implant/android/app/src/main/java/io/umbra/beacon/Wire.kt",
        "implant/android/app/src/main/java/io/umbra/beacon/Upk.kt",
        "implant/android/app/src/main/java/io/umbra/beacon/Crypto.kt",
        "implant/android/app/src/main/java/io/umbra/beacon/Session.kt",
    ],
}

# (canonical name, regex per language) -- the regex must capture the value.
SPECS: list[tuple[str, dict[str, str]]] = [
    # ---- frame layout -------------------------------------------------
    ("VERSION", {"python": r"^VERSION = (\d+)", "go": r"Version\s+byte\s*=\s*(\d+)",
                 "rust": r"pub const VERSION: u8 = (\d+)", "kotlin": r"const val VERSION: Byte = (\d+)"}),
    ("PRELUDE_LEN", {"python": r"^PRELUDE_LEN = (\d+)", "go": r"PreludeLen\s*=\s*(\d+)",
                     "rust": r"pub const PRELUDE_LEN: usize = (\d+)", "kotlin": r"const val PRELUDE_LEN = (\d+)"}),
    ("NONCE_LEN", {"python": r"^NONCE_LEN = (\d+)", "go": r"NonceLen\s*=\s*(\d+)",
                   "rust": r"pub const NONCE_LEN: usize = (\d+)", "kotlin": r"const val NONCE_LEN = (\d+)"}),
    ("TAG_LEN", {"python": r"^TAG_LEN = (\d+)", "go": r"TagLen\s*=\s*(\d+)",
                 "rust": r"pub const TAG_LEN: usize = (\d+)", "kotlin": r"const val TAG_LEN = (\d+)"}),
    ("MAX_BODY", {"python": r"^MAX_BODY = 1 << (\d+)", "go": r"MaxBody\s*=\s*1 << (\d+)",
                  "rust": r"pub const MAX_BODY: usize = 1 << (\d+)", "kotlin": r"const val MAX_BODY = 1 shl (\d+)"}),
    # ---- suites / flags ----------------------------------------------
    ("SUITE_AES", {"python": r"^SUITE_AES256_GCM = (\d+)", "go": r"SuiteAES256GCM\s+byte\s*=\s*(\d+)",
                   "rust": r"pub const SUITE_AES256_GCM: u8 = (\d+)", "kotlin": r"const val SUITE_AES256_GCM = (\d+)"}),
    ("SUITE_CHACHA", {"python": r"^SUITE_CHACHA20_POLY1305 = (\d+)", "go": r"SuiteChaCha20Poly1305\s+byte\s*=\s*(\d+)",
                      "rust": r"pub const SUITE_CHACHA20_POLY1305: u8 = (\d+)", "kotlin": None}),
    ("FLAG_BOOTSTRAP", {"python": r"^FLAG_BOOTSTRAP = (0x[0-9A-Fa-f]+|\d+)", "go": r"FlagBootstrap\s+byte\s*=\s*(0x[0-9A-Fa-f]+|\d+)",
                        "rust": r"pub const FLAG_BOOTSTRAP: u8 = (0x[0-9A-Fa-f]+|\d+)", "kotlin": r"const val FLAG_BOOTSTRAP = (0x[0-9A-Fa-f]+|\d+)"}),
    # ---- upk tags / limits -------------------------------------------
    ("UPK_MAX_DEPTH", {"python": r"^MAX_DEPTH = (\d+)", "go": r"MaxDepth\s*=\s*(\d+)",
                       "rust": r"pub const MAX_DEPTH: usize = (\d+)", "kotlin": r"const val MAX_DEPTH = (\d+)"}),
    ("UPK_MAX_ITEMS", {"python": r"^MAX_ITEMS = 1 << (\d+)", "go": r"MaxItems\s*=\s*1 << (\d+)",
                       "rust": r"pub const MAX_ITEMS: u64 = 1 << (\d+)", "kotlin": r"const val MAX_ITEMS = 1 shl (\d+)"}),
    ("UPK_MAX_STRING", {"python": r"^MAX_STRING = 1 << (\d+)", "go": r"MaxString\s*=\s*1 << (\d+)",
                        "rust": r"pub const MAX_STRING: usize = 1 << (\d+)", "kotlin": r"const val MAX_STRING = 1 shl (\d+)"}),
    ("UPK_MAX_TOTAL", {"python": r"^MAX_TOTAL = 4 << (\d+)", "go": r"MaxTotal\s*=\s*4 << (\d+)",
                       "rust": r"pub const MAX_TOTAL: usize = 4 << (\d+)", "kotlin": r"const val MAX_TOTAL = 4 shl (\d+)"}),
    ("UPK_TAG_MAP", {"python": r"^T_MAP = (0x[0-9A-Fa-f]+)", "go": r"\btMap\s+byte = (0x[0-9A-Fa-f]+)",
                     "rust": r"const T_MAP: u8 = (0x[0-9A-Fa-f]+)", "kotlin": r"const val T_MAP = (0x[0-9A-Fa-f]+)"}),
    ("UPK_TAG_BIN", {"python": r"^T_BIN = (0x[0-9A-Fa-f]+)", "go": r"\btBin\s+byte = (0x[0-9A-Fa-f]+)",
                     "rust": r"const T_BIN: u8 = (0x[0-9A-Fa-f]+)", "kotlin": r"const val T_BIN = (0x[0-9A-Fa-f]+)"}),
    # ---- roles --------------------------------------------------------
    ("ROLE_AGENT", {"python": r"^ROLE_AGENT = (\d+)", "go": r"RoleAgent\s+byte\s*=\s*(\d+)",
                    "rust": r"pub const ROLE_AGENT: u8 = (\d+)", "kotlin": r"const val ROLE_AGENT = (\d+)"}),
    ("ROLE_OPERATOR", {"python": r"^ROLE_OPERATOR = (\d+)", "go": r"RoleOperator\s+byte\s*=\s*(\d+)",
                       "rust": r"pub const ROLE_OPERATOR: u8 = (\d+)", "kotlin": r"const val ROLE_OPERATOR = (\d+)"}),
    # ---- rekey threshold ---------------------------------------------
    ("REKEY_AFTER", {"python": r"^REKEY_AFTER = 1 << (\d+)", "go": r"RekeyAfter\s*=\s*1 << (\d+)",
                     "rust": r"pub const REKEY_AFTER: u64 = 1 << (\d+)", "kotlin": r"const val REKEY_AFTER = 1L shl (\d+)"}),
    # ---- the handshake version and the module ABI --------------------
    ("HELLO_VERSION", {"python": r"^HELLO_VERSION = (\d+)", "go": r"HelloVersion\s+byte\s*=\s*(\d+)",
                       "rust": r"pub const HELLO_VERSION: u8 = (\d+)", "kotlin": r"const val HELLO_VERSION = (\d+)"}),
    ("ABI_VERSION", {"python": r"^ABI_VERSION = (\d+)", "go": r"ABIVersion\s+byte\s*=\s*(\d+)",
                     "rust": r"pub const ABI_VERSION: u8 = (\d+)", "kotlin": r"const val ABI_VERSION = (\d+)"}),
]

# Message type tables. Names differ in case/prefix across languages, so every
# extractor normalises to UPPER_SNAKE before comparing.
MSG_SPECS = {
    "python": r"^\s{4}(?!FRAME_)([A-Z][A-Z_]+) = (0x[0-9A-Fa-f]+)",
    "go": r"\bMsg([A-Z]\w*)\s+byte\s*=\s*(0x[0-9A-Fa-f]+)",
    "rust": r"pub const MSG_([A-Z_]+): u8 = (0x[0-9A-Fa-f]+)",
    "kotlin": r"const val MSG_([A-Z_]+) = (0x[0-9A-Fa-f]+)",
}

# Handshake payload markers (0x01/0x02) are spelled differently everywhere.
MARKER_SPECS = {
    "python": r"^\s{4}FRAME_([A-Z_]+) = (0x[0-9A-Fa-f]+)",
    "go": r"\bMarker([A-Z]\w*)\s+byte\s*=\s*(0x[0-9A-Fa-f]+)",
    "rust": r"pub const MARKER_([A-Z_]+): u8 = (0x[0-9A-Fa-f]+)",
    "kotlin": r"const val MARKER_([A-Z_]+) = (0x[0-9A-Fa-f]+)",
}

MARKER_ALIASES = {"VERSION": "HELLO", "HELLO": "HELLO", "HELLO_ACK": "HELLO_ACK"}

LABEL_SPECS = {
    "python": r'^LABEL_([A-Z]+) = b"(umbra/v1/[a-z]+)"',
    "go": r"Label([A-Za-z]+)\s*= \[\]byte\(\"(umbra/v1/[a-z]+)\"\)",
    "rust": r'pub const LABEL_([A-Z]+): &\[u8\] = b"(umbra/v1/[a-z]+)"',
    "kotlin": r'val LABEL_([A-Z]+) = "(umbra/v1/[a-z]+)"\.toByteArray',
}

# The label of the attestation lives in a namespace of its own: it is not
# a session label, it signs a report of the engagement, and a signature
# over a report must never be a signature over a frame.
ATTEST_SPECS = {
    "python": r'^LABEL_(ATTEST) = b"(umbra/w1/[a-z]+)"',
    "go": r"Label(Attest)\s*= \[\]byte\(\"(umbra/w1/[a-z]+)\"\)",
    "rust": r'pub const LABEL_(ATTEST): &\[u8\] = b"(umbra/w1/[a-z]+)"',
    "kotlin": r'val LABEL_(ATTEST) = "(umbra/w1/[a-z]+)"\.toByteArray',
}


def camel_to_snake(name: str) -> str:
    """Normalise Go's CamelCase to the UPPER_SNAKE used by the other languages."""
    if name.isupper():
        return name
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).upper()


def read(rel: str) -> str:
    path = os.path.join(ROOT, rel)
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def sources(lang: str) -> str:
    return "\n".join(read(p) for p in SOURCES[lang])


def norm(value: str) -> str:
    return str(int(value, 0))


def compare_table(
    kind: str,
    specs: dict[str, str],
    corpus: dict[str, str],
    normalise,
    aliases: dict[str, str] | None = None,
    numeric: bool = True,
) -> int:
    """Extract one table from every language and report disagreements."""
    table: dict[str, dict[str, str]] = {}
    for lang, pattern in specs.items():
        for match in re.finditer(pattern, corpus[lang], re.M):
            key = normalise(match.group(1))
            if aliases:
                key = aliases.get(key, key)
            value = match.group(2)
            table.setdefault(key, {})[lang] = norm(value) if numeric else value
    failures = 0
    for key in sorted(table):
        values = table[key]
        bad = len(set(values.values())) > 1
        missing = len(values) < len(specs)
        if bad:
            failures += 1
        marker = "!!" if bad else (" ." if missing else "  ")
        print(f"  {marker} {key:<16} {values}")
    return failures


# Task kinds and operator RPC commands are part of the contract too: a kind the
# server queues but the implant silently reports as "unknown" is a support
# incident waiting to happen. The doc table is the spec; the code must cover it.
TASK_KIND_SPECS = {
    "rust": r'^\s*"([a-z][a-z0-9.]*)"\s*(?:\||\|)?=>',  # inside task::run's match
    "kotlin": r'^\s*"([a-z][a-z0-9.]*)"\s*(?:, "[a-z][a-z0-9.]*")*\s*->',  # TaskRunner.run
}

# The Go implant is a switch of its own, and its capability list is a
# slice of strings.
GO_IMPLANT_TASKS = "implant/go/internal/beacon/tasks.go"

RPC_SPECS = {
    # A Go case may list aliases on one line (`case "agents.kill", "agents.exit":`),
    # so collect every quoted command in the case label, not just the first.
    "go": r'(?:case|,) "([a-z]+\.[a-z]+)"',
    # The call may be written on one line or split over several, so the
    # pattern tolerates the line break between the parenthesis and the name.
    "python": r'self\.rpc\(\s*"([a-z]+\.[a-z]+)"',
    "cli": r'rpc\(\s*"([a-z]+\.[a-z]+)"',
}


def doc_message_table() -> dict[str, int]:
    """Message ids from the PROTOCOL.md table: | `0x10` | CHECKIN | ..."""
    text = read("docs/PROTOCOL.md")
    section = text.split("All bodies are upk maps.", 1)[-1]
    section = section.split("`tasks[]` entries", 1)[0]
    table: dict[str, int] = {}
    for match in re.finditer(r"^\| `(0x[0-9A-Fa-f]{2})` \| ([A-Z_]+) \|", section, re.M):
        table[match.group(2)] = int(match.group(1), 16)
    return table


def doc_task_kinds() -> set[str]:
    """Task kinds listed in docs/PROTOCOL.md's kind table."""
    text = read("docs/PROTOCOL.md")
    section = text.split("Task kinds understood by the reference implants:", 1)[-1]
    # Stop at the next section: later subsections have their own tables, whose
    # first column is also a backticked lowercase word.
    for marker in ("Operator RPC commands", "\n### "):
        section = section.split(marker, 1)[0]
    return set(re.findall(r"^\| `([a-z][a-z0-9.]*)` \|", section, re.M))


def doc_event_kinds() -> set[str]:
    """The event kinds the protocol document lists."""
    text = read("docs/PROTOCOL.md")
    section = text.split("The kinds the server emits:", 1)[-1]
    # Stop at the next subsection: the tables after it have their own
    # first column.
    section = section.split("\n### ", 1)[0]
    return set(re.findall(r"^\| `([a-z][a-z0-9._]*)` \|", section, re.M))


def go_source_files() -> list[str]:
    """Every Go file of the server, as the paths the reader understands."""
    out = []
    root = os.path.join(ROOT, "server")
    for base, _dirs, files in os.walk(root):
        for name in files:
            if not name.endswith(".go") or name.endswith("_test.go"):
                continue
            out.append(os.path.relpath(os.path.join(base, name), ROOT))
    return sorted(out)


def code_event_kinds() -> set[str]:
    """Every event kind the server emits."""
    kinds: set[str] = set()
    for rel in go_source_files():
        text = read(rel)
        # Only the event literals: a task kind is stored in a field of
        # its own, and it is not an event.
        kinds |= set(re.findall(
            r'(?:hub\.)?Event\{Kind:\s*"([a-z][a-z0-9._]*)"', text))
    return kinds


def check_events() -> int:
    """The events the server emits are the events the document lists."""
    documented = doc_event_kinds()
    emitted = code_event_kinds()
    problems = 0
    missing = emitted - documented
    if missing:
        print(f"  !! EVENTS: the server emits {sorted(missing)} and the document does not say so")
        problems += 1
    extra = documented - emitted
    if extra:
        print(f"  !! EVENTS: the document lists {sorted(extra)} and the server never emits them")
        problems += 1
    if problems == 0:
        print(f"  EVENTS          {len(emitted)} kinds, emitted and documented")
    return problems


def doc_rpc_commands() -> set[str]:
    """Every RPC named in the protocol document, from the table or the prose."""
    text = read("docs/PROTOCOL.md")
    section = text.split("Operator RPC commands", 1)[-1]
    # Stop at the next top-level section so we do not pick up unrelated text.
    section = section.split("\n## ", 1)[0]
    table = set(re.findall(r"^\| `([a-z]+\.[a-z]+)` \|", section, re.M))
    prose = set(re.findall(r"`([a-z]+\.[a-z]+)`", section))
    # The prose also names the event kinds, the task kinds and the
    # persistence techniques, and those are not RPC commands: an event the
    # server emits, a task a beacon runs, and an entry the persistence
    # manager installs.  A table of a later section may hold the same
    # names, so the subtraction covers the tables as well.
    events = go_event_kinds()
    tasks = doc_task_kinds()
    techniques = rust_persist_techniques()
    prose -= events
    prose -= tasks
    prose -= techniques
    table -= events
    table -= tasks
    table -= techniques
    return table | prose


def rust_persist_techniques() -> set[str]:
    """The persistence technique ids in the beacon's catalogue."""
    text = read("implant/rust/src/persist.rs")
    return set(re.findall(r'Technique\s*\{\s*id:\s*"([a-z][a-z0-9.]*)"', text))


def go_event_kinds() -> set[str]:
    """The event kinds the Go server emits.

    Every package is read, not only the hub: the pivot manager emits its
    own events, and the vault and the other helpers emit theirs.
    """
    return code_event_kinds()


def doc_rpc_roles() -> dict[str, str]:
    """RPC -> minimum role, from the documented table."""
    text = read("docs/PROTOCOL.md")
    section = text.split("Operator RPC commands", 1)[-1].split("\n## ", 1)[0]
    roles: dict[str, str] = {}
    for line in section.splitlines():
        match = re.match(r"^\| `([a-z]+\.[a-z]+)` \| (viewer|operator|admin) \|", line)
        if match:
            roles[match.group(1)] = match.group(2)
    return roles


def go_rpc_roles() -> dict[str, str]:
    """RPC -> role, from server/internal/rbac."""
    text = read("server/internal/rbac/rbac.go")
    body = text.split("var requirements = map[string]string{", 1)[-1].split("\n}", 1)[0]
    out: dict[str, str] = {}
    for match in re.finditer(r'"([a-z]+\.[a-z]+)":\s*(Viewer|Operator|Admin)', body):
        out[match.group(1)] = match.group(2).lower()
    return out


def check_rbac_table() -> int:
    """The documented roles must match the enforcement table, exactly.

    A mismatch is a security bug in one direction (documented read-only, actually
    writable) and a support ticket in the other, so it is compared both ways.
    """
    documented = doc_rpc_roles()
    enforced = go_rpc_roles()
    problems = 0
    if not documented:
        print("  !! no role table found in docs/PROTOCOL.md")
        return 1
    if not enforced:
        print("  !! no requirements table found in rbac.go")
        return 1
    for cmd, role in sorted(documented.items()):
        actual = enforced.get(cmd)
        if actual is None:
            print(f"  !! RBAC: {cmd} is documented with role {role} but has no entry in rbac.go")
            problems += 1
        elif actual != role:
            print(f"  !! RBAC: {cmd} documented as {role}, enforced as {actual}")
            problems += 1
    for cmd in sorted(set(enforced) - set(documented)):
        print(f"  !! RBAC: {cmd} is enforced as {enforced[cmd]} but missing from the docs table")
        problems += 1
    if not problems:
        print(f"  RBAC            {len(documented)} commands documented with matching minimum roles")
    return problems


def config_keys() -> set[str]:
    """JSON field names declared on config.Server."""
    text = read("server/internal/config/config.go")
    start = text.index("type Server struct {")
    body = text[start:text.index("\n}", start)]
    return set(re.findall(r'json:"([a-z0-9_]+)(?:,[^"]*)?"', body))


def nested_config_keys(struct_name: str) -> set[str]:
    text = read("server/internal/config/config.go")
    start = text.index(f"type {struct_name} struct {{")
    body = text[start:text.index("\n}", start)]
    return set(re.findall(r'json:"([a-z0-9_]+)(?:,[^"]*)?"', body))


def check_deploy_configs() -> int:
    """Every key in deploy/*.json must be a real config key.

    A typo like ``audit_max_size_mb`` is silently ignored by encoding/json, so
    the server starts with the default and nobody notices until the log fills a
    disk. This is cheap to check and impossible to notice by reading.
    """
    import json

    problems = 0
    top = config_keys()
    nested = {
        "beacon": nested_config_keys("Beacon"),
        "limits": nested_config_keys("Limits"),
    }
    for name in ("deploy/server.dev.json", "deploy/server.prod.json"):
        try:
            doc = json.loads(read(name))
        except ValueError as exc:
            print(f"  !! {name}: invalid JSON ({exc})")
            problems += 1
            continue
        for key, value in doc.items():
            if key not in top:
                print(f"  !! {name}: unknown key {key!r} (not a config.Server field)")
                problems += 1
                continue
            if isinstance(value, dict):
                allowed = nested.get(key)
                if allowed is None:
                    continue
                for sub in value:
                    if sub not in allowed:
                        print(f"  !! {name}: unknown key {key}.{sub!r}")
                        problems += 1
        missing = top - set(doc)
        # Optional keys may be omitted; only report ones that are not optional.
        required = {"agent_listen", "operator_listen", "data_file"}
        for key in sorted(required - set(doc)):
            print(f"  !! {name}: missing required key {key!r}")
            problems += 1
        if missing:
            print(f"   . {name}: omits {sorted(missing)} (defaults apply)")
    if not problems:
        print("  DEPLOY_CONFIG   every deployed key exists in config.Server")
    return problems


def check_deploy_paths() -> int:
    """Every path the server *writes* must be writable under the systemd unit.

    ProtectSystem=strict makes everything outside ReadWritePaths read-only, so a
    production config pointing audit_file at /var/log/umbra would simply fail to
    start. Static checks are the only place this is visible without a box.
    """
    import json
    import posixpath

    written_keys = ("data_file", "audit_file")
    unit = read("deploy/umbra-server.service")
    roots = set(re.findall(r"^ReadWritePaths=(.+)$", unit, re.M))
    roots = {p.strip() for line in roots for p in line.split()}
    state_dir = re.search(r"^StateDirectory=(.+)$", unit, re.M)
    if state_dir:
        roots.add(posixpath.join("/var/lib", state_dir.group(1).strip()))

    problems = 0
    for name in ("deploy/server.dev.json", "deploy/server.prod.json"):
        doc = json.loads(read(name))
        for key in written_keys:
            path = doc.get(key) or ""
            if not path.startswith("/"):
                continue  # relative paths follow the working directory
            if not any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots):
                print(f"  !! {name}: {key}={path} is outside the writable paths {sorted(roots)}")
                problems += 1
    if not problems:
        print(f"  DEPLOY_PATHS    writable paths covered by {sorted(roots)}")
    return problems


def check_ci_env_names() -> int:
    """The CI build must set the env vars the Gradle file actually reads.

    The Android job used to pass UMBRA_SERVER while app/build.gradle reads
    UMBRA_HOST/UMBRA_PORT. Nothing failed: the APK simply baked in the default
    address and the CI build proved nothing. Names are now compared.
    """
    gradle = read("implant/android/app/build.gradle")
    read_by_gradle = set(re.findall(r"env(?:Or|Str|Int)\('(UMBRA_[A-Z0-9_]+)'", gradle))
    if not read_by_gradle:
        print("  !! could not find any envOr/envStr/envInt call in app/build.gradle")
        return 1

    ci = read(".github/workflows/ci.yml")
    # Only the Android job's env block matters; match "NAME:" under any env:.
    set_by_ci = set(re.findall(r"^\s+(UMBRA_[A-Z0-9_]+):", ci, re.M))

    unknown = set_by_ci - read_by_gradle
    problems = 0
    for name in sorted(unknown):
        print(f"  !! ci.yml sets {name} but app/build.gradle never reads it")
        problems += 1
    missing = read_by_gradle - set_by_ci
    if missing:
        print(f"   . ci.yml relies on defaults for {sorted(missing)}")
    if not problems:
        print(f"  CI_ENV          {len(set_by_ci & read_by_gradle)} variable names match app/build.gradle")
    return problems


def kind_set(spec: str, rel: str) -> set[str]:
    """All quoted kinds, including the aliases on a combined match arm."""
    text = read(rel)
    found: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not (stripped.startswith('"') and ("->" in stripped or "=>" in stripped)):
            continue
        found.update(re.findall(r'"([a-z][a-z0-9.]*)"',
                                stripped.split("->")[0].split("=>")[0]))
    return found


def go_implant_kinds() -> set[str]:
    """The kinds the Go implant runs: the arms of its switch."""
    text = read(GO_IMPLANT_TASKS)
    return set(re.findall(r'^\s*case "([a-z][a-z0-9.]*)":', text, re.M))


def go_implant_caps() -> set[str]:
    """The kinds the Go implant advertises in its handshake."""
    text = read(GO_IMPLANT_TASKS)
    block = text.split("kinds := []string{", 1)
    if len(block) < 2:
        return set()
    body = block[1].split("}", 1)[0]
    return set(re.findall(r'"([a-z][a-z0-9.]*)"', body))


def check_go_implant(documented: set[str], vocabulary: set[str]) -> int:
    """The Go implant says what it does, and it does what it says.

    The capability list is what the server reads before it queues work, so
    a kind that is advertised and not implemented is a task the operator
    waits for forever, and a kind that is implemented and not advertised is
    work the server refuses to queue.
    """
    problems = 0
    kinds = go_implant_kinds()
    caps = go_implant_caps()
    if not kinds:
        print(f"  !! TASK_KINDS: the Go implant has no task table")
        return 1
    missing = caps - kinds
    if missing:
        print(f"  !! TASK_KINDS: the Go implant advertises {sorted(missing)} and does not run them")
        problems += 1
    unadvertised = kinds - caps
    if unadvertised:
        print(f"  !! TASK_KINDS: the Go implant runs {sorted(unadvertised)} and does not advertise them")
        problems += 1
    # The vocabulary of the framework is the documented kinds and the
    # aliases the other implants run.
    unknown = kinds - vocabulary
    if unknown:
        print(f"  !! TASK_KINDS: the Go implant runs {sorted(unknown)}, which the framework does not know")
        problems += 1
    if problems == 0:
        print(f"  TASK_KINDS       go implant: {len(kinds)} kinds, advertised and documented")
    return problems


def check_set(name: str, expected: set[str], actual: set[str], where: str) -> int:
    missing = expected - actual
    extra = actual - expected
    # Aliases and helpers are allowed; only a *missing* documented kind is a bug.
    if missing:
        print(f"  !! {name}: {where} does not implement {sorted(missing)}")
        return 1
    if extra:
        print(f"   . {name}: {where} also implements {sorted(extra)} (aliases ok)")
    else:
        print(f"  {name:<16} {where}: {len(actual)} kinds covered")
    return 0


def main() -> int:
    failures = 0
    corpus = {lang: sources(lang) for lang in SOURCES}

    print("== scalar constants ==")
    for name, patterns in SPECS:
        values = {}
        for lang, pattern in patterns.items():
            if pattern is None:
                continue
            match = re.search(pattern, corpus[lang], re.M)
            if not match:
                print(f"  !! {name}: not found in {lang}")
                failures += 1
                continue
            values[lang] = norm(match.group(1))
        if len(set(values.values())) > 1:
            print(f"  !! {name}: MISMATCH {values}")
            failures += 1
        else:
            print(f"  {name:<15} {values}")

    print("\n== message types ==")
    failures += compare_table("MSG", MSG_SPECS, corpus, camel_to_snake)

    print("\n== handshake markers ==")
    failures += compare_table("MARKER", MARKER_SPECS, corpus, camel_to_snake, MARKER_ALIASES)

    print("\n== domain separation labels ==")
    failures += compare_table("LABEL", LABEL_SPECS, corpus, camel_to_snake, numeric=False)

    print("\n== the label of the attestation ==")
    failures += compare_table("ATTEST", ATTEST_SPECS, corpus, camel_to_snake, numeric=False)

    print("\n== message table vs docs/PROTOCOL.md ==")
    documented = doc_message_table()
    # Message ids live on the MsgType registry (the frame-level constants such
    # as PRELUDE_LEN are checked in the scalar table above).
    registry = wire_module.MsgType
    code_ids = {name: value for name, value in vars(registry).items()
                if name.isupper() and isinstance(value, int)
                and not name.startswith("FRAME_")}
    doc_problems = 0
    for name, value in sorted(documented.items(), key=lambda kv: kv[1]):
        code_value = code_ids.get(name)
        if code_value is None:
            print(f"  !! {name}: documented as 0x{value:02X} but not defined in wire.py")
            doc_problems += 1
            continue
        if code_value != value:
            print(f"  !! {name}: docs say 0x{value:02X}, wire.py says 0x{code_value:02X}")
            doc_problems += 1
    undocumented = [name for name in code_ids if name not in documented]
    for name in sorted(undocumented):
        print(f"  !! {name} (0x{code_ids[name]:02X}) is implemented but missing from docs/PROTOCOL.md")
        doc_problems += 1
    if not doc_problems:
        print(f"  MESSAGE_TABLE    {len(documented)} message types documented and matching")
    failures += doc_problems

    print("\n== task kinds vs docs/PROTOCOL.md ==")
    documented = doc_task_kinds()
    rust_kinds = kind_set(TASK_KIND_SPECS["rust"], "implant/rust/src/task.rs")
    kotlin_kinds = kind_set(TASK_KIND_SPECS["kotlin"],
                            "implant/android/app/src/main/java/io/umbra/beacon/TaskRunner.kt")
    failures += check_set("TASK_KINDS", documented, rust_kinds, "rust")
    failures += check_set("TASK_KINDS", documented, kotlin_kinds, "kotlin")
    # The Go implant is deliberately small, so it is not asked to cover
    # every documented kind; it is asked to be honest about its own.
    failures += check_go_implant(documented, documented | rust_kinds | kotlin_kinds)

    print("\n== the events the server pushes ==")
    failures += check_events()

    print("\n== deploy config vs config.Server ==")
    failures += check_deploy_configs()

    print("\n== deploy paths vs the systemd unit ==")
    failures += check_deploy_paths()

    print("\n== CI environment vs the Gradle build ==")
    failures += check_ci_env_names()

    print("\n== operator RPC commands ==")
    rpc_doc = doc_rpc_commands()
    go_rpc = set(re.findall(RPC_SPECS["go"], read("server/internal/link/operator.go")))
    py_rpc = set(re.findall(RPC_SPECS["python"], read("operator/umbra_cli/client.py")))
    failures += check_rbac_table()

    missing_go = rpc_doc - go_rpc
    if missing_go:
        print(f"  !! RPC: Go server is missing {sorted(missing_go)}")
        failures += 1
    else:
        print(f"  RPC             go: all {len(rpc_doc)} documented commands handled")
    unused = py_rpc - go_rpc
    if unused:
        print(f"  !! RPC: client calls commands the server does not handle: {sorted(unused)}")
        failures += 1
    else:
        print(f"  RPC             python: {len(py_rpc)} commands all handled by the server")
    # Every documented command must be reachable from the console: the
    # console is the product, and a command nobody can type is a command
    # that does not exist.
    unreachable = rpc_doc - py_rpc
    if unreachable:
        print(f"  !! RPC: the console does not reach {sorted(unreachable)}")
        failures += 1
    else:
        print(f"  RPC             console: all {len(rpc_doc)} documented commands reachable")

    print()
    if failures:
        print(f"FAILED: {failures} inconsistency(ies)")
        return 1
    print("OK: all implementations agree on every wire constant")
    return 0


if __name__ == "__main__":
    sys.exit(main())
