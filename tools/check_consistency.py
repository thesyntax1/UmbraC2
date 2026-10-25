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
    "rust": r'^\s*"([a-z]+)"\s*(?:\||\|)?=>',  # inside task::run's match
    "kotlin": r'^\s*"([a-z]+)"\s*(?:, "[a-z]+")*\s*->',  # inside TaskRunner.run
}

RPC_SPECS = {
    "go": r'case "([a-z]+\.[a-z]+)"',
    "python": r'self\.rpc\("([a-z]+\.[a-z]+)"',
    "cli": r'rpc\("([a-z]+\.[a-z]+)"',
}


def doc_task_kinds() -> set[str]:
    """Task kinds listed in docs/PROTOCOL.md's kind table."""
    text = read("docs/PROTOCOL.md")
    section = text.split("Task kinds understood by the reference implants:", 1)[-1]
    section = section.split("Operator RPC commands:", 1)[0]
    return set(re.findall(r"^\| `([a-z]+)` \|", section, re.M))


def doc_rpc_commands() -> set[str]:
    text = read("docs/PROTOCOL.md")
    section = text.split("Operator RPC commands:", 1)[-1]
    section = section.split("\n\n", 1)[0]
    return set(re.findall(r"`([a-z]+\.[a-z]+)`", section))


def kind_set(spec: str, rel: str) -> set[str]:
    """All quoted kinds, including the aliases on a combined match arm."""
    text = read(rel)
    found: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not (stripped.startswith('"') and ("->" in stripped or "=>" in stripped)):
            continue
        found.update(re.findall(r'"([a-z]+)"', stripped.split("->")[0].split("=>")[0]))
    return found


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

    print("\n== task kinds vs docs/PROTOCOL.md ==")
    documented = doc_task_kinds()
    rust_kinds = kind_set(TASK_KIND_SPECS["rust"], "implant/rust/src/task.rs")
    kotlin_kinds = kind_set(TASK_KIND_SPECS["kotlin"],
                            "implant/android/app/src/main/java/io/umbra/beacon/TaskRunner.kt")
    failures += check_set("TASK_KINDS", documented, rust_kinds, "rust")
    failures += check_set("TASK_KINDS", documented, kotlin_kinds, "kotlin")

    print("\n== operator RPC commands ==")
    rpc_doc = doc_rpc_commands()
    go_rpc = set(re.findall(RPC_SPECS["go"], read("server/internal/link/operator.go")))
    py_rpc = set(re.findall(RPC_SPECS["python"], read("operator/umbra_cli/client.py")))
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

    print()
    if failures:
        print(f"FAILED: {failures} inconsistency(ies)")
        return 1
    print("OK: all implementations agree on every wire constant")
    return 0


if __name__ == "__main__":
    sys.exit(main())
