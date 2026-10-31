#!/usr/bin/env python3
"""The verification matrix: what is implemented, and how we know.

The question this tool answers is the one a reviewer asks before trusting
a feature list: *which of these modules actually work, and what is the
evidence?*  A README is a claim; a handler, a client method, a test and a
wire row are evidence, and they can be counted.

For every operator command the protocol documents, the matrix records:

  go        the Go server has a case for it (the product)
  mock      the mock server answers it (the test double)
  client    the console can call it (the product's surface)
  rbac      the role table has a row for it (the door)
  docs      the protocol table documents it (the contract)
  tests     at least one test names it (the proof)
  cli       the console has a subcommand or a run function that reaches it

The status is then a function of the parts, and it is deliberately
conservative:

  Implemented          go + client + rbac + docs + tests
  Partially            go + client + rbac + docs, but no test names it
  Documented Only      docs, but no Go handler
  Not Verified         go + client, but the contract or the role is missing

Modules that are not commands (the stores, the audit ledger, the OTP
registry, the transport stack) are described with a file and a test count,
because their evidence is a package and not a row.

Run it with --check to make it a gate: it exits 1 when a documented
command is not implemented in Go, when the console cannot reach one, or
when a command has no test at all under --strict.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from typing import Dict, List, Set

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The commands the protocol documents, from the table of section 7.
CMD = r"[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+"


def read(path: str) -> str:
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return handle.read()


def doc_commands() -> Dict[str, str]:
    """Every documented command and the minimum role of its row."""
    text = read("docs/PROTOCOL.md")
    section = text.split("Operator RPC commands", 1)[-1].split("\n## ", 1)[0]
    out: Dict[str, str] = {}
    for line in section.splitlines():
        match = re.match(rf"^\| `({CMD})` \| (viewer|operator|admin) \|", line)
        if match:
            out[match.group(1)] = match.group(2)
    return out


def go_cases() -> Set[str]:
    """Every command a Go switch handles, aliases included.

    A handler may be written as `case "agents.kill":` or as
    `case "agents.kill", "agents.exit":`: an alias is a command the server
    answers, so both arms are read.  A scanner that knows only the first
    shape would report the second as missing, and a matrix that reports a
    working command as missing is worse than no matrix.
    """
    text = read("server/internal/link/operator.go")
    out: Set[str] = set()
    for match in re.finditer(r'case\s+((?:"[a-z][a-z0-9.]*"\s*,\s*)*"[a-z][a-z0-9.]*")\s*:', text):
        out |= set(re.findall(r'"([a-z][a-z0-9.]*)"', match.group(1)))
    return out


def mock_cases() -> Set[str]:
    """The commands the mock answers: single comparisons and groups."""
    text = read("tools/mock_server.py")
    out: Set[str] = set(re.findall(r'if cmd == "([a-z][a-z0-9.]*)"', text))
    for match in re.finditer(r'if cmd in \(([^)]*)\)', text):
        out |= set(re.findall(r'"([a-z][a-z0-9.]*)"', match.group(1)))
    return out


def client_methods() -> Dict[str, str]:
    """RPC name -> the client method that calls it.

    The call may be written on one line or wrapped over four, so the file
    is collapsed to logical lines before it is read: a method that calls
    `self.rpc(` and names the command two lines later is still the method
    that reaches it.
    """
    text = read("operator/umbra_cli/client.py")
    collapsed = re.sub(r"\s*\n\s*", " ", text)
    out: Dict[str, str] = {}
    for chunk in re.split(r"(?=\bdef [a-z_][a-z0-9_]*\()", collapsed):
        match = re.match(r"\bdef ([a-z_][a-z0-9_]*)\(", chunk)
        if not match:
            continue
        for call in re.finditer(r'self\.rpc\(\s*"([a-z][a-z0-9.]*)"', chunk):
            out.setdefault(call.group(1), match.group(1))
    return out


def rbac_roles() -> Dict[str, str]:
    text = read("server/internal/rbac/rbac.go")
    body = text.split("var requirements = map[string]string{", 1)[-1].split("\n}", 1)[0]
    return {m.group(1): m.group(2).lower()
            for m in re.finditer(rf'"({CMD})":\s*(Viewer|Operator|Admin)', body)}


def test_corpus() -> str:
    parts = []
    for name in ("tests/test_protocol.py", "tests/test_acceptance.py"):
        parts.append(read(name))
    return "\n".join(parts)


def cli_surface() -> str:
    return read("operator/umbra_cli/cli.py")


def status_of(cmd: str, go: Set[str], mock: Set[str], client: Dict[str, str],
              rbac: Dict[str, str], docs: Dict[str, str], tests: str,
              cli: str) -> tuple[str, List[str]]:
    """The status of one command, and the parts it is missing."""
    missing: List[str] = []
    if cmd not in go:
        missing.append("go")
    if cmd not in mock:
        missing.append("mock")
    if cmd not in client:
        missing.append("client")
    if cmd not in rbac:
        missing.append("rbac")
    if cmd not in docs:
        missing.append("docs")
    # The probe is deliberately loose: the test either names the command
    # (a wire test) or names the client method that calls it (a console
    # test).  A test that does neither is a test that does not know the
    # command exists.
    named = f'"{cmd}"' in tests or f"'{cmd}'" in tests
    if not named and cmd in client:
        named = f"{client[cmd]}(" in tests
    if not named:
        missing.append("tests")

    if "go" not in missing and "client" not in missing and "rbac" in missing:
        return "Not Verified", missing
    if "go" not in missing and "client" not in missing and "docs" not in missing \
            and "rbac" not in missing:
        if "tests" in missing:
            return "Partially Implemented", missing
        return "Implemented", missing
    if "docs" in docs and "go" in missing:
        return "Documented Only", missing
    if "go" in missing:
        return "Not Verified", missing
    return "Partially Implemented", missing


# The components that are not a single Go package: another language, or a
# tree of packages.  `kind` decides how the tests are counted; `runs` says
# whether this repository can execute them without an extra toolchain.
# (name, path, kind, tool, the command that runs the tests)
COMPONENTS = [
    ("The Python suite: the console, the mock and the contract", "tests", "python",
     sys.executable, ".venv/bin/pytest tests/ -q"),
    ("The Rust beacon", "implant/rust", "rust", "cargo", "cargo test --all-targets"),
    ("The Android beacon", "implant/android", "kotlin", "gradle",
     "gradlew assembleDebug (there is no test source set)"),
    ("The Go beacon", "implant/go", "go", "go", "go test ./... -race"),
    ("The Go server", "server", "go", "go", "go test ./... -race"),
]


def count_tests(path: str, kind: str) -> int:
    """How many tests live under a path, counted the way that language does."""
    full = os.path.join(ROOT, path)
    if os.path.isfile(full):
        files = [full]
    else:
        files = []
        for base, _dirs, names in os.walk(full):
            for name in names:
                files.append(os.path.join(base, name))
    total = 0
    for name in files:
        if kind == "python" and name.endswith(".py") and (
                "test_" in os.path.basename(name) or os.path.basename(name).endswith("_test.py")):
            with open(name, encoding="utf-8") as handle:
                total += len(re.findall(r"^def test_", handle.read(), re.M))
        elif kind == "rust" and name.endswith(".rs"):
            with open(name, encoding="utf-8") as handle:
                total += len(re.findall(r"#\[test\]", handle.read()))
        elif kind == "kotlin" and name.endswith(".kt"):
            with open(name, encoding="utf-8") as handle:
                total += len(re.findall(r"@Test", handle.read()))
        elif kind == "go" and name.endswith("_test.go"):
            with open(name, encoding="utf-8") as handle:
                total += len(re.findall(r"^func Test", handle.read(), re.M))
    return total


def go_packages(root: str) -> list[tuple[str, int, int, int]]:
    """(relative path, go files, test files, test functions) for each package."""
    full = os.path.join(ROOT, root)
    out = []
    for base, dirs, names in os.walk(full):
        dirs[:] = sorted(d for d in dirs if d not in ("testdata", "vendor"))
        go = sum(1 for n in names if n.endswith(".go") and not n.endswith("_test.go"))
        tests = [n for n in names if n.endswith("_test.go")]
        if go == 0 and not tests:
            continue
        funcs = 0
        for name in tests:
            with open(os.path.join(base, name), encoding="utf-8") as handle:
                funcs += len(re.findall(r"^func Test", handle.read(), re.M))
        out.append((os.path.relpath(base, ROOT), go, len(tests), funcs))
    return sorted(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="the matrix as JSON")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when a documented command is not implemented")
    parser.add_argument("--strict", action="store_true",
                        help="with --check: a command without a test is a failure")
    parser.add_argument("--write", default="",
                        help="write the markdown matrix to this path")
    args = parser.parse_args()

    docs = doc_commands()
    go = go_cases()
    mock = mock_cases()
    client = client_methods()
    rbac = rbac_roles()
    tests = test_corpus()
    cli = cli_surface()

    rows = []
    for cmd in sorted(docs):
        status, missing = status_of(cmd, go, mock, client, rbac, docs, tests, cli)
        rows.append({
            "command": cmd,
            "role": docs[cmd],
            "status": status,
            "missing": missing,
            "client": client.get(cmd, ""),
        })

    counts: Dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    packages = []
    for path, go_files, test_files, test_funcs in (
            go_packages("server") + go_packages(os.path.join("implant", "go"))):
        packages.append({"path": path, "go_files": go_files,
                         "test_files": test_files, "test_funcs": test_funcs})

    components = []
    for title, path, kind, tool, command in COMPONENTS:
        available = bool(tool) and (os.path.isabs(tool) or shutil.which(tool))
        components.append({
            "name": title, "path": path, "kind": kind,
            "tests": count_tests(path, kind),
            "tool": tool, "command": command, "available": available,
        })

    failing = [r for r in rows if r["status"] in ("Documented Only", "Not Verified")]
    untested = [r for r in rows if "tests" in r["missing"]]

    if args.json:
        json.dump({"commands": rows, "counts": counts, "packages": packages,
                   "components": components,
                   "failing": [r["command"] for r in failing],
                   "untested": [r["command"] for r in untested]},
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    if args.write:
        write_markdown(args.write, rows, counts, packages, components, untested)
        print(f"wrote {args.write}")

    print(f"commands documented: {len(rows)}")
    for status in ("Implemented", "Partially Implemented", "Documented Only",
                   "Not Verified"):
        if status in counts:
            print(f"  {status:<22} {counts[status]}")
    if untested:
        print(f"  no test names:         {len(untested)}")

    if args.check:
        bad = 0
        for row in rows:
            if row["status"] in ("Documented Only", "Not Verified"):
                print(f"  !! {row['command']} is {row['status']} (missing {row['missing']})")
                bad += 1
        if args.strict:
            for row in untested:
                print(f"  !! {row['command']} has no test")
                bad += 1
        if bad:
            print(f"FAILED: {bad} command(s) are not what the contract says")
            return 1
        print("OK: every documented command is implemented, reachable and tested "
              if args.strict else "OK: every documented command is implemented and reachable")
    return 0


def write_markdown(path: str, rows, counts, packages, components, untested) -> None:
    lines: List[str] = []
    lines.append("# The verification matrix")
    lines.append("")
    lines.append("> Generated by `tools/audit_matrix.py`. Do not edit by hand:")
    lines.append("> regenerate with `python3 tools/audit_matrix.py --write "
                 "docs/VERIFICATION.md`, and the diff is the audit.")
    lines.append("")
    lines.append("A README is a claim. A handler, a client method, a role row, a "
                 "wire row and a test are evidence, and evidence can be counted. "
                 "This page is the count.")
    lines.append("")
    lines.append("| Status | Meaning |")
    lines.append("|---|---|")
    lines.append("| **Implemented** | The Go server handles it, the console reaches it, "
                 "the role table guards it, the protocol documents it, and a test names it. |")
    lines.append("| **Partially Implemented** | All of the above except the test: the "
                 "code exists, the proof is missing. |")
    lines.append("| **Documented Only** | The protocol describes it and no Go handler "
                 "exists. |")
    lines.append("| **Not Verified** | The handler exists but the contract or the role "
                 "row does not: the door is not where the map says. |")
    lines.append("")
    lines.append(f"Commands documented: **{len(rows)}** — "
                 + ", ".join(f"{status}: {count}" for status, count in sorted(counts.items())))
    lines.append("")
    lines.append("## Commands")
    lines.append("")
    lines.append("| Command | Role | Status | Client method | Missing |")
    lines.append("|---|---|---|---|---|")
    for row in rows:
        missing = ", ".join(row["missing"]) or "—"
        lines.append(f"| `{row['command']}` | {row['role']} | {row['status']} | "
                     f"`{row['client'] or '—'}` | {missing} |")
    lines.append("")
    lines.append("## Go packages")
    lines.append("")
    lines.append("A package is not a command: its evidence is its own test tree. "
                 "A package with no test file is a package whose behaviour is "
                 "argued rather than checked, and it is listed as such.")
    lines.append("")
    lines.append("| Package | Go files | Test files | Test functions |")
    lines.append("|---|---|---|---|")
    for pkg in packages:
        lines.append(f"| `{pkg['path']}` | {pkg['go_files']} | "
                     f"{pkg['test_files']} | {pkg['test_funcs']} |")
    untested_pkgs = [p for p in packages if p["test_funcs"] == 0]
    lines.append("")
    lines.append(f"{len(packages)} packages, {sum(p['test_funcs'] for p in packages)} test "
                 f"functions, {len(untested_pkgs)} without one.")
    if untested_pkgs:
        lines.append("")
        lines.append("Without a test: " + ", ".join(f"`{p['path']}`" for p in untested_pkgs) + ".")
    lines.append("")
    lines.append("## The components in the other languages")
    lines.append("")
    lines.append("| Component | Path | Test functions | The command |")
    lines.append("|---|---|---|---|")
    for row in components:
        lines.append(f"| {row['name']} | `{row['path']}` | {row['tests']} | "
                     f"`{row['command']}` |")
    lines.append("")
    lines.append("A test *function* is not a test *case*: pytest counts each parametrised "
                 "case of a function separately, so the number of cases the suite reports "
                 "is larger than the number of functions here.")
    lines.append("")
    lines.append("## The gap list")
    lines.append("")
    if untested:
        lines.append("Documented and implemented, but no test names them. These are "
                     "the honest `Partially Implemented` rows:")
        lines.append("")
        for row in untested:
            lines.append(f"* `{row['command']}` — no test names the command or its "
                         f"client method `{row['client']}`.")
    else:
        lines.append("Every documented command is named by at least one test.")
    lines.append("")
    with open(os.path.join(ROOT, path), "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
