#!/usr/bin/env python3
"""A very small static checker for the Go tree.

The sandbox that this repository is developed in has no Go toolchain, so the
usual `go build` / `go vet` cannot run here.  This script does the part of
the job that can be done with a text editor: it checks that every
package-qualified identifier used in a file is actually declared by the
package it is imported from.

It is not a compiler and it does not pretend to be one: it only looks at
exported top level names, struct fields and method names.  A hit means a
sure typo, a miss means nothing.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "server"

DECL = re.compile(
    r"^\s*(?:func\s+(?:\([^)]*\)\s*)?([A-Z]\w*)|type\s+([A-Z]\w*)|"
    r"(?:const|var)\s+([A-Z]\w*)|(?:const|var)\s*\(([^)]*)\))",
    re.M,
)
GROUP_CONST = re.compile(r"^\s*([A-Z]\w*)\s*(?:[A-Za-z_\[\]\*\.\w]+\s*)?=", re.M)
FIELD = re.compile(r"^\t([A-Z]\w*)\s+[\w\*\[\]\.]", re.M)
METHOD = re.compile(r"^func\s+\([^)]*\)\s+([A-Z]\w*)\s*\(", re.M)
FUNC = re.compile(r"^func\s+([A-Z]\w*)\s*\(", re.M)
TYPE = re.compile(r"^type\s+([A-Z]\w*)\b", re.M)
CONST_BLOCK = re.compile(r"^\s*(?:const|var)\s*\(\s*$", re.M)


def exported_names(path: Path) -> set[str]:
    """Every exported name a package declares."""
    names: set[str] = set()
    src = path.read_text(encoding="utf-8")
    for match in re.finditer(r"^func\s+(?:\([^)]*\)\s*)?([A-Z]\w*)\s*[\(\[]", src, re.M):
        names.add(match.group(1))
    for match in re.finditer(r"^type\s+([A-Z]\w*)\b", src, re.M):
        names.add(match.group(1))
    for match in re.finditer(r"^(?:const|var)\s+([A-Z]\w*)\b", src, re.M):
        names.add(match.group(1))
    # Names inside a const or var block.
    block = re.findall(r"^(?:const|var)\s*\(\s*\n(.*?)^\)", src, re.M | re.S)
    for body in block:
        for line in body.splitlines():
            hit = re.match(r"\s*([A-Z]\w*)\b", line)
            if hit:
                names.add(hit.group(1))
    # Struct fields and interface methods.
    for match in re.finditer(r"^\t([A-Z]\w*)\s+[^\s]", src, re.M):
        names.add(match.group(1))
    return names


def package_files() -> dict[str, list[Path]]:
    out: dict[str, list[Path]] = {}
    for path in sorted(ROOT.rglob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        out.setdefault(str(path.parent.relative_to(ROOT)), []).append(path)
    return out


def main() -> int:
    packages = package_files()
    names: dict[str, set[str]] = {}
    for pkg, files in packages.items():
        acc: set[str] = set()
        for f in files:
            acc |= exported_names(f)
        names[pkg] = acc

    problems: list[str] = []
    for pkg, files in packages.items():
        for path in files:
            src = path.read_text(encoding="utf-8")
            body = src
            imports: dict[str, str] = {}
            for match in re.finditer(r'import\s+\((.*?)\)', src, re.S):
                for line in match.group(1).splitlines():
                    hit = re.match(r'\s*(?:(\w+)\s+)?"([^"]+)"', line)
                    if not hit:
                        continue
                    alias, ipath = hit.group(1), hit.group(2)
                    if alias in ("_", "."):
                        continue
                    local = alias or ipath.split("/")[-1]
                    if ipath.startswith("github.com/thesyntax1/UmbraC2/server/"):
                        imports[local] = ipath[len("github.com/thesyntax1/UmbraC2/server/"):]
                    else:
                        imports[local] = ""
                body = body.replace(match.group(0), "")
            for local, ipath in imports.items():
                if not ipath:
                    continue
                if ipath not in names:
                    problems.append(f"{path}: unknown internal package {ipath}")
                    continue
                for hit in re.finditer(r"\b" + re.escape(local) + r"\.([A-Z]\w*)", body):
                    ident = hit.group(1)
                    if ident not in names[ipath]:
                        problems.append(f"{path}: {ipath} has no exported name {ident!r}")

    for line in sorted(set(problems)):
        print(line)
    if problems:
        print(f"{len(set(problems))} problem(s)")
        return 1
    print("go symbols ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
