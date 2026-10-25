#!/usr/bin/env python3
"""Static symbol check for the parts of the tree we cannot compile here.

There is no Go or Rust toolchain in the CI image used for review, which means a
typo like ``wire.ErrTooLarge`` (or a renamed helper) would otherwise only be
caught on a developer machine. This script parses declarations with a small
scanner and verifies that every *qualified* reference resolves:

    go     <pkg>.<Symbol>   against the exported identifiers of that package
    rust   crate::mod::fn   against the public items of that module

It is deliberately conservative: it only reports a reference as missing when it
is certain the target module declares no such item. Unresolvable imports,
generics and macro-generated names are skipped rather than guessed at.

    python3 tools/check_symbols.py
"""

from __future__ import annotations

import os
import re
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(path: str) -> str:
    with open(os.path.join(ROOT, path), "r", encoding="utf-8") as fh:
        return fh.read()


def walk(pattern_root: str, suffix: str) -> list[str]:
    out: list[str] = []
    base = os.path.join(ROOT, pattern_root)
    for dirpath, _dirnames, filenames in os.walk(base):
        for name in filenames:
            if name.endswith(suffix):
                out.append(os.path.join(dirpath, name))
    return sorted(out)


def strip_comments(src: str) -> str:
    """Drop // and /* */ comments so prose in doc comments is not parsed."""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def strip_go_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def go_block_idents(src: str, keyword: str) -> set[str]:
    """Names declared by ``const (...)`` / ``var (...)`` blocks.

    Parenthesis matching is counted properly: an earlier naive ``[^)]*`` version
    silently truncated a block at the first ``errors.New("...")`` and then
    reported perfectly valid identifiers as missing.
    """
    names: set[str] = set()
    for match in re.finditer(r"^\s*" + keyword + r"\s*\(", src, re.M):
        depth = 0
        start = match.end() - 1
        for idx in range(start, len(src)):
            if src[idx] == "(":
                depth += 1
            elif src[idx] == ")":
                depth -= 1
                if depth == 0:
                    body = src[start + 1 : idx]
                    break
        else:
            continue
        for line in body.splitlines():
            line = line.split("//")[0].strip()
            if not line or line.startswith('"'):
                continue
            found = re.match(r"([A-Za-z_]\w*)\s*(?:[^=]*?)\s*(?:=|\Z)", line)
            if found:
                names.add(found.group(1))
    return names


def go_package_idents(files: list[str]) -> set[str]:
    names: set[str] = set()
    for path in files:
        src = strip_go_comments(read(os.path.relpath(path, ROOT)))
        for match in re.finditer(
            r"^(?:func|type)\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)", src, re.M
        ):
            names.add(match.group(1))
        for keyword in ("const", "var"):
            names |= go_block_idents(src, keyword)
            for match in re.finditer(r"^" + keyword + r"\s+([A-Za-z_]\w*)\s", src, re.M):
                names.add(match.group(1))
        for match in re.finditer(r"^func\s+\([^)]*\)\s*([A-Za-z_]\w*)", src, re.M):
            names.add(match.group(1))
    return names


def check_go() -> list[str]:
    files = walk("server", ".go")
    by_dir: dict[str, list[str]] = defaultdict(list)
    for path in files:
        by_dir[os.path.dirname(path)].append(path)

    idents = {d: go_package_idents(fs) for d, fs in by_dir.items()}
    by_internal = {
        "internal/" + d.split("internal/")[-1].replace(os.sep, "/"): d
        for d in by_dir
        if "internal/" in d
    }

    problems: list[str] = []
    for directory, fs in by_dir.items():
        imports: dict[str, str] = {}
        for path in fs:
            src = read(os.path.relpath(path, ROOT))
            for match in re.finditer(
                r'(?:(\w+)\s+)?"github\.com/thesyntax1/UmbraC2/server/(internal/[\w/]+)"', src
            ):
                target = match.group(2)
                alias = match.group(1) or target.split("/")[-1]
                imports[alias] = target
        for alias, target in imports.items():
            directory_of_target = by_internal.get(target)
            if directory_of_target is None:
                problems.append(f"{directory}: import of unknown package {target}")
                continue
            known = idents[directory_of_target]
            for path in fs:
                src = strip_comments(read(os.path.relpath(path, ROOT)))
                for match in re.finditer(r"\b" + re.escape(alias) + r"\.([A-Z]\w*)", src):
                    if match.group(1) not in known:
                        rel = os.path.relpath(path, ROOT)
                        line = src[: match.start()].count("\n") + 1
                        problems.append(f"{rel}:{line}: {alias}.{match.group(1)} is not declared in {target}")
    return sorted(set(problems))


def rust_module_idents(files: list[str]) -> set[str]:
    names: set[str] = set()
    for path in files:
        src = read(os.path.relpath(path, ROOT))
        for match in re.finditer(r"\bpub\s+(?:fn|struct|enum|const|static|type|mod)\s+([A-Za-z_]\w*)", src):
            names.add(match.group(1))
        for match in re.finditer(r"\bpub\s+use\s+([A-Za-z_][\w:]*)(?:\s+as\s+(\w+))?", src):
            names.add(match.group(2) or match.group(1).split("::")[-1])
        for match in re.finditer(r"^\s*pub\s+([A-Za-z_]\w*)\s*:", src, re.M):  # struct fields
            names.add(match.group(1))
        for match in re.finditer(r"^\s*([A-Z][A-Za-z0-9_]*)\s*[,({]", src, re.M):  # enum variants
            names.add(match.group(1))
    return names


def check_rust() -> list[str]:
    root = os.path.join(ROOT, "implant/rust/src")
    modules: dict[str, set[str]] = {}
    for name in sorted(os.listdir(root)):
        if not name.endswith(".rs"):
            continue
        module = name[:-3]
        if module == "main":
            continue
        modules[module] = rust_module_idents([os.path.join(root, name)])

    problems: list[str] = []
    files = walk("implant/rust", ".rs")
    for path in files:
        src = read(os.path.relpath(path, ROOT))
        rel = os.path.relpath(path, ROOT)
        for match in re.finditer(r"\b(?:(?:crate|umbra_beacon)::)?(\w+)::([A-Za-z_]\w*)", src):
            module, item = match.group(1), match.group(2)
            if module not in modules:
                continue  # re-exported type path, not a module we index
            if item not in modules[module]:
                line = src[: match.start()].count("\n") + 1
                problems.append(f"{rel}:{line}: {module}::{item} is not public in {module}.rs")
    return sorted(set(problems))


def check_resources() -> list[str]:
    """XML must parse and the Gradle/JSON files must be structurally sound.

    This exists because an XML comment placed *inside* a start tag -- easy to do
    when annotating a manifest attribute -- produces a manifest that AGP rejects
    only at build time. A plain parse catches it in a second.
    """
    import json
    import xml.etree.ElementTree as ET

    problems: list[str] = []
    for path in walk("implant/android", ".xml") + walk("deploy", ".json") + walk(".", ".gradle"):
        rel = os.path.relpath(path, ROOT)
        if "/build/" in rel or rel.startswith("build/"):
            continue
        try:
            text = read(rel)
            if path.endswith(".xml"):
                ET.fromstring(text)
            elif path.endswith(".json"):
                json.loads(text)
            else:  # .gradle: balanced braces are the cheap structural check
                if text.count("{") != text.count("}"):
                    problems.append(f"{rel}: unbalanced braces in a Gradle file")
        except ET.ParseError as exc:
            problems.append(f"{rel}: invalid XML ({exc})")
        except ValueError as exc:
            problems.append(f"{rel}: invalid JSON ({exc})")
    return problems


def main() -> int:
    go_problems = check_go()
    rust_problems = check_rust()
    resource_problems = check_resources()

    print(f"== go: qualified references ({len(go_problems)} unresolved) ==")
    for problem in go_problems:
        print("  !!", problem)
    print(f"== rust: module paths ({len(rust_problems)} unresolved) ==")
    for problem in rust_problems:
        print("  !!", problem)
    print(f"== resources: manifest/gradle/config ({len(resource_problems)} problems) ==")
    for problem in resource_problems:
        print("  !!", problem)

    total = len(go_problems) + len(rust_problems) + len(resource_problems)
    if total:
        print(f"\nFAILED: {total} unresolved symbol(s)")
        return 1
    print("\nOK: every cross-package reference resolves and every resource parses")
    return 0


if __name__ == "__main__":
    sys.exit(main())
