#!/usr/bin/env python3
"""Install a Go toolchain without root, without a Go installation.

The repository has two Go modules and 41 test files, and the machine that
builds it may not have Go: a laptop in a lab, a CI image that is pinned
for another reason, a container that was trimmed.  This script fetches a
prebuilt toolchain from PyPI (the `go-bin` wheel, which is a repackaging
of the official tarball), checks the digest the index publishes for that
file, unpacks it next to the cache, and prints the two lines to export.

It does not install anything into the repository and it does not need
root: the toolchain lands in `--dest` (default `~/.cache/umbra-go`).

    python3 tools/get_go.py                       # the pinned toolchain
    python3 tools/get_go.py --version 1.22.10     # the oldest supported
    export PATH="$HOME/.cache/umbra-go/go/bin:$PATH"

Two versions, two directories: the manifest declares `go 1.22`, so the
compatibility question is not "does it build on the machine that wrote it"
but "does it build on the oldest toolchain the manifest allows".  Install
both (`--dest ~/.cache/umbra-go-1.22` for the second) and run the suite
under each; `docs/BUILD-EVIDENCE.md` records the results.

The digest comes from the PyPI JSON index for the exact file, over TLS, so
the check is against the index rather than against a constant that somebody
has to remember to update when a version moves.  `--sha256` overrides it
when a mirror is used; an empty string skips the check, and the script says
so loudly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import urllib.request
import zipfile

# The version the repository is verified with; `--version` overrides it.
PINNED = "1.27.3"
INDEX = "https://pypi.org/pypi/go-bin"


def arch_suffix(machine: str) -> str:
    arch = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }.get(machine)
    if not arch:
        raise SystemExit(f"go-bin has no wheel for {machine!r}; use the official tarball")
    return f"py3-none-manylinux_2_17_{arch}.whl"


def wheel_for(version: str, machine: str) -> tuple[str, str, str]:
    """The (filename, URL, sha256) of the manylinux wheel for this machine."""
    suffix = arch_suffix(machine)
    with urllib.request.urlopen(f"{INDEX}/{version}/json", timeout=60) as response:
        payload = json.load(response)
    for item in payload.get("urls", []):
        if item["filename"].endswith(suffix):
            return item["filename"], item["url"], item["digests"]["sha256"]
    raise SystemExit(f"go-bin {version} has no wheel ending in {suffix!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", default=os.path.expanduser("~/.cache/umbra-go"))
    parser.add_argument("--version", default=PINNED)
    parser.add_argument("--sha256", default=None,
                        help="override the digest from the index ('' to skip)")
    args = parser.parse_args()

    name, url, want = wheel_for(args.version, platform.machine())
    if args.sha256 is not None:
        want = args.sha256
    if not want:
        print("WARNING: the digest check is off; you are trusting the network",
              file=sys.stderr)

    os.makedirs(args.dest, exist_ok=True)
    target = os.path.join(args.dest, name)
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=600) as response, open(target, "wb") as out:
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)

    if want:
        digest = hashlib.sha256()
        with open(target, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        if digest.hexdigest() != want:
            raise SystemExit(f"sha256 mismatch for {name}:\n  want {want}\n  got  {digest.hexdigest()}")
        print(f"sha256 ok ({want[:16]}…)")

    with zipfile.ZipFile(target) as archive:
        archive.extractall(args.dest)
    os.remove(target)

    # A wheel is a zip, and a zip does not carry the executable bit.  The
    # toolchain is useless without it, and "permission denied" on the first
    # command is a confusing way to learn that.
    root = os.path.join(args.dest, "go")
    for base, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(base, name)
            if base.endswith(os.sep + "bin") or os.sep + "tool" + os.sep in path:
                os.chmod(path, 0o755)

    go = os.path.join(args.dest, "go", "bin", "go")
    if not os.path.exists(go):
        raise SystemExit(f"the wheel did not contain {go}")
    version = os.popen(f"{go} version").read().strip()
    print(version)
    print()
    print("export PATH=\"%s:$PATH\"" % os.path.dirname(go))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
