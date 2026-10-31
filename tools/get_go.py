#!/usr/bin/env python3
"""Install a Go toolchain without root, without a Go installation.

The repository has two Go modules and 41 test files, and the machine that
builds it may not have Go: a laptop in a lab, a CI image that is pinned
for another reason, a container that was trimmed.  This script fetches a
prebuilt toolchain from PyPI (the `go-bin` wheel, which is a repackaging
of the official tarball), checks the digest of the file it downloaded,
unpacks it next to the cache, and prints the two lines to export.

It does not install anything into the repository and it does not need
root: the toolchain lands in `--dest` (default `~/.cache/umbra-go`).

    python3 tools/get_go.py
    export PATH="$HOME/.cache/umbra-go/go/bin:$PATH"
    make test-go

The digest below pins one wheel.  A different version is a different
file: pass `--sha256 ""` to skip the check only when you have verified
the file yourself.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import sys
import urllib.request
import zipfile

# The wheel the repository was verified with.
VERSION = "1.27.3"
SHA256 = "ae9a8cfefeacb582f53ff489a3b83d729256a284ac0f7f37b179216ac4bcb69d"
BASE = "https://files.pythonhosted.org/packages"


def wheel_for(machine: str) -> tuple[str, str]:
    """The (filename, URL) of the manylinux wheel for this machine."""
    arch = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }.get(machine)
    if not arch:
        raise SystemExit(f"go-bin has no wheel for {machine!r}; use the official tarball")
    if arch == "x86_64":
        path = "ed/d1/27aff47dacff1e8aff82a84a90ea61e56dc268117cad0a482cfb476f99af"
        name = f"go_bin-{VERSION}-py3-none-manylinux_2_17_x86_64.whl"
    else:
        path = "40/14/8f4be7432023010ba5642fb35e5cd362a688451f114b32e1f8d8081fe0b9"
        name = f"go_bin-{VERSION}-py3-none-manylinux_2_17_aarch64.whl"
    return name, f"{BASE}/{path}/{name}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", default=os.path.expanduser("~/.cache/umbra-go"),
                        help="where the toolchain is unpacked")
    parser.add_argument("--sha256", default=SHA256,
                        help="the digest of the wheel; empty skips the check")
    parser.add_argument("--keep", action="store_true", help="keep the downloaded wheel")
    args = parser.parse_args()

    if platform.system() != "Linux":
        raise SystemExit("this helper is for Linux; on another system use the official tarball")
    name, url = wheel_for(platform.machine())
    os.makedirs(args.dest, exist_ok=True)
    wheel = os.path.join(args.dest, name)

    if not os.path.exists(wheel):
        print(f"downloading {url}")
        with urllib.request.urlopen(url, timeout=120) as response, open(wheel, "wb") as handle:
            while chunk := response.read(1 << 20):
                handle.write(chunk)

    if args.sha256:
        digest = hashlib.sha256()
        with open(wheel, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        if digest.hexdigest() != args.sha256:
            os.unlink(wheel)
            raise SystemExit(f"the wheel does not match the pinned digest ({digest.hexdigest()})")

    print(f"unpacking into {args.dest}")
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(args.dest)
    go = os.path.join(args.dest, "go", "bin", "go")
    for base, _dirs, files in os.walk(os.path.join(args.dest, "go", "pkg")):
        for name in files:
            os.chmod(os.path.join(base, name), 0o755)
    os.chmod(go, 0o755)
    if not args.keep:
        os.unlink(wheel)

    if not os.path.exists(go):
        raise SystemExit("the wheel did not carry a toolchain")
    print()
    print('export PATH="' + os.path.join(args.dest, "go", "bin") + ':$PATH"')
    print("export GOTOOLCHAIN=local GOPROXY=off")
    print(f"# then: go version  &&  make test-go")
    return 0


if __name__ == "__main__":
    sys.exit(main())
