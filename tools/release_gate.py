#!/usr/bin/env python3
"""Say whether a commit is allowed to become a release.

The gate in docs/RELEASE-PROCESS.md is a sentence: every job of ci.yml green
on one commit.  This is the same sentence as an exit code, so that "did CI
pass?" is not a question answered by looking carefully at a web page.

    python3 tools/release_gate.py              # the commit at HEAD
    python3 tools/release_gate.py --sha <sha>
    python3 tools/release_gate.py --allow      # print the report, exit 0 anyway

It needs `gh` (authenticated) and nothing else.  Exit codes: 0 the gate is
open, 1 the gate is closed, 2 the question could not be answered (no run, no
network, no gh) -- and "could not be answered" is never a pass.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys


def gh(args: list[str]) -> tuple[int, str]:
    result = subprocess.run(["gh", *args], capture_output=True, text=True)
    return result.returncode, result.stdout.strip() or result.stderr.strip()


def repo_slug() -> str:
    code, out = gh(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"])
    if code != 0:
        raise SystemExit(f"release_gate: cannot read the repository: {out}")
    return out


def head_sha() -> str:
    code, out = gh(["api", "repos/{owner}/{repo}/commits/HEAD", "--jq", ".sha"])
    if code != 0:
        raise SystemExit(f"release_gate: cannot read HEAD: {out}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", default="")
    parser.add_argument("--workflow", default="ci.yml")
    parser.add_argument("--allow", action="store_true", help="report, do not fail")
    args = parser.parse_args()

    slug = repo_slug()
    sha = args.sha or head_sha()

    code, out = gh(["api", f"repos/{slug}/actions/workflows/{args.workflow}/runs"
                          f"?head_sha={sha}&per_page=10"])
    if code != 0:
        print(f"release_gate: cannot ask GitHub: {out}", file=sys.stderr)
        return 2
    runs = json.loads(out).get("workflow_runs", [])
    if not runs:
        print(f"release_gate: no run of {args.workflow} for {sha[:8]}: CLOSED")
        return 0 if args.allow else 2

    run = runs[0]
    print(f"release_gate: {args.workflow} run {run['id']} on {sha[:8]} "
          f"({run['status']}/{run['conclusion']})")
    print(f"  {run['html_url']}")

    code, out = gh(["api", f"repos/{slug}/actions/runs/{run['id']}/jobs"])
    if code != 0:
        print(f"release_gate: cannot list jobs: {out}", file=sys.stderr)
        return 0 if args.allow else 2
    jobs = json.loads(out).get("jobs", [])
    red = 0
    for job in jobs:
        mark = {"success": "ok  ", "skipped": "skip", "cancelled": "stop"}.get(
            job.get("conclusion") or "", "RED ")
        if mark == "RED ":
            red += 1
        print(f"  {mark} {job['name']}")

    if run["status"] != "completed":
        print("release_gate: the run has not finished: CLOSED")
        return 0 if args.allow else 1
    if red or run["conclusion"] != "success":
        print(f"release_gate: {red} job(s) not green, run {run['conclusion']}: CLOSED")
        return 0 if args.allow else 1
    print("release_gate: every job green: OPEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
