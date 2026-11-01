#!/usr/bin/env python3
"""Say whether a commit is allowed to become a release.

The gate in docs/RELEASE-PROCESS.md is a table of nine conditions.  This tool
checks the two it can check mechanically and reads the rest from
`release-evidence.json`, which has to name, for each of them, the run or the
platform where it happened.  A condition with no entry is a condition that is
not met, so a green CI run is one row of nine and never the answer.

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
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The conditions of docs/RELEASE-PROCESS.md §1 that cannot be computed here.
# Each one needs a recorded run, because a sentence in a document is not
# evidence and this tool refuses to treat it as one.
EVIDENCE = (
    ("platforms", "each platform's binary has run on its own platform"),
    ("android_tests", "the Android implant has tests"),
    ("protocol_conformance", "the three implants speak the same protocol"),
    ("hardening", "the persist and transport findings are closed"),
    ("provenance", "the release has a changelog and signed artefacts"),
)


def unrecorded(root: str, evidence: dict) -> list[str]:
    """The conditions of the gate that a green `ci.yml` run does not satisfy.

    `root` and `evidence` are arguments rather than globals so that the rule
    can be tested without a repository and without a network: a green matrix
    with nothing recorded must come back closed.
    """
    closed: list[str] = []
    changelog = os.path.exists(os.path.join(root, "CHANGELOG.md"))
    for key, title in EVIDENCE:
        reasons = []
        entry = evidence.get(key)
        if not isinstance(entry, dict) or not entry.get("evidence"):
            reasons.append("not recorded in release-evidence.json")
        # The changelog is the half of the provenance condition that can be
        # checked here, so it is checked here rather than trusted to the file.
        if key == "provenance" and not changelog:
            reasons.append("CHANGELOG.md does not exist")
        if reasons:
            closed.append(f"{key} {title}: " + "; ".join(reasons))
    return closed


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
    print("release_gate: every job green")

    # The other eight conditions.  They are not a matter of opinion: each one
    # names evidence that either exists or does not.
    evidence_path = os.path.join(ROOT, "release-evidence.json")
    evidence = {}
    closed: list[str] = []
    if os.path.exists(evidence_path):
        try:
            with open(evidence_path, encoding="utf-8") as handle:
                evidence = json.load(handle)
        except (OSError, ValueError) as error:
            closed.append(f"the evidence file cannot be read: {error}")
    closed += unrecorded(ROOT, evidence)
    if closed:
        for line in closed:
            print(f"  NOT MET  {line}")
        print(f"release_gate: {len(closed)} condition(s) of the gate are not met: CLOSED")
        return 0 if args.allow else 1
    print("release_gate: every condition of the gate is met: OPEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
