"""The flows of the console: the bulk run and the plan.

Two things the console does that a single command cannot: run one task on
many agents at once, and run a whole sequence of steps from one line.

Both live here, apart from the command line, because they are the parts of
the console that other programs want to reuse.
"""

from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .plan import expand_step

__all__ = ["run_bulk", "run_plan", "render_bulk_table", "render_workflows"]


def _print_progress(done: int, total: int, agent: str, state: str) -> None:
    """Write the progress line of a bulk run."""
    line = f"  [{done}/{total}] {agent} {state}"
    sys.stderr.write("\r" + line.ljust(72))
    sys.stderr.flush()


def _clear_progress() -> None:
    sys.stderr.write("\r" + " " * 72 + "\r")
    sys.stderr.flush()


def run_bulk(client: Any, console: Any, kind: str, task_args: Dict[str, Any],
             rows: List[Dict[str, Any]], cap: int = 4,
             timeout: float = 60.0, wait: bool = True) -> List[Dict[str, Any]]:
    """Run one task on many agents and collect what came back.

    The cap is how many answers are waited for at the same time: a hundred
    agents would otherwise open a hundred connections to the server and the
    operator would see a hundred progress lines.
    """
    results: List[Dict[str, Any]] = []
    queued = []
    for row in rows:
        entry = {"agent_id": row.get("agent_id", "")}
        if row.get("error"):
            entry["state"] = "failed"
            entry["err"] = row["error"]
            results.append(entry)
            continue
        entry["task_id"] = row.get("task_id", "")
        entry["state"] = row.get("state", "queued")
        queued.append(entry)
    if not wait:
        results.extend(queued)
        return results

    total = len(queued)
    done = 0
    workers = max(1, min(int(cap), total or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for entry in queued:
            futures[pool.submit(client.wait_for_result, entry["task_id"],
                                timeout=timeout)] = entry
        for future in as_completed(futures):
            entry = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - one agent must not stop the run
                entry["state"] = "failed"
                entry["err"] = str(exc)
            else:
                entry["state"] = result.get("state", "done")
                entry["code"] = result.get("code", 0)
                out = result.get("out") or ""
                entry["out"] = out if isinstance(out, str) else ""
                if console is not None:
                    console.note_result(entry.get("task_id", ""), result)
            done += 1
            _print_progress(done, total, entry.get("agent_id", ""), entry.get("state", ""))
    _clear_progress()
    results.extend(queued)
    return results


def render_bulk_table(results: Iterable[Dict[str, Any]]) -> str:
    """Render the per-agent result table of a bulk run."""
    lines = []
    lines.append("| agent | state | exit | answer |")
    lines.append("| --- | --- | --- | --- |")
    for row in results:
        answer = str(row.get("out", "") or row.get("err", "") or "")
        answer = answer.strip().splitlines()[0][:60] if answer.strip() else ""
        lines.append("| {} | {} | {} | {} |".format(
            row.get("agent_id", ""), row.get("state", ""),
            row.get("code", ""), answer))
    return "\n".join(lines)


def run_plan(client: Any, console: Any, steps: List[Dict[str, Any]],
             params: Optional[Dict[str, str]] = None, wait: bool = True,
             timeout: float = 60.0) -> Dict[str, Any]:
    """Run a sequence of steps.

    The steps are the ones of a plan: a task, a chain, a wait, a condition
    and a report.  The condition looks at the answer of the step before it
    and stops the rest of the plan when it is not met.
    """
    params = params or {}
    last_ok = True
    last_code = 0
    report: List[str] = []
    done: List[Dict[str, Any]] = []
    for index, raw in enumerate(steps):
        step = expand_step(raw, params)
        kind = str(step.get("kind", ""))
        entry: Dict[str, Any] = {"index": index, "kind": kind, "ok": True}
        if kind == "task":
            agent = str(step.get("agent", ""))
            task_kind = str(step.get("task_kind", ""))
            args = step.get("args") or {}
            if not agent or not task_kind:
                entry["ok"] = False
                entry["err"] = "the step needs an agent and a task kind"
            else:
                task_id = client.submit(agent, task_kind, args)
                entry["task_id"] = task_id
                if console is not None:
                    console.note_task(task_id, agent, task_kind, args)
                if wait:
                    result = client.wait_for_result(task_id, timeout=timeout)
                    entry["state"] = result.get("state", "done")
                    entry["code"] = result.get("code", 0)
                    out = result.get("out") or ""
                    entry["out"] = out if isinstance(out, str) else ""
                    entry["ok"] = entry.get("state") == "done" and entry["code"] == 0
                    if console is not None:
                        console.note_result(task_id, result)
                else:
                    entry["state"] = "queued"
        elif kind == "chain":
            agent = str(step.get("agent", ""))
            stages = step.get("stages") or []
            if not agent or not stages:
                entry["ok"] = False
                entry["err"] = "the chain step needs an agent and its stages"
            else:
                res = client.submit_chain(agent, stages)
                entry["task_id"] = res.get("task_id", "")
                entry["state"] = "queued"
        elif kind == "wait":
            seconds = int(step.get("seconds", 0) or 0)
            entry["detail"] = f"{seconds} seconds"
            if seconds > 0:
                time.sleep(seconds)
        elif kind == "condition":
            condition = str(step.get("condition", ""))
            entry["detail"] = condition
            if condition == "failed":
                last_ok = not last_ok
            elif condition.startswith("code=="):
                want = condition[len("code=="):].strip()
                last_ok = want == str(last_code)
            entry["ok"] = last_ok
            if not last_ok:
                entry["skipped"] = True
        elif kind == "report":
            title = str(step.get("title", "report"))
            entry["detail"] = title
            report.append("## " + title + "\n")
            report.append("\n".join(done_texts(done)) or "_nothing yet_")
            report.append("")
        else:
            entry["ok"] = False
            entry["err"] = f"unknown step kind {kind!r}"
        done.append(entry)
        if entry.get("skipped"):
            break
        last_ok = entry.get("ok", True)
        last_code = int(entry.get("code", 0) or 0)
    return {"steps": done, "report": "\n".join(report)}


def done_texts(done: List[Dict[str, Any]]) -> List[str]:
    """The answers of the steps that ran, as text."""
    out = []
    for entry in done:
        text = entry.get("out")
        if text:
            out.append(str(text))
    return out


def render_workflows(payload: Dict[str, Any]) -> str:
    """Render the catalogue of the workflows."""
    lines = []
    workflows = payload.get("workflows") or []
    if not workflows:
        lines.append("_no workflow was written_")
    for workflow in workflows:
        steps = workflow.get("steps") or []
        lines.append("### {}".format(workflow.get("name", "")))
        if workflow.get("description"):
            lines.append(workflow["description"])
        params = workflow.get("params") or []
        if params:
            lines.append("parameters: " + ", ".join(str(p) for p in params))
        lines.append("steps: " + ", ".join(str(s.get("kind", "")) for s in steps))
        lines.append("runs: {}".format(workflow.get("runs", 0)))
        lines.append("")
    runs = payload.get("runs") or []
    if runs:
        lines.append("## The runs")
        lines.append("")
        lines.append("| run | workflow | state | steps |")
        lines.append("| --- | --- | --- | --- |")
        for run in runs:
            lines.append("| {} | {} | {} | {} |".format(
                run.get("id", ""), run.get("workflow", ""),
                run.get("state", ""), len(run.get("steps") or [])))
        lines.append("")
    return "\n".join(lines)


def split_params(pairs: Iterable[str]) -> Tuple[Dict[str, str], List[str]]:
    """Read the "key=value" pairs of the command line."""
    out: Dict[str, str] = {}
    broken: List[str] = []
    for pair in pairs:
        if "=" not in pair:
            broken.append(pair)
            continue
        key, _, value = pair.partition("=")
        out[key.strip()] = value
    return out, broken
