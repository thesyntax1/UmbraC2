"""The plan file: a sequence of steps, written once and run often.

A plan is the text form of a workflow.  It is deliberately small — a YAML
subset with no anchors, no tags and no flow maps — because a plan is
something an operator writes by hand at two in the morning and expects the
server to do exactly what it says.

The format::

    name: sweep
    description: sweep the web tier and collect what answers
    params: [target, kind]
    steps:
      - kind: task
        agent: "{{target}}"
        task_kind: "{{kind}}"
        args:
          cmd: "systeminfo"
      - kind: wait
        seconds: 5
      - kind: condition
        condition: ok
      - kind: report
        title: The sweep

The parameters are written {{name}} in the text of a step; the operator
gives them at run time.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["PlanError", "parse_plan", "load_plan", "expand_params", "plan_steps"]


class PlanError(Exception):
    """The plan file could not be read."""


def load_plan(path: str) -> Dict[str, Any]:
    """Read a plan file from the disk.

    The file may be JSON: the plan is JSON-shaped, and a pipeline that
    writes JSON should not have to write YAML to be believed.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise PlanError(f"cannot read the plan {path}: {exc}") from exc
    return parse_plan(text)


def parse_plan(text: str) -> Dict[str, Any]:
    """Read a plan out of its text."""
    stripped = text.strip()
    if not stripped:
        raise PlanError("the plan is empty")
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise PlanError(f"the plan is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise PlanError("the plan must be an object")
        return data
    lines = _lines(text)
    if not lines:
        raise PlanError("the plan is empty")
    value, index = _parse_block(lines, 0, lines[0][2])
    if index != len(lines):
        raise PlanError(f"line {lines[index][0]}: the plan has trailing content")
    if not isinstance(value, dict):
        raise PlanError("the plan must be a mapping")
    return value


def _lines(text: str) -> List[Tuple[int, str, int]]:
    """Read the meaningful lines of the plan.

    Each line is (number, text, indent).  The comments and the blank lines
    are dropped here, so the parser only sees structure.
    """
    out: List[Tuple[int, str, int]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw.split("#")[0]:
            raise PlanError(f"line {number}: a tab is not allowed in the indent")
        body = _strip_comment(raw)
        if not body.strip():
            continue
        indent = len(body) - len(body.lstrip(" "))
        out.append((number, body.strip(), indent))
    return out


def _strip_comment(line: str) -> str:
    """Remove the comment of a line, keeping a # inside a quoted text."""
    quote = ""
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            continue
        if char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _parse_block(lines: List[Tuple[int, str, int]], index: int,
                 indent: int) -> Tuple[Any, int]:
    """Parse the block that starts at the given line."""
    if index >= len(lines):
        return None, index
    if lines[index][1].startswith("- "):
        return _parse_list(lines, index, indent)
    return _parse_map(lines, index, indent)


def _parse_list(lines: List[Tuple[int, str, int]], index: int,
                indent: int) -> Tuple[List[Any], int]:
    out: List[Any] = []
    while index < len(lines):
        number, text, own = lines[index]
        if own < indent or not text.startswith("- "):
            break
        if own > indent:
            raise PlanError(f"line {number}: the list is not aligned")
        body = text[2:].strip()
        index += 1
        if not body:
            # The item is a block of its own below the dash.
            if index < len(lines) and lines[index][2] > own:
                value, index = _parse_block(lines, index, lines[index][2])
                out.append(value)
            else:
                out.append(None)
            continue
        if ":" in body and not body.startswith(("\"", "'", "[", "{")):
            # The item is a mapping whose first key sits on the dash line.
            item_indent = own + 2
            first_key, _, rest = body.partition(":")
            item: Dict[str, Any] = {}
            key = first_key.strip()
            rest = rest.strip()
            if rest == "":
                item[key] = None
                if index < len(lines) and lines[index][2] > own:
                    nested, index = _parse_block(lines, index, lines[index][2])
                    item[key] = nested
            else:
                item[key] = _scalar(rest)
            # The rest of the mapping continues below.
            while index < len(lines) and lines[index][2] >= item_indent:
                sub, index = _parse_map_entry(lines, index, item_indent)
                if sub is None:
                    break
                item[sub[0]] = sub[1]
            out.append(item)
            continue
        out.append(_scalar(body))
    return out, index


def _parse_map(lines: List[Tuple[int, str, int]], index: int,
               indent: int) -> Tuple[Dict[str, Any], int]:
    out: Dict[str, Any] = {}
    while index < len(lines):
        entry, index = _parse_map_entry(lines, index, indent)
        if entry is None:
            break
        out[entry[0]] = entry[1]
    return out, index


def _parse_map_entry(lines: List[Tuple[int, str, int]], index: int,
                     indent: int) -> Tuple[Optional[Tuple[str, Any]], int]:
    """Parse one "key: value" line, with the block that may follow it."""
    number, text, own = lines[index]
    if own < indent:
        return None, index
    if own > indent:
        raise PlanError(f"line {number}: the mapping is not aligned")
    if text.startswith("- "):
        return None, index
    key, sep, rest = text.partition(":")
    if not sep:
        raise PlanError(f"line {number}: {text!r} is not a key")
    key = key.strip().strip("\"'")
    if not key:
        raise PlanError(f"line {number}: the key is empty")
    rest = rest.strip()
    index += 1
    if rest == "":
        # The value is the block below, if there is one.  A list may sit at
        # the indent of its key, the way people write them:
        #
        #     steps:
        #     - kind: task
        if index < len(lines):
            next_indent = lines[index][2]
            if next_indent > own:
                value, index = _parse_block(lines, index, next_indent)
                return (key, value), index
            if next_indent == own and lines[index][1].startswith("- "):
                value, index = _parse_list(lines, index, next_indent)
                return (key, value), index
        return (key, None), index
    if rest in ("|", ">"):
        # A block scalar: the lines below, dedented.
        block: List[str] = []
        while index < len(lines) and lines[index][2] > own:
            block.append(lines[index][1])
            index += 1
        return (key, "\n".join(block)), index
    return (key, _scalar(rest)), index


def _scalar(text: str) -> Any:
    """Read one scalar: a quoted text, a list, a number, a boolean or a word."""
    if text == "":
        return None
    if text[0] in "\"'":
        quote = text[0]
        end = text.find(quote, 1)
        if end < 0:
            raise PlanError(f"the quoted text {text!r} is not closed")
        return text[1:end]
    if text.startswith("["):
        if not text.endswith("]"):
            raise PlanError(f"the list {text!r} is not closed")
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part.strip()) for part in _split_list(inner)]
    if text.startswith("{"):
        if not text.endswith("}"):
            raise PlanError(f"the mapping {text!r} is not closed")
        inner = text[1:-1].strip()
        out: Dict[str, Any] = {}
        if not inner:
            return out
        for part in _split_list(inner):
            key, _, value = part.partition(":")
            if not _:
                raise PlanError(f"the mapping {text!r} is not understood")
            out[key.strip().strip("\"'")] = _scalar(value.strip())
        return out
    if text in ("true", "True", "yes"):
        return True
    if text in ("false", "False", "no"):
        return False
    if text in ("null", "~"):
        return None
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _split_list(text: str) -> List[str]:
    """Split a flow list on the commas that are not inside a quote."""
    parts: List[str] = []
    current: List[str] = []
    quote = ""
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            current.append(char)
            continue
        if char == ",":
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    if current:
        parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def plan_steps(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The steps of a plan, as the server wants them."""
    steps = plan.get("steps")
    if steps is None:
        raise PlanError("the plan has no steps")
    if not isinstance(steps, list):
        raise PlanError("the steps of a plan must be a list")
    out: List[Dict[str, Any]] = []
    for step in steps:
        if not isinstance(step, dict):
            raise PlanError("a step of a plan must be a mapping")
        if not step.get("kind"):
            raise PlanError("a step of a plan needs a kind")
        out.append(step)
    return out


def expand_params(text: str, params: Dict[str, str]) -> str:
    """Replace the {{name}} placeholders of a text."""
    if not text or not params:
        return text
    out = text
    for name, value in params.items():
        out = out.replace("{{" + str(name) + "}}", str(value))
    return out


def expand_step(step: Dict[str, Any], params: Dict[str, str]) -> Dict[str, Any]:
    """Fill the parameters of one step."""
    out: Dict[str, Any] = {}
    for key, value in step.items():
        if isinstance(value, str):
            out[key] = expand_params(value, params)
        elif isinstance(value, dict):
            out[key] = expand_step(value, params)
        elif isinstance(value, list):
            out[key] = [expand_step(item, params) if isinstance(item, dict)
                        else expand_params(item, params) if isinstance(item, str)
                        else item for item in value]
        else:
            out[key] = value
    return out


def plan_params(plan: Dict[str, Any]) -> List[str]:
    """The parameters a plan declares."""
    params = plan.get("params") or []
    if isinstance(params, str):
        return [part.strip() for part in params.split(",") if part.strip()]
    if not isinstance(params, list):
        raise PlanError("the params of a plan must be a list")
    return [str(item) for item in params]


def default_plan_path() -> str:
    """Where a plan is kept when the operator does not say."""
    home = os.path.expanduser("~")
    return os.path.join(home, ".umbra", "plans")
