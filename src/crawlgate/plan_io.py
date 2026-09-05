"""Plan <-> JSON. Parsing is fail-closed.

A hand-written or model-emitted plan is an INPUT. Every structural guarantee the
runtime relies on is re-asserted here, because the type system only protects
values that were constructed in Python.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import schema as schema_mod
from .types import Arg, CrawlScope, Plan, SlotRef, Step

KNOWN_TOOLS: frozenset[str] = frozenset({"fetch", "extract", "write_file", "report"})
_SLOT_KEY = "$slot"


class PlanError(ValueError):
    pass


def _parse_arg(raw: object, where: str) -> Arg:
    if isinstance(raw, dict):
        if set(raw) != {_SLOT_KEY} or not isinstance(raw[_SLOT_KEY], str):
            raise PlanError(f"{where}: an object argument must be exactly {{'{_SLOT_KEY}': name}}")
        return SlotRef(raw[_SLOT_KEY])
    if isinstance(raw, str | int | float | bool):
        return raw
    raise PlanError(f"{where}: unsupported argument type {type(raw).__name__}")


def _parse_scope(raw: object, where: str) -> CrawlScope:
    if not isinstance(raw, dict):
        raise PlanError(f"{where}: scope must be an object")
    # Structurally impossible to type a SlotRef into CrawlScope -- assert it
    # anyway, because this input never passed through the type checker.
    if _contains_slot(raw):
        raise PlanError(f"{where}: a scope may not reference a slot; it must be fixed by the plan")
    known = set(CrawlScope.__dataclass_fields__)
    unknown = set(raw) - known
    if unknown:
        raise PlanError(f"{where}: unknown scope fields {sorted(unknown)}")
    if not raw.get("allowed_hosts"):
        raise PlanError(f"{where}: scope must name at least one allowed host")
    return CrawlScope(
        allowed_hosts=tuple(str(h) for h in raw["allowed_hosts"]),
        path_prefix=str(raw.get("path_prefix", "/")),
        allowed_schemes=tuple(str(s) for s in raw.get("allowed_schemes", ("https",))),
        allowed_ports=tuple(int(p) for p in raw.get("allowed_ports", (443,))),
        max_depth=int(raw.get("max_depth", 1)),
        max_pages=int(raw.get("max_pages", 10)),
        max_bytes_per_page=int(raw.get("max_bytes_per_page", 512 * 1024)),
        request_timeout_s=float(raw.get("request_timeout_s", 10.0)),
        allow_loopback=bool(raw.get("allow_loopback", False)),
    )


def _contains_slot(node: object) -> bool:
    if isinstance(node, dict):
        return _SLOT_KEY in node or any(_contains_slot(v) for v in node.values())
    if isinstance(node, list | tuple):
        return any(_contains_slot(v) for v in node)
    return False


def _parse_step(raw: object, index: int) -> Step:
    where = f"step {index}"
    if not isinstance(raw, dict):
        raise PlanError(f"{where}: must be an object")

    tool = raw.get("tool")
    if tool not in KNOWN_TOOLS:
        raise PlanError(f"{where}: unknown tool {tool!r}; known: {sorted(KNOWN_TOOLS)}")

    args_raw = raw.get("args", {})
    if not isinstance(args_raw, dict):
        raise PlanError(f"{where}: args must be an object")
    args = {str(k): _parse_arg(v, f"{where}.args.{k}") for k, v in args_raw.items()}

    scope_raw = raw.get("scope")
    if tool == "fetch" and scope_raw is None:
        raise PlanError(f"{where}: a fetch step must declare a scope")
    if tool != "fetch" and scope_raw is not None:
        raise PlanError(f"{where}: only a fetch step may declare a scope")
    scope = _parse_scope(scope_raw, where) if scope_raw is not None else None

    if tool == "extract":
        declared = args.get("schema")
        if not isinstance(declared, str) or not schema_mod.is_known(declared):
            raise PlanError(f"{where}: extract needs a known schema, got {declared!r}")

    return Step(
        tool=tool,
        args=args,
        out=raw["out"] if raw.get("out") is not None else None,
        when=raw["when"] if raw.get("when") is not None else None,
        scope=scope,
        allow_tainted_sink=bool(raw.get("allow_tainted_sink", False)),
    )


def parse(raw: object) -> Plan:
    if not isinstance(raw, dict):
        raise PlanError("a plan must be an object")
    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        raise PlanError("a plan must have a non-empty steps list")

    steps = tuple(_parse_step(s, i) for i, s in enumerate(steps_raw))

    declared: set[str] = set()
    for i, step in enumerate(steps):
        for name, arg in step.args.items():
            if isinstance(arg, SlotRef) and arg.slot not in declared:
                raise PlanError(
                    f"step {i}.args.{name} references slot {arg.slot!r} "
                    "before any step declares it"
                )
        if step.when is not None:
            slot = step.when.split("==", 1)[0].strip()
            if slot not in declared:
                raise PlanError(f"step {i}: `when` references undeclared slot {slot!r}")
        if step.out is not None:
            declared.add(step.out)

    return Plan(
        steps=steps,
        rationale=str(raw.get("rationale", "")),
        allow_tainted_sink=bool(raw.get("allow_tainted_sink", False)),
        plan_version=int(raw.get("plan_version", 1)),
    )


def loads(text: str) -> Plan:
    try:
        return parse(json.loads(text))
    except json.JSONDecodeError as exc:
        raise PlanError(f"plan is not valid JSON: {exc}") from exc


def load(path: Path) -> Plan:
    return loads(path.read_text(encoding="utf-8"))


def _arg_to_json(arg: Arg) -> Any:
    return {_SLOT_KEY: arg.slot} if isinstance(arg, SlotRef) else arg


def to_json(plan: Plan) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    for step in plan.steps:
        entry: dict[str, Any] = {
            "tool": step.tool,
            "args": {k: _arg_to_json(v) for k, v in step.args.items()},
        }
        if step.scope is not None:
            entry["scope"] = asdict(step.scope)
        if step.out is not None:
            entry["out"] = step.out
        if step.when is not None:
            entry["when"] = step.when
        if step.allow_tainted_sink:
            entry["allow_tainted_sink"] = True
        steps.append(entry)
    return {
        "plan_version": plan.plan_version,
        "rationale": plan.rationale,
        "allow_tainted_sink": plan.allow_tainted_sink,
        "steps": steps,
    }


def dumps(plan: Plan) -> str:
    return json.dumps(to_json(plan), indent=2, sort_keys=False)
