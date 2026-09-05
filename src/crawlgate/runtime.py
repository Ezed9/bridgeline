"""The capability gate. This module is the guarantee.

`execute` runs a committed Plan. The structural properties, each enforced here
and nowhere else:

  - The executor iterates ONLY over `plan.steps`. There is no path by which a
    tool output can introduce a step, reorder steps, or change a step's
    destination. A Tainted `when` guard is the one bounded exception: it can
    skip or route among plan-fixed steps, but every reachable step's destination
    is a plan literal, so untrusted data may gate, never redirect.
  - Tool outputs are wrapped as Tainted and stored in a data channel. They are
    passed onward as opaque values via SlotRef, never spliced into instruction
    text and never returned to the planner.
  - A step whose tool is not in the toolset is refused. The plan IS the
    capability set.

None of this depends on a model behaving well: even a maximally malicious tool
output cannot escape, because the untrusted string is never interpreted as
control flow anywhere in this module.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from . import fetch as fetch_mod
from . import netpolicy
from . import schema as schema_mod
from .extractor import Extractor, render
from .guard import Guard
from .trace import (
    KIND_EXTRACT,
    KIND_STEP,
    LAYER_CAPABILITY_GATE,
    LAYER_SCHEMA,
    LAYER_SINK_GATE,
    TraceWriter,
)
from .types import (
    Arg,
    ExecEvent,
    ExecResult,
    Page,
    PageSet,
    Plan,
    SlotRef,
    Step,
    Tainted,
    ToolSpec,
)


class CapabilityError(Exception):
    pass


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "yes", "1")


def _condition_met(when: str, result: ExecResult) -> bool:
    if "==" in when:
        slot, expected = when.split("==", 1)
        cond = result.data.get(slot.strip())
        return cond is not None and str(cond.value).strip() == expected.strip()
    cond = result.data.get(when)
    return cond is not None and _truthy(cond.value)


def _resolve_arg(arg: Arg, data: dict[str, Tainted]) -> tuple[object, bool]:
    if isinstance(arg, SlotRef):
        if arg.slot not in data:
            raise CapabilityError(f"plan references undefined slot {arg.slot!r}")
        return data[arg.slot].value, True
    return arg, False


def _block(
    result: ExecResult, trace: TraceWriter, i: int, step: Step, reason: str, layer: str,
    args: dict[str, object] | None = None, contract: str | None = None,
    verdict: str | None = None,
) -> None:
    result.events.append(
        ExecEvent(i, step.tool, args or {}, blocked=True, reason=reason, layer=layer)
    )
    trace.write(KIND_STEP, outcome="blocked", step_index=i, tool=step.tool,
                args=args or {}, layer=layer, reason=reason,
                contract=contract, verdict=verdict)


def _source_text(value: object) -> str:
    if isinstance(value, PageSet):
        return render(value)
    if isinstance(value, Page):
        return value.text
    return str(value)


def _run_extract(
    i: int, step: Step, result: ExecResult, extractor: Extractor, trace: TraceWriter
) -> bool:
    declared = str(step.args.get("schema", ""))
    query = step.args.get("query", "")
    source_arg = step.args.get("from")
    if not isinstance(source_arg, SlotRef):
        _block(result, trace, i, step, "extract.from must reference a slot", LAYER_CAPABILITY_GATE)
        return False
    if source_arg.slot not in result.data:
        _block(result, trace, i, step, "extract.from slot unfilled", LAYER_CAPABILITY_GATE)
        return False

    source = _source_text(result.data[source_arg.slot].value)
    raw = extractor.extract(source, str(query), declared)
    value = schema_mod.validate(raw, declared)
    if value is None:
        # Leave the out-slot UNFILLED. The gate then blocks any dependent step.
        _block(result, trace, i, step, f"extraction failed schema {declared!r}", LAYER_SCHEMA)
        return False

    if step.out is not None:
        result.data[step.out] = Tainted(value, source_step=i, note=f"extract[{declared}]")
    trace.write(KIND_EXTRACT, outcome="executed", step_index=i, tool="extract",
                args={"schema": declared, "from": source_arg.slot},
                detail={"value": value, "source_chars": len(source)})
    return True


def execute(
    plan: Plan,
    tools: dict[str, ToolSpec],
    extractor: Extractor,
    guard: Guard,
    trace: TraceWriter,
    http: fetch_mod.HttpClient,
    resolver: netpolicy.Resolver = netpolicy.real_resolver,
    sleep: Callable[[float], None] = time.sleep,
) -> ExecResult:
    result = ExecResult()
    unfilled: set[str] = set()

    for i, step in enumerate(plan.steps):
        if step.when is not None and not _condition_met(step.when, result):
            _block(result, trace, i, step, f"condition {step.when!r} not satisfied",
                   LAYER_CAPABILITY_GATE)
            continue

        # extract is a runtime-provided quarantined read, never a tool.
        if step.tool == "extract":
            if not _run_extract(i, step, result, extractor, trace) and step.out is not None:
                unfilled.add(step.out)
            continue

        # ---- Layer 1: capability gate ----
        spec = tools.get(step.tool)
        if spec is None:
            _block(result, trace, i, step, "tool not in capability set", LAYER_CAPABILITY_GATE)
            continue
        unexpected = set(step.args) - set(spec.params)
        if unexpected:
            _block(result, trace, i, step,
                   f"args {sorted(unexpected)} not in tool's declared shape",
                   LAYER_CAPABILITY_GATE)
            continue

        resolved: dict[str, object] = {}
        tainted_names: set[str] = set()
        try:
            for name, arg in step.args.items():
                value, tainted = _resolve_arg(arg, result.data)
                resolved[name] = value
                if tainted:
                    tainted_names.add(name)
        except CapabilityError:
            referenced = {a.slot for a in step.args.values() if isinstance(a, SlotRef)}
            if referenced & unfilled:
                _block(result, trace, i, step,
                       "dependent slot unfilled (extraction failed schema)",
                       LAYER_CAPABILITY_GATE)
                continue
            raise

        # ---- Layer 1: sink gate, default-deny ----
        # Fail closed: an exfiltrating tool declaring NO sensitive_params is
        # treated as if every arg is sensitive, so a forgotten declaration can
        # never silently leave a destination unguarded.
        if spec.exfiltrating and not (plan.allow_tainted_sink or step.allow_tainted_sink):
            sensitive = set(spec.sensitive_params) or set(spec.params)
            tainted_sinks = tainted_names & sensitive
            if tainted_sinks:
                _block(result, trace, i, step,
                       f"tainted value in sensitive sink arg(s) {sorted(tainted_sinks)} "
                       "blocked (default-deny)",
                       LAYER_SINK_GATE, args=resolved)
                continue

        # Rendering is a channel. A tainted value bound for human eyes is
        # defanged deterministically -- not classified, not scanned.
        for name in spec.render_params:
            if name in tainted_names and isinstance(resolved.get(name), str):
                resolved[name] = netpolicy.defang(resolved[name])

        # ---- Layer 1 passed. Layer 2 now. ----
        if step.tool == "fetch":
            if step.scope is None:
                _block(result, trace, i, step, "fetch without a scope", LAYER_CAPABILITY_GATE)
                continue
            output: object = fetch_mod.crawl(
                seed=str(resolved["url"]), scope=step.scope, guard=guard,
                trace=trace, http=http, resolver=resolver, sleep=sleep,
            )
        else:
            # The guard judges what the tool will act on, not what the plan wrote.
            judged = spec.effective(resolved) if spec.effective else resolved
            verdict = guard.check(step.tool, judged)
            if not verdict.allowed:
                _block(result, trace, i, step, verdict.reason, "contract",
                       args=resolved, contract=verdict.contract, verdict=verdict.verdict)
                continue
            output = spec.impl(**resolved)

        result.events.append(ExecEvent(i, step.tool, resolved, output_repr=repr(output)[:200]))
        trace.write(KIND_STEP, outcome="executed", step_index=i, tool=step.tool, args=resolved)

        if step.tool == "report":
            result.final_text = str(output)

        # Tool output is untrusted data. It enters the one-way channel as Tainted
        # and is NEVER handed back to the planner. Output derived from a tainted
        # argument stays tainted.
        if step.out is not None:
            note = f"output of {step.tool}" + (" [derived]" if tainted_names else "")
            result.data[step.out] = Tainted(output, source_step=i, note=note)

    return result
