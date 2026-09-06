"""SPEC.md K5: can a live planner actually target the plan schema?

Kill criterion: fewer than 6 in 10 benign tasks yielding a schema-valid Plan
means the schema is too hard to aim at and should be simplified.

The informative case is not the pass rate but WHY a plan is rejected. A planner
reaching for a primitive the schema lacks -- most of all, trying to put a slot
where a destination belongs -- is exactly the signal capsep got from Gemini, and
it is worth more than the number.

    uv run python -m demo.k5_planner
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from dotenv import load_dotenv

from crawlgate import models, plan_io
from crawlgate.tools import build_tools
from crawlgate.types import Plan, SlotRef, Trusted
from demo.tasks import TASKS


def destination_slots(plan: Plan) -> list[str]:
    """Any slot that reached a destination. plan_io.parse should make this
    impossible -- checked anyway, because that is the whole invariant."""
    found: list[str] = []
    for i, step in enumerate(plan.steps):
        for name in ("url", "path"):
            if isinstance(step.args.get(name), SlotRef):
                found.append(f"step {i}.{name}")
    return found


_PACE_S = 7.0        # free-tier Gemini allows ~10 requests/minute
_RETRIES = 4


def _plan_once(planner: object, instruction: str, tools: dict) -> tuple[str, str]:
    delay = 10.0
    for attempt in range(_RETRIES):
        try:
            plan = planner.plan(Trusted(instruction), tools)
        except plan_io.PlanError as exc:
            return "invalid", f"rejected: {exc}"
        except Exception as exc:
            text = f"{type(exc).__name__}: {exc}"
            transient = "429" in text or "RESOURCE_EXHAUSTED" in text or "503" in text
            if transient and attempt < _RETRIES - 1:
                time.sleep(delay)
                delay *= 2
                continue
            return ("unavailable" if transient else "invalid"), text
        leaked = destination_slots(plan)
        if leaked:
            return "invalid", f"SLOT IN A DESTINATION: {leaked}"
        return "valid", " -> ".join(s.tool for s in plan.steps)
    return "unavailable", "exhausted retries"


def main() -> int:
    load_dotenv(override=False)
    tiers = models.from_env()
    if tiers.planner_profile == "none":
        raise SystemExit("no API key: set GOOGLE_API_KEY or ANTHROPIC_API_KEY")
    planner = tiers.planner()
    tools = build_tools(Path("/tmp/k5"))

    # Three outcomes, not two. A rate limit or a 503 says nothing about whether
    # the schema is targetable, so counting it as a schema failure would have
    # produced a kill verdict from an unanswered question.
    rows: list[tuple[str, str, str]] = []
    for task in TASKS:
        outcome, detail = _plan_once(planner, task.instruction, tools)
        rows.append((task.name, outcome, detail))
        time.sleep(_PACE_S)

    width = max(len(r[0]) for r in rows)
    mark = {"valid": "ok  ", "invalid": "FAIL", "unavailable": "-   "}
    for name, outcome, detail in rows:
        print(f"{name:<{width}}  {mark[outcome]}  {detail[:96]}")

    valid = sum(1 for r in rows if r[1] == "valid")
    invalid = sum(1 for r in rows if r[1] == "invalid")
    unavailable = sum(1 for r in rows if r[1] == "unavailable")
    answered = valid + invalid

    print(f"\nschema-valid   : {valid}/{answered} answered = "
          f"{(valid / answered if answered else 0):.0%}   (kill below 60%)")
    if unavailable:
        print(f"unavailable    : {unavailable}/{len(rows)} "
              "(rate limit or provider error -- not K5 evidence)")

    if answered < 10:
        print(f"\nINCONCLUSIVE: only {answered} of {len(rows)} tasks got a response. "
              "K5 needs at least 10.")
        return 2
    if valid / answered < 0.60:
        print("\nKILL K5: the plan schema is too hard for a live planner to target.")
        print("Report which primitive it kept reaching for, and simplify the schema.")
        return 1
    print("\nPASS K5.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
