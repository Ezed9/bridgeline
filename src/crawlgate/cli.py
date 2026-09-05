"""crawlgate CLI."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from . import models, plan_io
from .fetch import HttpxClient
from .guard import APPROVE_ASK, APPROVE_NEVER, APPROVE_SCOPE, NullGuard, build
from .runtime import execute
from .tools import build_tools
from .trace import KIND_PLAN_COMMITTED, KIND_RUN_END, KIND_RUN_START, TraceWriter
from .types import Plan, Trusted


def _run_dir(workspace: Path, run_id: str) -> Path:
    return workspace / ".crawlgate" / "runs" / run_id


def _allow_loopback(plan: Plan) -> Plan:
    steps = tuple(
        replace(s, scope=replace(s.scope, allow_loopback=True)) if s.scope is not None else s
        for s in plan.steps
    )
    return replace(plan, steps=steps)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crawlgate",
        description="Crawl the web under a plan-fixed scope, where page content "
                    "structurally cannot become an instruction.",
    )
    parser.add_argument("instruction", nargs="?", help="the trusted task")
    parser.add_argument("--plan", type=Path, help="run a plan JSON file instead of planning")
    parser.add_argument("--workspace", type=Path, default=Path("./work"))
    parser.add_argument("--models", help="<planner>:<extractor>, e.g. anthropic:gemini, or none")
    parser.add_argument("--approve", choices=(APPROVE_NEVER, APPROVE_SCOPE, APPROVE_ASK),
                        default=APPROVE_NEVER)
    parser.add_argument("--allow-loopback", action="store_true",
                        help="permit loopback destinations (fixture sites only)")
    parser.add_argument("--no-guard", action="store_true",
                        help="disable Layer 2, proving Layer 1 is independently sufficient")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the committed plan and exit before any I/O")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.instruction and not args.plan:
        raise SystemExit("give an instruction or --plan")

    workspace: Path = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    tools = build_tools(workspace)
    tiers = models.from_env(args.models)

    run_id = uuid4().hex
    run_dir = _run_dir(workspace, run_id)
    trace = TraceWriter(run_dir / "trace.jsonl", run_id)
    trace.write(KIND_RUN_START, detail={"workspace": str(workspace), "models": tiers.note,
                                        "approve": args.approve, "guard": not args.no_guard})

    # The plan is committed BEFORE anything is fetched. That ordering is the
    # whole design, so it is also the first thing written to disk.
    if args.plan:
        plan = plan_io.load(args.plan)
    else:
        plan = tiers.planner().plan(Trusted(args.instruction), tools)
    if args.allow_loopback:
        plan = _allow_loopback(plan)

    plan_json = plan_io.dumps(plan)
    (run_dir / "plan.json").write_text(plan_json, encoding="utf-8")
    trace.write(KIND_PLAN_COMMITTED, detail={"steps": len(plan.steps), "path": str(run_dir)})

    if args.dry_run:
        print(plan_json)
        return 0

    guard = (
        NullGuard()
        if args.no_guard
        else build(plan, workspace, tools, args.approve, trace, run_dir / "audit.jsonl")
    )
    result = execute(plan, tools, tiers.extractor(), guard, trace, HttpxClient())

    trace.write(KIND_RUN_END, detail={"blocked": sum(1 for e in result.events if e.blocked),
                                      "executed": len(result.tools_called())})

    if result.final_text:
        print(result.final_text)
    for event in result.events:
        if event.blocked:
            print(f"[blocked/{event.layer}] step {event.step_index} {event.tool}: {event.reason}",
                  file=sys.stderr)
    print(f"\ntrace: {trace.path}", file=sys.stderr)
    return 2 if result.had_block() else 0


if __name__ == "__main__":
    raise SystemExit(main())
