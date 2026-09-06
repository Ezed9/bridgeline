"""crawlgate CLI."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from rich.console import Console

from . import __version__, models, plan_io
from .fetch import HttpxClient
from .guard import APPROVE_ASK, APPROVE_NEVER, APPROVE_SCOPE, NullGuard, build
from .runtime import execute
from .tools import build_tools
from .trace import KIND_PLAN_COMMITTED, KIND_RUN_END, KIND_RUN_START
from .types import Plan, Trusted
from .ui import session, theme
from .ui.render import RenderingTraceWriter


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
    parser.add_argument("--yes", action="store_true",
                        help="skip the plan gate and run the committed plan")
    parser.add_argument("--no-color", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.instruction and not args.plan:
        raise SystemExit("give an instruction or --plan")

    # Chrome to stderr, answer to stdout: `crawlgate ... > out.md` stays clean.
    err = Console(stderr=True, highlight=False,
                  no_color=args.no_color or not theme.color_enabled(sys.stderr))
    interactive = not args.yes and sys.stdin.isatty() and sys.stderr.isatty()

    workspace: Path = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    tools = build_tools(workspace)
    tiers = models.from_env(args.models)

    original = args.instruction or ""
    instruction = original
    exit_code = 0

    while True:
        run_id = uuid4().hex
        run_dir = _run_dir(workspace, run_id)
        trace = RenderingTraceWriter(run_dir / "trace.jsonl", run_id, err)
        trace.banner(__version__)
        trace.write(KIND_RUN_START, detail={"workspace": str(workspace), "models": tiers.note,
                                            "approve": args.approve, "guard": not args.no_guard})

        if args.instruction:
            session.task_note(err, instruction)
            session.planner_input_note(err, instruction)
        trace.rule()

        # The plan is committed before anything is fetched, so it is also the
        # first thing shown and the first thing written to disk.
        plan = plan_io.load(args.plan) if args.plan else \
            tiers.planner().plan(Trusted(instruction), tools)
        if args.allow_loopback:
            plan = _allow_loopback(plan)

        plan_json = plan_io.dumps(plan)
        (run_dir / "plan.json").write_text(plan_json, encoding="utf-8")
        trace.write(KIND_PLAN_COMMITTED, detail={"steps": len(plan.steps), "path": str(run_dir)})

        if args.dry_run:
            print(plan_json)
            return 0

        decision, plan = session.plan_gate(err, plan, interactive)
        if decision == session.QUIT:
            return 1
        err.print()

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
        exit_code = 2 if result.had_block() else 0

        if not interactive or args.plan:
            break
        more = session.refine_prompt(err)
        if not more:
            break
        # A refinement re-plans from YOUR words. Nothing the crawl read is
        # carried across -- that channel is the one the design exists to close.
        instruction = f"{original} {more}"

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
