"""The plan gate, and the refine prompt.

The plan is the security artifact, so the gate is the one place a human has real
authority over a run. Editing goes through `plan_io.parse`, which already fails
closed on every structural violation -- a hand-edited plan gets exactly the same
validation as a generated one.

A refinement re-plans from your words plus the original instruction, and NEVER
from anything the crawl read. Re-feeding results to the planner is the naive fix
that would void the guarantee, so the gate states its input on screen.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from rich.console import Console
from rich.text import Text

from .. import plan_io
from ..types import Plan, SlotRef, Step
from . import theme

APPROVE, EDIT, QUIT = "approve", "edit", "quit"


def _val(value: object) -> tuple[str, str]:
    """Render an argument, and say whether it is a destination or a slot."""
    if isinstance(value, SlotRef):
        return f"{{{value.slot}}}", theme.MUTED
    return str(value), theme.CONTENT


def render_plan(console: Console, plan: Plan) -> None:
    g = theme.glyphs(console.file)
    head = Text()
    head.append("PLAN", style="bold")
    head.append("  committed before anything is fetched", style=theme.CHROME)
    head.append(f"   {len(plan.steps)} steps", style=theme.MUTED)
    console.print(head)
    console.print()

    for i, step in enumerate(plan.steps, start=1):
        line = Text(" ")
        line.append(f"{i} ", style=theme.MUTED)
        line.append(f"{step.tool:<12}", style=theme.CONTENT)
        primary = step.args.get("url") or step.args.get("path") or step.args.get("from")
        if primary is not None:
            text, style = _val(primary)
            line.append(text, style=style)
        console.print(line)

        if step.scope is not None:
            s = step.scope
            for label, value in (
                ("hosts", ", ".join(s.allowed_hosts)),
                ("prefix", s.path_prefix),
                ("depth", f"{s.max_depth}    pages <= {s.max_pages}"),
            ):
                row = Text("      ")
                row.append(f"{label:<8}", style=theme.CHROME)
                row.append(value, style=theme.CONTENT)
                console.print(row)

        for name, value in step.args.items():
            if name in ("url", "path", "from", "query"):
                continue
            row = Text("      ")
            row.append(f"{name:<8}", style=theme.CHROME)
            text, style = _val(value)
            row.append(text, style=style)
            console.print(row)

        if step.when is not None:
            row = Text("      ")
            row.append(f"{'when':<8}", style=theme.CHROME)
            row.append(step.when, style=theme.MUTED)
            console.print(row)

        if step.out is not None:
            row = Text("      ")
            row.append(f"-> {step.out}", style=theme.MUTED)
            console.print(row)

    console.print()
    note = Text("every destination above is a literal", style=theme.CHROME)
    note.append("  -  ", style=theme.MUTED)
    note.append("every {slot} sits in a content position", style=theme.CHROME)
    console.print(note)
    del g


def _open_editor(console: Console, plan: Plan) -> Plan | None:
    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL")
    if not editor:
        console.print(Text("set $EDITOR to edit the plan", style=theme.CHROME))
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".plan.json", delete=False) as fh:
        fh.write(plan_io.dumps(plan))
        temp = Path(fh.name)
    try:
        subprocess.run([*editor.split(), str(temp)], check=False)
        # Re-validated exactly like a generated plan: the fail-closed parser is
        # the authority, not the fact that a human typed it.
        return plan_io.load(temp)
    except plan_io.PlanError as exc:
        console.print(Text(f"plan rejected: {exc}", style=theme.SIGNAL))
        return None
    finally:
        temp.unlink(missing_ok=True)


def plan_gate(console: Console, plan: Plan, interactive: bool) -> tuple[str, Plan]:
    render_plan(console, plan)
    if not interactive:
        return APPROVE, plan

    while True:
        console.print()
        prompt = Text()
        for key, label in (("a", "approve"), ("e", "edit in $EDITOR"), ("q", "quit")):
            prompt.append(f"[{key}] ", style="bold")
            prompt.append(f"{label}   ", style=theme.CHROME)
        console.print(prompt, end="")
        try:
            choice = input(" ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return QUIT, plan
        if choice in ("", "a", "approve", "y"):
            return APPROVE, plan
        if choice in ("q", "quit", "n"):
            return QUIT, plan
        if choice in ("e", "edit"):
            edited = _open_editor(console, plan)
            if edited is not None:
                plan = edited
                console.print()
                render_plan(console, plan)


def refine_prompt(console: Console) -> str | None:
    """One prompt. A refinement becomes a fresh committed plan."""
    console.print()
    hint = Text("refine", style="bold")
    hint.append(" with more instruction, or blank to finish", style=theme.CHROME)
    console.print(hint)
    try:
        answer = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    return answer or None


def planner_input_note(console: Console, instruction: str) -> None:
    line = Text()
    line.append(f"{'planner input':<15}", style=theme.CHROME)
    line.append("your instruction only", style=theme.CHROME)
    line.append("  -  ", style=theme.MUTED)
    line.append("0 bytes", style=theme.CONTENT)
    line.append(" of page content", style=theme.CHROME)
    console.print(line)
    del instruction


def models_note(console: Console, planner: str, extractor: str, note: str) -> None:
    line = Text()
    line.append(f"{'models':<15}", style=theme.CHROME)
    line.append(f"planner {planner}", style=theme.CONTENT)
    line.append("  -  ", style=theme.MUTED)
    line.append(f"extractor {extractor}", style=theme.CONTENT)
    console.print(line)
    if "(" in note:
        warn = Text(" " * 15)
        warn.append(note[note.index("(") + 1:].rstrip(")"), style=theme.SIGNAL)
        console.print(warn)


def task_note(console: Console, instruction: str) -> None:
    line = Text()
    line.append(f"{'task':<15}", style=theme.CHROME)
    line.append(instruction, style=theme.CONTENT)
    console.print(line)


def steps_of(plan: Plan) -> tuple[Step, ...]:
    return plan.steps
