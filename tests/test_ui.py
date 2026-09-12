"""The interface, and the property that makes it safe to have one.

The UI observes the trace stream and cannot alter a decision. These tests hold
that line, and hold the piping contract that keeps the tool usable in scripts.
"""

from __future__ import annotations

import ast
import io
import json
import re
from pathlib import Path

import pytest
from conftest import GOOD_HOST, good_scope
from rich.console import Console

from bridgeline.types import Plan, SlotRef, Step
from bridgeline.ui import render, theme
from bridgeline.ui.render import RenderingTraceWriter
from bridgeline.ui.session import render_plan

SRC = Path(__file__).resolve().parents[1] / "src" / "bridgeline"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

SECURITY_MODULES = (
    "runtime.py", "fetch.py", "guard.py", "netpolicy.py",
    "tools.py", "plan_io.py", "schema.py", "types.py", "trace.py",
)


def test_the_security_path_never_imports_the_ui() -> None:
    """The whole reason a renderer is safe to bolt on: it is downstream of every
    decision and invisible to all of them."""
    offenders: list[str] = []
    for name in SECURITY_MODULES:
        tree = ast.parse((SRC / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and "ui" in (node.module or "").split("."):
                offenders.append(f"{name}: from {node.module}")
            if isinstance(node, ast.Import):
                offenders += [f"{name}: import {a.name}" for a in node.names if ".ui" in a.name]
    assert offenders == [], f"the security path reached into the UI: {offenders}"


def _console(*, terminal: bool) -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, force_terminal=terminal, no_color=not terminal,
                   width=100, highlight=False), buf


def test_a_redirected_stream_gets_no_escape_codes(tmp_path) -> None:
    console, buf = _console(terminal=False)
    writer = RenderingTraceWriter(tmp_path / "t.jsonl", "r", console)
    writer.banner("0.1.0")
    writer.refusal("netpolicy", "http://attacker.test/x", "host not in plan scope")
    assert ANSI.search(buf.getvalue()) is None


def test_a_redirected_stream_gets_no_mascot(tmp_path) -> None:
    """Drawing a spider into a log file helps nobody."""
    console, buf = _console(terminal=False)
    writer = RenderingTraceWriter(tmp_path / "t.jsonl", "r", console)
    writer.banner("0.1.0")
    assert "(oo)" not in buf.getvalue()
    assert "bridgeline" in buf.getvalue()


def test_a_terminal_gets_the_braced_spider_on_a_refusal(tmp_path) -> None:
    console, buf = _console(terminal=True)
    writer = RenderingTraceWriter(tmp_path / "t.jsonl", "r", console)
    writer.refusal("sink_gate", "http://attacker.test/x", "tainted value in ['url']")
    out = buf.getvalue()
    assert "(OO)" in out and "REFUSED" in out and "sink_gate" in out
    assert writer.refusals == 1


def test_a_reason_can_never_be_read_as_markup(tmp_path) -> None:
    """Reasons carry attacker-influenced text. Rich markup in one must render as
    characters, not as styling."""
    console, buf = _console(terminal=True)
    writer = RenderingTraceWriter(tmp_path / "t.jsonl", "r", console)
    writer.refusal("sink_gate", "x", "tainted value in sensitive sink arg(s) ['url']")
    assert "['url']" in ANSI.sub("", buf.getvalue())


def test_rendering_still_writes_the_trace(tmp_path) -> None:
    console, _ = _console(terminal=True)
    writer = RenderingTraceWriter(tmp_path / "t.jsonl", "r", console)
    writer.write("step", outcome="started", step_index=0, tool="fetch",
                 args={"url": "https://x.test/"})
    line = json.loads((tmp_path / "t.jsonl").read_text().splitlines()[0])
    assert line["tool"] == "fetch" and line["outcome"] == "started"


def test_a_rendering_failure_never_breaks_a_run(tmp_path, monkeypatch) -> None:
    console, _ = _console(terminal=True)
    writer = RenderingTraceWriter(tmp_path / "t.jsonl", "r", console)
    monkeypatch.setattr(writer, "_render", lambda r: 1 / 0)
    record = writer.write("step", outcome="executed", step_index=0, tool="report")
    assert record.tool == "report"
    assert (tmp_path / "t.jsonl").read_text()


@pytest.mark.parametrize(("layer", "reason", "hostile"), [
    ("sink_gate", "tainted value in sensitive sink arg(s) ['url']", True),
    ("capability_gate", "tool not in capability set", True),
    ("contract", "denied by policy", True),
    ("netpolicy", "host 'attacker.test' not in plan scope", True),
    ("netpolicy", "scheme 'file' not in {http, https}", True),
    ("netpolicy", "port 8443 not in plan scope (443,)", True),
    ("netpolicy", "path '/admin' outside plan prefix '/docs'", False),
    ("netpolicy", "disallowed by robots.txt", False),
])
def test_only_a_real_breach_earns_the_signal_colour(layer, reason, hostile) -> None:
    """Amber must stay rare. Leaving the plan's host space is the defense
    engaging; not being in the crawled section is routine filtering, and if both
    glowed the one that matters would stop standing out."""
    assert render.is_hostile(layer, reason) is hostile


def test_the_plan_tree_shows_destinations_and_slots_differently() -> None:
    console, buf = _console(terminal=False)
    plan = Plan(steps=(
        Step(tool="fetch", args={"url": f"https://{GOOD_HOST}/docs/n"},
             scope=good_scope(), out="pages"),
        Step(tool="write_file", args={"path": "notes/s.md", "content": SlotRef("pages")}),
    ))
    render_plan(console, plan)
    out = buf.getvalue()
    assert f"https://{GOOD_HOST}/docs/n" in out       # destination, verbatim
    assert "notes/s.md" in out                        # destination, verbatim
    assert "{pages}" in out                           # slot, marked as a slot
    assert "every destination above is a literal" in out


def test_glyphs_degrade_when_the_stream_cannot_encode_them() -> None:
    class Ascii:
        encoding = "ascii"

    g = theme.glyphs(Ascii())
    assert g.spider_braced == ""
    assert g.refused.isascii() and g.executed.isascii()
