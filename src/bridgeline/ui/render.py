"""The rendering seam.

`TraceWriter.write` is the single emission point for every event in a run, so a
subclass that overrides it, calls `super()`, and draws is the entire live UI --
`runtime.py`, `fetch.py`, `guard.py` and `netpolicy.py` need no changes at all.
The UI observes the security path; it cannot alter a decision.

Chrome goes to stderr and the answer to stdout, so `bridgeline ... > out.md`
still yields a clean file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.text import Text

from ..trace import (
    KIND_EXTRACT,
    KIND_HTTP,
    KIND_RUN_END,
    KIND_SKIP,
    KIND_STEP,
    TraceRecord,
    TraceWriter,
)
from . import theme

# A netpolicy refusal means one of two very different things. Leaving the plan's
# host space is the defense engaging against something the page named; not being
# in the crawled section is routine frontier filtering. Only the former earns
# the signal colour -- otherwise a normal crawl floods the screen with amber and
# the one moment that matters stops standing out.
_HOSTILE_PREFIXES: tuple[str, ...] = (
    "host ",
    "scheme ",
    "port ",
    "userinfo",
    "unresolvable",
    "url too long",
    "unparseable",
)
_STRUCTURAL_LAYERS = frozenset({"capability_gate", "sink_gate", "contract"})


def is_hostile(layer: str | None, reason: str) -> bool:
    if layer in _STRUCTURAL_LAYERS:
        return True
    if layer == "netpolicy":
        return reason.startswith(_HOSTILE_PREFIXES)
    return False


def _arg_summary(record: TraceRecord) -> str:
    args = record.args or {}
    for key in ("url", "path", "from"):
        value = args.get(key)
        if isinstance(value, str):
            return value
    return ""


class RenderingTraceWriter(TraceWriter):
    def __init__(self, path: Path, run_id: str, console: Console) -> None:
        super().__init__(path, run_id)
        self._c = console
        self._g = theme.glyphs(console.file, plain=not console.is_terminal)
        self.refusals = 0

    # Reasons carry attacker-influenced text (URLs, argument names like
    # ['url']). Building Text explicitly means square brackets can never be
    # read as Rich markup.
    def _line(self, *parts: tuple[str, str], indent: int = 0) -> None:
        text = Text("  " * indent)
        for chunk, style in parts:
            text.append(chunk, style=style)
        self._c.print(text)

    def banner(self, version: str) -> None:
        if self._g.spider_rest:
            self._c.print(Text(self._g.spider_rest, style=theme.CONTENT))
        head = Text()
        head.append("bridgeline", style="bold")
        head.append(f"  {version}", style=theme.MUTED)
        self._c.print(head)
        self.rule()

    def rule(self) -> None:
        self._c.print(Text("─" * 60 if self._g.spider_rest else "-" * 60,
                           style=theme.RULE))

    def refusal(self, layer: str, target: str, reason: str, aside: str = "") -> None:
        """The hero moment: the only amber on screen, beside the braced spider."""
        self.refusals += 1
        self._c.print()
        if self._g.spider_braced:
            spider = self._g.spider_braced.splitlines()
            head = Text("  ")
            head.append(spider[0], style=theme.SIGNAL)
            head.append("   ")
            head.append(f"{self._g.refused} REFUSED", style=theme.SIGNAL)
            head.append(f"   {layer}", style=theme.SIGNAL)
            self._c.print(head)
            rows = [target, reason, aside]
            for body, extra in zip(spider[1:], rows, strict=False):
                line = Text("  ")
                line.append(body, style=theme.SIGNAL)
                line.append("   ")
                line.append(extra, style=theme.CONTENT if extra is target else theme.CHROME)
                self._c.print(line)
        else:
            self._line((f"{self._g.refused} REFUSED  {layer}", theme.SIGNAL))
            self._line((target, theme.CONTENT), indent=1)
            self._line((reason, theme.CHROME), indent=1)
        self._c.print()

    def write(self, kind: str, **kwargs: Any) -> TraceRecord:
        record = super().write(kind, **kwargs)
        try:
            self._render(record)
        except Exception:  # rendering must never break a run
            pass
        return record

    def _render(self, r: TraceRecord) -> None:
        if r.kind == KIND_STEP:
            self._render_step(r)
        elif r.kind in (KIND_HTTP, KIND_SKIP):
            self._render_frontier(r)
        elif r.kind == KIND_EXTRACT:
            self._line(
                (f"{self._g.executed} ", theme.CONTENT),
                (f"{(r.step_index or 0) + 1}  ", theme.MUTED),
                (f"{'extract':<11}", theme.CONTENT),
                (f"schema {r.args.get('schema', '')}", theme.CHROME),
            )
        elif r.kind == KIND_RUN_END:
            self._render_end(r)

    def _render_step(self, r: TraceRecord) -> None:
        tool = r.tool or ""
        if r.outcome == "blocked":
            self.refusal(r.layer or "gate", _arg_summary(r) or tool, r.reason,
                         "the page named this - the plan did not")
            return
        if r.outcome != "started":
            return  # the header was drawn when the step began
        self._line(
            (f"{self._g.executed} ", theme.CONTENT),
            (f"{(r.step_index or 0) + 1}  ", theme.MUTED),
            (f"{tool:<11}", theme.CONTENT),
            (_arg_summary(r), theme.CONTENT),
        )

    def _render_frontier(self, r: TraceRecord) -> None:
        url = str((r.args or {}).get("url", ""))
        if r.outcome == "executed":
            detail = r.detail or {}
            self._line(
                (f"{self._g.executed} ", theme.CHROME),
                (f"{detail.get('status', ''):<5}", theme.CHROME),
                (url, theme.CONTENT),
                (f"  {detail.get('bytes', 0)} B", theme.MUTED),
                indent=2,
            )
            return
        if is_hostile(r.layer, r.reason):
            self.refusal(r.layer or "netpolicy", url, r.reason,
                         "the page named this - the plan did not")
            return
        self._line(
            (f"{self._g.skipped} ", theme.MUTED),
            (f"{'skip':<5}", theme.CHROME),
            (url, theme.CHROME),
            (f"  {r.reason}", theme.MUTED),
            indent=2,
        )

    def _render_end(self, r: TraceRecord) -> None:
        self.rule()
        detail = r.detail or {}
        summary = Text()
        summary.append(f"{detail.get('executed', 0)} executed", style=theme.CHROME)
        if self.refusals:
            summary.append("   ")
            summary.append(f"{self.refusals} refused", style=theme.SIGNAL)
        self._c.print(summary)
        try:
            shown: object = self.path.relative_to(Path.cwd())
        except ValueError:
            shown = Path(*self.path.parts[-4:])
        self._line(("trace  ", theme.CHROME), (str(shown), theme.MUTED))
