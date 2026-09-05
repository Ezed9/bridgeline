"""Layer 2: the contract seam onto mcp-bouncer.

bouncer is consumed UNMODIFIED through its public library API. In particular we
construct and RETAIN the `schemas` dict: `ContractEngine.__init__` stores the
caller's dict by reference, so pinning needs no private attribute access.
(bouncer's own AgentDojo driver poked `engine._schemas` only because it passed
an inline `{}` and threw the reference away.)

Layer 2 is defense in depth and an independent witness. It is never the proof --
`tests/test_layer1_alone.py` runs the whole acceptance suite with NullGuard.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from bouncer.approvals import ApprovalStore, approval_key
from bouncer.audit import AuditLog
from bouncer.engine import ContractEngine
from bouncer.policy import PolicyResolver
from bouncer.taint import TaintTracker
from bouncer.types import Decision, ToolCall, ToolPolicy, Verdict

from . import netpolicy
from .trace import LAYER_CONTRACT, TraceWriter
from .types import Plan, ToolSpec

APPROVE_NEVER = "never"
APPROVE_SCOPE = "scope"
APPROVE_ASK = "ask"


@dataclass(frozen=True)
class GuardVerdict:
    allowed: bool
    verdict: str
    reason: str
    contract: str


_ALLOWED = GuardVerdict(True, "allow", "", "default")


class Guard(Protocol):
    def check(self, tool: str, args: dict[str, object]) -> GuardVerdict: ...
    def vouch_scope(self, tool: str, param: str, value: str) -> None: ...
    def observe_untrusted(self, text: str) -> None: ...


class NullGuard:
    """Layer 2 disabled. Used to prove Layer 1 is independently sufficient."""

    def check(self, tool: str, args: dict[str, object]) -> GuardVerdict:
        return _ALLOWED

    def vouch_scope(self, tool: str, param: str, value: str) -> None:
        return None

    def observe_untrusted(self, text: str) -> None:
        return None


def build_policies(plan: Plan, workspace: Path) -> dict[str, ToolPolicy]:
    """Tool policies derived from TRUSTED plan literals only."""
    return {
        "fetch": ToolPolicy(
            name="fetch",
            exfiltrating=True,
            sink_params=("url",),
            arg_patterns=(("url", netpolicy.scope_regex(plan)),),
            max_calls=netpolicy.total_page_budget(plan),
        ),
        "write_file": ToolPolicy(
            name="write_file",
            write_params=("path",),
            allowed_path_prefixes=(str(workspace.resolve()),),
        ),
        "report": ToolPolicy(name="report"),
    }


class BouncerGuard:
    def __init__(
        self,
        engine: ContractEngine,
        schemas: dict[str, dict[str, object]],
        approve: str,
        trace: TraceWriter,
    ) -> None:
        self._engine = engine
        self._schemas = schemas
        self._approve = approve
        self._trace = trace

    def check(self, tool: str, args: dict[str, object]) -> GuardVerdict:
        # Belt and braces. PolicyResolver(use_heuristics=False) returns a fully
        # PERMISSIVE ToolPolicy for an unknown tool; that is safe today only
        # because the engine's pinning check ASKs first. Two independent things
        # now have to fail before an unpinned tool gets through.
        if tool not in self._schemas:
            return self._record(tool, GuardVerdict(False, "deny", "tool not pinned", "pinning"))

        decision: Decision = self._engine.evaluate(ToolCall(tool=tool, args=args))
        if decision.verdict is Verdict.ALLOW:
            return GuardVerdict(True, "allow", "", decision.contract)
        if decision.verdict is Verdict.DENY:
            return self._record(
                tool, GuardVerdict(False, "deny", decision.reason, decision.contract)
            )
        return self._record(tool, self._resolve_ask(tool, args, decision))

    def _resolve_ask(
        self, tool: str, args: dict[str, object], decision: Decision
    ) -> GuardVerdict:
        # A pinning ASK carries no ask_key. A human cannot vouch for "this tool
        # was never pinned", so it is always DENY.
        if decision.ask_key is None:
            return GuardVerdict(False, "deny", decision.reason, decision.contract)

        if self._approve == APPROVE_NEVER:
            return GuardVerdict(
                False, "deny", f"{decision.reason} (ask -> deny)", decision.contract
            )

        if self._approve == APPROVE_SCOPE:
            # fetch.url should already be vouched by the plan-fixed scope. An ASK
            # arriving here means the vouching path has a hole -- that is Layer 2
            # catching something Layer 1 missed, and it must be loud.
            return GuardVerdict(
                False, "deny", f"{decision.reason} (unvouched under --approve scope)",
                decision.contract,
            )

        if not sys.stdin.isatty():
            return GuardVerdict(
                False, "deny", "interactive approval needs a tty", decision.contract
            )
        prompt = f"[crawlgate] {tool}: {decision.reason}\nApprove? [y/N] "
        if input(prompt).strip().lower() not in ("y", "yes"):
            return GuardVerdict(False, "deny", "declined by operator", decision.contract)
        self._engine.on_approved(decision.ask_key)
        again = self._engine.evaluate(ToolCall(tool=tool, args=args), count_budget=False)
        if again.verdict is Verdict.ALLOW:
            return GuardVerdict(True, "allow", "", again.contract)
        return GuardVerdict(False, "deny", again.reason, again.contract)

    def _record(self, tool: str, verdict: GuardVerdict) -> GuardVerdict:
        self._trace.write(
            "guard",
            outcome="blocked",
            tool=tool,
            layer=LAYER_CONTRACT,
            reason=verdict.reason,
            contract=verdict.contract,
            verdict=verdict.verdict,
        )
        return verdict

    def vouch_scope(self, tool: str, param: str, value: str) -> None:
        """Record the plan-fixed scope as the approval authority for this URL.

        bouncer's `_trust_of` checks trusted_destinations, then approvals, then
        taint -- approvals beat taint. That ordering is what makes a crawl
        possible at all: a discovered URL appears verbatim in the page text we
        already fed to register_output, so it is TAINTED, and without this vouch
        every in-scope link would be denied.

        The authority here is NOT a human. It is `netpolicy.reject`, a pure
        function of the URL and plan-fixed literals. This is only ever called
        after that predicate has returned None.
        """
        self._engine.on_approved(approval_key(tool, param, value))

    def observe_untrusted(self, text: str) -> None:
        self._engine.register_output(text)


def build(
    plan: Plan,
    workspace: Path,
    tools: dict[str, ToolSpec],
    approve: str,
    trace: TraceWriter,
    audit_path: Path,
) -> BouncerGuard:
    # We own this dict; the engine holds it by reference. No private access.
    schemas: dict[str, dict[str, object]] = {
        name: {"properties": {p: {} for p in spec.params}} for name, spec in tools.items()
    }
    engine = ContractEngine(
        resolver=PolicyResolver(overrides=build_policies(plan, workspace), use_heuristics=False),
        taint=TaintTracker(),
        # In-memory: a scope vouch must never persist across runs.
        approvals=ApprovalStore(),
        audit=AuditLog(audit_path),
        schemas=schemas,
    )
    return BouncerGuard(engine, schemas, approve, trace)
