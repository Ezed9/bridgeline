"""Layer 2: the bouncer contract seam, and the reconciliation of two taint models."""

from __future__ import annotations

import ast
from pathlib import Path

from conftest import EVIL_HOST, GOOD_HOST, good_scope, make_guard, run_plan

from bridgeline.guard import build_policies
from bridgeline.types import Plan, Step

SRC = Path(__file__).resolve().parents[1] / "src"


def _plan() -> Plan:
    return Plan(steps=(
        Step(tool="fetch", args={"url": f"https://{GOOD_HOST}/docs/n"},
             scope=good_scope(), out="pages"),
    ))


def test_bouncer_is_never_touched_privately() -> None:
    """S5: bouncer stays an unmodified external dependency.

    Checked on the AST, not by grep, so a comment discussing private access
    cannot fail it and a string cannot hide one.
    """
    offending: list[str] = []
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute) or not node.attr.startswith("_"):
                continue
            if node.attr.startswith("__") and node.attr.endswith("__"):
                continue  # dunders are public API
            # `self._x` is our own state. Anything else reaching for a private
            # attribute is reaching into someone else's object.
            target = node.value
            if isinstance(target, ast.Name) and target.id == "self":
                continue
            offending.append(f"{path.name}:{node.lineno} .{node.attr}")
    assert offending == [], f"private attribute access outside self: {offending}"


def test_policies_are_derived_from_trusted_plan_literals_only(workspace) -> None:
    policies = build_policies(_plan(), workspace)
    assert policies["fetch"].exfiltrating is True
    assert policies["fetch"].sink_params == ("url",)
    assert policies["fetch"].max_calls == 8
    assert policies["write_file"].allowed_path_prefixes == (str(workspace.resolve()),)


def test_an_unpinned_tool_is_denied_not_asked(tools, workspace, trace) -> None:
    guard = make_guard(_plan(), workspace, tools, trace)
    verdict = guard.check("spawn_shell", {"cmd": "id"})
    assert not verdict.allowed and verdict.verdict == "deny"
    assert verdict.contract == "pinning"


def test_ask_degrades_to_deny_when_no_one_can_be_asked(tools, workspace, trace) -> None:
    guard = make_guard(_plan(), workspace, tools, trace, approve="never")
    # An unvouched, untainted destination is UNPROVEN -> ASK -> our DENY.
    verdict = guard.check("fetch", {"url": f"https://{GOOD_HOST}/docs/never-vouched"})
    assert not verdict.allowed
    assert "ask -> deny" in verdict.reason or verdict.contract in ("sink_gate", "constraint")


def test_an_out_of_scope_url_is_denied_by_the_arg_pattern_constraint(
    tools, workspace, trace
) -> None:
    """Layer 2's independent witness over frontier URLs, which Layer 1 cannot see:
    they never appear as a Step argument."""
    guard = make_guard(_plan(), workspace, tools, trace)
    guard.vouch_scope("fetch", "url", f"https://{EVIL_HOST}/collect")  # even if vouched
    verdict = guard.check("fetch", {"url": f"https://{EVIL_HOST}/collect"})
    assert not verdict.allowed
    assert verdict.contract == "constraint"


def test_vouching_must_precede_checking(tools, workspace, trace) -> None:
    """bouncer resolves approvals before taint. A discovered URL is tainted --
    it appeared in the page text we registered -- so without the vouch every
    in-scope link would be denied, and the crawl could not proceed at all."""
    guard = make_guard(_plan(), workspace, tools, trace)
    url = f"https://{GOOD_HOST}/docs/child"
    guard.observe_untrusted(f"<a href='{url}'>child</a>")

    unvouched = guard.check("fetch", {"url": url})
    assert not unvouched.allowed, "a tainted in-scope url should not pass unvouched"

    guard.vouch_scope("fetch", "url", url)
    assert guard.check("fetch", {"url": url}).allowed


def test_the_page_budget_is_an_independent_hard_cap(tools, workspace, trace) -> None:
    plan = Plan(steps=(
        Step(tool="fetch", args={"url": f"https://{GOOD_HOST}/docs/n"},
             scope=good_scope(max_pages=2), out="pages"),
    ))
    guard = make_guard(plan, workspace, tools, trace)
    urls = [f"https://{GOOD_HOST}/docs/{i}" for i in range(4)]
    verdicts = []
    for url in urls:
        guard.vouch_scope("fetch", "url", url)
        verdicts.append(guard.check("fetch", {"url": url}))
    assert [v.allowed for v in verdicts] == [True, True, False, False]
    assert verdicts[2].contract == "budget"


def test_write_outside_the_workspace_is_denied_by_the_path_prefix(
    tools, workspace, trace
) -> None:
    guard = make_guard(_plan(), workspace, tools, trace)
    verdict = guard.check("write_file", {"path": "/etc/pwned.md", "content": "x"})
    assert not verdict.allowed and verdict.contract == "constraint"


def test_the_audit_log_records_every_contract_decision(tools, workspace, trace) -> None:
    guard = make_guard(_plan(), workspace, tools, trace)
    guard.check("write_file", {"path": "/etc/pwned.md", "content": "x"})
    audit = (workspace / "audit.jsonl").read_text().splitlines()
    assert audit, "bouncer wrote no audit line"
    assert '"verdict": "deny"' in audit[-1]


def test_layer_two_alone_catches_a_deliberately_broken_scope_regex(
    tools, workspace, trace, http, monkeypatch
) -> None:
    """The inverse of test_layer1_alone: if Layer 1's scope predicate had a hole,
    Layer 2 would still refuse the request."""
    from bridgeline import netpolicy

    monkeypatch.setattr(netpolicy, "reject", lambda url, scope, robots=None, resolver=None: None)
    http.add(f"https://{GOOD_HOST}/docs/n",
             f"<a href='https://{EVIL_HOST}/collect'>x</a>")
    run_plan(_plan(), tools, workspace, trace, http)
    assert not http.touched(EVIL_HOST)
