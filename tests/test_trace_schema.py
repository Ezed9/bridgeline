"""The trace must not drift from its dataclass.

The prior harness had fields on the dataclass that never appeared on disk. These
tests make that a red build rather than a discovery six months later.
"""

from __future__ import annotations

import json
from datetime import datetime

from conftest import GOOD_HOST, good_scope, run_plan

from crawlgate.trace import EXPECTED_KEYS, TRACE_VERSION
from crawlgate.types import Plan, SlotRef, Step


def _lines(trace) -> list[dict]:
    return [json.loads(line) for line in trace.path.read_text().splitlines()]


def _run(tools, workspace, trace, http):
    http.add(f"https://{GOOD_HOST}/docs/n", "<h1>Notes</h1><p>v2 adds caching.</p>")
    plan = Plan(steps=(
        Step(tool="fetch", args={"url": f"https://{GOOD_HOST}/docs/n"},
             scope=good_scope(max_depth=0), out="pages"),
        Step(tool="extract",
             args={"from": SlotRef("pages"), "query": "summary", "schema": "string"}, out="s"),
        Step(tool="write_file", args={"path": "s.md", "content": SlotRef("s")}),
        Step(tool="report", args={"summary": SlotRef("s")}),
    ))
    run_plan(plan, tools, workspace, trace, http)
    return _lines(trace)


def test_every_line_has_exactly_the_dataclass_fields(tools, workspace, trace, http) -> None:
    lines = _run(tools, workspace, trace, http)
    assert lines
    for line in lines:
        assert set(line) == EXPECTED_KEYS, f"schema drift: {set(line) ^ EXPECTED_KEYS}"


def test_the_version_is_pinned(tools, workspace, trace, http) -> None:
    # Add a field without bumping TRACE_VERSION and this goes red.
    assert TRACE_VERSION == 1
    assert len(EXPECTED_KEYS) == 14
    for line in _run(tools, workspace, trace, http):
        assert line["trace_version"] == TRACE_VERSION


def test_timestamps_are_present_parseable_and_monotonic(tools, workspace, trace, http) -> None:
    lines = _run(tools, workspace, trace, http)
    stamps = [datetime.fromisoformat(line["ts"]) for line in lines]
    assert stamps == sorted(stamps)
    assert [line["seq"] for line in lines] == list(range(len(lines)))


def test_long_tainted_values_are_redacted_not_written_verbatim(
    tools, workspace, trace, http
) -> None:
    secret = "CANARY" + "x" * 400
    http.add(f"https://{GOOD_HOST}/docs/n", f"<p>{secret}</p>")
    plan = Plan(steps=(
        Step(tool="fetch", args={"url": f"https://{GOOD_HOST}/docs/n"},
             scope=good_scope(max_depth=0), out="pages"),
        Step(tool="extract",
             args={"from": SlotRef("pages"), "query": "all", "schema": "string"}, out="s"),
        Step(tool="write_file", args={"path": "s.md", "content": SlotRef("s")}),
    ))
    run_plan(plan, tools, workspace, trace, http)
    raw = trace.path.read_text()
    assert secret not in raw, "a large tainted value was written to the trace verbatim"
    assert "$tainted" in raw


def test_reasons_are_defanged(tools, workspace, trace, http) -> None:
    """A trace is opened by humans in log viewers that auto-fetch URLs."""
    from crawlgate.trace import KIND_SKIP

    trace.write(KIND_SKIP, reason="blocked https://attacker.test/p?d=secret")
    line = _lines(trace)[-1]
    assert "https://" not in line["reason"]
    assert "https[:]//" in line["reason"]


def test_contract_records_join_to_the_bouncer_audit_log(tools, workspace, trace, http) -> None:
    """Cross-file integrity: bouncer's audit and our trace must agree."""
    http.add(f"https://{GOOD_HOST}/docs/n", "<p>x</p>")
    plan = Plan(steps=(
        Step(tool="fetch", args={"url": f"https://{GOOD_HOST}/docs/n"},
             scope=good_scope(max_depth=0), out="pages"),
        Step(tool="write_file", args={"path": "/etc/pwned.md", "content": "x"}),
    ))
    run_plan(plan, tools, workspace, trace, http)

    contract_records = [line for line in _lines(trace) if line["layer"] == "contract"]
    assert contract_records, "no contract decision was traced"

    audit = [json.loads(line) for line in (workspace / "audit.jsonl").read_text().splitlines()]
    for record in contract_records:
        assert any(
            entry["tool"] == record["tool"] and entry["verdict"] == record["verdict"]
            for entry in audit
        ), f"trace record has no matching audit line: {record}"
