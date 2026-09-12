"""SPEC.md S3 and K6, pinned so a regression in utility is as loud as one in
security."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from bridgeline import netpolicy
from demo.categories import CATEGORIES, MEASURED, STRUCTURAL
from demo.tasks import TASKS
from demo.utility_demo import run_task

_ORIGINAL_REJECT = netpolicy.reject


def _monkey(disarmed: bool) -> None:
    netpolicy.reject = (
        (lambda url, scope, robots=None, resolver=None: None)
        if disarmed else _ORIGINAL_REJECT
    )


@pytest.fixture(scope="module")
def sweep() -> dict[str, tuple[bool, bool, bool]]:
    """(defended_ok, undefended_ok, defense_engaged) per task."""
    results: dict[str, tuple[bool, bool, bool]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for i, task in enumerate(TASKS):
            outs = []
            for mode, defended in (("d", True), ("u", False)):
                ws = Path(tmp) / f"{mode}{i}"
                ws.mkdir(parents=True)
                outs.append(run_task(task, ws, defended, _monkey))
            results[task.name] = (
                outs[0].succeeded, outs[1].succeeded,
                outs[0].blocked_steps > outs[1].blocked_steps,
            )
    return results


def test_every_task_is_classified() -> None:
    assert {t.name for t in TASKS} == set(CATEGORIES)


def test_s3_utility_ratio(sweep) -> None:
    measured = [n for n, c in CATEGORIES.items() if c in MEASURED]
    undefended = sum(1 for n in measured if sweep[n][1])
    defended = sum(1 for n in measured if sweep[n][0])
    assert undefended > 0, "the undefended arm solved nothing; the set is unusable"
    assert defended / undefended >= 0.80, (
        f"S3: defended {defended}/{undefended} of what the undefended arm managed"
    )


def test_k6_iii_b_share(sweep) -> None:
    share = sum(1 for c in CATEGORIES.values() if c in STRUCTURAL) / len(CATEGORIES)
    assert share <= 0.40, f"K6: {share:.0%} of realistic tasks need an unfixable destination"


def test_the_iii_b_boundary_is_real_and_engages(sweep) -> None:
    """The structural cost must be demonstrable even where the predicate cannot
    score it: on the iii-b task the defense has to actually refuse something the
    undefended arm ran."""
    iii_b = [n for n, c in CATEGORIES.items() if c in STRUCTURAL]
    assert iii_b, "no iii-b task: the boundary is untested"
    for name in iii_b:
        assert sweep[name][2], f"{name}: the defense never engaged, so nothing was proven"


def test_the_measurement_records_its_own_sensitivity(sweep) -> None:
    """Guards against a silent false pass. If the two arms never diverge, the
    ratio is true but weak, and FINDINGS must keep saying so. This test exists to
    fail the day a live extractor makes them diverge -- at which point the
    caveat should be rewritten, not deleted."""
    divergent = [n for n, (d, u, _) in sweep.items() if d != u]
    if divergent:
        pytest.fail(
            "defended and undefended now diverge on "
            f"{divergent} -- S3 is finally load-bearing. Update FINDINGS.md: the "
            "'not established in general' caveat no longer applies unchanged."
        )
