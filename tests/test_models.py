"""Provider resolution.

A key is not a usable provider. Selecting a profile whose SDK is absent raises
an ImportError halfway through a run -- after the plan is committed, which is the
worst possible moment to find out.
"""

from __future__ import annotations

import pytest

from crawlgate import models


def test_no_keys_gives_stubs_and_no_model_calls() -> None:
    tiers = models.resolve({})
    assert tiers.planner_profile == models.PROFILE_NONE
    assert tiers.extractor_profile == models.PROFILE_NONE
    assert "zero model calls" in tiers.note


def test_a_key_without_its_sdk_is_not_selected(monkeypatch) -> None:
    monkeypatch.setattr(models, "sdk_installed", lambda p: p != models.PROFILE_ANTHROPIC)
    tiers = models.resolve({"ANTHROPIC_API_KEY": "x"})
    assert tiers.planner_profile == models.PROFILE_NONE


def test_a_stranded_key_is_announced_never_silently_ignored(monkeypatch) -> None:
    monkeypatch.setattr(models, "sdk_installed", lambda p: p != models.PROFILE_ANTHROPIC)
    note = models.resolve({"ANTHROPIC_API_KEY": "x", "GOOGLE_API_KEY": "y"}).note
    assert "SDK missing" in note and "uv sync --extra anthropic" in note


def test_the_usable_provider_wins_when_another_key_is_stranded(monkeypatch) -> None:
    monkeypatch.setattr(models, "sdk_installed", lambda p: p != models.PROFILE_ANTHROPIC)
    tiers = models.resolve({"ANTHROPIC_API_KEY": "x", "GOOGLE_API_KEY": "y"})
    assert tiers.planner_profile == models.PROFILE_GEMINI
    assert tiers.extractor_profile == models.PROFILE_GEMINI


def test_two_usable_providers_split_by_authority(monkeypatch) -> None:
    monkeypatch.setattr(models, "sdk_installed", lambda p: True)
    tiers = models.resolve({"ANTHROPIC_API_KEY": "x", "GOOGLE_API_KEY": "y"})
    assert tiers.planner_profile == models.PROFILE_ANTHROPIC
    assert tiers.extractor_profile == models.PROFILE_GEMINI
    assert "split by authority" in tiers.note


def test_an_override_naming_an_uninstalled_sdk_fails_with_the_fix(monkeypatch) -> None:
    """--models anthropic bypasses resolution, so the guard has to sit on the
    constructor too -- and say how to fix it."""
    monkeypatch.setattr(models, "sdk_installed", lambda p: p != models.PROFILE_ANTHROPIC)
    tiers = models.resolve({}, override="anthropic")
    with pytest.raises(RuntimeError, match="uv sync --extra anthropic"):
        tiers.planner()


def test_the_security_configuration_needs_no_sdk_at_all() -> None:
    tiers = models.security_tiers()
    assert tiers.planner_profile == models.PROFILE_NONE
    assert tiers.extractor_profile == models.PROFILE_ADVERSARIAL
    tiers.planner()
    tiers.extractor()
