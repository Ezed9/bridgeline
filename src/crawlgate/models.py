"""Two-tier model resolution, split by AUTHORITY.

The planner and the extractor sit on opposite sides of the trust boundary:

  planner   sees ONLY the trusted instruction. Never page content.
  extractor sees ONLY page content. Never the instruction, never a tool name.

They are therefore resolved as SEPARATE profiles with separate clients and
separate contexts. That is what "multi-model" means here -- it is motivated by
the authority boundary, not by routing for its own sake. Nothing is shared
between them but the typed slot value that crosses under `schema.validate`.

The ladder degrades honestly:
  two keys -> two providers
  one key  -> both roles on one provider, still separate clients/contexts
  no keys  -> deterministic stubs, zero network. This is the R6 configuration
              and the ONLY one the security suite ever runs in.
"""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass

from .extractor import AdversarialExtractor, EchoExtractor, Extractor
from .planner import DeterministicPlanner, Planner


class ProviderError(RuntimeError):
    """A model call failed. Raised at the provider boundary so the CLI can say
    something useful instead of unwinding a stack through three SDKs."""


PROFILE_NONE = "none"
PROFILE_ADVERSARIAL = "adversarial"
PROFILE_ANTHROPIC = "anthropic"
PROFILE_GEMINI = "gemini"

_ANTHROPIC_MODEL = "claude-sonnet-5"
_GEMINI_MODEL = "gemini-2.5-flash"

# A key is not a usable provider. Selecting a profile whose SDK is absent
# produces an ImportError halfway through a run, which is the worst possible
# place to discover it.
_SDK: dict[str, str] = {
    PROFILE_ANTHROPIC: "anthropic",
    PROFILE_GEMINI: "google.genai",
}
_INSTALL_HINT: dict[str, str] = {
    PROFILE_ANTHROPIC: "uv sync --extra anthropic",
    PROFILE_GEMINI: "uv sync --extra gemini",
}


def sdk_installed(profile: str) -> bool:
    module = _SDK.get(profile)
    if module is None:
        return True
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _require_sdk(profile: str) -> None:
    if not sdk_installed(profile):
        raise RuntimeError(
            f"the {profile!r} profile needs its SDK: {_INSTALL_HINT[profile]}"
        )


@dataclass(frozen=True)
class Tiers:
    planner_profile: str
    extractor_profile: str
    note: str

    def planner(self) -> Planner:
        _require_sdk(self.planner_profile)
        if self.planner_profile == PROFILE_ANTHROPIC:
            from .providers import AnthropicPlanner

            return AnthropicPlanner(_ANTHROPIC_MODEL)
        if self.planner_profile == PROFILE_GEMINI:
            from .providers import GeminiPlanner

            return GeminiPlanner(_GEMINI_MODEL)
        return DeterministicPlanner()

    def extractor(self) -> Extractor:
        _require_sdk(self.extractor_profile)
        if self.extractor_profile == PROFILE_ADVERSARIAL:
            return AdversarialExtractor()
        if self.extractor_profile == PROFILE_ANTHROPIC:
            from .providers import AnthropicExtractor

            return AnthropicExtractor(_ANTHROPIC_MODEL)
        if self.extractor_profile == PROFILE_GEMINI:
            from .providers import GeminiExtractor

            return GeminiExtractor(_GEMINI_MODEL)
        return EchoExtractor()


def resolve(env: dict[str, str], override: str | None = None) -> Tiers:
    """`override` is `<planner>:<extractor>`, or a single profile for both."""
    if override:
        planner, _, extractor = override.partition(":")
        return Tiers(planner, extractor or planner, f"explicit: {override}")

    keyed = {
        PROFILE_ANTHROPIC: bool(env.get("ANTHROPIC_API_KEY")),
        PROFILE_GEMINI: bool(env.get("GOOGLE_API_KEY") or env.get("GEMINI_API_KEY")),
    }
    # A key whose SDK is absent is announced, never silently ignored -- someone
    # who exported a key deserves to know why it is not being used.
    stranded = [p for p, has_key in keyed.items() if has_key and not sdk_installed(p)]
    usable = [p for p, has_key in keyed.items() if has_key and sdk_installed(p)]
    notes = [f"{p} key set but SDK missing: {_INSTALL_HINT[p]}" for p in stranded]
    aside = "  (" + "; ".join(notes) + ")" if notes else ""

    if PROFILE_ANTHROPIC in usable and PROFILE_GEMINI in usable:
        # Distinct providers across the boundary: a jailbreak that works on the
        # extractor's model does not automatically transfer to the planner's.
        return Tiers(PROFILE_ANTHROPIC, PROFILE_GEMINI,
                     "two providers, split by authority" + aside)
    if usable:
        only = usable[0]
        return Tiers(only, only, f"{only}, separate contexts" + aside)
    return Tiers(PROFILE_NONE, PROFILE_NONE,
                 "no usable provider: deterministic stubs, zero model calls" + aside)


def security_tiers() -> Tiers:
    """The R6 configuration: a plan no model influenced, and a hijacked extractor."""
    return Tiers(PROFILE_NONE, PROFILE_ADVERSARIAL, "R6: deterministic plan, hijacked extractor")


def from_env(override: str | None = None) -> Tiers:
    return resolve(dict(os.environ), override)
