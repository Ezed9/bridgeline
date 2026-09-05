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

import os
from dataclasses import dataclass

from .extractor import AdversarialExtractor, EchoExtractor, Extractor
from .planner import DeterministicPlanner, Planner

PROFILE_NONE = "none"
PROFILE_ADVERSARIAL = "adversarial"
PROFILE_ANTHROPIC = "anthropic"
PROFILE_GEMINI = "gemini"

_ANTHROPIC_MODEL = "claude-sonnet-5"
_GEMINI_MODEL = "gemini-2.5-flash"


@dataclass(frozen=True)
class Tiers:
    planner_profile: str
    extractor_profile: str
    note: str

    def planner(self) -> Planner:
        if self.planner_profile == PROFILE_ANTHROPIC:
            from .providers import AnthropicPlanner

            return AnthropicPlanner(_ANTHROPIC_MODEL)
        if self.planner_profile == PROFILE_GEMINI:
            from .providers import GeminiPlanner

            return GeminiPlanner(_GEMINI_MODEL)
        return DeterministicPlanner()

    def extractor(self) -> Extractor:
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

    has_anthropic = bool(env.get("ANTHROPIC_API_KEY"))
    has_gemini = bool(env.get("GOOGLE_API_KEY") or env.get("GEMINI_API_KEY"))

    if has_anthropic and has_gemini:
        # Distinct providers across the boundary: a jailbreak that works on the
        # extractor's model does not automatically transfer to the planner's.
        return Tiers(PROFILE_ANTHROPIC, PROFILE_GEMINI, "two providers, split by authority")
    if has_anthropic:
        return Tiers(PROFILE_ANTHROPIC, PROFILE_ANTHROPIC, "one provider, separate contexts")
    if has_gemini:
        return Tiers(PROFILE_GEMINI, PROFILE_GEMINI, "one provider, separate contexts")
    return Tiers(PROFILE_NONE, PROFILE_NONE, "no keys: deterministic stubs, zero network")


def security_tiers() -> Tiers:
    """The R6 configuration: a plan no model influenced, and a hijacked extractor."""
    return Tiers(PROFILE_NONE, PROFILE_ADVERSARIAL, "R6: deterministic plan, hijacked extractor")


def from_env(override: str | None = None) -> Tiers:
    return resolve(dict(os.environ), override)
