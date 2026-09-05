"""The trusted planner.

`plan()` takes `Trusted` text and the tool catalog. It NEVER takes page content
-- that is the whole point, and the `Trusted` NewType is what makes a violation
a type error rather than a code-review question.
"""

from __future__ import annotations

import re
from typing import Protocol
from urllib.parse import urlsplit

from .types import CrawlScope, Plan, SlotRef, Step, ToolSpec, Trusted

_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_DEPTH = re.compile(r"(\d+)\s*(?:levels?|deep|depth)", re.IGNORECASE)
_WRITE_TO = re.compile(r"(?:write|save|put|store)\b[^.]{0,60}?\b(?:to|into|in)\s+(\S+)", re.I)


class Planner(Protocol):
    def plan(self, instruction: Trusted, tools: dict[str, ToolSpec]) -> Plan: ...


class PlanError(ValueError):
    pass


class DeterministicPlanner:
    """A keyless planner over a small grammar of crawl instructions.

    Deliberately not clever. Its purpose is to make the security suite runnable
    with no API key and no model in the loop, so the R6 claim is measured
    against a plan no model influenced.
    """

    def plan(self, instruction: Trusted, tools: dict[str, ToolSpec]) -> Plan:
        text = str(instruction)
        urls = _URL.findall(text)
        if not urls:
            raise PlanError("no seed url in the instruction")
        seed = urls[0].rstrip(".,;")

        parts = urlsplit(seed)
        host = (parts.hostname or "").lower()
        # The scope prefix is the seed's containing directory: "summarize the
        # notes at /docs/notes" means that section of the site, not that single
        # page -- otherwise depth > 0 could never reach a sibling. It remains a
        # literal fixed by the trusted plan before anything is fetched.
        prefix = (parts.path or "/").rsplit("/", 1)[0] or "/"

        depth_match = _DEPTH.search(text)
        depth = int(depth_match.group(1)) if depth_match else 1

        scheme = parts.scheme.lower()
        port = parts.port or (443 if scheme == "https" else 80)
        loopback = host in ("localhost", "127.0.0.1", "::1")

        scope = CrawlScope(
            allowed_hosts=(host,),
            path_prefix=prefix,
            allowed_schemes=(scheme,),
            allowed_ports=(port,),
            max_depth=min(depth, 3),
            max_pages=10,
            allow_loopback=loopback,
        )

        steps: list[Step] = [
            Step(tool="fetch", args={"url": seed}, scope=scope, out="pages"),
            Step(
                tool="extract",
                args={"from": SlotRef("pages"), "query": text, "schema": "string"},
                out="summary",
            ),
        ]

        write_match = _WRITE_TO.search(text)
        if write_match:
            steps.append(
                Step(
                    tool="write_file",
                    args={"path": write_match.group(1).rstrip(".,;"),
                          "content": SlotRef("summary")},
                )
            )
        steps.append(Step(tool="report", args={"summary": SlotRef("summary")}))

        return Plan(
            steps=tuple(steps),
            rationale="deterministic: scope-confined crawl, one typed extraction, fixed sinks",
        )
