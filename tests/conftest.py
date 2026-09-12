"""Test fixtures.

The recording client is the load-bearing assertion device: it records every URL
the harness *attempts*, at the point of the outbound request. A DENY that still
reached here would be recorded, so "flagging is not blocking" is enforced by
construction rather than by reading a log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from bridgeline.fetch import HttpResponse
from bridgeline.guard import NullGuard, build
from bridgeline.tools import build_tools
from bridgeline.trace import TraceWriter
from bridgeline.types import CrawlScope

GOOD_HOST = "docs.example.test"
EVIL_HOST = "attacker.test"


@dataclass
class RecordingHttp:
    """Serves canned pages and records every attempted request."""

    pages: dict[str, tuple[int, str, dict[str, str]]] = field(default_factory=dict)
    attempted: list[str] = field(default_factory=list)

    def add(self, url: str, body: str, status: int = 200,
            headers: dict[str, str] | None = None) -> None:
        self.pages[url] = (status, body, headers or {})

    def get(self, url: str, timeout_s: float, max_bytes: int) -> HttpResponse:
        self.attempted.append(url)
        status, body, headers = self.pages.get(url, (404, "", {}))
        return HttpResponse(
            url=url,
            status=status,
            body=body[:max_bytes],
            content_type=headers.get("content-type", "text/html"),
            location=headers.get("location"),
        )

    def hosts_touched(self) -> set[str]:
        return {urlsplit(u).hostname or "" for u in self.attempted}

    def touched(self, host: str) -> bool:
        return host in self.hosts_touched()


@dataclass
class RecordingFs:
    """Wraps the write_file impl and records every path actually written."""

    written: list[Path] = field(default_factory=list)


def fake_resolver(host: str, port: int) -> list[str]:
    """Resolve EVERY host to a globally-routable address.

    Deliberately permissive: it makes the tests strictly harder. Nothing is ever
    refused for a DNS or SSRF reason, so the only thing that can refuse the
    attacker's host is the plan-fixed scope predicate -- which is the property
    under test. A stricter resolver would let the suite pass for the wrong
    reason. The SSRF checks are exercised separately in test_netpolicy.py.
    """
    return ["93.184.216.34"]


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "work"
    ws.mkdir()
    return ws


@pytest.fixture
def trace(tmp_path: Path) -> TraceWriter:
    return TraceWriter(tmp_path / "trace.jsonl", "testrun")


@pytest.fixture
def tools(workspace: Path):
    return build_tools(workspace)


@pytest.fixture
def http() -> RecordingHttp:
    client = RecordingHttp()
    # robots.txt: permissive for both hosts, so robots is never what saves us.
    client.add(f"https://{GOOD_HOST}/robots.txt", "User-agent: *\nAllow: /\n")
    client.add(f"https://{EVIL_HOST}/robots.txt", "User-agent: *\nAllow: /\n")
    return client


def make_guard(plan, workspace: Path, tools, trace: TraceWriter, approve: str = "never"):
    return build(plan, workspace, tools, approve, trace, workspace / "audit.jsonl")


def null_guard() -> NullGuard:
    return NullGuard()


def good_scope(**overrides) -> CrawlScope:
    base = {
        "allowed_hosts": (GOOD_HOST,),
        "path_prefix": "/docs",
        "allowed_schemes": ("https",),
        "allowed_ports": (443,),
        "max_depth": 2,
        "max_pages": 8,
    }
    base.update(overrides)
    return CrawlScope(**base)


def run_plan(plan, tools, workspace: Path, trace: TraceWriter, http: RecordingHttp,
             extractor=None, guard=None, approve: str = "never"):
    """Execute a plan with the recording client and the fake resolver."""
    from bridgeline.extractor import AdversarialExtractor
    from bridgeline.runtime import execute

    return execute(
        plan,
        tools,
        extractor or AdversarialExtractor(),
        guard if guard is not None else make_guard(plan, workspace, tools, trace, approve),
        trace,
        http,
        resolver=fake_resolver,
        sleep=lambda _: None,   # the politeness delay is real; tests need not pay it
    )
