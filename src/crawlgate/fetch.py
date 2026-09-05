"""Bounded frontier expansion. The only module that opens sockets.

Every destination decision here runs through `netpolicy.reject`, a pure function
of the URL and plan-fixed literals. No page semantics reach it.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urldefrag, urljoin

from . import netpolicy
from .guard import Guard
from .trace import KIND_HTTP, KIND_SKIP, LAYER_CONTRACT, LAYER_NETPOLICY, TraceWriter
from .types import CrawlScope, Page, PageSet

USER_AGENT = "crawlgate/0.1 (+https://example.invalid/crawlgate)"
_MIN_HOST_DELAY_S = 1.0


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status: int
    body: str
    content_type: str
    location: str | None = None


class HttpClient(Protocol):
    def get(self, url: str, timeout_s: float, max_bytes: int) -> HttpResponse: ...


class HttpxClient:
    """Redirects are NEVER followed: a 3xx Location re-enters the frontier and is
    re-checked from scratch. Auto-following is a silent destination-choosing
    primitive, which is exactly what this design exists to remove."""

    def __init__(self) -> None:
        import httpx

        self._client = httpx.Client(
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
            trust_env=False,
        )

    def get(self, url: str, timeout_s: float, max_bytes: int) -> HttpResponse:
        chunks: list[bytes] = []
        size = 0
        # Stream and cap during read: a lying Content-Length must not decide this.
        with self._client.stream("GET", url, timeout=timeout_s) as response:
            for chunk in response.iter_bytes():
                room = max_bytes - size
                if room <= 0:
                    break
                chunks.append(chunk[:room])
                size += len(chunk[:room])
            return HttpResponse(
                url=str(response.url),
                status=response.status_code,
                body=b"".join(chunks).decode("utf-8", "replace"),
                content_type=response.headers.get("content-type", ""),
                location=response.headers.get("location"),
            )


def visible_text(html: str) -> str:
    try:
        from selectolax.parser import HTMLParser
    except ImportError:
        return html
    tree = HTMLParser(html)
    for tag in ("script", "style", "noscript", "template"):
        for node in tree.css(tag):
            node.decompose()
    body = tree.body or tree.root
    return body.text(separator="\n", strip=True) if body is not None else ""


def discover_links(html: str, response_url: str) -> list[str]:
    """`<a href>` only, resolved against the RESPONSE url.

    `<base href>` is ignored entirely -- honouring it would let a page re-root
    every relative link onto a host of its choosing. `<link rel=prefetch>`,
    `<img>`, `<iframe>` and scripts are not walked at all.
    """
    try:
        from selectolax.parser import HTMLParser
    except ImportError:
        return []
    links: list[str] = []
    for node in HTMLParser(html).css("a[href]"):
        if (node.attributes.get("rel") or "").lower().find("nofollow") >= 0:
            continue
        href = (node.attributes.get("href") or "").strip()
        if not href or href.startswith(("#", "javascript:", "data:", "mailto:")):
            continue
        links.append(urldefrag(urljoin(response_url, href))[0])
    return links


def crawl(
    seed: str,
    scope: CrawlScope,
    guard: Guard,
    trace: TraceWriter,
    http: HttpClient,
    resolver: netpolicy.Resolver = netpolicy.real_resolver,
    sleep: Callable[[float], None] = time.sleep,
) -> PageSet:
    robots = netpolicy.RobotsGate(
        fetch_text=lambda url: _robots_body(http, url, scope),
        user_agent=USER_AGENT,
    )
    frontier: deque[tuple[str, int]] = deque([(seed, 0)])
    seen: set[str] = {netpolicy.canonical(seed)}
    pages: list[Page] = []
    skipped: list[tuple[str, str]] = []
    last_request = 0.0

    while frontier and len(pages) < scope.max_pages:
        url, depth = frontier.popleft()

        # (1) Deterministic predicate over the URL and plan-fixed literals only.
        reason = netpolicy.reject(url, scope, robots, resolver)
        if reason is not None:
            skipped.append((url, reason))
            trace.write(KIND_SKIP, outcome="skipped", tool="fetch", args={"url": url},
                        layer=LAYER_NETPOLICY, reason=reason, detail={"depth": depth})
            continue

        # (2) The plan's scope IS the approval authority. Must precede check():
        #     bouncer resolves approvals before taint, and this URL is tainted
        #     because it appeared in page text we already registered.
        guard.vouch_scope("fetch", "url", url)

        # (3) Layer 2 contract check on the real outbound request.
        verdict = guard.check("fetch", {"url": url})
        if not verdict.allowed:
            skipped.append((url, verdict.reason))
            trace.write(KIND_SKIP, outcome="blocked", tool="fetch", args={"url": url},
                        layer=LAYER_CONTRACT, reason=verdict.reason,
                        contract=verdict.contract, verdict=verdict.verdict)
            continue

        elapsed = time.monotonic() - last_request
        if last_request and elapsed < _MIN_HOST_DELAY_S:
            sleep(_MIN_HOST_DELAY_S - elapsed)
        last_request = time.monotonic()

        response = http.get(url, scope.request_timeout_s, scope.max_bytes_per_page)

        if 300 <= response.status < 400 and response.location:
            # A redirect is a frontier CANDIDATE, never a followed hop.
            target = urljoin(url, response.location)
            key = netpolicy.canonical(target)
            if key not in seen and depth < scope.max_depth:
                seen.add(key)
                frontier.append((target, depth + 1))
            skipped.append((url, f"redirect {response.status} not followed"))
            trace.write(KIND_HTTP, outcome="skipped", tool="fetch", args={"url": url},
                        reason="redirect not followed",
                        detail={"status": response.status, "location": response.location})
            continue

        text = visible_text(response.body)
        page = Page(
            url=url,
            status=response.status,
            text=text,
            depth=depth,
            fetched_at=datetime.now(UTC).isoformat(timespec="milliseconds"),
            content_type=response.content_type,
        )
        pages.append(page)
        trace.write(KIND_HTTP, outcome="executed", tool="fetch", args={"url": url},
                    detail={"status": response.status, "bytes": len(response.body),
                            "depth": depth, "content_type": response.content_type})

        # Everything read is untrusted. Feed both the text and each discovered
        # link so Layer 2 has an independent content-level witness later.
        guard.observe_untrusted(text)

        if depth < scope.max_depth:
            for link in discover_links(response.body, url):
                guard.observe_untrusted(link)
                key = netpolicy.canonical(link)
                if key not in seen:
                    seen.add(key)
                    frontier.append((link, depth + 1))

    return PageSet(tuple(pages), truncated=bool(frontier), skipped=tuple(skipped))


def _robots_body(http: HttpClient, url: str, scope: CrawlScope) -> str | None:
    """Unreachable / 5xx / timeout -> None, which RobotsGate treats as Disallow."""
    try:
        response = http.get(url, scope.request_timeout_s, 64 * 1024)
    except Exception:
        return None
    if response.status == 404:
        return ""  # no robots.txt is a genuine "no rules", not a failure
    if response.status != 200:
        return None
    return response.body
