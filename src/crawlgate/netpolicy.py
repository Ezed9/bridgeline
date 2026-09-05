"""Deterministic predicates over URLs and the plan-fixed CrawlScope.

Nothing in this module consults page semantics, model output, or a Tainted
value. `reject` is a pure function of the URL string, plan-fixed literals, and
an injected DNS resolver. That is what makes scope membership decidable without
trusting anything the crawl read.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

from .types import CrawlScope, Plan

# (host, port) -> list of resolved address strings. Injected so tests need no
# network and so the demo can pin loopback.
Resolver = Callable[[str, int], list[str]]

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Named explicitly so a refactor of the generic checks cannot silently drop them.
_BLOCKED_HOST_SUFFIXES = (".local", ".internal", ".localhost")
_BLOCKED_HOST_NAMES = frozenset({
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
})
_IMDS_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})

_SCHEME_IN_TEXT = re.compile(r"\b(https?|ftp|file|data|gopher|javascript)://", re.IGNORECASE)


def real_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


def defang(text: str) -> str:
    """Neutralise auto-fetching renderers (the EchoLeak shape).

    Deterministic rewrite of `scheme://` to `scheme[:]//`. Applied to tainted
    text before it reaches a terminal, a report, or a trace `reason` field.
    """
    return _SCHEME_IN_TEXT.sub(lambda m: f"{m.group(1)}[:]//", text)


def _idna(host: str) -> str | None:
    """Lowercase + IDNA-encode. Returns None for anything unencodable.

    This is what makes a Cyrillic-homoglyph host compare unequal to its ASCII
    lookalike instead of equal to it.
    """
    host = host.strip().rstrip(".").lower()
    if not host:
        return None
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        # Already-ASCII hosts with underscores etc. fail IDNA; accept pure ASCII.
        return host if host.isascii() else None


def _port_of(scheme: str, split_port: int | None) -> int | None:
    if split_port is not None:
        return split_port
    return _DEFAULT_PORTS.get(scheme)


def _is_forbidden_address(addr: str, allow_loopback: bool) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # unparseable -> fail closed

    if str(ip) in _IMDS_ADDRESSES:
        return True

    # IPv4-mapped IPv6 (::ffff:127.0.0.1) must be judged on the mapped address.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
        if str(ip) in _IMDS_ADDRESSES:
            return True

    if ip.is_loopback:
        return not allow_loopback

    # `is_global` is the primary test because the named predicates have gaps:
    # Python 3.12 reports is_private=False for 100.64.0.0/10 (RFC 6598 CGNAT),
    # so an is_private-based check would accept a carrier-NAT address. Anything
    # not globally routable is refused.
    if not ip.is_global:
        return True

    # Kept as belt-and-braces so a future refactor of the above cannot silently
    # re-open the ranges that matter most.
    return bool(
        ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def canonical(url: str) -> str:
    """Stable key for frontier dedupe. Drops the fragment, normalises the host."""
    parts = urlsplit(url)
    host = _idna(parts.hostname or "") or (parts.hostname or "")
    port = _port_of(parts.scheme.lower(), parts.port)
    netloc = host if port in (None, _DEFAULT_PORTS.get(parts.scheme.lower())) else f"{host}:{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def scope_host_ok(url: str, scope: CrawlScope) -> bool:
    parts = urlsplit(url)
    host = _idna(parts.hostname or "")
    if host is None:
        return False
    allowed = {_idna(h) for h in scope.allowed_hosts}
    return host in allowed


def reject(
    url: str,
    scope: CrawlScope,
    robots: RobotsGate | None = None,
    resolver: Resolver = real_resolver,
) -> str | None:
    """Return a rejection reason, or None if the URL is inside the plan-fixed space.

    Order matters: cheap syntactic checks first, DNS last, so an out-of-scope
    URL never causes a lookup.
    """
    if len(url) > 2048:
        return "url too long"

    try:
        parts = urlsplit(url)
    except ValueError:
        return "unparseable url"

    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        return f"scheme {scheme or '<none>'!r} not in {{http, https}}"
    if scheme not in scope.allowed_schemes:
        return f"scheme {scheme!r} not in plan scope"

    # http://docs.example.com@127.0.0.1/ -- the authority is 127.0.0.1.
    if parts.username is not None or parts.password is not None or "@" in (parts.netloc or ""):
        return "userinfo in authority"

    try:
        raw_port = parts.port
    except ValueError:
        return "invalid port"

    host = _idna(parts.hostname or "")
    if host is None:
        return "unresolvable or non-encodable host"
    if host in _BLOCKED_HOST_NAMES or host.endswith(_BLOCKED_HOST_SUFFIXES):
        if not scope.allow_loopback:
            return f"host {host!r} is a reserved local name"

    # Host before port: both refuse, but the reason should name the real
    # problem, and an operator reading the trace needs to see "wrong host".
    allowed = {_idna(h) for h in scope.allowed_hosts}
    if host not in allowed:
        return f"host {host!r} not in plan scope"

    port = _port_of(scheme, raw_port)
    if port is None or port not in scope.allowed_ports:
        return f"port {port} not in plan scope {scope.allowed_ports}"

    path = parts.path or "/"
    if not path.startswith(scope.path_prefix):
        return f"path {path!r} outside plan prefix {scope.path_prefix!r}"

    if robots is not None and not robots.allowed(url):
        return "disallowed by robots.txt"

    # DNS last. Every returned address must be public.
    try:
        addresses = resolver(host, port)
    except OSError as exc:
        return f"dns failure: {exc}"
    if not addresses:
        return "host resolved to no addresses"
    for addr in addresses:
        if _is_forbidden_address(addr, scope.allow_loopback):
            return f"host resolves to non-public address {addr}"

    return None


def scope_regex(plan: Plan) -> str:
    """A fullmatch regex over every fetch scope in the plan.

    Handed to bouncer as a `ToolPolicy.arg_patterns` constraint on `fetch.url`,
    giving Layer 2 an independent witness over the frontier URLs that Layer 1
    structurally cannot see (they are internal to one fetch step).
    """
    alternatives: list[str] = []
    for step in plan.steps:
        if step.scope is None:
            continue
        s = step.scope
        schemes = "|".join(re.escape(x) for x in s.allowed_schemes) or "https"
        hosts = "|".join(re.escape(_idna(h) or h) for h in s.allowed_hosts)
        if not hosts:
            continue
        ports = "|".join(str(p) for p in s.allowed_ports)
        alternatives.append(
            rf"(?:{schemes})://(?:{hosts})(?::(?:{ports}))?{re.escape(s.path_prefix)}[^\s]*"
        )
    if not alternatives:
        return r"(?!)"  # matches nothing: no fetch scope means no fetch permitted
    return "|".join(alternatives)


def total_page_budget(plan: Plan) -> int:
    """Hard cap on HTTP requests, independent of the frontier's own accounting."""
    return sum(s.scope.max_pages for s in plan.steps if s.scope is not None) or 1


class RobotsGate:
    """robots.txt, consulted only for hosts already inside the scope.

    Two deliberate positions:
      - Robots may only ever NARROW the crawl. An `Allow:` directive can never
        grant access outside CrawlScope, because reject() checks scope first.
      - Unreachable / 5xx / timeout is treated as Disallow, deviating from
        RFC 9309. An attacker who can make robots.txt return 500 must not
        thereby gain crawl access.
    """

    def __init__(self, fetch_text: Callable[[str], str | None], user_agent: str) -> None:
        self._fetch_text = fetch_text
        self._user_agent = user_agent
        self._cache: dict[str, object] = {}

    def _parser_for(self, url: str) -> object | None:
        from urllib.robotparser import RobotFileParser

        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin in self._cache:
            cached = self._cache[origin]
            return None if cached is False else cached

        body = self._fetch_text(f"{origin}/robots.txt")
        if body is None:
            self._cache[origin] = False  # fail closed
            return None
        parser = RobotFileParser()
        parser.parse(body.splitlines())
        self._cache[origin] = parser
        return parser

    def allowed(self, url: str) -> bool:
        parser = self._parser_for(url)
        if parser is None:
            return False
        return bool(parser.can_fetch(self._user_agent, url))
