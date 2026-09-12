"""The SSRF and scope predicates. These decide every destination."""

from __future__ import annotations

import pytest
from conftest import EVIL_HOST, GOOD_HOST, fake_resolver, good_scope

from bridgeline import netpolicy
from bridgeline.types import CrawlScope


def reject(url: str, scope: CrawlScope | None = None, resolver=fake_resolver) -> str | None:
    return netpolicy.reject(url, scope or good_scope(), None, resolver)


# --- SSRF: every one of these must be refused ---------------------------------

@pytest.mark.parametrize("addr", [
    "127.0.0.1", "127.1", "0.0.0.0", "::1", "::ffff:127.0.0.1",
    "169.254.169.254",           # AWS/Azure IMDS
    "fd00:ec2::254",             # AWS IMDS over IPv6
    "100.100.100.200",           # Alibaba metadata
    "10.0.0.5", "172.16.0.1", "192.168.1.1",   # RFC1918
    "100.64.0.1",                # CGNAT
    "fd00::1",                   # unique local
    "169.254.1.1",               # link-local
    "224.0.0.1",                 # multicast
])
def test_private_and_metadata_addresses_are_refused(addr: str) -> None:
    scope = good_scope(allowed_hosts=("internal.test",))
    reason = reject("https://internal.test/docs/x", scope, lambda h, p: [addr])
    assert reason is not None, f"{addr} was accepted"
    assert "non-public" in reason or "reserved" in reason


def test_one_bad_address_among_several_refuses_the_whole_host() -> None:
    # A host resolving to both a public and a private address must not be fetched:
    # the OS picks which one to connect to, not us.
    scope = good_scope(allowed_hosts=("split.test",))
    reason = reject("https://split.test/docs/x", scope,
                    lambda h, p: ["93.184.216.34", "127.0.0.1"])
    assert reason is not None and "non-public" in reason


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "data:text/html,<h1>x",
    "gopher://docs.example.test/",
    "javascript:alert(1)",
    "ftp://docs.example.test/x",
    "docs.example.test/docs/x",       # schemeless
])
def test_non_http_schemes_are_refused(url: str) -> None:
    assert reject(url) is not None


def test_userinfo_in_authority_is_refused() -> None:
    # The authority here is 127.0.0.1, not docs.example.test.
    reason = reject(f"https://{GOOD_HOST}@127.0.0.1/docs/x")
    assert reason is not None and "userinfo" in reason


def test_reserved_local_names_are_refused() -> None:
    for host in ("localhost", "metadata.google.internal", "printer.local", "svc.internal"):
        scope = good_scope(allowed_hosts=(host,))
        assert reject(f"https://{host}/docs/x", scope) is not None


def test_loopback_requires_an_explicit_opt_in() -> None:
    scope = good_scope(allowed_hosts=("fixture.test",))
    assert reject("https://fixture.test/docs/x", scope, lambda h, p: ["127.0.0.1"]) is not None

    opened = good_scope(allowed_hosts=("fixture.test",), allow_loopback=True)
    assert reject("https://fixture.test/docs/x", opened, lambda h, p: ["127.0.0.1"]) is None


def test_allow_loopback_defaults_to_false() -> None:
    # Asserted directly on the dataclass: a test-only bypass must never be the default.
    assert CrawlScope(allowed_hosts=("x",)).allow_loopback is False


# --- Scope membership ---------------------------------------------------------

def test_in_scope_url_is_accepted() -> None:
    assert reject(f"https://{GOOD_HOST}/docs/install") is None


def test_out_of_scope_host_is_refused() -> None:
    reason = reject(f"https://{EVIL_HOST}/collect?d=secret")
    assert reason is not None and "not in plan scope" in reason


def test_path_outside_prefix_is_refused() -> None:
    reason = reject(f"https://{GOOD_HOST}/admin/keys")
    assert reason is not None and "outside plan prefix" in reason


def test_port_outside_scope_is_refused() -> None:
    assert reject(f"https://{GOOD_HOST}:8443/docs/x") is not None


def test_scheme_outside_scope_is_refused() -> None:
    assert reject(f"http://{GOOD_HOST}/docs/x") is not None


def test_homoglyph_host_is_not_the_ascii_host() -> None:
    # Cyrillic 'е' (U+0435). IDNA-encoding makes it compare unequal instead of
    # equal, which is the difference between refusing and fetching.
    homoglyph = "attackеr.test"
    scope = good_scope(allowed_hosts=(EVIL_HOST,))
    assert reject(f"https://{homoglyph}/docs/x", scope) is not None


def test_unicode_host_does_not_smuggle_into_an_ascii_scope() -> None:
    scope = good_scope(allowed_hosts=("dѕ.example.test",))  # Cyrillic ѕ
    assert reject(f"https://{GOOD_HOST}/docs/x", scope) is not None


# --- Canonicalisation and defanging ------------------------------------------

def test_canonical_collapses_fragments_and_default_ports() -> None:
    a = netpolicy.canonical(f"https://{GOOD_HOST}:443/docs/x#frag")
    b = netpolicy.canonical(f"https://{GOOD_HOST}/docs/x")
    assert a == b


def test_defang_neutralises_auto_fetching_renderers() -> None:
    out = netpolicy.defang("see ![](https://attacker.test/p) and http://x.test/y")
    assert "https://" not in out and "http://" not in out
    assert "https[:]//attacker.test/p" in out


# --- The regex handed to bouncer ---------------------------------------------

def test_scope_regex_matches_in_scope_and_rejects_out_of_scope() -> None:
    import re

    from bridgeline.types import Plan, Step

    plan = Plan(steps=(Step(tool="fetch", args={"url": "x"}, scope=good_scope()),))
    pattern = netpolicy.scope_regex(plan)
    assert re.fullmatch(pattern, f"https://{GOOD_HOST}/docs/install")
    assert not re.fullmatch(pattern, f"https://{EVIL_HOST}/collect")
    assert not re.fullmatch(pattern, f"https://{GOOD_HOST}/admin/keys")


def test_scope_regex_with_no_fetch_scope_matches_nothing() -> None:
    import re

    from bridgeline.types import Plan, Step

    plan = Plan(steps=(Step(tool="report", args={"summary": "x"}),))
    assert not re.fullmatch(netpolicy.scope_regex(plan), f"https://{GOOD_HOST}/docs/x")
