"""Bounded frontier expansion, and the four crawl-native attack surfaces."""

from __future__ import annotations

from conftest import EVIL_HOST, GOOD_HOST, fake_resolver, good_scope, null_guard

from bridgeline.fetch import crawl, discover_links, visible_text


def _crawl(http, trace, scope=None, seed=None):
    return crawl(
        seed=seed or f"https://{GOOD_HOST}/docs/index",
        scope=scope or good_scope(),
        guard=null_guard(),
        trace=trace,
        http=http,
        resolver=fake_resolver,
        sleep=lambda _: None,
    )


def test_depth_and_page_caps_bound_the_crawl(http, trace) -> None:
    for i in range(20):
        http.add(f"https://{GOOD_HOST}/docs/p{i}",
                 "".join(f"<a href='/docs/p{j}'>x</a>" for j in range(20)))
    http.add(f"https://{GOOD_HOST}/docs/index",
             "".join(f"<a href='/docs/p{j}'>x</a>" for j in range(20)))

    pages = _crawl(http, trace, good_scope(max_pages=5, max_depth=3))
    assert len(pages.pages) == 5
    assert pages.truncated


def test_out_of_scope_links_are_never_requested(http, trace) -> None:
    http.add(
        f"https://{GOOD_HOST}/docs/index",
        f"<a href='https://{EVIL_HOST}/collect?d=x'>click</a>"
        f"<a href='/admin/keys'>admin</a>"
        f"<a href='/docs/ok'>ok</a>",
    )
    http.add(f"https://{GOOD_HOST}/docs/ok", "<p>fine</p>")

    pages = _crawl(http, trace)
    assert not http.touched(EVIL_HOST)
    assert {p.url for p in pages.pages} == {
        f"https://{GOOD_HOST}/docs/index", f"https://{GOOD_HOST}/docs/ok"
    }
    reasons = dict(pages.skipped)
    assert any("not in plan scope" in r for r in reasons.values())
    assert any("outside plan prefix" in r for r in reasons.values())


def test_a_redirect_is_a_candidate_not_a_followed_hop(http, trace) -> None:
    """Auto-following would be a silent destination-choosing primitive."""
    http.add(f"https://{GOOD_HOST}/docs/index", "", status=302,
             headers={"location": f"https://{EVIL_HOST}/collect"})
    pages = _crawl(http, trace)
    assert not http.touched(EVIL_HOST)
    assert pages.pages == ()
    assert any("redirect" in r for _, r in pages.skipped)


def test_an_in_scope_redirect_is_re_checked_and_followed(http, trace) -> None:
    http.add(f"https://{GOOD_HOST}/docs/index", "", status=301,
             headers={"location": f"https://{GOOD_HOST}/docs/real"})
    http.add(f"https://{GOOD_HOST}/docs/real", "<p>arrived</p>")
    pages = _crawl(http, trace)
    assert [p.url for p in pages.pages] == [f"https://{GOOD_HOST}/docs/real"]


def test_base_href_cannot_re_root_relative_links(http, trace) -> None:
    html = f"<base href='https://{EVIL_HOST}/'><a href='collect?d=x'>x</a>"
    links = discover_links(html, f"https://{GOOD_HOST}/docs/index")
    assert links == [f"https://{GOOD_HOST}/docs/collect?d=x"]
    assert not any(EVIL_HOST in link for link in links)


def test_only_anchor_hrefs_are_walked(http, trace) -> None:
    html = (
        f"<link rel='prefetch' href='https://{EVIL_HOST}/a'>"
        f"<img src='https://{EVIL_HOST}/b'>"
        f"<iframe src='https://{EVIL_HOST}/c'></iframe>"
        f"<script>fetch('https://{EVIL_HOST}/d')</script>"
        f"<a href='/docs/ok'>ok</a>"
    )
    links = discover_links(html, f"https://{GOOD_HOST}/docs/index")
    assert links == [f"https://{GOOD_HOST}/docs/ok"]


def test_nofollow_is_honoured(http, trace) -> None:
    html = "<a href='/docs/a' rel='nofollow'>a</a><a href='/docs/b'>b</a>"
    links = discover_links(html, f"https://{GOOD_HOST}/docs/index")
    assert links == [f"https://{GOOD_HOST}/docs/b"]


def test_robots_may_narrow_the_crawl(http, trace) -> None:
    http.add(f"https://{GOOD_HOST}/robots.txt", "User-agent: *\nDisallow: /docs/private\n")
    http.add(f"https://{GOOD_HOST}/docs/index", "<a href='/docs/private/x'>p</a>")
    http.add(f"https://{GOOD_HOST}/docs/private/x", "<p>secret</p>")
    pages = _crawl(http, trace)
    assert [p.url for p in pages.pages] == [f"https://{GOOD_HOST}/docs/index"]
    assert any("robots" in r for _, r in pages.skipped)


def test_robots_can_never_widen_the_crawl(http, trace) -> None:
    """robots.txt is untrusted data. An Allow: naming the attacker must not grant
    access -- scope is checked before robots is even consulted."""
    http.add(f"https://{GOOD_HOST}/robots.txt",
             f"User-agent: *\nAllow: /\nAllow: https://{EVIL_HOST}/\n")
    http.add(f"https://{GOOD_HOST}/docs/index", f"<a href='https://{EVIL_HOST}/collect'>x</a>")
    _crawl(http, trace)
    assert not http.touched(EVIL_HOST)


def test_unreachable_robots_fails_closed(http, trace) -> None:
    """Deliberate RFC 9309 deviation: an attacker who can 500 robots.txt must not
    thereby gain crawl access."""
    http.add(f"https://{GOOD_HOST}/robots.txt", "", status=503)
    http.add(f"https://{GOOD_HOST}/docs/index", "<p>x</p>")
    pages = _crawl(http, trace)
    assert pages.pages == ()
    assert any("robots" in r for _, r in pages.skipped)


def test_a_missing_robots_is_a_genuine_no_rules(http, trace) -> None:
    http.add(f"https://{GOOD_HOST}/robots.txt", "", status=404)
    http.add(f"https://{GOOD_HOST}/docs/index", "<p>x</p>")
    assert len(_crawl(http, trace).pages) == 1


def test_the_byte_cap_is_enforced_during_read(http, trace) -> None:
    http.add(f"https://{GOOD_HOST}/docs/index", "<p>" + "A" * 100_000 + "</p>")
    pages = _crawl(http, trace, good_scope(max_bytes_per_page=1024))
    assert len(pages.pages[0].text) < 2000


def test_the_frontier_dedupes_on_canonical_form(http, trace) -> None:
    http.add(f"https://{GOOD_HOST}/docs/index",
             "<a href='/docs/a#one'>1</a><a href='/docs/a#two'>2</a><a href='/docs/a'>3</a>")
    http.add(f"https://{GOOD_HOST}/docs/a", "<p>a</p>")
    pages = _crawl(http, trace)
    assert len(pages.pages) == 2


def test_scripts_and_styles_are_stripped_from_visible_text() -> None:
    text = visible_text("<style>.a{}</style><script>evil()</script><p>real content</p>")
    assert "real content" in text
    assert "evil()" not in text
