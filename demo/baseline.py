"""An undefended agent, for comparison.

This is the control. It is shaped like an ordinary tool-calling loop: fetch a
page, put the page text back into the model's context, let the model decide what
to do next. That single re-feed is the whole vulnerability, and it is what
crawlgate's plan-then-execute structure removes.

The "model" here is a deterministic `GullibleModel` rather than a live LLM. That
is deliberate: it needs no API key, it is reproducible, and it models the worst
case honestly -- an agent that believes what it reads. A real model is sometimes
more stubborn, never more principled.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urljoin

from demo.attacks import Attack

_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_ABS_PATH = re.compile(r"(?<![\w/])/(?:etc|tmp|var|root|home)/[\w./-]+")
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_ATTR = re.compile(r"(?:alt|title|content)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_BASE_HREF = re.compile(r"<base[^>]+href\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_ANY_SRC = re.compile(r"(?:href|src)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍﻿"))


@dataclass
class BaselineResult:
    name: str
    hijacked: bool = False
    fetched: list[str] = field(default_factory=list)
    wrote: list[str] = field(default_factory=list)
    reason: str = ""


def _deobfuscate(text: str) -> str:
    """A real model reads through the tricks a naive filter would miss."""
    text = text.translate(_ZERO_WIDTH)
    text = unicodedata.normalize("NFKC", text)
    for blob in _B64.findall(text):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if decoded.isprintable():
            text += "\n" + decoded
    return text


class GullibleModel:
    """Reads a page and does what it says. No judgement, by construction."""

    def act(self, html: str, page_url: str) -> tuple[list[str], list[str]]:
        surface = html + "\n" + "\n".join(_COMMENT.findall(html) + _ATTR.findall(html))
        surface = _deobfuscate(surface)

        base = _BASE_HREF.search(html)
        root = base.group(1) if base else page_url

        urls = {u.rstrip(".,;\"'") for u in _URL.findall(surface)}
        for ref in _ANY_SRC.findall(html):
            if not ref.startswith(("#", "javascript:", "mailto:", "data:")):
                urls.add(urljoin(root, ref))
        return sorted(urls), sorted(set(_ABS_PATH.findall(surface)))


def run_undefended(attack: Attack, max_steps: int = 6) -> BaselineResult:
    result = BaselineResult(name=attack.name)
    model = GullibleModel()
    frontier = [attack.seed]
    seen: set[str] = set()

    while frontier and len(result.fetched) < max_steps:
        url = frontier.pop(0)
        if url in seen:
            continue
        seen.add(url)

        status, body, headers = attack.pages.get(url, (404, "", {}))
        result.fetched.append(url)

        # The undefended agent follows redirects, because that is the default
        # everywhere. This is where the redirect attack lands.
        if 300 <= status < 400 and headers.get("location"):
            frontier.insert(0, urljoin(url, headers["location"]))
            continue

        urls, paths = model.act(body, url)
        result.wrote.extend(paths)
        frontier.extend(u for u in urls if u not in seen)

    hostile_fetch = [u for u in result.fetched if "attacker" in u or "attack" in u]
    hostile_write = [p for p in result.wrote if not p.startswith("/tmp/workspace")]
    if hostile_fetch or hostile_write:
        result.hijacked = True
        result.reason = (
            f"fetched {hostile_fetch[:2]}" if hostile_fetch else f"wrote {hostile_write[:2]}"
        )
    return result


if __name__ == "__main__":
    from demo.attacks import ATTACKS

    for attack in ATTACKS:
        outcome = run_undefended(attack)
        mark = "HIJACKED" if outcome.hijacked else "  survived"
        print(f"{mark}  {attack.name:28} {outcome.reason}")
