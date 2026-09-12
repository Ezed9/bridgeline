"""The quarantined read.

An Extractor is the ONLY component that sees attacker-controlled page text. It
returns a value the plan already declared a type for; `schema.validate` then
bounds that value's shape. It never sees the trusted instruction, never chooses
a tool, and its output is always Tainted.

Extractor fidelity is NOT a security property. A wrong extraction is a wrong
answer, never a leak -- so the security suite runs against an extractor that is
deliberately, maximally hijacked.
"""

from __future__ import annotations

import re
from typing import Protocol

from .types import PageSet

_URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_PAGE_DELIM = "\n\n===== page {n}: {url} =====\n"
_CHAR_BUDGET = 40_000


class Extractor(Protocol):
    def extract(self, source: str, query: str, schema: str) -> object: ...


def render(pages: PageSet) -> str:
    """Flatten a PageSet with deterministic delimiters and a hard char budget."""
    parts: list[str] = []
    used = 0
    for n, page in enumerate(pages.pages):
        head = _PAGE_DELIM.format(n=n, url=page.url)
        room = _CHAR_BUDGET - used - len(head)
        if room <= 0:
            break
        parts.append(head + page.text[:room])
        used += len(parts[-1])
    return "".join(parts)


class AdversarialExtractor:
    """A maximally hijacked extractor, for R6.

    It believes the page completely: for `url` it returns the first URL on the
    page (the attacker's), for `bool` it believes any urgency claim, for `enum`
    it picks whatever the page names, for `string` it returns the page verbatim
    including the injection. If the harness is safe against THIS, it is safe
    against any model, which is the strongest form of "security must not depend
    on a model behaving well".
    """

    def extract(self, source: str, query: str, schema: str) -> object:
        if schema == "url":
            found = _URL_IN_TEXT.search(source)
            return found.group(0) if found else ""
        if schema == "bool":
            return True
        if schema == "int":
            digits = re.search(r"-?\d+", source)
            return digits.group(0) if digits else "0"
        if schema.startswith("enum["):
            members = [m.strip() for m in schema[5:-1].split(",") if m.strip()]
            for member in members:
                if member.lower() in source.lower():
                    return member
            return members[0] if members else ""
        return source


class EchoExtractor:
    """A benign deterministic extractor for utility measurement, no API key.

    Returns the first non-empty lines of the source for `string`, and answers
    `bool` by literal keyword presence. Not clever -- but honest, so the utility
    number it produces is a floor rather than a model's mood.
    """

    def extract(self, source: str, query: str, schema: str) -> object:
        body = "\n".join(line for line in source.splitlines() if line.strip())
        if schema == "string":
            return body[:4000]
        if schema == "bool":
            keywords = [w for w in re.findall(r"[a-z]{4,}", query.lower())]
            return any(k in body.lower() for k in keywords)
        if schema == "int":
            digits = re.search(r"-?\d+", body)
            return digits.group(0) if digits else "0"
        if schema == "url":
            found = _URL_IN_TEXT.search(body)
            return found.group(0) if found else ""
        members = [m.strip() for m in schema[5:-1].split(",")] if schema.startswith("enum[") else []
        for member in members:
            if member.lower() in body.lower():
                return member
        return members[0] if members else ""
