"""Typed-slot validation for extractor output.

An extractor reads untrusted content and returns a value the plan declared a
type for. A value failing validation returns None, leaving the out-slot
UNFILLED -- the capability gate then blocks any dependent step.

This is what bounds an injection to a *type-valid* value: an attacker cannot
smuggle arbitrary text into a bool or enum slot.
"""

from __future__ import annotations

import re

_MAX_STRING = 20_000
_ENUM_RE = re.compile(r"^enum\[(.*)\]$")
_URL_RE = re.compile(r"^https?://[^\s\x00-\x1f\x7f]{1,2000}$", re.IGNORECASE)

SCHEMAS: tuple[str, ...] = ("string", "bool", "int", "url")


def _enum_members(schema: str) -> tuple[str, ...] | None:
    m = _ENUM_RE.match(schema)
    if not m:
        return None
    return tuple(p.strip() for p in m.group(1).split(",") if p.strip())


def is_known(schema: str) -> bool:
    return schema in SCHEMAS or _enum_members(schema) is not None


def validate(value: object, schema: str) -> object | None:
    """Return the coerced value if it satisfies `schema`, else None (fail closed)."""
    if schema == "string":
        text = str(value)
        return text if len(text) <= _MAX_STRING else None

    if schema == "bool":
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("true", "yes", "1"):
            return True
        if text in ("false", "no", "0"):
            return False
        return None

    if schema == "int":
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None

    if schema == "url":
        # Shape only. A url-typed slot is still Tainted, so the sink gate -- not
        # this regex -- is what stops it reaching fetch.url.
        text = str(value).strip()
        return text if _URL_RE.match(text) else None

    members = _enum_members(schema)
    if members is not None:
        text = str(value).strip()
        return text if text in members else None

    return None  # unknown schema -> reject
