"""Semantic roles, glyphs and the mascot.

Colours are ANSI names, not hex. A terminal tool does not control its own
background, so the palette is foreground-only and inherits whatever theme the
user already runs -- which is also why it degrades intact over SSH.

Exactly one role is saturated: SIGNAL, meaning a gate refused something.
Nothing else in the interface is ever amber, so a refusal is the only thing on
screen that glows.

Colour never carries the verdict alone. Roughly 8% of men cannot reliably
separate red from green, and the verdict is the one signal that must not be
missed -- so the glyph, the layer name and the indentation carry it, and colour
only reinforces.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

CHROME = "bright_black"      # rules, labels, paths
CONTENT = "default"          # the answer itself
SIGNAL = "bold yellow"       # a gate refused something -- and nothing else
MUTED = "dim"                # budgets, byte counts, timings
RULE = "bright_black"

# rest and watching are padded to four rows so the header never jumps when a
# refusal fires: braced is four rows and the others are three.
SPIDER_REST = r"""
 \\  //
--(oo)--
 //  \\"""

SPIDER_WATCHING = r"""
 \\  //
--(OO)--
 //  \\"""

# The frame is open at the bottom -- a doorway walked through, not a box the
# spider sits in. Its lintel is a horizontal contrast bar no other state has,
# which is what makes a refusal register before it is read.
SPIDER_BRACED = r"""┌────────┐
│ \\  // │
│--(OO)--│
│ //  \\ │"""

LOGO = r"""\\(oo)//  crawlgate
//    \\"""


@dataclass(frozen=True)
class Glyphs:
    executed: str
    refused: str
    skipped: str
    branch: str
    spider_rest: str
    spider_braced: str
    logo: str


_UNICODE = Glyphs(
    executed="▸",
    refused="⨯",
    skipped="·",
    branch="└",
    spider_rest=SPIDER_REST,
    spider_braced=SPIDER_BRACED,
    logo=LOGO,
)

# A terminal that cannot encode the box-drawing frame would shear the mascot
# sideways, so that path drops it entirely rather than rendering it broken.
_ASCII = Glyphs(
    executed=">",
    refused="X",
    skipped=".",
    branch="`",
    spider_rest="",
    spider_braced="",
    logo="crawlgate",
)


def supports_unicode(stream: object | None = None) -> bool:
    encoding = getattr(stream or sys.stderr, "encoding", None)
    if encoding is None:
        # A text sink with no declared encoding takes str directly, so absence
        # is not evidence against Unicode.
        return True
    if "utf" not in encoding.lower():
        return False
    try:
        SPIDER_BRACED.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def glyphs(stream: object | None = None, *, plain: bool = False) -> Glyphs:
    """`plain` drops the mascot and box-drawing entirely -- for a redirected
    stream, where drawing a spider into a log file helps nobody."""
    if plain or not supports_unicode(stream):
        return _ASCII
    return _UNICODE


def color_enabled(stream: object | None = None) -> bool:
    """Honour the conventions before honouring ourselves."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("CRAWLGATE_NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(stream or sys.stderr, "isatty", lambda: False)())


LAYER_LABEL: dict[str, str] = {
    "capability_gate": "capability_gate",
    "sink_gate": "sink_gate",
    "netpolicy": "netpolicy",
    "contract": "contract",
    "schema": "schema",
}
