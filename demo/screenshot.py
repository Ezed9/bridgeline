"""Capture a real run as SVG for the README.

Rich exports its own rendering, so what lands in docs/ is the actual terminal
output of an actual run against the fixture site -- not a mockup that could
quietly drift from what the tool does.

    uv run python -m demo.screenshot
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import rich.console as rc

DOCS = Path(__file__).resolve().parents[1] / "docs"
_captured: list[rc.Console] = []
_original = rc.Console.__init__


def _recording(self, *args: object, **kwargs: object) -> None:
    kwargs["force_terminal"] = True
    kwargs["record"] = True
    kwargs["width"] = 92
    kwargs.pop("no_color", None)
    _original(self, *args, **kwargs)
    if kwargs.get("stderr"):
        _captured.append(self)


def main() -> int:
    rc.Console.__init__ = _recording  # type: ignore[method-assign]
    from bridgeline.cli import main as cli_main
    from demo.serve import serve_in_background

    server, port = serve_in_background()
    workspace = Path(tempfile.mkdtemp()) / "work"
    try:
        cli_main([
            f"Summarize the release notes at http://127.0.0.1:{port}/docs/notes "
            "and write it to notes/summary.md",
            "--workspace", str(workspace), "--allow-loopback", "--yes",
            "--models", "none",
        ])
    finally:
        server.shutdown()

    if not _captured:
        raise SystemExit("no console was captured")
    DOCS.mkdir(exist_ok=True)
    target = DOCS / "run.svg"
    _captured[0].save_svg(str(target), title="bridgeline")
    print(f"wrote {target.relative_to(DOCS.parent)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
