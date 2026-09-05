"""The tool catalog. Three tools; `extract` is a runtime pseudo-tool and is
deliberately absent, so a plan can never call it with forged arguments."""

from __future__ import annotations

from pathlib import Path

from .types import ToolSpec


class ToolError(RuntimeError):
    pass


def _resolve_target(workspace: Path, path: str) -> Path:
    target = Path(path)
    if not target.is_absolute():
        target = workspace / target
    return target.resolve()


def _write_file(workspace: Path, path: str, content: object) -> str:
    target = _resolve_target(workspace, str(path))
    root = workspace.resolve()
    # Layer 2 enforces this too (allowed_path_prefixes). Both, independently.
    if not (target == root or root in target.parents):
        raise ToolError(f"path {target} outside workspace {root}")
    target.parent.mkdir(parents=True, exist_ok=True)
    text = content if isinstance(content, str) else str(content)
    target.write_text(text, encoding="utf-8")
    return f"wrote {len(text)} chars to {target.relative_to(root)}"


def _report(summary: object) -> str:
    return summary if isinstance(summary, str) else str(summary)


def _fetch_unavailable(**_: object) -> object:
    raise ToolError("fetch is executed by the crawl frontier, not through impl")


def build_tools(workspace: Path) -> dict[str, ToolSpec]:
    return {
        "fetch": ToolSpec(
            name="fetch",
            description="Crawl a seed URL within a plan-fixed scope.",
            params=("url",),
            impl=_fetch_unavailable,
            exfiltrating=True,
            sensitive_params=("url",),
        ),
        "write_file": ToolSpec(
            name="write_file",
            description="Write text to a path inside the workspace.",
            params=("path", "content"),
            impl=lambda path, content: _write_file(workspace, str(path), content),
            exfiltrating=True,
            sensitive_params=("path",),
            render_params=("content",),
            effective=lambda args: {
                **args,
                "path": str(_resolve_target(workspace, str(args.get("path", "")))),
            },
        ),
        "report": ToolSpec(
            name="report",
            description="Return a summary to the operator.",
            params=("summary",),
            impl=_report,
            exfiltrating=False,
            render_params=("summary",),
        ),
    }
