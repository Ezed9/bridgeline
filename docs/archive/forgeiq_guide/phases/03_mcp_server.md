# Phase 3 — MCP Tool Server

**Time: ~2.5 hours** | **Checkpoint: each tool works when tested manually**

## What you're building

A standalone MCP server that exposes 6 tools over stdio. This runs as a separate process. The Coder agent will call these tools through the MCP protocol (via Bouncer).

## Step 3.1 — Create `src/forgeiq/tools/server.py`

This is the most important file in the project. It's a real MCP server using the `mcp` Python SDK.

```python
"""MCP stdio server exposing repository manipulation tools."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

server = Server("forgeiq-tools")

# Global repo root — set via CLI arg
_repo_root: Path = Path.cwd()


def _resolve(path: str) -> Path:
    """Resolve a path, making relative paths relative to repo root."""
    p = Path(path)
    if not p.is_absolute():
        p = _repo_root / p
    return p.resolve()


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="read_file",
            description="Read the contents of a file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the file to read"}
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="write_file",
            description="Write content to a file. Creates parent directories if needed.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to write to"},
                    "content": {"type": "string", "description": "Content to write"},
                },
                "required": ["path", "content"],
            },
        ),
        Tool(
            name="edit_file",
            description="Edit a file by replacing the first occurrence of old_text with new_text.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the file"},
                    "old_text": {"type": "string", "description": "Exact text to find"},
                    "new_text": {"type": "string", "description": "Replacement text"},
                },
                "required": ["path", "old_text", "new_text"],
            },
        ),
        Tool(
            name="search_code",
            description="Search for a pattern in files using grep. Returns matching lines.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Search pattern (literal string)"},
                    "path": {"type": "string", "description": "Directory to search (default: repo root)"},
                },
                "required": ["pattern"],
            },
        ),
        Tool(
            name="run_command",
            description="Run a shell command and return stdout, stderr, and exit code.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to run"},
                    "cwd": {"type": "string", "description": "Working directory (default: repo root)"},
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="list_directory",
            description="List contents of a directory with file sizes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path to list"}
                },
                "required": ["path"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        result = _dispatch(name, arguments)
        return [TextContent(type="text", text=result)]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {e}")]


def _dispatch(name: str, args: dict) -> str:
    match name:
        case "read_file":
            return _read_file(args["path"])
        case "write_file":
            return _write_file(args["path"], args["content"])
        case "edit_file":
            return _edit_file(args["path"], args["old_text"], args["new_text"])
        case "search_code":
            return _search_code(args["pattern"], args.get("path"))
        case "run_command":
            return _run_command(args["command"], args.get("cwd"))
        case "list_directory":
            return _list_directory(args["path"])
        case _:
            raise ValueError(f"Unknown tool: {name}")


def _read_file(path: str) -> str:
    p = _resolve(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    return p.read_text(encoding="utf-8")


def _write_file(path: str, content: str) -> str:
    p = _resolve(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return f"Written {len(content)} bytes to {p}"


def _edit_file(path: str, old_text: str, new_text: str) -> str:
    p = _resolve(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    content = p.read_text(encoding="utf-8")
    if old_text not in content:
        preview = old_text[:80].replace("\n", "\\n")
        raise ValueError(f"Text not found in {p}: '{preview}...'")
    new_content = content.replace(old_text, new_text, 1)  # First occurrence only
    p.write_text(new_content, encoding="utf-8")
    return f"Edited {p}: replaced {len(old_text)} chars with {len(new_text)} chars"


def _search_code(pattern: str, path: str | None = None) -> str:
    search_path = _resolve(path) if path else _repo_root
    try:
        result = subprocess.run(
            ["grep", "-rnI", "--include=*.py", "--include=*.js", "--include=*.ts",
             "--include=*.yaml", "--include=*.yml", "--include=*.json",
             "--include=*.md", "--include=*.html", "--include=*.css",
             "--include=*.txt", "--include=*.toml",
             pattern, str(search_path)],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        return "Search timed out after 10 seconds"

    lines = result.stdout.strip().split("\n")[:50]  # Cap at 50 results
    if not lines or lines == [""]:
        return f"No matches found for '{pattern}'"
    return "\n".join(lines)


def _run_command(command: str, cwd: str | None = None) -> str:
    work_dir = _resolve(cwd) if cwd else _repo_root
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=60, cwd=str(work_dir),
        )
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 60 seconds"

    output = f"Exit code: {result.returncode}\n"
    if result.stdout.strip():
        output += f"\nSTDOUT:\n{result.stdout.strip()}\n"
    if result.stderr.strip():
        output += f"\nSTDERR:\n{result.stderr.strip()}\n"
    return output


def _list_directory(path: str) -> str:
    p = _resolve(path)
    if not p.is_dir():
        raise NotADirectoryError(f"{p} is not a directory")
    entries = []
    for item in sorted(p.iterdir()):
        if item.name.startswith("."):
            continue
        if item.is_dir():
            count = sum(1 for _ in item.iterdir())
            entries.append(f"  {item.name}/ (dir, {count} items)")
        else:
            size = item.stat().st_size
            if size < 1024:
                entries.append(f"  {item.name} ({size} B)")
            else:
                entries.append(f"  {item.name} ({size / 1024:.1f} KB)")
    return "\n".join(entries) if entries else "(empty directory)"


async def main():
    global _repo_root
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".", help="Repository root path")
    args = parser.parse_args()
    _repo_root = Path(args.repo).resolve()

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

**Key things to understand for interviews:**
- It uses the `mcp` Python SDK's `Server` class with `@server.list_tools()` and `@server.call_tool()` decorators
- All paths are resolved relative to `_repo_root` which is set via `--repo` CLI arg
- `edit_file` does exact-match search-and-replace (first occurrence only) — this is fragile by design; the agent prompt must enforce reading before editing
- `run_command` uses `shell=True` with a 60s timeout — Bouncer handles command allowlisting
- `search_code` caps at 50 results and 10s timeout

## Step 3.2 — Test it manually

In one terminal:
```bash
uv run python -m forgeiq.tools.server --repo .
```

It should start and wait for stdin (MCP stdio transport). Kill it with Ctrl+C. The fact that it starts without error means the server is correctly defined.

## Step 3.3 — Create `tests/test_tools.py`

Write tests that start the server as a subprocess and call tools via the MCP client SDK.

```python
"""Tests for the MCP tool server."""

import asyncio
import os
import tempfile
from pathlib import Path

import pytest

from forgeiq.tools.server import (
    _read_file, _write_file, _edit_file,
    _search_code, _run_command, _list_directory,
    _repo_root,
)


@pytest.fixture()
def tmp_repo(tmp_path):
    """Create a temporary repo with some files."""
    # Set the global repo root for the tool functions
    import forgeiq.tools.server as srv
    srv._repo_root = tmp_path

    (tmp_path / "hello.py").write_text("def greet():\n    return 'hello'\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "nested.py").write_text("x = 42\n")
    return tmp_path


class TestReadFile:
    def test_reads_existing_file(self, tmp_repo):
        result = _read_file(str(tmp_repo / "hello.py"))
        assert "def greet" in result

    def test_raises_on_missing_file(self, tmp_repo):
        with pytest.raises(FileNotFoundError):
            _read_file(str(tmp_repo / "nope.py"))


class TestWriteFile:
    def test_writes_new_file(self, tmp_repo):
        target = str(tmp_repo / "new.py")
        result = _write_file(target, "print('hi')")
        assert "Written" in result
        assert Path(target).read_text() == "print('hi')"

    def test_creates_parent_dirs(self, tmp_repo):
        target = str(tmp_repo / "a" / "b" / "c.py")
        _write_file(target, "x = 1")
        assert Path(target).exists()


class TestEditFile:
    def test_replaces_text(self, tmp_repo):
        path = str(tmp_repo / "hello.py")
        _edit_file(path, "return 'hello'", "return 'world'")
        assert "world" in Path(path).read_text()

    def test_raises_on_missing_text(self, tmp_repo):
        path = str(tmp_repo / "hello.py")
        with pytest.raises(ValueError, match="Text not found"):
            _edit_file(path, "nonexistent text", "replacement")


class TestSearchCode:
    def test_finds_pattern(self, tmp_repo):
        result = _search_code("def greet")
        assert "hello.py" in result

    def test_no_matches(self, tmp_repo):
        result = _search_code("zzz_not_here_zzz")
        assert "No matches" in result


class TestRunCommand:
    def test_captures_output(self, tmp_repo):
        result = _run_command("echo hello")
        assert "Exit code: 0" in result
        assert "hello" in result

    def test_captures_error(self, tmp_repo):
        result = _run_command("python -c 'raise ValueError(\"boom\")' ")
        assert "Exit code: 1" in result


class TestListDirectory:
    def test_lists_contents(self, tmp_repo):
        result = _list_directory(str(tmp_repo))
        assert "hello.py" in result
        assert "sub/" in result

    def test_raises_on_file(self, tmp_repo):
        with pytest.raises(NotADirectoryError):
            _list_directory(str(tmp_repo / "hello.py"))
```

## Checkpoint ✅

```bash
uv run pytest tests/test_tools.py -v
```

All 12 tests should pass. If they do, commit:

```bash
git add .
git commit -m "Phase 3: MCP tool server with 6 tools + tests"
```

## What you should be able to explain

- Why stdio transport? (MCP standard, Bouncer wraps stdio servers)
- Why `shell=True` in run_command? (Bouncer handles command restrictions, not the server)
- Why first-occurrence-only in edit_file? (Prevents unintended mass replacements; agent must be precise)
- Why 50-result cap in search_code? (Context window management)
