# Phase 5 — MCP → LangChain Tool Adapter

**Time: ~1.5 hours** | **Checkpoint: LangChain tools call MCP server through Bouncer**

## What you're building

`tools/adapter.py` — a context manager that:
1. Renders the Bouncer policy (substitutes repo path)
2. Creates a temp MCP config pointing to your tool server
3. Runs `bouncer init` on the config
4. Starts the Bouncer process as a subprocess
5. Connects an MCP `ClientSession` to Bouncer's stdio
6. Calls `tools/list` to discover available tools
7. Wraps each MCP tool as a LangChain `StructuredTool`
8. On cleanup: kills the Bouncer subprocess

## Key implementation

```python
"""Bridge between MCP tools (via Bouncer) and LangChain tool-calling."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from langchain_core.tools import StructuredTool
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _render_policy(repo_path: str) -> Path:
    """Render bouncer_policy.yaml.template with the actual repo path."""
    template_path = Path(__file__).parent.parent.parent.parent / "bouncer_policy.yaml.template"
    content = template_path.read_text()
    rendered = content.replace("{repo_path}", str(Path(repo_path).resolve()))
    tmp = Path(tempfile.mktemp(suffix=".yaml"))
    tmp.write_text(rendered)
    return tmp


def _create_mcp_config(repo_path: str) -> Path:
    """Create a temporary MCP config JSON for the tool server."""
    config = {
        "mcpServers": {
            "forgeiq_tools": {
                "command": "python",
                "args": ["-m", "forgeiq.tools.server", "--repo", str(Path(repo_path).resolve())],
            }
        }
    }
    tmp = Path(tempfile.mktemp(suffix=".json"))
    tmp.write_text(json.dumps(config))
    return tmp


def _mcp_tool_to_langchain(session: ClientSession, name: str, description: str, schema: dict) -> StructuredTool:
    """Wrap a single MCP tool as a LangChain StructuredTool."""

    async def _call(**kwargs: Any) -> str:
        result = await session.call_tool(name, arguments=kwargs)
        # MCP returns list of content blocks; join text blocks
        return "\n".join(block.text for block in result.content if hasattr(block, "text"))

    # LangChain needs a sync or coroutine function
    return StructuredTool.from_function(
        coroutine=_call,
        name=name,
        description=description,
        # Convert MCP JSON schema to LangChain-compatible schema
        # You may need to adapt this based on how StructuredTool handles schemas
    )


@asynccontextmanager
async def bouncer_toolkit(repo_path: str):
    """Context manager that yields LangChain tools connected through Bouncer."""
    policy_path = _render_policy(repo_path)
    config_path = _create_mcp_config(repo_path)

    # Run bouncer init to wrap the config
    subprocess.run(["bouncer", "init", "--config", str(config_path)], check=True)

    # Read the wrapped config to get the bouncer command
    # ... connect via stdio_client ...
    # ... discover tools ...
    # ... wrap as LangChain tools ...
    # ... yield tools ...
    # ... cleanup on exit ...

    # This is the skeleton — you need to fill in the MCP client connection
    # The exact API depends on the mcp SDK version. Check:
    #   from mcp.client.stdio import stdio_client
    #   async with stdio_client(server_params) as (read, write):
    #       async with ClientSession(read, write) as session:
    #           await session.initialize()
    #           tools_result = await session.list_tools()
    pass
```

## What to figure out yourself

1. The exact `mcp.client.stdio` API — read the mcp SDK source or docs
2. How `bouncer init` rewrites the config — read Bouncer's `cli.py:rewrite_config()`
3. How to extract the bouncer command from the rewritten config
4. How to properly build the `StructuredTool` with the MCP schema

This is the most integration-heavy file. Take your time.

## Checkpoint ✅

```python
# Quick test:
async with bouncer_toolkit("./sample_repo") as tools:
    print(f"Got {len(tools)} tools: {[t.name for t in tools]}")
    result = await tools[0].ainvoke({"path": "./app.py"})
    print(result)
```

Commit:
```bash
git add .
git commit -m "Phase 5: MCP-to-LangChain adapter via Bouncer"
```
