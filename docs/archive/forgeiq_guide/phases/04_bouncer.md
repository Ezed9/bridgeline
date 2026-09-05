# Phase 4 — Bouncer Integration

**Time: ~1.5 hours** | **Checkpoint: ALLOW and DENY verdicts working**

## What you're building

The integration layer between your MCP tool server and MCP Bouncer. You will NOT modify Bouncer's code. You'll create a policy YAML and verify that Bouncer correctly gates tool calls.

## Step 4.1 — Create `bouncer_policy.yaml.template`

This is a Jinja-style template. At runtime, `{repo_path}` gets replaced with the actual repo path.

Before writing this file, you MUST check the actual policy YAML format that Bouncer expects. Look at:
- `mcp-bouncer/src/bouncer/policy.py` → `_policy_from_dict()` function
- `mcp-bouncer/src/bouncer/packs/filesystem.yaml` → working example
- `mcp-bouncer/examples/bouncer.yaml` → user override example

The policy needs to match Bouncer's actual schema. The intent:

```yaml
# Writes: confined to repo path, budgeted
write_file:
  max_calls: 50
  # path confinement — check Bouncer's exact field names
  # The field may be called allowed_path_prefixes, path_prefixes, or arg_constraints.path
  # READ bouncer/src/bouncer/policy.py to confirm

edit_file:
  max_calls: 50
  # Same path confinement as write_file

# Commands: restricted to safe prefixes
run_command:
  max_calls: 30
  # Regex on "command" argument
  # Allow only: pytest, ruff, git, cat, head, tail, wc, find, ls

# Reads: unlimited (safe operations)
read_file:
  max_calls: 200

search_code:
  max_calls: 100

list_directory:
  max_calls: 100
```

> **IMPORTANT**: Clone/install mcp-bouncer locally and read `policy.py` to get the exact field names. Do not guess.

## Step 4.2 — Write the policy rendering function

Add a function (in `tools/adapter.py` or a new `tools/policy.py`) that:
1. Reads `bouncer_policy.yaml.template`
2. Replaces `{repo_path}` with the actual absolute path
3. Writes the rendered policy to a temp file
4. Returns the temp file path

## Step 4.3 — Test Bouncer integration

Create `tests/test_bouncer.py`:

```python
"""Test that Bouncer correctly gates tool calls."""
# This test requires mcp-bouncer to be installed
# It starts the MCP server through Bouncer and verifies ALLOW/DENY

# Test 1: write_file inside repo → ALLOW
# Test 2: write_file outside repo → DENY (response contains "[bouncer blocked]")
```

This test is harder to write because it requires starting Bouncer as a subprocess. You may need to:
1. Create a temp MCP config JSON pointing to your tool server
2. Run `bouncer init` on it
3. Start the bouncer process
4. Connect an MCP client to it
5. Make tool calls and check verdicts

## Step 4.4 — Understand the integration for interviews

Key points:
- Bouncer is an UNMODIFIED external dependency. You didn't write it.
- It enforces security DETERMINISTICALLY — no LLM in the security path
- It's a stdio proxy: your MCP client talks to Bouncer, Bouncer talks to your tool server
- The policy YAML is your configuration surface
- Bouncer's audit log (`~/.bouncer/audit.jsonl`) records every verdict

## Checkpoint ✅

```bash
uv run pytest tests/test_bouncer.py -v
```

Both ALLOW and DENY tests pass. Commit:

```bash
git add .
git commit -m "Phase 4: Bouncer policy + integration tests"
```
