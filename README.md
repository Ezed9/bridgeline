# crawlgate

A small agentic harness that crawls the web, in which **page content
structurally cannot become an instruction**.

An agent that reads the open web is reading attacker-controlled text. crawlgate's
answer is not to detect that, but to make it not matter: a trusted planner
commits the complete plan *before* any byte is fetched, and nothing read
afterwards can add, remove, reorder or redirect a tool call.

```bash
uv sync --extra dev
uv run python -m demo.security_demo   # 16 attacks, no API key, no network
uv run pytest -q
```

```bash
uv run crawlgate "Summarize the release notes at https://example.com/docs/notes and write the summary to notes/summary.md" --workspace ./work --dry-run
```

`--dry-run` prints the committed plan and exits before any I/O. Every
destination in it — the seed URL, every field of `scope`, every `write_file`
path — is a literal. Every `{"$slot": …}` sits in a content position. That is the
whole invariant, visible on one screen.

## Two layers

| | Mechanism | Question |
|---|---|---|
| **Layer 1** | plan-then-execute + capability gate | *Is this call plan-derived at all?* |
| **Layer 2** | [`mcp-bouncer`](../Fable/bouncer)'s `ContractEngine`, unmodified | *Is this argument value permissible?* |

Layer 1 is the proof — the suite passes with Layer 2 switched off
(`--no-guard`). Layer 2 is an independent contract witness over the frontier
URLs Layer 1 structurally cannot see.

## Multi-model, split by authority

The planner sees only your instruction. The extractor sees only page text. They
are resolved as separate profiles with separate clients and separate contexts,
because they sit on opposite sides of the trust boundary. Two keys → two
providers; one key → one provider, still separate contexts; **no keys →
deterministic stubs, which is the only configuration the security claim is
measured in.**

- [SPEC.md](SPEC.md) — the pre-registered invariant, success and kill criteria
- [FINDINGS.md](FINDINGS.md) — results, the narrow claim, and what it costs
