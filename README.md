```
\\(oo)//  crawlgate
//    \\
```

A small agentic harness that crawls the web, in which **page content
structurally cannot become an instruction**.

An agent that reads the open web is reading attacker-controlled text. crawlgate's
answer is not to detect that, but to make it not matter: a trusted planner
commits the complete plan *before* any byte is fetched, and nothing read
afterwards can add, remove, reorder or redirect a tool call.

![a crawlgate run: the plan committed up front, then a page's attempt to redirect the crawl refused](docs/run.svg)

That image is a real run against `demo/serve.py`, exported from the terminal
rather than mocked. The fixture page carries an injected instruction to fetch
`attacker.test`. The plan named its destinations before the page was read, so
the link is refused — and the refusal is the only thing on screen that glows.

```bash
uv sync --extra dev
uv run python -m demo.security_demo   # 16 attacks, no API key, no network
uv run python -m demo.utility_demo    # 15 benign tasks, defended vs undefended
uv run pytest -q
```

```bash
uv run crawlgate "Summarize the release notes at https://example.com/docs/notes and write the summary to notes/summary.md" --workspace ./work
```

You get the committed plan first, and approve it, edit it in `$EDITOR`, or quit.
Every destination in it — the seed URL, every field of `scope`, every
`write_file` path — is a literal; every `{slot}` sits in a content position.
That is the whole invariant, on one screen, before anything is fetched.
`--dry-run` prints the plan as JSON and exits; `--yes` skips the gate.

Chrome goes to stderr and the answer to stdout, so `crawlgate … > out.md` still
gives you a clean file, and a redirected stream gets no colour and no mascot.

## Two layers

| | Mechanism | Question |
|---|---|---|
| **Layer 1** | plan-then-execute + capability gate | *Is this call plan-derived at all?* |
| **Layer 2** | [`mcp-bouncer`](../Fable/bouncer)'s `ContractEngine`, unmodified | *Is this argument value permissible?* |

Layer 1 is the proof — the attack suite passes with Layer 2 switched off
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
- [docs/mascot-variants.md](docs/mascot-variants.md) — how the spider was chosen
