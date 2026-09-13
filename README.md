```
\\(oo)//  bridgeline
//    \\
```

A crawling agent harness in which **page content structurally cannot become an
instruction** — and a claim you can falsify on your own machine in five seconds:

```bash
uvx bridgeline verify
```

That runs sixteen prompt-injection attacks through an undefended agent and
through bridgeline, offline, with no API key. The undefended agent is hijacked
by 14 of them. bridgeline leaks on 0. The exit code is the verdict.

---

An agent that reads the open web is reading attacker-controlled text.
bridgeline's answer is not to detect that, but to make it not matter: a trusted
planner commits the complete plan *before* any byte is fetched, and nothing read
afterwards can add, remove, reorder or redirect a tool call.

![a bridgeline run: the plan committed up front, then a page's attempt to redirect the crawl refused](docs/run.svg)

That image is a real run against `demo/serve.py`, exported from the terminal
rather than mocked. The fixture page carries an injected instruction to fetch
`attacker.test`. The plan named its destinations before the page was read, so
the link is refused — and the refusal is the only thing on screen that glows.

A *bridge line* is the first silk thread an orb-weaver casts across a gap,
before any web exists. Everything else is anchored to it, and nothing can
exceed it.

## Use it

```bash
uv tool install 'bridgeline[anthropic]'      # or [gemini], or both; pip works too

bridgeline "Summarize the release notes at https://example.com/docs/notes and write the summary to notes/summary.md"
```

You get the committed plan first, and approve it, edit it in `$EDITOR`, or quit.
Every destination in it — the seed URL, every field of `scope`, every
`write_file` path — is a literal; every `{slot}` sits in a content position.
That is the whole invariant, on one screen, before anything is fetched.
`--dry-run` prints the plan as JSON and exits; `--yes` skips the gate.

Chrome goes to stderr and the answer to stdout, so `bridgeline … > out.md` gives
you a clean file, and a redirected stream gets no colour and no mascot.

With no API key it still runs, on deterministic stubs: the crawl is real and the
plan is sensible, but the "answer" is an echo of page text rather than a summary.
That configuration exists for the security measurement, not for use.

## Two layers

| | Mechanism | Question |
|---|---|---|
| **Layer 1** | plan-then-execute + capability gate | *Is this call plan-derived at all?* |
| **Layer 2** | [`bouncer-core`](https://github.com/Ezed9/mcp-bouncer)'s `ContractEngine`, unmodified | *Is this argument value permissible?* |

Layer 1 is the proof — the attack suite passes with Layer 2 switched off
(`--no-guard`, and the `layer-1-only` column of `bridgeline verify`). Layer 2 is
an independent contract witness over the frontier URLs Layer 1 structurally
cannot see.

A crawl cannot enumerate its URLs at plan time, which is what usually makes
plan-then-execute useless for one. bridgeline's plan commits a destination
**space** instead of a list: a discovered link is followed only if a pure
function of the URL string and plan-fixed literals admits it. Untrusted pages
choose *which member* of that space is visited. They can never choose a
non-member.

## Both layers are mine

That weakens the independence claim, so here is what to check instead of taking
it on trust:

- **Layer 2 is never load-bearing.** The full acceptance suite passes with the
  contract engine replaced by a `NullGuard` (SPEC criterion S4). Whoever wrote
  Layer 2, the security result does not rest on it.
- **No private access, enforced rather than asserted.** A test walks the AST of
  every module in `src/` and fails on any reach into another object's private
  attributes (S5).
- **The integration notes are complaints.** [FINDINGS.md](FINDINGS.md) records
  four things the engine made awkward — an undocumented by-reference retention,
  a permissive fallback that had to be refused, an unsynchronized engine, and a
  dependency split it needed. That is what a constrained consumer writes, not
  an author shaping both sides to fit.

## What the claim was measured in

The security result is measured **only** with no API key: a deterministic
planner and a deliberately hijacked extractor that does whatever a page says.
`bridgeline verify` is that configuration. Classifiers, LLM judges and
instruction-hierarchy prompting are not used anywhere — not as a fallback, not
as defense in depth.

Running with a key is a configuration the security claim was *not* measured in.
Structurally it should be safer — a live extractor is less hostile than one
built to be hijacked. The genuinely new surface is the **planner**: with a key,
it is an LLM, and it is the thing that commits the scope. The plan gate is where
a scope broader than you meant gets caught. `--yes` skips it.

A live planner does target the plan schema: 13 of 15 blind-authored benign tasks
produced a valid plan against Gemini 2.5 Flash. Extraction *quality* with a live
model is untested.

## What it does not claim

- **Confidentiality of destinations, not integrity of routing.** A malicious
  in-scope page decides which in-scope pages get visited and in what order, and
  can spend the page budget. It cannot send content anywhere the plan did not
  fix.
- **An extracted URL is never fetched** under the default policy, even a
  legitimate one. That is the price, not a bug.
- **DNS rebinding** between resolution and connection is a documented, open
  window.
- Sixteen attacks by one blind author is not AgentDojo.

The full accounting is in [FINDINGS.md](FINDINGS.md).

## Reproduce everything

```bash
git clone https://github.com/Ezed9/bridgeline && cd bridgeline
uv sync --extra dev
uv run bridgeline verify              # the attack suite
uv run python -m demo.utility_demo    # 15 benign tasks, defended vs undefended
uv run pytest -q
```

- [SPEC.md](SPEC.md) — the invariant and the success and kill criteria,
  committed before any implementation existed, and corrected once in the open
- [FINDINGS.md](FINDINGS.md) — results, the narrow claim, and what it costs
- [docs/mascot-variants.md](docs/mascot-variants.md) — how the spider was chosen

bridgeline was called **crawlgate** until 2026-09-12. `SPEC.md` still uses that
name throughout, deliberately: it is a pre-registration. It has been amended
once, on 2026-09-06, to narrow an invariant that overclaimed — `git log -p
SPEC.md` shows exactly what changed, and the commit message says why.

Python 3.12+. MIT licensed.
