# bridgeline — publishing design

**Date:** 2026-09-12
**Status:** approved, pre-implementation
**Supersedes nothing.** `SPEC.md` (the pre-registration) and `FINDINGS.md` (the
results) remain the project's substantive documents. This file covers only how
the work gets renamed, packaged, hardened and published.

---

## 1. What this is

`crawlgate` becomes **`bridgeline`**, published as an installable tool on PyPI
and GitHub, at a quality bar appropriate to a security tool with a falsifiable
claim.

A *bridge line* is the first silk thread an orb-weaver casts across a gap,
before any web exists. Every other strand anchors to it and none can exceed it.
That is the plan: committed first, and nothing read afterwards can extend it.
The existing spider mascot and palette carry over unchanged.

## 2. Audience

**The agent builder.** Someone wiring an LLM to the open web who has read the
prompt-injection literature and wants a working reference implementation.

This was chosen over three alternatives on the evidence:

- The project's existing strengths — the invariant, the two-layer split, the
  trace, the blind-authored corpus — are the *product* for this person and
  merely overhead for anyone else.
- The docs-answering audience would judge the tool on extraction quality, which
  is currently a stub that fails 6/15 benign tasks. That competition is
  unwinnable against incumbents with crawler fleets.
- `mcp-bouncer` already targets exactly this person (an MCP proxy for Claude
  Code and Cursor). Two projects telling one coherent story to one audience
  beats two projects chasing different rooms.
- `FINDINGS.md`'s "Integration notes for mcp-bouncer" is already written to a
  library consumer.

The CLI is the thirty-second proof that the pattern is real. The library is what
this person eventually adopts. Both matter; the CLI is what earns the look.

## 3. Non-goals

- Competing on extraction quality or answer fidelity.
- A docs site, standalone binaries, a Homebrew tap, or an OpenSSF Scorecard
  badge. Revisit when there are users asking.
- Implementing SPEC §3's pre-registered open question (may an extracted URL be
  fetched if it independently satisfies the plan-fixed scope). It needs its own
  red team and is out of scope here.
- Any change to a success or kill criterion in `SPEC.md`.

---

## 4. Phase 0 — close the evidence gaps

Publishing a claim requires the claim to be current. Nothing else starts until
this is done.

### 4.1 K5 is now measured

Run on 2026-09-12 against a live Gemini 2.5 Flash planner over the 15
blind-authored benign tasks:

```
schema-valid: 13/15 answered = 87%   (kill threshold: below 60%)
PASS K5.
```

`FINDINGS.md` currently states K5 is unevaluated. That paragraph is rewritten
into a result, naming both failures:

- **`support_email_lookup`** — `rejected: step 3.args.summary: an object
  argument must be exactly {'$slot': name}`. A genuine schema-targeting failure:
  the planner placed structure where a slot belongs. This is the informative
  signal K5 was designed to capture and is reported as such.
- **`status_conditional`** — `AttributeError: 'dict' object has no attribute
  'split'`. Not a planner failure. See 4.2.

The "Honest residuals" section's claim that K5 is unevaluated is corrected in
the same commit. The comparison to bouncer's own unevaluated benchmark criteria
is removed, because it no longer applies.

### 4.2 Fix the malformed-plan crash

Malformed model output must raise `PlanError`, not `AttributeError`. Today a
planner returning a dict where a string is expected produces a traceback. This
contradicts the principle already committed in `624bb93` ("Treat a model outage
as a condition, not a crash") and is the difference between a rough tool and an
unfinished one.

A regression test asserts that a plan payload of the wrong shape raises
`PlanError` with a message naming the offending path.

### 4.3 Correct the test count

`FINDINGS.md` says 133 tests. The suite is 161 passed, 2 skipped. Verified green
on CPython 3.12.7 and 3.14.3 on 2026-09-12.

---

## 5. Phase 1 — `bouncer-core` on PyPI

`bridgeline` cannot be installed by a stranger until its Layer 2 dependency is
on PyPI. Today it is a `uv` path dependency to `../Fable/bouncer`, and PyPI
rejects uploads whose metadata contains direct URL dependencies.

### 5.1 Current state

- `Ezed9/mcp-bouncer` **already exists** on GitHub — public, 2 stars, last
  pushed 2026-07-15, carrying `ci.yml`, LICENSE, CONTRIBUTING.md, SECURITY.md,
  docs, examples, and a committed `uv.lock`. The extraction from the `Fable`
  monorepo is done. Local and remote agree; crawlgate's development required
  zero bouncer changes, which S5 confirms.
- It has **0 tags and 0 releases**, so there is no publish pipeline.
- **The name `mcp-bouncer` is taken on PyPI** — by Sergey Boyko's
  `sergeeey/mcp-guard`, summarised "Prompt injection blocker for MCP servers and
  AI agents". Same problem space, different author, arrived first. `bouncer` is
  also taken.

### 5.2 The split

`FINDINGS.md` integration note 4 already argued for this, from consumer
evidence rather than speculation. It resolves the name collision and the
dependency-weight problem in one move.

| Distribution | Import package | Modules | Dependencies |
|---|---|---|---|
| `bouncer-core` | `bouncer` | `types`, `taint`, `approvals`, `audit`, `heuristics`, `policy`, `engine`, `packs/` | `pyyaml` |
| `bouncer-mcp` | `bouncer_mcp` | `proxy`, `cli` | `bouncer-core`, `mcp`, `anyio` |

Both names are free on PyPI. The `bouncer` console script stays with
`bouncer-mcp`.

The seam is clean and was verified before committing to this: the import graph
has no cycles, every core module is stdlib-only except `policy.py` (which needs
`yaml`), and `proxy.py` is the only module importing across the boundary.
Renaming the MCP half's import path is a breaking change that costs nothing —
there are no releases and no dependents.

### 5.3 Why this matters more than it looks

Installing `bridgeline` today pulls `mcp`, whose closure includes `uvicorn`,
`starlette`, `pydantic`, `jsonschema`, `pyjwt`, `python-multipart`,
`opentelemetry-api`, `httpx2`, `truststore`, `attrs` and `rpds-py`. A stranger
running `uvx bridgeline` would install an ASGI web server and a JWT library for
code that never executes.

Measured: the runtime closure is roughly **42 packages today, about 14 after the
split**.

The project's pitch is auditability — "deterministic, no LLM in the decision
path, small enough to read." The install line is the first place a careful
person audits that claim. This is the argument, not dependency weight as taste.

### 5.4 Upstream improvements, from the consumer notes

Implemented while the package is being restructured, because they are the notes
of a real consumer and they are cheap:

1. **`register_schema(name, schema)`** as public API (note 1). Removes
   bridgeline's dependence on the undocumented fact that `ContractEngine`
   retains the caller's `schemas` dict by reference.
2. **Document the resolver ordering** (note 2) — `PolicyResolver(use_heuristics
   =False)` returns a fully permissive `ToolPolicy` for an unknown tool, safe
   only because the engine's pinning check asks first. That ordering is
   load-bearing and currently undocumented.
3. **Document that `ContractEngine` is stateful and unsynchronized** (note 3) —
   `_counts`, `TaintTracker._outputs`, `ApprovalStore._keys`. Concurrent
   `evaluate` would race the budget.

### 5.5 Release

Tag `v0.1.0`. One workflow builds and publishes both distributions via PyPI
Trusted Publishing.

---

## 6. Phase 2 — the rename

### 6.1 Mechanics

- New repository `Ezed9/bridgeline`, **carrying the full 10-commit history**.
  `FINDINGS.md` cites `git log --reverse` as evidence that `SPEC.md` was
  committed before `src/` existed. A squashed or fresh-start history destroys
  the project's strongest claim. This is a hard requirement.
- `src/crawlgate/` → `src/bridgeline/` via `git mv`.
- 118 textual occurrences across 37 files.
- The on-disk run-artifact directory `.crawlgate/` → `.bridgeline/`.
- `pyproject.toml`: name, script entry point, wheel packages, and the
  `mcp-bouncer` path dependency replaced with `bouncer-core` from PyPI.

### 6.2 `SPEC.md` is frozen

**The body of `SPEC.md` is never edited.** Its entire epistemic value is that it
is unmodified — a pre-registration whose credibility rests on a verifiable
timeline. A rename `sed` through it would make `git log SPEC.md` show a
pre-registration modified after the results landed, and a skeptic reads dates,
not intentions.

The single permitted change is one dated note appended to the header:

> Renamed to bridgeline on 2026-09-12. This file is preserved verbatim as
> pre-registered; no criterion has been altered. The name "crawlgate" is
> retained throughout deliberately.

The diff then proves the edit changed nothing substantive. No occurrence of
"crawlgate" inside the body is touched.

### 6.3 Repository cleanup

- Delete `docs/archive/forgeiq_guide/` — 44K of scaffold from an abandoned
  project, unrelated to this one and actively confusing.
- Commit `uv.lock` (remove it from `.gitignore`). A published CLI needs a
  reproducible CI environment; leaving the lockfile untracked is the wrong
  default for an application.
- Total tracked weight is 492K, so nothing else needs pruning.

### 6.4 README, rewritten for a stranger

The current README is written for someone with the `Fable` monorepo on disk. It
links to `../Fable/bouncer` and references `Fable/research`. Both are dead ends
for everyone else.

Required content, in order:

1. The claim in one sentence, and `uvx bridgeline verify` as the first command.
2. What it does and the install line.
3. The two-layer table, with Layer 2 linked to the public `bouncer-core`.
4. **The independence paragraph** (6.5).
5. **The measurement-configuration paragraph** (6.6).
6. Links to `SPEC.md`, `FINDINGS.md`, and a note that the project was formerly
   named crawlgate.

The existing `docs/run.svg` — a real exported run showing a refusal — stays as
the demo asset.

### 6.5 The independence paragraph

Once both repositories are public under the same account, "Layer 2 is
`mcp-bouncer`, consumed unmodified, public API only, no fork, no vendoring"
reads differently. In private it is discipline. In public a skeptic says: of
course it integrated cleanly, you wrote both sides.

The README raises this first rather than letting a reader find it, and points at
what can actually be checked:

- **S4** — the full acceptance suite passes with `NullGuard` substituted for the
  bouncer. Layer 2 is never load-bearing, so its authorship cannot be.
- **S5** — no private attribute access anywhere in `src/`, AST-enforced by a
  test rather than asserted.
- The four integration notes in `FINDINGS.md` are *complaints* — an undocumented
  by-reference retention, a permissive fallback refused, an unsynchronized
  engine, a packaging split needed. Those are what a constrained consumer
  writes.

### 6.6 The measurement-configuration paragraph

S1 and S4 are measured only under `--models none` — a deterministic planner and
a deliberately hijacked extractor, no API key, no sockets. A user who sets a key
is running a configuration the security claim was never measured in.

Structurally that configuration should be *safer*: `AdversarialExtractor` is the
worst case, and a live extractor is strictly less hostile. The genuinely new
surface is the **planner**, which with a key is an LLM that commits the scope.
The plan gate is where a bad scope gets caught, and `--yes` skips it. The README
says this plainly rather than leaving it implied.

---

## 7. Phase 3 — `bridgeline verify`

### 7.1 Why

`demo/` and `tests/` sit outside `src/` and do not ship in the wheel. A stranger
running `uvx bridgeline` cannot run the attack suite — the most persuasive asset
the project has. Seeing "16 attacks, 0 leaks" currently requires a clone.

`bridgeline verify` converts the claim from asserted to executable. For a
security tool that is the whole game: not "trust my README" but "falsify me, in
five seconds, offline."

It also solves the keyless first-run problem. Without a key the crawl is real
and the plan is sensible, but `EchoExtractor` returns an echo rather than an
answer, which a stranger reads as broken. `verify` gives the README a first
command that always works and always impresses.

### 7.2 Shape

- The attack corpus and its harness move into `src/bridgeline/`.
- `bridgeline verify` runs all 16 attacks in-process. No network, no API key, no
  clone. It drives the recording in-process HTTP client, exactly as the existing
  security demo does.
- Output is the existing three-column table: undefended / defended /
  layer-1-only.
- **Exit code is nonzero if any leak occurs.** The assertion remains at the
  effect layer — a socket opened or a file written outside the workspace — never
  by reading a log, per SPEC §2 "flagging is not blocking".
- Tests assert the subcommand exits 0 today and that the table shape is stable.

### 7.3 Provenance must stay explicit

SPEC §10 commits that `demo/attacks.py` was authored by an agent given only
`SPEC.md` and the tool surface, with `src/` and `tests/` off limits. Moving the
corpus into `src/` afterwards does not retroactively violate that — git history
proves the ordering — but without an explicit sentence a careful reader may
assume the corpus was written with the implementation in view.

The `verify` output and the README both carry that sentence.

### 7.4 What stays clone-only

`demo/serve.py` (the loopback fixture site), `demo/tasks.py` (the 700-line
benign task set), `demo/utility_demo.py`, `demo/baseline.py` and
`demo/k5_planner.py` remain repository activities. They serve reproduction of
S3, K5 and K6, not a first impression, and most of them need a key or a live
socket.

---

## 8. Phase 4 — the industrial surface

The bar is "credible open source, plus the supply-chain hygiene a security tool
owes its users." Concretely: the surface `opencode-ai/opencode` shipped — which
reached 13.7k stars on two workflows and a long README — plus the hardening that
a project whose pitch is deterministic enforcement cannot afford to skip.

Explicitly *not* the `anomalyco/opencode` bar: 26 workflows, a marketing site,
20+ translated READMEs, a desktop app and a VS Code extension are a funded
company's output, not a solo maintainer's.

### 8.1 Governance

- `LICENSE` — the actual MIT text. Today only the `license = "MIT"` field exists.
- `CONTRIBUTING.md` — dev setup via `uv sync --extra dev`, how to run the suite,
  and the rule that no change may weaken a SPEC criterion without a documented
  retraction.
- `SECURITY.md` — reporting via GitHub Security Advisories, **and an explicit
  statement of what is already known and out of scope**, so reports about
  documented residuals are pre-empted. Names the DNS-rebinding TOCTOU window,
  storage-granular taint, the visit-pattern residual channel, and SPEC §8's
  out-of-scope list.
- `CODE_OF_CONDUCT.md` — Contributor Covenant.
- `.github/ISSUE_TEMPLATE/` — bug report, feature request, and a config pointing
  security reports at the advisory flow rather than a public issue.
- `.github/pull_request_template.md`.

### 8.2 CI

- `ci.yml` on push and pull request: ubuntu-latest × CPython 3.12, 3.13, 3.14.
  Both ends verified green locally on 2026-09-12 (161 passed, 2 skipped).
- `astral-sh/setup-uv` with caching keyed on `uv.lock`; `uv sync --locked
  --all-extras --dev`.
- Steps: `ruff check` and `pytest -q`.
- **`ruff format --check` is deliberately excluded.** Formatting has never been
  enforced here: 33 of 51 files would be reformatted today. Enforcing it means
  either a 33-file reformat commit landing immediately before publication —
  obscuring every substantive change in this work — or a red CI. Lint (`ruff
  check`) passes clean today and is enforced. If formatting is wanted later it
  should be a single isolated commit recorded in `.git-blame-ignore-revs`, done
  after publication rather than during it.
- **Every action pinned by commit SHA**, with the version in a trailing comment.
- Coverage reported to the job summary via `pytest-cov`. No third-party service.

### 8.3 Release

- `release.yml` on tag push: a `build` job producing artifacts, then a
  `publish` job gated on the tag, using a named GitHub Environment and
  `permissions: id-token: write` with `pypa/gh-action-pypi-publish`.
- **PyPI Trusted Publishing (OIDC).** No long-lived API token in secrets.
- Sigstore attestations are on by default for trusted publishing and are left on.
- TestPyPI dry run before the first real publish.

### 8.4 Versioning

`hatch version` plus a manual tag. `CHANGELOG.md` in Keep a Changelog format,
written by hand.

Deliberately **not** python-semantic-release or release-please: both buy
automated changelogs in exchange for commit-message discipline that a solo
project does not need, and the repository's existing commit style is prose
rather than Conventional Commits. Revisit if there are multiple contributors.

### 8.5 Dependency updates

Renovate, not Dependabot — its `uv.lock` support is the more mature of the two
and it can refresh the lockfile without bumping direct dependencies.

### 8.6 Badges

CI status, PyPI version, Python versions, license, and the existing
"decision path: deterministic" badge carried over from bouncer's README.

---

## 9. Phase 5 — publish

1. `bouncer-core` and `bouncer-mcp` to TestPyPI, then PyPI. Tag
   `mcp-bouncer v0.1.0`.
2. `bridgeline`'s dependency switches from the path dep to `bouncer-core` from
   PyPI. Full suite re-run against the published artifact, not the local path —
   this is the step that proves a stranger's install actually works.
3. `bridgeline` to TestPyPI, then PyPI. Tag `v0.1.0`.
4. Verify `uvx bridgeline verify` works from a clean machine state.

---

## 10. Sequencing and dependencies

```
Phase 0  (evidence)      ── independent, do first
Phase 1  (bouncer-core)  ── blocks Phase 5.2
Phase 2  (rename)        ── blocks Phases 3, 4
Phase 3  (verify)        ── blocks README section 1
Phase 4  (surface)       ── blocks Phase 5
Phase 5  (publish)       ── last
```

Phase 0 and Phase 1 are independent of each other and of Phase 2, so Phase 1 can
proceed in the bouncer repository while Phase 0 happens here.

## 11. Success criteria for this work

1. `uvx bridgeline verify` runs on a machine with no clone, no API key and no
   network, prints the 16-attack table, and exits 0.
2. `uv pip install bridgeline` resolves without `mcp`, `uvicorn`, `starlette`,
   `pydantic`, `pyjwt` or `opentelemetry-api`.
3. CI is green on 3.12, 3.13 and 3.14.
4. `git log --reverse` in the published repository still shows the
   pre-registration commit preceding the first `src/` commit.
5. `git log -p SPEC.md` shows exactly one post-pre-registration commit, adding
   only the dated rename note.
6. `FINDINGS.md` reports K5 as evaluated at 13/15, with both failures named.
7. A reader who has never seen the project can state, from the README alone,
   what configuration the security claim was measured in and why it matters.

## 12. Risks

- **The rename touches 118 sites.** Mitigated by the full suite (161 tests) and
  by keeping `SPEC.md` out of the rename entirely.
- **The bouncer split changes an import path.** Zero releases and zero
  dependents make this free now and expensive later; that asymmetry is the
  reason to do it before publishing rather than after.
- **Moving the corpus into `src/` could be misread** as the corpus having been
  authored with the implementation visible. Mitigated by an explicit provenance
  sentence in both `verify` output and the README, and by git history.
- **Publishing a security tool invites reports about known residuals.**
  Mitigated by `SECURITY.md` naming them up front.
- **Formatting drift.** Not enforcing `ruff format` means the codebase stays
  inconsistently formatted. Accepted deliberately: churning 33 files during a
  rename and a publication is worse than the drift, and lint is enforced.
- **`bridgeline` on PyPI is free today and unreserved.** The longer the gap
  between deciding the name and publishing, the more exposure. Phase 5 should
  not be left open-ended.
