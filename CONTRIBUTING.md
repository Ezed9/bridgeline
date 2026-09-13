# Contributing to bridgeline

bridgeline is a security claim with some code attached. The bar is that the
claim stays true and stays checkable — correctness and clarity over cleverness.
Small, well-tested PRs are far easier to accept than large ones.

## Development setup

bridgeline uses [uv](https://docs.astral.sh/uv/). Until `bouncer-core` is
published, it is resolved from a sibling checkout, so clone both side by side:

```bash
git clone https://github.com/Ezed9/mcp-bouncer
git clone https://github.com/Ezed9/bridgeline && cd bridgeline
uv sync --extra dev
uv run pytest -q
uv run ruff check .
uv run bridgeline verify
```

CI runs exactly those three on Python 3.12, 3.13 and 3.14, and additionally runs
`bridgeline verify` from a freshly built wheel. Get them green locally first.

## Rules that are not negotiable

- **No model in the security path.** The invariant must hold even if every model
  is fully malicious (SPEC R6). No classifier, LLM judge or prompt-based defense,
  not even as a fallback.
- **Assert effects, never logs.** A test passes only if the forbidden effect did
  not happen — no request recorded, no file written. A DENY that still opened the
  socket is a failure (SPEC §2, "flagging is not blocking").
- **`SPEC.md` is frozen.** It is a pre-registration. Do not edit it — not even to
  fix the old project name inside it.
- **No criterion is weakened quietly.** If a change makes a SPEC success or kill
  criterion fail, or changes what it measures, that is recorded in `FINDINGS.md`
  as a retraction, in the same PR.
- **`src/bridgeline/verify/attacks.py` is not edited.** It was written from the
  SPEC alone, with the implementation unread, and that is its whole value. New
  attacks go in a separate module whose docstring states how its author was
  blinded — or that they were not.
- **Layer 1 must stand alone.** Anything that makes the acceptance suite depend
  on Layer 2 breaks S4.

## What makes a good PR

- **Tests with it.** New behavior needs a test; a bug fix needs a regression
  test that fails before the change and passes after.
- **Type hints on every function signature.**
- **Match the surrounding style** — comment density, naming, idiom. No
  docstrings on obvious functions.
- **Keep the diff scoped.** No refactoring around a fix.

## Commit messages

A short imperative subject, and a body that explains *why* whenever the diff
does not make it obvious. `git log` has plenty of examples.

## Security issues

Please do not open a public issue for a way to defeat the invariant. See
[SECURITY.md](SECURITY.md).
