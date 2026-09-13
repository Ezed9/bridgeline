## What and why

<!-- What does this change, and why is it needed? -->

## Checks

- [ ] `uv run pytest -q` and `uv run ruff check .` pass
- [ ] `uv run bridgeline verify` still exits 0
- [ ] New behaviour or a bug fix comes with a test that failed before this change
- [ ] Tests assert effects (requests, writes), not log lines
- [ ] `SPEC.md` and `src/bridgeline/verify/attacks.py` are untouched
- [ ] If a SPEC criterion's result or meaning changed, `FINDINGS.md` says so
