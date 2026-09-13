# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-13

### Added
- `bridgeline verify` — the sixteen-attack corpus as a command, runnable from an
  installed package with no API key and no network. The exit code is the verdict.
- K5 evaluated: a live planner produced a schema-valid plan for 13 of 15 benign
  tasks (kill threshold 60%).

### Changed
- Renamed from `crawlgate`. `SPEC.md` keeps the old name, deliberately.
- Layer 2 is now `bouncer-core`, which installs with `pyyaml` alone instead of the
  full MCP SDK.
- A missing model SDK now suggests a `pip install` line that works outside a clone.

### Fixed
- A plan whose `out` or `when` was not a string crashed the parser, or — for a
  numeric `out` — was silently accepted. Both are now rejected with `PlanError`.
