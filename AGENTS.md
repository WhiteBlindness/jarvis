# AGENTS.md

Guidance for anyone changing this repository, human or automated. Read `docs/threat-model.md` and `docs/architecture.md` before changing anything in `crates/jarvis-core` or the protocol.

## What this repository is

A local agent runtime. The Rust Core is the only component that decides and acts. A Python worker proposes typed tool requests over a strict stdio protocol. Every decision is recorded in SQLite.

## Commands

Rust (from the repository root):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked          # needs python3 (3.11+) on PATH, or JARVIS_TEST_PYTHON
```

Python worker (from `services/intelligence-python`):

```bash
uv sync --locked
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest
```

Demo:

```bash
cargo run -p jarvis-core -- run --config config/jarvis.example.toml
cargo run -p jarvis-core -- audit --config config/jarvis.example.toml
```

CI runs all of the above on every pull request. Rust tests also run on Windows.

## Invariants

Do not weaken these without an ADR in `docs/decisions/` and an update to the threat model.

1. Execution, policy, task state, audit and supervision live in Rust. Never in the worker, never in a future UI.
2. No generic execution interface: no tool takes a command line, script, URL or unrestricted path.
3. Workers never name capabilities. They are derived in `policy::required_capabilities` by an exhaustive match.
4. Unlisted capabilities are denied. Every call needs at least one capability.
5. Decide, record, then act: the decision and `execution_started` are committed before a tool runs.
6. A task transition and its audit events commit in one transaction. Audit events are append-only; terminal tasks are immutable.
7. Decoding is strict on both sides: unknown fields, unknown types and other protocol versions are rejected.
8. Everything the worker can influence is bounded: frame size, request count, error count, tool time, result size, and how long a write to the worker may block.
9. The worker starts with a cleared environment and is never started through a shell.
10. The worker package never performs privileged operations itself (`tests/test_boundaries.py` guards this).

## Adding a tool

1. Update the threat model: which class (A, B or C) does it belong to, and why?
2. `jarvis-protocol`: argument and result structs with `deny_unknown_fields`, a `ToolCall` variant, its name in `ToolCall::NAMES`, a `ToolResult` variant and `answers`.
3. `jarvis-protocol`: a new `Capability` if no existing one describes the intent.
4. `jarvis-core/src/policy.rs`: map the call to its capabilities.
5. `jarvis-tools`: implement it in `Toolbox`, returning typed results and errors without host paths.
6. `jarvis-core/src/gateway.rs`: add tool-specific result checks if the result has invariants.
7. Tests: allowed, denied, invalid arguments, tool failure, and the session test for the full path.
8. `docs/protocol.md` and the fixtures in `tests/protocol/`, then the Python worker's types.

## Conventions

- Rust edition 2024, `unsafe` forbidden, `clippy -D warnings`. Libraries use `thiserror`; only `main.rs` uses `anyhow`. No `unwrap` or `expect` outside tests.
- SQL migrations are append-only: add `NNNN_name.sql` and a `MIGRATIONS` entry. Never edit an applied migration.
- Python: standard library only at runtime, `mypy --strict`, `ruff`. stdout is reserved for protocol frames; logs go to stderr.
- Tests assert behaviour through public interfaces. A failing test is fixed, never skipped.
- Commits use conventional prefixes (`feat`, `fix`, `docs`, `test`, `ci`, `refactor`, `chore`) and explain why.

## Public repository

This repository is public. Write for an engineer reading it for the first time.

- Describe the product, the engineering decisions, the tests and the real limitations.
- Keep implemented and planned work clearly separated. Do not present planned work as existing.
- No speculative claims about scale or security, no secrets, no machine-specific paths or hostnames.
- No notes about how the code was produced, internal tooling, or the history of earlier attempts.

## Out of scope for now

Model routing, voice, remote access, wake-on-LAN, browser automation, personal application integrations, memory, a WASM plugin runtime, shell execution and deployment. See `docs/decisions/0006-defer-ui-voice-integrations.md`.
