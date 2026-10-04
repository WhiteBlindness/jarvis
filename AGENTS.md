# AGENTS.md

Guidance for anyone changing this repository, human or automated. Read `docs/threat-model.md` and `docs/architecture.md` before changing anything in `crates/jarvis-core` or the protocol.

## What this repository is

A local agent runtime. A long-lived Rust Core is the only component that decides and acts. A contained Python worker proposes typed tool requests over a strict stdio protocol. Requests with side effects wait for a person, who decides through a local RPC client. Every decision is recorded in SQLite.

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

Demo (the Core in one terminal, clients in another):

```bash
cargo run -p jarvis-core -- isolation check --config config/jarvis.example.toml
cargo run -p jarvis-core -- serve --config config/jarvis.example.toml
cargo run -p jarvis-core -- submit "write notes.txt: hello" --config config/jarvis.example.toml
cargo run -p jarvis-core -- approvals list --config config/jarvis.example.toml
cargo run -p jarvis-core -- audit --config config/jarvis.example.toml
```

CI runs all of the above on every pull request. Rust tests also run on Windows. Windows behaviour that CI cannot prove is listed in `docs/windows-validation.md`. On Linux the tests need a kernel with Landlock enabled; on Windows, a real `python.exe` (not the `py` launcher or a virtual environment).

## Invariants

Do not weaken these without an ADR in `docs/decisions/` and an update to the threat model.

1. Execution, policy, approvals, task state, audit and supervision live in Rust. Never in the worker, never in a client or a future UI.
2. No generic execution interface: no tool takes a command line, script, URL or unrestricted path, and no RPC operation runs a tool directly.
3. Workers never name capabilities or approvals. Capabilities are derived in `policy::required_capabilities` by an exhaustive match.
4. Unlisted capabilities are denied. Every call needs at least one capability. A class B capability can never be set to `allow`.
5. Decide, record, then act: the decision (and, for class B, the consumed approval) and `execution_started` are committed in one transaction before a tool runs.
6. An approval is bound by fingerprint to one exact request, granted only by a local client that presents that fingerprint, used at most once, and never survives its session or a restart.
7. State changes and their audit events commit in one transaction. Audit events are append-only; terminal tasks, decided approvals and finished jobs are immutable.
8. Decoding is strict on every interface: unknown fields, unknown types and other protocol versions are rejected.
9. Everything the worker or a client can influence is bounded: frame and request sizes, request and error counts, tool, job and approval time, result size, buffered frames, connections, long polls, worker memory and restarts.
10. The worker starts with a cleared environment, is never started through a shell, runs inside its OS isolation (ADRs 0013, 0014) from its first instruction with no network, no child processes and no files beyond its runtime and source, and is refused by the RPC server. The Core proves the isolation at start-up and does not run a worker without it.
11. The worker package never performs privileged operations itself (`tests/test_boundaries.py` guards this).

## Adding a tool

1. Update the threat model: which class (A, B or C) does it belong to, and why?
2. `jarvis-protocol`: argument and result structs with `deny_unknown_fields`, a `ToolCall` variant, its name in `ToolCall::NAMES`, its arguments in `ToolCall::arguments`, a `ToolResult` variant and `answers`.
3. `jarvis-protocol`: a new `Capability` with its class if no existing one describes the intent.
4. `jarvis-core/src/policy.rs`: map the call to its capabilities.
5. `jarvis-core/src/approval.rs`: describe its arguments for a person in `describe` (display-safe, bounded).
6. `jarvis-tools`: implement it in `Toolbox`, returning typed results and errors without host paths.
7. `jarvis-core/src/gateway.rs`: add tool-specific result checks if the result has invariants.
8. Tests: allowed, denied, invalid arguments, tool failure, and the session test for the full path; for class B also approved, declined and expired.
9. `docs/protocol.md` and the fixtures in `tests/protocol/`, then the Python worker's types.

## Conventions

- Rust edition 2024, `clippy -D warnings`. `unsafe` is forbidden everywhere except `crates/jarvis-sandbox`, where every block carries a `SAFETY` comment. Libraries use `thiserror`; only `main.rs` uses `anyhow`. No `unwrap` or `expect` outside tests.
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
