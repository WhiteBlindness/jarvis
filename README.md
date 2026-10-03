# JARVIS

A local-first agent runtime with a Rust execution core, typed capabilities and Python intelligence workers.

**Status:** Phase 1, the foundation. The Rust Core, the versioned protocol, the capability policy, durable task state, the audit log and a deterministic Python worker are implemented and tested on Linux and Windows. There is no language model, UI, voice or personal integration yet.

## Why it exists

The usual way to let an assistant act on a computer is to hand it a shell. Once a model can choose a command line, every permission check written around commands can be bypassed by quoting, chaining or picking another binary, and nothing records why an action happened.

JARVIS starts from the opposite end: the model never gets operating system access. It can only propose typed requests such as `system.info {}` or `filesystem.read_fixture { "path": "welcome.txt" }`. A Rust Core decides whether each request may run, runs it under limits, and records the decision before acting on it. The goal is autonomy that is safe, observable and recoverable.

## What is technically interesting

- **Capabilities, not commands.** The worker names a tool and its arguments, never a permission. The Core derives the required capabilities through an exhaustive `match`, so a new tool without a declared capability does not compile. Unlisted capabilities are denied.
- **Decide, record, then act.** The policy decision and `execution_started` are committed to SQLite before a tool runs. If that write fails, nothing runs. A test injects that failure to prove it.
- **Integrity in the schema, not only in code.** Triggers make the audit log append-only and terminal tasks immutable. A task transition and its audit events commit in one transaction.
- **An untrusted worker by design.** The Python worker talks over a strict, versioned, line-delimited JSON protocol on its own stdin and stdout. Unknown fields such as `"approved": true` are rejected rather than ignored. Contract fixtures are checked by both the Rust and the Python test suites.
- **Supervision and limits.** No shell, a cleared environment, a handshake timeout, a per-tool timeout that aborts the tool's task, contained panics, a frame-size limit enforced while reading, a write timeout for a worker that stops reading, a request cap, an error budget, and a kill after the shutdown grace period.
- **Crash recovery.** WAL with `synchronous=FULL`, an exclusive lock file, and start-up recovery that marks tasks left open by a crash as `interrupted`.
- **Adversarial tests.** A hostile worker process tries smuggled approvals, path traversal, invented tools and replays against the real binary, and must see every attempt refused.

## Architecture

```
Python worker  ── tool_request ──►  Rust Core                              SQLite
(proposes)        (stdio, JSON)     decode → capabilities → policy  ──►  tasks
               ◄─ tool_response ──  → record → Tool Gateway → verify ──►  audit_events
                                                  │
                                            typed tools
                                    (system.info, filesystem.read_fixture)
```

| Component | Language | Role |
| --- | --- | --- |
| `crates/jarvis-protocol` | Rust | Versioned wire types, closed tool and capability sets, strict decoding |
| `crates/jarvis-core` | Rust | Config, policy, Tool Gateway, session, SQLite store, worker supervision, CLI |
| `crates/jarvis-tools` | Rust | First-party tools behind a `ToolExecutor` trait |
| `services/intelligence-python` | Python | Worker: protocol client and a deterministic planner (standard library only) |

Details: [architecture](docs/architecture.md), [protocol](docs/protocol.md), [decisions](docs/decisions/README.md).

## Security model

Every capability belongs to one class:

| Class | Meaning | Today |
| --- | --- | --- |
| A. Allow automatically | Read-only, bounded, no personal data | `system.info`, `filesystem.read.fixture` |
| B. Require confirmation | Side effects that can be undone, or personal data | Policy supports it; no such tool exists yet |
| C. Prohibited | Shell, process launch, unrestricted filesystem or network, credentials, the Core's own state | No tool exists, and the protocol cannot express them |

The main limitation is stated plainly in the [threat model](docs/threat-model.md): the worker is not yet sandboxed by the operating system. The protocol cannot be used to bypass policy, but compromised worker code could call OS APIs directly. OS containment is planned.

## Implemented

- Rust Core with start-up, recovery, graceful shutdown on signals, structured logs (text or JSON) and a TOML config with range-checked limits.
- Versioned protocol with strict decoding on both sides, shared contract fixtures and property tests on arbitrary input.
- Capability policy with `allow`, `require_confirmation` and `deny`, default deny, strictest decision wins.
- Tool Gateway with timeouts, cancellation, panic containment and result verification.
- Two harmless tools: `system.info` (no hostname, username, environment or paths) and `filesystem.read_fixture` (one configured directory, symlink escapes refused).
- SQLite store with migrations, task state machine, append-only audit log, replay protection and crash recovery.
- Supervised Python worker with a deterministic planner, and CLI commands to inspect tasks and the audit log.

## Planned

- An approval channel so a person can confirm class B requests.
- A long-lived Core with an RPC interface, and a TypeScript dashboard on top of it.
- Model-backed planning in the Python worker, then speech and retrieval.
- OS-level sandboxing of the worker.
- Tools with side effects, each added through the threat model first.

## Stack

Rust 2024 (Tokio, rusqlite with bundled SQLite, serde, clap, tracing) · Python 3.11+ standard library · pytest, mypy, ruff, uv · proptest · GitHub Actions on Linux and Windows

## Run it

Requirements: Rust 1.89 or newer and Python 3.11 or newer. Nothing else: SQLite is compiled in and the worker has no dependencies.

```bash
cargo run -p jarvis-core -- run   --config config/jarvis.example.toml
cargo run -p jarvis-core -- tasks --config config/jarvis.example.toml
cargo run -p jarvis-core -- audit --config config/jarvis.example.toml
```

On Windows, set `program = "python"` in `config/jarvis.example.toml`.

The example asks the worker to "describe the runtime, then read welcome.txt". The audit log shows each decision being recorded before the tool runs:

```
 4  request_received    01a0fe69-a91a-…  {"request_id":"req-aa5f…","tool":"system.info"}
 5  policy_evaluated    01a0fe69-a91a-…  {"capabilities":["system.info"],"decision":"allow"}
 6  execution_started   01a0fe69-a91a-…  {"tool":"system.info"}
 7  execution_finished  01a0fe69-a91a-…  {"duration_ms":0,"error":null,"status":"completed"}
```

To see the policy refuse something, change the goal in the config to `read ../Cargo.toml` (rejected as an invalid path) or set `"system.info" = "deny"`.

## Test it

```bash
cargo test --workspace          # needs python3 on PATH, or set JARVIS_TEST_PYTHON

cd services/intelligence-python
uv sync && uv run pytest && uv run mypy && uv run ruff check .
```

The Rust suite covers allowed, denied and confirmation-required requests, malformed frames, unknown tools, invalid arguments and path traversal, tool failure, timeout and cancellation, audit and task durability across reopen and restart, crash recovery, protocol version mismatch, and a hostile worker trying to bypass policy. CI runs it on Linux and Windows, along with the Python checks, the documented demo and a secret scan.

## Repository layout

```
crates/            jarvis-protocol, jarvis-core, jarvis-tools
services/          intelligence-python (the worker)
config/            example configuration
docs/              architecture, protocol, threat model, decisions
tests/protocol/    contract fixtures shared by Rust and Python
tests/fixtures/    the fixture directory used by the demo
```
