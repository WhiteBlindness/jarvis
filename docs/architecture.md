# Architecture

JARVIS separates the code that interprets intent from the code that decides and acts. A Python worker proposes actions as typed requests. The Rust Core validates them, derives the capabilities they need, evaluates policy, executes allowed tools under limits, verifies their output and records every step in SQLite.

This document describes what exists in Phase 1. Planned components are marked as such.

## Components

```
                         config file (TOML)
                                |
+-------------------------------v--------------------------------+
| jarvis-core (Rust binary)                                       |
|                                                                 |
|  runtime     start-up, recovery, shutdown, signal handling      |
|  supervisor  spawn worker, clear env, forward stderr, reap/kill |
|  session     framing, handshake, limits, request pipeline       |
|  policy      capability extraction, policy evaluation           |
|  gateway     timeout, cancellation, panic containment,          |
|              result verification                                |
|  store       SQLite: tasks, audit_events, schema_migrations     |
+---------------------------+-------------------------------------+
            stdin/stdout    |   uses
            (protocol)      |
                            v
+------------------------+   +-----------------------------------+
| Python worker          |   | jarvis-tools                       |
| jarvis_worker          |   |  system.info                       |
|  client  (protocol)    |   |  filesystem.read_fixture           |
|  planner (stub)        |   +-----------------------------------+
+------------------------+
                            jarvis-protocol: shared types, strict
                            decoding, used by core and tools
```

| Crate or package | Responsibility | Knows about |
| --- | --- | --- |
| `crates/jarvis-protocol` | Wire messages, IDs, capabilities, typed tool calls and results, task statuses, audit event kinds, strict decoding | Nothing else in the repository; no I/O |
| `crates/jarvis-tools` | First-party tool implementations behind the `ToolExecutor` trait | The protocol types. Not policy |
| `crates/jarvis-core` | Everything that decides, executes, records and supervises | Protocol and tools |
| `services/intelligence-python` | Worker process: protocol client and a deterministic planner | The wire protocol only |

## Request lifecycle

Every request follows one path. The step that records the decision comes before the step that acts on it.

| Step | Where | On failure |
| --- | --- | --- |
| 1. Read one line, at most `max_frame_bytes` | `framing` | `frame_too_large`, session continues |
| 2. Decode: JSON, object, `protocol`, schema | `jarvis-protocol` | `malformed_frame` (or fatal `unsupported_protocol_version`); no task |
| 3. Check handshake state and session limits | `session` | Fatal `handshake_required` or `limit_exceeded` |
| 4. Create the task (`received`) with `request_received` | `store` | Duplicate `request_id`: `duplicate_request`, no new task |
| 5. Resolve the tool and decode its typed arguments | `ToolCall::from_request` | Task `rejected` with `unknown_tool` or `invalid_arguments` |
| 6. Derive required capabilities | `policy::required_capabilities` | Cannot fail: exhaustive match |
| 7. Evaluate policy | `Policy::evaluate` | Task `denied` or `awaiting_confirmation`; nothing runs |
| 8. Record the decision and `execution_started` | `store`, one transaction | Store error stops the Core; the tool never runs |
| 9. Execute under timeout and cancellation | `gateway` | Task `timed_out`, `cancelled` or `failed` |
| 10. Verify the result | `gateway` | Task `failed` with `result_rejected` |
| 11. Record the outcome and `execution_finished` | `store`, one transaction | Store error stops the Core |
| 12. Send `tool_response` | `session` | Worker gone: session ends |

## Task state machine

```
received ──┬─► rejected                       (unknown tool, invalid arguments)
           ├─► denied                         (policy)
           ├─► awaiting_confirmation ──► expired   (session ended / restart)
           └─► executing ──┬─► completed
                           ├─► failed         (tool error, result rejected)
                           ├─► timed_out
                           └─► cancelled      (shutdown)

received | executing ──► interrupted          (found open at start-up)
```

The store checks the expected source state of every transition, inside the same transaction that appends the audit events. The schema adds a second line of defence: terminal tasks and task identity columns cannot be updated, tasks cannot be deleted, and audit events cannot be updated or deleted.

## Process model

- `jarvis-core run` starts one supervised worker session and exits when it ends. A long-lived daemon with an RPC endpoint for a dashboard is planned, not built.
- The worker is started directly from the config's program and argument list, with no shell. Its environment is cleared apart from `PATH` and `SYSTEMROOT`, plus any variables the config names explicitly.
- The worker's stdout carries protocol frames, its stdin carries replies, and its stderr is forwarded to the Core's log as escaped, length-limited lines.
- A worker that does not complete the handshake in time is killed. At the end of a session the Core closes the worker's stdin, waits for the configured grace period, and then kills it if it is still running. The exit status is recorded either way.
- On `SIGINT` or `SIGTERM` (Ctrl+C on Windows) the Core cancels the running tool, records it as `cancelled`, ends the session and goes through the same stop sequence.

## Concurrency

The Core runs on Tokio. A session handles one request at a time, which keeps ordering obvious and doubles as a limit: a worker cannot have more than one tool running. Tools run in their own Tokio task so that a panic is contained and a timeout or cancellation can abort them. SQLite work runs on the blocking pool through `Store::call`, so disk latency never stalls the async runtime.

## Durability

- SQLite in WAL mode with `synchronous=FULL`: a committed transaction survives a crash or power loss.
- A task's state change and its audit events commit in one transaction.
- On start-up, tasks left in `received` or `executing` become `interrupted`, and tasks left in `awaiting_confirmation` become `expired`. Each gets a `task_recovered` event.
- A lock file next to the database stops a second Core from opening it, so recovery never closes another live Core's tasks. `jarvis-core tasks` and `jarvis-core audit` open the database read-only and do not need the lock.
- Migrations are embedded SQL files applied in order and recorded in `schema_migrations`. A database from a newer Core is refused.

## Observability

- Structured logs on stderr through `tracing`, as text or JSON (`--log-format json`), filtered with `JARVIS_LOG` (for example `JARVIS_LOG=debug`).
- The audit log is typed: every row deserialises back into `AuditEventKind`, and the `kind` column must match the stored event.
- `jarvis-core tasks` and `jarvis-core audit` print the durable state, as text or as JSON lines.

## Testing strategy

| Layer | What is tested | Where |
| --- | --- | --- |
| Protocol | Syntax rules, strict decoding, version handling, contract fixtures shared with Python, property tests on arbitrary bytes | `crates/jarvis-protocol` |
| Tools | Fixture containment, symlink escape, size and encoding limits, no identifying data | `crates/jarvis-tools` |
| Store | Migrations, reopen, append-only audit, immutable terminal tasks, recovery, locking | `crates/jarvis-core/src/store/tests.rs` |
| Policy and framing | Default deny, strictest-wins property, framing against a reference splitter for any chunking | Unit tests |
| Session | Every failure path over in-memory pipes with an untrusted peer | `crates/jarvis-core/tests/session.rs` |
| Processes | Real binary with the real Python worker, a hostile worker, crashes, handshake timeout, signals, restart | `crates/jarvis-core/tests/process.rs` |
| Worker | Protocol client, planner, contract fixtures, a guard that the package performs no privileged operations | `services/intelligence-python/tests` |

## Not built yet

- Approval channel for `require_confirmation` decisions.
- Long-lived daemon, dashboard RPC and the dashboard itself.
- Model-backed planning, speech, retrieval and memory.
- OS-level sandboxing of the worker.
- Any tool with side effects.
