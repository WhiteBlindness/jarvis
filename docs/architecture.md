# Architecture

JARVIS separates the code that interprets intent from the code that decides and acts. A Python worker proposes actions as typed requests. A long-lived Rust Core validates them, derives the capabilities they need, evaluates policy, asks a person when policy requires it, executes allowed tools under limits, verifies their output and records every step in SQLite. Local clients talk to the Core over a small typed RPC interface.

This document describes what exists in Phase 2. Planned components are marked as such.

## Components

```
   jarvis-core CLI (client commands)            config file (TOML)
          |  local RPC (Unix socket / named pipe)      |
+---------v--------------------------------------------v-----------+
| jarvis-core serve (long-lived Rust process)                       |
|                                                                   |
|  daemon      start-up, recovery, worker restarts, shutdown        |
|  rpc         peer identification, strict requests, long polls     |
|  supervisor  spawn and contain the worker, forward stderr, kill   |
|  session     handshake, jobs, request pipeline, limits            |
|  policy      capability extraction, policy evaluation             |
|  approval    fingerprints, display-safe descriptions, wake-ups    |
|  gateway     timeout, cancellation, panic containment, checks     |
|  store       SQLite: jobs, tasks, approvals, audit_events         |
+----------------------+-------------------------------+------------+
      stdin/stdout      |                               | uses
      (worker protocol) |                               v
+---------------------- v ---+   +-------------------------------------+
| Python worker (contained)  |   | jarvis-tools                        |
|  client  (protocol, jobs)  |   |  system.info                        |
|  planner (deterministic)   |   |  filesystem.read_fixture            |
+----------------------------+   |  workspace.write_file               |
                                 +-------------------------------------+
   jarvis-sandbox: OS containment (the only crate with unsafe code)
   jarvis-protocol: wire types for both protocols, strict decoding
```

| Crate or package | Responsibility | Knows about |
| --- | --- | --- |
| `crates/jarvis-protocol` | Worker protocol v2 and local RPC v1: messages, IDs, capabilities, typed tool calls and results, task, job and approval statuses, audit event kinds, strict decoding | Nothing else in the repository; no I/O |
| `crates/jarvis-tools` | First-party tools behind the `ToolExecutor` trait | The protocol types. Not policy |
| `crates/jarvis-sandbox` | Worker containment (job objects, tokens, process groups), the owner-only named pipe, peer process helpers | The OS |
| `crates/jarvis-core` | Everything that decides, executes, records, supervises and serves clients; the CLI | Protocol, tools and sandbox |
| `services/intelligence-python` | Worker process: protocol client, job loop and a deterministic planner | The worker protocol only |

## A job, end to end

1. A client submits a goal (`jarvis-core submit "write notes.txt: buy milk"`). The RPC server records a `queued` job and wakes the session.
2. The session claims the job (`running`) and sends it to the worker.
3. The worker plans the goal and sends one `tool_request` at a time, each naming the job.
4. Each request becomes a task and goes through the request lifecycle below.
5. The worker sends `job_result` with an outcome and a one-line summary; the job becomes `completed` or `failed`. A client waiting on the job (`--wait`) gets the result.

## Request lifecycle

Every request follows one path. The step that records a decision comes before the step that acts on it.

| Step | Where | On failure |
| --- | --- | --- |
| 1. Read one line, at most `max_frame_bytes` | `framing` | `frame_too_large`, session continues |
| 2. Decode: JSON, object, `protocol`, schema | `jarvis-protocol` | `malformed_frame` (or fatal `unsupported_protocol_version`); no task |
| 3. Check handshake, job and session limits | `session` | `unexpected_message` for another job; fatal `handshake_required` or `limit_exceeded` |
| 4. Create the task (`received`) with `request_received` | `store` | Duplicate `request_id`: `duplicate_request`, no new task |
| 5. Resolve the tool and decode its typed arguments | `ToolCall::from_request` | Task `rejected` with `unknown_tool` or `invalid_arguments` |
| 6. Derive required capabilities | `policy::required_capabilities` | Cannot fail: exhaustive match |
| 7. Evaluate policy | `Policy::evaluate` | Task `denied`; nothing runs |
| 8a. `allow`: record the decision and `execution_started` | `store`, one transaction | Store error stops the Core; the tool never runs |
| 8b. `require_confirmation`: record the approval request; wait for a decision, expiry, the worker leaving or shutdown | `store`, `approval`, `session` | Denied: task `denied`, reply `declined`. Expired: task `expired`, reply `expired` |
| 8c. Granted: consume the approval, move the task to `executing`, record `approval_consumed` and `execution_started` | `store`, one transaction | Any mismatch or a store error: nothing runs |
| 9. Execute under timeout and cancellation | `gateway` | Task `timed_out`, `cancelled` or `failed` |
| 10. Verify the result | `gateway` | Task `failed` with `result_rejected` |
| 11. Record the outcome and `execution_finished` | `store`, one transaction | Store error stops the Core |
| 12. Send `tool_response` | `session` | Worker gone, or not reading within the write timeout: session ends |

While a request waits for a person the session keeps reading the worker's stream, so it notices the worker leaving. Up to 16 frames that arrive meanwhile are buffered and handled afterwards, in order; more ends the session.

## State machines

Tasks:

```
received ──┬─► rejected                       (unknown tool, invalid arguments)
           ├─► denied                         (policy)
           ├─► awaiting_confirmation ──┬─► executing  (approval consumed)
           │                           ├─► denied     (a person refused)
           │                           └─► expired    (time-to-live, session end, restart)
           └─► executing ──┬─► completed
                           ├─► failed         (tool error, result rejected)
                           ├─► timed_out
                           └─► cancelled      (shutdown)

received | executing ──► interrupted          (found open at start-up)
```

Approvals: `pending → granted → consumed`, `pending → denied`, `pending | granted → expired`.

Jobs: `queued → running → completed | failed | interrupted`, `queued → cancelled` (at start-up).

The store checks the expected source state of every transition inside the transaction that appends its audit events. The schema adds a second line of defence: triggers reject changes to identity columns, terminal tasks, decided approvals and finished jobs, deletions, and any change to audit events.

## Approvals

- The fingerprint is SHA-256 over a canonical JSON encoding of the task ID, request ID, tool, normalised arguments and sorted capabilities (ADR 0008).
- A client approves with the approval ID and the fingerprint it displayed. Granting is a conditional update that only records the decision.
- The session is woken by an in-memory signal, but always re-reads the approval from the database before acting. The database is the only source of truth.
- Consumption happens in the same transaction that starts execution, and checks the fingerprint against the one the session computed from the call it is about to run.
- Approvals expire after `approvals.ttl_ms`, when their session ends, and at start-up (ADR 0009).

## Process model

- `jarvis-core serve` is the long-lived Core (ADR 0011). It takes the database lock, migrates, recovers, binds the RPC endpoint, prints `ready <endpoint>` and supervises the worker.
- The worker is started directly from the configured program and arguments, without a shell, with an environment cleared apart from `PATH` and `SYSTEMROOT`. Containment is applied before it runs any code (ADR 0012). Its stdout carries protocol frames, its stdin carries replies, and its stderr is forwarded to the Core's log as escaped, length-limited lines.
- A worker that does not complete the handshake, or a job that runs past `job_timeout`, is killed. When the worker stops for any reason, the session expires its approvals and interrupts its job, and the supervisor restarts it with exponential backoff, within a restart budget per time window. Once the budget is spent the Core reports itself unhealthy and refuses jobs.
- On SIGINT, SIGTERM, Ctrl+C, Ctrl+Break or console close, or an authorised `shutdown` request, the Core cancels the running tool, expires pending approvals, closes the worker's stdin, kills it after the grace period, stops the RPC server and records `core_stopped`. A second signal exits immediately.
- The client commands (`health`, `submit`, `job`, `jobs`, `approvals`, `shutdown`) connect to the endpoint named in the same config file. `tasks` and `audit` read the database directly, read-only.

## Local RPC

- Unix domain socket in an owner-only directory, or a named pipe that only the current user can open (ADR 0010). No TCP.
- Every connection is identified by the OS before a request is read. Unidentifiable peers, other users (Unix) and the worker are refused and audited.
- One request at a time per connection, at most 16 KiB each, idle timeout 30 s, at most 16 connections, long polls up to 60 s. Long polls wait on a change counter that the session and the RPC server bump, then re-read the database.

## Concurrency

The Core runs on Tokio. A session handles one request at a time: a worker can never have more than one tool running or more than one request waiting for a person. Tools run in their own Tokio task so that a panic is contained and a timeout or cancellation can abort them. SQLite work runs on the blocking pool through `Store::call`. RPC connections are served concurrently, each in its own task.

## Durability

- SQLite in WAL mode with `synchronous=FULL`: a committed transaction survives a crash or power loss.
- A state change and its audit events commit in one transaction.
- Start-up recovery, in one transaction: approvals still pending or granted become `expired`; tasks left `received` or `executing` become `interrupted`, tasks left `awaiting_confirmation` become `expired`; running jobs become `interrupted` and queued jobs `cancelled`.
- The guarantee for approvals is *at most once*: once consumed, an approval can never be used again. A side effect interrupted by a crash may or may not have happened; its task says `interrupted`.
- A lock file next to the database stops a second Core from opening it. On Unix the Core also refuses to start if another Core answers on its socket.
- `recursive_triggers` is on, so `INSERT OR REPLACE` fires the delete triggers and cannot rewrite protected rows.
- Migrations are embedded SQL files applied in order and recorded in `schema_migrations`. A database from a newer Core is refused.

## Observability

- Structured logs on stderr through `tracing`, as text or JSON (`--log-format json`), filtered with `JARVIS_LOG`.
- The audit log is typed: every row deserialises back into `AuditEventKind`. Besides the task pipeline it records jobs, approvals (`approval_requested`, `_granted`, `_denied`, `_expired`, `_consumed`), the worker's life (`worker_spawned`, `_exited`, `_killed`, `_restart_scheduled`, `_restart_abandoned`), refused RPC clients and the Core's start and stop.
- `jarvis-core health` reports the worker's state, pid, restarts and containment, queued jobs and pending approvals.

## Testing strategy

| Layer | What is tested | Where |
| --- | --- | --- |
| Protocol | Syntax rules, strict decoding of both protocols, version handling, contract fixtures shared with Python, property tests on arbitrary bytes | `crates/jarvis-protocol` |
| Tools | Fixture containment; workspace writes against `..`, symlinks, junctions (Windows), hard links, a directory swapped for a link mid-write, size limits | `crates/jarvis-tools` |
| Containment | Memory limit, killing the tree, descendants that leave the process group (Linux), no child processes, low integrity and the owner-only pipe (Windows) | `crates/jarvis-sandbox/tests` |
| Store | Migrations, append-only audit, triggers on every table, approval grant, deny, expiry and single use, failure inside the consuming transaction, recovery | `crates/jarvis-core/src/store/tests.rs` |
| Policy, restarts, config | Default deny, class ceilings, backoff and budget | Unit tests |
| Session | Every failure path over in-memory pipes with an untrusted peer, including approvals and database failures before and after execution | `crates/jarvis-core/tests/session.rs` |
| Processes | The real binary as a daemon with the real Python worker and a hostile worker: CLI approvals, restarts, crashes, signals, recovery, the RPC interface | `crates/jarvis-core/tests/process.rs` |
| Worker | Protocol client, job loop, planner, contract fixtures, a guard that the package performs no privileged operations | `services/intelligence-python/tests` |

## Not built yet

- Dashboard and any client other than the CLI.
- Model-backed planning, speech, retrieval and memory.
- A sandbox for the worker stronger than the current containment.
- More than one worker, and tools beyond the three above.
