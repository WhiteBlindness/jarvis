# Architecture

JARVIS separates the code that interprets intent from the code that decides and acts. A Python worker proposes actions as typed requests. A long-lived Rust Core validates them, derives the capabilities they need, evaluates policy, asks a person when policy requires it, executes allowed tools under limits, verifies their output and records every step in SQLite. Local clients talk to the Core over a small typed RPC interface.

This document describes what exists in Phase 3. Planned components are marked as such.

## Components

```
   jarvis-core CLI (client commands)            config file (TOML)
          |  local RPC (Unix socket / named pipe)      |
+---------v--------------------------------------------v-----------+
| jarvis-core serve (long-lived Rust process)                       |
|                                                                   |
|  daemon      start-up, recovery, worker restarts, shutdown        |
|  rpc         peer identification, strict requests, long polls     |
|  isolation   worker confinement; start-up check that it holds     |
|  supervisor  start the isolated worker, forward stderr, kill      |
|  governor    optional: hold job starts while a game runs          |
|  inference   optional: local model broker, conversations          |
|  session     handshake, jobs, request pipeline, limits            |
|  policy      capability extraction, policy evaluation             |
|  approval    fingerprints, display-safe descriptions, wake-ups    |
|  gateway     timeout, cancellation, panic containment, checks     |
|  store       SQLite: jobs, tasks, approvals, audit_events         |
+----------------------+-------------------------------+------------+
      stdin/stdout      |                               | uses
      (worker protocol) |                               v
+=====================  v  ===+  +-------------------------------------+
| OS isolation boundary        |  | jarvis-tools                        |
|  Windows: AppContainer, job  |  |  system.info                        |
|  Linux: Landlock + seccomp   |  |  filesystem.read_fixture            |
| +--------------------------+ |  |  workspace.write_file               |
| | Python worker            | |  +-------------------------------------+
| |  client  (protocol, jobs)| |
| |  planner (deterministic) | |
| +--------------------------+ |
+==============================+
   jarvis-sandbox: starts the worker inside the boundary (the only crate with unsafe code)
   jarvis-protocol: wire types for both protocols, strict decoding

   inference, when configured (ADR 0021):

   desktop app / CLI --RPC--> Core (inference) --loopback HTTP, per-start key--> model server
   (Tauri, an RPC client)       |                                                 (llama.cpp, no tools)
                                +--> chat database (SQLite, separate from the audit database)
```

The model server and the desktop app are outside the worker's boundary and never talk to it. The worker does not see the model, and the model has no tools.

| Crate or package | Responsibility | Knows about |
| --- | --- | --- |
| `crates/jarvis-protocol` | Worker protocol v2 and local RPC v3: messages, IDs, capabilities, typed tool calls and results, task, job and approval statuses, conversation types, audit event kinds, strict decoding | Nothing else in the repository; no I/O |
| `crates/jarvis-tools` | First-party tools behind the `ToolExecutor` trait | The protocol types. Not policy |
| `crates/jarvis-sandbox` | Starts the worker under a `Confinement`: AppContainer, job, handle list and mitigations (Windows); Landlock, seccomp and process controls (Linux). Also the owner-only named pipe and peer process helpers | The OS |
| `crates/jarvis-core` | Everything that decides, executes, records, supervises and serves clients; the CLI. Its `inference` module starts and talks to the model server, owns the conversation database and builds prompts | Protocol, tools and sandbox |
| `apps/donna` | Desktop client (Tauri 2). An RPC client like the CLI: it holds no policy, approvals or state of its own, renders model text without HTML and never parses it for actions (ADR 0021) | The RPC interface only |
| `services/intelligence-python` | Worker process: protocol client, job loop and a deterministic planner | The worker protocol only |

## A job, end to end

1. A client submits a goal (`jarvis-core submit "write notes.txt: buy milk"`). The RPC server records a `queued` job and wakes the session.
2. The session claims the job (`running`) and sends it to the worker.
3. The worker plans the goal and sends one `tool_request` at a time, each naming the job.
4. Each request becomes a task and goes through the request lifecycle below.
5. The worker sends `job_result` with an outcome and a one-line summary; the job becomes `completed` or `failed`. A client waiting on the job (`--wait`) gets the result.

## A conversation, end to end

This path exists only when `[inference]` is configured (ADR 0021). It never touches the policy, the worker or the approval store, except through the optional last step.

1. A client sends `chat_send` with a message and, for a new conversation, no conversation id. The RPC server validates the text (`ChatText`), checks that no reply is being written and that no game holds the model, stores the person's message and an empty reply in the chat database in one transaction, and answers with a `turn_id`.
2. In the background the Core makes sure the model server is running: it checks the model file's SHA-256 against the configuration, starts the server with a cleared environment under a job, waits until it answers, and records `inference_loaded`.
3. The Core builds the prompt from the persona, the language rule and as much of the conversation's history as fits the context, and sends it to the server over loopback with the per-start key. It reads the streamed answer under size and time limits and appends the text to the reply as it arrives.
4. The client polls `chat_poll` with a byte cursor. Each poll returns the text after the cursor, and waits for new text when asked to. The stream has its own wake-up signal, so it does not wake clients waiting on approvals.
5. When the stream ends the reply becomes final (`complete`, or `cancelled` or `failed`, with the text so far kept) and is stored with its measurements. If the person's own message asked for something to be copied and the reply holds one clean clipboard block, the final `chat_delta` also carries it as `proposal`.
6. Optionally, the person presses a button in the client, which submits the proposal with `submit_clipboard_job`. The Core keeps the text as a temporary payload and queues the job `copy payload:<id>:<sha256>`; the text is in no job, task or audit record (ADR 0022). From there it is the normal path: the worker plans a write that names the payload, policy requires confirmation, and the person approves the exact text in the approval inbox. The Core resolves the payload to show it and again just before the write, and refuses if it is gone or no longer has the approved SHA-256. The payload is deleted when the job ends.

While a configured game runs and the governor is enabled, the Core stops the server (or switches to the fallback model, if configured). A reply being written is cancelled and kept as far as it got.

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

Jobs: `queued → running → completed | failed | interrupted`, and `running → queued` when the worker or the Core stopped and the job may be resumed (ADR 0015). A job is claimed at most `max_job_attempts` times. `cancelled` exists in the schema but nothing produces it.

The store checks the expected source state of every transition inside the transaction that appends its audit events. The schema adds a second line of defence: triggers reject changes to identity columns, terminal tasks, decided approvals and finished jobs, deletions, and any change to audit events.

## Approvals

- The fingerprint is SHA-256 over a canonical JSON encoding of the task ID, request ID, tool, normalised arguments and sorted capabilities (ADR 0008).
- A client approves with the approval ID and the fingerprint it displayed. Granting is a conditional update that only records the decision.
- The session is woken by an in-memory signal, but always re-reads the approval from the database before acting. The database is the only source of truth.
- Consumption happens in the same transaction that starts execution, and checks the fingerprint against the one the session computed from the call it is about to run.
- Approvals expire after `approvals.ttl_ms`, when their session ends, and at start-up (ADR 0009).

## Process model

- `jarvis-core serve` is the long-lived Core (ADR 0011). It takes the database lock, migrates, recovers, binds the RPC endpoint, prints `ready <endpoint>` and supervises the worker.
- Before the first worker starts, `isolation::verify` runs a probe under the worker's exact isolation and checks that it cannot reach a loopback listener, send a datagram, read a file next to the database, list the home directory (when one is found) or start a process. The Core observes the loopback and file results itself; the home and process results come from the probe's own report. If any check fails, `serve` stops with an error (ADR 0013).
- The worker is started directly from the resolved absolute program path and the configured arguments, without a shell, with an environment cleared apart from `PATH` and `SYSTEMROOT` (plus, on Windows, the profile variables an AppContainer launch requires). Every isolation control is in force before it runs any code (ADRs 0013, 0014): it can read its interpreter and its source directory and no other user files, can write nowhere (on Windows, nowhere but its own AppContainer folder, emptied before every start), and has no network by design (the start-up check covers loopback only) and no child processes. On Windows it can still read system files and registry keys open to every AppContainer, including parts of `HKEY_CURRENT_USER`, and can obtain a screen device context (ADR 0013). Its stdout carries protocol frames, its stdin carries replies, and its stderr is forwarded to the Core's log as escaped, length-limited lines.
- A worker that does not complete the handshake, or a job that runs past `job_timeout`, is killed. When the worker stops for any reason, the session expires its approvals and either puts its job back in the queue or ends it (ADR 0015), and the supervisor restarts the worker with exponential backoff, within a restart budget per time window. Once the budget is spent the Core reports itself unhealthy and refuses jobs.
- With `[governor]` enabled (ADR 0016), a task reads the process list every `poll_ms` and publishes whether queued jobs may start. The Core starts held and the gate is closed until the first reading. Each session reads the gate before it claims a job and does not claim while it is closed, so a held job is not counted as an attempt and its job timer never starts; jobs already running are left alone. A hold is never ended by time: after `alert_after_ms` it is flagged overdue and one event is recorded. A read that takes longer than `poll_ms` counts as failed (the jobs are held) and at most one read is in flight; a hold closes the gate before it is recorded, a release is recorded before the gate opens. The governor does not exist when it is disabled, and the gate is open.
- On SIGINT, SIGTERM, Ctrl+C, Ctrl+Break or console close, or an authorised `shutdown` request, the Core cancels the running tool, expires pending approvals, closes the worker's stdin, kills it after the grace period, stops the RPC server and records `core_stopped`. A second signal exits immediately.
- With `[inference]` configured (ADR 0021), the Core starts the model server (`llama-server`) on demand, or at start-up when `load_on_start` is set. It is started like the Session Agent: from an absolute path in the configuration, never through a shell, with a cleared environment, no child processes, a commit limit and a kill-on-close job, so it dies with the Core. It binds `127.0.0.1` on a port chosen at each start and requires a key generated for that start. The RPC server refuses connections from its process. It is not isolated from the user, because it needs the GPU. The Core hashes the model file before its first load and refuses one that does not match the configuration.
- `serve --exit-with <pid>` makes the Core follow one process: it holds a handle to it (on Windows, so a reused process ID is never mistaken for it) and stops as on Ctrl+C once it has exited. The desktop app passes its own process when it starts the Core, so a Core it started never outlives it; a Core started any other way is unaffected, and the app never stops one it did not start.
- After each model load the Core generates a few tokens and records the measured speed. A model on the GPU below `slow_below_tokens_per_second` is reported as `slow`: on Windows the system can place part of a model's GPU memory in system memory, which the model server's own checks do not see and which cuts generation speed about threefold.
- The client commands (`health`, `submit`, `job`, `jobs`, `approvals`, `chat`, `shutdown`) connect to the endpoint named in the same config file. `tasks` and `audit` read the database directly, read-only.

## Local RPC

- Unix domain socket in an owner-only directory, or a named pipe that only the current user can open (ADR 0010). No TCP.
- The isolated worker cannot reach the endpoint at all: it has no sockets on Linux, and its package SID is not in the pipe's DACL on Windows.
- Every connection is identified by the OS before a request is read. Unidentifiable peers, other users (Unix), restricted tokens (Windows: AppContainer or below medium integrity) and the worker are refused and audited.
- One request at a time per connection, at most 16 KiB each, idle timeout 30 s, at most 16 connections, long polls up to 60 s. Long polls wait on a change counter that the session and the RPC server bump, then re-read the database.

## Concurrency

The Core runs on Tokio. A session handles one request at a time: a worker can never have more than one tool running or more than one request waiting for a person. Tools run in their own Tokio task so that a panic is contained and a timeout or cancellation can abort them. SQLite work runs on the blocking pool through `Store::call`. RPC connections are served concurrently, each in its own task.

## Durability

- SQLite in WAL mode with `synchronous=FULL`: a committed transaction survives a crash or power loss.
- A state change and its audit events commit in one transaction.
- Start-up recovery, in one transaction: approvals still pending or granted become `expired`; tasks left `received` or `executing` become `interrupted`, tasks left `awaiting_confirmation` become `expired`; queued jobs stay queued, and a running job is settled by the same function a session uses when it ends (`requeue_or_close`, ADR 0015) before the open tasks are rewritten. The decision reads the `execution_started` event and the task's final status, so it does not depend on that order; settling first records the quarantine before the task rewrite.
- The guarantee for approvals is *at most once*: once consumed, an approval can never be used again. A side effect interrupted by a crash may or may not have happened; its task says `interrupted`, and its job is quarantined instead of resumed.
- Resuming a job never runs a step whose completion is recorded, and never runs one whose outcome is unknown (anything that started and did not end `completed` or `failed` with an error the tool reported). It is not exactly-once. Every task created for a job is recorded with the attempt and position that created it in an insert-only ledger (`job_steps`). When a later attempt asks for a position whose earlier task completed, and the request, current policy and the stored result all still check out, the Core answers with the stored result and records `step_replayed`. Otherwise the job fails.
- Conversations live in their own SQLite file (`chat_database`), not in the audit database, because a person must be able to delete what they said and the audit log is append-only. It is opened with `secure_delete` on; deleting a conversation, or all of them, removes the rows and truncates the write-ahead log. Retention (`retention_days`) deletes conversations not updated for that long. A reply found unfinished at start-up becomes `interrupted`. The worker's isolation lists the file and the persona as protected paths, so no grant may contain them.
- A lock file next to the database stops a second Core from opening it. On Unix the Core also refuses to start if another Core answers on its socket.
- `recursive_triggers` is on, so `INSERT OR REPLACE` fires the delete triggers and cannot rewrite protected rows.
- Migrations are embedded SQL files applied in order and recorded in `schema_migrations`. A database from a newer Core is refused.

## Observability

- Structured logs on stderr through `tracing`, as text or JSON (`--log-format json`), filtered with `JARVIS_LOG`.
- The audit log is typed: every row deserialises back into `AuditEventKind`. Besides the task pipeline it records jobs, approvals (`approval_requested`, `_granted`, `_denied`, `_expired`, `_consumed`), the worker's life (`worker_spawned`, `_exited`, `_killed`, `_restart_scheduled`, `_restart_abandoned`), the governor (`governor_hold`, `governor_released`, `governor_hold_overdue`), refused RPC clients, the model server (`inference_loaded` with the profile, model SHA-256, context size, GPU layers and load time; `inference_stopped` with the reason) and the Core's start and stop. Conversation text is never recorded in the audit log.
- `jarvis-core health` reports the worker's state, pid, restarts and containment, the governor (off, open, held with its reason, or releasing, how long, and whether the hold is overdue), queued jobs and pending approvals.

## Testing strategy

| Layer | What is tested | Where |
| --- | --- | --- |
| Protocol | Syntax rules, strict decoding of both protocols, version handling, contract fixtures shared with Python, property tests on arbitrary bytes | `crates/jarvis-protocol` |
| Tools | Fixture containment; workspace writes against `..`, symlinks, junctions (Windows), hard links, a directory swapped for a link mid-write, size limits | `crates/jarvis-tools` |
| Isolation | A real Python child under the worker's confinement tries to read user files and the home directory, write anywhere, reach loopback and the internet, start or signal processes, read the Core, use leaked handles and open the Core's pipe; identity, privileges, capabilities, memory limit, lifetime, concurrent launches; the start-up check passing, failing on a missing boundary, and failing closed when the probe cannot run | `crates/jarvis-sandbox/tests`, `crates/jarvis-core/tests/isolation.rs` |
| Store | Migrations, append-only audit, triggers on every table, approval grant, deny, expiry and single use, failure inside the consuming transaction, recovery | `crates/jarvis-core/src/store/tests.rs` |
| Policy, restarts, config | Default deny, class ceilings, backoff and budget | Unit tests |
| Session | Every failure path over in-memory pipes with an untrusted peer, including approvals and database failures before and after execution | `crates/jarvis-core/tests/session.rs` |
| Processes | The real binary as a daemon with the real Python worker and a hostile worker: CLI approvals, restarts, crashes, signals, recovery, the RPC interface | `crates/jarvis-core/tests/process.rs` |
| Gaming governor | The state machine as a pure function; the loop against a scripted source on a paused clock (exact release time, one alert, errors, failing audit writes); the gate in a real session (held jobs are not claimed, no attempt, no timer, wake on release, start-up); the real binary with a stand-in process started and killed | `crates/jarvis-core/src/governor/machine.rs`, `tests/governor.rs`, `tests/process.rs` |
| Process detection | The production function finds the test binary's own name, a stand-in copied to a unique name while it runs and not after it exits | `crates/jarvis-sandbox/tests/processes.rs` |
| Local model | Prompt building and history fitting; the request gate for clipboard proposals (only the person's own words, outside quoted text, can ask for a copy) and the clipboard block parser; lenient but bounded decoding of the server's responses (chunked bodies, malformed chunks); the server's command line (loopback, key, switched-off features, no `LLAMA_*` in the environment); the conversation store (turns, history, regeneration, search, deletion with a check that deleted text is gone from the files, retention, unfinished replies); chat types and their fixtures | `crates/jarvis-core/src/inference`, `crates/jarvis-protocol/src/chat.rs`, `tests/protocol` |
| Worker | Protocol client, job loop, planner, contract fixtures, a guard that the package performs no privileged operations | `services/intelligence-python/tests` |
| Session Agent | Grants as pure functions (exact binding, single use, expiry, revocation, clock, bounds, concurrency); the agent loop; the full path in a real session with the real agent binary; fault injection after dispatch (exit, hang, wrong grant, garbage, refusal, no start, shutdown) and job quarantine; clipboard writes (full text shown, busy refused, faults and wrong lengths unknown) and a write-only clipboard primitive tested in its own window station; the helper inherits no stray handle or descriptor and its pipes accept no other client | `crates/jarvis-core/src/session_agent.rs`, `src/session_agent/serve.rs`, `tests/session.rs`, `crates/jarvis-sandbox/tests/contain.rs`, `crates/jarvis-sandbox/tests/clipboard.rs` |

## Not built yet

- Model-backed planning. The local model converses, but it does not plan jobs, call tools or choose actions; the worker's planner is still deterministic.
- Speech, retrieval and memory. Nothing is remembered between conversations.
- A model in the worker. The worker has no model and no network; the model is brokered by the Core.
- More than one worker.
- Remote access to the model or the desktop client.
- Desktop operations other than writing the clipboard. Screen capture, clipboard reading and typing are typed, describable and always denied (ADR 0020 records why typing stays closed).
