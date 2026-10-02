# Threat model

This document defines what JARVIS protects, where the trust boundaries are, and which controls exist today. It covers the Phase 1 system: a Rust Core that supervises one Python worker and executes typed tools under a capability policy. It was written before any model integration, and it is the reference for every new tool.

Each threat lists its current mitigation and the test that proves it, or states plainly that the mitigation is planned.

## System in scope

```
            user (config file, CLI)
                     |
                     v
+--------------------------------------------+
| Rust Core (trusted, enforcement point)      |
|  session -> validation -> capability        |
|  extraction -> policy -> Tool Gateway       |
|  SQLite: tasks, audit_events                |
+--------------------------------------------+
        ^  stdio pipe, line-delimited JSON
        |  (the worker's only channel)
        v
+--------------------------------------------+
| Python worker (untrusted at the protocol)   |
|  deterministic planner today; models later  |
+--------------------------------------------+
```

The Core starts the worker as a child process. The worker has no network listener and no channel to the Core other than its own stdin and stdout. There is no other IPC endpoint in Phase 1.

## Assets

| Asset | Why it matters | Phase 1 exposure |
| --- | --- | --- |
| Filesystem | Personal files, project files, system files | Read access only inside one configured fixture directory |
| Credentials | API keys, tokens, SSH keys, password stores | None through tools; the worker starts with a cleared environment |
| Private documents | Notes, mail, documents on the PC | None |
| Browser and session data | Cookies, profiles, saved sessions | None |
| Processes | Ability to start, stop or control programs | The Core starts only the configured worker; no tool starts processes |
| Network access | Exfiltration, remote actions | No tool performs network I/O |
| Local services | Databases, home automation, other daemons | None |
| User identity | Hostname, username, account names | `system.info` deliberately omits them |
| The Core's own state | Policy, config, audit log, task history | Not reachable through the protocol |

## Actors and trust levels

| Actor | Trust | Notes |
| --- | --- | --- |
| User | Trusted | Owns the machine, writes the config and policy |
| Model (future) | Untrusted | Its output is data. It may be steered by content it reads (prompt injection) |
| Python worker | Untrusted at the protocol boundary | Hosts the model and processes untrusted content. Its requests are validated as if hostile |
| Rust Core | Trusted | The only component that decides and executes |
| Tool Gateway and tools | Trusted code, bounded | Receive typed arguments only after policy allows them |
| Operating system | Trusted | The Core relies on OS process isolation and file permissions |
| Remote services (future) | Untrusted | Not reachable in Phase 1 |

## Trust boundaries

1. **Model → worker.** Model output never becomes code. The worker turns it into typed tool requests or discards it. This boundary does not exist yet in code because no model is integrated.
2. **Worker → Core (stdio protocol).** This is the enforcement boundary in Phase 1. Every frame is size-bounded, decoded strictly, version-checked and validated before it can create a task.
3. **Core → tools.** The Gateway calls a tool only with a typed, validated call that policy has allowed, under a timeout and a cancellation signal. Tool output is verified before it is stored or returned.
4. **Core → OS.** The Core touches the OS through the SQLite file, the lock file, the fixture directory, and the worker process it spawns. Nothing else.
5. **Core → remote services.** None in Phase 1.

## Security invariants

These rules hold in the current code. Changes that break one of them need an ADR.

1. **The worker never names capabilities.** The Core derives the required capabilities from the typed tool call through an exhaustive match. A request that tries to carry capabilities, approvals or task IDs is rejected as malformed.
2. **Default deny.** A capability that the policy does not list is denied.
3. **No generic execution interface.** No tool accepts a command line, a script, a URL or an arbitrary path. The tool set is a closed enum compiled into the Core.
4. **Decide, record, then act.** The policy decision and the start of execution are committed to SQLite before a tool runs. If that write fails, the tool does not run.
5. **One task, one terminal state.** Every well-formed tool request creates exactly one task record. Each task reaches exactly one terminal state, and a database trigger rejects later changes to terminal tasks.
6. **Append-only audit.** Database triggers reject `UPDATE` and `DELETE` on `audit_events`.
7. **Approvals do not carry over.** There is no approval token in the protocol. A request that needs confirmation is not executed in Phase 1, and its task expires when the session ends.
8. **Everything is bounded.** Frame size, result size, fixture size, tool time, requests per session and protocol errors per session all have limits.
9. **The worker does not inherit secrets.** The Core clears the worker's environment and passes through only what the interpreter needs to start.
10. **Strict decoding.** Unknown fields, unknown message types and other protocol versions are rejected, never ignored.

## Action classes

Every capability belongs to one class. The class sets the strongest decision that the policy may grant.

### A. Allow automatically

Read-only, side-effect free, bounded output, no personal data.

- `system.info`: OS family, architecture, logical CPU count, Core version, protocol version and Core uptime.
- `filesystem.read.fixture`: read a UTF-8 text file inside the configured fixture directory, up to a size limit.

Planned examples: status of an approved application, listing an approved directory.

### B. Require confirmation

Actions with side effects that can be undone, or reads of personal data.

Planned examples: reading a document outside approved roots, writing inside an approved directory, launching an application from an allowlist, sending a notification, a request to an allowlisted host.

Phase 1 has no class B tool. The policy engine already returns `require_confirmation`, and a test proves that such a request is recorded and not executed. The approval channel itself (a human confirming a specific task) is Phase 2 work.

### C. Prohibited

No policy can allow these. They are enforced structurally: no tool exists for them, and the protocol has no generic variant that could express them.

- Arbitrary shell or command execution, generic process launch.
- Unrestricted filesystem write or delete.
- Reading credential stores, browser profiles, SSH keys or password managers.
- Unrestricted network access.
- Changing the Core's own policy, config, database or audit log.
- Disabling or bypassing audit.

The policy file cannot name a capability that the Core does not know. Loading such a config fails.

## Threats and mitigations

Status: **Implemented** means the mitigation exists in code and a test covers it. **Partial** means part of it exists. **Planned** means it is not built.

| Threat | Mitigation | Status | Evidence |
| --- | --- | --- | --- |
| Prompt injection | Model output can only become typed requests. Policy is evaluated on derived capabilities, not on the model's stated intent. Class B needs a human, class C does not exist. Residual risk: an injected model can still call any class A tool, so class A must stay harmless | Partial (no model yet) | Architecture; `rogue_worker` end-to-end test |
| Tool injection (invented tools such as `shell.exec`) | Closed tool set. A well-formed but unknown tool name creates a `rejected` task and nothing runs | Implemented | `unknown_tool_is_rejected_and_recorded` |
| Malformed arguments | Each tool has a typed argument struct that rejects unknown fields and wrong types, followed by semantic checks | Implemented | `invalid_arguments_are_rejected_before_policy` |
| Path traversal | Fixture paths must be relative and contain only normal components (no `..`, no root, no drive prefix, bounded length). The tool then checks that the canonical target stays under the canonical fixture root, which also catches symlinks that point outside | Implemented | `fixture_path` unit tests; `path_traversal_is_rejected` |
| Arbitrary process execution | No tool starts processes. The only child process is the configured worker, started from config with an argument vector and no shell | Implemented | No such tool exists; `worker_environment_is_cleared` |
| Capability escalation | Capabilities are derived by the Core. A request field such as `capabilities` or `approved` is rejected. The policy cannot reference unknown capabilities. Default deny | Implemented | `worker_cannot_smuggle_authority`; `denied_capability_never_executes`; config tests |
| Confused deputy | The Core evaluates the worker's grants, not its own authority. Tools receive typed arguments only, and the fixture reader is bound to the configured root. Phase 1 has a single principal; per-principal grants come with more workers | Partial | Policy tests |
| Stale approvals | No approval token exists. Confirmation-required tasks expire at session end and again during startup recovery | Implemented | `confirmation_required_is_not_executed`; recovery tests |
| Replayed requests | `request_id` is unique per session, enforced by a database constraint. A duplicate is rejected without re-execution. Session IDs are generated by the Core | Implemented | `duplicate_request_id_is_rejected` |
| Runaway jobs | Per-tool timeout, one tool in flight per worker, per-session request cap, protocol error budget | Implemented | `tool_timeout_is_recorded`; `request_cap_closes_session` |
| Worker crash or hang | The Core detects EOF and process exit, records the exit status, expires pending confirmations, and kills a worker that does not finish the handshake or does not exit after shutdown | Implemented | `worker_crash_is_recorded`; `handshake_timeout_kills_worker` |
| Core crash mid-task | WAL with `synchronous=FULL`. On startup, non-terminal tasks become `interrupted` or `expired`, with an audit event for each | Implemented | `recovery_marks_unfinished_tasks` |
| Resource exhaustion | Frame limit enforced while reading (no unbounded buffering), result size limit, fixture size limit, truncated worker log lines | Implemented | Framing tests; `oversized_result_is_rejected` |
| Malformed IPC | Bounded line framing, strict JSON decoding, per-frame version check, error budget. A property test feeds arbitrary bytes to the decoder | Implemented | `malformed_frames_*`; `decode_never_panics` property test |
| Protocol version mismatch | Exact version match on every frame. A mismatch closes the session | Implemented | `protocol_version_mismatch_closes_session` |
| Forged or oversized tool results | The Gateway checks that the result variant matches the call and that its size is within limits before storing it | Implemented | `mismatched_result_is_rejected` |
| Credential leakage to the worker | Cleared environment; `system.info` excludes hostname, username, environment variables and paths | Implemented | `worker_environment_is_cleared` |
| Audit tampering by Core bugs | Append-only triggers; terminal tasks immutable; transitions checked against the expected source state | Implemented | Store tests |
| Audit tampering with file access | Not addressed. Anyone with write access to the database file can rewrite it. A hash chain or external log sink is planned | Planned | None |
| Two Cores on one database | Exclusive lock file held for the Core's lifetime, so recovery cannot mark another live Core's tasks as interrupted | Implemented | `second_core_cannot_open_same_database` |
| Log injection through worker stderr | Worker stderr is forwarded as an escaped field value and truncated per line | Implemented | Supervisor code |

## Known gaps

These are stated so that nobody mistakes the Phase 1 controls for more than they are.

- **The worker is not sandboxed by the OS.** It is an ordinary process with the user's privileges. The policy cannot be bypassed through the protocol, but compromised worker code could call OS APIs directly. Today the mitigation is that the worker code is fixed and never executes model output. OS containment is planned: Job Objects and restricted tokens on Windows, namespaces, Landlock or seccomp on Linux.
- **A local attacker running as the same user** can edit the config, the policy and the database. JARVIS does not defend against that account.
- **Fixture reads have a time-of-check to time-of-use window** between canonicalisation and open. The fixture root is controlled by the user, so this is accepted for Phase 1. Reads of user data will need handle-based checks.
- **Dependencies are pinned by lockfiles** but not yet audited in CI.
- **No authentication on the stdio channel.** None is needed while the pipe is private to the parent and child. Any future socket or remote endpoint needs authentication before it ships.

## When to revisit this document

- Before adding any tool or capability.
- Before integrating a model, a speech pipeline or any remote access.
- Before adding a second worker or any IPC endpoint other than the worker pipe.
