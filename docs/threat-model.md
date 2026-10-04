# Threat model

This document defines what JARVIS protects, where the trust boundaries are, and which controls exist today. It covers the Phase 3 system: a long-lived Rust Core that supervises one Python worker isolated by the operating system, executes typed tools under a capability policy, asks a person before any class B action, and serves local clients over RPC. It was written before any model integration, and it is the reference for every new tool.

Each threat lists its current mitigation and the test that proves it, or states plainly that the mitigation is planned.

## System in scope

```
   person ── CLI (or a future dashboard)
                 |  local RPC: Unix socket (0700 dir) or named pipe
                 |  same user only; the worker is refused
                 v
+--------------------------------------------------+
| Rust Core (trusted, enforcement point)            |
|  RPC server -> jobs, approvals                    |
|  session -> validation -> capability extraction   |
|  -> policy -> [approval] -> Tool Gateway          |
|  SQLite: jobs, tasks, approvals, audit_events     |
|  supervisor: spawn, contain, restart, kill        |
+--------------------------------------------------+
        ^  stdio pipe, line-delimited JSON
        |  (the worker's only channel to the Core)
        v
+==================================================+
| OS isolation boundary, proved at Core start-up    |
|  Windows: AppContainer (no capabilities), job,    |
|    child-process policy, handle list, mitigations |
|  Linux: Landlock + seccomp + no capabilities      |
| +----------------------------------------------+ |
| | Python worker (untrusted)                    | |
| |  reads its runtime and source, nothing else  | |
| |  no network, no processes, no other files    | |
| |  deterministic planner today; models later   | |
| +----------------------------------------------+ |
+==================================================+
```

## Assets

| Asset | Why it matters | Phase 2 exposure |
| --- | --- | --- |
| Filesystem | Personal files, project files, system files | Tools read inside one fixture directory and write inside one workspace directory, writes only after a person approves |
| Credentials | API keys, tokens, SSH keys, password stores | None through tools; the worker starts with a cleared environment |
| Private documents | Notes, mail, documents on the PC | None through tools. The worker's OS isolation denies it every file outside its runtime and source |
| Browser and session data | Cookies, profiles, saved sessions | As above |
| Processes | Ability to start, stop or control programs | No tool starts processes. The worker can start, signal or read no other process |
| Network access | Exfiltration, remote actions | No tool performs network I/O. The worker has no network at all, loopback included |
| The approval channel | Whoever can approve can trigger class B actions | Local RPC, same user only, worker refused |
| User identity | Hostname, username, account names | `system.info` deliberately omits them |
| The Core's own state | Policy, config, audit log, task and approval history | Not reachable through the worker protocol or the RPC interface |

## Actors and trust levels

| Actor | Trust | Notes |
| --- | --- | --- |
| Person at the machine | Trusted | Owns the machine, writes the config and policy, decides on approvals |
| Local client (CLI) | Trusted as the person | Any process of the same user that can open the RPC endpoint, except the worker |
| Model (future) | Untrusted | Its output is data. It may be steered by content it reads (prompt injection) |
| Python worker | Untrusted | Its requests are validated as if hostile, and the OS isolates it from everything but its runtime, its source and its stdio |
| Rust Core | Trusted | The only component that decides and executes |
| Tool Gateway and tools | Trusted code, bounded | Receive typed arguments only after policy (and, for class B, a person) allows them |
| Other local users | Untrusted | Cannot reach the RPC endpoint |
| Operating system | Trusted | The Core relies on AppContainers, the Windows Filtering Platform and job objects (Windows), Landlock and seccomp (Linux), file permissions and peer credentials |

## Trust boundaries

1. **Model → worker.** Model output never becomes code. This boundary does not exist yet in code because no model is integrated.
2. **Worker → Core (stdio protocol).** Every frame is size-bounded, decoded strictly, version-checked, tied to the current job and validated before it can create a task.
3. **Client → Core (local RPC).** The OS identifies every peer before a request is read. Requests are size-bounded and decoded strictly; there are nine typed operations and none runs a tool directly.
4. **Core → tools.** The Gateway calls a tool only with a typed, validated call that policy has allowed and, for class B, whose approval was consumed in the same transaction that started execution.
5. **Worker → OS.** The worker runs inside an OS isolation boundary (ADRs 0013, 0014): it can read its interpreter and its own source, and nothing else; it has no network, cannot start or signal processes, and cannot reach the Core's RPC endpoint. The Core proves the boundary on each start before any worker runs, and refuses to run a worker if it does not hold.

## Security invariants

These rules hold in the current code. Changes that break one of them need an ADR.

1. **The worker never names capabilities or approvals.** The Core derives the capabilities through an exhaustive match. A request that carries capabilities, approvals, approval IDs, fingerprints or task IDs is rejected as malformed.
2. **Default deny, with a ceiling per class.** A capability the policy does not list is denied. A class B capability cannot be set to `allow`; loading such a config fails.
3. **No generic execution interface.** No tool accepts a command line, a script, a URL or an unrestricted path. The tool set is a closed enum compiled into the Core.
4. **Decide, record, then act.** The policy decision (and for class B, the consumption of the approval) and `execution_started` are committed before a tool runs. If that write fails, the tool does not run.
5. **One approval, one request, one use.** An approval is bound by fingerprint to one task, request, tool, argument set and capability set. It is granted only by a local client that presents that fingerprint, and consumed at most once. It never survives its session or a restart.
6. **One task, one terminal state; append-only audit.** Task and approval transitions commit with their audit events. Triggers reject changes to terminal tasks, decided approvals, finished jobs and any audit event.
7. **Everything is bounded.** Frames, results, fixture and workspace sizes, tool time, job time, approval time, requests and protocol errors per session, frames buffered while waiting for a person, RPC request size, RPC connections, long-poll time, worker memory and worker restarts.
8. **The worker does not inherit secrets or authority.** Cleared environment (on Windows plus the profile variables an AppContainer launch requires), no inherited descriptors or handles besides stdio, no shell, no privileges or capabilities, OS isolation applied before it runs any code.
9. **Strict decoding on every interface.** Unknown fields, unknown message types and other versions are rejected on the worker protocol and the RPC interface.
10. **The worker's isolation is proved, not assumed.** Before the first worker starts, the Core runs a probe under the identical isolation and checks from its own side that it cannot reach the network (loopback included), read the Core's files or start a process. If any check fails, the Core does not start.

## Action classes

### A. Allow automatically

Read-only, side-effect free, bounded output, no personal data.

- `system.info`: OS family, architecture, logical CPU count, Core version, protocol version and Core uptime.
- `filesystem.read.fixture`: read a UTF-8 text file inside the configured fixture directory, up to a size limit.

### B. Require confirmation

Side effects that stay inside an approved area and can be undone.

- `workspace.write`: `workspace.write_file` creates or replaces one UTF-8 text file inside the configured workspace directory, up to a size limit. It cannot create directories, delete files, follow symlinks or junctions out of the workspace, write through an existing link, or write anywhere else. Every call needs a person's approval; the policy may also deny it, but not allow it.

Planned examples: launching an application from an allowlist, sending a notification, a request to an allowlisted host.

### C. Prohibited

No policy can allow these. They are enforced structurally: no tool exists for them, and neither protocol has a generic variant that could express them.

- Arbitrary shell or command execution, generic process launch.
- Unrestricted filesystem write or delete.
- Reading credential stores, browser profiles, SSH keys or password managers.
- Unrestricted network access.
- Changing the Core's own policy, config, database or audit log.
- Disabling or bypassing audit or approvals.

## Threats and mitigations

Status: **Implemented** means the mitigation exists in code and a test covers it. **Partial** means part of it exists. **Planned** means it is not built.

### Requests from the worker

| Threat | Mitigation | Status | Evidence |
| --- | --- | --- | --- |
| Prompt injection | Model output can only become typed requests. Policy is evaluated on derived capabilities. Class B needs a person who sees the exact arguments; class C does not exist. Residual risk: an injected model can call any class A tool, and can ask for class B actions a person might approve without reading | Partial (no model yet) | Architecture; rogue worker test |
| Tool injection (invented tools such as `shell.exec`) | Closed tool set. An unknown tool creates a `rejected` task and nothing runs | Implemented | `unknown_tool_is_rejected_and_recorded` |
| Malformed arguments | Typed argument structs that reject unknown fields and wrong types, then semantic checks | Implemented | `invalid_arguments_are_rejected_before_policy` |
| Path traversal, absolute paths | Paths must be relative with plain components (no `..`, root, drive, device names, streams). Reads check the canonical target stays under the fixture root. Writes resolve every component beneath an open directory handle (`cap-std`), which refuses to leave the root | Implemented | `path_traversal_is_rejected_for_reads_and_writes`; `RelativePath` tests |
| Symlink or junction escape on write | Handle-based resolution refuses links that lead outside; a link at the target is refused; a hard link at the target is replaced, not written through | Implemented (junction: Windows CI) | `symlinked_directory_leading_outside_is_refused`; `symlink_at_the_target_is_refused`; `hard_link_at_the_target_is_replaced_not_written_through`; `junction_leading_outside_is_refused` |
| Race: a directory swapped for a link during a write | Each component is opened relative to the handle of the previous one, so no interleaving can redirect the write | Implemented (Unix test) | `swapping_a_directory_for_a_symlink_mid_write_cannot_escape` |
| Capability escalation | Capabilities derived by the Core; authority fields rejected; unknown capabilities refused in config; class ceiling enforced at load | Implemented | `worker_cannot_smuggle_authority`; config tests |
| Requests outside the current job | Every request names its job; any other job is refused and creates no task | Implemented | `requests_and_results_must_belong_to_the_current_job` |
| Replayed requests | `request_id` unique per session (database constraint). A duplicate is rejected without re-execution | Implemented | `duplicate_request_id_is_rejected` |
| Flooding while a request waits for a person | At most 16 frames are buffered; more ends the session and expires the approval | Implemented | `too_many_frames_while_waiting_end_the_session` |

### Approvals

| Threat | Mitigation | Status | Evidence |
| --- | --- | --- | --- |
| Worker grants itself approval | No approval field exists in the worker protocol; the worker never sees an approval it could act on | Implemented | `worker_cannot_smuggle_authority`; rogue worker test |
| Worker approves through the RPC interface | Peers are identified by the OS, at connection time and again before every request. The worker, its process group and descendants (Linux) or job (Windows) are refused; on Windows its low integrity level also blocks the pipe. Refusals are audited | Implemented (with the Linux gap below) | `a_rogue_worker_cannot_bypass_policy_or_approve_its_own_request`; `a_descendant_that_leaves_the_process_group_is_still_recognised` |
| Approving something other than what was shown | The client must present the fingerprint of the exact request it displayed; the session consumes the approval only if the fingerprint still matches the call it is about to run | Implemented | `a_wrong_fingerprint_grants_nothing`; `consuming_for_a_different_call_is_refused_and_changes_nothing`; `a_write_runs_only_after_a_person_approves_it_through_another_client` |
| Approval reused, replayed or used twice | Conditional state transitions in one transaction, enforced again by triggers; consumed approvals are terminal | Implemented | `an_approval_is_used_at_most_once_even_across_restarts`; `approval_rows_are_protected_by_triggers` |
| Stale approvals | Time-to-live checked at grant and at use; expiry on session end and on restart | Implemented | `an_approval_nobody_decides_on_expires`; `no_approval_or_queued_job_survives_a_restart`; `no_approval_can_be_used_after_the_core_restarts` |
| Crash between approval and execution | Consumption and `execution_started` commit together. If that commit fails nothing runs and recovery expires the approval; if it succeeds the approval is spent whatever happens next | Implemented | `a_store_failure_before_consumption_never_runs_the_tool`; `a_store_failure_after_the_tool_ran_leaves_a_consumed_approval` |
| Terminal injection in what the person reviews | Arguments are shown through a display-safe description: control characters escaped, long values cut, file content summarised by size, SHA-256 and a short escaped preview | Implemented | `description_is_safe_to_print` |
| Approval fatigue | Out of scope for code; every approval shows the full request and expires. A person can still approve without reading | Accepted risk | — |

### The RPC interface

| Threat | Mitigation | Status | Evidence |
| --- | --- | --- | --- |
| Other local users | Socket in a `0700` directory and `0600` itself, peer UID check; named pipe with an explicit DACL for the current user only, remote clients rejected | Implemented | `the_rpc_socket_is_private_to_the_user`; `the_worker_cannot_open_an_owner_only_pipe` (Windows) |
| Network exposure | No TCP listener exists | Implemented | Architecture |
| Endpoint squatting | Unix: refuse a directory others can enter, refuse to start if another Core answers on the socket. Windows: first-instance flag, start fails if the name is taken | Implemented | `the_rpc_socket_is_private_to_the_user`; `a_second_core_cannot_use_the_same_database` |
| Malformed or oversized requests | Strict decoding, 16 KiB limit (connection closed when exceeded), version check | Implemented | `the_rpc_interface_is_strict_and_bounded`; RPC decoding tests and fixtures |
| Resource exhaustion by clients | At most 16 connections, idle timeout, long polls capped at 60 s, write timeout | Implemented | `the_rpc_interface_is_strict_and_bounded` |
| Remote shutdown by any client | `shutdown` is refused unless the configuration allows it | Implemented | `shutdown_over_rpc_can_be_disabled` |

### Supervision and durability

| Threat | Mitigation | Status | Evidence |
| --- | --- | --- | --- |
| Worker crash or hang | Exit detected and recorded; pending approvals expired; job marked interrupted; handshake and job timeouts kill a stuck worker. The job timeout also applies while a request waits for a person and while buffered requests are handled | Implemented | `a_crashing_worker_is_restarted_until_the_budget_is_spent`; `a_silent_worker_is_killed_at_the_handshake_timeout`; `a_job_that_runs_too_long_ends_the_session`; `the_job_time_limit_applies_while_waiting_for_a_person`; `buffered_requests_do_not_extend_a_job_past_its_limit`; `a_worker_that_dies_while_waiting_for_approval_leaves_nothing_usable` |
| Restart loops | Exponential backoff and a restart budget per time window; after that the Core reports itself unhealthy and refuses jobs | Implemented | `RestartPolicy` unit tests; `a_crashing_worker_is_restarted_until_the_budget_is_spent` |
| Worker outliving the Core | Job object kill-on-close (Windows), `PR_SET_PDEATHSIG` (Linux) | Implemented | `the_worker_dies_with_the_core` |
| Core crash mid-task | WAL with `synchronous=FULL`; start-up recovery closes tasks, approvals and jobs left open | Implemented | `recovery_marks_unfinished_tasks`; `start_up_recovers_what_a_previous_run_left_open` |
| Two Cores on one database | Exclusive lock file | Implemented | `second_core_cannot_open_same_database`; `a_second_core_cannot_use_the_same_database` |
| Audit tampering by Core bugs | Append-only triggers with `recursive_triggers` on; immutable terminal rows | Implemented | `audit_log_is_append_only`; trigger tests |
| Audit tampering with file access | Not addressed. Anyone with write access to the database file can rewrite it | Planned | — |
| Log or terminal injection | Worker and client text is escaped before it reaches the wire, the audit log, the logs or the CLI | Implemented | `worker_text_in_errors_is_escaped`; `error_messages_are_sanitised` |
| Credential leakage to the worker | Cleared environment with no config option to add variables; no inherited descriptors | Implemented (descriptors: Linux test) | `the_worker_environment_is_cleared` |

## Durability semantics

The Core guarantees that **authority is used at most once**: an approval is consumed in the same transaction that starts execution, and can never be consumed again. It does **not** guarantee that a side effect happens exactly once. If the Core dies after that transaction and before the result is recorded, the write may or may not have happened; the task is marked `interrupted` and the approval stays consumed. A person decides whether to ask again.

## Known gaps

- **The worker is contained, not sandboxed.** On both platforms it can read any file the user can read and open network connections. On Linux it can also write the user's files and start processes. A separate account, AppContainer, or namespaces with Landlock and seccomp are the next step (ADR 0012).
- **The Linux worker check relies on ancestry.** A worker process that leaves its process group *and* is re-parented away from the worker (by double forking) is indistinguishable from any other process of the user, and can use the RPC interface, including to approve requests.
- **Processes the Linux worker starts and detaches can survive it.** Killing the process group does not reach a process that left the group.
- **A local attacker running as the same user** can edit the config, the policy and the database, and can approve requests. JARVIS does not defend against that account.
- **Some Windows controls are verified only on a real desktop:** UI restrictions, the low-integrity token against the user's profile, and handle inheritance. See [`windows-validation.md`](windows-validation.md).
- **Fixture reads have a time-of-check to time-of-use window** between canonicalisation and open; the fixture root is the user's to populate. Writes do not have this problem.
- **Dependencies are pinned by lockfiles** but not yet audited in CI.

## When to revisit this document

- Before adding any tool or capability.
- Before integrating a model, a speech pipeline or any remote access.
- Before adding a second worker, a dashboard or any other client of the RPC interface.
