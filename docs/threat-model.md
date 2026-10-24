# Threat model

This document defines what JARVIS protects, where the trust boundaries are, and which controls exist today. It covers a long-lived Rust Core that supervises one Python worker isolated by the operating system, executes typed tools under a capability policy, asks a person before any class B action, serves local clients over RPC, and brokers a local language model that can converse but has no tools (ADR 0021). It is the reference for every new tool.

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
|  inference: conversations, model-server broker    |
+--------------------------------------------------+
   |  loopback HTTP, key made per start   ^  stdio pipe, line-delimited
   |  (text in, text out, no tools)       |  JSON (the worker's only
   v                                      v  channel to the Core)
 model server (llama.cpp): trusted helper with the
 user's token, kill-on-close job, cleared environment
+==================================================+
| OS isolation boundary, checked at Core start-up   |
|  Windows: AppContainer (no capabilities), job,    |
|    child-process policy, handle list, mitigations |
|  Linux: Landlock + seccomp + no capabilities      |
| +----------------------------------------------+ |
| | Python worker (untrusted)                    | |
| |  reads its runtime and source (+ known gaps) | |
| |  no user files, no processes                 | |
| |  no network (by design)                      | |
| |  deterministic planner; no model             | |
| +----------------------------------------------+ |
+==================================================+
```

## Assets

| Asset | Why it matters | Exposure |
| --- | --- | --- |
| Filesystem | Personal files, project files, system files | Tools read inside one fixture directory and write inside one workspace directory, writes only after a person approves |
| Credentials | API keys, tokens, SSH keys, password stores | None through tools; the worker starts with a cleared environment |
| Private documents | Notes, mail, documents on the PC | None through tools. The worker's OS isolation denies it every user file outside its runtime and source. On Windows it can still read system directories and registry keys open to every AppContainer, such as Explorer's list of recent documents (opened for read on a desktop run; see known gaps) |
| Browser and session data | Cookies, profiles, saved sessions | As above |
| Processes | Ability to start, stop or control programs | No tool starts processes. The worker can start, signal or read no other process. When the governor is on, the Core reads the system process list to look for the configured game names; this detection opens no process, only a snapshot of the list (ADR 0016) |
| Network access | Exfiltration, remote actions | No tool performs network I/O. By design the worker has no network at all, loopback included (no capabilities on Windows, no sockets on Linux). The start-up probe checks loopback TCP and UDP at every Core start (not on worker restarts); see the isolation table for what else is tested |
| The approval channel | Whoever can approve can trigger class B actions | Local RPC, same user only, worker refused |
| User identity | Hostname, username, account names | `system.info` deliberately omits them |
| The Core's own state | Policy, config, audit log, task and approval history | Not reachable through the worker protocol or the RPC interface |
| Conversations | What the person said to the assistant and what it answered: personal text, possibly pasted e-mails or documents | Stored in their own database file, separate from the audit log so that they can be deleted. Readable through the RPC interface by any same-user client; sent to the model server and nowhere else. Never written to the audit log (ADR 0021) |
| Clipboard text waiting for approval | A text a person (or the model, with their say-so) wants copied: it may be a password, a message or an address | Held in a working table (`payloads`) for as long as its job exists, then deleted in the transaction that ends the job; `jarvis.db` runs with `secure_delete` and the log is truncated after the deletion. It is in no job, task, approval or audit record (ADR 0022). The worker sees only an identifier and the SHA-256 of a random salt followed by the text; the salt lives in the payload row and is deleted with it, so neither the worker nor a reader of the records can test guesses of a short text. Rows written before ADR 0022 still hold their text |
| The model files | Weights the person chose to trust | Pinned by SHA-256 in the configuration; the Core refuses a file that does not match |

## Actors and trust levels

| Actor | Trust | Notes |
| --- | --- | --- |
| Person at the machine | Trusted | Owns the machine, writes the config and policy, decides on approvals |
| Local client (CLI) | Trusted as the person | Any process of the same user that can open the RPC endpoint, except the worker |
| Model output | Untrusted | Its output is data. It can be steered by anything in its context, including text a person pastes (prompt injection). It is stored and shown as text and never parsed for instructions, apart from one optional suggestion a person must accept (see "The local model") |
| Model server (llama.cpp) | Trusted, bounded | A large C++ program the Core starts from a configured path, with a cleared environment, no child processes and a memory limit, under a kill-on-close job. It runs with the user's token and is not isolated from the user, because it needs the GPU. It listens on loopback with a key made for that start. The Core treats what it returns as untrusted (ADR 0021) |
| Python worker | Untrusted | Its requests are validated as if hostile, and the OS isolates it from the user's files, the Core's data, the network and other processes. It keeps its runtime, its source and its stdio; on Windows it can also read what Windows opens to every AppContainer (see known gaps) |
| Rust Core | Trusted | The only component that decides and executes |
| Session Agent | Trusted, bounded | A process of the user at medium integrity that the Core starts and talks to over pipes only the Core holds. It performs an operation only under a single-use grant the Core issued after a person approved that exact request, and has two operations: a synthetic health check and writing approved text to the clipboard (ADRs 0017, 0019, 0020) |
| Tool Gateway and tools | Trusted code, bounded | Receive typed arguments only after policy (and, for class B, a person) allows them |
| Other local users | Untrusted | Cannot reach the RPC endpoint |
| Operating system | Trusted | The Core relies on AppContainers, the Windows Filtering Platform and job objects (Windows), Landlock and seccomp (Linux), file permissions and peer credentials |

## Trust boundaries

1. **Model → anything that acts.** Model output never becomes code, a tool call or a policy input. The worker never sees the model, and the model never sees the worker. The only structure the Core extracts from a reply is one clipboard suggestion, which does nothing until a person submits it as an ordinary job and approves it (ADR 0021).
2. **Worker → Core (stdio protocol).** Every frame is size-bounded, decoded strictly, version-checked, tied to the current job and validated before it can create a task.
3. **Client → Core (local RPC).** The OS identifies every peer before a request is read. Requests are size-bounded and decoded strictly; the operations are typed and none runs a tool directly. The conversation operations never reach the policy or the worker.
4. **Core → tools.** The Gateway calls a tool only with a typed, validated call that policy has allowed and, for class B, whose approval was consumed in the same transaction that started execution.
5. **Worker → OS.** The worker runs inside an OS isolation boundary (ADRs 0013, 0014): it can read its interpreter and its own source and, on Windows, what Windows opens to every AppContainer (system directories, registry keys that grant "ALL APPLICATION PACKAGES", including parts of `HKEY_CURRENT_USER`; its access to the screen and keyboard state is not proven blocked). It reads no user file and no Core data. By design it has no network, cannot start or signal processes, and cannot reach the Core's RPC endpoint. At every Core start, before the first worker runs, the Core checks that the boundary holds for a loopback listener (TCP and UDP), a file next to the database, the user's home and starting a process, and refuses to run a worker if any check fails.
6. **Core → Session Agent.** The channel is the agent's stdio, created by the Core for that child: no named endpoint, no RPC operation and no worker handle reaches it. An operation is sent only for a grant made from a consumed approval of that exact call and used up before sending; every outcome is recorded with the task's final state (ADR 0019).
7. **Core → model server.** The Core starts the server, holds its key and talks to it over loopback HTTP. The server receives conversation text and the persona and nothing else, sends back text, and is refused at the RPC interface. Its responses are bounded and read leniently, never as commands (ADR 0021).

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
10. **The worker's isolation is checked, not assumed.** Before the first worker starts, the Core runs a probe under the identical isolation and checks from its own side that it cannot reach a loopback listener (TCP and UDP), read a file next to the Core's database or the user's home, or start a process. If any check fails, the Core does not start. The probe does not exercise other network paths; those rest on the isolation design (no capabilities, no sockets) and on the tests listed in the isolation table.

## Action classes

### A. Allow automatically

Read-only, side-effect free, bounded output, no personal data.

- `system.info`: OS family, architecture, logical CPU count, Core version, protocol version and Core uptime.
- `filesystem.read.fixture`: read a UTF-8 text file inside the configured fixture directory, up to a size limit.

### B. Require confirmation

Side effects that stay inside an approved area and can be undone.

- `workspace.write`: `workspace.write_file` creates or replaces one UTF-8 text file inside the configured workspace directory, up to a size limit. It cannot create directories, delete files, follow symlinks or junctions out of the workspace, write through an existing link, or write anywhere else. Every call needs a person's approval; the policy may also deny it, but not allow it.

- `session_agent.healthcheck`: the Session Agent echoes a label. It has no effect and reads nothing, but it crosses into a separate process with the user's authority, so it is confirmed like any agent operation.
- `desktop.clipboard.write`: the Session Agent replaces the clipboard's content with a text of at most 1,024 visible characters, shown to the person in full before they approve it, and reads nothing back. Off unless the owner sets it to `require_confirmation`; every write needs its own approval (ADR 0020). The text is held as a temporary payload and the request names it by identifier and SHA-256 (ADR 0022): the Core shows the text, checks the SHA-256 before approving and before writing, and refuses a payload that is missing or changed. The effect can be undone by copying something else, and any same-user program can already write the clipboard.
- `desktop.screen.observe`, `desktop.clipboard.read`, `desktop.input.send`: defined so that requests for them can be described, and refused: the configuration may only set them to `deny`, and the Core has no way to perform them. Typing stays closed because focus can change between a check and the input's delivery (ADR 0020).

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
| Prompt injection | Model output can only become typed requests. Policy is evaluated on derived capabilities. Class B needs a person who sees the exact arguments; class C does not exist. Residual risk: an injected model can call any class A tool, and can ask for class B actions a person might approve without reading | Partial (the worker has no model; the local model has its own section below) | Architecture; rogue worker test |
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
| Worker approves through the RPC interface | First the OS: on Linux the worker cannot create a socket at all; on Windows its package SID is not in the pipe's DACL. Then the Core: peers are identified at connection time and again before every request; the worker, its process group or job, and (Windows) any AppContainer or below-medium-integrity client are refused and audited | Implemented | `a_rogue_worker_cannot_bypass_policy_or_approve_its_own_request` (asserts the attack never reaches the Core); `the_worker_cannot_open_an_owner_only_pipe`; `the_rpc_check_recognises_the_worker_as_restricted` (Windows) |
| Approving something other than what was shown | The client must present the fingerprint of the exact request it displayed; the session consumes the approval only if the fingerprint still matches the call it is about to run | Implemented | `a_wrong_fingerprint_grants_nothing`; `consuming_for_a_different_call_is_refused_and_changes_nothing`; `a_write_runs_only_after_a_person_approves_it_through_another_client` |
| Approval reused, replayed or used twice | Conditional state transitions in one transaction, enforced again by triggers; consumed approvals are terminal | Implemented | `an_approval_is_used_at_most_once_even_across_restarts`; `approval_rows_are_protected_by_triggers` |
| Stale approvals | Time-to-live checked at grant and at use; expiry on session end and on restart | Implemented | `an_approval_nobody_decides_on_expires`; `no_approval_survives_a_restart_and_queued_jobs_stay_queued`; `no_approval_can_be_used_after_the_core_restarts`; `an_approval_from_an_earlier_attempt_cannot_be_used_in_the_next` |
| Crash between approval and execution | Consumption and `execution_started` commit together. If that commit fails nothing runs and recovery expires the approval; if it succeeds the approval is spent whatever happens next | Implemented | `a_store_failure_before_consumption_never_runs_the_tool`; `a_store_failure_after_the_tool_ran_leaves_a_consumed_approval` |
| Terminal injection in what the person reviews | Arguments are shown through a display-safe description: control characters escaped, long values cut, file content summarised by size, SHA-256 and a short escaped preview | Implemented | `description_is_safe_to_print` |
| Approval fatigue | Out of scope for code; every approval shows the full request and expires. A person can still approve without reading | Accepted risk | — |

### Worker isolation (Phase 3)

What a compromised worker can do when it ignores the protocol and calls the operating system directly. **Prevented**: the OS refuses it and a test proves the refusal on CI. **Mitigated**: reduced, not removed. **Residual**: possible today, accepted and stated. **Untested**: not exercised by any test or desktop run. **Out of scope**: not defended against.

| Attempt | Windows (AppContainer, ADR 0013) | Linux (Landlock + seccomp, ADR 0014) | Classification | Evidence |
| --- | --- | --- | --- | --- |
| Read the user's files (profile, Documents, Desktop, `.ssh`, other drives) | The package SID is not in their ACLs | Not beneath a Landlock grant | Prevented | `reading_a_user_file_is_denied`; `listing_the_home_directory_is_denied` |
| Read the Core's database, config or logs | Same | Same | Prevented, and checked at every start | Start-up probe (`no access to the Core's files`); `the_real_confinement_passes_every_check` |
| Write or delete any file | Only read grants exist. Windows lets an AppContainer write in its own folder (where `TEMP` points) through an entry no deny entry overrides; the Core empties that folder before every start | Only read grants exist | Prevented on Linux; Mitigated on Windows (own folder only, nothing survives a restart, disk use not bounded) | `writing_outside_the_grants_is_denied`; `what_it_writes_in_its_container_folder_does_not_outlive_it` (Windows) |
| A grant broader than intended (an interpreter in `~/bin`, a drive root) | No grant may be a root or contain the profile, the database or the workspace | Same | Prevented | `a_grant_that_contains_protected_data_is_refused`; `filesystem_roots_are_never_granted` |
| Learn that a path exists, its size and times | Needs read-attributes access, which the package SID lacks | Landlock does not mediate `stat` | Residual on Linux (metadata only, no contents) | ADR 0014 |
| Read system files outside the runtime | Readable where Windows grants "ALL APPLICATION PACKAGES" (system directories) | `/etc`, `/proc`, `/run` and others denied | Prevented on Linux; Residual on Windows (system files only, no user data) | `system_files_outside_the_grants_are_denied` (Linux) |
| Read the user's registry, screen or clipboard | Registry keys that grant "ALL APPLICATION PACKAGES" are readable, including parts of `HKEY_CURRENT_USER` (such as Explorer's list of recent documents); a screen device context could be obtained before win32k system calls were disabled for the worker (ADR 0018), and the clipboard is refused. Values in those keys, not only names, are presumed readable (opening a key for read grants the right to query its values; no value read was recorded); the full set of readable keys has not been enumerated. Whether the screen contents can be captured is not proven either way, and reading keyboard state was inconclusive | Not applicable | Residual on Windows (registry keys open to every AppContainer; screen and keyboard access not proven blocked; no direct read of user files, but whether file contents shown on screen can be captured is not proven) | Desktop run recorded in the known gaps; not covered by CI |
| Any network: internet, LAN, loopback, DNS, model APIs | No capabilities: the Filtering Platform is expected to drop all traffic | No socket can be created | Prevented for what is tested. Checked at every start: loopback TCP and UDP only. CI also covers a public address on port 443 and a DNS lookup, and on Linux every socket kind. IPv6 loopback and the host's LAN address were denied on one manual desktop run only | `connecting_to_a_loopback_listener_is_denied`; `reaching_the_internet_is_denied`; `every_kind_of_socket_is_denied` (Linux); start-up probe (loopback only) |
| Reach the Core's RPC endpoint | Pipe DACL omits the package SID; RPC refuses restricted tokens | No sockets | Prevented | `a_rogue_worker_cannot_bypass_policy_or_approve_its_own_request`; `the_worker_cannot_open_an_owner_only_pipe` |
| Start another program, or escape the job | Child-process policy plus a one-process job without breakaway | `fork`, `vfork` and process `clone` denied | Prevented, and checked at every start | `starting_a_child_process_is_denied` |
| Re-execute itself as another binary | Not possible without creating a process | `execve` of a binary under a runtime root, which keeps the same Landlock domain and seccomp filter | Mitigated on Linux | ADR 0014 |
| Read, signal or change other processes (including the Core) | AppContainer and low integrity: `OpenProcess` refused | `ptrace`, `process_vm_readv`, the `kill` family, signal ownership through `fcntl`/`ioctl`, other processes' limits and scheduling denied; `/proc` unreadable; Landlock signal scoping on ABI 6+ | Prevented | `reading_another_process_is_denied`; `signalling_another_process_is_denied` and `signalling_through_file_ownership_or_limits_is_denied` (Linux) |
| Reach other processes through System V IPC, or watch directories for activity | AppContainer object namespace | `shm*`, `msg*`, `sem*`, `inotify`, `fanotify` denied | Prevented | `ipc_watches_and_newer_metadata_calls_are_denied` (Linux) |
| Use a handle or descriptor it should not have | Explicit handle list: only the three stdio pipes | Every descriptor above 2 is close-on-exec | Prevented | `an_inheritable_handle_does_not_reach_the_worker` (Windows); `an_inheritable_descriptor_does_not_reach_the_worker` (Linux) |
| Read secrets from its environment | Only `PATH`, `SYSTEMROOT` and the profile variables Windows needs | Only `PATH` | Prevented | `only_the_given_environment_reaches_the_worker`; `the_worker_environment_is_cleared` |
| Learn the user's name or profile path | From the profile variables an AppContainer launch requires | Not exposed | Residual on Windows | ADR 0013 |
| Use privileges or capabilities | Token checked for exactly our package SID and no capabilities; every privilege but `SeChangeNotifyPrivilege` removed before it runs | All capabilities dropped; `no_new_privs` | Prevented | `the_worker_runs_in_an_app_container_at_low_integrity` (Windows); `the_worker_has_no_capabilities` (Linux) |
| Exhaust memory | Job commit limit | `RLIMIT_AS` | Mitigated (CPU time is not limited) | `the_memory_limit_applies` |
| Outlive the Core | Job kill-on-close | `PR_SET_PDEATHSIG` | Prevented | `the_worker_dies_with_the_core` |
| Run with a boundary that silently failed to apply | Every control is applied before the first instruction; any failure aborts the start; the start-up probe checks loopback, file and process denial | Same | Prevented | `a_missing_boundary_is_detected`; `a_probe_that_cannot_run_fails_closed`; `a_missing_worker_program_stops_the_core_before_any_worker` |
| Network block disabled because the Base Filtering Engine is stopped | If the Base Filtering Engine were stopped the block might not apply. The start-up probe is expected to notice loopback traffic and the Core to refuse to start; this has not been run. Other traffic would not be noticed | Not applicable | Untested; at most mitigated, and only for loopback | Start-up probe; the last step of section 9 in [`windows-validation.md`](windows-validation.md) is not yet run |
| The optional provisioning script giving administrator rights to code a user process could replace | It derives the package SID itself and never runs `jarvis-core.exe` elevated; it grants only validated interpreter directories | Not applicable | Prevented | CI runs the script end to end on an administrator runner; not yet run on a desktop |
| Exploit a kernel or OS-component vulnerability to leave the boundary | — | — | Out of scope | — |
| A same-user process outside JARVIS tampering with the Core | — | — | Out of scope (see known gaps) | — |

### The RPC interface

| Threat | Mitigation | Status | Evidence |
| --- | --- | --- | --- |
| Other local users | Socket in a `0700` directory and `0600` itself, peer UID check; named pipe owned by the current user with a DACL for that user only and a medium no-read-up label, remote clients rejected, and the Core's own check of the client's token: same user SID, not an AppContainer, not below medium integrity, read by impersonating the client; a token that cannot be read is refused. Windows allows that impersonation for a client that opened the pipe without security flags only after the client has sent something, so the Core waits up to one second for its first bytes (accepting waits too, so a same-user process can slow new connections, not bypass the check) | Implemented | `the_rpc_socket_is_private_to_the_user`; `a_client_that_writes_late_is_still_served` (Windows, served after a late first write, and refused if it never writes); `the_worker_cannot_open_an_owner_only_pipe` (Windows, the DACL and label); `a_client_that_hides_its_token_is_refused_audited_and_does_not_block_others` and `reading_a_client_token_leaves_the_thread_as_itself` (Windows, a real token over a real pipe); `unidentified_peers_and_other_users_are_refused` (the refusal for each token class, with constructed values); the cross-account run in `windows-validation.md` (the DACL). A real other-user or low-integrity token reaching the Core's check is not tested: the DACL and label stop both first |
| Network exposure | No TCP listener exists | Implemented | Architecture |
| Endpoint squatting | Unix: refuse a directory others can enter, refuse to start if another Core answers on the socket. Windows: first-instance flag, start fails if the name is taken; the client refuses a pipe that another account owns or that is labelled below medium integrity, so a pipe created while the Core is stopped by another account or a low-integrity process receives nothing | Implemented | `the_rpc_socket_is_private_to_the_user`; `a_second_core_cannot_use_the_same_database`; `a_live_endpoint_cannot_be_taken_by_a_second_listener`; `the_core_pipe_is_owned_by_its_user`, `a_client_accepts_only_a_pipe_of_its_own_user_at_medium_integrity` (Windows); the cross-account squat in `windows-validation.md` |
| Stale connections across a stop or restart | A Core that stops closes every open connection; a restarted Core accepts new connections only, and approvals never survive a restart (ADR 0009) | Implemented | `connections_close_when_the_core_stops_and_a_restarted_core_serves_new_clients` |
| Malformed or oversized requests | Strict decoding, 16 KiB limit (connection closed when exceeded), version check | Implemented | `the_rpc_interface_is_strict_and_bounded`; RPC decoding tests and fixtures |
| Resource exhaustion by clients | At most 16 connections, idle timeout, long polls capped at 60 s, write timeout | Implemented | `the_rpc_interface_is_strict_and_bounded` |
| Remote shutdown by any client | `shutdown` is refused unless the configuration allows it | Implemented | `shutdown_over_rpc_can_be_disabled` |

### Supervision and durability

| Threat | Mitigation | Status | Evidence |
| --- | --- | --- | --- |
| Worker crash or hang | Exit detected and recorded; pending approvals expired; the job is requeued, or ends interrupted when its attempts are spent or a task of it has an unknown outcome (ADR 0015); handshake and job timeouts kill a stuck worker. The job timeout also applies while a request waits for a person and while buffered requests are handled | Implemented | `a_crashing_worker_is_restarted_until_the_budget_is_spent`; `a_silent_worker_is_killed_at_the_handshake_timeout`; `a_job_that_runs_too_long_ends_the_session`; `the_job_time_limit_applies_while_waiting_for_a_person`; `buffered_requests_do_not_extend_a_job_past_its_limit`; `a_worker_that_dies_while_waiting_for_approval_leaves_nothing_usable`; `a_job_whose_attempts_are_spent_ends_interrupted`; `a_job_whose_worker_keeps_dying_replays_its_first_step_until_the_attempts_are_spent` |
| Restart loops | Exponential backoff and a restart budget per time window; after that the Core reports itself unhealthy and refuses jobs | Implemented | `RestartPolicy` unit tests; `a_crashing_worker_is_restarted_until_the_budget_is_spent` |
| Worker outliving the Core | Job object kill-on-close (Windows), `PR_SET_PDEATHSIG` (Linux) | Implemented | `the_worker_dies_with_the_core`; `dropping_the_process_kills_the_worker` |
| Core crash mid-task | WAL with `synchronous=FULL`; start-up recovery closes tasks and approvals left open and settles running jobs; queued jobs stay queued | Implemented | `recovery_marks_unfinished_tasks`; `start_up_recovers_what_a_previous_run_left_open`; `a_queued_job_stays_queued_across_recovery`; `recovery_requeues_a_running_job_until_its_attempts_are_spent` |
| Resuming a job repeats a side effect | A step is replayed from its stored result only if the earlier task completed and the new request, current policy and the stored result still check out. A task that started and did not end `completed`, or `failed` with an error the tool reported, quarantines its job; so do a tool that panicked and a result the Core rejected after the tool ran. A class B step at an open position gets a new task and a new fingerprint, so no earlier approval matches it | Implemented | `a_completed_step_is_replayed_and_the_next_one_runs_normally`; `a_request_that_differs_from_the_completed_step_fails_the_job`; `a_step_that_policy_now_denies_is_not_replayed`; `a_stored_result_that_does_not_decode_is_not_replayed`; `a_task_with_an_unknown_outcome_quarantines_its_job`; `a_failure_the_tool_did_not_report_quarantines_its_job`; `a_tool_cancelled_by_shutdown_quarantines_its_job`; `a_completed_write_is_replayed_without_a_new_approval`; `a_job_resumes_after_a_core_crash_without_repeating_a_completed_step` |
| Endless retries of a job that kills its worker | At most `max_job_attempts` claims per job (1 to 10, default 3); the job timeout applies to each attempt; the worker restart budget still applies | Implemented | `a_job_whose_attempts_are_spent_ends_interrupted`; `a_job_whose_worker_keeps_dying_replays_its_first_step_until_the_attempts_are_spent` |
| Two Cores on one database | Exclusive lock file | Implemented | `second_core_cannot_open_same_database`; `a_second_core_cannot_use_the_same_database` |
| Audit tampering by Core bugs | Append-only triggers with `recursive_triggers` on; immutable terminal rows | Implemented | `audit_log_is_append_only`; trigger tests |
| Audit tampering with file access | Not addressed. Anyone with write access to the database file can rewrite it | Planned | — |
| Log or terminal injection | Worker and client text is escaped before it reaches the wire, the audit log, the logs or the CLI; control and invisible characters are removed from model text as it arrives (`strip_hidden`) | Implemented | `worker_text_in_errors_is_escaped`; `error_messages_are_sanitised`; `hidden_characters_are_stripped_from_model_text` |
| Credential leakage to the worker | Cleared environment with no config option to add variables; no inherited descriptors or handles; no readable credential files | Implemented | `the_worker_environment_is_cleared`; `only_the_given_environment_reaches_the_worker`; the descriptor and handle probes |

### The local model (ADR 0021)

Only present when `[inference]` is configured. The model has no tools: no tool definition is sent to it, no tool call is parsed from it, and nothing it writes reaches the policy, the approval store, the worker or the Session Agent.

| Threat | Mitigation | Status | Evidence |
| --- | --- | --- | --- |
| Prompt injection: text the person pastes (an e-mail, a web page) tells the model to act | The model cannot act. At most a reply may carry one clipboard suggestion (`proposal`). The Core reads it only if the person's own last message, outside quoted or pasted text, asks for a copy (`asks_for_copy`), and only if the line passes the clipboard allowlist (ADR 0020). The client shows it with a button; pressing it submits an ordinary job, which policy holds for confirmation (`desktop.clipboard.write` must be opted in) and a person approves by fingerprint with the exact text shown. So an injection can at most produce a suggestion that a person sees in full and must accept twice. In the recorded evaluation the model did write a clipboard block when a pasted e-mail asked it to, and the gate suppressed it | Implemented | `only_the_persons_own_words_can_ask_for_a_copy`; `only_a_clean_clipboard_block_is_a_proposal`; the clipboard approval path (ADR 0020) |
| Model output treated as markup or code by a client | Replies are stored and returned as plain text and the protocol has no field for markup. A client must render them as text; the desktop client renders them without HTML and never parses them for actions | Implemented in the Core; rendering is the client's duty | Protocol types |
| Another machine or user reaches the model server | It listens on `127.0.0.1` only, on a port chosen at each start, and refuses requests without a key made for that start. Its web interface, built-in agent tools, slot endpoint and downloads are switched off | Implemented | `the_server_is_local_keyed_and_has_no_extras`; `keys_are_long_and_fresh` |
| The key is on the server's command line | A same-user process can read it. Such a process can already use the RPC interface, so this adds no authority over the Core | Accepted | ADR 0021 |
| The server is used to reach the Core | The Core refuses RPC connections from the server's process, as it does for the worker | Implemented | Code path (`rpc::refusal` and `Inference::is_server_process`, set from the moment the server is spawned); no automated test |
| Environment variables switch on server features (`LLAMA_ARG_*`) | The server starts with a cleared environment holding only what Windows and the GPU driver need, and a test asserts that no `LLAMA` variable is passed | Implemented | `the_server_is_local_keyed_and_has_no_extras` |
| A swapped or corrupted model file | The configuration pins the file's SHA-256. The Core hashes the file before its first load and refuses a mismatch; a match is remembered for that path, size and modification time. The load is recorded with the hash. A file replaced between the check and the server opening it is not detected | Partial | `inference_loaded` audit event |
| The server consumes unbounded resources or starts programs | A job object with a commit limit, no child processes and kill-on-close; replies bounded in tokens, bytes and time; one reply at a time. The job limits are validated on Windows hardware (`windows-validation.md`) | Implemented, with that validation pending | Configuration range checks; ADR 0021 |
| A hostile or broken server response | Responses are decoded leniently but boundedly: header, chunk, line and body sizes are capped, only the fields read are type-checked, and anything unreadable fails the reply. The text is only stored and shown as text. This is a deliberate exception to the strict-decoding invariant, because the schema is not ours | Implemented | `chunked_bodies_are_decoded_into_lines`; `malformed_chunks_are_refused`; `events_are_read_leniently_but_typed` |
| Conversations cannot be removed | They live in their own SQLite file, not in the append-only audit database. Deleting one or all removes the rows with `secure_delete` on and truncates the write-ahead log; a test checks the files' bytes | Implemented | `deleted_text_does_not_remain_in_the_files`; `deletion_removes_messages_and_retention_removes_old_conversations` |
| Conversations kept longer than wanted | Retention a person chooses in the app (`set_retention`: keep, 7, 30, 90 or 365 days), stored in the conversation database and applied at once; the configuration's `retention_days` is only the default. Each conversation can be exported to a plain file or deleted. On Unix the conversation database files are readable by their owner only; on Windows they inherit the per-user profile folder's access list. Nothing is remembered between conversations | Implemented | `deletion_removes_messages_and_retention_removes_old_conversations`; `settings_are_remembered_and_replaced` |
| Conversation content in the audit log | The audit log records that the model loaded (profile, SHA-256, context size, GPU layers, load time) and why it stopped, never what anyone said | Implemented | `inference_loaded` and `inference_stopped` carry no text fields |
| The worker reads or overwrites the conversation database or the persona | Both are protected paths in the worker's isolation: no grant may contain them | Implemented | `conversations_and_the_persona_are_protected` |
| A game loses the GPU to the model | With the governor enabled, the Core stops the server while a configured game runs and loads it again after the resume delay. A reply being written is cancelled and kept as far as it got; new messages are refused with a reason | Implemented; GPU release is validated on Windows hardware | `windows-validation.md` |
| Oversized or hostile client input | `ChatText` is 1 to 6000 characters with no control or invisible formatting characters; a search is one line of at most 200; every request still fits the 16 KiB frame; the cursor and the context size are range-checked | Implemented | `chat_text_allows_layout_but_not_control_or_invisible_characters`; `chat_send_with_invisible_text.json` |

### The gaming governor

Only present when `[governor]` is enabled (ADR 0016). It adds no tool, capability or RPC operation, and the worker does not know it exists.

| Threat | Mitigation | Status | Evidence |
| --- | --- | --- | --- |
| A job starts while a game runs | The session reads the governor's gate before its single claim and does not claim while it is closed. No attempt is counted and no job timer starts | Implemented | `while_held_a_queued_job_is_not_claimed`; `a_hold_longer_than_the_job_timeout_does_not_use_up_the_job`; `a_requeued_job_is_held_too`; `queued_jobs_wait_while_a_game_runs_and_start_after_it_exits` |
| A job queued before a restart starts before the first check | The Core starts held and the gate is closed before the first session can run; the first reading opens it | Implemented | `no_job_starts_before_the_first_detection`; `a_game_that_is_running_at_start_up_holds_a_job_queued_before_the_restart` |
| The process list cannot be read, so "no game" would be a guess | Any failure to read the whole list is an error that holds the jobs; no read failure is reported as an empty list | Implemented | `a_failed_detection_holds_and_a_streak_is_recorded_once`; the pure `step` tests. That the detection itself returns an error, not a short list, is by construction: no test can make the OS list fail |
| A hold waits for a slow or locked database | The gate closes first and the hold is recorded after | Implemented | `a_game_closes_the_gate_before_the_hold_is_recorded` |
| A hold or alert that cannot be written is lost from the audit log | It waits in memory and is retried, in order, at every later reading; a release is recorded only after everything before it. Events still waiting when the Core stops are lost, and the next start records afresh | Implemented, with that limitation | `an_alert_that_could_not_be_recorded_is_recorded_once_when_the_database_recovers`; `a_hold_that_could_not_be_recorded_is_recorded_once_when_the_database_recovers`; `a_release_waits_for_every_event_before_it_to_be_recorded`; `a_hold_and_an_alert_that_wait_together_are_recorded_in_order` |
| A read of the process list that hangs | A read not finished within one poll counts as failed and holds the jobs; only one read is ever in flight; a late answer is used; shutdown does not wait for it, though the process can take up to 5 s to exit while the blocking thread is outstanding | Implemented | `a_read_that_never_finishes_holds_the_jobs_and_is_not_started_again`; `a_late_answer_to_the_one_read_in_flight_is_used` |
| The governor task dies and leaves the gate open | A guard closes the gate (held, `detection_failed`) if the task ends for any reason but a stop request | Implemented | `if_the_governor_task_dies_the_gate_is_closed`; `a_task_that_is_stopped_leaves_the_gate_as_it_was` |
| A release that is not on the record | The release is written before the gate opens; if the write fails the gate stays shut and tries again | Implemented | `if_the_release_cannot_be_recorded_the_gate_stays_closed_until_it_can`; `the_gate_opens_after_exactly_the_resume_delay_and_the_release_is_recorded_first` |
| Time silently releasing work while the game runs | Time never ends a hold. After `alert_after_ms` one event is recorded and `health` shows `overdue` | Implemented | `a_long_hold_raises_one_alert_and_is_never_released_by_time` |
| The governor touching the game | The process list is a snapshot of names. No process is opened, suspended, inspected or reprioritised, and a running job is never paused. Not tried against any game | Implemented | `a_process_is_found_while_it_runs_and_not_after_it_exits`; `a_hold_that_starts_while_a_job_runs_leaves_it_running` |
| The audit log or `health` becoming a process inventory | Only the configured name that matched is recorded or shown | Implemented | `audit_events_carry_only_the_configured_name` |
| A local process of any account named like a configured game | Not prevented. It holds jobs for as long as it runs. The alert and the audit log make it visible | Accepted | `a_long_hold_raises_one_alert_and_is_never_released_by_time` |
| A game that starts between the gate check and the claim | Not prevented; that job runs. A running job is never paused | Accepted | ADR 0016 |
| Long names matching another program on Linux | `comm` keeps 15 bytes, so names are compared cut to 15. Two programs that share them cannot be told apart | Accepted | `a_linux_name_is_compared_as_the_kernel_keeps_it` (Linux CI) |

## Durability semantics

The Core guarantees that **authority is used at most once**: an approval is consumed in the same transaction that starts execution, and can never be consumed again. It does **not** guarantee that a side effect happens exactly once. If the Core dies after that transaction and before the result is recorded, the write may or may not have happened; the task is marked `interrupted` and the approval stays consumed. A person decides whether to ask again.

Resuming a job keeps to the same rule. It never repeats a step whose completion is recorded, and never repeats a step whose outcome is unknown: a job with such a step is quarantined, not resumed. That is *at most once for a recorded completion*, not exactly-once. A tool can act and the Core can stop before the result is recorded; the action may then have happened once and is never repeated automatically. Resuming also assumes the worker sends the same requests in the same order on every attempt; if it does not, the job fails at the first difference.

## Known gaps

- **The isolation is as strong as the OS mechanisms behind it.** A kernel, AppContainer or Landlock escape is out of scope. The seccomp filter is a denylist of dangerous syscall groups, not an allowlist; an independent review found and closed gaps in an earlier version (signals through file ownership, other processes' limits, System V IPC, newer metadata calls), and a syscall added by a future kernel is allowed until it is listed.
- **On Linux the worker can `stat` paths outside its grants**, learning whether they exist and their size, mode and times (Landlock does not mediate metadata). It cannot read contents.
- **On Windows the worker can read system directories** that grant "ALL APPLICATION PACKAGES" (for example `C:\Windows`, `Program Files`), and learns the user's profile path from the variables an AppContainer launch requires. It can open neither the profile nor anything else of the user's.
- **On Windows the worker can read registry keys that grant "ALL APPLICATION PACKAGES"**, which include parts of the user's `HKEY_CURRENT_USER` such as the Explorer list of recently opened documents. It has no channel out except the typed requests the Core checks, but the names it learns can appear in a request a person reviews. On a desktop run it opened `HKEY_CURRENT_USER\Software` and Explorer's `RecentDocs` for reading. Reading the values in readable keys, not only listing their names, follows from the read access but was not separately recorded, and the full set of readable keys has not been enumerated. A less privileged AppContainer (LPAC), which drops that group, is not implemented: with the current grants CPython does not start under it (process initialisation fails with access denied), so it needs a validated grant list first. It is a possible future mitigation only.
- **On Windows the worker's access to the screen and keyboard state is not proven blocked.** It cannot open the clipboard, but it can obtain a screen device context; whether it can capture screen pixels is not proven either way, and reading keyboard state (`GetAsyncKeyState`) was inconclusive. The controls are the AppContainer, the job's UI restrictions (applied only when the Core is not itself inside a job, unlike CI and some terminals) and the win32k lockdown (ADR 0018), which the kernel reports as set for the worker in either case and which leaves Python code in it without `ctypes`; no test makes a particular window, GDI or input call and checks that it fails. No test reads pixels, key state or the clipboard, so these channels are not proven closed. A named private window station needs administrator rights, and an unnamed one is per logon session and may already belong to other software, so neither isolates the worker for a standard user (ADR 0017).
- **Until the registry and screen and keyboard gaps are resolved, no language model, voice or personal-data integration may run in the worker.** Desktop features are planned for the separate Session Agent instead (ADRs 0017, 0019, 0020; it exists, and its only desktop operation writes approved text to the clipboard), so they do not depend on closing these gaps. Such an integration would give the worker data worth reading, and these are channels through which it could read more than the typed requests show.
- **On Windows the worker can write in its own AppContainer folder** (where `TEMP` points), because Windows grants an AppContainer that folder through an entry no deny entry overrides. The Core empties it before every start, so nothing survives into the next worker, but within one session disk use is bounded only by free space.
- **The Session Agent runs with the user's authority.** It is a trusted helper, not a sandbox: a same-user process at medium integrity can start its own copy, read its memory or open it, as it could any process of the user. That account is already trusted (see below). What is enforced is that the worker cannot reach it and that the Core sends an operation only under a grant from a consumed approval. An operation whose outcome is unknown (the agent did not answer after `perform`) is recorded as such and never retried, which is fail-closed but not exactly-once for an operation with real effects.

- **Clipboard writes are visible to every program of the user.** Once the agent writes approved text, any same-user program can read it or replace it, and clipboard managers that ignore the history and cloud exclusion formats may keep a copy. The agent never reads the clipboard, so nothing on it reaches the Core, the worker or a model. A clipboard held open by another program makes the write fail as busy, never wait (ADR 0020).

- **The agent's executable is recorded, not verified.** The Core starts the configured program, or `jarvis-session-agent` next to its own executable, and records the SHA-256 of what it started in `session_agent_started`. It resolves links and junctions in the path first, then on Windows holds the file open without write or delete sharing from the hash until the process exists, so the file cannot change in between; renaming a directory on the resolved path could still redirect the start. On Linux the file can change between the hash and the start. A same-user process can still replace the file before the Core opens it, and the Core has no trusted value to compare against: the record supports checking after the fact, not prevention. Writing the clipboard adds nothing such a process could not already do.
- **The model server is a large, unsandboxed C++ program that runs with the user's token.** It parses model files and model output and drives a GPU driver. The Core starts it from a configured path with fixed flags, a cleared environment and a job, and gives it no input but the conversation, but a vulnerability in it would give an attacker whatever the user's account can do. It is not isolated like the worker (ADR 0021).
- **A same-user process can read the model server's key** from its command line and talk to the server directly. That process can already use the RPC interface, so this adds no authority over the Core, but it can read or generate model text without the Core seeing it.
- **Reply quality and accuracy are not checked.** Wrong facts, wrong spelling, wrong summaries of pasted text and misleading advice are the model's. The persona instructs it; the Core does not verify the result.
- **Pasted text can open the request gate.** The Core removes text inside quotation marks, guillemets, angle brackets and code fences before looking for a copy request, but cannot tell unquoted pasted text from the person's own words, and earlier injected turns stay in the history. An injected proposal then appears as a suggestion; the person still has to submit it and approve its exact text.
- **The request gate is a heuristic.** `asks_for_copy` looks for words in the person's last message that ask for a copy. A person's own phrasing can slip past it (the suggestion is then simply not offered), and text that is not recognised as quoted can fool it. The gate is a first filter; the approval, which shows the exact text, is the real control.
- **Crisis handling is a heuristic too.** `crisis_signals` matches Portuguese and English phrases for self-harm and medical emergencies; for a match the Core writes the reply's first sentence and adds serious instructions. Words that are ordinary on their own ("não responde", "swallowed", "numb") count only next to a person or a body part in the same clause, so an everyday message rarely triggers it, and a crisis split across a comma ("O meu pai caiu, não responde.") can be missed; when one does, the person gets a serious opening such as "Liga já para o 112." in the middle of an ordinary chat. A crisis described in other words gets only the persona's instructions, which a small model follows less reliably: in a local evaluation with phrasings the lists were not written for, about a third of replies did not point to help. Donna is not an emergency service.
- **Rows written before ADR 0022 still hold their text.** A clipboard text submitted by an earlier build is a job goal and a task argument, and appears in approval views, in the append-only database; nothing rewrites those rows and deleting the conversation does not remove them. Texts submitted since are held as temporary payloads and removed when their job ends.
- **A clipboard text is readable by same-user programs while its job exists.** It sits in `jarvis.db` until the job ends, and the file is readable by the user's own processes. On Unix `jarvis.db` keeps the mode the user's umask gives it; only the conversation database is made owner-only. A process that edits it gets a refusal (the SHA-256 no longer matches), not a different clipboard. Deleted text is overwritten and the log normally truncated (a busy checkpoint is logged and retried at the next one), but a copy made by a backup or file-history tool, or left in a page the file system has not reused, is outside the Core's reach.
- **A Core follows the app that started it only through `--exit-with`.** When the app starts the Core it passes its own process, and the Core stops (as on Ctrl+C) within about a second of that process ending, however it ended. A Core started any other way runs until it is stopped. If the Core itself is killed, its model server and worker die with it (kill-on-close jobs); the next start recovers as after any crash. Sleep and resume are not tested automatically.
- **CPU time is not limited.** A worker that spins wastes CPU until the job or handshake timeout ends its session.
- **A local attacker running as the same user** can edit the config, the policy and the database, and can approve requests. JARVIS does not defend against that account. Neither does it defend against an administrator.
- **On Unix the client does not check who owns the socket it connects to.** The socket directory must be the user's own with mode `0700`, which keeps other users from placing a socket there, but the client itself does not verify it. On Windows the client checks the pipe's owner.
- **The governor trusts the process names on the machine.** A process of any account, named like a configured game, holds queued jobs until it exits: on Windows the snapshot lists the processes of every account and session, and on Linux every `/proc` entry that is visible and readable counts, including other users' processes. This is an accepted availability risk, not a privilege escalation. The hold grants no authority and starts nothing, it is visible through `health` and the overdue alert, and nothing here bounds it. On Linux, `hidepid` or a different PID namespace (a container) makes `/proc` show fewer processes, so a game outside what the Core sees is not seen and nothing reports it; an entry that is visible but unreadable is treated as a failed detection.
- **Some Windows behaviour is verified only on a real desktop:** UI restrictions (CI runs inside a job), a standard (non-administrator) account, and Windows editions other than the CI image. See [`windows-validation.md`](windows-validation.md).
- **Fixture reads have a time-of-check to time-of-use window** between canonicalisation and open; the fixture root is the user's to populate. Writes do not have this problem.
- **Dependencies are pinned by lockfiles** but not yet audited in CI.

## When to revisit this document

- Before adding any tool or capability.
- Before giving the model tools, moving it into the worker, or integrating a speech pipeline or any remote access.
- Before adding a second worker or any other client of the RPC interface.
