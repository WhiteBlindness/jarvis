# Protocols

JARVIS has two wire protocols with separate version keys:

| Protocol | Between | Version key | Version |
| --- | --- | --- | --- |
| Worker protocol | The Core and its worker process, over the worker's stdio | `protocol` | 2 |
| Local RPC | Local clients (the CLI) and the long-lived Core | `rpc` | 1 |

The Rust types in `crates/jarvis-protocol` are the reference implementation. The fixtures in `tests/protocol/` are checked by the Rust suite (both protocols) and the Python suite (worker protocol).

## Rules shared by both protocols

- Each frame is one JSON object encoded as UTF-8, followed by `\n`. A trailing `\r` before the newline is tolerated.
- The version key is checked before the schema, and only the receiver's own version is accepted.
- Unknown message types, unknown fields, missing fields and values of the wrong type are rejected. A frame is never partly accepted. Fields whose value may be `null` must still be present.
- Duplicate keys inside one object are not rejected; as in most JSON parsers, the last value wins.
- Identifiers that are UUIDs use the hyphenated form only. Text that a person or worker supplies and that may be shown in a terminal (goals, summaries, reasons) must not contain control characters.

## Worker protocol, version 2

### Transport and framing

- The Core spawns the worker and talks to it over the worker's stdin and stdout. Nothing else may be written to stdout. Logs go to stderr.
- The Core enforces a maximum frame size (64 KiB by default, announced in `welcome`). It stops buffering an oversized frame as soon as it passes the limit, discards the rest of the line, and replies with `frame_too_large`.
- The Core handles the worker's requests one at a time, in order. A worker must keep reading its stdin: if a reply cannot be written within the write timeout (5 s by default), the Core ends the session.

### Session

```
worker                                     core
  | hello ------------------------------->  |
  | <------------------------------- welcome|
  | <----------------------------------- job|   a person submitted a goal
  | tool_request (job_id) --------------->  |   validate, derive capabilities, policy
  |                                          |   [require_confirmation: wait for a person]
  | <------------------------ tool_response|   executed, denied, declined, expired, ...
  | ...                                      |
  | job_result -------------------------->  |
  | <----------------------------------- job|   next goal, whenever one is queued
```

- The first frame must be `hello`. Before it, every error is fatal: a request gets `handshake_required`, and a malformed, oversized or other-version frame gets its own code with `fatal: true`. A worker that does not send `hello` within the handshake timeout is killed.
- The worker works on one job at a time. Every `tool_request` must name the job it belongs to; a request for any other job is refused with `unexpected_message` and creates no task. The job ends when the worker sends `job_result`, or fails when it exceeds the job timeout, in which case the Core ends the session and restarts the worker.
- The Core ends the session by closing the worker's stdin; the worker should then exit.

### Requests that need a person

When policy returns `require_confirmation`, the Core records an approval request and does not reply until a person decides through the local RPC interface or the approval expires. The worker never sees the approval, its identifier on the way in, or any way to grant it. The reply is then one of:

- `completed` or `failed`: a person approved; the Core consumed the approval and ran the tool;
- `declined`: a person refused;
- `expired`: nobody decided in time.

### Worker messages

`hello`:

```json
{"protocol": 2, "type": "hello", "worker": "jarvis-worker", "worker_version": "0.2.0"}
```

`worker` and `worker_version` are 1 to 64 characters from `[A-Za-z0-9._+-]`.

`tool_request`:

```json
{"protocol": 2, "type": "tool_request", "request_id": "req-0001",
 "job_id": "01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b", "tool": "system.info", "args": {}}
```

| Field | Rules |
| --- | --- |
| `request_id` | 1 to 64 characters from `[A-Za-z0-9_-]`, unique within the session |
| `job_id` | The job the worker is working on |
| `tool` | Dot-separated lowercase segments, at least two, up to 64 characters |
| `args` | JSON object matching the tool's argument schema |

There is no field for capabilities, approvals, task IDs or policy. Adding one makes the frame malformed.

`job_result`:

```json
{"protocol": 2, "type": "job_result", "job_id": "…", "outcome": "completed", "summary": "2 call(s): completed=2"}
```

`outcome` is `completed` or `failed`. `summary` is 0 to 1000 characters without control characters.

### Core messages

`welcome`:

```json
{"protocol": 2, "type": "welcome", "session_id": "…", "core_version": "0.2.0",
 "tools": ["filesystem.read_fixture", "system.info", "workspace.write_file"],
 "limits": {"max_frame_bytes": 65536, "tool_timeout_ms": 5000, "max_requests": 1000}}
```

`job`:

```json
{"protocol": 2, "type": "job", "job_id": "…", "goal": "describe the runtime, then read welcome.txt"}
```

`goal` is 1 to 2000 characters without control characters.

`tool_response`, sent for every `tool_request` that becomes a task (it decodes, belongs to the current job, is within the request cap and does not reuse a `request_id`):

```json
{"protocol": 2, "type": "tool_response", "request_id": "req-0001", "task_id": "…",
 "outcome": {"status": "completed", "result": {"os": "linux", "...": "..."}}}
```

| `outcome.status` | Fields | Meaning |
| --- | --- | --- |
| `completed` | `result` | Policy allowed it (with a person's approval where required), the tool ran, the result passed verification |
| `denied` | `capabilities`, `reason` | Policy denied a required capability. Nothing ran |
| `declined` | `approval_id`, `reason` | A person refused. Nothing ran |
| `expired` | `approval_id` | Nobody decided before the approval expired. Nothing ran |
| `rejected` | `error` | Unknown tool or invalid arguments. Nothing ran |
| `failed` | `error` | The tool failed, timed out, was cancelled, or its result was rejected |

`error`, sent for frames that did not create a task. `request_id` is always present, `null` when it could not be recovered. `fatal: true` means the Core is closing the session:

```json
{"protocol": 2, "type": "error", "request_id": null,
 "error": {"code": "unsupported_protocol_version", "message": "…"}, "fatal": true}
```

### Error codes

| Code | Reply | Fatal |
| --- | --- | --- |
| `malformed_frame` | `error` | Before the handshake; afterwards once the error budget is spent |
| `frame_too_large` | `error` | Before the handshake; afterwards once the error budget is spent |
| `unsupported_protocol_version` | `error` | Yes |
| `handshake_required` | `error` | Yes |
| `unexpected_message` | `error` | No, until the error budget is spent |
| `duplicate_request` | `error` | No, until the error budget is spent |
| `unknown_tool` | `tool_response` (`rejected`) | No |
| `invalid_arguments` | `tool_response` (`rejected`) | No |
| `tool_failed` | `tool_response` (`failed`) | No |
| `timeout` | `tool_response` (`failed`) | No |
| `cancelled` | `tool_response` (`failed`) | No |
| `result_rejected` | `tool_response` (`failed`) | No |
| `limit_exceeded` | `error` | Yes |
| `internal` | `error` | Yes |

### Tools

| Tool | Capability | Class | Arguments | Result |
| --- | --- | --- | --- | --- |
| `system.info` | `system.info` | A | `{}` | `os`, `os_family`, `arch`, `logical_cpus`, `core_version`, `protocol_version`, `core_uptime_ms` |
| `filesystem.read_fixture` | `filesystem.read.fixture` | A | `{"path"}` | `path`, `bytes`, `content` |
| `workspace.write_file` | `workspace.write` | B | `{"path", "content"}` | `path`, `bytes`, `created` |

`system.info` never returns hostname, username, environment variables or paths.

`path` is relative to the tool's root directory: the fixture directory for reads, the workspace for writes. It uses `/` as separator and at most 16 components of `[A-Za-z0-9._-]`, each starting with a letter or digit and not ending with `.`. Windows device names are refused. The Core resolves the path beneath a handle to the root directory, so symlinks and junctions cannot lead outside it.

`workspace.write_file` creates or replaces one UTF-8 text file up to the configured size. The parent directory must already exist inside the workspace. The file is written to a temporary name and renamed into place, so a reader sees either the old or the new content, and an existing symlink or hard link at the target is replaced rather than written through. Because the capability is class B, every call needs a person's approval.

## Local RPC, version 1

### Transport

- Unix: a Unix domain socket (mode `0600`) inside a directory that only the owner can open (mode `0700`). The Core checks the peer's user ID, and refuses to start if another Core already answers on the socket.
- Windows: a named pipe that only the current user can open, that refuses remote clients and that fails to start if another process already owns the name. The worker runs at low integrity and cannot open the pipe.
- On both, the Core identifies the peer process through the OS and refuses connections it cannot identify and connections from the worker: the worker itself, any process in its process group or descended from it (Linux), or any process in its job object (Windows). Refusals are recorded as `rpc_client_rejected`.
- One request at a time per connection, each answered by one response. Requests are limited to 16 KiB; a connection that stays idle for 30 s is closed; at most 16 connections are served at once.

### Requests

```json
{"rpc": 1, "type": "approve", "approval_id": "…", "fingerprint": "3f3f…"}
```

| `type` | Fields | Reply |
| --- | --- | --- |
| `health` | | `health` |
| `submit_job` | `goal` | `job` |
| `get_job` | `job_id`, `wait_ms` | `job` (waits up to `wait_ms` for the job to finish) |
| `list_jobs` | `limit` | `jobs` |
| `list_approvals` | `wait_ms` | `approvals` (pending only; waits up to `wait_ms` for one to appear) |
| `get_approval` | `approval_id` | `approval` |
| `approve` | `approval_id`, `fingerprint` | `approval` |
| `deny` | `approval_id`, `reason` | `approval` |
| `shutdown` | | `shutting_down`, or `forbidden` unless the configuration allows it |

`wait_ms` is capped at 60 000. There is no operation that runs a command or a tool directly.

### Approvals

An `approval` reply carries what a person needs to decide: the tool, the derived capabilities, a display-safe description of the arguments (for a write: path, size, SHA-256 and a short escaped preview), the task, request and job IDs, the request time, the expiry and the time left. It also carries the `fingerprint`, a SHA-256 over the task ID, request ID, tool, normalised arguments and capabilities.

`approve` succeeds only if the approval is still pending, has not expired, and the supplied fingerprint equals the stored one. Before the tool runs, the Core consumes the approval only if the stored fingerprint also equals the one it computes from the exact call it is about to execute. The CLI fetches the approval, shows it, and sends the fingerprint it showed, so a person can only approve exactly what was displayed.

### Error codes

`malformed_request`, `unsupported_version`, `request_too_large`, `not_found`, `conflict` (already decided), `expired`, `fingerprint_mismatch`, `forbidden`, `unavailable` (the worker exhausted its restart budget), `internal`.
