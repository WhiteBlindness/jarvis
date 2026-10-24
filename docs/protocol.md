# Protocols

JARVIS has two wire protocols with separate version keys:

| Protocol | Between | Version key | Version |
| --- | --- | --- | --- |
| Worker protocol | The Core and its worker process, over the worker's stdio | `protocol` | 2 |
| Local RPC | Local clients (the CLI, the desktop app) and the long-lived Core | `rpc` | 4 |

The Rust types in `crates/jarvis-protocol` are the reference implementation. The fixtures in `tests/protocol/` are checked by the Rust suite (both protocols) and the Python suite (worker protocol).

## Rules shared by both protocols

- Each frame is one JSON object encoded as UTF-8, followed by `\n`. A trailing `\r` before the newline is tolerated.
- The version key is checked before the schema, and only the receiver's own version is accepted.
- Unknown message types, unknown fields, missing fields and values of the wrong type are rejected. A frame is never partly accepted. Fields whose value may be `null` must still be present.
- Duplicate keys inside one object are not rejected; as in most JSON parsers, the last value wins.
- Identifiers that are UUIDs use the hyphenated form only. Text that a person or worker supplies and that may be shown in a terminal (goals, summaries, reasons) must not contain control characters.

## Worker protocol, version 3

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
{"protocol": 3, "type": "hello", "worker": "jarvis-worker", "worker_version": "0.2.0"}
```

`worker` and `worker_version` are 1 to 64 characters from `[A-Za-z0-9._+-]`.

`tool_request`:

```json
{"protocol": 3, "type": "tool_request", "request_id": "req-0001",
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
{"protocol": 3, "type": "job_result", "job_id": "…", "outcome": "completed", "summary": "2 call(s): completed=2"}
```

`outcome` is `completed` or `failed`. `summary` is 0 to 1000 characters without control characters.

### Core messages

`welcome`:

```json
{"protocol": 3, "type": "welcome", "session_id": "…", "core_version": "0.2.0",
 "tools": ["filesystem.read_fixture", "system.info", "workspace.write_file"],
 "limits": {"max_frame_bytes": 65536, "tool_timeout_ms": 5000, "max_requests": 1000}}
```

`job`:

```json
{"protocol": 3, "type": "job", "job_id": "…", "goal": "describe the runtime, then read welcome.txt"}
```

`goal` is 1 to 2000 characters without control characters.

`tool_response`, sent for every `tool_request` that becomes a task (it decodes, belongs to the current job, is within the request cap and does not reuse a `request_id`), and for a request answered from the job's earlier work (below):

```json
{"protocol": 3, "type": "tool_response", "request_id": "req-0001", "task_id": "…",
 "outcome": {"status": "completed", "result": {"os": "linux", "...": "..."}}}
```

| `outcome.status` | Fields | Meaning |
| --- | --- | --- |
| `completed` | `result` | Policy allowed it (with a person's approval where required), the tool ran, the result passed verification |
| `denied` | `capabilities`, `reason` | Policy denied a required capability. Nothing ran |
| `declined` | `approval_id`, `reason` | A person refused. Nothing ran |
| `expired` | `approval_id` | Nobody decided before the approval expired. Nothing ran |
| `rejected` | `error` | Unknown tool or invalid arguments. Nothing ran |
| `failed` | `error` | The tool failed, panicked, timed out, was cancelled, or its result was rejected |

A job can be handed out again after its worker or the Core stopped. Requests are counted from 1 in each attempt. If an earlier attempt already completed the step at a position, and the worker now sends the same call there, the Core answers `completed` with the stored result and the `task_id` of the original task. No task is created, no tool runs and no approval is needed. A request that differs from the completed step ends the job as failed and closes the session with a fatal `unexpected_message`. Only positions with a completed step are checked: a request at any other position is a new request with a new task and, for class B, a new approval. A worker that plans the same calls in the same order on every attempt, as the current planner does, never sees the difference.

`error`, sent for frames that did not create a task. `request_id` is always present, `null` when it could not be recovered. `fatal: true` means the Core is closing the session:

```json
{"protocol": 3, "type": "error", "request_id": null,
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
| `internal` | `error`, or `tool_response` (`failed`) when a tool panicked | Yes as an `error`; no as a `tool_response` |

### Tools

| Tool | Capability | Class | Arguments | Result |
| --- | --- | --- | --- | --- |
| `system.info` | `system.info` | A | `{}` | `os`, `os_family`, `arch`, `logical_cpus`, `core_version`, `protocol_version`, `core_uptime_ms` |
| `filesystem.read_fixture` | `filesystem.read.fixture` | A | `{"path"}` | `path`, `bytes`, `content` |
| `workspace.write_file` | `workspace.write` | B | `{"path", "content"}` | `path`, `bytes`, `created` |
| `session_agent.healthcheck` | `session_agent.healthcheck` | B | `{"label"}` | `agent_operation` (a receipt) |
| `desktop.capture_window` | `desktop.screen.observe` | B, `deny` only | `{"target"}` | none: not performable |
| `desktop.read_clipboard_text` | `desktop.clipboard.read` | B, `deny` only | `{}` | none: not performable |
| `desktop.write_clipboard_text` | `desktop.clipboard.write` | B, `deny` by default; may be `require_confirmation` | `{"payload_id", "sha256"}` | `{"agent_operation"}` receipt |
| `desktop.type_text` | `desktop.input.send` | B, `deny` only | `{"target", "text"}` | none: not performable |

`system.info` never returns hostname, username, environment variables or paths.

`path` is relative to the tool's root directory: the fixture directory for reads, the workspace for writes. It uses `/` as separator and at most 16 components of `[A-Za-z0-9._-]`, each starting with a letter or digit and not ending with `.`. Windows device names are refused. The Core resolves the path beneath a handle to the root directory, so symlinks and junctions cannot lead outside it.

`workspace.write_file` creates or replaces one UTF-8 text file up to the configured size. The parent directory must already exist inside the workspace. The file is written to a temporary name and renamed into place, so a reader sees either the old or the new content, and an existing symlink or hard link at the target is replaced rather than written through. Because the capability is class B, every call needs a person's approval.

`session_agent.healthcheck` is performed by the Session Agent, a separate process the Core starts (ADR 0019). `label` is 1 to 64 visible characters. The Core keeps the agent's report and answers the worker with a receipt, `{"agent_operation": "session_agent.healthcheck"}`, whatever an agent operation returns.

`desktop.write_clipboard_text` is performed by the Session Agent when the owner has set `desktop.clipboard.write` to `require_confirmation` (ADR 0020). The request names the text, it does not carry it (ADR 0022; this is what changed in worker protocol version 3). `payload_id` is the identifier of a clipboard payload, a hyphenated UUID, and `sha256` is the SHA-256 of the payload's random 16-byte salt followed by its text, as 64 lowercase hexadecimal characters. The salt is deleted with the payload, so the value cannot be tested against guesses of the text afterwards. A client creates the payload with `submit_clipboard_job`; the Core gives the worker the goal `copy payload:<payload_id>:<sha256>`, and the planner turns exactly that form into the call. The worker never sees the text. Before showing the request and again before running it, the Core resolves the payload, checks that it belongs to the job and that its salted SHA-256 is `sha256`, and refuses the request otherwise. The text is 1 to 1024 characters, each a newline, tab, space, printable ASCII, a letter or digit of any script, or common typographic punctuation (ADR 0020 lists what is refused; the Core checks it when the payload is created). It is written exactly as stored, and the worker gets the same receipt as for the health check. The other `desktop.*` tools are typed so that a person can be shown exactly what one would do, but none can run: the configuration may only `deny` their capabilities. `target` is a window number; for `desktop.type_text`, `text` is at most 4096 visible characters with no control characters at all.

## Session Agent channel, version 1

Between the Core and the Session Agent only, over the agent's standard input and output, which the Core creates for that one child. One JSON object per line, at most 16 KiB, every object carrying `"v": 1`; unknown fields, operations and versions are rejected.

- Agent to Core, once at start: `{"type": "ready", "v": 1, "agent_version": "0.2.0"}`.
- Core to agent: `{"type": "perform", "v": 1, "grant_id": "<approval id>", "operation": {"op": "healthcheck", "label": "ping"}, "ttl_ms": 9800}`. The operations are `healthcheck` and `{"op": "write_clipboard_text", "text": "..."}`.
- Agent to Core, once per `perform`: `{"type": "result", "v": 1, "grant_id": "<the same id>", "outcome": {"status": "done", "report": {"op": "healthcheck", "label": "ping", "performed": 1}}}` or, for a clipboard write, a report of `{"op": "write_clipboard_text", "utf16_units": 41}` (never the text). A refusal, meaning nothing was done, is `{"status": "refused", "reason": "replayed_grant" | "expired" | "clipboard_busy" | "clipboard_unavailable"}`. `{"status": "faulted", "reason": "clipboard_incomplete"}` means the operation started and may have taken effect; the Core records it as unknown.

Anything else from the agent, or no answer within the configured time, ends the agent; see ADR 0019 for how each outcome is recorded.

## Local RPC, version 4

### Transport

- Unix: a Unix domain socket (mode `0600`) inside a directory that only the owner can open (mode `0700`). The Core checks the peer's user ID, and refuses to start if another Core already answers on the socket.
- Windows: a named pipe that only the current user can open, that refuses remote clients and that fails to start if another process already owns the name. The worker's AppContainer package SID is not in the pipe's DACL, so the worker cannot open it.
- The isolated worker cannot reach either endpoint: on Linux it cannot create a socket at all (ADR 0014), on Windows the pipe refuses its identity (ADR 0013).
- On both, the Core also identifies the peer process through the OS, when the connection opens and again before every request, and refuses connections it cannot identify and connections from the worker: the worker itself, any process in its process group or descended from it (Linux), or any process in its job object (Windows). On Windows it also refuses any client whose token is an AppContainer token or below medium integrity, and any client it cannot inspect. Refusals are recorded as `rpc_client_rejected`.
- One request at a time per connection, each answered by one response. Requests are limited to 16 KiB; a connection that stays idle for 30 s is closed; at most 16 connections are served at once.

### Requests

```json
{"rpc": 4, "type": "approve", "approval_id": "…", "fingerprint": "3f3f…"}
```

| `type` | Fields | Reply |
| --- | --- | --- |
| `health` | | `health` |
| `submit_job` | `goal` | `job` |
| `submit_clipboard_job` | `text` | `job` (see Clipboard jobs below) |
| `get_job` | `job_id`, `wait_ms` | `job` (waits up to `wait_ms` for the job to finish) |
| `list_jobs` | `limit` | `jobs` |
| `list_approvals` | `wait_ms` | `approvals` (pending only; waits up to `wait_ms` for one to appear) |
| `get_approval` | `approval_id` | `approval` |
| `approve` | `approval_id`, `fingerprint` | `approval` |
| `deny` | `approval_id`, `reason` | `approval` |
| `shutdown` | | `shutting_down`, or `forbidden` unless the configuration allows it |
| `chat_send` | `conversation_id` (or `null`), `text`, `language` | `chat_turn` |
| `chat_regenerate` | `conversation_id`, `language` | `chat_turn` |
| `chat_poll` | `turn_id`, `cursor`, `wait_ms` | `chat_delta` (waits up to `wait_ms` for new text or a final state) |
| `chat_cancel` | `turn_id` | `chat_delta` |
| `list_conversations` | `query` (or `null`), `limit` | `conversations` |
| `get_conversation` | `conversation_id` | `conversation` |
| `delete_conversation` | `conversation_id` | `deleted` |
| `delete_all_conversations` | | `deleted` |
| `inference_status` | | `inference` |
| `load_model` | | `inference` |
| `unload_model` | | `inference` |
| `set_context_size` | `context_size` | `inference` |
| `set_retention` | `days` (one of 0, 7, 30, 90, 365; 0 keeps conversations) | `inference` |

`wait_ms` is capped at 60 000. There is no operation that runs a command or a tool directly. The conversation operations (everything from `chat_send` on) talk to the local model and the conversation store only; they never reach the policy, the worker or the approval store (ADR 0021). Every field is required; a field that may be `null` must still be present.

### Health

`health` reports the worker (`state`, `pid`, `restarts`, `containment`), the governor, the number of queued jobs and the number of pending approvals. `ok` is false once the worker has failed for good.

`governor` has five fields, all required:

| Field | Meaning |
| --- | --- |
| `state` | `off` (the governor is disabled), `open`, `held` or `releasing` |
| `reason` | While held: `starting` (the first check has not finished), `game` or `detection_failed`; otherwise `null` |
| `process` | While held for `game`: the configured process name that matched; otherwise `null` |
| `held_ms` | While held or releasing: how long the hold has lasted; otherwise `null` |
| `overdue` | True once a hold has lasted longer than the configured alert time |

Version 2 added `governor`, version 3 the conversation and model operations, and version 4 `submit_clipboard_job`, `set_retention` and the retention and warm-up fields of `inference` (see Compatibility below).

The governor also writes three audit events, which are not part of either wire protocol: `governor_hold` (`reason`, and `process` when a game caused it), `governor_released` (`held_ms`) and `governor_hold_overdue` (`held_ms`). They carry the configured process name that matched and nothing else about the process list (ADR 0016).

### Compatibility

The RPC version changes with any change to the wire format, including a field added to a reply: strict decoding means a peer built before the change cannot read it. There is one version at a time and no negotiation. The Core and the CLI must come from the same build.

On a mismatch each side refuses, and neither falls back:

- A newer CLI talking to an older Core: the Core refuses the request with `unsupported_version`, and the refusal carries the Core's older version number, so the CLI reports `the Core speaks RPC version N, this command speaks version M` and exits with a failure.
- An older CLI talking to a newer Core: the Core refuses with `unsupported_version`, encoded at its own version. The older CLI cannot decode that answer either, so it can only report an invalid response. The Core keeps serving.

To upgrade, stop the Core, replace the binaries, and start it again. The database is migrated on start-up and is not affected by the RPC version.

### Conversations and the local model

Available when the `[inference]` section is configured (ADR 0021). Without it, every operation in this section is answered with `unavailable` ("the local model is not configured").

Value types:

| Type | Rules |
| --- | --- |
| `ChatText` (`text`) | 1 to 6000 characters, not blank. Newlines and tabs are allowed; other control characters, carriage returns and invisible formatting characters (zero-width and bidirectional controls) are refused |
| `SearchQuery` (`query`) | 1 to 200 characters on one line, same character rules without newlines or tabs |
| `language` | `pt_pt`, `en` or `auto`. `auto` follows the language of the person's last message |
| `conversation_id`, `turn_id`, `message_id` | Hyphenated UUIDs |
| `context_size` | One of 4096, 8192, 16384, 32768 |
| `limit` | Capped at 200 |

#### Sending a message

```json
{"rpc": 4, "type": "chat_send", "conversation_id": null, "text": "Olá Donna,\ntens um minuto?", "language": "pt_pt"}
```

A `null` `conversation_id` starts a new conversation. The Core stores the person's message, starts the reply and answers at once:

```json
{"rpc": 4, "type": "chat_turn", "conversation_id": "…", "user_message_id": "…", "turn_id": "…"}
```

`turn_id` is the id of the reply being written. `user_message_id` is `null` for `chat_regenerate`, which discards the conversation's last reply and generates another from the same history. One reply is generated at a time, across all conversations and clients. If the model is not loaded the Core loads it in the background; the reply stays `streaming` with no text until the model is ready.

#### Reading a reply

```json
{"rpc": 4, "type": "chat_poll", "turn_id": "…", "cursor": 0, "wait_ms": 20000}
```

`cursor` is a UTF-8 byte offset into the reply text, not a character count. The answer carries the text after it:

```json
{"rpc": 4, "type": "chat_delta", "turn_id": "…", "text": "Sempre. ", "next_cursor": 8,
 "status": "complete", "error": null,
 "stats": {"prompt_tokens": 412, "completion_tokens": 3, "first_token_ms": 180, "tokens_per_second_x10": 552},
 "proposal": "Reunião às 15h"}
```

The client appends `text` and passes `next_cursor` on the next poll, until `status` is final. A `cursor` that is past the end of the reply or not on a character boundary is refused with `malformed_request`. With `wait_ms` above 0 the Core holds the poll until there is new text, the reply is final or the time is up (then `text` is empty and `next_cursor` equals `cursor`). Streaming has its own wake-up, separate from the one for approvals.

| `status` | Meaning | Final |
| --- | --- | --- |
| `streaming` | The model is still writing | No |
| `complete` | The reply finished normally | Yes |
| `cancelled` | A person stopped it (`chat_cancel`), or the model was unloaded while it ran, for example for a game. The text so far is kept | Yes |
| `failed` | The server failed, timed out or sent something unreadable. `error` says briefly why; the text so far is kept | Yes |
| `interrupted` | The reply was unfinished when the Core started again | Yes |

`error`, `stats` and `proposal` are `null` until the reply is final, and `error` stays `null` unless it failed. `stats` holds the measurements of that reply. A reply is bounded in tokens (`max_reply_tokens`), in size (64 KiB) and in time (`reply_timeout_ms`).

`chat_cancel` takes the `turn_id` and answers with a `chat_delta` for the same turn, in its final state.

#### Proposals

`proposal` is at most one line of 1 to 1024 characters, from the clipboard allowlist (ADR 0020), without newline or tab, so that it can be sent unchanged as `submit_clipboard_job`. The Core sets it only when the person's own last message asked for something to be copied, outside any quoted or pasted text, and the reply held one fenced block marked `clipboard` that passes those rules. It is a suggestion: it has no authority and nothing happens unless a client submits it with `submit_clipboard_job`, after which it is an ordinary job. The worker plans it, policy asks for confirmation, and a person approves the exact text as in the approval flow above. Clients must show the text in full and must not submit it without an explicit action by the person.

#### Reading and deleting conversations

`list_conversations` returns the most recently updated first. With a `query`, only conversations with a message containing it (wildcard characters in the query are matched literally), each with a `snippet`: a short excerpt around the first match. Without one, `snippet` is `null`.

```json
{"rpc": 4, "type": "conversations", "conversations": [
  {"conversation_id": "…", "title": "Olá Donna", "created_at": "2026-10-03T18:49:12.994Z",
   "updated_at": "2026-10-03T18:50:01.120Z", "message_count": 4, "snippet": null}]}
```

`get_conversation` answers `conversation` with `conversation_id`, `title`, `created_at`, `updated_at` and `messages`, oldest first. Each message has `message_id`, `role` (`user` or `assistant`), `content`, `status` (as above; a person's message is `complete`), `created_at`, `stats` and `proposal`.

`delete_conversation` and `delete_all_conversations` answer `{"rpc": 4, "type": "deleted", "conversations": 1}` with the number removed. The text is removed from the database file and its write-ahead log, not only marked deleted. A conversation can be deleted while a reply is being written for it; the reply is cancelled.

#### The model

```json
{"rpc": 4, "type": "inference", "state": "ready", "profile": "primary", "model": "…",
 "model_sha256": "…", "context_size": 16384, "gpu_layers": 999,
 "last_error": null, "load_ms": 6200, "last_stats": null,
 "retention_days": 0, "warmup_tokens_per_second_x10": 552, "slow": false}
```

| `state` | Meaning |
| --- | --- |
| `disabled` | No `[inference]` section |
| `unloaded` | Not loaded; the next message, or `load_model`, loads it |
| `loading` | The server is starting and the model file is being checked and read |
| `ready` | Loaded and idle |
| `generating` | A reply is being written |
| `paused_for_game` | The governor reports a game and the configuration says `unload` (ADR 0016) |
| `failed` | The server could not be started or stopped answering; `last_error` says why |

`profile` is `primary`, or `fallback` while a game runs and `on_game = "fallback"`. `load_model` starts loading and answers at once; follow the load with `inference_status`. `unload_model` stops the server and frees its memory, cancelling a reply in progress. `set_context_size` changes the size and reloads a loaded model. `gpu_layers` is the number of layers on the GPU (0 means CPU only), and `load_ms` how long the last load took. `set_retention` stores the retention period in the conversation database, applies it at once and keeps it across restarts; `retention_days` reports it (the configuration's value until a person chooses one). After each load the Core generates a few tokens and reports the measured speed as `warmup_tokens_per_second_x10`; `slow` is true when a model on the GPU measured below the configured `slow_below_tokens_per_second`, which usually means part of it was placed outside video memory.

#### Errors specific to this section

| Code | When |
| --- | --- |
| `conflict` | A reply is already being written, or the model is loading |
| `unavailable` | The model is not configured, is paused for a game, or failed to load (a model file that does not match its SHA-256 is a failed load) |
| `not_found` | Unknown conversation or turn |
| `malformed_request` | Invalid `cursor` or `context_size`, or a `chat_regenerate` with no finished reply to replace |

Text that does not satisfy `ChatText` or `SearchQuery` fails to decode and is refused as `malformed_request` like any other invalid field.

### Clipboard jobs

`submit_clipboard_job` takes `text` (the clipboard text rules of ADR 0020: 1 to 1024 characters, plain) and answers with the queued `job`, like `submit_job`. In one transaction the Core stores the text as a payload, creates the job with the goal `copy payload:<payload_id>:<sha256>` and records `job_submitted`; the text is in no job, task, approval or audit record (ADR 0022). At most 16 payloads wait at once; beyond that the request is refused as `unavailable`. The payload is deleted in the transaction that ends its job, and by start-up recovery for a job that already ended. A job put back in the queue keeps it.

### Approvals

An `approval` reply carries what a person needs to decide: the tool, the derived capabilities, a display-safe description of the arguments (for a write: path, size, SHA-256 and a short escaped preview), the task, request and job IDs, the request time, the expiry and the time left. It also carries the `fingerprint`, a SHA-256 over the task ID, request ID, tool, normalised arguments and capabilities. For a clipboard write the Core resolves the payload while it exists and shows the text in full (`text`, `characters`, `lines`, `bytes`, and the request's `sha256`). Once the payload is gone, `arguments` holds `sha256` and `text` says `the text is no longer kept`; if the stored text no longer has the SHA-256 the request binds, `text` says it was changed and that the request must be refused. Approvals written before ADR 0022 hold the text in their arguments; they stay viewable as a short escaped preview of the stored arguments. Since ADR 0022 the `sha256` a clipboard request binds is taken over a random salt and the text, so it is shown but cannot be checked against a text.

`approve` succeeds only if the approval is still pending, has not expired, and the supplied fingerprint equals the stored one. Before the tool runs, the Core consumes the approval only if the stored fingerprint also equals the one it computes from the exact call it is about to execute. The CLI fetches the approval, shows it, and sends the fingerprint it showed, so a person can only approve exactly what was displayed.

### Error codes

`malformed_request`, `unsupported_version`, `request_too_large`, `not_found`, `conflict` (already decided; for conversations, a reply is already being written or the model is loading), `expired`, `fingerprint_mismatch`, `forbidden`, `unavailable` (the worker exhausted its restart budget; for conversations, the model is not configured, paused or failed to load), `internal`.

### Fixtures

`tests/protocol/rpc/` holds valid examples that the Rust suite checks, among them `request/chat_send.json`, `request/chat_poll.json` and `response/chat_delta.json`. `tests/protocol/invalid/rpc/` holds frames that must be refused, among them `chat_send_without_conversation_field.json` (a nullable field must still be present) and `chat_send_with_invisible_text.json` (a bidirectional control in the text).

### Audit events for the model

Not part of the wire protocol. `inference_loaded` records the profile, the model's SHA-256, the context size, the GPU layers and the load time in milliseconds; `inference_stopped` records why the server stopped (on request, for a game, at shutdown, or because it failed). Neither records any conversation text (ADR 0021).
