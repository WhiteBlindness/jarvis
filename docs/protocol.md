# Worker protocol, version 1

This is the wire contract between the Rust Core and a worker process. The Rust types in `crates/jarvis-protocol` are the reference implementation. The fixtures in `tests/protocol/` are checked by both the Rust and the Python test suites.

## Transport and framing

- The Core spawns the worker and talks to it over the worker's stdin and stdout. Nothing else may be written to stdout. Logs go to stderr.
- Each frame is one JSON object encoded as UTF-8, followed by `\n`. A trailing `\r` before the newline is tolerated.
- The Core enforces a maximum frame size (64 KiB by default, announced in `welcome`). It stops buffering an oversized frame as soon as it passes the limit, discards the rest of the line, and replies with `frame_too_large`.
- Requests are handled one at a time, in order. A worker may write several requests without waiting, but each reply arrives only after the previous request has finished.

## Versioning

Every frame carries `"protocol": 1`. The Core checks the version before the schema and accepts only its own. A mismatch produces a fatal `unsupported_protocol_version` error and closes the session. Any change to the wire format increases the version.

## Strictness

Both sides reject unknown message types, unknown fields, missing fields and values of the wrong type. A frame is never partly accepted.

## Session

```
worker                                   core
  | hello ----------------------------->  |
  | <----------------------------- welcome|
  | tool_request ---------------------->  |   validate, derive capabilities,
  | <------------------------ tool_response|   evaluate policy, execute, record
  | ...                                    |
  | (close stdout or exit)                 |   session closed, worker reaped
```

The first frame must be `hello`. Anything else before it gets a fatal `handshake_required` error. A worker that does not send `hello` within the handshake timeout is killed. The Core ends the session by closing the worker's stdin; the worker should then exit.

## Worker messages

### `hello`

```json
{"protocol": 1, "type": "hello", "worker": "jarvis-worker", "worker_version": "0.1.0"}
```

`worker` and `worker_version` are 1 to 64 characters from `[A-Za-z0-9._+-]`.

### `tool_request`

```json
{"protocol": 1, "type": "tool_request", "request_id": "req-0001", "tool": "system.info", "args": {}}
```

| Field | Rules |
| --- | --- |
| `request_id` | 1 to 64 characters from `[A-Za-z0-9_-]`, unique within the session |
| `tool` | Dot-separated lowercase segments, at least two, up to 64 characters |
| `args` | JSON object matching the tool's argument schema |

There is no field for capabilities, approvals, task IDs or policy. Adding one makes the frame malformed.

## Core messages

### `welcome`

```json
{
  "protocol": 1, "type": "welcome",
  "session_id": "01928f5e-7c3a-7d10-9a2b-3c4d5e6f7a8b",
  "core_version": "0.1.0",
  "tools": ["filesystem.read_fixture", "system.info"],
  "limits": {"max_frame_bytes": 65536, "tool_timeout_ms": 5000, "max_requests": 1000}
}
```

### `tool_response`

Sent for every well-formed `tool_request`. `task_id` is the durable task the Core created for it.

```json
{"protocol": 1, "type": "tool_response", "request_id": "req-0001",
 "task_id": "01928f5e-7c3b-7a20-8b3c-4d5e6f7a8b9c",
 "outcome": {"status": "completed", "result": {"os": "linux", "...": "..."}}}
```

| `outcome.status` | Fields | Meaning |
| --- | --- | --- |
| `completed` | `result` | Policy allowed it, the tool ran, the result passed verification |
| `denied` | `capabilities`, `reason` | Policy denied a required capability. Nothing ran |
| `confirmation_required` | `capabilities`, `reason` | A human must confirm. Nothing ran. The task expires when the session ends |
| `rejected` | `error` | Unknown tool or invalid arguments. Nothing ran |
| `failed` | `error` | The tool failed, timed out, was cancelled, or its result was rejected |

### `error`

Sent for frames that did not create a task. `request_id` is filled in when the frame contained a valid one. `fatal: true` means the Core is closing the session.

```json
{"protocol": 1, "type": "error", "request_id": null,
 "error": {"code": "unsupported_protocol_version", "message": "..."}, "fatal": true}
```

## Error codes

| Code | Reply | Fatal |
| --- | --- | --- |
| `malformed_frame` | `error` | No, until the session's error budget is spent |
| `frame_too_large` | `error` | No, until the error budget is spent |
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

## Tools

### `system.info`

Capability: `system.info`. Arguments: `{}`.

Result:

| Field | Type | Notes |
| --- | --- | --- |
| `os` | string | `linux`, `windows`, `macos`, ... |
| `os_family` | string | `unix` or `windows` |
| `arch` | string | `x86_64`, `aarch64`, ... |
| `logical_cpus` | integer | Logical CPUs available to the Core |
| `core_version` | string | |
| `protocol_version` | integer | |
| `core_uptime_ms` | integer | |

It does not return hostname, username, environment variables or paths.

### `filesystem.read_fixture`

Capability: `filesystem.read.fixture`. Arguments: `{"path": "notes/welcome.txt"}`.

`path` is relative to the fixture directory the Core is configured with. It uses `/` as separator and at most 16 components of `[A-Za-z0-9._-]`, each starting with a letter or digit and not ending with `.`. Windows device names are refused. The resolved file must stay inside the fixture directory after symlinks are resolved, must be a regular file, must be UTF-8 and must not exceed the configured size limit.

Result: `{"path": "...", "bytes": 6, "content": "hello\n"}`.
