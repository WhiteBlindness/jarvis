# 0010. Local RPC over a Unix socket or a named pipe

**Status:** Accepted

## Context

A long-lived Core needs a way for local clients (the CLI today, a dashboard later) to submit goals, watch jobs and decide on approvals. Whatever can reach this interface can approve class B actions, so it must not be reachable from the network, from other users, or from the worker.

## Decision

- **Transport.** A Unix domain socket on Unix, a named pipe on Windows. No TCP listener exists.
- **Unix.** The socket lives in a directory created with mode `0700`; an existing directory with group or other permissions, or owned by someone else, is refused rather than changed. The socket itself is `0600`. The peer's user ID (from `SO_PEERCRED`) must match the Core's. A stale socket is removed only if nothing answers on it.
- **Windows.** The pipe is created with an explicit DACL that grants access to the current user only (the default DACL would let every account open it for reading), with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so start-up fails if another process already owns the name, and it rejects remote clients. The client process ID comes from `GetNamedPipeClientProcessId`.
- **The worker is not a client.** A connection whose process cannot be identified is refused, and so is one from the worker: its process ID, its process group or a descendant on Linux, its job object on Windows. On Windows the worker's low integrity level also stops it opening the pipe. Refusals are audited.
- **A small typed protocol.** Nine operations, the same strict decoding rules as the worker protocol, its own version key (`rpc`), requests limited to 16 KiB, an idle timeout, at most 16 concurrent connections, long polls capped at 60 s. `shutdown` is refused unless the configuration allows it.

## Consequences

- Any process running as the same user and able to open the socket or pipe is a trusted client. That matches the rest of the system, where the same account can edit the config and the database, and it is written down in the threat model.
- The worker check on Linux relies on process ancestry. A worker that detaches a process from both its process group and its parent can reach the socket like any other process of the user. Closing that gap needs a separate user or a sandbox for the worker.
- A dashboard can be built on the same interface without new authority: it can only do what the CLI can do.
