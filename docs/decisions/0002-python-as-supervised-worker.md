# 0002. Python intelligence runs as a separate supervised process

**Status:** Accepted

## Context

Model orchestration, retrieval and speech tooling are strongest in Python. Embedding Python in the Core (for example through PyO3) would put untrusted-input processing inside the trusted process and tie the Core's stability to the interpreter.

## Decision

The intelligence layer is a separate Python process that the Core spawns and supervises. It talks to the Core only through its own stdin and stdout, using the protocol in `docs/protocol.md`. The Core clears its environment, limits the handshake time, records its exit status and kills it if it does not stop during shutdown.

The worker in Phase 1 uses only the Python standard library, so the Core can start it with a plain interpreter.

## Consequences

- A worker crash cannot take down the Core or corrupt its state.
- The pipe is private to the parent and child, so Phase 1 needs no socket authentication, and the design works the same on Windows and Linux.
- The worker can only make typed requests. It cannot reach the policy, the database or the tools.
- The worker is not yet sandboxed by the OS (see the threat model). The process boundary makes that containment possible later without changing the protocol.
- Every request crosses a serialisation boundary. For tool calls measured in milliseconds, that cost is irrelevant.
