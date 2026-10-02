# 0003. SQLite is the first and only durable store

**Status:** Accepted

## Context

The Core needs durable task state and an audit trail that survive crashes and restarts on a single machine. It does not need multiple writers across machines.

## Decision

Use SQLite through `rusqlite` with the bundled library, so there is no system dependency on Windows. The database runs in WAL mode with `synchronous=FULL` and foreign keys on. Schema changes are numbered SQL migrations embedded in the binary and recorded in `schema_migrations`. The Core refuses to open a database whose schema is newer than it knows.

Integrity rules live in the schema as well as in code: a uniqueness constraint on `(session_id, request_id)`, a `CHECK` on task status, triggers that make `audit_events` append-only and make terminal tasks immutable. A lock file prevents two Cores from using the same database.

## Consequences

- One file holds the whole state. It is easy to back up, inspect with standard tools and delete in tests.
- A task transition and its audit event commit in the same transaction, so the two tables cannot disagree.
- `synchronous=FULL` costs an fsync per commit. That is the right trade for an audit log at human-scale request rates.
- SQLite calls run on Tokio's blocking pool, so a slow disk does not stall the async runtime.
- Moving to a server database would be a deliberate decision with its own ADR. Nothing in Phase 1 needs it.
