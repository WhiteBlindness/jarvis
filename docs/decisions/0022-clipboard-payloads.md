# 0022. Clipboard text is held as a temporary payload, never in immutable records

**Status:** Accepted. Amends ADR 0020 (where the approved text is kept) and ADR 0021 (how a clipboard proposal is submitted). Leaves ADRs 0008, 0009 and 0015 in force.

## Context

Since ADR 0020, the text a person approves for the clipboard is written verbatim into two immutable places: the job's goal (`copy "<text>"`) and the task's arguments. Both columns are covered by identity-immutability triggers from the moment the row is inserted, so the text stays for good, and deleting the conversation it came from (ADR 0021) does not remove it. The project's security model asks for the opposite: minimal retention, no full sensitive contents in logs, and a record a person can still inspect.

The requirement: a new clipboard operation must not leave its raw text in the jobs, tasks or audit tables, while keeping exact-request approval binding (ADR 0008), single use, durable recovery (ADR 0015) and append-only audit. Historical rows are left untouched.

## Options

| | A. Redact at the terminal state | B. Temporary payload (chosen) |
| --- | --- | --- |
| How | Write the text as today; when the job ends, replace it in `jobs.goal` and `tasks.args` with its hash | Keep the text in a mutable working table; the immutable rows only ever hold an identifier and a salted SHA-256 |
| Immutability | Needs a new exception to the identity triggers on `goal` and `args`, which every other guarantee relies on | No trigger changes; the immutable tables never receive the text |
| Crash consistency | Text survives a crash between execution and the end of the job, and stays if the job is quarantined (ADR 0015) | Payload deleted in the transaction that ends the job, and by start-up recovery for jobs already ended |
| Approval binding | Unchanged | The fingerprint covers the payload's identifier and SHA-256; the Core checks the SHA-256 again before showing and before executing, so a changed payload is refused, never written |
| Worker exposure | The worker plans with the text | The worker never sees the text, only a reference |
| Cost | Small schema change, large weakening of a core invariant | A new tool argument shape (worker protocol version 3), a migration adding one table, a new RPC operation, and resolution in the approval view and the Session Agent path |

Option A was rejected: it buys a smaller change with an exception to the property the audit trail depends on.

## Decision

**Payloads.** Migration 0004 adds `payloads (payload_id, job_id, sha256, salt, text, created_at)`. It is a working table like pending approvals, not evidence: rows are deleted, never kept. `jarvis.db` runs with `secure_delete` on, and the write-ahead log is checkpointed and truncated after payloads are deleted, so the text does not normally linger in either file. If another program holds the file and the checkpoint stays busy after a short retry, the Core logs a warning and the next truncating checkpoint removes the text.

**One way in.** A client submits a clipboard text with the RPC operation `submit_clipboard_job {text}`. In one transaction the Core stores the payload, creates the job with the goal `copy payload:<payload_id>:<sha256>` and records `job_submitted`. There is no other way to put clipboard text into a job: the worker's planner no longer accepts `copy "<text>"`, and the tool `desktop.write_clipboard_text` takes `{payload_id, sha256}` instead of `text` (worker protocol version 3). The number of payloads waiting at once is bounded. The CLI gains `jarvis-core clipboard "<text>"`; that puts the text on the command line and in the shell's history, so it is meant for testing, not for secrets.

**Salted hash.** The SHA-256 is computed over 16 random bytes followed by the text. The salt is kept only in the payload row and deleted with it. A plain SHA-256 of a short text (a PIN, a one-time code, a phone number) could be recovered from the immutable records or by the worker by trying guesses; the salted value cannot once the salt is gone. Two submissions of the same text are bound to different values.

**Resolution.** The approval view resolves the payload while it exists and shows the full text as before (ADR 0020), after checking its SHA-256 against the request. Execution resolves it again, checks the SHA-256, and gives the Session Agent the text; the agent protocol is unchanged. A missing payload, or one whose SHA-256 differs, is refused before the approval is used.

**Lifetime.** A payload belongs to its job. It is deleted in the same transaction as every transition that ends the job (completed, failed, interrupted, quarantined), and start-up recovery deletes any payload whose job has already ended. A job put back in the queue keeps its payload, so ADR 0015 resumption still works; a step that already completed is replayed from its stored result and needs no payload.

**What remains.** After the job ends, the records show that a clipboard write of a text with this salted SHA-256 was requested, approved by whom and when, and what happened. The approval view then shows the salted SHA-256 and that the text is no longer kept; nobody can check a text against it any more. Rows written before this change still hold their text; nothing rewrites them.

## Consequences

- New clipboard writes leave no raw text in `jobs`, `tasks`, `approvals` or `audit_events`, and none in the database files once their job has ended.
- The worker can no longer read or plan a clipboard text; a same-user process that edits a payload gets a refusal, not a different clipboard.
- The worker protocol and the clipboard tool change shape, so the Core and the worker must be updated together (both ship from this repository).
- A person who needs to see what was copied after the fact cannot: only the hash remains. That is the point.
