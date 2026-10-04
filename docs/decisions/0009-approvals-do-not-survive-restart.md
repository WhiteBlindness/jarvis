# 0009. Pending approvals do not survive a restart

**Status:** Accepted

## Context

When the Core stops, requests may be waiting for a person, or may have been approved but not yet used. On the next start the worker that asked is gone, its job context is lost, and the situation the person reviewed may have changed.

## Decision

Start-up recovery closes everything that carries authority, in one transaction, before the Core accepts any client:

- pending and granted approvals become `expired`, each with an `approval_expired` event;
- tasks waiting for confirmation become `expired`, tasks that were received or executing become `interrupted`, each with a `task_recovered` event;
- running jobs become `interrupted` and queued jobs `cancelled`.

The same applies, without a restart, when a session ends: the worker exiting, crashing or being restarted expires the approvals of that session.

## Consequences

- No approval issued by one run of the Core can be used by another, and no approval outlives the worker process that asked for it.
- A person who approved just before a crash has to approve again, after the worker asks again. That is the intended cost.
- Queued jobs are not resumed automatically. Resubmitting is a client's decision.
