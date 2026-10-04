# 0008. Approvals are bound to one exact request and used once

**Status:** Accepted

## Context

Class B capabilities need a person's confirmation. The obvious shortcuts are unsafe: an `approved: true` field supplied by the worker lets the untrusted side grant itself authority, and an approval that names only a tool ("allow writes for five minutes") authorises requests the person never saw. An approval also has to survive the gap between the moment a person reads a request and the moment it runs.

## Decision

- **The worker never handles approvals.** It sends an ordinary `tool_request`. The Core suspends the request, records an approval, and replies only after a decision. Decoding rejects any request field that looks like authority (`approved`, `approval_id`, `fingerprint`, `capabilities`).
- **An approval is a database row, not a token.** It carries its own ID, the task ID, request ID, exact tool name, derived capabilities, issue time and expiry. The task row holds the exact arguments; both are immutable by trigger.
- **A fingerprint binds the decision to the request.** SHA-256 over a canonical JSON encoding of the task ID, request ID, tool, normalised arguments and sorted capabilities. A client approves by sending the approval ID *and* the fingerprint it showed the person. The CLI fetches the approval, prints it, and sends the fingerprint it printed; `--fingerprint` pins an earlier review.
- **Granting and using are separate steps.** Granting is a conditional update `pending → granted`. Using the approval is one transaction: check it is granted, unexpired and still bound to the fingerprint of the exact call about to run, mark it `consumed`, move the task to `executing`, and record `approval_consumed` and `execution_started`. Only then does the tool run.
- **Every approval expires.** By its time-to-live (default five minutes), when its session ends, and when the Core restarts (ADR 0009). Expiry is checked again at grant and at use.
- **States only move forward.** `pending → granted → consumed`, or `pending → denied | expired`, or `granted → expired`. Triggers reject any other transition and any change to a decided approval.

## Consequences

- An approval authorises one request, once. A second identical write needs a new approval with a new fingerprint.
- If the Core crashes after the consuming transaction commits, the approval is spent even if the tool never finished. The guarantee is that authority is used at most once, not that the side effect happens exactly once; recovery marks such a task `interrupted` and a person decides whether to ask again.
- If that transaction cannot commit (for example, the disk is full), the tool does not run and the approval stays unused; start-up recovery then expires it.
- A local client that can reach the RPC endpoint can approve. ADR 0010 and the threat model describe who that is.
