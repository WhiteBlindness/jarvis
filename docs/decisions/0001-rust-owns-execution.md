# 0001. The Rust Core owns execution, policy and state

**Status:** Accepted

## Context

An agent runtime has two kinds of code. One kind interprets intent: model calls, retrieval, speech. The other decides and acts: it checks permissions, runs tools, enforces limits and records what happened. The second kind is where a bug becomes a security incident or a corrupted history.

## Decision

All execution, policy evaluation, task state, audit, protocol enforcement, worker supervision, timeouts and cancellation live in the Rust Core. Other components can ask the Core to act. They cannot act themselves.

## Consequences

- Rust's type system carries the security model. The tool set is a closed enum, and capability extraction is an exhaustive match, so adding a tool without declaring its capability does not compile.
- Ownership and `async` cancellation make timeouts and shutdown explicit instead of best-effort.
- Contributors need Rust to change anything security-relevant. That is intended: the boundary should be hard to cross by accident.
- The Core must stay small and boring. Features that are not about deciding or acting belong elsewhere.
