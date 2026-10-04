# Architecture decisions

Short records of decisions that shape the codebase. Each one states the context, the decision and its consequences. A decision is changed by adding a new record that supersedes it, not by editing history.

| ADR | Decision |
| --- | --- |
| [0001](0001-rust-owns-execution.md) | The Rust Core owns execution, policy and state |
| [0002](0002-python-as-supervised-worker.md) | Python intelligence runs as a separate supervised process |
| [0003](0003-sqlite-first.md) | SQLite is the first and only durable store |
| [0004](0004-typed-capabilities-not-shell.md) | Typed tools and capabilities instead of shell access |
| [0005](0005-no-wasm-sandbox-yet.md) | No WASM plugin sandbox in Phase 1 |
| [0006](0006-defer-ui-voice-integrations.md) | Dashboard, voice and personal integrations are deferred |
| [0007](0007-line-delimited-json-protocol.md) | Strict line-delimited JSON with an exact protocol version |
| [0008](0008-approval-binding.md) | Approvals are bound to one exact request and used once |
| [0009](0009-approvals-do-not-survive-restart.md) | Pending approvals do not survive a restart |
| [0010](0010-local-rpc-transport.md) | Local RPC over a Unix socket or a named pipe |
| [0011](0011-long-lived-core.md) | A long-lived Core that supervises its worker |
| [0012](0012-worker-containment.md) | OS containment of the worker, without claiming a sandbox |
