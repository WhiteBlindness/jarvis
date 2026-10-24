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
| [0012](0012-worker-containment.md) | OS containment of the worker, without claiming a sandbox (superseded in part by 0013 and 0014) |
| [0013](0013-windows-appcontainer.md) | Isolate the Windows worker in an AppContainer, and check it at start-up |
| [0014](0014-linux-landlock-seccomp.md) | Isolate the Linux worker with Landlock and seccomp |
| [0015](0015-durable-jobs.md) | Durable jobs: resume what is safe, quarantine what is not (amends 0009) |
| [0016](0016-gaming-governor.md) | A gaming governor that defers starting jobs while a configured game runs |
| [0017](0017-session-agent-boundary.md) | Desktop access belongs to a trusted Session Agent, never to the worker (proposed; its channel and grants are implemented by 0019) |
| [0018](0018-windows-win32k-lockdown.md) | The Windows worker cannot make win32k system calls (amends 0013) |
| [0019](0019-session-agent-channel.md) | The first Session Agent: a Core-owned channel and one synthetic operation (implements part of 0017) |
| [0020](0020-clipboard-write.md) | The first desktop operation: writing approved text to the clipboard; typing stays closed |
| [0021](0021-local-inference.md) | A local model brokered by the Core, with no authority (amends 0006 for conversation and a desktop client) |
| [0022](0022-clipboard-payloads.md) | Clipboard text is held as a temporary payload, never in immutable records (amends 0020 and 0021) |
