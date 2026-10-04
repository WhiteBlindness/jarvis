# JARVIS

A local-first agent runtime with a Rust execution core, typed capabilities and Python intelligence workers.

**Status:** Phase 2. A long-lived Rust Core supervises a contained Python worker, executes typed tools under a capability policy, asks a person before any action with side effects, and records every decision in SQLite. Local clients use a small typed RPC interface. Tested on Linux and Windows. There is no language model, UI, voice or personal integration yet.

## Why it exists

The usual way to let an assistant act on a computer is to hand it a shell. Once a model can choose a command line, every permission check written around commands can be bypassed by quoting, chaining or picking another binary, and nothing records why an action happened.

JARVIS starts from the opposite end: the model never gets operating system access. It can only propose typed requests such as `system.info {}` or `workspace.write_file { "path": "notes.txt", "content": "…" }`. A Rust Core decides whether each request may run, asks a person when policy says so, runs it under limits, and records the decision before acting on it. The goal is autonomy that is safe, observable and recoverable.

## What is technically interesting

- **Capabilities, not commands.** The worker names a tool and its arguments, never a permission. The Core derives the required capabilities through an exhaustive `match`; unlisted capabilities are denied, and the config cannot raise a class B capability to `allow`.
- **Approvals bound to one exact request.** A request that needs a person is suspended in the Core. The worker never sees an approval and has no field to claim one. A person approves through a separate client, which must present the SHA-256 fingerprint of the exact task, request, tool, arguments and capabilities it displayed. The approval is consumed in the same transaction that starts execution, and can never be used twice, outlive its session or survive a restart.
- **Decide, record, then act.** The policy decision, the consumed approval and `execution_started` are committed before a tool runs. Tests inject database failures before and after execution to show what happens in each case.
- **Integrity in the schema, not only in code.** Triggers keep the audit log append-only and make terminal tasks, decided approvals and finished jobs immutable, including against `INSERT OR REPLACE`.
- **A supervised, contained worker.** No shell, a cleared environment, a handshake and a job timeout, restarts with exponential backoff inside a budget, and OS containment applied before the worker runs any code: on Windows a job object (no child processes, memory limit, killed with the Core) and a low-integrity token without privileges; on Linux its own process group, death with the Core, `no_new_privs` and a memory limit.
- **A local RPC interface that refuses the worker.** Unix socket in an owner-only directory, or a named pipe that only the current user can open. Every peer is identified by the OS, and connections from the worker (or anything it started) are refused and audited.
- **Adversarial tests.** A hostile worker process tries smuggled approvals, path traversal, invented tools, replays, requests outside its job and approving its own write over the RPC endpoint, against the real binary.

## Architecture

```
 person ── CLI ── local RPC ──►  Rust Core (jarvis-core serve)              SQLite
                                  rpc → jobs, approvals               ──►  jobs, tasks,
 Python worker ── tool_request ►  decode → capabilities → policy            approvals,
 (contained)   ◄─ tool_response   → [approval] → record → Tool Gateway ──►  audit_events
                                                       │
                                                  typed tools
                          system.info · filesystem.read_fixture · workspace.write_file
```

| Component | Language | Role |
| --- | --- | --- |
| `crates/jarvis-protocol` | Rust | Worker protocol v2 and local RPC v1: closed tool and capability sets, strict decoding |
| `crates/jarvis-core` | Rust | Daemon, RPC server, policy, approvals, Tool Gateway, session, SQLite store, supervision, CLI |
| `crates/jarvis-tools` | Rust | First-party tools behind a `ToolExecutor` trait |
| `crates/jarvis-sandbox` | Rust | Worker containment; the only crate with `unsafe` code |
| `services/intelligence-python` | Python | Worker: protocol client, job loop and a deterministic planner (standard library only) |

Details: [architecture](docs/architecture.md), [protocols](docs/protocol.md), [threat model](docs/threat-model.md), [decisions](docs/decisions/README.md), [Windows validation](docs/windows-validation.md).

## Security model

Every capability belongs to one class:

| Class | Meaning | Today |
| --- | --- | --- |
| A. Allow automatically | Read-only, bounded, no personal data | `system.info`, `filesystem.read.fixture` |
| B. Require confirmation | Side effects inside an approved area | `workspace.write` (write one text file inside the configured workspace) |
| C. Prohibited | Shell, process launch, unrestricted filesystem or network, credentials, the Core's own state | No tool exists, and neither protocol can express them |

The limits are stated plainly in the [threat model](docs/threat-model.md). The worker is contained, not sandboxed: on both platforms it can still read the user's files and open network connections, and on Linux it can also write the user's files. Any process running as the same user can use the RPC interface, which is the trust boundary. Some Windows controls can only be checked on a real desktop; [docs/windows-validation.md](docs/windows-validation.md) lists them.

## Implemented

- Long-lived Core with start-up recovery, worker supervision with a restart budget, graceful shutdown on signals or an authorised RPC request, structured logs and a range-checked TOML config.
- Local RPC: health, submit and wait for jobs, list and wait for approvals, approve, deny, shutdown. CLI commands for each, plus read-only `tasks` and `audit`.
- Human approval for class B requests, bound by fingerprint, single use, with expiry, audited from request to consumption.
- Three tools: `system.info` (no hostname, username, environment or paths), `filesystem.read_fixture` (one configured directory) and `workspace.write_file` (one configured directory, handle-based resolution, atomic replace, no links followed out).
- Worker containment on Windows and Linux, with tests that probe it from a real child process.
- SQLite store with migrations, jobs, tasks, approvals, an append-only audit log, replay protection and crash recovery.
- Python worker with a job loop and a deterministic planner.

## Planned

- A TypeScript dashboard on the RPC interface.
- Model-backed planning in the Python worker, then speech and retrieval.
- A stronger worker sandbox (separate account, AppContainer, namespaces with Landlock and seccomp).
- More tools, each added through the threat model first.

## Stack

Rust 2024 (Tokio, rusqlite with bundled SQLite, serde, clap, tracing, cap-std, sha2, windows-sys) · Python 3.11+ standard library · pytest, mypy, ruff, uv · proptest · GitHub Actions on Linux and Windows

## Run it

Requirements: Rust 1.89 or newer and Python 3.11 or newer. SQLite is compiled in and the worker has no dependencies. On Windows, set `program = "python"` in `config/jarvis.example.toml` and see [docs/windows-validation.md](docs/windows-validation.md).

Start the Core in one terminal:

```bash
cargo run -p jarvis-core -- serve --config config/jarvis.example.toml
```

Use it from another:

```bash
jarvis() { cargo run -q -p jarvis-core -- "$@" --config config/jarvis.example.toml; }
jarvis health
jarvis submit "describe the runtime, then read welcome.txt" --wait
jarvis submit "write notes.txt: remember the milk"
jarvis approvals list
jarvis approvals approve <approval-id>      # shows the request, then asks for `yes`
jarvis jobs
jarvis audit
jarvis shutdown
```

The write waits for a person. `approvals list` shows exactly what would run:

```
approval      01a10319-5022-74aa-80f9-6c29e8f4f896
status        pending
tool          workspace.write_file
capabilities  workspace.write
arguments     bytes = 17
              path = notes.txt
              preview = remember the milk
              sha256 = 0057061a4f16934b96f73f579167f795c4d4c20d8c501fc495197c550af51110
task          01a10319-5021-73d0-ba45-e0c93916f943
request       req-c62b9fe6b5394ff4a60dbfb8da446921
job           01a10319-501e-762a-b088-9295fb881977
requested     2026-10-03T18:49:12.994Z (1s ago)
expires       2026-10-03T18:54:12.994Z (in 4m 59s)
fingerprint   5e849f28156a39774031cb46c7c01891b945407b13b367f4596b2b5f5103fd10
```

After approval the audit log shows the decision, the approval and its consumption recorded before the tool ran:

```
18  policy_evaluated    {"capabilities":["workspace.write"],"decision":"require_confirmation"}
19  approval_requested  {"approval_id":"01a10319-5022-…","fingerprint":"5e849f28…","tool":"workspace.write_file",…}
20  approval_granted    {"approval_id":"01a10319-5022-…","client":"local client pid 6391"}
21  approval_consumed   {"approval_id":"01a10319-5022-…"}
22  execution_started   {"tool":"workspace.write_file"}
23  execution_finished  {"duration_ms":1,"error":null,"status":"completed"}
```

The file appears in `var/workspace/notes.txt`. Try `jarvis approvals deny <id>`, or a goal such as `read ../Cargo.toml` or `write ../escape.txt: x`, to see refusals.

## Test it

```bash
cargo test --workspace          # needs python3 on PATH, or set JARVIS_TEST_PYTHON

cd services/intelligence-python
uv sync && uv run pytest && uv run mypy && uv run ruff check .
```

The Rust suite covers the request pipeline and every refusal path, approvals (grant, deny, expiry, wrong fingerprint, single use, restart, the worker leaving while a request waits, database failures before and after execution), the workspace writer against traversal, links and races, containment probes, worker crashes and restart budgets, signals, recovery and the RPC interface. CI runs it on Linux and Windows, along with the Python checks, the minimum supported Rust version, the documented quick start and a secret scan.

## Repository layout

```
crates/            jarvis-protocol, jarvis-core, jarvis-tools, jarvis-sandbox
services/          intelligence-python (the worker)
config/            example configuration
docs/              architecture, protocols, threat model, decisions, Windows validation
tests/protocol/    contract fixtures shared by Rust and Python
tests/fixtures/    the fixture directory used by the demo
```
