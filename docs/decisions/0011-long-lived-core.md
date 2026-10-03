# 0011. A long-lived Core that supervises its worker

**Status:** Accepted

## Context

Phase 1 ran one worker session per invocation. Approvals need a process that stays up while a person decides, and clients need something to talk to. A long-lived process also needs rules for a worker that crashes, hangs or never starts.

## Decision

- `jarvis-core serve` opens the store (exclusive lock, migrations), runs start-up recovery, records `core_started`, binds the RPC endpoint and prints `ready <endpoint>`.
- The Core starts and contains the worker (ADR 0012), runs one session with it, and hands it one queued job at a time. A job that exceeds `job_timeout` fails and the worker is restarted.
- When the worker stops, the Core restarts it with exponential backoff (doubling from `backoff_initial` up to `backoff_max`, reset after a healthy run). At most `restart_budget` restarts are allowed within `restart_window`. Once the budget is spent the Core stops restarting, reports itself unhealthy, refuses new jobs and waits for shutdown. Every step is audited: `worker_spawned`, `worker_exited`, `worker_killed`, `worker_restart_scheduled`, `worker_restart_abandoned`.
- Shutdown comes from a signal (SIGINT, SIGTERM, Ctrl+C, Ctrl+Break, console close) or an authorised RPC request. It cancels the running tool, expires pending approvals, closes the worker's stdin, kills the worker after the grace period, stops the RPC server and records `core_stopped` with the reason. A second signal exits immediately.
- The worker never outlives the Core: on Windows the job object kills it when the Core's handle closes, on Linux `PR_SET_PDEATHSIG` kills it when the Core dies.

## Consequences

- There is no restart loop: a worker that fails repeatedly costs at most `restart_budget` restarts per window.
- Exit codes tell an operator what happened: 0 for a clean shutdown, 2 if the worker had been given up on, 1 for a Core error.
- One worker, one job at a time. Concurrency across workers is future work and needs per-worker policy.
