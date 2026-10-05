# jarvis-worker

The Python intelligence worker for the JARVIS Core. The Core spawns it as a separate process and
talks to it over the worker's own stdin and stdout, using the line-delimited JSON protocol in
[`docs/protocol.md`](../../docs/protocol.md). There is no model yet: planning is a deterministic
stub that maps a goal to typed tool calls.

```
python -m jarvis_worker
```

Run it from `src/`. The Core does that with a cleared environment and inside an OS isolation
boundary (an AppContainer on Windows, Landlock and seccomp on Linux): the worker can read its
interpreter and its own source, and has no network, no child processes and no other files. It
needs no installation and no environment variables. It uses only the Python standard
library (3.11 or newer). After the handshake it waits for jobs: for each goal it plans the calls,
asks the Core to run them one at a time, and reports a one-line summary. A call that needs a
person simply takes longer to answer; the worker never sees or handles approvals.

The stub planner understands three phrases, in order of appearance: a topic word (`system`,
`runtime`, `machine`, `environment`) asks for `system.info`; `read <path>` asks for
`filesystem.read_fixture`; `write <path>: <text>` asks for `workspace.write_file` with the rest of
the goal as content.

Frames go to stdout, logs go to stderr. Exit code `0` means the Core closed the session while the
worker was idle, `2` is a usage error and `3` is a session or protocol failure.

## The boundary rule

The worker is untrusted at the protocol boundary. It never reads files, starts processes or opens
network connections itself: it asks the Core, which validates the request, applies policy and
executes it. `tests/test_boundaries.py` guards that rule by scanning the package for the imports
and calls that would break it.

## Development

Requires [uv](https://docs.astral.sh/uv/).

```
uv sync
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

The tests check the shared contract fixtures in `tests/protocol/` at the repository root, the
same files the Rust side checks.
