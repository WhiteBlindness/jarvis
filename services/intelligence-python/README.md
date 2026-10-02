# jarvis-worker

The Python intelligence worker for the JARVIS Core. The Core spawns it as a separate process and
talks to it over the worker's own stdin and stdout, using the line-delimited JSON protocol in
[`docs/protocol.md`](../../docs/protocol.md). In Phase 1 there is no model: planning is a
deterministic stub that maps a goal to typed tool calls.

```
python -m jarvis_worker --goal "describe the runtime, then read welcome.txt"
```

Run it from `src/`. The Core does that with a cleared environment, so the worker needs no
installation and no environment variables. It uses only the Python standard library (3.11 or
newer). Frames go to stdout, logs go to stderr. Exit code `0` means every planned call received a
response from the Core, `2` is a usage error and `3` is a session or protocol failure.

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
