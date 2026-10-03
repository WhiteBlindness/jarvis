# 0007. Strict line-delimited JSON with an exact protocol version

**Status:** Accepted

## Context

The Core and the worker are written in different languages and ship from the same repository. The protocol must be easy to implement with the Python standard library, easy to inspect while debugging, and hard to misuse.

## Decision

- **Framing:** one JSON object per line over stdio, UTF-8, with a maximum frame size enforced while reading.
- **Versioning:** every frame carries `"protocol": 1`. The Core accepts only its own version, and any mismatch closes the session. Any change to the wire format bumps the version.
- **Strictness:** unknown message types and unknown fields are rejected, on both sides.
- **Contract tests:** example frames live in `tests/protocol/`. The Rust and Python test suites both check them, so neither side can drift alone.

## Consequences

- Strict decoding rules out forward-compatible additions without a version bump. Because both sides ship together, that is acceptable, and it prevents a worker from attaching fields such as `approved` that an older Core would silently ignore.
- JSON costs more bytes and parsing time than a binary format. At this request rate it does not matter, and it keeps the worker free of dependencies.
- A future network transport can reuse the same messages with a different framing layer.
