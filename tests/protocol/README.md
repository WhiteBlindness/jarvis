# Protocol contract fixtures

Example frames that pin the wire formats so that no side can change them alone.

- `worker/` and `core/`: valid worker-protocol messages (version 2), one per file. The Rust and Python suites each decode the direction they receive and check that their own encoding of the direction they send produces the same JSON value.
- `rpc/request/` and `rpc/response/`: valid local RPC messages (version 1), checked by the Rust suite.
- `invalid/worker/`, `invalid/core/` and `invalid/rpc/`: frames that must be rejected. Each file holds the raw frame as a string and the expected error code.

Files are pretty-printed for review. Comparison is by JSON value, not by bytes.
