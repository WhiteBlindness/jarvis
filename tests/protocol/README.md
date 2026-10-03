# Protocol contract fixtures

Example frames shared by the Rust and Python test suites. They pin the wire format so that neither side can change it alone.

- `worker/` and `core/`: valid messages, one per file. Each side decodes the direction it receives and checks that its own encoding of the direction it sends produces the same JSON value.
- `invalid/worker/` and `invalid/core/`: frames that must be rejected. Each file holds the raw frame as a string and the expected error code.

Files are pretty-printed for review. Comparison is by JSON value, not by bytes.
