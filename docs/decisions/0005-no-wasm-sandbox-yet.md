# 0005. No WASM plugin sandbox in Phase 1

**Status:** Accepted

## Context

A WASM runtime such as Wasmtime could host third-party tools with strong isolation and explicit host imports. It is the likely long-term answer for user-supplied plugins.

## Decision

Phase 1 has no plugin system and no WASM runtime. All tools are first-party Rust code compiled into the Core and reviewed with it.

## Consequences

- There is no third-party code to isolate yet, so a sandbox would protect nothing today and add a large dependency and a second ABI.
- The Tool Gateway already separates the decision from the execution through the `ToolExecutor` trait. A WASM-backed executor can be added behind it without changing the protocol or the policy.
- The decision will be revisited before the first plugin that is not reviewed as part of this repository.
