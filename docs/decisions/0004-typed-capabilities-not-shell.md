# 0004. Typed tools and capabilities instead of shell access

**Status:** Accepted

## Context

The easiest way to give an agent power is a shell tool. It is also the way that makes every permission check meaningless: once a model can choose a command line, any policy written in terms of commands can be bypassed by quoting, chaining or a different binary.

## Decision

Tools are typed operations with typed arguments, such as `system.info {}` or `filesystem.read_fixture { path }`. Each tool maps to one or more capabilities (`system.info`, `filesystem.read.fixture`) through an exhaustive match in the Core. The worker names a tool and its arguments. It never names a capability. Policy maps each capability to `allow`, `require_confirmation` or `deny`, and the most restrictive decision wins. Unlisted capabilities are denied.

## Consequences

- Policy is written in terms of intent (read a fixture), not syntax (a command string), so it can be reviewed and tested.
- Each new ability costs a new tool and a capability. That friction is the point.
- Tool names and capability names are separate namespaces. Several tools can share one capability.
- Some tasks that a shell handles in one line will need several typed tools. That is accepted.
