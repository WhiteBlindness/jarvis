# 0006. Dashboard, voice and personal integrations are deferred

**Status:** Accepted

## Context

The long-term system includes a TypeScript dashboard, voice input and output, remote access, and integrations with personal applications. Each of these adds an input channel or a privileged action. Built before the execution core, they would define the security model by accident.

## Decision

Phase 1 builds only the foundation: protocol, Core, policy, durable state, audit and a deterministic Python worker. The dashboard, voice, model routing, remote access and every personal integration are deferred until the foundation is tested.

## Consequences

- The repository has no UI and no model integration. The README says so.
- Each deferred feature must arrive as typed tools with declared capabilities, and the threat model must be updated first.
- When the dashboard arrives, it talks to the Core over a typed RPC interface. It never executes actions itself.
