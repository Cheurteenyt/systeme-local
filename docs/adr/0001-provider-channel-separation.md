# ADR 0001: Separate provider channels

- Status: Accepted
- Date: 2026-07-18

## Context

MCP tool calls, provider machine transports, visible web conversations and user-mediated handoff
have different initiators, credentials, identifiers and completion semantics. Treating them as
one generic “AI connection” would blur trust boundaries.

## Decision

Maintain four independent channel classes:

1. inbound MCP tools;
2. outbound provider adapter;
3. provider-approved visible web-session bridge;
4. interactive signed handoff.

All channels translate into local canonical tasks and cannot bypass policy, approval, execution
or audit. MCP is never treated as a prompt-submission API.

## Consequences

- one provider surface cannot prove another surface’s capabilities;
- credentials are not reused implicitly;
- conversation identity remains local unless an official surface returns a stable mapping;
- a real integration may require both inbound tools and an outbound provider transport.
