# ADR 0002: Keep provider context locally canonical

- Status: Accepted
- Date: 2026-07-18

## Context

Provider projects, chats, quotas and memory are mutable and may be unavailable or undiscoverable.
Lifecycle evidence has different retention and concurrency requirements.

## Decision

Store provider account, quota, project and conversation context in a separate versioned local
registry. Local project and conversation identifiers remain canonical. Provider identifiers are
optional evidence-backed mappings and are never guessed from labels, URLs, tabs or model output.

## Consequences

- lifecycle replay and context mutation remain separate;
- account-wide enumeration is not inferred from known bindings;
- provider memory can assist continuity but cannot replace local state;
- a disconnect never silently creates a replacement conversation.
