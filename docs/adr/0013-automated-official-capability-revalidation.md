# ADR 0013: Automate official capability revalidation without promotion

Status: accepted

Date: 2026-07-27

## Context

C2 established that current official OpenAI documentation does not expose a
custom or local MCP tool interface in native Chat. C3 separated non-deterministic
official-source acquisition from deterministic reviewed evidence, and C4 made
that reviewed evidence authoritative at runtime.

The remaining operation was periodic manual revalidation. Manual copying is
slow and error-prone, while allowing fetched documentation to update the
active registry would collapse the acquisition and authorization trust
domains.

## Decision

Add a provider-neutral C6 revalidation contract with one production policy for
ChatGPT. The policy binds exact C3 registry/profile digests, reviewed official
URL-and-anchor routes, normalized byte counts, SHA-256 fingerprints, bounded
semantic markers, and review dates.

Acquisition uses only the public read-only OpenAI Docs MCP endpoint. Responses
are treated as untrusted input, validated and normalized in memory, and
reduced to bounded metadata and digests. Raw document bodies are never written
to Git, local state, CI artifacts, or logs.

An exact match may create only a fresh C3 candidate that reproduces the active
reviewed claims. Any drift creates no candidate. Acquisition, reports,
candidates, and scheduled workflows all have zero promotion authority.

Promotion remains a separate deliberate change requiring independent source
review, a committed registry/profile update, a successor seal, full CI, and
code review.

Every acquisition or policy failure is fail-closed. The workflow may report a
warning or error but cannot create credentials, Tunnels, Plugins, chats,
issues, pull requests, commits, tags, releases, tools, or runtime admission.

## Consequences

- Official-source drift becomes visible daily without weakening the runtime
  gate.
- Network instability can fail scheduled governance but cannot change
  capability.
- Exact content fingerprints deliberately create review work for harmless
  official formatting changes; this is preferred to silently accepting drift.
- Provider-neutral types do not make ChatGPT evidence portable. A future
  provider needs a separate policy, official sources, semantics, threat model,
  tests, review, and seal.
- The current ChatGPT result remains
  `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`, with six denials, zero
  effective tools, and zero live actions.
- The scheduled workflow requires outbound access only to the fixed public
  documentation endpoint and keeps repository permissions at
  `contents: read`.
