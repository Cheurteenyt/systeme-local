# ADR 0009: Gate live Web integration on official Chat-surface capability

Status: accepted

Date: 2026-07-27

Stacked base: C1 commit
`2aee36fdfa3d20c23acdc75eb3348bc54536ef4f` and draft
[PR #67](https://github.com/Cheurteenyt/systeme-local/pull/67)

## Context

C1 established that the local facade, one-tool policy, audit correlation, and
Secure MCP Tunnel can be prepared safely. Those transport facts do not prove
that ChatGPT **Chat** can invoke a custom or local MCP tool. The reviewed OpenAI
Plugins documentation explicitly separates Chat from Work and states that
Plugins are unavailable in Chat.

Repeating the C1 live setup while this product-surface incompatibility remains
would create credentials, processes, and browser exposure without a supported
path to the requested result.

## Decision

C2 commits a strict official-capability profile for the exact tuple:

```text
provider = chatgpt
native surface = chat
surface class = conversational_chat
capability = custom_or_local_mcp_tool_invocation
```

The profile accepts exactly `supported`, `unsupported`, or `unobservable`. Each
official source has a canonical summary, SHA-256 digest, consultation time, and
revalidation deadline. The whole canonical profile has a second SHA-256
commitment.

The current state is `unsupported`. A preflight decision therefore denies all
four protected actions:

- Runtime-key creation;
- Tunnel startup;
- temporary Plugin creation;
- browser testing.

Stale or unobservable evidence also denies every action. A malformed profile,
digest mismatch, time inversion, unknown field, unsupported provider, or
surface mismatch maps to `BLOCKED_BY_SECURITY_INVARIANT`.

## Consequences

No C1 Web test is repeated in C2, and no credential, tunnel, Plugin, or browser
test is created. Transport readiness is preserved as prior C1 evidence but is
not promoted to Chat compatibility.

The provider and surface-class interfaces are reusable data shapes only. Their
current registries contain ChatGPT and conversational Chat alone. A future AI
Web provider requires its own identifier, native-surface mapping, sources,
security review, tests, and seal. This ADR creates no portability or
compatibility claim.

An eventual `supported` profile is necessary but not sufficient for live work:
operator authorization, privacy boundaries, scoped credentials, rollback, and
the complete C1 safety contract would still apply.
