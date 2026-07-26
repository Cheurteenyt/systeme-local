# ADR 0008: Bound Chat-surface observability to two sterile conversations

Status: accepted

Date: 2026-07-26

Issue: [#66](https://github.com/Cheurteenyt/systeme-local/issues/66)

## Context

The C0 probe establishes a narrow, read-only MCP connectivity boundary, but its
implementation cannot determine whether a visible ChatGPT page is Chat or
Work, attribute the active Codex runtime from a ChatGPT label, or enumerate
provider conversations. Treating these domains as interchangeable would create
false claims and invite access to unsupported private browser interfaces.

## Decision

C1 uses exactly two newly created Chat pages with local labels only. A signed
pre-prompt observation must classify each visible surface as Chat. Work, Codex,
and unknown observations fail closed without a prompt or Plugin selection.
Existing chats, history, titles, IDs, private requests, cookies, and browser
storage are never evidence sources.

Direct Codex turn metadata is the only accepted source for active runtime model
and reasoning values. `config.toml` values remain configured defaults.
ChatGPT-visible labels are stored in a separate type and never identify hidden
model routing.

Each positive Chat result is bound to a distinct synthetic challenge, strict C0
response, local policy, exact one-tool snapshot, and a distinct HMAC-verified
audit record. Final evidence additionally requires bounded replay and
prompt-injection results plus a failed call after Plugin and Runtime-key
revocation.

## Consequences

C1 can prove reachability from two designated Chat tests without claiming
arbitrary-chat discovery. Account-wide chat detection remains unsupported
unless OpenAI documents a public interface. Live completion requires manual or
freshly authorized bounded browser actions and cannot be produced by fixtures,
local probes, stale receipts, or edited JSON.
