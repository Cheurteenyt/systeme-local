# ADR 0015: Bind live Work effects to one revocable C8 cycle

Status: accepted

Date: 2026-07-27

Accepted base: C7 squash commit
`e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f`

## Context

C7 proved only that current official OpenAI documentation supports a
Plugin-mediated custom/local MCP route on ChatGPT Work on the Web. It
deliberately exposed zero tools and performed no live action. Native Chat
remained `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`.

C8 must establish a narrower fact: whether exactly two new synthetic Work
tasks can each invoke the existing read-only probe through Secure MCP Tunnel,
produce separate local audit records and then become unreachable after
revocation. Official eligibility, operator authorization, visible account
entitlement, visible quota and actual call correlation belong to different
trust domains.

The historical C1 finalization also showed that requiring every short-lived
receipt to remain unexpired at final-attestation time is fragile. A valid call
must be proved to have occurred inside its grant window; historical HMAC-bound
evidence does not become false merely because that window later closes.

## Decision

C8 introduces one cycle-wide operator receipt, two fresh UI observations and
one live grant:

```text
explicit bounded operator authorization
    + visible Work surface and entitlement <= 5 minutes old
    + visible usable Work quota <= 5 minutes old
    + current official C8 revalidation
    + exact C7 profile and policy
    -> HMAC-bound grant <= 20 minutes
    -> provider runtime mode chatgpt_work_c8
    -> exactly one effective tool
```

The authorization permits only Plugins, explicit Work selection, a temporary
Tunnel/Plugin connection and at most two new synthetic Work tasks. It
permanently excludes native Chat, automatic switching, existing
conversations, history, account/security settings, private browser state,
writes, files, commands, secrets, real evidence and protocol v2.

The runtime independently reloads the committed C7 and C8 governance, verifies
every HMAC and digest, checks freshness and admits only
`systeme_local_connectivity_probe`. Generic MCP construction cannot satisfy
the `chatgpt_work_c8` mode without the ignored live-cycle bundle.

Each positive call requires a separate HMAC-bound visible task observation,
fresh unique challenge, structured probe response and exactly one matching
local MCP audit record. No conversation identifier or private response
content is retained.

Replay, cross-task reuse, unknown fields and malformed challenges must be
rejected. Capabilities that the one-tool surface does not expose are recorded
as `capability_not_exposed`; a UI negative that cannot safely be attempted may
be `not_safely_exposed`. Post-revocation reachability must never use a skip
state.

Final attestation verifies the chronology and HMAC bindings rather than
requiring an already used grant to remain active. It requires two distinct
ordered Work proofs, negative evidence, stopped listeners, removed Plugin
connection, revoked Runtime key, cleared secrets and a failed
post-revocation Work call.

## Consequences

- C8 remains fail-closed before explicit authorization and fresh Work/quota
  evidence.
- The two-call result cannot be generalized to native Chat or regular use.
- Visible model/reasoning labels may be recorded, but an internal model ID is
  never inferred.
- Runtime key creation and revocation remain operator actions; raw values are
  never stored.
- Final historical evidence can be verified after the live window expires
  without reopening connectivity.
- Another Web AI provider must define its own capability identity, official
  evidence, surface/quota observations, transport mapping and revocation
  contract; ChatGPT receipts are not portable authority.
