# ADR 0014: Separate ChatGPT Work eligibility from live authorization

Status: accepted

Date: 2026-07-27

Accepted base: C6 squash commit
`81bed9b81f266709fab0ea4178f98f0607c3da44`

## Context

C1 historically proved that two manually created synthetic ChatGPT Web test
chats could reach the single read-only local MCP probe through Secure MCP
Tunnel and leave correlated audit records. C2 through C6 then established that
this transport evidence does not prove a supported native Chat interface.
Current reviewed OpenAI documentation makes Plugins available in ChatGPT Work
on the Web and unavailable in Chat.

Treating Work as an alias for Chat would invalidate the existing surface and
privacy boundary. Treating an official support statement as operator
authorization would also collapse evidence, policy and effect authorization
into one trust domain.

## Decision

C7 adds a separate, exact capability identity:

```text
provider = chatgpt
native surface = work
surface class = agentic_work
capability = custom_or_local_mcp_tool_invocation
```

The Work profile has its own reviewed sources, claims, lifecycle and
commitments. It does not modify the historical native Chat profile or its
`BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE` result.

C7 is an overlay on the accepted C3/C4/C6 artifacts. It binds their committed
digests instead of rewriting historical evidence. The overlay names exactly
one future-eligible tool, `systeme_local_connectivity_probe`, with the already
reviewed read-only C4 protocol digest.

Official Work support is necessary but insufficient for any effect. The
default decision denies all six protected actions and exposes zero tools. A
future C8 cycle requires a fresh, HMAC-authenticated operator authorization
receipt bound to:

- the exact Work identity;
- the current C7 profile and policy digests;
- an explicit Work request, visible Work surface and available entitlement;
- a usable Work quota observation no older than five minutes;
- a maximum twenty-minute lifetime;
- no more than two new synthetic Work chats;
- no native Chat, automatic surface switch, existing chat, history, private
  browser state, account/security setting, write, raw secret, real evidence or
  protocol-v2 access.

An exact internal model ID is not required because the Web product does not
promise to expose one. A visible model or reasoning label may be recorded as
bounded context but cannot authorize the surface.

C7 defines and tests this future receipt contract but never creates a receipt
and never performs a live action.

## Consequences

- Chat remains denied and cannot inherit Work evidence.
- Work cannot be selected automatically from a Chat request.
- A fresh official profile alone exposes zero tools.
- A forged, stale, cross-profile, cross-policy or wrong-surface grant fails
  closed.
- C8 can later perform a small Work-only live validation without redesigning
  the trust boundary.
- A later AI Web provider still requires an independent profile, surface
  mapping, sources, threat model, tests and seal. ChatGPT Work evidence is not
  portable.
