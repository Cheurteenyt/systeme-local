# ADR 0011: Enforce provider capability admission before runtime effects

Status: accepted

Date: 2026-07-27

## Context

C3 validates official evidence and returns one atomic capability decision. Its
PowerShell gate blocks the current C1 live entry points, but it does not define
a reusable runtime receipt, an effective tool surface, replay semantics, or a
provider-bound MCP-registry constructor.

Policy-derived local MCP tools and official provider capability are different
authorities. Treating either as sufficient for the other would permit
capability confusion or privilege expansion.

## Decision

Introduce a provider-neutral C4 admission layer between C3 and any
provider-bound effect.

Admission binds the exact provider/surface/capability/action identity, C3
digests and states, C4 adapter digest, UTC time, request correlation, and tool
metadata. It produces an immutable allow/deny decision and canonical receipt.

Only `current` + `reviewed` + `supported` evidence and an allowed C3 action can
continue. Provider-visible tools must also be an exact subset of a reviewed
read-only adapter grant. Denials expose zero tools.

Use a locked process-local correlation table for replay/collision rejection.
Keep the stateless evaluator for deterministic testing, without representing
it as replay protection.

Keep generic local MCP construction separate. A provider-bound runtime must use
explicit provider mode, repeat admission inside the Python process, and use
the admitted constructor. The constructor consumes controller-issued authority
exactly once and verifies the receipt, action, local policy presence, and exact
protocol digest. A canonical receipt digest is integrity, not authentication;
a statelessly forged allow receipt has no tool authority. The reduction-only
registry filter cannot add a policy-denied tool.

Register only ChatGPT in production. Synthetic providers are test fixtures,
not portability claims.

## Consequences

- Current ChatGPT Chat derives zero effective tools and all six actions deny.
- C1 protected entry points call C4 before C1 logic or side effects.
- Provider-bound Python startup repeats C4 before constructing MCP tools or
  initializing the runtime.
- C3 remains the evidence authority; C4 cannot acquire or promote evidence.
- Local MCP policy remains necessary but is insufficient for provider
  exposure.
- Out-of-repository manual actions and independently launched processes remain
  outside local code enforcement and are documented residual risks.
- C4 is not an OS sandbox and makes no host-wide enforcement claim.
- Distributed deployments need a durable atomic replay store before claiming
  cross-process replay resistance.
- Future provider support requires independent evidence, adapter review,
  threat analysis, tests, and a seal.

## Rejected alternatives

- Treat policy-allowed tools as provider-authorized: rejected because local
  policy says nothing about a web surface.
- Treat C3 `supported` as permission for every tool: rejected because official
  interface support does not define local least privilege.
- Let a candidate profile or admission receipt promote support: rejected
  because it collapses review and enforcement authorities.
- Store correlations only in decision JSON: rejected because immutable output
  alone cannot detect replay.
- Accept any self-consistent allow receipt: rejected because a digest does not
  prove that the stateful admission authority issued it.
- Claim OS-wide prevention of manual actions: rejected because C4 controls
  repository boundaries, not arbitrary user processes or provider UI actions.
