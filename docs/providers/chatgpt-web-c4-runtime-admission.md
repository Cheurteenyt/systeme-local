# C4 provider-neutral runtime admission

Status: `implemented` on the C4 branch; current ChatGPT Chat admission is
`denied`.

Base commit: `9140801e88ed44afca9481ac06288783a0d52da2`

Issue: [#71](https://github.com/Cheurteenyt/systeme-local/issues/71)

## Purpose

C3 answers whether official evidence supports a provider capability. C4 turns
that reviewed answer into an immutable runtime decision before a protected
effect or provider-visible tool surface can exist.

C4 does not make ChatGPT support true. It does not acquire official evidence,
promote a C3 candidate, start a process, create a credential, control a
browser, or call ChatGPT. It consumes only the committed C3 result.

The production registry contains exactly one adapter:

| Field | Value |
|---|---|
| Provider | `chatgpt` |
| Native surface | `chat` |
| Surface class | `conversational_chat` |
| Capability | `custom_or_local_mcp_tool_invocation` |
| Maximum tool grant | `systeme_local_connectivity_probe` |
| Access | read-only, non-destructive, not high-risk |
| Tool protocol SHA-256 | `de0389f0a2329daa8afa3ad8126eb6e3e80aba1b77ed2e0f29998c37c383c65b` |
| Registry SHA-256 | `c63ae8d266ba25f7871b60f4f36b659b97a4f17e6fd13fc32b7acd6dcf85c20d` |

The maximum grant is not an effective grant. Current unsupported evidence
reduces the effective ChatGPT tool set to empty.

## Trust domains

```text
official source review
    -> C3 reviewed profile and capability registry
    -> C3 lifecycle/support/action decision
    -> immutable C4 admission request
    -> C4 production adapter + exact tool metadata
    -> allow or deny + effective tools
    -> canonical decision receipt
    -> one-time controller-issued tool authority
    -> provider-bound boundary may continue only on allow
```

Evidence acquisition, evidence promotion, admission, MCP tool construction,
and live validation are separate authorities. A receipt cannot modify C3
evidence or register a provider.

## Admission contract

Every request binds:

- provider ID, native surface, surface class, and capability;
- one of the five C3 actions or `tool_surface_exposure`;
- exact requested tool metadata;
- normalized UTC evaluation time;
- a `c4_` correlation containing 128 random bits;
- a canonical request SHA-256.

Every decision binds:

- the request identity, action, time, correlation, and digest;
- C3 registry, profile, evidence, and decision digests;
- C3 lifecycle, reviewer, and support states;
- the C4 adapter-registry digest;
- requested and effective tool tuples;
- allow/deny and a closed reason code;
- a self-verifying canonical receipt SHA-256.

Allowed decisions require `current` + `reviewed` + `supported`, the mapped C3
action allowed, an exact adapter identity, and an exact read-only tool subset.
A denial always contains zero effective tools.

The receipt SHA-256 proves canonical integrity, not authority or authenticity.
For provider tool exposure, `RuntimeAdmissionController` must have issued the
allow decision and the provider-bound constructor must consume that authority
exactly once. A separately reconstructed, self-consistent allow receipt cannot
expose tools.

## Current action and tool matrix

| Action | Current result | Effective tools |
|---|---|---|
| Runtime-key creation | deny | none |
| Tunnel startup | deny | none |
| Plugin creation | deny | none |
| Browser test | deny | none |
| ChatGPT action | deny | none |
| Provider tool-surface exposure | deny | none |

The common reason is `official_capability_unsupported`. Lifecycle due,
expired, drifted, invalid, candidate, mismatched, unknown, replayed, collided,
or privilege-expanded inputs have more specific denial reasons.

## Bypass audit

| Boundary | Pre-C4 condition | C4 control | Remaining boundary |
|---|---|---|---|
| `Prepare-C1.ps1` | C3 denied the action, but produced no runtime receipt | C4 admission executes before C1 state or secret generation | PowerShell cannot prevent a person creating a key outside the repository |
| `Start-C1Facade.ps1` | C3 used the broader browser action | exact `tool_surface_exposure` admission requests the approved tool metadata before environment mutation or any process | generic local MCP is not automatically a web-provider surface |
| `Start-C1Tunnel.ps1` | C3 denied Tunnel startup | C4 admission executes before credential reads, environment mutation, ports, or `Start-Process` | an independently launched external binary is outside repository enforcement |
| `Show-C1OperatorSteps.ps1` | C3 denied Plugin guidance | C4 admission executes before C1 guidance | provider UI changes still require separate human authorization |
| C1 branch guard | descendant C2/C3 branches could never pass the historical exact-branch check | current runtime requires the exact C4 branch and exact reviewed C1 ancestry | historical C1 evidence keeps its historical branch value |
| `McpToolRegistry` | policy alone derived the local tool set | an optional effective scope can only reduce policy tools | the generic registry remains a local primitive, not provider authorization |
| provider-bound Python startup | a direct `systeme_local_gateway.main` import could otherwise bypass the PowerShell check | `chatgpt_chat_c4` mode rebuilds reviewed C3/C4 context and denies before registry construction, audit/replay initialization, or listener startup | generic mode remains local-only and carries no provider authorization |
| provider-bound MCP construction | no typed bridge from evidence to a registry | `build_admitted_mcp_registry` verifies and one-time consumes controller-issued authority, then verifies exact action, policy presence, and per-tool protocol digest | callers must use this boundary when classifying a runtime as provider-bound |
| lower-level executor/runtime | can execute only tools already present in its registry and still applies authentication/policy | C4 prevents provider-bound tool construction before these layers | C4 is not an OS sandbox and cannot classify arbitrary out-of-repo processes |

C0 scripts remain historical and branch-locked before their side effects.
They are not a current C4 provider path. Evidence-writing and cleanup scripts
do not themselves perform the five protected effects and remain usable only
under the C1 branch/ancestry guard.

## Replay and concurrency

`RuntimeAdmissionController` owns a locked in-memory correlation table.
Exactly one request may consume a new correlation. An identical second
request is `correlation_replay`; a different request with the same correlation
is `correlation_collision`. Both deny with zero tools.

An admitted tool receipt is also single-use: its controller authority is
atomically removed when the MCP registry is built. Reuse, a receipt issued by
another controller, and a statelessly reconstructed receipt all fail closed.

The table is intentionally process-local. A future distributed runtime must
replace it with an atomic durable store before claiming cross-process replay
protection. The deterministic stateless evaluator exists for tests and policy
composition; it does not claim replay resistance by itself.

## Provider-neutral boundary

The C4 data contract accepts a provider-specific adapter, but the committed
builder and JSON require exactly ChatGPT. Tests may create a `synthetic_ai`
adapter to prove isolation and supported-path mechanics. That adapter is
never serialized to governance, exported by operator scripts, or treated as
implemented support.

A future provider requires its own official C3 evidence identity, production
adapter review, exact native-surface semantics, approved read-only tool
metadata, threat analysis, tests, seal, and merge.

## Operator inspection

From a clean C4 branch:

```powershell
Set-Location 'D:\systeme-local-agent-gateway-github'
.\scripts\c4\Test-C4Preflight.ps1 `
  -Action tool_surface_exposure `
  -RequestApprovedTools
.\scripts\c4\Get-C4ActionMatrix.ps1
.\scripts\c4\Show-C4AdmissionSteps.ps1
```

These commands are offline and secret-free. They read only fixed reviewed JSON
under `governance`, reject reparse points, and cannot start infrastructure.
The current result is six denials and zero effective tools.

## Exact future gate

Live testing remains prohibited until all steps occur in order:

1. official OpenAI documentation explicitly supports custom/local MCP on
   native Chat;
2. an independently reviewed C3 candidate is deliberately promoted and
   merged as `current` + `reviewed` + `supported`;
3. C4 admits only the exact reviewed read-only tool and its protocol digest;
4. separate goal-scoped browser authorization and C1 privacy/revocation
   controls are satisfied;
5. a new bounded live cycle is executed and independently correlated.

Tunnel availability, a visible UI control, a historical C1 receipt, or a
synthetic C4 allow test cannot skip any step.

## Residual risks

- C4 cannot prevent manual actions taken outside repository-controlled entry
  points.
- Process-local replay protection is not distributed replay protection.
- A generic local MCP runtime is not intrinsically classified as a web
  provider surface; explicit provider mode plus the inner Python admission
  and provider-bound constructor are required.
- Official documentation can change before C3 expiry, bounded by scheduled
  real-time governance.
- Tool protocol metadata must be deliberately updated if the C0 probe schema
  changes; mismatch denies.

These are explicit limits, not implied permissions.
