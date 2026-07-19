# Architecture actuellement implémentée

Status: implemented architecture through pull request #38

This document describes the code that exists on `main`. It is not the target product
architecture; that role belongs to [`blueprint-v2.md`](blueprint-v2.md).

## Documentation authority

| Document | Role |
|---|---|
| [`../README.md`](../README.md) | concise project overview and operator entry points |
| [`blueprint-v2.md`](blueprint-v2.md) | target architecture and long-term design |
| this document | architecture currently implemented |
| [`connectivity-model.md`](connectivity-model.md) | sole normative cross-provider connectivity contract |
| provider-neutral documents in `docs/` | normative contracts for lifecycle, context and attachments |
| provider-specific documents in [`providers/`](providers/) | time-bounded provider facts and implementation status |
| [`roadmap.md`](roadmap.md) | ordered delivery plan and gates |
| [`adr/`](adr/) | accepted architectural decisions and consequences |

## Current trust boundary

```text
remote agent or compatible web host
        |
        | signed task envelope or MCP tool call
        v
loopback gateway
  authentication
  persistent replay protection
  policy-derived capability visibility
  local approval queue
  task processor
  bounded execution
  audit and optional external anchoring
        |
        v
dedicated workspace snapshot and sandbox
```

The local node remains the authority. A provider, MCP client, relay, browser, model response or
operator label cannot expand local permissions.

## Implemented components

### Inbound task and MCP façades

The FastAPI gateway exposes:

- `/v1/tasks` for signed task envelopes;
- an optional loopback-only Streamable HTTP MCP endpoint on `/mcp`;
- a policy-derived MCP tool registry;
- constant-time bearer authentication for MCP;
- `Host`, `Origin`, request-size, rate and concurrency controls;
- conversion of every accepted MCP tool call into the same local `TaskProcessor` path.

The MCP façade is stateless transport. It is not a provider conversation identifier and it does
not create, enumerate or select ChatGPT conversations.

### Local control plane

The implemented local authority includes:

- signed task verification and bounded expiry;
- persistent transactional nonce replay protection;
- deny-by-default policy evaluation;
- local single-use approvals bound to the exact task;
- capability-specific executors;
- minimal HMAC-bound audit records;
- interprocess audit serialization;
- optional external audit anchoring;
- an independent Rust witness verifier, including Windows ACL and Event Log checks.

### Execution plane

Current execution uses capability-specific Python executors and a container sandbox for supported
tasks. Sandbox execution uses a bounded temporary snapshot instead of a writable mount of the
source workspace, disables network by default, removes privileges and enforces resource and output
limits.

The target WASI, hardened sandbox and microVM tiers remain future architecture.

### Provider lifecycle foundation

`systeme_local_gateway.providers` contains a deterministic provider-neutral lifecycle layer:

```text
CommittedTurn
  -> ProviderRun
  -> ordered LifecycleEvent values
  -> ProviderRunState
  -> verified delegation completion
```

The lifecycle store is separate from mutable provider context. Raw prompts, outputs, tool
arguments and provider errors are excluded from the durable event ledger.

### Provider context registry

A separate versioned SQLite registry stores bounded provider account, quota, project and
conversation metadata. It uses compare-and-swap revisions, append-only quota observations and
semantic corruption checks.

Local identifiers and local memory remain canonical. Provider identifiers are optional mappings
and are never guessed from display labels, copied URLs, browser tabs or model output.

### Attachment manifest foundation

Attachment bytes are inspected locally and represented by immutable metadata. The implemented
layer provides:

- bounded PNG, JPEG, PDF, UTF-8 text and strict JSON inspection;
- committed attachments bound to a committed turn;
- ordered manifests;
- evidence-backed capability profiles;
- deterministic all-or-nothing batching;
- metadata-only simulated receipts and ambiguous-acceptance handling.

Encrypted blob storage, redaction, approval, retention and verified deletion are not implemented
and remain a separate security lot.

### ChatGPT MCP deployment and readiness contracts

The ChatGPT-specific inbound MCP path currently has four deterministic layers:

1. an expiring official-evidence deployment capability profile;
2. a conflict-aware official-evidence reconciliation profile;
3. a complete eleven-check readiness observation and staged decision;
4. a sealed operator-evidence bundle that commits only typed states, bounded counts and SHA-256
   digests.

These layers do not install Secure MCP Tunnel, create OAuth credentials, configure an app or
establish a real ChatGPT connection. Every decision remains fail-closed and records that no real
connection or secret storage exists.

## Connectivity directions

The implemented and planned channels remain independent:

| Channel | Direction | Current status |
|---|---|---|
| signed task API | remote caller -> local gateway | implemented |
| local MCP façade | compatible host -> governed local tools | implemented on loopback |
| deterministic provider lifecycle mock | local orchestrator -> simulated provider | implemented |
| ChatGPT custom MCP deployment/readiness contracts | ChatGPT host -> future remote MCP surface | deterministic contracts implemented; live connection absent |
| official outbound provider transport | local orchestrator -> provider | planned |
| provider-approved visible web-session bridge | local orchestrator -> visible web session | research |
| signed interactive handoff | user-mediated | architecture defined; automation absent |

## Implementation-status matrix

| Area | Status | Evidence or boundary |
|---|---|---|
| signed local task gateway | implemented | authentication, replay, policy and audit tests |
| loopback MCP façade | implemented | official-client and out-of-process smoke tests |
| public remote MCP exposure | out_of_scope | direct public exposure is forbidden |
| provider lifecycle and replay | implemented | deterministic fake ChatGPT scenarios and SQLite replay |
| provider context registry | implemented | revisioned SQLite and Chat-first policy |
| attachment metadata and batching | implemented | no real provider upload |
| encrypted attachment storage and redaction | planned | separate security lot |
| ChatGPT MCP deployment eligibility | implemented | expiring official-evidence profile |
| ChatGPT MCP readiness | implemented | conflict-aware staged decision |
| sealed operator-evidence bundle | implemented | no live evidence collection |
| real operator-evidence collection | planned | must follow provider-package refactor |
| Secure MCP Tunnel installation | planned | separate operator-approved lot |
| OAuth/OIDC client and token lifecycle | planned | separate secret-management lot |
| configured ChatGPT app | planned | no current app or connection |
| real outbound OpenAI transport | planned | no credential or network adapter |
| visible ChatGPT web automation | blocked_by_evidence | private endpoints and DOM automation forbidden |
| A2A endpoint | planned | target architecture only |
| desktop control application | planned | target architecture only |

## Public provider package

The current provider package intentionally exposes a compatibility façade from
`systeme_local_gateway.providers`. Its measured size and duplicated primitives are documented in
[`provider-package-audit.md`](provider-package-audit.md).

No broad provider-package reorganization belongs in this reconciliation lot. A follow-up must
preserve public imports and digest domains while extracting shared canonicalization primitives.

## Runtime and data boundaries

The implementation does not:

- expose an unrestricted shell;
- mount the host home directory or Docker socket into provider-facing tasks;
- store provider passwords, browser cookies, API keys or OAuth token values;
- treat an MCP session as ChatGPT conversation identity;
- scrape provider sidebars, private DOM state or undocumented endpoints;
- infer quotas or permissions from UI appearance;
- claim a green CI proves provider evidence is still current after its revalidation date.

## Next architectural gates

The next safe order is:

1. complete documentation, CI and evidence-governance reconciliation;
2. perform a compatibility-preserving provider-package refactor;
3. implement bounded local operator-evidence collection;
4. only then consider separate tunnel, OAuth/OIDC and app-configuration lots using freshly
   revalidated official evidence.
