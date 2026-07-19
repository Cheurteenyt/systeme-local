# Roadmap

Status: reconciled with the implementation through pull request #38

The target architecture remains defined in [`blueprint-v2.md`](blueprint-v2.md). This roadmap
tracks delivery state and gates; it does not redefine normative connectivity or security
contracts.

## Status vocabulary

| Status | Meaning |
|---|---|
| `implemented` | merged on `main` with tests and documentation |
| `partial` | a bounded foundation exists but the complete product capability does not |
| `planned` | accepted direction with no implemented capability |
| `research` | evidence or contract is insufficient for implementation |
| `blocked_by_evidence` | implementation is prohibited until a documented contract exists |
| `out_of_scope` | deliberately excluded from the product boundary |

## Current baseline

| Capability | Status | Boundary |
|---|---|---|
| signed task gateway, policy and replay protection | implemented | local authority remains canonical |
| local single-use approvals | implemented | no remote approval endpoint |
| HMAC audit chain and optional external anchor | implemented | external append-only properties remain operational |
| independent Rust audit witness | implemented | secret-free verification only |
| loopback MCP Streamable HTTP façade | implemented | disabled by default and never publicly exposed directly |
| provider lifecycle and deterministic ChatGPT adapter | implemented | no provider network transport |
| provider context registry and Chat-first policy | implemented | no account-wide discovery |
| attachment metadata, manifests and batching | implemented | no durable bytes or real upload |
| ChatGPT MCP deployment capability profile | implemented | official evidence expires |
| ChatGPT MCP evidence reconciliation and readiness | implemented | ready means next bounded step only |
| sealed operator-evidence bundle | implemented | no live evidence collection |

## Consolidation gate

### Architecture and evidence governance

Status: `in_progress`

This lot aligns README, implemented architecture, roadmap, ChatGPT characterization, threat
model, ADRs, CI, dependency reproducibility and GitHub governance. It adds no capability and
performs no provider connection.

Promotion gate:

- documentation roles are explicit and non-overlapping;
- provider evidence expiry is visible in scheduled governance checks;
- Python lint, format, typing, dependency audit and lock checks are reproducible;
- GitHub governance is recorded from direct evidence or marked unknown;
- complete Python and Rust validation remains green.

## Near-term delivery order

### Provider package compatibility refactor

Status: `planned`

- measure and preserve the current public import surface;
- extract shared UTC, canonical JSON and sorted-unique validation helpers;
- split provider-neutral and ChatGPT-specific subpackages without changing digest domains;
- retain compatibility imports and exact behavior.

### Bounded operator-evidence collection

Status: `planned`

- collect exactly the eleven required observations;
- enforce source compatibility and freshness;
- sanitize and hash outside public models;
- define temporary raw-evidence access, retention and destruction;
- compile and evaluate one fifteen-minute bundle;
- produce only a local blocked/next-step report.

No tunnel, OAuth client or provider call belongs in this lot.

### Secure MCP Tunnel

Status: `planned`

- revalidate current official documentation;
- define installation, update, revocation and rollback;
- protect tunnel credentials outside source control and public models;
- produce a secret-free transport attestation;
- keep the loopback gateway non-public.

### OAuth/OIDC and app configuration

Status: `planned`

Separate lots must define:

- issuer and discovery trust;
- redirect URI and client registration;
- refresh-token capability;
- secret storage and rotation;
- app draft, tool scan, action review, publication and access-control evidence;
- immediate revocation and recovery.

### One supported outbound provider transport

Status: `planned`

Select one official machine contract. It must preserve committed turns, idempotency, lifecycle
events, tool-call governance, cancellation semantics, quota evidence and secret redaction.

### Visible ChatGPT web-session automation

Status: `blocked_by_evidence`

No browser cookie replay, private endpoint, sidebar scraping or DOM completion heuristic is
permitted. The surface remains research unless OpenAI provides a documented, visible and
interruptible mechanism.

## Longer-term target phases

| Target | Status |
|---|---|
| Local Delegation Protocol specification | planned |
| Rust local daemon and policy engine | partial |
| hardened WASI/container/microVM runtime tiers | partial |
| A2A endpoint and durable streaming tasks | planned |
| desktop approval and rollback application | planned |
| signed plugin ecosystem and SDKs | planned |
| enterprise SSO, SIEM and multi-tenant control plane | planned |
| external audit and bug-bounty program | planned |

## Mandatory gates

No capability becomes more powerful without:

- deterministic conformance and policy tests;
- explicit resource, network and data-export bounds;
- isolation and rollback documentation;
- threat-model updates;
- revocation and recovery procedures;
- evidence freshness where provider facts are involved;
- public-schema and digest compatibility review;
- CI and repository-governance checks appropriate to the changed boundary.
