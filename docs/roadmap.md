# Roadmap

Status: reconciled with the implementation through pull request #42 at commit
`1c84538369eb662b61cc4f56a79131569b9ca200`.

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
| architecture, evidence and repository governance | implemented | merged in PR #40 without adding capability |
| private provider canonicalization and compatibility oracles | implemented | merged in PR #42 without public API or digest drift |

## Completed consolidation

### Architecture and evidence governance

Status: `implemented`

Pull request #40 merged as `c720f4ae9d295e3e2af6993b40a0b03bfd14c2b9`. It reconciled
README, implemented architecture, roadmap, ChatGPT characterization, threat model, ADRs, CI,
dependency reproducibility, evidence expiry and GitHub governance without adding a capability or
performing a provider connection.

Completion evidence:

- documentation roles are explicit and non-overlapping;
- provider evidence expiry is visible in scheduled governance checks;
- Python lint, format, typing, dependency audit and lock checks are reproducible;
- GitHub governance is recorded from direct evidence or marked unknown;
- complete Python and Rust validation remained green.

## Near-term delivery order

### Provider canonicalization compatibility refactor

Status: `implemented`

Pull request #42 merged as `1c84538369eb662b61cc4f56a79131569b9ca200` and:

- preserved all 179 ordered public provider exports;
- preserved 18 affected Pydantic contracts, 22 enums and 13 digest domains;
- extracted shared UTC, canonical JSON and sorted-unique validation helpers into one private
  provider-neutral module;
- added deterministic compatibility and ownership oracles;
- retired the provider Mypy baseline from three diagnostics to zero;
- reduced the Ruff formatting baseline from 57 to 54 files.

This completed private implementation ownership only. It did not split the public façade, move
public classes or functions, or authorize a provider-neutral versus ChatGPT-specific public package
reorganization.

### Bounded operator-evidence collection

Status: `planned`

This is the next product implementation lot. It must:

- collect exactly the eleven required observations;
- enforce source compatibility and freshness;
- sanitize and hash outside public models;
- define temporary raw-evidence access, retention and destruction;
- compile and evaluate one fifteen-minute bundle;
- produce only a local blocked/next-step report.

No tunnel, OAuth client, app configuration or provider call belongs in this lot.

### Secure MCP Tunnel

Status: `planned`

This lot may start only after fresh bounded operator evidence and a separate explicit approval. It
must:

- revalidate current official documentation;
- define installation, update, revocation and rollback;
- protect tunnel credentials outside source control and public models;
- produce a secret-free transport attestation;
- keep the loopback gateway non-public.

### OAuth/OIDC and app configuration

Status: `planned`

This remains separate from tunnel installation and requires fresh evidence plus explicit approval.
Separate lots must define:

- issuer and discovery trust;
- redirect URI and client registration;
- refresh-token capability;
- secret storage and rotation;
- app draft, tool scan, action review, publication and access-control evidence;
- immediate revocation and recovery.

### One supported outbound provider transport

Status: `planned`

Select one official machine contract only after its own evidence and approval gate. It must preserve
committed turns, idempotency, lifecycle events, tool-call governance, cancellation semantics, quota
evidence and secret redaction.

### Visible ChatGPT web-session automation

Status: `blocked_by_evidence`

No browser cookie replay, private endpoint, sidebar scraping or DOM completion heuristic is
permitted. The surface remains research unless OpenAI provides a documented, visible and
interruptible mechanism.

## Deferred compatibility decision

### Public provider package reorganization

Status: `planned`

A future provider-neutral versus ChatGPT-specific public package split requires a separate issue and
an explicit compatibility and versioning decision. It must preserve or deliberately version the
179-export façade, public object origins, schemas and digest domains. PR #42 does not grant implicit
permission for that reorganization, and this decision is not a prerequisite for bounded
operator-evidence collection.

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

<!-- systeme-local:b1-5-deterministic-sanitization -->
## B1.5 deterministic sanitization foundation

Status: `implemented foundation` once this lot is merged; bounded operator-evidence collection itself
remains `planned`.

This B1 sub-lot adds five closed deterministic sanitizers and a private sanitized-output commitment
without changing protocol v1 or collecting real evidence. B1.6 must still add explicit
retention/disposition behavior and verifiable logical-disposition receipts. B2 may begin only after
those custody foundations are merged, and remains responsible for Python orchestration of the eleven
observations, response verification, bundle compilation and local reporting.
