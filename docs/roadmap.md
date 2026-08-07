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

<!-- systeme-local:b1-6-logical-disposition -->
## B1.6 bounded retention and logical disposition foundation

Status: `implemented foundation` once this lot is merged; real operator-evidence collection remains
`planned`.

This B1 sub-lot adds closed retention decisions, a maximum 900-second sanitized-artifact retention
window, retryable capability-relative cleanup and secret-free logical-disposition receipts. Raw
staged sources cannot remain retained after sealing.

B2 may begin only after B1.6 is merged and independently reviewed. B2 remains responsible for
timestamp acquisition, Python subprocess orchestration, the eleven observations, response
verification, bundle compilation and local reporting.


<!-- systeme-local:b2-0-orchestration-contract -->
## B2.0 operator-evidence protocol and orchestration contract

Status: `implemented` contract design once this lot is merged; runtime collection remains `planned`.

B2.0 selects inherited read-only handles, one-shot `process_evidence`, fail-closed
`recover_evidence`, immediate disposition and the exact eleven-check compatibility matrix. It adds no
wire-reachable operation and no real evidence.

B2.1 may implement synthetic protocol-v2 transaction mechanics only after independent review.
Profile gaps, Python orchestration, bundle construction and the operator command remain separate
gates.

## C0 bounded ChatGPT Web MCP connectivity

Status: `partial` until the manual Web call, correlated audit, and revocation
test are independently observed.

C0 is the ADR 0007 sequencing exception that tests the inbound MCP path without
collecting B2 evidence. It adds a disabled-by-default `1/0/0` tool policy,
synthetic probe, official Secure MCP Tunnel scripts, and a separate expiring
live-attestation model. It does not make protocol v2 reachable, publish a
Plugin, enable writes, add provider-outbound transport, or automate ChatGPT
Web. The next gate is the exact manual procedure in
[`providers/chatgpt-mcp-c0-connectivity.md`](providers/chatgpt-mcp-c0-connectivity.md).
Formatting only the Python files touched by C0 reduces the current Ruff debt
from 54 to 42 files.

## C1 bounded Chat-surface observability

Status: `blocked` by the current official product surface contract. Plugins
are available on ChatGPT Web only in Work and are unavailable in Chat, while
C1 explicitly forbids Work. The live gate can resume only after official
revalidation shows Plugin availability in Chat or a separate goal explicitly
authorizes a compatible surface.

C1 is stacked on the unmerged C0 branch and tracked by issue
[#66](https://github.com/Cheurteenyt/systeme-local/issues/66). It adds strict
runtime/default/Web-label attribution, a Chat-versus-Work fail-closed guard,
two-chat correlation receipts, negative-test and revocation receipts, a
short-lived final attestation, and a raw-evidence cleanup. It never tests Work,
enumerates existing chats, stores conversation IDs, infers hidden routing,
enables writes, or changes the exact C0 probe snapshot.

The live gate and rollback are specified in
[`providers/chatgpt-mcp-c1-observability.md`](providers/chatgpt-mcp-c1-observability.md).

ChatGPT remains the first Web-provider priority. Later AI Web integrations
must use separate provider profiles, official capability evidence,
surface/privacy boundaries, revocation semantics, live tests, and seals.
Shared local primitives do not make ChatGPT evidence portable to another
provider.

## C2 ChatGPT-first official capability gating

Status: `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`.

C2 is stacked on exact C1 commit
`2aee36fdfa3d20c23acdc75eb3348bc54536ef4f`. Current official OpenAI
documentation routes custom/local MCP use through Plugins and explicitly makes
Plugins unavailable in Chat. C2 therefore implements a typed, expiring
official-capability profile and atomically blocks Runtime-key creation, Tunnel
startup, temporary Plugin creation, and browser testing.

No C1 live test is repeated. The next permissible activity is official
documentation revalidation. A future `supported` result would still require
the existing privacy, authorization, credential, revocation, and test gates.

C2 adds only minimal provider, native-surface, surface-class, capability,
evidence, and decision contracts. ChatGPT remains the only implemented Web
provider. Other AI Web providers remain planned and require independent
sources, semantics, threat models, tests, and seals.

## C3 provider capability evidence lifecycle

Status: `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`; lifecycle `current`.

C3 is stacked on exact C2 commit
`cf05e963ba30539f9b2c9ec2f5f71326cbba8399` and tracked by issue
[#69](https://github.com/Cheurteenyt/systeme-local/issues/69). It separates
official-document acquisition from deterministic decisions, adds a strict
ChatGPT-only provider registry and adapter, binds canonical claims, evidence,
profiles, and the registry by SHA-256, and distinguishes `current`,
`revalidation_due`, `expired`, `source_drift`, and `invalid`.

Candidate evidence is never authoritative and cannot change an action.
Runtime-key creation, Tunnel startup, Plugin creation, browser testing, and
any ChatGPT action are atomically denied under the current `unsupported`
profile. The four C1 live entry points now call C3 before C1 logic.

The next permissible activity is documentation-only revalidation no later than
`2026-08-10T11:55:00Z`. A future provider remains out of scope until it has an
independent adapter, official sources, native-surface semantics, threat model,
tests, and seal. See
[`providers/chatgpt-web-c3-evidence-lifecycle.md`](providers/chatgpt-web-c3-evidence-lifecycle.md).

## C4 provider-neutral runtime admission

Status: `implemented` on the C4 branch; current ChatGPT admission remains
denied.

C4 is stacked on exact C3 commit
`9140801e88ed44afca9481ac06288783a0d52da2` and tracked by issue
[#71](https://github.com/Cheurteenyt/systeme-local/issues/71). It converts the
reviewed C3 result into a typed runtime request, immutable decision, effective
tool set, and canonical receipt before a protected effect.

The production registry still contains only ChatGPT. Current native Chat
derives zero effective tools and denies Runtime-key creation, Tunnel startup,
Plugin creation, browser tests, ChatGPT actions, and provider tool exposure.
Synthetic supported providers exist only in tests and make no portability
claim.

The next product gate remains official native Chat support followed by an
independently promoted C3 profile. C4 must then admit only the exact reviewed
read-only tool before a separately authorized live cycle can begin. See
[`providers/chatgpt-web-c4-runtime-admission.md`](providers/chatgpt-web-c4-runtime-admission.md).

## C5 squash-safe C0-C4 main integration

Status: `implemented` and accepted on `main` by PR #74 at
`418112758d8675326835d9947ccce3a1b12f6f25`.

C5 is tracked by issue
[#73](https://github.com/Cheurteenyt/systeme-local/issues/73). A direct
simulation proved that the five green stacked pull requests cannot be
independently squash-merged without invalidating the historical C4
seal/HEAD assumption.

C5 therefore creates one aggregate pull request to `main`, keeps the exact
C0-C4 ancestry reachable through
`evidence/c0-c4-main-integration-v2`, and binds the integrated tree with a
framed SHA-256 commitment over paths, modes, lengths, and blob bytes. It
changes no capability: current ChatGPT remains denied for all six C4 actions
with zero tools and zero live actions.

After aggregate merge and green `main` CI, PRs #65, #67, #68, #70, and #72
were superseded rather than independently merged. The C5 verifier now proves
the immutable historical/tagged tree against the exact accepted `main` commit
and requires later repository heads to descend from it; ordinary future
changes do not rewrite historical evidence. See
[`providers/chatgpt-web-c5-main-integration.md`](providers/chatgpt-web-c5-main-integration.md).

## C6 official capability revalidation

Status: `implemented` and accepted on `main`; the public-source validation,
annotated evidence seal, remote CI and governance closeout are complete.

C6 starts from exact accepted C5 `main`
`418112758d8675326835d9947ccce3a1b12f6f25`. It adds a provider-neutral,
strictly typed revalidation protocol with ChatGPT as the only production
profile. The policy binds exact C3 registry/profile digests and four official
OpenAI documentation sections.

The acquisition client uses only the public read-only OpenAI Docs MCP,
persists no raw document body, detects exact fingerprint or marker drift, and
can create only a review candidate. It cannot promote C3 evidence or change C4
admission. Network, protocol, policy, drift, due, and expiry failures all keep
six actions denied and zero tools exposed.

The first real public-document acquisition returned four unchanged sections.
This does not unblock ChatGPT: Plugins remain unavailable in Chat, so the
result is still `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`.

The next product gate is not another C1 live cycle. It is either:

1. a future official source change that is independently reviewed and
   deliberately promoted through a successor evidence/seal change; or
2. an independent official provider profile with its own semantics, sources,
   threat model, tests, and seal.

See
[`providers/chatgpt-web-c6-official-revalidation.md`](providers/chatgpt-web-c6-official-revalidation.md).

## C7 ChatGPT Work pre-live admission

Status: `COMPLETE_C7_WORK_PROFILE_READY_FOR_BOUNDED_LIVE_VALIDATION`;
accepted on `main` with its annotated evidence seal and green remote CI.

C7 starts from accepted C6 `main`
`81bed9b81f266709fab0ea4178f98f0607c3da44` and is tracked by issue
[#76](https://github.com/Cheurteenyt/systeme-local/issues/76). It adds the
first independent ChatGPT Work capability profile for the exact
`chatgpt:work:agentic_work:custom_or_local_mcp_tool_invocation` tuple.

Current official documentation supports the Plugin-mediated MCP route on Work
and excludes Plugins from native Chat. C7 therefore preserves the native Chat
blocker unchanged, forbids automatic Chat-to-Work switching and binds the
historical C3/C4/C6 artifacts instead of rewriting their evidence.

Official Work support is an eligibility fact, not live authorization. The
default policy denies Runtime-key creation, Tunnel startup, Plugin creation,
browser testing, ChatGPT Work actions and tool exposure. It exposes zero tools.
A C8 cycle requires a fresh HMAC-authenticated operator grant bound to
the exact profile/policy, Work-only surface, maximum twenty-minute lifetime
and at most two new synthetic Work chats. It must include an explicit Work
request plus fresh visible-surface, entitlement and usable-quota observations.

C7 performed no browser, credential, Tunnel, Plugin, chat or provider action.
Its green seal enabled the separately authorized C8 Work-only live
validation. See
[`providers/chatgpt-web-c7-work-prelive-admission.md`](providers/chatgpt-web-c7-work-prelive-admission.md).

## C8 bounded ChatGPT Work live validation

Status: `COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED`; the bounded
provider cycle, negative tests, revocation and cleanup are complete.

C8 starts from accepted C7 `main`
`e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f` and is tracked by issue
[#78](https://github.com/Cheurteenyt/systeme-local/issues/78). It does not
reopen native Chat. It implements the fresh C7 grant contract for one explicit
Work-only cycle, at most twenty minutes and exactly two new synthetic tasks.

The runtime required a durable HMAC-bound operator scope plus fresh visible
Work, entitlement and quota evidence. It exposes only the reviewed read-only
probe, correlates each result to local audit, then requires bounded negatives,
Plugin removal, Runtime-key revocation, closed listeners and post-revocation
unreachability.

The executed cycle created exactly two synthetic Work tasks and correlated
exactly one probe call from each. Replays and malformed inputs were rejected,
the capability surface did not expand, the Plugin connection and Runtime key
were removed, both listeners closed, and a post-revocation call was
unreachable. The result means only
`COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED`; it does not mean
regular-use readiness, native Chat support or exact model attribution.

After C8, the next product lot should convert the proven one-tool pathway into
a deliberately scoped, user-facing read-only capability design with explicit
operational lifecycle, quota and revocation policy. Support for a different
Web AI remains a later provider-specific profile and adapter lot, not an
inference from ChatGPT evidence. See
[`providers/chatgpt-web-c8-work-live-validation.md`](providers/chatgpt-web-c8-work-live-validation.md).
