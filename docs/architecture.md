# Architecture actuellement implémentée

Status: implemented architecture through B1.6 operator-evidence logical disposition

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
| operator-evidence session lifecycle | implemented | in-memory Rust state machine |
| operator-evidence bounded staging | implemented | capability-rooted synthetic reads; no wire operation |
| operator-evidence logical disposition | implemented | bounded sanitized retention and logical namespace cleanup |
| real operator-evidence collection | planned | must follow controlled staging, sanitizer and disposition gates |
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

## Operator-evidence custody foundation

Status: partial

The repository contains a private Python/Rust foundation for bounded operator evidence. Python
remains the policy, public-model and existing-digest authority. Rust owns future raw-byte custody
and now implements an in-memory session lifecycle.

The B0 wire surface still accepts only `describe_contract`. It performs no filesystem evidence
ingestion, sanitizer execution, network access, tunnel installation, OAuth/OIDC registration, app
configuration or provider call.

B1.1 adds the exact `created -> collecting -> sealed -> disposed` lifecycle plus the authorized
`aborted`, `expired` and `retained` paths. Illegal transitions and revision overflow fail without
mutation. Transition receipts are deterministic, path-free and secret-free.

B1.2 adds an internal capability-rooted reader for synthetic staged files. It accepts only opaque
direct-child names, disables following the final link, rejects non-regular and multiply-linked
objects, compares metadata around a bounded streaming read and keeps bytes inside a redacted,
non-serializable Rust object. The reader is callable only for a `collecting` session.

The B0 binary still exposes only `describe_contract`; Python cannot provide a path or invoke B1.2.

The accepted ownership decision is recorded in ADR 0005. The normative wire contract is
[`operator-evidence-custodian-protocol.md`](operator-evidence-custodian-protocol.md), the lifecycle
authority is [`operator-evidence-session-lifecycle.md`](operator-evidence-session-lifecycle.md),
and the staging authority is
[`operator-evidence-staging.md`](operator-evidence-staging.md).

## B1.3 controlled synthetic staging

| Capability | Status |
|---|---|
| operator-evidence controlled staging | implemented |
| Rust-created `stg_` root | implemented |
| verified Unix modes | implemented |
| verified protected Windows DACL | implemented |
| exclusive session lease | implemented |
| source commitment | planned |
| sanitizer profile | planned |
| real evidence ingestion | not implemented |

The controlled API is private to the Rust library and remains unreachable from the B0 NDJSON
binary. Python still receives no path, lock identifier or raw byte content.

<!-- systeme-local:b1-4-source-commitment -->
## Private source commitment and sanitizer-profile boundary

The Rust custodian can now turn one stable lease-bound `GuardedSource` into a private commitment
receipt. The only public commitment entry point reuses the controlled staging checks, so an ambient
path, mismatched session, inactive lease or changed root cannot bypass custody.

The sanitizer-profile registry is closed and versioned. It records evidence class, deterministic
output class, input/output ceilings and explicit network/environment prohibitions. It provides no
transformation engine, no public evidence assertion and no protocol operation. Python remains
authoritative for mapping later sanitized evidence to the eleven readiness checks.

<!-- systeme-local:b1-5-deterministic-sanitization -->
## B1.5 private deterministic sanitization

The Rust custodian now implements the five closed B1.4 sanitizer profiles as deterministic private
library operations. A call must pass through the matching controlled root and active lease while the
custody session remains `collecting`; the exact source commitment is reverified before parsing.

Canonical sanitized bytes remain in Rust-owned guarded memory and receive best-effort overwrite on
drop. Only bounded metadata and private source/output commitments are exposed. No source path, source
name, session identifier, endpoint, provider document, tool definition, action text or secret-bearing
value is returned.

The B0 binary and NDJSON contract remain unchanged and still advertise
`sanitizer_execution=false`, because this internal capability is not wire-reachable. Real
operator-evidence collection, retention, disposition, Python orchestration, tunnel installation and
provider connectivity remain unimplemented.

<!-- systeme-local:b1-6-logical-disposition -->
## B1.6 private retention and logical disposition

The private Rust custodian now supports closed immediate disposition and bounded in-memory retention
of canonical sanitized artifacts. Raw staged sources, the lease control file and the exact controlled
staging root are removed and verified absent before an artifact can remain retained.

A retryable in-memory operation records monotonic cleanup progress. Immediate, retained, aborted and
expired paths end in the existing terminal `disposed` state and produce only a secret-free logical
disposition receipt. Retained artifacts are bounded to a caller-supplied window of at most 900
seconds; Rust reads no clock and late cleanup remains mandatory with `deadline_met=false`.

This is logical namespace disposition, not physical erasure. Protocol v1, the binary entrypoint,
Cargo dependencies, public provider models and real-evidence collection remain unchanged.


<!-- systeme-local:b2-0-orchestration-contract -->
## B2.0 contract-only orchestration design

The repository now has an accepted design for a future protocol-v2 operator-evidence transaction.
The design selects inherited read-only source and staging-parent handles, a one-shot process,
immediate disposition and a separate recovery operation.

No version-2 operation is implemented or wire-reachable. Real operator-evidence collection remains
`planned`; the current binary still exposes only protocol-v1 `describe_contract`.

## Optional C0 inbound connectivity boundary

ADR 0007 adds a disabled-by-default operator path:

```text
manual ChatGPT Web draft Plugin
    -> OpenAI Secure MCP Tunnel control plane
    -> official customer-run tunnel client (outbound-only)
    -> http://127.0.0.1:8765/mcp
    -> authenticated TaskProcessor
    -> one synthetic read-only probe
    -> HMAC-chained local audit
```

The separate C0 policy prevents inheritance of file, command, task, provider, or
B2 tools. The runtime aborts unless the registry contains exactly the single C0
tool. The facade and tunnel health surface bind to explicit loopback addresses;
public endpoint construction is outside the implementation. The full contract
and rollback are in
[`providers/chatgpt-mcp-c0-connectivity.md`](providers/chatgpt-mcp-c0-connectivity.md).

## Optional C1 Chat-surface observation boundary

ADR 0008 layers typed observation and correlation over the unchanged C0 probe.
It does not add a provider-conversation transport or a browser-history reader.
Two locally labeled, newly created Chat pages each receive one distinct
positive challenge. A pre-prompt visible-surface observation must be `chat`;
`work`, `codex`, and `unknown` fail closed before prompting.

Codex turn metadata, Codex configured defaults, and ChatGPT-visible labels are
stored in separate fields and evidence domains. Two response/audit pairs,
bounded negative results, explicit Plugin/key revocation, and a failed
post-revocation call are required for the short-lived final attestation. The
full contract is in
[`providers/chatgpt-mcp-c1-observability.md`](providers/chatgpt-mcp-c1-observability.md).

## C2 official Chat-surface capability gate

ADR 0009 inserts a documentation-derived gate before every C1 live action:

```text
official OpenAI sources
    -> canonical source summaries + SHA-256
    -> strict ChatGPT / Chat / custom-or-local-MCP profile
    -> freshness and schema validation
    -> supported | unsupported | unobservable
    -> one atomic decision for Runtime key, Tunnel, Plugin, and browser
```

The current `unsupported` result denies all four actions before credentials or
processes exist. Stale, ambiguous, malformed, or mismatched evidence also
denies all four. The gate has no network, browser, credential, or process
dependency and cannot convert C1 transport readiness into surface support.

Provider ID, native surface, surface class, official capability, evidence, and
policy decision are separated so a future AI Web provider can supply an
independent profile. Only ChatGPT is registered; no evidence or capability is
portable. See
[`providers/chatgpt-web-c2-capability-gating.md`](providers/chatgpt-web-c2-capability-gating.md).
