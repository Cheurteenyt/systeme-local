# Documentation governance

Status: normative ownership contract

## Purpose

Système Local separates overview, target architecture, implemented architecture, normative
contracts, provider facts and delivery planning. A document must not silently take over the role
of another document.

## Authority matrix

| Path | Authority |
|---|---|
| `README.md` | concise overview, safe operator entry points and links |
| [`docs/index.md`](index.md) | descriptive documentation navigation and authority map; no normative ownership |
| `docs/blueprint-v2.md` | target product architecture |
| `docs/architecture.md` | architecture implemented on `main` |
| `docs/connectivity-model.md` | sole normative cross-provider connectivity contract |
| `docs/provider-context-registry.md` | provider-neutral account/project/conversation context |
| `docs/provider-attachments.md` | provider-neutral attachment metadata and batching |
| `docs/providers/chatgpt.md` | ChatGPT surface characterization and implementation status |
| `docs/providers/chatgpt-mcp-*.md` | expiring ChatGPT MCP evidence and operator contracts |
| `docs/providers/chatgpt-web-c*.md` | stacked ChatGPT Web capability gates, evidence lifecycles, runtime admissions and test ledgers |
| `docs/providers/chatgpt-web-c9-attachment-handoff.md` | C9 exact package, real local-AI, one Work rich Plugin/MCP proof and one normal-Chat manual-handoff proof |
| `docs/providers/chatgpt-web-c9-test-evidence.md` | executed C9 offline/live evidence ledger and explicit no-live boundary |
| `docs/operator-evidence-custodian-protocol.md` | private Python/Rust custody subprocess contract |
| `docs/operator-evidence-orchestration.md` | protocol-v2, inherited-handle, recovery and eleven-check orchestration contract |
| `docs/operator-evidence-protocol-v2-design.json` | machine-readable B2.0 protocol and compatibility manifest |
| `docs/operator-evidence-session-lifecycle.md` | private Rust custody-session state and transition contract |
| `docs/operator-evidence-staging.md` | private Rust capability-rooted synthetic staging contract |
| `docs/operator-evidence-retention-disposition.md` | private Rust retention and logical-disposition contract |
| `docs/threat-model.md` | current threats, controls and residual risks |
| `docs/roadmap.md` | ordered delivery status and gates |
| `docs/adr/*.md` | accepted decisions and consequences |
| [`docs/github-governance.md`](github-governance.md) | bounded snapshot of repository settings and unknowns |

Provider-specific facts never become cross-provider defaults. Target architecture never implies
implementation. A roadmap entry never authorizes a capability.

A C4 admission receipt records one enforcement result. It is not official
capability evidence, cannot promote an evidence candidate, and cannot register
a provider.

A C5 integration seal records exact repository content and preserves reviewed
commit ancestry across a squash merge. It is not a release signature, provider
evidence, runtime admission, or permission to perform a live action.

A C6 acquisition receipt records bounded official-source fingerprints and
drift state. A C6 candidate is review input only. Neither is reviewed provider
evidence, promotion authority, runtime admission, or permission to perform a
live action. Raw fetched document bodies must not be committed, persisted as
local C6 state, attached to CI, or printed in logs.

## Status vocabulary

Documents that describe implementation use only:

- `implemented`;
- `partial`;
- `planned`;
- `research`;
- `blocked_by_evidence`;
- `out_of_scope`.

Provider evidence documents additionally record review and revalidation timestamps. Expired
evidence cannot be described as current even when historical tests remain green.

## Change rules

A change must update every affected authority:

- architecture changes update implemented architecture and, when structural, an ADR;
- new provider facts update the provider document and evidence manifest;
- new capability or trust boundary updates the threat model;
- public schema or digest changes require an explicit compatibility decision;
- roadmap status changes only after merge evidence exists;
- README and `docs/index.md` remain concise and link to normative details instead of duplicating them.

## Automated checks

CI verifies:

- the Ruff formatting ratchet: no new debt and every touched Python file formatted;
- the Mypy ratchet: governance scripts type-clean, no new provider-model diagnostics and touched
  debt-bearing files repaired;
- the exported lock dependency audit: frozen `uv.lock`, hashes required and local project omitted;
- the Python test security floor: `pytest>=9.0.3,<10`, with `pytest 9.0.3` locked to
  remediate `PYSEC-2026-1845` without an audit ignore;
- relative Markdown links;
- source-of-truth markers;
- implemented/planned status consistency;
- provider phase references;
- evidence review and revalidation dates;
- exact C6 policy/C3 digest binding and review-only acquisition behavior;
- CODEOWNERS and PR-template governance markers.

The scheduled evidence-governance workflow intentionally uses current time. Unit and pull-request
tests use an explicit `--as-of` timestamp so they remain deterministic. Its
C6 network step uses only public official documentation, has `contents: read`,
and cannot promote or persist a candidate.

C7 adds a separately reviewed Work profile and pre-live policy. Documentation
must never collapse `supported on Work` into `supported on Chat`, or
`officially eligible` into `operator-authorized live action`. Every C7 status
report must retain the native Chat blocker, the automatic-switch denial, six
default action denials and zero effective tools. A C8 receipt is a
separate evidence class and cannot be manufactured from C7 profile data.

C8 documentation must keep five facts separate: current official Work
eligibility, fresh visible entitlement/quota, local admission, two real Work
correlations and completed revocation. A positive statement about one class
cannot substitute for another. The exact final status may be recorded only
from the validated final attestation. Visible model or reasoning labels are
presentation evidence, never internal model attribution. Historical receipts
may remain verifiable after expiry, but expiry can never be extended to
authorize another action.

The completed C8 report records only the final attestation and receipt
commitments, bounded counts, visible labels, negative outcomes and revocation
facts. It excludes Runtime keys, Tunnel and Plugin identifiers, raw
challenges, structured responses, audit-log bodies, database contents and
conversation identifiers. The annotated C8 evidence tag binds a
self-excluding repository seal to the exact final-attestation SHA-256; it does
not restore live connectivity or authorize another cycle.

C9 documentation must keep these facts separate:

1. the immutable, completed and revoked C8 transport evidence;
2. offline attachment-security, Work rich-renderer and private-export
   implementation;
3. local-AI adapter tests using controlled loopback responses;
4. a fresh HMAC-bound native-runtime observation whose PID/process identity
   and privacy settings are explicitly operator-attested, not automatically
   verified;
5. a future inference receipt from that operator-reviewed local multimodal
   runtime;
6. a future Work MCP rich-content proof;
7. a future normal-Chat proof through one visible operator-performed manual
   file handoff;
8. the official product rule that Plugins are unavailable in normal Chat;
9. final cleanup, revocation, attestation and repository sealing.

The C8 evidence tag is a dependency, not a reusable C9 grant. A controlled
HTTP response proves only the adapter contract and cannot be the sole
installed-runtime evidence. The signed runtime observation authenticates its
contents and bindings; it does not independently prove the operator-declared
PID, product metadata or privacy settings. Documentation must also distinguish
`adapter_persistent_storage_used=false` from the separate operator
confirmations about runtime request logging and persistence. A Work result
cannot be described as a Chat result. The current Plugins guide explicitly
states that Plugins are unavailable in Chat; a general “new conversation”
instruction must not be interpreted as a normal-Chat Plugin exception.

C9 status reports must state the Work and Chat counters independently, record
whether a real local model was used, and preserve the exact zero-tool-before /
one-tool-after Work grant boundary. They must record the Work tool argument
and the separate Chat manual-export claim. The qualifying operator runbook
must be deterministic: Work rich MCP first, then normal-Chat manual handoff.
They must not infer success from filenames, attachment UI, task creation or a
metadata-only MCP status. Positive consumption requires both independent
nonce proofs bound to the exact sanitized manifest.

C9 v1 live evidence is limited to generated synthetic PNG + UTF-8 TXT.
It cannot be generalized to screenshots, personal documents, arbitrary file
handoff or regular use. Work must use the read-only Plugin/MCP rich-content
path. Normal Chat must use one owner-only, short-lived, at-most-once manual
file-picker handoff. The Chat receipt may prove visible transfer and nonce
consumption only; it must deny MCP, app, local-endpoint, internal-app-ID and
autonomous-delivery claims.

The C9 script inventory and numerical test snapshot must come from the exact
closeout commit. Documentation must not preserve an obsolete fixed script
count or add overlapping intermediate test runs. While integration is active,
the ledger must say that the consolidated snapshot is pending refresh.

Windows Chat-export documentation must state both the required owner-only
DACL application/query chain and its limit: private-state operations and the
picker remain path-based where handle-relative operations are unavailable.
Component, identity, hash and ACL checks narrow, but cannot eliminate, a
privileged local TOCTOU race. The receipt must preserve this residual risk.

Raw source/sanitized bytes, nonce values, local-AI request/response bodies,
picker paths, Runtime keys, Tunnel/Plugin identifiers, browser state,
conversation identifiers and audit bodies are forbidden from versioned C9
evidence. The C9 ledger may retain only typed metadata, hashes, bounded
counts, visible-label observations, explicit negative outcomes and revocation
facts.

The C9 final status must remain `partial` while the counters are `0/1` Work
and `0/1` normal Chat, and until one bound real runtime/inference proof, one
Work rich proof, one normal-Chat manual-handoff proof, export cleanup,
Plugin/Tunnel removal, operator Runtime-key revocation, post-revocation Work
and local-control unreachability, final attestation and repository seal all
validate. If the manual Chat handoff is not explicitly authorized or the
file picker is unavailable, the result is `PARTIAL/BLOCKED`. Offline green
tests never authorize the browser, create a credential or change a live
counter.
