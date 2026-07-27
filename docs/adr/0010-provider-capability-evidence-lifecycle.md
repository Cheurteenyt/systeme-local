# ADR 0010: Separate official evidence acquisition from capability decisions

Status: accepted

Date: 2026-07-27

Stacked base: C2 commit
`cf05e963ba30539f9b2c9ec2f5f71326cbba8399` and draft
[PR #68](https://github.com/Cheurteenyt/systeme-local/pull/68).

Tracking issue:
[#69](https://github.com/Cheurteenyt/systeme-local/issues/69).

## Context

ADR 0009 introduced a correct fail-closed ChatGPT Chat capability profile, but
one module owned provider allowlisting, the individual profile, freshness, and
live-action decisions. That is sufficient for one reviewed C2 snapshot but
does not express revalidation due separately from expiry, compare a proposed
review without changing active evidence, or isolate future provider adapters.

Fetching current product documentation is inherently non-deterministic.
Runtime authorization and CI must remain deterministic and cannot silently
promote a changed page, account rollout, or candidate profile.

## Decision

C3 separates official-document acquisition from repository decisions.

Acquisition uses the official documentation interface and produces bounded,
repository-authored canonical claims. The active decision path performs no
network or browser access. It validates:

- one versioned provider adapter;
- one exact capability identity;
- one reviewed active profile;
- canonical claim, conclusion, evidence-set, profile, and registry SHA-256
  commitments;
- current, revalidation-due, expired, source-drift, and invalid lifecycle
  states;
- supported, unsupported, and unobservable support states;
- one atomic decision for every protected action.

Candidate profiles are non-authoritative. They always deny every protected
action. Evidence changes are `source_drift` until an independent review,
deliberate profile and registry update, complete validation, and merge.

The registry contains only ChatGPT. Provider-neutral shapes are extension
points, not compatibility claims. A future provider requires new reviewed
code and evidence.

C3 supersedes C2 as the gate imported by C1 live entry points. C2 code,
profile, tests, documentation, and seal remain historical and unchanged except
for documentation that names the new owner.

## Consequences

Current ChatGPT Chat custom/local MCP support remains `unsupported`, so
Runtime-key, Tunnel, Plugin, browser, and ChatGPT actions are denied.

Revalidation due is visible before expiry without enabling an action. Expired,
invalid, or drifted evidence fails CI. Scheduled governance stays read-only and
cannot edit a profile, open an issue, or promote support.

No raw official page, browser state, credential, chat, Tunnel, Plugin, or live
call is introduced. The cost is an intentional manual review and promotion
step whenever official evidence changes.
