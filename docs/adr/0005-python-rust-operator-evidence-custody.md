# ADR 0005: Split operator-evidence authority between Python and Rust

Status: accepted

Date: 2026-07-20

## Context

Système Local already has deterministic Python models for the eleven ChatGPT MCP readiness
checks, source compatibility, freshness, public provider schemas, digest domains, operator-evidence
bundles, compilation and readiness evaluation. The next product phase requires temporary custody of
raw local evidence before any public model can be constructed.

Raw local evidence introduces a distinct trust boundary. It can contain paths, endpoint values,
metadata, tool definitions, workspace facts or secret material that must never enter provider models,
logs, command-line arguments or long-lived reports.

The repository also has a Rust workspace with `unsafe_code = "forbid"` and strict Clippy policy.
Rust is suitable for a narrow byte- and file-system custody boundary, while Python remains the
existing policy and model authority.

## Decision

Use a one-shot, local, versioned NDJSON subprocess boundary.

Python owns:

- the ordered eleven-observation plan;
- source/check compatibility and freshness;
- every existing public provider model and digest domain;
- evidence records, summaries, bundles, compilation and evaluation;
- subprocess orchestration and final local `blocked/next-step` interpretation.

Rust owns:

- bounded raw-byte custody;
- canonical path and file-type checks;
- streaming limits and sanitizer dispatch;
- private source, sanitized, session and disposition commitments;
- temporary session transitions;
- logical deletion or explicit retention receipts;
- secret-free and path-free protocol responses.

The v1 process accepts exactly one synthetic request on stdin and emits exactly one response on
stdout. B0 exposes only `describe_contract`; it does not open a path, read evidence, execute a
sanitizer or create a custody session.

Public provider models and their existing digest domains remain Python-owned. Rust private
commitments use separate, explicitly versioned domains and cannot replace or reinterpret public
provider commitments.

## Why subprocess instead of PyO3 or FFI

A subprocess:

- preserves a process-level failure boundary;
- avoids Python ABI and dynamic-library packaging complexity on Windows;
- keeps raw bytes outside the Python heap in future custody lots;
- permits independent executable tests and explicit timeout handling;
- makes stdout, stderr, environment and exit-code behavior reviewable.

The additional serialization cost is acceptable because collection is bounded, local and
operator-driven rather than latency-sensitive request processing.

## Trust and failure model

- stdin is the only request channel;
- stdout is reserved for one protocol response;
- stderr is bounded and must be empty on success;
- unknown fields, wrong versions, malformed identifiers and invalid digests fail closed;
- no raw value is passed in CLI arguments;
- no network capability belongs to the custodian;
- Python independently validates the Rust response and commitment;
- any malformed output, timeout or non-zero exit blocks progression.

## Logical deletion

A future disposition receipt may prove that custodian-managed temporary files are no longer
reachable through the managed session. It must not claim physical erasure from SSDs, snapshots,
backups or operating-system caches.

The distinction is explicit:

- logical deletion can be verified;
- physical erasure is not guaranteed;
- operator-owned source files are never deleted implicitly.

## Consequences

Positive:

- one authority remains responsible for public policy and provider compatibility;
- raw evidence receives a narrow memory- and file-system-focused boundary;
- Python and Rust can share checked-in conformance fixtures;
- Windows invocation and non-disclosure can be tested directly.

Costs:

- protocol evolution requires coordinated Python, Rust, fixture and documentation changes;
- the binary must be built and located deterministically;
- process startup and serialization add bounded overhead;
- private commitments require their own versioning discipline.

## Follow-up lots

- B1.1 implements the Rust in-memory custody-session state machine and private transition
  commitments without file or protocol capability.
- B1.2 implements capability-rooted, no-follow, bounded reads of synthetic staged files while
  keeping that capability unreachable from protocol v1.
- Later B1 lots add controlled staging creation, sanitizer profiles, source/sanitized commitments
  and disposition receipts.
- B2 implements Python orchestration of the eleven observations, subprocess verification, bundle
  compilation and local reporting.
- B3 adds the operator command, end-to-end non-disclosure tests and governance.

Tunnel installation, OAuth/OIDC registration, ChatGPT app configuration, provider calls and browser
automation remain outside these lots until separately approved.

## B1.1 implementation boundary

B1.1 adds an in-memory Rust session model with exact states, typed actions, monotonic revisions,
fail-closed transition errors and path-free transition receipts. It introduces the private digest
domain `systeme-local:operator-evidence-session-transition:v1\x00`.

B1.1 does not change protocol version 1 or add a wire operation. It performs no filesystem access,
raw-byte ingestion, sanitizer execution, retention, disposition or deletion.

## B1.2 implementation boundary

B1.2 adds an internal Rust staging reader based on an open directory capability. It accepts only an
opaque direct-child source name, disables following the final link, requires a regular single-link
file, reads by fixed-size chunks under a strict limit and preserves bytes only in a non-serializable
`GuardedSource`.

The read is permitted only while the B1.1 session state is `collecting`. Pre-open, opened-handle and
post-read fingerprints must match.

Protocol version 1 and its fixtures remain unchanged. `filesystem_access=false` continues to mean
that no filesystem capability is reachable through the sole `describe_contract` operation. Python
provides no path and receives no raw bytes.

B1.2 uses only synthetic temporary files. It does not establish operator-source provenance,
sanitization, retention, disposition or deletion.

## B1.3 implementation record

B1.3 implements Rust-controlled synthetic staging creation and one exclusive session lease. The
root name is derived from the validated session identifier, creation is relative to an approved
parent capability, and platform access restrictions are verified after creation.

On Unix, root and lease modes are `0700` and `0600`. On Windows, the implementation uses the audited
safe `SetSecurityInfo` wrapper with `SE_FILE_OBJECT`, `READ_CONTROL | WRITE_DAC`, and
`Dacl | ProtectedDacl`; the generic upstream `set_multiple` path is intentionally not used.

This implementation does not authorize real evidence, source commitments, sanitization, retention,
disposition or a new wire operation.

<!-- systeme-local:b1-4-source-commitment -->
## B1.4 implementation record

B1.4 adds a private, versioned source commitment after the existing lease-bound stable read. The
framing binds the custody-session identifier, the exact byte length and the exact Rust-owned bytes
under the dedicated domain `systeme-local:operator-evidence-source-commitment:v1`.

The public receipt exposes only the bounded byte length and a lowercase SHA-256 commitment. Raw
bytes, paths, source names and the session identifier remain private. The same lot defines a closed
five-profile sanitizer registry for UI exports, metadata documents, tool scans, action reviews and
local-policy snapshots. The registry describes deterministic limits and output classes only; it
does not execute a sanitizer or make a provider-readiness decision.

The commitment and profile contracts remain library-only. Protocol v1, its fixtures and the binary
entry point are unchanged.
