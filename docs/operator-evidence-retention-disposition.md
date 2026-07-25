# Operator-evidence retention and logical disposition

Status: normative private Rust retention/disposition contract through B1.6

## Purpose

This document defines the B1.6 private Rust contract for bounded sanitized-artifact retention,
retryable logical disposition and secret-free disposition receipts.

B1.6 remains synthetic-only, library-only and unreachable from protocol v1. It does not authorize
real evidence collection, Python orchestration, provider access or connectivity.

## Authority

Python remains authoritative for observation planning, source compatibility, freshness, retention
authorization, reviewed timestamps, public provider models, bundle compilation and readiness
interpretation.

Rust remains authoritative for controlled raw and sanitized byte custody, closed retention
validation, capability-relative namespace cleanup, explicit sanitized-buffer overwrite, lifecycle
transitions and private disposition commitments.

## Closed retention decision

The exact modes are:

```text
dispose_immediately
retain_until
```

The exact owner is:

```text
local_operator
```

A retention decision contains only:

```text
mode
owner
justification_sha256
decided_at_unix_seconds
dispose_by_unix_seconds
retention_window_seconds
retention_decision_sha256
```

`justification_sha256` is exactly 64 lowercase hexadecimal characters. No free-form justification
enters Rust.

For `dispose_immediately`, `dispose_by_unix_seconds == decided_at_unix_seconds` and the window is
zero. For `retain_until`:

```text
1 <= dispose_by_unix_seconds - decided_at_unix_seconds <= 900
```

Rust reads no clock, locale, environment variable or network source. B2 may later supply reviewed
timestamps; B1.6 only validates and commits exact caller-supplied integers.

## Raw-source minimization

Raw staged evidence is never retained after sealing.

Before a sanitized artifact can be retained or disposed, the custodian revalidates:

```text
same session
same controlled parent and root identity
same active lease
same opaque direct-child source
same exact source commitment
root contains only the source and .custody.lock
```

The retryable cleanup order is:

```text
prepared
  -> source_absent
  -> lease_absent
  -> root_absent
  -> artifact_overwritten
  -> session_disposed
  -> complete
```

The retention path stops after verified root absence, applies `sealed -> retained`, and returns a
non-serializable `RetainedSanitization`. Later disposition resumes at `root_absent`.

An aborted or expired session may use the same cleanup path without a sanitized artifact. An absent
source is accepted only when the prepared plan explicitly records that no committed source existed.

## Capability-relative cleanup

Source, lock and staging-root removal remain relative to already-open directory capabilities.

The implementation:

- rejects unexpected children;
- rechecks source, lock, parent and root identities;
- rejects links, reparse objects, non-regular sources and multiply-linked sources;
- closes the lease handle before removing `.custody.lock`;
- closes root handles before removing the exact empty `stg_` child;
- verifies source, lock and root absence after each destructive step;
- preserves monotonic in-memory progress for retry after a typed failure.

Errors contain only a closed stage classification. They contain no path, source name, operating-system
error string, raw byte, session identifier, endpoint, timestamp or secret.

## Sanitized-artifact behavior

Immediate disposition consumes the `SanitizationResult`, explicitly overwrites its initialized byte
range, makes the artifact inaccessible and applies:

```text
sealed -> disposed
```

Bounded retention owns the artifact only inside a redacted, non-serializable Rust wrapper and applies:

```text
sealed -> retained
```

Later explicit disposition overwrites the artifact and applies:

```text
retained -> disposed
```

Cleanup is always allowed after the retention deadline. A late disposition records
`deadline_met=false`; it does not preserve the artifact.

Aborted and expired paths derive their reason from the prior lifecycle state:

```text
sealed + dispose_immediately -> completed
retained                     -> retention_released
aborted                      -> aborted
expired                      -> expired
```

No arbitrary reason string is accepted.

## Retention-decision commitment

The exact private domain is:

```text
systeme-local:operator-evidence-retention-decision:v1\x00
```

The framed fields, in order, are:

```text
custody session identifier
source commitment SHA-256
sanitized-output commitment SHA-256
sanitizer profile identifier
sanitizer profile version
sanitized output class
retention mode
retention owner
justification SHA-256
decided-at UTC seconds
dispose-by UTC seconds
retention-window seconds
```

Every field is length-prefixed with an unsigned 64-bit big-endian length. Integers use canonical
base-10 ASCII.

## Logical-disposition commitment

The exact private domain is:

```text
systeme-local:operator-evidence-logical-disposition:v1\x00
```

The framed fields, in order, are:

```text
custody session identifier
prior lifecycle state
resulting lifecycle state
lifecycle revision
transition commitment SHA-256
source commitment SHA-256 or absent
sanitized-output commitment SHA-256 or absent
retention-decision commitment SHA-256 or absent
derived disposition reason
raw source absent
lease absent
staging root absent
sanitized artifact overwrite attempted
deadline met or not_applicable
```

Booleans use lowercase `true` or `false`. Optional fields use the exact closed markers `absent` and
`not_applicable`.

## Public receipt

`LogicalDispositionReceipt` exposes only:

```text
prior_state
resulting_state
revision
transition_sha256
source_commitment_sha256
sanitized_commitment_sha256
retention_decision_sha256
disposition_reason
raw_source_absent
lease_absent
staging_root_absent
sanitized_artifact_overwrite_attempted
deadline_met
logical_disposition_sha256
```

It contains no session identifier, path, source name, raw byte, arbitrary text, endpoint, account or
workspace label, credential, token or cookie.

## Claim boundary

The receipt proves verified logical namespace disposition inside the Rust-managed custody session.

It does not prove:

- physical overwrite of a storage device;
- erasure from filesystem journals, snapshots, swap or caches;
- backup deletion;
- forensic irrecoverability;
- source provenance or truth.

Best-effort memory overwrite and verified namespace absence are explicit controls, not a physical-erasure
claim.

## Protocol boundary

`protocol.rs`, `main.rs`, Cargo manifests, `Cargo.lock` and the checked-in B0 fixtures remain
byte-for-byte unchanged. Protocol v1 still exposes only `describe_contract` and continues to report
filesystem access, real-evidence ingestion and sanitizer execution as false.

B2 may begin only after B1.6 is merged and independently reviewed.
