<!-- systeme-local:adr-0006-inherited-evidence-handles:v1 -->
# ADR 0006: Use inherited read-only handles for bounded operator evidence

Status: accepted contract decision; runtime implementation deferred

Date: 2026-07-25

## Context

B1.1 through B1.6 implement private Rust custody, controlled staging, sanitization and logical
disposition, but none is reachable through protocol v1. B2 must eventually process operator-selected
evidence without giving Rust or a remote agent ambient path authority and without copying raw bytes
into Python.

A process crash can occur after controlled staging exists but before terminal disposition. The
process model therefore needs a recoverable namespace contract without becoming a long-lived
privileged daemon.

## Decision

Keep the one-shot subprocess boundary from ADR 0005.

Python opens exactly two local OS capabilities and passes them in the child process's explicit
inherited-handle allowlist:

- one read-only regular-file source handle;
- one owner-only staging-parent directory handle.

The version-2 NDJSON request carries only decimal handle identifiers, transaction and scope
commitments, a closed evidence class and profile, and reviewed timestamps. It carries no path and no
raw byte.

Rust derives the session, root, source and recovery-journal names from the transaction identifier.
`process_evidence` ends only after immediate logical disposition. `recover_evidence` cleans an
interrupted transaction and can never produce verified evidence.

Only `dispose_immediately` becomes wire-reachable. The B1 `retain_until` capability remains
library-only.

## Rejected alternatives

### Arbitrary or allowlisted paths in NDJSON

A path is still ambient host authority, creates logging and error-leakage risk, and differs across
Windows and Unix. Rejected.

### Python byte relay

Reading raw evidence into Python defeats the custody split and broadens the heap, exception and log
surfaces. Rejected.

### Ambient temporary directories

Current-directory, environment and platform temporary-directory conventions are not capabilities and
are vulnerable to substitution and permission drift. Rejected.

### Long-lived custodian daemon

A daemon would add lifecycle, privilege, authentication and recovery surfaces before they are needed.
Rejected.

### Provider upload or network fetch

B2 is local evidence processing only. Network and provider connectivity remain separate lots.
Rejected.

## Consequences

Positive:

- no raw path crosses the protocol;
- Python does not read evidence bytes;
- Rust receives only explicit capabilities;
- the B1 controlled-root model remains usable;
- Windows and Unix handle inheritance are testable independently;
- an interrupted process has an explicit cleanup operation.

Costs:

- Python and Rust need platform-specific inherited-handle adapters;
- B2.1 must add a bounded sibling recovery journal;
- a recovered transaction cannot become verified evidence;
- every gap profile requires a separate review.

## Compatibility

Protocol v1 and all checked-in v1 fixtures remain byte-for-byte unchanged. Public provider models and
digest domains remain Python-owned and unchanged.


<!-- systeme-local:b2-0-contract-repair-v2 -->
## Independent-review closure

Contract revision 2 fixes the inherited-handle decision at implementation
precision. The machine-readable manifest is authoritative for numeric handle
bounds, exact Windows and Unix rights and flags, duplication, close behavior,
identity revalidation, journal replacement and timeouts.

It also defines how Python reconstructs each B1 canonical sanitized output and
recomputes the existing sanitized-output commitment. This adds no runtime
capability and changes no protocol-v1 fixture.
