# Operator-evidence synthetic staging

Status: normative private Rust staging contract through B1.3

## Purpose

This document defines the first internal filesystem capability for the Rust operator-evidence
custodian.

B1.2 reads only synthetic temporary files created by tests or controlled local development
procedures. It does not authorize operator-evidence collection.

The B0 NDJSON protocol remains unchanged and still exposes only `describe_contract`.

## Authority and reachability

Rust owns the internal staging capability and raw bytes read through it.

Python receives no path, source name or byte content.

The protocol-v1 descriptor remains:

```text
filesystem_access = false
real_evidence_ingestion = false
sanitizer_execution = false
```

These values describe capabilities reachable through protocol v1. The internal Rust library now
contains a filesystem reader, but neither `protocol.rs` nor `main.rs` calls it.

## Dependency decision

B1.2 uses exactly:

```text
cap-std = 4.0.2
cap-fs-ext = 4.0.2
windows-permissions = 0.2.4 (Windows target only)
```

The staging root is represented by an open directory capability. Source lookup is relative to that
handle rather than to the ambient filesystem namespace.

The final source component is opened with symlink following disabled.

## Staging root

`StagingRoot::open` accepts a Rust-local `Path` and performs:

```text
symlink metadata
  -> directory check
  -> symlink/reparse rejection
  -> canonicalization
  -> repeated directory and reparse check
  -> capability-directory open
  -> handle metadata check
```

The canonical path is private state. `Debug` renders only:

```text
StagingRoot([redacted])
```

There is no public path getter.

B1.3 adds a controlled creator above this low-level reader. Future custody code must use the
controlled root and lease API; direct `StagingRoot::open` remains a synthetic B1.2 primitive used by
tests and internal composition.

## Controlled root and session lease

`StagingParent::open` holds one approved existing parent as a directory capability. It rejects an
absent, linked, reparse or non-directory parent and exposes no path getter.

`ControlledStagingRoot::create` is authorized only while the session state is `created`. It derives
one direct child with the exact syntax:

```text
stg_[0-9a-f]{32}
```

Creation is exclusive and never silently reuses an existing child. Unix creates the root with mode
`0700`. Windows applies and re-reads a protected DACL containing exactly one owner full-control ACE
with object/container inheritance. The owner, DACL protection, ACE count and absence of broad
Everyone, Authenticated Users and Builtin Users ACEs are verified after creation.

The creator immediately acquires `.custody.lock` with `create_new` semantics. Unix uses mode `0600`.
Windows verifies one protected owner-only file ACE. A second live acquisition fails closed. Dropping
the lease closes and removes the control file but does not remove the staging root or claim evidence
disposition.

A controlled read requires:

```text
same session identifier
same root identity
same live lease identity
session.state == collecting
```

Filesystem operations never advance the session state or revision.

## Source name

A source name has the exact syntax:

```text
src_[0-9a-f]{32}.raw
```

It contains no:

- path separator;
- drive prefix;
- root prefix;
- `.` or `..` component;
- original filename;
- workspace label;
- arbitrary operator text.

The name denotes one direct child of the open staging root.

`SourceName` is not deserializable from the wire and its `Debug` is opaque.

## Session gate

A source read is authorized only while:

```text
session.state == collecting
```

Every other state returns `session_not_collecting` semantics through a Rust-only typed error.

Reading does not itself mutate the session state or revision.

## File restrictions

Before opening, B1.2 requires:

- source existence;
- a non-link, non-reparse direct child;
- a regular file;
- exactly one hard link;
- an initial size within the selected limit.

The source is then opened relative to the directory capability with final-component symlink
following disabled.

Metadata from the path and opened handle must identify the same object.

## Read limit

`SourceReadLimit` accepts:

```text
1 ..= 8 MiB
```

The fixed read chunk is:

```text
16 KiB
```

The reader:

1. allocates at most the validated initial size;
2. reads one fixed-size chunk at a time;
3. uses checked length arithmetic;
4. rejects before appending beyond the limit;
5. re-reads metadata from the open handle;
6. requires the pre-open, handle and post-read fingerprints to match;
7. requires the number of bytes read to equal the final handle length.

The fingerprint binds:

```text
device
inode/file identifier
hard-link count
byte length
modification time when available
creation time when available
```

A mismatch returns a path-free `source_changed` classification.

## Guarded source

A successful read creates `GuardedSource`.

The public Rust surface exposes only:

```text
byte_len
is_empty
```

It exposes no public byte getter and implements no serialization trait.

`Debug` contains the byte count and `[redacted]`, never content or a path.

Drop overwrites the initialized byte vector as best-effort memory hygiene.
This is not a disposition receipt, a logical-deletion proof or a physical-erasure guarantee.

## Error disclosure

Errors contain only a typed classification such as:

```text
invalid_staging_root
source_unavailable
source_link_rejected
source_not_regular_file
source_hard_link_rejected
source_too_large
source_changed
```

No error stores or formats:

- a path;
- a source name;
- an operating-system error string;
- raw bytes;
- a secret or endpoint.

## Synthetic tests

Tests create isolated temporary roots and synthetic byte sequences.

They cover:

- source-name and limit boundaries;
- session-state authorization;
- ordinary and exact-limit reads;
- oversized sources;
- directories;
- hard links;
- file symlinks;
- root symlinks;
- redacted debug output;
- absence of serialization, networking and public byte getters;
- absence of staging references from the protocol and binary modules.

Windows symlink tests may skip only when the runner lacks the OS privilege required to create the
test link. The production rejection logic remains compiled and covered by the other invariants.

## Residual risks and deferred controls

B1.2 does not establish operator-source provenance.

It does not yet provide:

- a source commitment;
- sanitizer allowlists;
- a sanitized commitment;
- retention policy;
- disposition receipt;
- logical deletion.

No real evidence may be handled until those controls and the B2/B3 non-disclosure path are merged.

<!-- systeme-local:b1-4-source-commitment -->
## Lease-bound commitment gate

B1.4 adds one controlled operation after the stable read:

```text
collecting session
    + matching controlled root
    + active matching lease
    + stable bounded source read
    -> private source commitment receipt
```

The receipt exposes only byte length and a lowercase SHA-256 commitment. The source buffer is still
owned by `GuardedSource` and receives the existing best-effort overwrite on drop. No path, source
name, session identifier or raw byte is returned.

The sanitizer-profile registry added by B1.4 is descriptive only. Sanitizer execution, sanitized
output, real evidence import, retention and disposition remain unavailable.

<!-- systeme-local:b1-5-deterministic-sanitization -->
## B1.5 lease-bound deterministic sanitizer gate

B1.5 adds one controlled operation after the B1.4 stable read and source commitment:

```text
collecting session
    + matching controlled root
    + active matching lease
    + stable bounded source
    + exact source commitment
    + closed sanitizer profile
    -> Rust-owned sanitized artifact
    -> bounded sanitized-output receipt
```

Each profile rejects malformed, unknown, duplicate, non-canonical or over-limit input. Text profiles
use closed key/value vocabularies and stable LF output. JSON profiles use closed typed fields,
duplicate rejection and canonical compact JSON. The implementation performs no network access,
subprocess execution, environment lookup, archive extraction, OCR or provider call.

Raw and sanitized buffers remain private and receive best-effort overwrite on drop. This does not
prove provenance, retention, logical deletion or physical erasure. Real evidence remains forbidden
until later disposition and Python non-disclosure gates are merged.
