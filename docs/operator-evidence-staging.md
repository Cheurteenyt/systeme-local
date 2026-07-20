# Operator-evidence synthetic staging

Status: normative private Rust staging contract, B1.2

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

B1.2 assumes the root was created by a controlled synthetic procedure. Controlled creation and
cross-platform permission hardening belong to a later B1 lot.

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

- Rust-controlled staging creation;
- verified owner-only ACL or mode enforcement;
- a lock or persistent session directory;
- a source commitment;
- sanitizer allowlists;
- a sanitized commitment;
- retention policy;
- disposition receipt;
- logical deletion.

No real evidence may be handled until those controls and the B2/B3 non-disclosure path are merged.
