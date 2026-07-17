# Rust audit watchdog

## Security boundary

The Rust watchdog is a read-only verifier for public witness data. It does not
parse `.env`, read an HMAC key, start a service, or modify the anchor.

The portable core accepts only the current versioned schemas and fails closed on:

- unknown or duplicate JSON fields;
- non-canonical lowercase digests and commit identifiers;
- non-UTC or malformed RFC 3339 timestamps;
- symbolic links or non-regular input files;
- oversized receipt or anchor files;
- missing final line endings or malformed checkpoint records;
- duplicate checkpoint identifiers or HMAC values;
- changed audit-log identity;
- broken checkpoint pointers;
- non-monotonic record counts or timestamps;
- mismatch between the receipt and its bootstrap checkpoint;
- mismatch between the receipt SHA-256 and the exact bootstrap prefix;
- a receipt that points to another anchor path.

Both LF and CRLF records are accepted because the current Windows runtime can
produce CRLF files. JSON parsing removes one optional carriage return, while the
bootstrap SHA-256 is always computed over the exact raw bytes, including the
original line ending.

## Windows-local witness backend

The `verify-windows` command extends the portable report without weakening it.
It first acquires the existing `audit-anchor.jsonl.lock` with a bounded
five-second timeout. On Windows the Rust standard library uses `LockFileEx`;
the Python runtime locks the first byte through `msvcrt.locking`, so the
overlapping ranges coordinate one stable snapshot.

While the lock is held, the backend:

1. verifies the receipt and anchor with the portable core;
2. invokes the bundled, no-profile Windows PowerShell collector through the
   absolute system executable;
3. collects numeric ACL metadata without reading `.env` contents;
4. validates in Rust that all five objects are owned by `SYSTEM`, have protected
   DACLs, exactly two explicit allow ACEs, one consistent runtime SID, and the
   expected rights;
5. filters the Application log by provider `SystemeLocalAuditAnchor` and event
   ID `18001`;
6. requires one event whose path, record count, digests, commit, and timestamp
   match the bootstrap receipt exactly.

The collector is intentionally not authoritative: it emits bounded JSON
metadata, and Rust performs every comparison. The report records that the
snapshot was lock-coordinated and that PowerShell supplied Windows metadata.

## Explicit limitation

Neither command reads `SLG_AUDIT_ANCHOR_KEY`. They verify witness consistency,
not HMAC authenticity. This limitation is included in every successful report:

```json
{
  "cryptographic_authentication_performed": false
}
```

The Python runtime remains the HMAC authority.

## Local commands

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps --document-private-items --locked
cargo audit
```

Run the portable verifier with:

```text
cargo run --locked -p systeme-local-audit-watchdog -- verify --project-root .
```

On the activated Windows host, run the full local witness verifier with:

```text
cargo run --locked -p systeme-local-audit-watchdog -- verify-windows --project-root .
```

See [`windows-audit-witness.md`](windows-audit-witness.md) for the exact ACL and
Event Log contract.
