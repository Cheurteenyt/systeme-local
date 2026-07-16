# Rust audit watchdog

## Security boundary

The first Rust increment is a read-only verifier for public witness data. It does
not parse `.env`, read an HMAC key, start a service, modify the anchor, or call
Windows APIs.

The verifier accepts only the current versioned schemas and fails closed on:

- unknown or duplicate JSON fields;
- non-canonical lowercase digests and commit identifiers;
- non-UTC or malformed RFC 3339 timestamps;
- symbolic links or non-regular input files;
- oversized receipt or anchor files;
- missing final line endings or malformed checkpoint records;
- duplicate checkpoint identifiers;
- changed audit-log identity;
- broken checkpoint pointers;
- non-monotonic record counts;
- mismatch between the receipt and its bootstrap checkpoint;
- mismatch between the receipt SHA-256 and the exact bootstrap prefix;
- a receipt that points to another anchor path.

Both LF and CRLF records are accepted because the current Windows runtime can
produce CRLF files. JSON parsing removes one optional carriage return, while the
bootstrap SHA-256 is always computed over the exact raw bytes, including the
original line ending.

## Explicit limitation

The Rust core never reads `SLG_AUDIT_ANCHOR_KEY`. It verifies witness consistency,
not HMAC authenticity. This limitation is included in every successful JSON
report as:

```json
{
  "scope": "non-secret-witness-consistency",
  "cryptographic_authentication_performed": false
}
```

The next increment will add a Windows-only backend that validates NTFS ACLs and
the `SystemeLocalAuditAnchor` event witness without weakening this secret-free
core.

## Local commands

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps --document-private-items --locked
cargo audit
```

Run the verifier with:

```text
cargo run --locked -p systeme-local-audit-watchdog -- verify --project-root .
```
