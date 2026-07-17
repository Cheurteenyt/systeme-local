# Système Local Audit Watchdog

This crate independently verifies the non-secret witness material produced by the
Système Local audit-anchor bootstrap.

The portable core validates strict JSON schemas, canonical digests, checkpoint
ordering, record monotonicity, the checkpoint pointer chain, the exact SHA-256
bootstrap prefix, the bootstrap receipt, and later anchor advancement.

On Windows, `verify-windows` additionally:

- acquires the existing audit-anchor lock before taking the snapshot;
- validates protected NTFS ACLs on `.env`, the anchor directory, anchor, lock,
  and bootstrap receipt;
- derives one consistent runtime SID from the hardened directory ACL;
- correlates an `Application` event from provider `SystemeLocalAuditAnchor`
  with ID `18001` to every receipt field;
- uses the bundled PowerShell collector only for Windows metadata and performs
  all security decisions in Rust.

The crate deliberately does **not** read `SLG_AUDIT_ANCHOR_KEY` and therefore
does not claim to authenticate checkpoint HMACs. The Python runtime remains
responsible for HMAC verification.
