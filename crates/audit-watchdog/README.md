# Système Local Audit Watchdog

This crate independently verifies the non-secret witness material produced by the
Système Local audit-anchor bootstrap.

It validates strict JSON schemas, canonical digests, checkpoint ordering, record
monotonicity, the checkpoint pointer chain, the exact SHA-256 bootstrap prefix,
the bootstrap receipt, and later anchor advancement.

It deliberately does **not** read `SLG_AUDIT_ANCHOR_KEY` and therefore does not
claim to authenticate checkpoint HMACs. The Python runtime remains responsible
for HMAC verification. A later Windows backend will compare this core report with
NTFS ACLs and Windows Event Log witnesses.
