# ADR 0004: Exclude raw provider evidence from public models

- Status: Accepted
- Date: 2026-07-18

## Context

UI exports, endpoint values, OAuth metadata, tool definitions and screenshots can contain secrets,
private identifiers or unrelated workspace data. Persisting them in public models would widen the
trust boundary and retention burden.

## Decision

Public provider evidence models store only typed states, bounded counts, timestamps and
domain-separated SHA-256 commitments. Raw evidence is sanitized outside public models and must
follow a separately governed temporary lifecycle.

## Consequences

- a digest is a commitment, not proof of source authenticity;
- future collectors need explicit temporary storage, access, sanitization and deletion rules;
- unknown or unsanitizable evidence fails closed;
- durable encrypted storage and verified deletion remain a separate security lot.
