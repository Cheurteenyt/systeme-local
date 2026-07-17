# Windows audit witness contract

## Scope

This backend verifies local Windows witnesses that were created when optional
external audit anchoring was activated. It remains read-only and secret-free.

The verifier never reads:

- `SLG_AUDIT_KEY`;
- `SLG_AUDIT_ANCHOR_KEY`;
- `.env` contents;
- raw audit arguments, outputs, or session identifiers.

## Coordinated snapshot

The backend opens `.systeme-local/audit-anchor/audit-anchor.jsonl.lock` for
reading and writing and attempts an exclusive lock for at most five seconds.

The lock overlaps the first byte used by the Python runtime. The receipt,
anchor, ACLs, and Event Log witness are therefore observed while writers are
excluded. A timeout fails closed.

## NTFS ACL contract

Five objects are validated:

1. `.env`;
2. `.systeme-local/audit-anchor`;
3. `audit-anchor.jsonl`;
4. `audit-anchor.jsonl.lock`;
5. `bootstrap-receipt.json`.

Every object must:

- be a direct, non-reparse filesystem object;
- be owned by SID `S-1-5-18` (`SYSTEM`);
- have inheritance protection enabled;
- contain exactly two explicit `Allow` ACEs;
- contain no inherited or additional ACE.

The second principal is derived from the anchor directory and becomes the
activation runtime SID. That SID must be identical on all five objects.

Expected rights are compared numerically:

| Object | SYSTEM | Runtime SID |
|---|---:|---:|
| Anchor directory | `2032127` | `1179817` |
| Anchor file | `2032127` | `1180063` |
| Lock file | `2032127` | `1180063` |
| Bootstrap receipt | `2032127` | `1179785` |
| `.env` | `2032127` | `1180063` |

The `SYSTEM` directory ACE must use both container and object inheritance.
Every other ACE must use no inheritance or propagation flags.

## Event Log contract

The collector queries the `Application` log with:

- provider `SystemeLocalAuditAnchor`;
- event ID `18001`;
- at most the 64 newest matching events.

A valid event must match the bootstrap receipt exactly for:

- anchor path, compared as a normalized case-insensitive Windows path;
- record count;
- last audit HMAC;
- bootstrap checkpoint HMAC;
- bootstrap prefix SHA-256;
- Git commit.

The event timestamp must be UTC, must not predate the receipt, and its Event Log
record ID must be positive.

## Collector boundary

The bundled `windows_snapshot.ps1` collector runs with:

- the absolute system Windows PowerShell executable;
- `-NoProfile`;
- `-NonInteractive`;
- a cleared and reconstructed environment;
- a controlled system module path;
- bounded stdout and stderr.

It emits only JSON metadata. Rust validates the schema, paths, SIDs, rights,
event identity, and receipt correlation.

## Report boundary

A successful report uses scope:

```json
{
  "scope": "windows-local-witness-consistency",
  "lock_coordinated_snapshot": true,
  "powershell_collector_used": true,
  "cryptographic_authentication_performed": false
}
```

This does not prove HMAC authenticity and does not provide rollback resistance
beyond the configured local storage and Event Log boundaries.
