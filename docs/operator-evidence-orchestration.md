<!-- systeme-local:b2-0-orchestration-contract:v1 -->
# B2.0 bounded operator-evidence orchestration contract

Status: normative contract design; no protocol-v2 runtime capability is implemented

## Purpose

B2.0 closes the contract between the merged B1 custody foundation and future Python orchestration.
It does not collect real evidence. It selects one process and ingestion model, freezes protocol-v2
operations and limits, records the eleven-check compatibility matrix, and defines interruption
recovery before any filesystem or sanitizer capability becomes wire-reachable.

The project invariant remains:

```text
a remote agent proposes an intention
the local node remains the sole authority
raw local evidence stays inside a narrow local custody boundary
only minimized, typed and verified results may leave that boundary
```

## Authority

Python owns the immutable eleven-entry plan, account/workspace scope, source/check compatibility,
freshness, public provider models and digests, subprocess timeout and verification, bundle
construction, readiness evaluation and the final local `blocked/next-step` report.

Rust owns inherited-handle validation, raw-byte custody, controlled staging, source identity,
sanitizer dispatch, private commitments, immediate logical disposition and path-free responses.

Rust does not decide provider readiness. Python does not read raw evidence bytes merely to relay them.

## Protocol versions and operations

Protocol version 1 remains byte-for-byte unchanged and continues to expose only
`describe_contract`.

Protocol version 2 reserves exactly:

```text
describe_contract
process_evidence
recover_evidence
```

B2.0 defines these operations but implements none of them. A version-2 request against the B2.0
binary must still be rejected as unsupported until B2.1 is merged.

Every process remains one-shot: exactly one UTF-8 NDJSON request and one response. Success uses exit
code `0`, typed rejection uses `2`, and local I/O failure before a response uses `3`. Successful
stderr is empty and Python caps captured stderr at 8,192 bytes.

Limits are exact:

| Surface | Maximum |
|---|---:|
| stdin request | 16,384 bytes |
| stdout response | 65,536 bytes |
| stderr captured by Python | 8,192 bytes |
| typed projection | 8,192 bytes |
| recovery journal | 4,096 bytes |
| raw source absolute ceiling | 8,388,608 bytes |

## Selected source-ingestion capability

The selected design uses two explicitly inherited OS handles:

1. one read-only regular-file handle for the operator-selected source;
2. one owner-only directory handle for the approved staging parent.

The request contains only unsigned decimal handle identifiers. It contains no source path, staging
path or raw byte. Python opens the handles but never reads the source. Rust duplicates and validates
them before use.

Unix uses `close_fds=True` with an exact `pass_fds` allowlist. Windows uses
`STARTUPINFOEX.lpAttributeList["handle_list"]` with `close_fds=True`; every other handle remains
non-inheritable. The child rejects a handle that was not inherited, is writable, names a link,
reparse point, non-regular object or multiply-linked source, or does not identify an owner-only
staging parent.

Rejected alternatives:

- an arbitrary path in JSON, CLI arguments or environment;
- Python reading the file and writing bytes to a pipe;
- an ambient current-directory or temporary-directory convention;
- a long-lived privileged custodian daemon;
- a provider-facing upload or network channel.

## Transaction identity and controlled names

Python supplies one canonical `txn_[0-9a-f]{32}` transaction identifier. Rust derives the custody
session and controlled names from it under:

```text
systeme-local:operator-evidence-session-from-transaction:v1\x00
```

The first 32 lowercase hexadecimal characters of the framed SHA-256 become:

```text
ses_<derived>
stg_<derived>
src_<derived>.raw
rcv_<derived>.json
```

The recovery journal is a sibling of the staging root under the inherited staging-parent capability.
It is never placed inside the root, so the B1.6 root-emptiness contract remains intact.

## Process transaction

`process_evidence` is one closed transaction:

```text
validate request and inherited handles
-> create recovery journal
-> create session, controlled root and lease
-> copy from the inherited read-only handle into the exact staged source
-> stable read and source commitment
-> execute one accepted B1 profile
-> construct one typed projection
-> seal
-> dispose_immediately
-> verify source, lease, root and journal absence
-> emit one terminal response
```

Only `dispose_immediately` is wire-reachable. `retain_until` remains a private B1 library capability.
No success response is emitted before the resulting lifecycle state is `disposed`, the raw source,
lease and staging root are absent, the sanitized artifact overwrite was attempted and the recovery
journal was removed.

## Interruption recovery

The journal is created before raw bytes enter controlled staging and is atomically replaced after
each monotonic step. It contains only versioned identifiers, profile identifiers, progress states and
private commitments that already satisfy non-disclosure rules.

After timeout or abnormal termination, Python kills and reaps the process, then calls
`recover_evidence` with the transaction identifier and staging-parent handle. Recovery may remove an
existing source, lease, root and journal or prove they are already absent.

A recovered transaction never emits verified evidence. Its response requires:

```text
success_evidence_emitted = false
```

Python marks the record blocked or failed. Failure to recover blocks the complete run and produces a
local cleanup-required result.

## Request contracts

Common fields are exact, and unknown fields fail closed. `source_handle_id` is present only for
`process_evidence`; recovery cannot reopen the operator-owned source.

`process_evidence` fields:

```text
protocol_version
request_id
operation
challenge_sha256
transaction_id
plan_entry_sha256
scope_sha256
evidence_class
profile_id
source_handle_id
staging_parent_handle_id
source_collected_at_unix_seconds
retention_mode
retention_justification_sha256
retention_decided_at_unix_seconds
```

`recover_evidence` fields:

```text
protocol_version
request_id
operation
challenge_sha256
transaction_id
plan_entry_sha256
scope_sha256
staging_parent_handle_id
```

## Success response contract

A successful process response contains a closed typed projection plus private commitments and
terminal cleanup booleans. It contains no source name, path, session identifier, endpoint, metadata
body, tool definition, arbitrary operator prose or secret.

A successful recovery response contains no projection and no evidence commitment that Python may
convert to `verified`.

The complete field lists and enums are machine-readable in
[`operator-evidence-protocol-v2-design.json`](operator-evidence-protocol-v2-design.json).

## Timestamp ownership

Python owns:

```text
plan_created_at
custody_started_at
sanitized_at
disposed_at
record_expires_at
bundle_collected_at
bundle_expires_at
```

Only `source_collected_at_unix_seconds` and `retention_decided_at_unix_seconds` cross the process
boundary. Rust reads no clock. Python samples process start and terminal response times locally,
enforces ordering and computes public validity windows. The complete bundle expires within fifteen
minutes and never after a member record or summary.

## Eleven-check compatibility matrix

| # | Check | Current exact path | Decision |
|---:|---|---|---|
| 1 | `plan_role_observation` | typed local attestation only | `ui_export_v1` lacks plan and role; reserve `readiness_ui_snapshot_v1` |
| 2 | `web_client` | typed local attestation only | `ui_export_v1` does not bind the web client |
| 3 | `transport` | none | requires a separate transport attestation summary and future transport lot |
| 4 | `authentication_metadata` | none | `metadata_document_v1` lacks the five public summary digests |
| 5 | `refresh_token` | none | must reuse the exact future authentication summary |
| 6 | `developer_mode` | typed local attestation only | no current UI field |
| 7 | `app_configuration` | typed local attestation only | `app_state` is not the exact configured boolean |
| 8 | `workspace_access` | typed workspace-admin attestation only | `access_control` is not access granted |
| 9 | `tool_snapshot` | none | destructive count is not high-risk count; reserve `tool_review_snapshot_v1` |
| 10 | `action_review` | `action_review_snapshot_v1`, partial | verified state still depends on the future combined tool-review summary |
| 11 | `local_policy` | `local_policy_snapshot_v1` | exact |

Typed local attestations contain only closed provider enums, booleans, collector identifiers,
timestamps and a domain-separated digest. They are Python-owned and do not carry raw UI bytes.
The B3 operator command is responsible for obtaining the explicit human confirmation.

Reserved gap-profile names are design placeholders, not authorized runtime profiles:

```text
readiness_ui_snapshot_v1
authentication_summary_v1
tool_review_snapshot_v1
transport_attestation_summary_v1
```

A separate reviewed lot must define and implement any of them.

## Public-model compatibility

The design preserves all existing public imports, Pydantic schemas, enums, canonical bytes and
digest domains. Private Rust commitments do not replace:

- `McpOperatorEvidenceRecord`;
- `McpTransportEvidenceSummary`;
- `McpAuthenticationEvidenceSummary`;
- `McpToolReviewEvidenceSummary`;
- `McpOperatorEvidenceBundle`;
- existing readiness observations or decisions.

Unknown, stale, contradictory, unavailable or gap-blocked evidence remains `unknown`,
`not_applicable` or the exact typed `failed` state. It never falls back to `verified`.

## Validation precedence

The exact order is recorded in the design manifest and begins with input size, message cardinality,
JSON syntax, shape, unknown and missing fields. Handle presence is not inspected until protocol
shape, identifiers, digests and field combinations have passed. Sanitization precedes retention,
logical disposition precedes serialization, and no partial success is emitted.

## Non-disclosure

Requests, responses, errors, journals, fixtures, debug output and durable reports contain no:

- source or staging path;
- raw evidence;
- endpoint value;
- metadata body;
- tool definition or action text;
- account/workspace display label;
- credential, cookie, token or private key;
- operating-system error string.

Operator-owned sources are never deleted or modified. Namespace cleanup and memory overwrite remain
logical controls, not physical-erasure guarantees.

## Sequencing

B2.0 is contract-only. After independent approval and merge:

1. B2.1 may implement protocol-v2 transaction mechanics with synthetic handles and fixtures;
2. a separate gap-profile lot may implement only the profiles explicitly selected after review;
3. B2.2 may implement Python orchestration;
4. B2.3 may construct the fifteen-minute bundle and local `blocked/next-step` report;
5. B3 may add the operator command and end-to-end real-evidence non-disclosure tests.

Tunnel, OAuth/OIDC client registration, ChatGPT app configuration, provider calls and browser
automation remain separately approved future lots.


<!-- systeme-local:b2-0-contract-repair-v2 -->
## Contract revision 2

Independent review findings B20-REV-001 through B20-REV-005 are closed by the
machine-readable revision-2 manifest.

The wire contract now defines exact field types, operation-specific field order,
canonical JSON/NDJSON, version negotiation, exit codes, idempotency, typed error
responses, and domain-separated request, success, error and projection
commitments. Every error code and every validation-precedence edge has a
synthetic manifest example.

Each B1 profile now has one exact projection schema, profile version, evidence
class, output class, byte limits and canonical-byte reconstruction. Python
derives the private `ses_` identifier from `transaction_id` and can recompute the
existing B1 sanitized-output commitment from the returned source commitment and
the reconstructed sanitized bytes without receiving the raw source.

Python-owned plan/role, web-client, developer-mode, app-configuration and
workspace-access attestations have closed fields, authorities, validity windows
and separate digest domains. Workspace access requires `workspace_admin`.

The recovery journal has exact fields, thirteen monotonic states, a prior-hash
chain, owner-only cross-platform permissions and atomic `.next` replacement.
Journal data is never authority to skip actual namespace validation.

Inherited-handle identifiers, rights, Windows flags, Unix flags, duplication,
close behavior and before/after identity checks are exact. Version 2 supports
64-bit processes only.

Timestamps are bounded to `0..=253402300799`; process and recovery timeouts are
60 and 30 seconds. Record and bundle expiry use checked, deterministic
equations. Version 2 remains non-reachable and real evidence remains prohibited.

## C0 non-interference

ADR 0007 permits a separate synthetic connectivity probe before B2 collection.
The probe has no operator-evidence handle, staging path, protocol-v2 operation,
or provider-outbound transport. Its fixed response explicitly reports
`real_evidence_access=false` and `protocol_v2_reachable=false`. A successful C0
call therefore proves only the inbound MCP path and does not satisfy any B2
gate.
