# Operator-evidence custodian protocol

Status: normative protocol contract, version 1 synthetic scaffold

## Purpose

This document is the authority for the private process boundary between Python policy orchestration
and the Rust operator-evidence custodian. It does not authorize evidence collection or connectivity.

B0 supports one synthetic operation only:

```text
describe_contract
```

It opens no file, accepts no path, performs no sanitization and creates no custody session.

## Ownership

Python owns the eleven observations, source/check compatibility, freshness, existing public provider
models and digest domains, bundle compilation, readiness evaluation and the final local
`blocked/next-step` report.

Rust owns future raw-byte custody, bounded ingestion, path and file-type safety, sanitizer execution,
private commitments, temporary sessions and logical disposition receipts.

Rust does not own or reproduce public provider models or existing public digest domains.

## Transport

- one local process per request;
- stdin and stdout use UTF-8 NDJSON;
- exactly one request and one response;
- input limit: 8,192 bytes;
- stdout contains only the response line;
- stderr is empty on success and bounded by the Python caller;
- no shell invocation;
- no path or raw evidence in CLI arguments;
- no network access;
- no secret-bearing environment variables.

A trailing LF or CRLF is accepted. Any second line is rejected.

## Request v1

Fields are exact and unknown fields are rejected.

```json
{
  "protocol_version": 1,
  "request_id": "contract_probe_001",
  "operation": "describe_contract",
  "challenge_sha256": "3e5318cc2a895a2db4d7cb083f095ae9d33c929cfe5aefd3d0d9798fd25e4f39"
}
```

Schema:

| Field | Contract |
|---|---|
| `protocol_version` | integer `1` |
| `request_id` | `^[a-z][a-z0-9_]{2,127}$` |
| `operation` | `describe_contract` |
| `challenge_sha256` | 64 lowercase hexadecimal characters |

## Success response v1

```json
{
  "protocol_version": 1,
  "request_id": "contract_probe_001",
  "status": "ok",
  "operation": "describe_contract",
  "challenge_sha256": "3e5318cc2a895a2db4d7cb083f095ae9d33c929cfe5aefd3d0d9798fd25e4f39",
  "contract_sha256": "ac0b52c54d52e4733dd965b973f08e47e8d1a7435541052262061ad51f51f823",
  "contract": {
    "synthetic_only": true,
    "real_evidence_ingestion": false,
    "filesystem_access": false,
    "network_access": false,
    "sanitizer_execution": false,
    "public_provider_model_authority": false
  }
}
```

Every capability in the synthetic descriptor is fail-closed. In B0, filesystem access, evidence
ingestion and sanitizer execution are all false.

## Error response v1

```json
{"protocol_version":1,"request_id":null,"status":"error","error_code":"invalid_json"}
```

`request_id` is echoed only when it already satisfies the identifier contract. Raw input is never
echoed.

Typed error codes:

- `input_too_large`;
- `multiple_messages`;
- `invalid_json`;
- `invalid_shape`;
- `unknown_field`;
- `missing_field`;
- `unsupported_protocol_version`;
- `invalid_request_id`;
- `unsupported_operation`;
- `invalid_digest`;
- `serialization_failure`.

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | valid synthetic response |
| `2` | typed protocol rejection |
| `3` | local I/O failure before a protocol response can be written |

## Validation precedence

Implementations classify errors in this order:

1. input size;
2. message cardinality;
3. JSON syntax;
4. top-level object shape;
5. unknown fields;
6. missing fields;
7. protocol version;
8. request identifier;
9. operation;
10. digest syntax.

This order is part of the conformance contract.

## Contract commitment

The private contract commitment is:

```text
SHA-256(
  domain ||
  len64(protocol_version_utf8) || protocol_version_utf8 ||
  len64(request_id_utf8)       || request_id_utf8 ||
  len64(operation_utf8)        || operation_utf8 ||
  len64(challenge_utf8)        || challenge_utf8
)
```

The domain is the exact byte sequence:

```text
systeme-local:operator-evidence-custodian-contract:v1\x00
```

Lengths are unsigned 64-bit big-endian integers. The synthetic fixture commitment is:

```text
ac0b52c54d52e4733dd965b973f08e47e8d1a7435541052262061ad51f51f823
```

This is a private protocol commitment. It does not replace any public provider digest.

## Non-disclosure

Success and error responses cannot contain:

- source paths;
- endpoint values;
- raw evidence;
- credentials, tokens or cookies;
- metadata documents;
- tool definitions;
- environment values.

Checked-in fixtures are synthetic and contain no operator evidence.

## B1.1 internal session lifecycle

B1.1 adds an in-memory Rust session state machine governed by
[`operator-evidence-session-lifecycle.md`](operator-evidence-session-lifecycle.md).

This internal Rust API:

- does not add a protocol operation;
- does not change protocol version `1`;
- does not alter the checked-in B0 request or response fixture;
- performs no filesystem or network I/O;
- emits no session receipt through stdout.

The B0 wire descriptor therefore remains synthetic-only with filesystem access, evidence ingestion
and sanitizer execution set to `false`.

## B1.2 internal staging reader

B1.2 adds an internal Rust library capability governed by
[`operator-evidence-staging.md`](operator-evidence-staging.md).

The reader:

- opens a Rust-local staging root as a directory capability;
- accepts only an opaque direct-child name;
- disables following the final symbolic-link component;
- rejects non-regular, reparse and multiply-linked objects;
- reads synthetic bytes under a strict streaming limit;
- returns a redacted, non-serializable Rust object.

This capability is not reachable through protocol v1. `protocol.rs` and `main.rs` do not reference
the staging API. No path, source name or byte field is added to a request or response.

Therefore the checked-in B0 response remains byte-for-byte unchanged and continues to report
`filesystem_access=false`: no filesystem action is reachable through `describe_contract`.

## Evolution

Any protocol change requires:

- a new protocol version;
- an ADR amendment or successor;
- coordinated Python and Rust changes;
- new conformance fixtures;
- compatibility and non-disclosure tests;
- explicit review before real evidence custody is enabled.

## B1.3 controlled staging boundary

B1.3 adds `StagingParent`, `ControlledStagingRoot` and `SessionLease` inside the Rust library. It
does not add a protocol operation, request field, response field or path input. `protocol.rs` and
`main.rs` do not reference the controlled staging API.

Protocol v1 therefore still reports:

```text
filesystem_access = false
real_evidence_ingestion = false
sanitizer_execution = false
```

These values continue to describe wire-reachable capabilities. The internal Rust filesystem
capability is not reachable through protocol v1.

<!-- systeme-local:b1-4-source-commitment -->
## B1.4 remains outside protocol v1

Source commitments and sanitizer profiles are private library contracts. They are not request
operations, response fields or serialized protocol objects. `protocol.rs`, `main.rs` and the
checked-in protocol-v1 fixtures remain unchanged.

The advertised protocol descriptor therefore continues to require literal false values for
`filesystem_access`, `real_evidence_ingestion`, `network_access`, `sanitizer_execution` and
`public_provider_model_authority`.

<!-- systeme-local:b1-5-deterministic-sanitization -->
## B1.5 remains outside protocol v1

Deterministic sanitizer execution and sanitized-output commitments are private Rust library
contracts. They add no request operation, response field or serialized artifact. `protocol.rs`,
`main.rs` and the checked-in B0 fixtures remain byte-for-byte unchanged.

The protocol-v1 descriptor therefore continues to report literal false values for filesystem access,
real-evidence ingestion, network access and sanitizer execution. B1.5 does not authorize Python or a
remote caller to submit a path, raw evidence, sanitizer profile or source commitment over the wire.

<!-- systeme-local:b1-5-sanitizer-contract-repair -->
## B1.5 normative deterministic sanitizer contract

This section is the normative B1.5 sanitizer contract. The five profiles are closed, version `1`,
pure, local and deterministic. Input order may vary only for the two line-oriented profiles; every
successful output uses the stable ordering defined below. Duplicate, unknown and missing fields fail
closed. No profile accepts a path, endpoint, arbitrary prose, credential, cookie, token, account or
workspace label.

### Shared custody and error precedence

The public Rust entry point first proves, in order:

1. the same custody session, controlled root and active lease;
2. a stable bounded source read while the session is `collecting`;
3. the closed profile registry;
4. recomputation and exact equality of the source commitment;
5. the profile input-byte ceiling;
6. the profile-specific input grammar;
7. the profile output-byte ceiling;
8. the sanitized-output commitment.

A failure returns no `SanitizedArtifact` and no `SanitizedOutputReceipt`.

For line-oriented profiles, parser error precedence is:

1. invalid UTF-8;
2. missing final LF, empty input, blank line or forbidden control/bidi character;
3. malformed `key=value` line;
4. unknown key;
5. unsupported value or duplicate key;
6. missing required key;
7. output-capacity failure.

For JSON profiles, parser error precedence is:

1. UTF-8 BOM, CR or trailing LF as non-canonical transport encoding;
2. invalid UTF-8;
3. JSON maximum nesting greater than `MAX_JSON_DEPTH = 1`;
4. JSON syntax, top-level shape, duplicate, unknown or missing field;
5. mismatch from the exact compact canonical JSON field order;
6. classified-count validation where applicable;
7. lowercase SHA-256 syntax;
8. output serialization or capacity failure.

The maximum JSON nesting is exactly one container: one top-level object containing scalar booleans,
unsigned counts, closed enums and lowercase SHA-256 strings. Nested objects and arrays are rejected
before deserialization.

### `ui_export_v1`

- accepted input grammar: strict UTF-8 `key=value\n`, exactly one line for every key;
- maximum input: `8388608` bytes;
- maximum output: `262144` bytes;
- output grammar: canonical UTF-8 text with LF endings;
- stable output order and closed values:
  1. `access_control=public|restricted|unknown`;
  2. `action_review=approved|blocked|unknown`;
  3. `app_state=draft|published|unknown`;
  4. `authentication=available|unavailable|unknown`;
  5. `tool_scan=blocked|passed|unknown`;
  6. `transport=available|unavailable|unknown`.

### `metadata_document_v1`

- accepted input grammar: one compact canonical JSON object, `MAX_JSON_DEPTH = 1`;
- maximum input: `2097152` bytes;
- maximum output: `262144` bytes;
- output grammar and stable field order:
  1. `authorization_code`: boolean;
  2. `document_sha256`: 64 lowercase hexadecimal characters;
  3. `pkce`: boolean;
  4. `refresh_token`: boolean;
  5. `token_auth_method`: `client_secret_post`, `private_key_jwt` or `none`.

### `tool_scan_snapshot_v1`

- accepted input grammar: one compact canonical JSON object, `MAX_JSON_DEPTH = 1`;
- maximum input: `4194304` bytes;
- maximum output: `524288` bytes;
- output grammar and stable field order:
  1. `capability_count`: unsigned integer in `0..=4096`;
  2. `destructive_count`: unsigned integer;
  3. `read_only_count`: unsigned integer;
  4. `snapshot_sha256`: 64 lowercase hexadecimal characters;
  5. `unknown_count`: unsigned integer;
- `destructive_count + read_only_count + unknown_count` must equal `capability_count` with checked
  arithmetic.

### `action_review_snapshot_v1`

- accepted input grammar: one compact canonical JSON object, `MAX_JSON_DEPTH = 1`;
- maximum input: `1048576` bytes;
- maximum output: `131072` bytes;
- output grammar and stable field order:
  1. `action_count`: unsigned integer in `0..=4096`;
  2. `approved_count`: unsigned integer;
  3. `blocked_count`: unsigned integer;
  4. `snapshot_sha256`: 64 lowercase hexadecimal characters;
  5. `unknown_count`: unsigned integer;
- `approved_count + blocked_count + unknown_count` must equal `action_count` with checked
  arithmetic.

### `local_policy_snapshot_v1`

- accepted input grammar: strict UTF-8 `key=value\n`, exactly one line for every key;
- maximum input: `1048576` bytes;
- maximum output: `262144` bytes;
- output grammar: canonical UTF-8 text with LF endings;
- stable output order and closed values:
  1. `approval=not_required|required`;
  2. `network=disabled|enabled`;
  3. `retention=ephemeral|retained`;
  4. `secrets=absent|present`;
  5. `workspace=isolated|shared`.

### Sanitized-output commitment and receipt

The exact commitment field order is:

```text
domain
len64(custody session identifier) || custody session identifier
len64(source commitment)          || source commitment
len64(profile identifier)         || profile identifier
len64(profile version)            || profile version
len64(output class)               || output class
u64be(output length)
sanitized bytes
```

The domain remains:

```text
systeme-local:operator-evidence-sanitized-output:v1\x00
```

Every `len64` and the output length are unsigned 64-bit big-endian values obtained with checked
conversion. The receipt exposes only the source commitment, profile identifier, profile version,
output class, sanitized byte length and sanitized commitment. The artifact exposes no public byte
getter and its initialized buffer uses best-effort overwrite on drop. These controls prove neither
provenance, truth, retention, logical disposition nor physical erasure.
