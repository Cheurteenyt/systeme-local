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
