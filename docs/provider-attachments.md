# Provider attachment manifests and deterministic batching

Status: provider-neutral metadata foundation implemented

## Decision

Système Local treats screenshots and files as committed binary inputs with explicit local identity. Attachment bytes are inspected and hashed locally, then represented by bounded metadata. Raw bytes are not placed in Pydantic models, lifecycle events, context records, receipts, logs or documentation fixtures.

This foundation is independent from any real provider transport. It does not prove that ChatGPT, another visible web surface or an API accepts a file.

## Layering

```text
immutable input bytes
    -> bounded structural inspection
    -> CommittedAttachment
    -> ordered AttachmentManifest bound to CommittedTurn
    -> capability and quota policy
    -> deterministic AttachmentBatchPlan
    -> metadata-only simulated provider receipt
```

Each layer has a separate digest domain. A raw content digest is not interchangeable with an attachment metadata digest, manifest digest, batch-plan digest or receipt digest.

## Supported local inspection formats

Version 1 verifies only formats with bounded deterministic checks:

| Media type | Required local evidence |
|---|---|
| `image/png` | PNG signature, valid chunk bounds and CRCs, first `IHDR`, valid dimensions and terminal `IEND` |
| `image/jpeg` | SOI/EOI boundaries and a bounded valid SOF marker before scan data |
| `application/pdf` | supported PDF header plus bounded terminal `startxref` and `%%EOF` |
| `text/plain` | strict UTF-8 without NUL |
| `application/json` | strict UTF-8, JSON-grammar whitespace only, no BOM, no NUL, no duplicate keys, no non-standard constants and one complete JSON value |

There is intentionally no generic `application/octet-stream` commitment in this lot. A type that cannot be verified from bounded content evidence is refused rather than guessed from a file extension.

The PNG parser validates structure and checksums but does not decompress image data. The JPEG parser extracts dimensions from bounded marker structure but does not decode pixels. PDF validation does not execute active content, render pages or extract embedded objects.

## Display-name contract

`display_name` is presentation metadata, never a filesystem path. It must:

- already be NFC-normalized;
- contain no `/` or `\`;
- contain no control character;
- not be `.` or `..`;
- not end in a Windows space or dot;
- not use a reserved Windows device stem such as `CON`, `NUL`, `COM1` or `LPT1`;
- fit within 240 UTF-8 bytes.

No provider or local storage identity is derived from the display name.

## Committed attachment

`CommittedAttachment` binds:

```text
attachment_id
conversation_id
turn_id
trace_id
ordinal
display_name
role
source
media_type
raw content SHA-256
byte size
optional image dimensions
inspection timestamp
commit timestamp
domain-separated metadata SHA-256
```

The ordinal is part of the commitment. Reordering attachments after commitment changes the manifest identity.

Attachment bytes are re-read and re-inspected before use. Any drift in byte size, raw digest, media type or dimensions invalidates the commitment.

## Ordered manifest

`AttachmentManifest` is bound to one existing `CommittedTurn` and includes:

- local manifest identity;
- conversation, turn and trace bindings;
- authenticated local principal;
- committed text-turn digest;
- contiguous zero-based attachment ordinals;
- attachment count and total bytes;
- ordered attachment metadata digests;
- manifest commit timestamp;
- domain-separated manifest SHA-256.

The manifest rejects:

- an empty attachment list;
- duplicate `attachment_id` values;
- duplicate raw content digests;
- non-contiguous ordinals;
- attachments belonging to another conversation, turn or trace;
- totals that do not exactly match entries;
- a commit timestamp earlier than any attachment commitment;
- any digest mismatch.

Duplicate content is rejected even when display names differ. This prevents accidental repeated upload and makes batching cardinality unambiguous.

## Capability profile

`AttachmentCapabilityProfile` is provider-surface specific, revisioned and evidence backed. It carries a stable local profile identifier, observation timestamp and domain-separated profile SHA-256. A supported profile records:

```text
profile identity and revision
support state and evidence
supported media types
max bytes per file
max bytes per batch
max bytes per manifest
max files per batch
max files per manifest
max batches per manifest
max image width
max image height
max image pixels
mixed-media behavior
upload-quota requirement
```

Unknown and unsupported profiles carry no positive limits and authorize no batch plan. A profile observed after the planning timestamp is rejected as future evidence. Profiles without image media must use zero image limits so irrelevant capabilities cannot be smuggled into the record.

Provider-specific product limits remain volatile observations. They are not compiled into these provider-neutral model defaults.

## Deterministic all-or-nothing batching

Planning cannot precede manifest commitment. The planner processes attachments in manifest order and uses a stable sequential greedy algorithm:

1. validate support, manifest limits and required quota;
2. validate every attachment media type, byte size and image bound;
3. append an attachment to the current batch when all limits remain satisfied;
4. otherwise close the current batch and start the next;
5. never reorder, omit or duplicate an attachment;
6. reject the entire plan when the resulting batch count exceeds the profile.

When mixed media is disabled, a media-family transition starts a new batch. Images and documents are separate families.

The planner never returns a partial plan after policy failure. Typed refusal reasons identify the first attachment or evidence violation.

Each plan binds the exact account, capability-profile identifier, revision and profile digest. When upload quota is required, the plan also binds a domain-separated digest of the complete quota snapshot in addition to its identifier and observation timestamp. Re-verification revalidates the manifest, profile, plan and quota models, then replays media, size, image, batch, quota and deterministic batch-ID constraints against the original evidence.

## Upload quota evidence

A profile may require a fresh `file_upload_rate` quota observation. Required evidence must:

- belong to the same account;
- use the `file_upload_rate` dimension;
- not come from the future;
- be within the positive local freshness window;
- be `available` or `near_limit`.

Missing, stale, unknown, exhausted, unavailable or reset-pending quota fails closed. No quota is inferred from task counts, UI appearance, previous uploads or model text.

## Simulated provider

`DeterministicFakeAttachmentProvider` is metadata-only, accepts only its declared provider surface and performs no transport. A simulated receipt cannot predate its plan. It supports deterministic scenarios:

```text
completed
partial
cancelled
rejected
ambiguous
```

A completed receipt lists all accepted attachments. A partial receipt lists a known prefix and forbids blind retry. A cancellation before acceptance may be retried safely. A rejection is final for the same payload. An ambiguous result asserts no accepted identifiers and requires reconciliation.

An idempotency key may be reused only for the exact same plan and batch payload. A repeated exact request returns the original receipt even when the caller asks the fake to use another scenario. Reusing the key for another batch fails with an idempotency conflict.

Receipt verification recomputes deterministic receipt and provider-upload identifiers, rejects duplicate provider-upload identifiers and temporal inversion, then checks completed, partial, cancelled, rejected and ambiguous semantics against the exact batch. A partial result must be a non-empty stable prefix; recomputing a receipt digest cannot legitimize a reordered acceptance set.

Ambiguous acceptance never authorizes an automatic retry.

## Security boundaries

The provider-neutral metadata foundation:

- stores no raw attachment bytes;
- stores no local path;
- performs no OCR, EXIF interpretation, archive extraction, decompression or document conversion;
- executes no active content;
- opens no socket and imports no HTTP client or OpenAI SDK;
- uses no browser, cookie, token or private endpoint;
- does not guess provider upload identifiers;
- does not claim a real provider can upload any supported local format;
- does not purchase credits or infer quota.

## Failure behavior

- malformed or truncated content -> reject before commitment;
- type/content mismatch -> reject;
- post-commit byte drift -> reject;
- duplicate identity or content -> reject manifest;
- unknown capability -> reject plan;
- unsupported media or limit breach -> reject plan;
- stale or unusable required quota -> reject plan;
- excessive batch count -> reject whole plan;
- changed idempotent payload -> conflict;
- ambiguous provider result -> reconcile, never blind retry.

## Non-goals

- durable attachment storage;
- encryption or key management;
- redaction, OCR, screenshot capture or image editing;
- approval workflow;
- retention or verified deletion;
- real provider upload;
- provider-specific account or project discovery;
- ChatGPT UI automation;
- OpenAI API transport;
- archive extraction or document conversion.

## Follow-up security lot

A separate security lot may add encrypted blob storage, short-lived leases, redaction decisions, approval, retention policy and verified deletion receipts. That lot must consume these immutable manifests rather than redefine attachment identity.

## C9 bounded live security overlay

Status: `partial` — implemented on the C9 branch with consolidated offline
closeout validation passed; live provider validation pending.

C9 consumes this provider-neutral identity without changing its public models
or digest domains. It adds a private process-local overlay for one exact
synthetic package:

```text
one generated PNG + one generated UTF-8 text file
    -> C9 sanitization and private mutable buffers
    -> existing canonical AttachmentManifest
    -> fresh operator-attested native-runtime observation
    -> real local-AI inference and two-nonce verification
    -> one Work rich-delivery lease
    -> one normal-Chat manual-export authority
```

This overlay is intentionally narrower than the formats supported by local
inspection above. C9 v1 rejects PDF, JSON, archives, office documents and
generic binary files. It strips non-essential PNG/JPEG metadata, normalizes
text and re-inspects the sanitized bytes before commitment.

Source paths and sanitized bytes do not enter `CommittedAttachment`,
`AttachmentManifest`, lifecycle events, audit records or public C9 receipts.
They remain under one private in-process authority. The authority verifies
source identity and hashes before and after callbacks, zeros buffers at a
terminal lease state and never creates a durable general attachment store.

The local AI receives read-only views of the sanitized package and does not
consume the delivery leases. A separate HMAC-bound observation records the
operator-attested native runtime, PID and privacy settings plus the inspected
executable digest and endpoint/model commitments. It is required in the final
chain but is not independent proof of the manually declared facts. Only after
that observation is fresh and the inference proves both synthetic nonce
hashes does C9 create one Work rich-delivery lease and one normal-Chat
manual-export authority. Both bind the same ordered descriptor and content
commitments but remain non-interchangeable transport proofs.

On the Work path, the read-only MCP tool uses the explicit `work` surface.
The metadata-only task result is audited before the renderer returns one
`ImageContent` block and one embedded UTF-8 resource. Current official
guidance explicitly excludes Plugins from normal Chat, so that tool is not a
Chat transport.

After Work, the private maximum-ten-minute export materializes the same
sanitized package for one visible, operator-performed normal-Chat file-picker
handoff. Exact private POSIX modes or an applied-and-queried owner-only
Windows DACL, path checks and hash revalidation narrow ordinary-principal and
TOCTOU exposure but do not protect against a privileged local attacker.

The Chat receipt may qualify only the visible manual transfer and nonce
consumption. It cannot qualify an MCP call, local endpoint, app invocation,
same-app identity or autonomous delivery.

This C9 overlay does not implement the general encrypted blob-storage lot
described above, authorize real user files, automate private ChatGPT
interfaces or prove another provider’s upload support. Its qualifying proof
fixture is synthetic PNG + TXT only. See
[`providers/chatgpt-web-c9-attachment-handoff.md`](providers/chatgpt-web-c9-attachment-handoff.md).
