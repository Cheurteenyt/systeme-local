# Provider context registry

Status: provider-neutral foundation implemented

## Decision

Système Local keeps provider account, quota, project and conversation context in a dedicated local registry. This registry is separate from the provider lifecycle event store because durable execution evidence and mutable provider context have different retention, concurrency and recovery semantics.

The user-facing rule is simple:

```text
automatic selection -> Chat
explicit Chat request -> Chat
explicit Work request + proven availability + usable quota -> Work
otherwise -> typed fallback to Chat
```

Work is never selected automatically. Système Local never purchases provider credits automatically.

Provider memory is complementary. The local registry and local task ledger remain canonical if a provider project, chat, quota or memory feature becomes unavailable.

## Components

```text
ProviderAccountProfile
    account availability, plan category and evidence
    Work capability
    project/chat discovery capabilities

ProviderQuotaSnapshot
    append-only observation for one quota dimension

ProviderProjectBinding
    local project identity and optional provider mapping

ProviderConversationBinding
    local conversation identity and optional provider mapping

ExperienceSelectionDecision
    deterministic Chat/Work decision with a user-facing reason code

ProviderContextStore
    versioned SQLite registry with compare-and-swap revisions
```

Raw prompts, model outputs, screenshots, file contents, passwords, cookies, bearer tokens and API keys do not belong in this registry.

## Evidence model

Every provider claim is evidence-backed:

```text
documented
observed
simulated
none
```

`unknown` is a valid safe state and requires `evidence=none`. A known state cannot use `evidence=none`.

Provider discovery capabilities are independent:

```yaml
can_create_projects: supported | unsupported | unknown
can_enumerate_projects: supported | unsupported | unknown
exposes_project_id: supported | unsupported | unknown
can_create_conversations: supported | unsupported | unknown
can_enumerate_conversations: supported | unsupported | unknown
exposes_conversation_id: supported | unsupported | unknown
```

A project visible to the operator does not prove that an automated surface can enumerate projects. A copied label or URL does not prove a stable provider identifier.

## Account profiles

An account profile contains only bounded metadata:

```yaml
account_id: acct_...
provider: example
surface: visible_account
provider_account_id: null
plan_kind: free | paid | managed | unknown
plan_code: null
availability: available | unavailable | degraded | unknown
work_capability:
  state: supported | unsupported | unknown
  evidence: documented | observed | simulated | none
revision: 1
created_at: UTC timestamp
updated_at: UTC timestamp
```

Provider account identifiers are optional. Once a non-null provider mapping is recorded, a later revision cannot replace or erase it. A previously unknown mapping may be enriched exactly once when supported evidence becomes available.

Project membership is mutable context, not conversation identity. An existing conversation may be moved into a project created later while preserving the conversation's original `created_at`; a new binding revision records the current project without rewriting history.

## Chat-first experience selection

Automatic selection always chooses Chat when the account is available. It does not inspect quotas to opportunistically switch to Work.

An explicit Work request is accepted only when:

1. the account is available;
2. Work is proven supported for that account and surface;
3. a Work quota observation belongs to the same account;
4. the quota dimension is `work_agentic`;
5. the quota observation is fresh under the local policy window;
6. the quota state is `available` or `near_limit`.

All other Work states fall back deterministically to Chat:

| Work state | Local decision |
|---|---|
| unsupported | Chat fallback |
| unknown | Chat fallback |
| quota missing | Chat fallback |
| quota unknown | Chat fallback |
| quota unavailable | Chat fallback |
| quota exhausted | Chat fallback |
| reset pending | Chat fallback |
| quota observation stale | Chat fallback |

An unavailable or unknown account produces no selected experience and a typed user message. The user interface translates message codes into concise language; internal exception names are not exposed as the primary message.

## Quota snapshots

Quota state is append-only evidence, not a mutable counter inferred by Système Local.

```yaml
snapshot_id: quota_...
account_id: acct_...
dimension: chat_messages | work_agentic | file_upload_rate | file_storage | project_file_slots
state: available | near_limit | exhausted | reset_pending | unavailable | unknown
evidence: documented | observed | simulated | none
observed_at: UTC timestamp
reset_at: null
remaining_value: null
limit_value: null
unit: unknown
```

Numeric values are optional because many provider surfaces expose only a qualitative state. Système Local does not estimate remaining quota from task counts, UI animations or previous errors.

A snapshot may include numeric evidence only with a known unit. An exhausted snapshot cannot report a positive remainder. Exact duplicates are idempotent; conflicting observations at the same account, dimension and timestamp fail closed.

A Work decision uses a bounded freshness window. The default local policy accepts a Work quota observation for at most five minutes; callers may choose a stricter positive window. A stale observation never authorizes Work and produces a typed Chat fallback.

## Projects

A local project binding records:

- canonical local `project_id`;
- account, provider and surface;
- display label;
- `project_only`, `default` or `unknown` memory scope;
- active, archived, deleted, inaccessible or unknown state;
- discovery source;
- optional stable provider mapping;
- monotonic revision and timestamps.

Provider project memory can help continuity between chats, but it is never the sole source of truth. Project instructions and summaries should be reproducible from local state.

## Conversations

A conversation binding records:

- canonical local `conversation_id`;
- optional local project membership;
- Chat or Work experience;
- persistent, temporary or unknown persistence;
- cloud, device-local, mixed or unknown synchronization scope;
- active, archived, deleted, inaccessible or unknown state;
- discovery source and optional provider mapping;
- monotonic revision and timestamps.

Temporary conversations cannot belong to projects. A disconnect never creates a replacement chat silently. A provider conversation mapping, once known, cannot be changed or cleared by a later revision.

## Allowed discovery sources

```text
operator_confirmed
provider_returned
official_connector
compliance_api
shared_reference
simulated
```

The following are prohibited:

```text
sidebar scraping
DOM observation
private endpoint discovery
cookie replay
guessed identifiers
model-generated identity claims
```

The registry may contain known projects and conversations without claiming that the provider supports enumeration of the whole account.

## Storage and concurrency

`ProviderContextStore` uses a separate versioned SQLite database with:

- `PRAGMA quick_check` and foreign-key verification;
- exact table, column and security-index verification;
- `BEGIN IMMEDIATE` transactions;
- current account, project and conversation heads;
- append-only version history;
- append-only quota observations;
- canonical JSON fingerprints with domain separation;
- denormalized-column verification;
- compare-and-swap revisions;
- unique current provider mappings;
- semantic verification that each head matches a canonical, contiguous version history;
- refusal of extra tables, missing metadata, missing uniqueness indexes and orphaned histories.

Two processes cannot both replace the same revision. The second stale writer fails closed and must reload current state before retrying.

## Failure behavior

- unknown Work support -> Chat fallback;
- exhausted or stale Work quota -> Chat fallback;
- unavailable account -> no provider selection;
- stale revision -> reject and reload;
- missing project -> reject conversation binding;
- conflicting provider mapping -> reject;
- corrupted payload, fingerprint, column or history -> refuse the store;
- unknown schema version -> refuse the store;
- real discovery unavailable -> keep capabilities `unknown` and use operator-confirmed bindings.

## Documentation ownership

This document is the provider-neutral contract. Provider-specific facts, volatile limits and product terminology belong in `docs/providers/` and must cite current official sources.

`docs/connectivity-model.md` remains the cross-provider connectivity source of truth. The lifecycle ledger remains authoritative for submitted turns and provider events; this context registry remains authoritative for local account/project/conversation bindings and quota observations.

## Next lot: multimodal attachments

Screenshots and files are intentionally separate. The next foundation will define:

- `CommittedAttachment` and ordered manifests;
- content hashes, MIME types, sizes and image dimensions;
- encrypted local blob storage;
- redaction and approval state;
- batching and provider limits;
- partial upload and ambiguous-acceptance recovery;
- retention and verified deletion.

No attachment bytes or screenshots are stored by the provider context registry.

## Non-goals

- real provider account enumeration;
- browser automation;
- private endpoint use;
- real project or conversation creation;
- real Work invocation;
- automatic credit purchase;
- attachment upload;
- replacing local canonical memory with provider memory.
