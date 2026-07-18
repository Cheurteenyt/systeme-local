# Connectivity model — provider-specific web AI channels

## Decision

Système Local supports separate connectivity channels that share the same provider-neutral task ledger, policy engine, audit trail and local execution plane. A protocol façade, a provider transport and a visible provider conversation are different concepts and must never be merged into one implicit abstraction.

Every web AI provider has a dedicated capability profile and adapter. ChatGPT is the first provider to be characterized, but the common core must not assume that later providers expose the same conversation identifiers, streaming events, tool calls, cancellation semantics or browser features.

| Mode | Who starts the exchange? | Direction | Machine contract required? |
|---|---|---|---:|
| Inbound MCP tools | The web host | web host → local tools | MCP |
| Outbound provider adapter | The authenticated local agent | local orchestrator → provider | Yes, provider-specific |
| Provider-approved web-session bridge | The local agent through a visible, supported companion | local orchestrator → visible web session | Provider-supported mechanism |
| Interactive handoff | The user | manual in both directions | No |

A prompt displayed in a provider website is not automatically equivalent to a public developer API request. Private browser endpoints, cookies and undocumented DOM behavior are not stable integration contracts.

Provider-specific details belong under `docs/providers/`. This document is the only normative cross-provider connectivity source of truth.

## Two directions must coexist

A complete integration can require two independent channels:

```text
local agent
    │ committed, authenticated turn
    ▼
provider adapter
    │ provider-specific outbound transport
    ▼
web AI
    │ structured tool request
    ▼
local MCP façade
    │ policy + approval + execution + audit
    ▼
tool result returned through the provider adapter
```

The current MCP implementation covers the lower half of this loop: a client calls governed local tools. It remains useful even when a separate provider adapter is added for local-agent initiated turns.

MCP must not be treated as a generic prompt-submission API. Likewise, a provider API or web-session bridge must not bypass the local capability registry, policy engine, approval store or audit trail.

## Provider capability profiles

Before an adapter is implemented, it must publish an evidence-backed profile. Unknown capabilities remain `unknown`; they are never inferred from another provider.

Minimum fields:

```yaml
provider: example
profile_version: 1
surfaces:
  inbound_mcp:
    status: supported | unsupported | unknown
    evidence: documented | observed | none
  outbound_machine_turns:
    status: supported | unsupported | unknown
    evidence: documented | observed | none
  visible_web_session:
    status: supported | unsupported | research | unknown
    evidence: documented | observed | none
capabilities:
  can_initiate_turn: true | false | unknown
  can_create_conversation: true | false | unknown
  can_enumerate_conversations: true | false | unknown
  exposes_conversation_id: true | false | unknown
  exposes_terminal_response_event: true | false | unknown
  supports_streaming: true | false | unknown
  supports_tool_calls: true | false | unknown
  supports_cancellation: true | false | unknown
  supports_resume: true | false | unknown
```

The profile records what is proven for a specific surface. A capability available through an official API does not prove that the same capability exists in the provider's visible web interface.

## Provider account context and experience selection

Provider execution state and provider account context are separate. The lifecycle ledger records submitted turns and normalized provider events. The context registry records evidence-backed account availability, quota observations, project bindings and conversation bindings. See [`provider-context-registry.md`](provider-context-registry.md).

For providers that expose conversational and agentic experiences, the local policy is deterministic:

- Automatic selection uses Chat;
- an explicit Chat request uses Chat when the account is available;
- Work is selected only after an explicit request, proven support and a fresh usable quota observation;
- unknown, unavailable or exhausted Work state falls back to Chat with a typed reason;
- automatic credit purchase is forbidden.

Minimum context capability fields:

```yaml
context_capabilities:
  can_create_projects: supported | unsupported | unknown
  can_enumerate_projects: supported | unsupported | unknown
  exposes_project_id: supported | unsupported | unknown
  can_create_conversations: supported | unsupported | unknown
  can_enumerate_conversations: supported | unsupported | unknown
  exposes_conversation_id: supported | unsupported | unknown
```

A known project or conversation binding does not prove that the provider supports account-wide enumeration. Provider identifiers remain optional mappings and are never guessed from display labels, copied URLs, browser tabs or model output.

Provider quota observations are append-only. The local system records only what a supported surface proves and never estimates remaining usage from task counts or UI appearance.

## Local-agent identity

The local agent is authenticated before any provider-specific transport is used. Its identity is not established by prompt text.

A committed turn binds at least:

- `agent_id`;
- `instance_id`;
- `key_id`;
- `conversation_id`;
- `turn_id`;
- creation and expiry timestamps;
- nonce;
- content hash;
- signature.

The provider may receive a descriptive claim that the turn came from an authenticated local agent, but the model does not perform the authentication. Cryptographic verification and authorization remain local.

A provider conversation identifier, browser tab, MCP connection identifier or model-generated statement is never sufficient proof of identity.

## Turn and completion semantics

Système Local uses explicit lifecycle events instead of silence, punctuation or UI animation heuristics.

```text
local_turn.started
local_turn.content.delta
local_turn.committed
provider_run.submitted
provider_response.started
provider_response.event
provider_response.terminal
tool_loop.completed
delegation.completed
receipt.verified
```

`local_turn.committed` means the local agent has finished the immutable input. The final content hash, byte count and part count are verified before submission.

`provider_response.terminal` means the provider-specific response reached a documented terminal state such as completed, failed, cancelled or incomplete. It does not necessarily mean the delegation is finished.

`delegation.completed` requires all of the following:

- a successful terminal provider response;
- no pending tool call;
- no pending approval;
- required outputs validated;
- audit and receipt persisted.

Adapters must normalize provider events into this lifecycle while retaining the original provider identifiers and sequence numbers as evidence.

## Conversation ownership

Tasks and conversations belong to the local ledger, not to a provider sidebar or browser tab.

The local registry uses its own identifiers:

```text
conversation_id
turn_id
task_id
provider_run_id
tool_call_id
trace_id
```

Provider identifiers are optional mappings:

```json
{
  "conversation_id": "slconv_...",
  "provider": "example",
  "provider_conversation_id": null,
  "last_provider_run_id": "provider-specific",
  "state": "active"
}
```

Creating a new visible provider chat, detecting that a new chat was opened or enumerating existing chats are provider-specific capabilities. They remain unsupported or unknown until the provider profile contains evidence.

A disconnect never silently creates a new conversation. A retry never repeats a local effect without the same idempotency key and a verified state transition.

## Inbound MCP tools

Inbound MCP is the path where a compatible web host initiates tool calls:

```text
web host
    │ MCP tool call
    ▼
authenticated MCP edge or supported tunnel
    │ outbound local delivery
    ▼
local control plane
    │ policy + approval + sandbox
    ▼
structured tool result
```

In this mode:

- the provider host initiates model turns;
- the local node exposes only policy-advertised tools;
- the local node cannot force a model response when no host session is active;
- the MCP session is transport state, not a trusted conversation identity;
- tool calls still become signed local tasks and pass through the same `TaskProcessor`.

The local loopback MCP runtime, bearer authentication, host and origin checks, request limits, rate limits, concurrency limits, policy-derived registry, audit integration and official-client smoke workflow are retained.

## Outbound provider adapters

A local agent initiates a provider turn only through a dedicated adapter whose capability profile proves a supported machine contract.

A supported contract may be an official API, SDK, agent protocol or another documented provider mechanism. The common core does not require every provider to use an API, but it refuses to invent one from private browser traffic.

The adapter is responsible for:

- provider authentication;
- request and conversation identifiers;
- event ordering;
- terminal-state detection;
- tool-call normalization;
- bounded retries and idempotency;
- cancellation and resume when supported;
- error and quota evidence;
- redaction of secrets and sensitive content.

When the provider emits a tool call, the orchestrator validates it locally, invokes the governed capability through the local execution path, then returns the structured result through the provider adapter.

## Provider-approved web-session bridges

A visible web-session bridge is a separate provider surface. It may be considered only when the mechanism is documented or explicitly supported, remains visible to the user and does not depend on private endpoints or credential extraction.

Before implementation, characterization must answer:

- how the local agent submits a complete turn;
- how the source agent is represented;
- whether a stable conversation identifier is exposed;
- whether a new conversation can be created explicitly;
- how a response terminal state is observed;
- how human interruption is detected;
- how login expiry, moderation, quotas and provider UI changes are surfaced;
- whether the mechanism permits reliable cancellation and resume.

If these questions cannot be answered with evidence, the surface remains `research` or `unsupported`. The system falls back to an official provider contract or interactive handoff.

## Interactive handoff

When no supported autonomous transport exists, Système Local creates a signed task capsule containing:

- a provider-neutral checkpoint;
- a minimal prompt brief;
- references to exportable artifacts;
- an expected structured response schema;
- expiry;
- idempotency key.

The user transfers the capsule and returns the response. An optional companion may assist only through documented browser extension or accessibility APIs, remain visible and user-controlled, and never replay private provider endpoints.

## Switching providers without losing work

A task belongs to the local ledger. Every provider reasoning step consumes a provider-neutral checkpoint and produces a typed result.

Switching providers:

1. closes or releases the current provider claim;
2. preserves the checkpoint and idempotency state;
3. selects an adapter with a compatible capability profile;
4. compiles a new provider-specific brief;
5. creates or maps a provider conversation only when supported;
6. continues from the local checkpoint, not from an assumed copy of another provider's raw chat.

## Availability and usage evidence

Availability is represented as a state with evidence and confidence:

- `available`;
- `degraded`;
- `temporary_capacity`;
- `rate_limited`;
- `quota_exhausted`;
- `user_action_required`;
- `offline`;
- `unknown`.

Quota is a separate append-only observation stream. Common dimensions include:

- conversational message usage;
- agentic or Work usage;
- file-upload rate;
- file-storage capacity;
- project file slots.

A quota snapshot records the account, dimension, qualitative state, observation time, evidence and optional numeric values. Numeric values require an explicit unit. Unknown quota uses `evidence=none`; exhausted quota cannot report a positive remainder.

Adapters may report only what their surface proves. They must not invent remaining quotas, project state, conversation state or completion from UI appearance. A task count is not a quota counter.

Retries are bounded, idempotent and policy-controlled. Authentication failures, quota exhaustion, policy refusals and ambiguous local-effect outcomes do not trigger an automatic retry loop. Credit purchase is always an explicit user action outside automatic provider selection.

## Provider onboarding sequence

Each new provider follows the same order:

1. create a provider-specific document under `docs/providers/`;
2. record surfaces, capability states and evidence;
3. define normalized lifecycle mappings;
4. implement a deterministic lifecycle mock adapter;
5. add a deterministic account, quota, project and conversation context fixture;
6. define Chat/agentic selection and fallback policy;
7. add a separate multimodal attachment foundation when needed;
8. perform a manual characterization run with secrets excluded from logs;
9. implement one supported real transport;
10. connect tool calls to the existing governed local execution path;
11. add provider-specific recovery and drift tests.

ChatGPT is the first provider in this sequence. See [`providers/chatgpt.md`](providers/chatgpt.md).

## Non-goals

- treating MCP as a prompt-submission API;
- treating one provider's behavior as universal;
- automating undocumented provider endpoints;
- persisting browser cookies as provider credentials;
- scraping hidden account or conversation data;
- guessing response completion from silence or animations;
- allowing a provider to change local permissions;
- bypassing provider limits, safety controls or terms;
- exposing a shell or public local MCP endpoint.
