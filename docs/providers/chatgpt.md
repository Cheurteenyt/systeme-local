# ChatGPT provider characterization

Status: architecture and capability characterization
Last reviewed: 2026-07-17
Cross-provider rules: [`../connectivity-model.md`](../connectivity-model.md)

## Purpose

This document defines the ChatGPT-specific surfaces that Système Local may integrate. It does not define common provider behavior, and it does not claim that capabilities available through one OpenAI product surface are available through another.

The first implementation must be selected only after the relevant ChatGPT surface has been characterized with current official documentation and controlled observations.

## Current ChatGPT product terminology

As of 2026-07-09, OpenAI moved ChatGPT discovery from the app directory to the plugin directory. A plugin can contain skills, apps and app templates. The underlying app remains the integration that connects ChatGPT or Codex to external data and actions.

This document therefore uses:

- **plugin** for the current ChatGPT discovery and installation wrapper;
- **app** for the underlying ChatGPT integration, including an MCP-backed custom app;
- **MCP server** for the protocol endpoint exposed by Système Local;
- **provider adapter** for a separate outbound machine-to-machine transport.

Current UI labels, eligible plans, workspace permissions and publication steps are time-sensitive. They must be rechecked against [Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461) and [Apps in ChatGPT](https://help.openai.com/en/articles/11487775-connectors-in-chatgpt) before implementation or operator documentation is published.

## Surfaces

| Surface | Direction | Current project status | What it proves |
|---|---|---|---|
| ChatGPT custom MCP app | ChatGPT → local tools | Local loopback runtime and official-client smoke are implemented; remote ChatGPT connection is not implemented | ChatGPT can call approved MCP tools when an app is configured |
| OpenAI Responses API | local agent → OpenAI model | Not implemented; optional provider transport | Documented machine-to-machine turns, events, conversations and tools |
| Visible ChatGPT web conversation initiated by the local agent | local agent → chatgpt.com chat | Research only; no supported contract is assumed | Nothing until a documented or explicitly supported mechanism is identified |
| Interactive handoff | user ↔ ChatGPT web | Architecturally supported, not automated | A visible user can transfer a signed capsule |

These surfaces must not share credentials implicitly. A ChatGPT login session, an OpenAI API credential and an MCP app authentication mechanism are separate security contexts.

## Existing MCP work is retained

The merged MCP foundation is not discarded. It provides the governed local tool plane that a ChatGPT integration can reuse:

- loopback-only Streamable HTTP endpoint;
- independent bearer token;
- `Host` and `Origin` checks;
- request-size, rate and concurrency limits;
- policy-derived tool visibility;
- signed conversion into the existing task processor;
- approval and deny-by-default behavior;
- chained local audit;
- official MCP client smoke command;
- real out-of-process Uvicorn integration test.

This channel answers: “How can ChatGPT or another MCP host call safe local tools?”

It does not answer: “How can a local agent initiate or manage a ChatGPT conversation?” That requires a separate ChatGPT provider adapter or a separately characterized web-session bridge.

## Initial capability profile

The following profile distinguishes documented capability from unknown visible-web behavior.

```yaml
provider: chatgpt
profile_version: 1
surfaces:
  custom_mcp_app:
    direction: inbound
    status: documented
    local_runtime_status: implemented
    remote_connection_status: not_implemented
  openai_responses_api:
    direction: outbound
    status: documented
    project_status: not_implemented
  visible_chatgpt_web_session:
    direction: outbound
    status: research
    project_status: not_implemented
capabilities:
  web_host_can_call_local_mcp_tools:
    custom_mcp_app: true
  local_agent_can_initiate_machine_turn:
    openai_responses_api: true
    visible_chatgpt_web_session: unknown
  local_agent_can_create_visible_chat:
    visible_chatgpt_web_session: unknown
  can_enumerate_visible_chats:
    visible_chatgpt_web_session: unknown
  exposes_stable_visible_chat_id:
    visible_chatgpt_web_session: unknown
  exposes_terminal_response_event:
    openai_responses_api: true
    visible_chatgpt_web_session: unknown
  supports_streaming:
    openai_responses_api: true
    visible_chatgpt_web_session: unknown
  supports_tool_calls:
    custom_mcp_app: true
    openai_responses_api: true
    visible_chatgpt_web_session: unknown
  supports_cancellation:
    openai_responses_api: documented
    visible_chatgpt_web_session: unknown
  supports_resume_after_process_crash:
    project_orchestrator: required
    visible_chatgpt_web_session: unknown
```

The profile must be revised when evidence changes. “Unknown” is an intentional safe state.

## Identity of the local AI

ChatGPT must not be asked to authenticate the local AI from prose alone.

Before submission, Système Local verifies a signed local principal and committed turn containing:

```text
agent_id
instance_id
key_id
conversation_id
turn_id
created_at
expires_at
nonce
content_sha256
signature
```

After verification, the provider adapter may add a descriptive statement that the content came from an authenticated local agent. That statement helps the model interpret roles, but local cryptographic verification remains the authority.

A model response saying “I recognize the local AI” is not security evidence.

## Input turn boundary

The local AI finishes a prompt through an explicit commit event:

```text
local_turn.started
local_turn.content.delta
local_turn.committed
```

`local_turn.committed` includes the final content hash, part count and byte count. No provider submission occurs before this event.

The following are not valid completion signals:

- silence;
- punctuation;
- a delay;
- a UI animation;
- a text marker such as `FIN`;
- temporary loss of connectivity.

## Provider response boundary

For a documented machine transport, the adapter maps provider events to:

```text
provider_response.started
provider_response.output.delta
provider_tool_call.requested
provider_response.terminal
```

The terminal event records one of:

```text
completed
failed
cancelled
incomplete
```

A provider response reaching `completed` does not necessarily finish the delegation. A tool call, approval, verification step or follow-up provider turn may remain pending.

The final local condition is:

```text
terminal provider response
+ no pending tool call
+ no pending approval
+ output validation passed
+ audit persisted
= delegation.completed
```

For the visible ChatGPT web surface, no terminal signal is assumed until a supported mechanism is characterized.

## Conversation registry

Système Local owns the canonical conversation record:

```json
{
  "conversation_id": "slconv_...",
  "provider": "chatgpt",
  "surface": "custom_mcp_app | openai_responses_api | visible_web_session",
  "provider_conversation_id": null,
  "last_provider_run_id": null,
  "state": "active",
  "created_by_agent": "local-agent-main"
}
```

Creating a new ChatGPT sidebar chat, detecting that one was opened, enumerating existing chats and observing a stable web chat identifier are separate capabilities. They must not be inferred from an MCP session or browser tab.

The current MCP runtime uses a generic transport session label. That label is sufficient for the present stateless tool façade and is not a ChatGPT conversation identifier.

## Characterization questions

Before any visible-web adapter is coded, a controlled study must answer:

### Connection and authentication

- Which current ChatGPT plan and workspace controls are required?
- Is the surface documented and supported for automated initiation?
- Which credential belongs to which surface?
- How is logout, expiry or reauthentication reported?
- Can connectivity be revoked immediately?

### Local-agent initiation

- Can a local process submit a complete prompt through a supported mechanism?
- Can the user keep the interaction visible and interruptible?
- Can the source agent identity be attached without pretending that prompt text is authentication?
- What is the maximum safe prompt and attachment size?

### Conversations

- Can a new conversation be created explicitly?
- Can an existing conversation be selected without scraping the sidebar?
- Is a stable conversation identifier exposed?
- Can two conversations be active concurrently?
- What happens after refresh, reconnect or provider-side archival?

### Completion

- What event proves that prompt submission finished?
- What event proves that response generation reached a terminal state?
- How are tool calls, refusals, moderation blocks and partial responses represented?
- How is a human interruption distinguished from a network failure?
- Can cancellation and resume be performed without duplicating a local effect?

### Reliability

- How are retries made idempotent?
- What happens when the local process crashes after a provider accepted the prompt?
- What happens when a local tool executed but its result was not acknowledged?
- Which evidence survives reconnect?
- How is provider drift detected?

Answers must cite current official documentation or be labeled as controlled observations with date, environment and reproducible steps.

## Implementation phases

### Phase 0 — documentation and invariants

- maintain this capability profile;
- preserve the existing MCP tool channel;
- define normalized local lifecycle events;
- define provider-neutral conversation identifiers;
- prohibit undocumented web automation in production code.

### Phase 1 — deterministic ChatGPT mock adapter

- simulate successful, failed, cancelled and incomplete responses;
- simulate one or more tool calls;
- test committed-turn boundaries;
- test crash recovery and idempotency;
- test separate new-conversation and continue-conversation operations;
- emit verifiable delegation receipts.

No network credential is required for this phase.

### Phase 2 — one supported outbound surface

Select exactly one documented ChatGPT/OpenAI machine surface. Implement it behind the provider interface without changing the local task and policy semantics.

A real integration test is opt-in and receives credentials only through the process environment.

### Phase 3 — tool-call bridge

Normalize provider tool requests and route them through the existing governed local capability path. The bridge must preserve:

- policy-derived visibility;
- approval requirements;
- idempotency;
- request and output limits;
- audit correlation;
- secret redaction.

### Phase 4 — ChatGPT custom MCP app

Connect the existing MCP façade to ChatGPT through the currently supported app and tunnel mechanism. This is the inbound direction and remains independent from the outbound provider adapter.

### Phase 5 — visible web-session research

Investigate only documented or explicitly supported mechanisms. If no reliable contract exists, retain `research` or `unsupported` and use an official provider transport or interactive handoff.

## Security invariants

- never store a ChatGPT password, session cookie, bearer token or API key in the repository;
- never log authorization headers or raw credentials;
- never reverse engineer or replay private ChatGPT endpoints;
- never treat DOM text, UI animation or silence as authenticated protocol state;
- never infer identity from prompt text;
- never let the provider expand local capabilities;
- never expose the loopback MCP endpoint directly to the public internet;
- never repeat a local effect after an ambiguous provider failure without verified idempotency state.

## Evidence sources

Recheck these official sources before implementation because product availability and permissions can change:

- [Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461)
- [Apps in ChatGPT](https://help.openai.com/en/articles/11487775-connectors-in)
- [OpenAI Responses API reference](https://platform.openai.com/docs/api-reference/responses)
- [OpenAI streaming events](https://platform.openai.com/docs/api-reference/responses-streaming/response/refusal/delta)
