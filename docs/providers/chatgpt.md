# ChatGPT provider characterization

Status: provider characterization plus deterministic lifecycle, context, attachment and ChatGPT MCP evidence foundations implemented; no live provider transport or connection
Last reviewed: 2026-07-18
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

## Current custom MCP deployment contract

The current official-source review is committed in
[`chatgpt-mcp-deployment.md`](chatgpt-mcp-deployment.md). Full write/modify MCP is currently a
web beta for Business and Enterprise/Edu. Pro is limited to read/fetch custom MCP in developer
mode. Unsupported or unknown plans fail closed rather than inheriting another plan's rights.

ChatGPT cannot connect directly to the loopback MCP endpoint. A private, on-premises or
developer-machine deployment requires Secure MCP Tunnel; a public remote endpoint may use a
direct remote MCP connection. This characterization does not claim that either transport is
already configured.

The user opens the intended ChatGPT conversation and selects or mentions the Système Local
app. Custom MCP does not prove account-wide chat/project enumeration or a stable visible-chat
identifier. The MCP server never receives a ChatGPT password, browser cookie or ChatGPT
session token; OAuth/OIDC authorizes access to Système Local as a separate security context.

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

## Chat, Work, projects and provider context

Last characterized: 2026-07-18.

Chat is the Système Local default. Automatic selection never upgrades a request to Work. Work requires an explicit user request, proven availability for the active account and a fresh usable `work_agentic` quota observation. The default local freshness window is five minutes. If Work support or quota is stale, unknown, unavailable, reset-pending or exhausted, the local policy falls back to Chat. Système Local never purchases provider credits automatically.

Current official documentation describes Chat as the conversational experience and Work as the longer-running research and deliverable experience. Work is rolling out to eligible paid accounts and follows the same usage structure as Codex; actual consumption varies by task. The registry therefore stores qualitative, time-stamped evidence and does not invent a numeric remainder. See [ChatGPT Work and Codex](https://help.openai.com/en/articles/20001275) and the current [ChatGPT release notes](https://help.openai.com/en/articles/6825453-chatgpt-release-notes).

Projects are available across free and paid ChatGPT plans. They group chats, files and project instructions, and can use project-only memory selected when a new project is created. Chats in a project may reference other chats in that project when the account and memory settings allow it. Current file-slot observations are volatile: only 10 files can be uploaded at once, with documented per-project limits of 5 for Free, 25 for Go/Plus and 40 for Edu/Pro/Business/Enterprise. See [Projects in ChatGPT](https://help.openai.com/en/articles/10169521-projects-in-chatgpt).

Current official documentation also permits moving an eligible existing chat into a project. The registry preserves the chat's original `created_at` and records project membership as mutable revision state; it does not require the project to predate the chat.

Project and chat enumeration remain `unknown` for a personal visible-account automation surface. The local registry may hold operator-confirmed bindings without claiming account-wide discovery. It never scrapes the sidebar, observes private DOM state, replays cookies or calls undocumented endpoints.

Chat conversations are modeled separately from Work threads. Synchronization scope is explicit because current official documentation distinguishes cloud Work threads from desktop-local Work threads and files. Temporary conversations cannot be bound to a project.

File and image limits are observations, not schema constants. Current documentation lists 512 MB per general file, 2 million tokens per text/document file, about 50 MB per spreadsheet and 20 MB per image, plus upload-rate and storage caps. See [File Uploads FAQ](https://help.openai.com/en/articles/8555545-file-uploads-faq).

The provider-neutral attachment foundation validates local bytes, commits ordered manifests, binds capability and quota evidence, plans deterministic batches and simulates ambiguous acceptance recovery. Real ChatGPT upload capability for an outbound local-agent surface remains `unknown`. No local format validator or fake receipt proves a supported ChatGPT transport. See [`../provider-attachments.md`](../provider-attachments.md).

The provider context registry stores metadata, evidence and optional stable mappings only. Local memory remains canonical if provider memory, a project or a conversation becomes unavailable.

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

Status: `implemented`

- cross-provider connectivity authority is defined;
- ChatGPT surfaces remain distinct;
- private web automation is prohibited;
- lifecycle, identity and conversation boundaries are explicit.

### Phase 1 — deterministic ChatGPT lifecycle adapter

Status: `implemented`

The implementation is deterministic, metadata-only and performs no network request. It covers
completed, failed, cancelled, incomplete and tool-call scenarios, committed-turn boundaries,
idempotency, crash recovery and exact event replay.

### Phase 2 — Chat-first context registry

Status: `implemented`

The provider-neutral registry models account availability, qualitative quota evidence, projects,
conversations and deterministic Chat/Work selection. It performs no account-wide discovery and
never purchases credits automatically.

### Phase 3 — multimodal attachment foundation

Status: `implemented`

The implemented foundation validates bounded local bytes, commits metadata-only attachments and
ordered manifests, applies provider capability and quota evidence, creates deterministic batches
and verifies simulated receipts.

Encrypted blob storage, redaction, OCR, approval, retention and verified deletion are **not**
part of this phase. They remain a separate security lot.

### Phase 4 — ChatGPT MCP deployment eligibility

Status: `implemented`

An expiring official-evidence profile commits plan, role, client, transport, authentication,
refresh-token, tool-drift and workspace boundaries. It does not install a tunnel, create
credentials or configure an app.

### Phase 5 — evidence reconciliation and connection readiness

Status: `implemented`

Current official evidence is reconciled before operator observations are accepted. Ambiguous Plus
scope fails closed. The complete eleven-check observation authorizes only bounded configure, test,
publish-review or use-review stages and never claims a live connection.

### Phase 6 — sealed operator-evidence bundle

Status: `implemented`

One short-lived record is required for every readiness check. Public models contain only typed
states, bounded counts and SHA-256 commitments. No live evidence is collected and no raw UI,
endpoint, metadata or tool content is stored.

### Phase 7 — architecture and provider-package reconciliation

Status: `in_progress`

Align repository documentation, threat model, CI, evidence expiry and GitHub governance. Measure
the current provider public surface and define a compatibility-preserving refactor boundary.

### Phase 8 — provider package compatibility refactor

Status: `planned`

Extract shared canonicalization primitives and clearer subpackages while preserving public
imports, model semantics and digest domains.

### Phase 9 — bounded local operator-evidence collection

Status: `planned`

Implement temporary raw-evidence governance, sanitization, source compatibility, hashing,
destruction or explicit retention, bundle construction and a local blocked/next-step report.

This phase still performs no tunnel installation, OAuth registration or provider call.

### Phase 10 — one supported real transport

Status: `planned`

Select exactly one documented machine surface. A real integration test is opt-in and receives
credentials only through the process environment or an approved secret store.

Inbound ChatGPT custom MCP connectivity remains a separate path from an outbound Responses API or
other provider adapter.

### Phase 11 — tool-call bridge

Status: `planned`

Normalize provider tool requests and route them through policy-derived visibility, approval,
idempotency, limits, audit correlation and secret redaction.

### Phase 12 — ChatGPT custom MCP app connection

Status: `planned`

Only after fresh evidence and operator approval, consider Secure MCP Tunnel, OAuth/OIDC, draft app
configuration, tool scan, action review, publication and access controls as separate reversible
lots.

### Phase 13 — visible web-session research

Status: `blocked_by_evidence`

Investigate only documented or explicitly supported mechanisms. If no reliable contract exists,
retain `research` or `unsupported` and use an official provider transport or interactive handoff.

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

Recheck these official sources before implementation because product availability, quotas and permissions can change:

- [ChatGPT Work and Codex](https://help.openai.com/en/articles/20001275)
- [Projects in ChatGPT](https://help.openai.com/en/articles/10169521-projects-in-chatgpt)
- [File Uploads FAQ](https://help.openai.com/en/articles/8555545-file-uploads-faq)
- [ChatGPT release notes](https://help.openai.com/en/articles/6825453-chatgpt-release-notes)
- [Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461)
- [Apps in ChatGPT](https://help.openai.com/en/articles/11487775-connectors-in)
- [OpenAI Responses API reference](https://platform.openai.com/docs/api-reference/responses)
- [OpenAI streaming events](https://platform.openai.com/docs/api-reference/responses-streaming/response/refusal/delta)
