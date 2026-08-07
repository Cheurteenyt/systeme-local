# ChatGPT provider characterization

Status: deterministic lifecycle, context, attachment and ChatGPT MCP evidence
foundations implemented; C8 Work connectivity completed and revoked; C9
Work-rich/Chat-manual attachment handoff validated offline, with all live
proofs pending
Last reviewed: 2026-07-28
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
| ChatGPT Work Plugin/MCP | ChatGPT → local tools | C8 proved two bounded probe calls and revoked the connection; C9 rich attachment delivery is offline-implemented and live-pending | Work can call only the locally admitted Plugin/MCP capability for the active grant |
| normal Chat Plugin/MCP | ChatGPT → local tools | Blocked by the current official rule that Plugins are unavailable in Chat | No normal-Chat local-app claim is permitted |
| normal Chat manual attachment handoff | user → ChatGPT Chat | Bounded private export, proof and attestation path verified offline; live proof pending | A correlated visible response may prove consumption of the exact operator-attached package, never a local app call |
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

Last characterized: 2026-07-26.

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

Status: `implemented`

Pull request #40 merged as `c720f4ae9d295e3e2af6993b40a0b03bfd14c2b9`. It reconciled
repository documentation, threat modeling, CI, evidence expiry, dependency reproducibility and
GitHub governance, then measured the provider public surface and fixed the compatibility boundary.
It added no capability and performed no provider connection.

### Phase 8 — private provider canonicalization compatibility refactor

Status: `implemented`

Pull request #42 merged as `1c84538369eb662b61cc4f56a79131569b9ca200`. One private
provider-neutral module now owns canonical JSON, aware-datetime UTC normalization and sorted-unique
validation. Deterministic oracles preserve all 179 ordered public exports, 18 affected Pydantic
contracts, 22 enums and 13 digest domains. The provider Mypy baseline is zero diagnostics and the
Ruff formatting baseline is 54 files.

This phase did not split the public façade or move public classes and functions. A future
provider-neutral versus ChatGPT-specific public package reorganization remains a separate planned
compatibility and versioning decision.

### Phase 9 — bounded local operator-evidence collection

Status: `planned`

This is the next product implementation phase. Implement temporary raw-evidence governance,
sanitization, source compatibility, hashing, destruction or explicit retention, bundle construction
and a local blocked/next-step report for exactly the eleven required observations.

This phase still performs no tunnel installation, OAuth registration, app configuration or provider
call.

<!-- systeme-local:b2-0-orchestration-contract -->
#### B2.0 contract boundary

B2.0 freezes the local protocol, inherited-handle, recovery and eleven-check compatibility design.
It keeps Phase 9 `planned`: no real evidence, tunnel, OAuth registration, app configuration or
provider call is enabled by the design lot.

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

### Phase 14 — provider capability evidence lifecycle

Status: `implemented`

C3 separates official-document acquisition from deterministic capability
decisions. A strict registry contains the only active provider adapter
(`chatgpt`), native Chat identity, official-domain allowlist, reviewed profile
digest, and five protected actions. Candidate profiles cannot authorize any
action. `revalidation_due`, `expired`, `source_drift`, and `invalid` all fail
closed independently of the support state.

The C3 evidence snapshot recorded at that phase classified custom/local MCP on
native Chat as `unsupported`. That historical decision remains reproducible
for C3 but must not be reported as the current product state without a new
review. The detailed historical contract is in
[`chatgpt-web-c3-evidence-lifecycle.md`](chatgpt-web-c3-evidence-lifecycle.md).

### Phase 15 — provider-bound runtime admission

Status: `implemented`

C4 consumes the reviewed C3 result and derives one immutable runtime admission
decision plus an effective tool tuple. The production adapter contains only
ChatGPT and at most the exact read-only connectivity probe. The current
unsupported native Chat profile reduces that maximum grant to zero tools and
denies all six runtime actions.

C4 adds request/receipt commitments, exact provider and tool identity, bounded
process-local replay/collision rejection, an inner Python provider-mode gate,
and a provider-bound MCP registry constructor with one-time controller-issued
authority. It does not change the official capability result or authorize a
live test. See
[`chatgpt-web-c4-runtime-admission.md`](chatgpt-web-c4-runtime-admission.md).

### Phase 16 — official capability revalidation

Status: `implemented`

C6 automates bounded retrieval of the four reviewed official documentation
sections through the public read-only OpenAI Docs MCP endpoint. Strict models
bind the exact ChatGPT native Chat identity, C3 registry/profile digests,
routes, anchors, normalized byte counts, fingerprints, semantic markers, and
review dates.

The first public acquisition found all four then-reviewed sections unchanged.
It created only a review candidate and did not modify C3. At that C6 snapshot,
ChatGPT Chat therefore remained
`BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`; C4 denied all six actions and
exposed zero tools. This is historical C6 evidence, not a current C9
availability observation.

Drift, network/protocol failure, due or expired evidence, policy substitution,
or output-path escape all fail closed. No raw document body is persisted and
no Runtime key, Tunnel, Plugin, browser session, chat, Work surface, history,
conversation, or account setting is used. See
[`chatgpt-web-c6-official-revalidation.md`](chatgpt-web-c6-official-revalidation.md).

### Phase 17 — ChatGPT Work pre-live admission

Status: `COMPLETE_C7_WORK_PROFILE_READY_FOR_BOUNDED_LIVE_VALIDATION`;
accepted on `main` with its annotated evidence seal and green remote CI.

C7 models Work independently as
`chatgpt:work:agentic_work:custom_or_local_mcp_tool_invocation`. Six reviewed
official sources support the Plugin-mediated MCP route on Work. The existing
native Chat profile remains unsupported and no Work evidence can satisfy it.

The C7 default decision denies all six protected effects and exposes zero
tools. It requires a fresh C8 operator grant, authenticated by a
process-local audit key and bound to a Work-only, two-new-chat, twenty-minute
maximum cycle with fresh surface, entitlement and usable-quota observations.
C7 itself creates no grant and performs no ChatGPT, browser,
credential, Tunnel, Plugin or provider action. See
[`chatgpt-web-c7-work-prelive-admission.md`](chatgpt-web-c7-work-prelive-admission.md).

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
- [Connect from ChatGPT](https://developers.openai.com/plugins/deploy/connect-chatgpt)
- [Secure MCP Tunnels](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [Plugin authentication](https://developers.openai.com/plugins/build/auth)
- [Plugin reference](https://developers.openai.com/plugins/reference)
- [ChatGPT Plugins](https://learn.chatgpt.com/docs/plugins)
- [Model Context Protocol](https://learn.chatgpt.com/docs/extend/mcp)

## C0 connectivity exception

The bounded [C0 connectivity contract](chatgpt-mcp-c0-connectivity.md) permits a
manual draft ChatGPT Web Plugin to call exactly one synthetic read-only MCP tool
through Secure MCP Tunnel. It is an inbound connectivity test, not an outbound
provider transport, chat automation, publication, or B2 evidence collection.
No live claim exists until the separate attestation proves the call, audit
correlation, and revocation failure.

C0 formats only its touched Python surface, reducing the current Ruff formatting
baseline from 54 to 42 files while leaving the historical phase-8 measurement
unchanged.

## C1 through C8 interpretation

Historical C1 receipts proved short-lived correlation between two manually
created synthetic test chats, the single read-only probe, and local audit
records. They did not prove current official native Chat support, a durable
final attestation, conversation discovery, production use, or write
capability.

C2 identified the product-surface blocker in its reviewed snapshot. C3 owns the deterministic
evidence lifecycle. C4 owns runtime admission. C5 preserved the reviewed stack
through squash integration. C6 now retrieves bounded official sources and
prepares review-only candidates without promotion. Those historical decisions deny
Runtime-key creation, Tunnel startup, Plugin creation, browser testing, and
any ChatGPT action or tool-surface exposure. The historical C1 records remain
evidence of bounded calls, not authority to bypass current official
documentation or C4 admission.

C7 adds a separate Work eligibility and pre-live policy overlay. It does not
change native Chat or repeat C1. Its successful status authorized only the
design of the separately approved C8 validation.

### Phase 18 — bounded ChatGPT Work live validation

Status: `COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED`

C8 consumed the accepted C7 Work profile only through a fresh, revocable
operator grant. The grant is bound to visible Work, available entitlement,
usable quota, two new synthetic tasks, one read-only tool and a twenty-minute
maximum. `chatgpt_work_c8` is enforced during Python runtime construction;
PowerShell cannot independently authorize the tool surface.

The completed cycle produced two distinct Work correlations, rejected same-
and cross-Work replay, rejected malformed schema inputs, exposed no additional
capability, stopped both listeners, removed the Plugin connection, revoked the
Runtime key, cleared process secrets and proved post-revocation
unreachability.

The exact verified historical success value is
`COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED`.
Its C8-native-Chat field stays
`BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`; C9 does not rewrite that sealed
receipt and instead performs a fresh current-product test. Optional visible
labels never prove an internal model ID, and a bounded success never claims
regular-use readiness. See
[`chatgpt-web-c8-work-live-validation.md`](chatgpt-web-c8-work-live-validation.md).

### Phase 19 — bounded image and document handoff

Status: `partial` — security, Work rich-content, private-export and asymmetric
closeout paths passed consolidated offline validation; all three live proofs
are pending.

C9 is tracked by issue
[#80](https://github.com/Cheurteenyt/systeme-local/issues/80) and descends from
the immutable C8 evidence tag target
`bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5`. It verifies the accepted C8
transport evidence without reusing its completed live grant.

The exact live package is one generated synthetic PNG image plus one generated UTF-8
text document. Each contains an independent random nonce. Explicit selection,
sanitization and the existing canonical `AttachmentManifest` occur locally
before a literal-loopback local AI reads the exact sanitized bytes. A fresh
HMAC-bound observation commits the operator-declared native runtime, product,
PID and privacy settings, the inspected executable digest and exact
endpoint/model hashes. Its schema explicitly says that process identity and
privacy settings are operator-attested rather than automatically verified.
The local AI must reproduce both nonce commitments before either Web surface
can be approved.

The C9 adapter's `adapter_persistent_storage_used=false` describes only the
adapter. Whether the local runtime logs or persists requests is a separate
operator confirmation. An HTTP response alone cannot complete the evidence
chain, but the signed observation does not independently prove a manual
declaration.

The qualifying Work delivery uses one reviewed read-only capability:
`systeme_local_attachment_handoff(surface="work")`. After metadata-only local
audit, its result expands into MCP `ImageContent` plus a text
`EmbeddedResource`. Official schemas permit content arrays, but Work's
interpretation of these exact blocks remains live-pending.

Current official [plugin connection
guidance](https://developers.openai.com/plugins/deploy/connect-chatgpt)
must be read together with the current
[Plugins](https://learn.chatgpt.com/docs/plugins) rule that Plugins are not
available in Chat. C9 therefore never attempts or claims a normal-Chat
Plugin/MCP call.

After Work, the private short-lived export materializes the same sanitized
package for one operator-performed file-picker handoff in one new normal Chat
conversation. That proof may establish only visible manual transfer and
two-nonce consumption. It cannot establish an app, MCP tool, local endpoint,
same internal app ID or autonomous delivery. C9 uses no DOM/private API and
forbids automatic Chat-to-Work switching.

The live limit is one new synthetic Work task followed by one new synthetic
normal Chat conversation, using only the generated PNG + TXT fixture. Both
primary counters are currently `0/1`; installed local-runtime inference is
also unexecuted. A completion claim requires one Work rich receipt and one
normal-Chat manual-handoff receipt over equal package commitments, followed
by authority cleanup, listener shutdown, Work Plugin removal, operator
Runtime-key revocation and Work/control post-revocation unreachability.

Real ChatGPT upload capability for an outbound local-agent surface remains
`unknown`. The manual Chat handoff is operator-assisted, not an autonomous
outbound provider adapter; neither C9 path proves regular-use readiness.

See
[`chatgpt-web-c9-attachment-handoff.md`](chatgpt-web-c9-attachment-handoff.md)
and
[`chatgpt-web-c9-test-evidence.md`](chatgpt-web-c9-test-evidence.md).
