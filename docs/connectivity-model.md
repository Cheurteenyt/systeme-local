# Connectivity model — manual web prompts, MCP and provider APIs

## Decision

Système Local supports three distinct connectivity modes. They share the same
provider-neutral task ledger, but they must never be confused in code or in the
user interface.

| Mode | Who starts the exchange? | Fully automatic? | Requires provider API? |
|---|---|---:|---:|
| Inbound MCP client | The web agent calls Système Local | During an open agent session | No |
| Outbound official API | Système Local calls the model | Yes | Yes |
| Interactive handoff | The user or an approved companion transfers a capsule | No | No |

A prompt typed manually into a provider website is not a call to the provider's
public developer API. The browser still communicates with the provider's own
backend, but those internal endpoints are private implementation details. They
are not a stable or supported integration contract and Système Local must not
reverse engineer or automate them.

## Priority path: the web agent drives through MCP

This is the preferred flow for a web product that can connect to a remote MCP
server:

```text
User types a prompt into GLM/web agent
              │
              ▼
The provider's agent reasons in its normal web session
              │ MCP tool call
              ▼
Public MCP Edge (authenticated, no execution authority)
              │ encrypted task delivery / outbound local connection
              ▼
Local Control Plane
              │ policy + approval + sandbox
              ▼
Local worker executes and emits structured observations
              │
              └──────── MCP result ───────► web agent continues reasoning
```

In this mode:

- the user keeps the web subscription and its interface;
- Système Local does not submit the original prompt to a model API;
- the provider remains the MCP client and initiates every model turn;
- the local node can return tool results, progress and artifacts;
- the local node cannot force the web model to answer when no session is active;
- exact web quota information is generally unavailable unless the host exposes it.

## Autonomous routing requires an official API

The Brain Router can choose a provider and call it without the user only when a
supported machine-to-machine contract exists. That normally means an official
API with documented authentication, request schemas, errors and rate limits.

```text
Task Ledger -> Context Compiler -> Brain Router -> Official Provider API
```

Only profiles with `transport=official_api` are eligible for autonomous outbound
selection. An MCP client is never silently treated as an API provider.

## Interactive handoff for closed web interfaces

When an interface has neither an API usable by the project nor an MCP client,
Système Local creates a signed `TaskCapsule` containing:

- the provider-neutral checkpoint;
- a minimal prompt brief;
- references to exportable artifacts;
- the expected structured response schema;
- an expiry and an idempotency key.

The user pastes the capsule into the web interface and returns the response. An
optional browser companion may assist with copying and validating the response,
but it must remain visible, user-controlled and limited to supported browser
extension APIs. It must not replay private web endpoints or bypass service
restrictions.

## Switching web brains without losing the task

A task belongs to the Task Ledger, not to a provider conversation. Every remote
reasoning step consumes a provider-neutral `Checkpoint` and produces a typed
result.

For inbound MCP clients, switching is intentionally simple:

1. the current agent releases or loses its short task claim;
2. the checkpoint remains in the local ledger;
3. the user opens another compatible web agent connected to the same MCP edge;
4. the new agent calls `task.list_pending` and `task.claim`;
5. it receives a newly compiled brief, not the previous provider's raw chat.

Claims are leases with expiration. Responses include the task ID, step ID,
checkpoint hash and idempotency key, preventing duplicate local effects.

## Availability and usage limits

Availability is represented as a state with evidence and confidence:

- `available`
- `degraded`
- `temporary_capacity`
- `rate_limited`
- `quota_exhausted`
- `user_action_required`
- `offline`
- `unknown`

For official APIs, adapters may use documented status codes, error bodies,
`Retry-After` and quota endpoints. For web sessions, Système Local should only
report observations it can actually prove, such as a disconnected MCP session,
a task-claim timeout or a provider error explicitly relayed by the host. It must
not invent a remaining request count.

Retries are bounded, idempotent and policy-controlled. A temporary failure may
be retried with backoff and jitter. A quota exhaustion, authentication failure
or policy refusal does not trigger an automatic retry loop.

## Installation experience

The desired user journey is:

1. install the local node;
2. pair the node with a Système Local MCP Edge or a self-hosted edge;
3. copy one authenticated MCP URL into the chosen web agent;
4. approve which workspaces and capabilities that agent may see;
5. type normal prompts in the web agent.

The MCP URL exposes only capabilities that are currently authorized. The public
edge never obtains direct host execution authority; the local node keeps an
outbound connection and independently validates every task.

## Non-goals

- automating undocumented provider web endpoints;
- bypassing account limits, risk controls or provider policies;
- claiming that a closed text-only UI can be switched automatically;
- using browser cookies as durable provider credentials;
- allowing a remote model to change its own permissions.
