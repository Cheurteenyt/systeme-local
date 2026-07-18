# ChatGPT MCP deployment evidence and operator contract

Status: evidence-bound deployment profile implemented; real connection not implemented

Reviewed: 2026-07-18

Revalidate no later than: 2026-08-17

## Decision

Système Local treats a ChatGPT custom MCP app as an **inbound tool channel**:

```text
user opens the intended ChatGPT conversation
    -> user selects or mentions the Système Local app
    -> ChatGPT calls an approved MCP tool
    -> remote MCP endpoint or Secure MCP Tunnel
    -> local authentication, policy, approval, execution and audit
    -> structured tool result returns to the same host conversation
```

The MCP app is not an account-wide ChatGPT automation interface. It does not log in to
ChatGPT on behalf of Système Local, scrape the sidebar, choose a personal chat from the
account, or convert an MCP session identifier into a ChatGPT conversation identifier.

## Simple operator rule

The operator chooses the conversation in ChatGPT by opening that conversation and enabling
or invoking the Système Local app there. ChatGPT may provide relevant current-conversation
context to the app when calling a tool, subject to app permissions and the tool schema.

Système Local keeps its own canonical conversation identity. A provider chat or project
mapping is recorded only when an official surface returns a stable identifier or the operator
confirms a bounded reference. Account-wide chat and project enumeration remain `unknown`.

## Current plan and role matrix

The following table is a committed interpretation of current official OpenAI documentation.
It expires after the local revalidation date and must be rebuilt when OpenAI changes plan
eligibility, roles, permissions or product labels.

| Plan | Test a custom MCP app | Write/modify tools | Publish to workspace | Use after configuration |
|---|---|---|---|---|
| Free | unsupported by this profile | unsupported | unsupported | unsupported |
| Go | unsupported by this profile | unsupported | unsupported | unsupported |
| Plus | unsupported by this profile | unsupported | unsupported | unsupported |
| Pro | read/fetch in developer mode | unsupported | unsupported | read/fetch in developer mode |
| Business | admin/owner | supported in beta | admin/owner | enabled workspace members |
| Enterprise | authorized developer, admin or owner | supported in beta | admin/owner | RBAC-authorized members |
| Edu | authorized developer, admin or owner | supported in beta | admin/owner | RBAC-authorized members |

`unsupported by this profile` means the current official custom-MCP eligibility documentation
does not authorize deployment for that plan. It does not describe unrelated apps from the
Plugins Directory.

## Client and execution surfaces

- Custom MCP apps and developer mode are currently web-only.
- Mobile custom MCP use is `unsupported` in this profile.
- Agent mode does not use custom apps.
- Deep research may use custom apps for read/fetch actions only, not write actions.
- A workspace may invoke multiple apps in one prompt when the workspace and apps permit it.
- Search and fetch tools are not mandatory for every connected MCP server.

## Server location

ChatGPT does not connect directly to a loopback MCP endpoint.

| MCP server location | Required transport |
|---|---|
| Public remote server | direct remote MCP connection |
| Private network | Secure MCP Tunnel |
| On-premises server | Secure MCP Tunnel |
| Developer machine | Secure MCP Tunnel |
| Unknown location | refuse deployment |

This profile records that Secure MCP Tunnel is the documented connection class for private
or local servers. It does **not** claim that the tunnel is installed, authenticated or
operational in Système Local.

## Authentication

ChatGPT app authentication and ChatGPT account authentication are separate security contexts.

- The user signs in to ChatGPT normally to use ChatGPT.
- The MCP app may use OAuth or OpenID Connect to authorize access to Système Local.
- Système Local never receives or replays the user's ChatGPT password, browser cookies or
  ChatGPT session tokens.
- Persistent OAuth connectivity requires refresh-token issuance; for OIDC this commonly
  requires `offline_access` to be advertised and granted.
- Local policy requires authenticated access before a published or regularly used deployment
  is approved.
- A no-auth configuration is allowed only for a bounded pre-publication test and does not
  authorize production use.

## Chat and project capabilities

| Capability | State | Meaning |
|---|---|---|
| Select the app in the current chat | supported | the user opens the intended chat and invokes the app |
| Use project context inside ChatGPT | supported by ChatGPT projects | this does not grant MCP account discovery |
| Enumerate all personal chats through custom MCP | unknown | no official contract is assumed |
| Enumerate all projects through custom MCP | unknown | no official contract is assumed |
| Treat an MCP session as a ChatGPT chat ID | unsupported locally | transport state is not conversation identity |
| Guess a chat/project ID from a URL, label or model output | forbidden | no guessed identity enters the registry |

There is no automatic “choose the right ChatGPT chat” operation in this lot. The operator
opens the desired chat. Système Local can then bind its local conversation to that
operator-confirmed context without claiming account-wide discovery.

## Runtime gates

A plan or role being eligible does not make a deployment operational. The deterministic
request also records whether:

- developer mode is actually enabled when required;
- the app is configured before an ordinary use request;
- a managed-workspace member has been granted access to the published app;
- persistent OAuth/OIDC connectivity can issue refresh tokens.

Missing runtime gates fail closed with typed reasons. An allowed decision means the proposed
configuration is eligible under the committed profile; it does not claim that a tunnel,
OAuth client or live ChatGPT connection has already been installed.

## Tool and permission drift

Published MCP tool definitions are treated as a reviewed snapshot:

- server-side tool changes are not trusted automatically;
- new or changed actions require an explicit refresh and review;
- write actions may require confirmation depending on permissions and context;
- some especially risky actions may be blocked instead of being offered for approval;
- a permissive ChatGPT confirmation setting never bypasses Système Local policy, approval
  or audit.

## Evidence-bound profile

`ChatGptMcpCapabilityProfile` commits:

```text
reviewed_at
revalidate_after
official source references
source statement digests
complete capability matrix
complete plan × phase × access entitlement matrix
profile SHA-256
```

The entitlement matrix contains every combination of the seven known plans, three deployment
phases and two access modes. Unknown plans are not silently mapped to a paid plan.

`McpDeploymentRequest` records the observed plan, workspace role, client, deployment phase,
access mode, server location, authentication mode, refresh-token capability, runtime gates
and any requested discovery or agent-mode dependencies.

`McpDeploymentDecision` is deterministic and binds the profile digest. It always records that:

- the operator selects the app in the current chat;
- automatic chat enumeration is false;
- automatic project enumeration is false;
- ChatGPT account credentials are not used by the MCP server.

Expired evidence, unknown plan/role/client/location, unsupported access, missing authorization,
absent refresh tokens, required chat/project enumeration, agent mode and deep-research writes
all fail closed with typed reasons.

## Conflict-aware connection-readiness handoff

The next layer is implemented in
[`chatgpt-mcp-connection-readiness.md`](chatgpt-mcp-connection-readiness.md). It reconciles
current official sources before accepting operator evidence. The general Apps plan matrix now
lists Custom (MCP) for Plus, while the dedicated developer-mode article does not document a
Plus deployment path. Système Local records that scope as ambiguous and
fails closed on that ambiguity. The rule is explicit: never treat a
general availability mark as deployment authorization.

The readiness layer commits all required checks exactly once, binds tool and local-policy
digests, refuses write tools in a read/fetch snapshot, and requires a separate review for
high-risk tools. Its stages authorize only the next bounded operator step and always record
`real_connection_established=false` and `secrets_stored=false`.

## Deployment sequence after this lot

A real connection may begin only after the operator supplies and verifies:

1. the actual ChatGPT plan;
2. the workspace role;
3. the intended read/fetch or write/modify access;
4. the web client and workspace controls;
5. a supported remote endpoint or Secure MCP Tunnel installation path;
6. an OAuth/OIDC issuer controlled for Système Local;
7. refresh-token behavior for persistent access;
8. the exact published tool snapshot and action controls.

The real-connection lot must repeat the official-source review before enabling any tool.

## Non-goals

- installing or starting Secure MCP Tunnel;
- creating OAuth clients or storing tokens;
- connecting ChatGPT to the local runtime;
- listing ChatGPT chats or projects;
- selecting a chat automatically;
- creating or moving ChatGPT conversations;
- enabling write tools;
- uploading attachments to ChatGPT;
- using the ChatGPT login as MCP authentication;
- browser automation, cookies, private endpoints or DOM scraping.

## Official sources

- [Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461)
- [Apps in ChatGPT](https://help.openai.com/en/articles/11487775-apps-in-chatgpt)
- [Projects in ChatGPT](https://help.openai.com/en/articles/10169521-projects-in-chatgpt)
