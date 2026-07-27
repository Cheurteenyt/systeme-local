# C7 ChatGPT Work pre-live admission

Status: `COMPLETE_C7_WORK_PROFILE_READY_FOR_BOUNDED_LIVE_VALIDATION`

Reviewed at: `2026-07-27T15:42:00Z`

Revalidate after: `2026-08-10T15:42:00Z`

Issue: [#76](https://github.com/Cheurteenyt/systeme-local/issues/76)

## Purpose

C7 establishes whether the supported ChatGPT Work surface may proceed to a
separately authorized live-validation lot. It does not run that validation.

The exact Work identity is:

```text
chatgpt:work:agentic_work:custom_or_local_mcp_tool_invocation
```

The existing native Chat identity remains separate:

```text
chatgpt:chat:conversational_chat:custom_or_local_mcp_tool_invocation
```

Its result remains `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`.

## Official evidence

Only current official OpenAI sources were used.

| Source | Reviewed claim |
|---|---|
| [Get started with ChatGPT Work](https://learn.chatgpt.com/docs/get-started-with-work) | Work is a separately selected outcome-oriented surface that can use plugins and approved tools; it is not Chat. |
| [Plugins](https://learn.chatgpt.com/docs/plugins) | Plugins are available with Work on the Web, unavailable in Chat, and may add MCP tools to new chats. |
| [Model Context Protocol](https://learn.chatgpt.com/docs/extend/mcp) | Hosted Work chats use installed plugins for remote MCP-backed tools. |
| [Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt) | Connection setup registers an HTTPS `/mcp` endpoint and requires review of discovered tools and metadata. |
| [Package your plugin](https://developers.openai.com/plugins/build/plugins) | Local MCP plugin creation and testing is assigned to Work mode or Codex after developer-mode registration. |
| [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) | The Tunnel supplies transport to supported plugin setup; it does not grant a surface or tool capability. |

The canonical profile is
[`governance/c7-chatgpt-work-capability-profile.json`](../../governance/c7-chatgpt-work-capability-profile.json).
Its profile SHA-256 is
`d6cca6b29ebdc8d2cb4cccedede4faf3ac06561cfbedd8159bad025b78f61ade`.

The reviewed conclusion is intentionally narrow: the Plugin-mediated
custom/local MCP route is officially supported on ChatGPT Work on the Web.
This does not establish native Chat support, authorize a live cycle, prove a
current account entitlement or quota, or expose a local tool.

## Pre-live policy

The canonical policy is
[`governance/c7-work-prelive-policy.json`](../../governance/c7-work-prelive-policy.json).
Its SHA-256 commitment is
`74d79861fbd5cb78e729f39b3416ea856b9ec2f8de6b4650e16e28050383df77`.

It binds:

- accepted C6 `main`
  `81bed9b81f266709fab0ea4178f98f0607c3da44`;
- the exact C7 Work profile digest;
- the immutable native Chat profile and blocker;
- the C6 official-revalidation policy;
- the C4 protocol digest for `systeme_local_connectivity_probe`;
- six protected effects;
- a zero-action, zero-tool default boundary;
- the future C8 grant requirements.

## Default decision

Without a fresh future C8 authorization grant:

| Protected effect | C7 default |
|---|---|
| Runtime-key creation | denied |
| Secure MCP Tunnel startup | denied |
| Plugin creation | denied |
| browser test | denied |
| ChatGPT Work action | denied |
| tool-surface exposure | denied |

The resulting state is:

```text
official Work eligibility = supported and current
operator live-cycle authorization = absent
automatic Chat -> Work switch = false
live actions allowed = false
effective tools = 0
```

`COMPLETE_C7_WORK_PROFILE_READY_FOR_BOUNDED_LIVE_VALIDATION` means only
that a separate C8 lot may be proposed. It is not live connectivity or regular
use.

## Future C8 authorization contract

C7 defines `C8LiveCycleGrant` but provides no command that creates one. C8 must
obtain a fresh explicit authorization and authenticate it with a process-local
audit key. The receipt is valid for at most twenty minutes and exactly two new
synthetic Work chats. It must also bind an explicit Work request, a visible
Work-surface observation, an available Work entitlement and a usable Work
quota observation no older than five minutes.

It permanently excludes:

- native Chat and automatic Chat-to-Work switching;
- existing chats and history;
- private browser state;
- account or security settings;
- local file and command access;
- raw credentials and secrets;
- real operator evidence;
- protocol v2;
- write or high-risk tools.

Only the existing synthetic, idempotent, read-only connectivity probe may
become effective. A missing key, wrong HMAC, expired receipt, wrong profile,
wrong policy, modified privacy flag or surface substitution denies all effects
and exposes zero tools.

## No-live C7 boundary

C7 creates no Runtime key, Tunnel, Plugin, chat, Work thread or live provider
call. It does not open ChatGPT, control a browser, access a conversation,
inspect history, change account settings or collect private browser state.
It performs public official-document review plus deterministic local
validation only.

It also makes no claim about an exact internal model ID. A future visible model
or reasoning label remains a bounded UI observation and cannot be promoted to
an unexposed internal routing fact. An exact internal model ID is not a C8
authorization prerequisite.

## Operator commands

The scripts refuse configured transport/runtime secrets, `tunnel-client`, and
listeners on ports 8765/8766:

```powershell
.\scripts\c7\Test-C7Prerequisites.ps1
.\scripts\c7\Get-C7Status.ps1
.\scripts\c7\Show-C8Gates.ps1
```

The committed default status is deterministic and secret-free. No C7 command
accepts a Runtime key, Tunnel ID, Plugin ID, browser state or live-cycle grant.

## Completion and next gate

C7 is complete only after full repository validation and a reproducible seal.
The next permissible product lot is C8: a separately authorized, Work-only,
two-chat synthetic live test with exact positive correlation, negative tests,
revocation and irreversible cleanup.

No C8 action may begin from C7 authorization or from historical C1 receipts.
