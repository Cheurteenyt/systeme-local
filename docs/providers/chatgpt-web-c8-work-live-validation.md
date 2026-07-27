# C8 ChatGPT Work bounded live validation

Status: implementation and pre-live validation in progress

Issue: [#78](https://github.com/Cheurteenyt/systeme-local/issues/78)

Accepted C7 base:
`e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f`

## Exact claim

C8 may establish only this statement:

> During one explicitly authorized and revoked cycle, exactly two newly
> created synthetic ChatGPT Work tasks each invoked the one reviewed
> read-only MCP connectivity probe and each invocation matched one local audit
> record.

Until the two correlations and final revocation receipt exist, that statement
is not true. Even after success it does not establish native Chat support,
history access, existing-conversation discovery, writes, regular-use
readiness, production readiness or a particular internal model.

The exact identity is:

```text
chatgpt:work:agentic_work:custom_or_local_mcp_tool_invocation
```

Native Chat remains:

```text
BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE
```

No automatic Chat-to-Work switch is permitted.

## Current official evidence

C8 revalidated the current official route at
`2026-07-27T17:33:00Z`, with revalidation due by
`2026-08-10T17:33:00Z`.

| Official source | Result used by C8 |
|---|---|
| [Plugins](https://learn.chatgpt.com/docs/plugins) | Plugins are available with Work on the Web, unavailable in Chat/IDE/mobile, and can add MCP tools to new chats. |
| [Model Context Protocol](https://learn.chatgpt.com/docs/extend/mcp) | The fetched guide now directly confirms that ChatGPT web can use remote MCP-backed tools supplied by Plugins; the Plugins page supplies the Work-only boundary. |
| [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) | ChatGPT Plugins can select a workspace-associated Tunnel; the operator needs Tunnel Read and Use permissions. |
| [Apps and connectors](https://learn.chatgpt.com/docs/enterprise/apps-and-connectors) | The official enterprise route independently corroborates Work-on-Web and non-Chat availability. |
| [Enterprise admin setup](https://learn.chatgpt.com/docs/enterprise/admin-setup) | Least-access and non-sensitive validation remain the correct setup boundary. |
| [Work admin FAQ](https://learn.chatgpt.com/docs/enterprise/work-admin-faq) | Work, Chat and connected workflow runtime boundaries are separate. |
| [ChatGPT Work](https://chatgpt.com/fr-FR/work/) | The visible official product page says desktop access is available while web/mobile rollout is progressive for Plus, Pro, Business, Enterprise and Edu; this cannot prove account-specific web access. |

The machine-readable receipt is
[`governance/c8-official-work-revalidation.json`](../../governance/c8-official-work-revalidation.json).
The earlier fetched-body inconsistency is now resolved and recorded as such.
The Work conclusion still requires multiple independent official pages, and
the progressive rollout means current account access cannot be inferred.

Official documentation does not prove the current account's Work entitlement
or usable quota. Those facts require visible observations no older than five
minutes.

## Authorization and privacy boundary

One durable operator authorization covers the C8 goal until success, explicit
stop or goal termination. The versioned repository stores only the canonical
scope and its digest. The ignored local receipt stores:

- a random cycle identifier;
- the exact immutable allow/deny flags;
- authorization and expiry timestamps;
- an HMAC under a process-local audit key.

The scope permits:

- visible Plugins and explicitly selected Work controls;
- at most two new synthetic Work tasks;
- temporary Tunnel/MCP and Plugin connection setup;
- operator-managed Runtime key creation and revocation.

It forbids:

- native Chat or an automatic surface switch;
- history, sidebar navigation and existing conversations;
- account or security settings;
- cookies, local storage, private requests or other browser state;
- local files, commands, writes, secrets or real evidence;
- protocol v2 and every tool except the C0 probe.

## Admission and runtime enforcement

The canonical policy is
[`governance/c8-live-work-policy.json`](../../governance/c8-live-work-policy.json).
The default state is zero live effects and zero effective tools.

`chatgpt_work_c8` startup requires:

1. exact accepted C7 ancestry and a clean C8 branch;
2. current committed C7 and C8 governance;
3. active HMAC-authenticated operator authorization;
4. visible explicit Work plus available entitlement;
5. visible usable quota;
6. both UI observations no older than five minutes;
7. one grant no longer than twenty minutes;
8. exact profile, policy, observation and tool-protocol digests;
9. one ignored live-cycle file below `.systeme-local/c8`;
10. `systeme_local_connectivity_probe` as the only effective tool.

The server remains on `127.0.0.1:8765`. Tunnel health remains on
`127.0.0.1:8766`. Raw HTTP logging and remote UI are disabled. Request size,
rate and concurrency remain bounded.

## Positive proof protocol

For Work A and Work B separately:

1. explicitly select Work and create a new synthetic task;
2. select the reviewed Plugin without opening history;
3. commit a task-surface observation before the prompt;
4. generate a unique `c0_[0-9a-f]{32}` challenge;
5. invoke only `systeme_local_connectivity_probe`;
6. retain only the small structured response;
7. verify response, build, policy and tool-snapshot digests;
8. find exactly one matching completed MCP audit record;
9. HMAC-bind the task, response and audit correlation.

Both responses must report:

```text
read_only = true
write_actions_enabled = false
real_evidence_access = false
protocol_v2_reachable = false
```

The two challenges, responses, audit correlations and audit-record digests
must all be distinct. Conversation identifiers are neither read nor stored.

## Negative and revocation protocol

Replay, cross-task replay, unknown fields and malformed challenges must be
rejected. File, command, secret, write, real-evidence and protocol-v2 requests
must remain outside the effective capability surface. Unsafe UI tests are not
forced merely to produce a result.

After both positive calls:

1. stop Tunnel and facade;
2. close listeners 8765 and 8766;
3. clear transport and runtime variables while preserving the audit key;
4. remove the temporary Plugin connection;
5. revoke the operator-created Runtime key;
6. prove a post-revocation Work call is unreachable;
7. commit negative and revocation receipts;
8. create the final attestation;
9. remove raw challenges, responses, logs and databases;
10. clear the audit key.

The final exact success value is:

```text
COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED
```

Any missing gate uses one of the exact `BLOCKED_BY_*` C8 results and never a
partial success.

## Operator commands

These commands are intentionally split around visible UI and
operator-managed credential steps:

Run the complete live cycle in one PowerShell terminal and keep that terminal
open until the final attestation. `Prepare-C8.ps1` creates three independent
process-local secrets; a different terminal cannot verify the HMAC receipts
and must never be treated as a continuation of the same cycle.

```powershell
.\scripts\c8\Prepare-C8.ps1 -ConfirmedExactScope
.\scripts\c8\Test-C8Prerequisites.ps1 -RequireSecrets
.\scripts\c8\New-C8WorkAdmission.ps1 `
    -WorkVisible -EntitlementAvailable -QuotaUsable -PluginSurfaceVisible
.\scripts\c8\Test-C8Prerequisites.ps1 -RequireSecrets -RequireLiveCycle
.\scripts\c8\Start-C8Facade.ps1
.\scripts\c8\Test-C8LocalProbe.ps1
```

Only after the local probe succeeds does the operator create a fresh Runtime
key and place that key plus the existing Tunnel ID in the same process
environment. The key value is never printed, persisted or committed. Then:

```powershell
.\scripts\c8\Test-C8Prerequisites.ps1 `
    -RequireSecrets -RequireLiveCycle -RequireTunnelCredentials
.\scripts\c8\Start-C8Tunnel.ps1
```

Work A and Work B then use:

```powershell
.\scripts\c8\New-C8WorkTaskObservation.ps1 `
    -TestWork a -VisibleWorkAndPluginSelected
.\scripts\c8\New-C8Challenge.ps1 -TestWork a
.\scripts\c8\Confirm-C8WorkProof.ps1 -TestWork a
```

The same sequence runs once for `b`. No third Work task is allowed.

If preparation is interrupted before a grant, facade, Tunnel, Plugin
connection or Work task exists, the operator can discard only the bounded
pre-live receipt and observations:

```powershell
.\scripts\c8\Reset-C8PreLive.ps1 -ConfirmedNoLiveActions
```

The reset refuses any live-cycle grant, proof, PID, listener or unexpected
state. It is not a recovery path after any live effect.

## Portability

The HMAC, chronology, negative-test and revocation structures are reusable
design patterns. The Work identity, official sources, visible controls,
entitlement/quota semantics, Plugin connection and Tunnel mapping are
ChatGPT-specific. A future Web AI integration must fail closed until it has
its own provider profile and independently tested adapter.
