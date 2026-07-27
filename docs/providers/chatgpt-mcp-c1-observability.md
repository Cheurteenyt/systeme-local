# C1 ChatGPT Web Chat-surface observability and Codex runtime attribution

The execution status, exact test counts, skips, warnings, and live-evidence
gaps are maintained in the
[C1 test and evidence ledger](chatgpt-mcp-c1-test-evidence.md). The ledger
must be updated from direct command output after every material validation
round and must never classify an unexecuted Web test as passed.

Status: `BLOCKED_BY_PLUGIN_UNAVAILABLE_IN_CHAT`; the current official Web
surface contract exposes Plugins in Work and not in Chat, while C1 forbids Work

Reviewed: 2026-07-27T00:45:00Z

Revalidate no later than: 2026-08-10T00:45:00Z

Issue: [#66](https://github.com/Cheurteenyt/systeme-local/issues/66)

Dependency: draft [PR #65](https://github.com/Cheurteenyt/systeme-local/pull/65)
at exact C0 commit `912d0d33e119469ff957965104cf20af5e491923`

## Claim boundary

C1 can establish only this narrow claim after its complete live procedure:

> Two explicitly designated, newly created ChatGPT Web Chat pages each called
> the reviewed synthetic C0 probe with distinct challenges, produced distinct
> locally correlated audit records, preserved the closed capability boundary,
> and became unreachable after revocation.

C1 does not detect, enumerate, search, identify, or read the operator's existing
chats. It does not prove access to arbitrary conversations. It does not test
ChatGPT Work. It does not infer ChatGPT's internal model routing.

The current official Plugins documentation creates a product-surface blocker
for that claim: Plugins are available on ChatGPT Web in Work and are not
available in Chat. Because the operator's standing authorization permanently
excludes Work for this goal, no Plugin-backed Chat call may be attempted. C1
must fail closed before a prompt until an official contract explicitly makes
Plugins available in Chat or a separately authorized goal changes the surface.

The boundaries remain independent:

- ChatGPT Web Chat and ChatGPT Work;
- Codex in the ChatGPT desktop app, Codex CLI, IDE extension, and cloud;
- OpenAI Platform API;
- ChatGPT-visible model and reasoning labels;
- the active Codex runtime model and reasoning effort;
- Codex configuration defaults;
- service tier or Fast mode;
- the draft MCP Plugin and Secure MCP Tunnel.

A value observed at one boundary is never proof about another.

## C0 dependency and cleanup

C0 did not complete a real ChatGPT Web call. Its allowed status remains
`READY_BUT_MANUAL_CHATGPT_WEB_GATE_PENDING`. Before this branch was created:

- the C0 facade and Tunnel were intentionally stopped;
- ports `8765` and `8766` had no listener;
- no C0 process remained;
- the ignored C0 logs, challenge, audit, replay database, and local response
  were removed;
- text evidence was scanned without a secret finding;
- the operator explicitly confirmed revocation of the temporary C0 Runtime API
  key and closure of the C0 PowerShell process;
- no C0 draft Plugin connection had been created;
- Git was clean.

C1 therefore inherits reviewed code and an exact one-tool boundary, not a
proven live ChatGPT Web connection.

## Current official evidence

The canonical source profile is
[`governance/c1-official-evidence-profile.json`](../../governance/c1-official-evidence-profile.json).
Its profile SHA-256 is
`940ea95013c98dbef476432265d2542278888c70fdeaa9128bf823cbfebb8295`.
The builder recomputes every summary digest and the profile digest.

| Official source | C1 fact | Summary SHA-256 |
|---|---|---|
| [Get started with ChatGPT Work](https://learn.chatgpt.com/docs/get-started-with-work) | Chat is used for answers and conversation; Work is a separately selected task surface. C1 tests Chat only. | `c544c6e81799b7623b8a54dde0942a252563758894bb2ae71c65656470f1ac7e` |
| [Models](https://learn.chatgpt.com/docs/models) | Current clients may show model/reasoning controls; canonical Codex reasoning values and localized UI labels remain separate evidence. | `ff1ff72a22abb6cd99e22d16545260ca97212c2bf896a77c8dc6d3259fa163f8` |
| [Config basics](https://learn.chatgpt.com/docs/config-file/config-basic) | Precedence is CLI, project, profile, user, system, built-in. A configured default is not runtime proof. | `34d07ae296b4496c79590d1d1332e4487d3584cd5eef562ee916df12ad9075a1` |
| [Models](https://developers.openai.com/api/docs/models) | `gpt-5.6-sol`, `gpt-5.6-terra`, and `gpt-5.6-luna` are distinct official IDs. | `408b74017cc9d42ff0dcf63476bc433e2374fc70ebb2b53e5cfb697747df8c71` |
| [Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt) | The reviewed Plugin is selected in a new conversation. The documented flow does not expose account chat history. | `c87ac8d404a8fbf1aa776eae82410f42132ee7314a6e79cc3a94aac37fbea42b` |
| [Plugins](https://learn.chatgpt.com/docs/plugins) | Plugins are available with ChatGPT Work on the Web and are not available in Chat. A Chat-only Plugin test is therefore blocked before any prompt. | `2bea24e00c73e66791d0696d198ca766d318c7c248a12fa0009a8f456449fa93` |
| [Authentication](https://developers.openai.com/plugins/build/auth) | C1 reuses only the reviewed draft C0 `noauth` probe behind independent local and Tunnel controls. | `057f6725dd2509d41003f923deeabf4e097944a9925d5c4af28f5a3871ee71ae` |
| [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) | The official client provides outbound-only private connectivity with distinct Tunnel and Runtime-key permissions. | `0b4e1c1e3b717280dfcd3c9960706c2b48e06b443821b1208fabb27747bb7666` |
| [Browser](https://learn.chatgpt.com/docs/browser) | The in-app browser is a distinct surface; C1 restricts control to visible state in two sterile chats. | `6be663d6eb35833fd8114eb8462db7d1ca1b906111def89355885b43bdecfb41` |

No reviewed official integration contract exposes existing ChatGPT Web chat
history or conversation identifiers to this Plugin. C1 records that capability
as unsupported or unobservable. It never substitutes sidebar scraping, DOM
inventory, private endpoints, cookies, storage, or session export. A request to
detect all existing chats therefore ends with
`BLOCKED_BY_NO_OFFICIAL_CHAT_HISTORY_INTERFACE`.

## Runtime attribution

`C1RuntimeSetupObservation` stores every setup item as:

- `value`;
- `state`: `observed`, `configured_default`, `unobservable`, or
  `not_applicable`;
- a fixed `evidence_source`;
- an aware UTC observation time.

The current Codex turn metadata directly reports `gpt-5.6-sol` and `xhigh`.
Those are active runtime facts. The user configuration independently contains
the same model and reasoning values, but C1 records them only as configured
defaults. Direct runtime metadata reports sandbox `none`; the permission
context reports unrestricted filesystem access, network enabled, and approval
policy `never`. Active service tier and authentication boundary are not exposed
by the current runtime metadata and remain `unobservable`. A configured
`service_tier = "default"` is not promoted to runtime evidence.

The recorded configuration precedence is exactly:

1. CLI override;
2. project configuration;
3. profile configuration;
4. user configuration;
5. system configuration;
6. built-in default.

`C1VisibleModelObservation` is separate. It stores only directly visible
ChatGPT Web labels. It can store an internal model ID only if the visible
supported UI exposes that exact ID. A localized reasoning label maps to a
canonical value only with a current source-summary digest. ChatGPT Web labels
can never populate Codex runtime fields.

## Exact tool and network boundary

C1 does not add or alter an MCP tool. It reuses the C0 challenge format
`c0_[0-9a-f]{32}` because the exact reviewed C0 schema remains unchanged.
The sole tool is:

```text
systeme_local_connectivity_probe
```

The required snapshot is exactly:

```text
tool_count = 1
write_tool_count = 0
high_risk_tool_count = 0
readOnlyHint = true
destructiveHint = false
idempotentHint = true
openWorldHint = false
```

The committed policy SHA-256 is
`17a53ee929232bae5901037c26c23ad1379dbdb09998c698b1ed85c60a75700e`.
The tool-snapshot SHA-256 is
`6d9a8e0f6dadb9f3a615abcca8c882cb37fb257944922151e97c65a8575da14b`.

The facade binds only to `127.0.0.1:8765`. Tunnel health binds only to
`127.0.0.1:8766`. Raw HTTP logging, remote UI, automatic browser opening,
public binds, firewall changes, DNS, reverse proxies, write tools, B2 access,
and provider-outbound transports remain disabled.

## Typed live evidence

The models in `c1_observability.py` forbid unknown fields and use aware UTC
timestamps, fixed enums, bounded expiry, canonical JSON digests, and
domain-separated HMACs. They contain no conversation ID or personal content.

- `C1RuntimeSetupObservation` distinguishes active runtime evidence from
  configured defaults.
- `C1SurfaceObservation` is captured before a prompt and makes
  `prompt_sent=false` and `work_tested=false` immutable.
- `C1VisibleModelObservation` keeps Web labels separate from internal/runtime
  IDs.
- `C1TestChatObservation` binds one strict response and all four false-sensitive
  capability flags.
- `C1ChatCorrelationReceipt` authenticates the response, challenge, observation,
  policy, snapshot, audit UUID, audit record, and verified chain length.
- `C1NegativeTestReceipt` requires every bounded negative result exactly once.
- `C1RevocationReceipt` requires Plugin removal, Runtime-key revocation,
  process shutdown, no listener, and a failed post-revocation Chat call.
- `C1FinalAttestation` requires two ordered, distinct, unexpired,
  non-simulated Chat proofs and all revocation bindings.

A manual C1 evidence cycle has a two-hour cryptographic validity window. This
window exists for the signed surface, visible-label, Chat-proof, negative, and
revocation artifacts so a human operator can complete the bounded browser and
revocation sequence without racing a 30-minute finalization deadline. It does
not weaken call freshness: each challenge remains valid for at most 30 minutes,
and the strict response must be observed no more than 30 minutes after its
pre-prompt Chat-surface observation. The final attestation remains valid for at
most 30 minutes and never outlives any input evidence.

A fixture, mock, local call, stale observation, manually altered receipt, Work
observation, configured default, duplicated challenge/audit, changed response,
policy drift, snapshot drift, or secret/private-state field cannot create the
final status.

## Local preparation

Commit and validate the C1 implementation before live runtime startup; runtime
scripts require a clean dedicated branch.

```powershell
.\scripts\c1\Prepare-C1.ps1
.\scripts\c1\Test-C1Prerequisites.ps1 -RequireSecrets
.\scripts\c1\New-C1RuntimeSetupObservation.ps1 `
  -RuntimeModel "gpt-5.6-sol" `
  -ReasoningEffort "xhigh"
.\scripts\c1\Start-C1Facade.ps1
.\scripts\c1\Test-C1LocalProbe.ps1
.\scripts\c1\Stop-C1.ps1 -ClearAuditKey
.\scripts\c1\Clear-C1Preflight.ps1
```

Create a new temporary Runtime API key for C1, configure
`CONTROL_PLANE_TUNNEL_ID` and `CONTROL_PLANE_API_KEY` only in the current
PowerShell process, and run:

```powershell
.\scripts\c1\Test-C1Prerequisites.ps1 `
  -RequireSecrets `
  -RequireTunnelCredentials
.\scripts\c1\Start-C1Tunnel.ps1
.\scripts\c1\Show-C1OperatorSteps.ps1
```

The previous revoked C0 key must never be reused.
Run `Prepare-C1.ps1` again in the live-test PowerShell after the preflight
cleanup so the live audit chain and all three process secrets are fresh.

## Product-surface compatibility gate

Before creating a Runtime key, starting C1 processes, creating a temporary
Plugin, or opening test pages, revalidate the official Plugins surface
contract. At the current review instant, the contract says:

- Plugins are available with ChatGPT Work on the Web;
- Plugins are not available in Chat.

The C1 claim and the operator's authorization both prohibit Work. Therefore the
current result is `BLOCKED_BY_PLUGIN_UNAVAILABLE_IN_CHAT`. Do not treat a
default Work page, a Plugin-directory action, an app mention, or a successful
Tunnel connection as permission to continue. Close any newly opened test
pages, disconnect the temporary Plugin, stop local processes, revoke the
temporary Runtime key, and retain no positive evidence from that cycle.

## Goal-scoped browser authorization gate

Browser control is forbidden until the operator provides explicit
authorization for the current C1 goal. Ambient browser state is not
authorization. Once granted, the same bounded authorization remains valid
across necessary retries until the operator revokes it, the goal ends, or the
requested scope changes. It must not be requested again for every cycle.

After authorization, control is limited to:

- at most two newly created sterile Chat pages per cycle;
- the visible Chat/Work/Codex selector;
- visible model and reasoning labels;
- selecting the reviewed draft Plugin;
- synthetic C1 prompts and structured synthetic results.

It must not open or inspect:

- the sidebar, history, search, existing chats, projects, titles, or IDs;
- cookies, local/session storage, IndexedDB, private requests, or session data;
- account, API-key, or billing pages;
- unrelated tabs, developer tools, raw CDP state, or personal content.

If the current selector is Work, Codex, or unknown, no prompt is sent and Codex
must not switch the surface. The run ends with the most specific product or
surface blocker.

If a browser-control action opens Work or Codex, accesses an existing chat or
private browser state, sends an unexpected prompt, or invokes a tool outside
the exact two-Chat protocol, the cycle is rejected immediately. Close both
test tabs, stop both C1 processes, remove the temporary Plugin, revoke the
Runtime API key, and run:

```powershell
.\scripts\c1\Reject-C1ScopeViolationCycle.ps1 `
  -Violation work_surface_opened_without_prompt `
  -TestTabsClosed `
  -PluginConnectionRemoved `
  -RuntimeApiKeyRevoked
```

The rejection refuses an open listener, a validated final attestation, missing
operator confirmations, or a state directory without typed evidence. It
irreversibly removes the rejected cycle and all process secrets. No response,
challenge, receipt, audit record, or browser page from that cycle may be reused.

## Two sterile Chat protocol

Use exactly two new pages. `c1-test-chat-a` and `c1-test-chat-b` are local
labels only; no provider title or conversation ID is collected.

For Chat A:

The current official developer-mode instructions allow either selecting the
draft app from the ChatGPT tools menu or referring to the app in the prompt.
Do not use the Plugin-directory `Essayer dans le chat` / `Try in chat` control:
it can switch the current surface to Work. Do not use an `@` selection pill
whose click target opens Plugin details. If the tools menu does not expose an
unambiguous selection that visibly remains in Chat, keep the new page in Chat
and use one plain-text prompt that names the temporary app and exact tool. The
pre-prompt surface observation records that bounded app target, and the local
audit correlation remains the authority for which tool actually ran.

```powershell
.\scripts\c1\New-C1Challenge.ps1 -TestChat a
.\scripts\c1\New-C1SurfaceObservation.ps1 `
  -TestChat a `
  -Surface chat `
  -PluginSelected
```

Send one synthetic prompt that requests only one call to
`systeme_local_connectivity_probe` with the generated challenge and asks for
only the structured result. Save only that strict result as ignored
`.systeme-local/c1/live-response-a.json`, then run:

```powershell
.\scripts\c1\Confirm-C1ChatProof.ps1 -TestChat a
```

Repeat with a distinct challenge and a new sterile Chat B:

```powershell
.\scripts\c1\New-C1Challenge.ps1 -TestChat b
.\scripts\c1\New-C1SurfaceObservation.ps1 `
  -TestChat b `
  -Surface chat `
  -PluginSelected
.\scripts\c1\Confirm-C1ChatProof.ps1 -TestChat b
```

Each response must contain:

```text
read_only = true
write_actions_enabled = false
real_evidence_access = false
protocol_v2_reachable = false
```

The verifier requires distinct challenge digests, response digests, audit
correlations, and audit-record digests.

Record visible labels separately. Omit a label that is not visibly exposed:

```powershell
.\scripts\c1\New-C1VisibleModelObservation.ps1 `
  -VisibleModelLabel "<exact visible label>" `
  -VisibleReasoningLabel "<exact ASCII visible label>"
```

Non-ASCII labels must use canonical UTF-8 Base64 so Windows console code pages
cannot alter signed evidence. For the directly observed French label
`Très élevée`, use:

```powershell
.\scripts\c1\New-C1VisibleModelObservation.ps1 `
  -VisibleReasoningLabelUtf8Base64 "VHLDqHMgw6lsZXbDqWU="
```

The C1 Python CLIs render non-ASCII JSON characters as `\u` escapes. The typed
value remains exact after JSON parsing while every byte crossing the
PowerShell/native-process boundary remains ASCII.

Do not supply `-ExactInternalModelId` unless that exact ID is visibly exposed.
Do not supply `-CanonicalReasoning` without a current mapping-summary digest.

## Negative Chat verification

Only after both positive correlations, perform in Chat:

1. replay Chat A's challenge in Chat A;
2. replay Chat A's challenge in Chat B;
3. request an unknown tool argument;
4. request a malformed challenge;
5. request local-file access using no real filename or content;
6. request command execution using no real command or data;
7. request a synthetic secret;
8. request B2 evidence;
9. request a write operation.

The first four must be rejected by schema/replay protection or remain
incapable of a call. The last five must leave the capability unavailable; the
tool snapshot must remain exactly one read-only probe. No negative test is run
in Work and no real secret, file content, command, or personal datum is used.

## Revocation and finalization

After the first nine negative checks:

1. run `Stop-C1.ps1` and verify ports `8765/8766` are closed;
2. manually remove the draft Plugin connection;
3. revoke the temporary C1 Runtime API key;
4. in one fresh sterile Chat page, verify the tool call is unavailable;
5. record all ten negative results;
6. record the explicit revocation facts;
7. commit the final attestation;
8. remove raw responses, challenges, logs, databases, and process secrets.

```powershell
.\scripts\c1\Stop-C1.ps1

.\scripts\c1\Confirm-C1NegativeTests.ps1 `
  -SameChatReplay rejected `
  -CrossChatReplay rejected `
  -UnknownField rejected `
  -MalformedChallenge rejected `
  -LocalFileRequest capability_not_exposed `
  -CommandExecutionRequest capability_not_exposed `
  -SecretRequest capability_not_exposed `
  -B2EvidenceRequest capability_not_exposed `
  -WriteOperationRequest capability_not_exposed `
  -PostRevocationCall unreachable_after_revocation

.\scripts\c1\Confirm-C1Revocation.ps1 `
  -PluginConnectionRemoved `
  -RuntimeApiKeyRevoked `
  -PostRevocationChatCallFailed

.\scripts\c1\Commit-C1FinalAttestation.ps1
.\scripts\c1\Clear-C1Temporary.ps1
```

`Clear-C1Temporary.ps1` keeps only approved secret-free typed observations,
receipts, and the final attestation. Raw responses and audit material are not
recoverable. Final cleanup does not require access to either test page or any
pre-existing conversation.

If final attestation fails because typed evidence expired, fail closed. Stop
both C1 processes, remove the draft Plugin, revoke the temporary Runtime API
key, and do not reuse any response, challenge, or receipt from that cycle. Once
those facts are true and at least one typed artifact is expired, reject and
erase the failed private state with:

```powershell
.\scripts\c1\Reject-C1ExpiredCycle.ps1 `
  -PluginConnectionRemoved `
  -RuntimeApiKeyRevoked
```

The rejection path refuses live listeners, a validated attestation, or a cycle
without expired typed evidence. Its deletion is irreversible and clears all
process secrets before a fresh `Prepare-C1.ps1` run.

## Status mapping

Use `COMPLETE_BOUNDED_CHAT_SURFACE_OBSERVABILITY_VERIFIED` only after both live
Chat calls, both local audit correlations, direct Codex runtime attribution,
all ten negative results, Plugin/key revocation, shutdown, and the failed
post-revocation call are validated and unexpired.

Otherwise use exactly the most specific allowed C1 status:

- `READY_BUT_MANUAL_WEB_GATE_PENDING`
- `BLOCKED_BY_C0_NOT_COMPLETE`
- `BLOCKED_BY_CHATGPT_PLAN_OR_ROLE`
- `BLOCKED_BY_PLUGIN_UNAVAILABLE_IN_CHAT`
- `BLOCKED_BY_CHAT_SURFACE`
- `BLOCKED_BY_BROWSER_AUTHORIZATION`
- `BLOCKED_BY_NO_OFFICIAL_CHAT_HISTORY_INTERFACE`
- `BLOCKED_BY_RUNTIME_MODEL_ATTRIBUTION`
- `BLOCKED_BY_PLUGIN_OR_TUNNEL`
- `BLOCKED_BY_LIVE_CHAT_CALL`
- `BLOCKED_BY_AUDIT_CORRELATION`
- `BLOCKED_BY_REVOCATION_TEST`
- `BLOCKED_BY_SECURITY_INVARIANT`
- `BLOCKED_BY_TEST_FAILURE`
