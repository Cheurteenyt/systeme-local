# C0 ChatGPT Web MCP read-only connectivity probe

Status: implementation and local validation complete; manual ChatGPT Web gate not yet observed

Reviewed: 2026-07-26T00:00:00Z

Revalidate no later than: 2026-08-09T00:00:00Z

Issue: [#64](https://github.com/Cheurteenyt/systeme-local/issues/64)

## Claim boundary

C0 can establish only this narrow claim after a real manual test:

> A draft ChatGPT Web plugin called one synthetic read-only MCP tool through
> Secure MCP Tunnel in a bounded, dated environment.

C0 does not establish general ChatGPT integration, chat automation, production
connectivity, production OAuth, provider-outbound transport, real B2 evidence
collection, or availability of any write tool.

The repository contains no live ChatGPT Web observation. Until an eligible
operator completes the scan, live call, audit correlation, and revocation test,
the only permitted classification is a non-complete C0 status.

## Current official evidence

The source summaries are committed in the typed profiles. Each summary is
domain-separated and SHA-256 bound by
`commit_official_source_reference`. The capability profile SHA-256 is
`4395331832c736eecc4424ad4c2222efdc7113ac2ae2c2cf9b4a3c3fd3bdd4e2`;
the reconciliation profile SHA-256 is
`1aa125db3cb2f7d70088a5308e76f20d72d8b393df3a8b723841ab9bd01c19b8`.

| Official source | Fact used by C0 | Summary SHA-256 |
|---|---|---|
| [Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461) | Full MCP is documented for Business, Enterprise, and Edu; Pro is limited to read/fetch. Eligibility also depends on workspace role and access. Custom MCP is a Web surface. | `9a89f983925d69be081e0a4c96244bb516ffcf163bc122d7c2879d5caa27b0b4` |
| [Apps in ChatGPT](https://help.openai.com/en/articles/11487775-apps-in-chatgpt) | Discovery moved to the Plugin directory on 2026-07-09; eligibility and management controls remain plan- and workspace-dependent. | `6cfd7c37d5d208a5e8dec2c3653b00e98101aeeae97cf76aee59a28783f61a57` |
| [Connect from ChatGPT](https://developers.openai.com/plugins/deploy/connect-chatgpt) | A developer adds the endpoint or Tunnel, reviews discovered tools, selects the connection in a new chat, and refreshes/reviews after metadata changes. | `9b722a6230bafb3a360016b5187df585a39c3939738c466b3c81d3ce7d4c0431` |
| [Secure MCP Tunnels](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) | The customer-run client keeps the local server private and creates outbound-only connectivity. Tunnel and runtime-key permissions are distinct from ChatGPT developer-mode access. | `a3f7d21b48cfaf94d0ead03d7809036bfc77149c4d59eddef59369ea4eabf705` |
| [Authentication](https://developers.openai.com/plugins/build/auth) | Per-tool schemes can be `noauth` or OAuth 2.1. C0 permits `noauth` only for this unpublished, time-bounded synthetic tool while the tunnel and local facade remain independently authenticated. | `24389eec374ed33438b44c29dfea38b130c693d4ff00882857c04f2163dabf50` |
| [Projects in ChatGPT](https://help.openai.com/en/articles/10169521-projects-in-chatgpt) | Projects provide bounded chat, file, instruction, and memory context, but no custom-MCP contract for account-wide chat or project enumeration is documented. | `d51bf2b5933fead23cb5d31e317e9d24913ae63a6a6c41205d41e4b5f445dda2` |
| [MCP tools specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Tool metadata supports `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`, and an object-root output schema. | specification reviewed 2026-07-26 |
| [openai/tunnel-client v0.0.10](https://github.com/openai/tunnel-client/releases/tag/v0.0.10) | The pinned Windows AMD64 archive is the official release asset. Its release-published SHA-256 is recorded in `governance/c0-tunnel-client.json`. | `5e64a056f1d96786da0a6f8db1da5f5f4a03fd19a90d951a25cf2ca8d9093d00` |

Plan, seat, workspace, role, RBAC, ChatGPT developer-mode access, OpenAI
Platform Tunnel permissions, and Runtime API-key permissions are separate
observations. An unknown or ambiguous value fails closed. If the real
configuration requires OAuth/OIDC, C0 stops with
`BLOCKED_BY_AUTHENTICATION_GATE`; it does not add OAuth silently.

## Implemented boundary

`SLG_C0_ENABLED` defaults to false and is valid only when the authenticated MCP
runtime is explicitly enabled and a full build commit is injected. The separate
`policy.c0.yaml` is default-deny and declares only
`systeme_local_connectivity_probe`. Startup aborts unless that is the exact and
only visible tool.

The tool accepts exactly one `c0_[0-9a-f]{32}` challenge. Unknown fields,
malformed input, replay, or policy/snapshot drift fail closed. It reads no
operator file, starts no process, makes no network call, touches no business
state, and cannot reach protocol v2. Its response contains only the challenge
SHA-256, build/policy/snapshot digests, fixed security booleans, an audit UUID,
and a UTC timestamp.

```text
read_only=true
write_actions_enabled=false
real_evidence_access=false
protocol_v2_reachable=false
```

The advertised snapshot is:

```text
tool_count = 1
write_tool_count = 0
high_risk_tool_count = 0
readOnlyHint = true
destructiveHint = false
idempotentHint = true
openWorldHint = false
```

The snapshot SHA-256 is computed from canonical JSON containing the name,
description, input schema, output schema, and annotations. ChatGPT's scanned
metadata must match every field; a count or metadata difference blocks the
live test. The committed local policy SHA-256 is
`17a53ee929232bae5901037c26c23ad1379dbdb09998c698b1ed85c60a75700e`
and the committed tool snapshot SHA-256 is
`6d9a8e0f6dadb9f3a615abcca8c882cb37fb257944922151e97c65a8575da14b`.
The full reviewable snapshot is
[`governance/c0-tool-snapshot.json`](../../governance/c0-tool-snapshot.json).

## Network and authentication

The facade binds to `127.0.0.1:8765`. Its existing literal-loopback client,
singleton `Host`/`Origin`/`Authorization`, bearer, size, rate, and concurrency
controls remain enabled. The official tunnel client health surface binds to
`127.0.0.1:8766`. No firewall rule, DNS name, TLS private key, public reverse
proxy, port forward, wildcard bind, or third-party tunnel is created.
The C0 facade is explicitly capped at a 4 KiB request, 30 requests per minute,
and one concurrent request. The tunnel client uses the required `main` channel,
one in-flight MCP request, a five-minute connection TTL, and one buffered
control-plane command.
The authenticated C0 MCP endpoint rejects the optional standalone SSE `GET`
with `405`; C0 is stateless JSON request/response and emits no unsolicited
server messages. This lets the official Go client complete initialization
without leaving an unbounded stream open.
The facade starts from the ignored C0 state directory rather than the
repository root, so repository-local `.env` values cannot silently widen or
re-anchor the probe. Explicit process-level audit-anchor configuration is
rejected before startup.

The pinned tunnel client receives credentials only through process
environment. Static local MCP headers use
`Authorization: env:SLG_MCP_AUTHORIZATION`; that process-only variable is
derived from the independent MCP token with the required bearer scheme and is
cleared during rollback. Discovery uses the same exact reference and pins
`Content-Type: application/json` so the official client's startup initialize
probe completes rather than falling back to its timeout-tolerant readiness
state. The local integration test requires the resulting
`mcp session initialized` event. Raw HTTP logging, remote UI, and automatic
browser opening are disabled. The bearer is sent only to the configured
loopback MCP origin.

## Operator sequence

Run the scripts from a clean
`interop/chatgpt-web-mcp-connectivity-c0` worktree:

```powershell
.\scripts\c0\Prepare-C0.ps1
.\scripts\c0\Test-C0Prerequisites.ps1 -RequireSecrets
.\scripts\c0\Start-C0Facade.ps1
.\scripts\c0\New-C0Challenge.ps1
.\scripts\c0\Test-C0LocalProbe.ps1
.\scripts\c0\New-C0Challenge.ps1
.\scripts\c0\Test-C0TunnelClientLocal.ps1
.\scripts\c0\New-C0Challenge.ps1
.\scripts\c0\Test-C0Prerequisites.ps1 -RequireSecrets -RequireTunnelCredentials
.\scripts\c0\Start-C0Tunnel.ps1
.\scripts\c0\Show-C0ChatGptSteps.ps1
```

The operator performs all ChatGPT Web actions manually. No code reads the DOM,
cookies, local storage, private requests, conversation identifiers, sidebar,
projects, or other chats. Only a strict response JSON and bounded, sanitized
states/counts/digests may enter the ignored `.systeme-local/c0` directory.

The manual checklist records exactly these readiness checks:

1. `plan_role_observation`
2. `web_client`
3. `transport`
4. `authentication_metadata`
5. `refresh_token`
6. `developer_mode`
7. `app_configuration`
8. `workspace_access`
9. `tool_snapshot`
10. `action_review`
11. `local_policy`

Each state is `verified`, `failed`, `unknown`, or `not_applicable`.
`not_applicable` requires a mode-specific justification. Any `failed` or
`unknown` blocks live attestation.

After the call, `Confirm-C0LiveProof.ps1` verifies the challenge, schema, current
build, raw policy digest, canonical tool snapshot, HMAC audit chain, and exact
audit UUID. Its intermediate receipt is itself authenticated with a
domain-separated HMAC, binds the challenge creation/check window, response,
build, policy, tool snapshot, audit record, and verified chain length, and
deliberately keeps `real_connection_established=false`. The final attestation
command requires and revalidates that receipt; directly bypassing the proof
check fails closed.

The operator's `manual-web-observation.json` is validated by
`C0ManualWebObservation`. It contains only plan, role, fixed
Web/Tunnel/noauth/draft facts, the exact tool name and `1/0/0` counts, policy
and tool SHA-256 values, all eleven typed states, and two UTC timestamps.
Unknown fields, simulated evidence, Plus/unknown plans, unknown roles,
publication, writes, risky tools, or unjustified `not_applicable` states are
rejected.

After removing the draft connection, stopping both processes, revoking the
Runtime API key, and manually confirming a failed call in a fresh chat, run:

```powershell
.\scripts\c0\Confirm-C0Revocation.ps1 `
  -PluginConnectionRemoved `
  -RuntimeApiKeyRevoked `
  -ManualCallFailedAfterRevocation
.\scripts\c0\Commit-C0LiveAttestation.ps1
```

The latter is the only operator command that can serialize
`real_connection_established=true`; it requires every bounded input and writes
only the secret-free expiring attestation to the ignored C0 state directory.

## Live attestation

The separate `ChatGptMcpLiveProbeAttestation` never changes historical
readiness decisions. Its committing validator requires:

- a current official capability profile;
- all eleven checks verified or justified not-applicable;
- local and scanned counts of exactly `1/0/0`;
- matching policy, tool, challenge, response, and audit data;
- the authenticated fresh-call receipt produced before revocation;
- an MCP-attributed completed audit record;
- a bounded manual Web time window;
- a manually verified failed call after revocation.

Only that model may record `real_connection_established=true`. Local smoke
tests, mocks, fixtures, or pending receipts do not produce a live attestation.

## Rollback

1. Remove or disable the draft Plugin connection in ChatGPT Web.
2. Stop Secure MCP Tunnel with `Stop-C0.ps1`.
3. Stop the C0 facade with the same script.
4. Revoke the temporary Runtime API key in the official Platform settings.
5. Leave `SLG_C0_ENABLED` unset/false.
6. Confirm ports 8765 and 8766 have no remaining listeners.
7. In a fresh manual ChatGPT Web chat, confirm the draft tool cannot be called.
8. Commit only permitted digests and typed receipts, never raw UI evidence.
9. Run `Clear-C0Temporary.ps1` to remove raw local material; it is not recoverable.
10. Confirm `git status --short` is clean.

Rollback does not require access to the original test conversation.

## Final status mapping

`COMPLETE_LIVE_CHATGPT_WEB_CONNECTION_VERIFIED` is legal only after the real
call, local audit correlation, and post-revocation failed call are all
committed. Otherwise use the most specific status from the C0 goal, including
`READY_BUT_MANUAL_CHATGPT_WEB_GATE_PENDING`,
`BLOCKED_BY_CHATGPT_PLAN_OR_ROLE`, `BLOCKED_BY_DEVELOPER_MODE`,
`BLOCKED_BY_TUNNEL`, `BLOCKED_BY_AUTHENTICATION_GATE`,
`BLOCKED_BY_TOOL_SCAN`, `BLOCKED_BY_LIVE_CALL`,
`BLOCKED_BY_REVOCATION_TEST`, `BLOCKED_BY_SECURITY_INVARIANT`, or
`BLOCKED_BY_TEST_FAILURE`.
