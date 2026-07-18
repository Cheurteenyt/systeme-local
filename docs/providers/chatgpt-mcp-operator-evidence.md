# ChatGPT MCP sealed operator evidence bundle

Status: deterministic evidence-bundle and compilation foundation implemented; no live evidence collected

Reviewed: 2026-07-18T18:30:00Z

## Decision

Système Local now has a typed boundary between human or workspace observations and the existing
connection-readiness evaluator:

```text
raw operator/workspace evidence
    -> sanitize outside public models
    -> commit only typed states, bounded counts and SHA-256 digests
    -> seal one complete eleven-record bundle
    -> compile deterministically into McpConnectionReadinessObservation
    -> evaluate the existing readiness policy
```

This lot does not collect real account data, inspect ChatGPT, install Secure MCP Tunnel, create
an OAuth client, scan live tools, store tokens or configure an app. It provides the contract that
a later operator procedure must satisfy.

Every bundle and every compilation records:

```text
real_connection_established = false
secrets_stored = false
raw_endpoint_values_stored = false
raw_metadata_documents_stored = false
raw_tool_definitions_stored = false
```

## Why a separate bundle is required

`McpConnectionReadinessObservation` is the normalized policy input. It intentionally does not
describe how an operator obtained each digest. `McpOperatorEvidenceBundle` adds bounded
provenance, freshness and source compatibility without introducing raw evidence into the
readiness model.

A screenshot, copied page, metadata document, endpoint URL or tool definition is not inserted
into the bundle. An external operator procedure must sanitize and hash the evidence first. The
bundle stores only the resulting digest, a typed source, a typed assertion and a short validity
window.

## Complete evidence record set

The bundle contains exactly one `McpOperatorEvidenceRecord` for each readiness check:

| Check | Permitted evidence sources | Maximum record validity |
|---|---|---:|
| `plan_role_observation` | operator/admin attestation or sanitized UI-export digest | 24 hours |
| `web_client` | operator attestation or sanitized UI-export digest | 4 hours |
| `transport` | public-endpoint or Secure MCP Tunnel attestation | 15 minutes |
| `authentication_metadata` | sanitized metadata digest | 1 hour |
| `refresh_token` | sanitized metadata digest | 1 hour |
| `developer_mode` | operator/admin attestation or sanitized UI-export digest | 1 hour |
| `app_configuration` | operator/admin attestation or sanitized UI-export digest | 1 hour |
| `workspace_access` | admin attestation or sanitized UI-export digest | 1 hour |
| `tool_snapshot` | reviewed tool-scan snapshot | 30 minutes |
| `action_review` | action-review snapshot | 30 minutes |
| `local_policy` | exact local-policy snapshot | 24 hours |

Each record uses `verified`, `failed`, `unknown` or `not_applicable`. Verified and failed records
require a digest and an allowed source. Failed records require the exact typed failure code for
their check. Unknown and not-applicable records require `source=none` and cannot claim evidence.

Assertions are derived from the check identifier. A record cannot relabel plan evidence as
transport evidence, reuse an operator attestation where a tool scan is required or attach an
arbitrary failure string.

## Short-lived sealed bundle

The complete bundle expires no later than fifteen minutes after collection and never after any
member record or summary. This makes the bundle a transaction-like handoff, not a durable claim
that mutable workspace state remains true indefinitely.

The bundle binds:

```text
deployment request
capability-profile SHA-256
evidence-reconciliation-profile SHA-256
eleven sorted evidence records
optional sanitized transport summary
optional sanitized authentication summary
optional tool/action review summary
local-policy SHA-256 when verified
collection and expiry timestamps
bundle SHA-256
```

The bundle is immutable, strict, domain-separated and digest-bound. Extra fields fail
validation. The public schema has no fields for endpoint URLs, metadata bodies, passwords,
cookies, API keys, bearer tokens, access tokens, refresh-token values, client secrets or private
keys.

## Sanitized transport summary

A verified transport record must bind one `McpTransportEvidenceSummary`.

For a public remote server, the summary requires:

```text
server_location = public_remote
selected_transport = remote_direct
endpoint-origin digest
TLS-profile digest
public-endpoint attestation digest
```

For a private network, on-premises server or developer machine, the summary requires:

```text
selected_transport = secure_mcp_tunnel
endpoint-origin digest
TLS-profile digest
Secure MCP Tunnel attestation digest
```

The summary never stores the endpoint value, tunnel token, certificate private keys or tunnel configuration. A digest is evidence commitment, not proof that ChatGPT has connected.

## Sanitized OAuth/OIDC summary

A verified authentication-metadata record must bind one
`McpAuthenticationEvidenceSummary`. The summary accepts only OAuth or OpenID Connect and commits
digests for:

```text
issuer
discovery metadata
authorization endpoint
token endpoint
supported scopes
```

It also records whether refresh capability is advertised and whether refresh tokens are actually issued. It stores neither metadata contents nor client credentials.

For persistent connectivity, a verified refresh-token record must bind the same authentication
summary, the deployment request must use `refresh_token_capability=issued`, and both advertised
refresh capability and observed issuance must be true. This follows the current OpenAI guidance
that OAuth/OIDC deployments need refresh-token capability for durable access and may otherwise
require reauthentication.

## Tool and action review summary

A verified tool snapshot or action review binds one `McpToolReviewEvidenceSummary` containing:

```text
tool-snapshot SHA-256
tool count
write-tool count
high-risk-tool count
action-review SHA-256
```

The summary expires within thirty minutes and stores no raw tool definitions. The existing
readiness rules remain authoritative:

- read/fetch is blocked when the snapshot contains write tools;
- any high-risk tool requires a separate explicit review lot;
- server-side tool changes require refresh, comparison and recommitment;
- a ChatGPT confirmation prompt is not a local authorization guarantee.

## Deterministic compilation

`compile_chatgpt_mcp_operator_evidence_bundle`:

1. revalidates the capability profile and evidence-reconciliation profile;
2. verifies the complete bundle and exact profile digests;
3. refuses compilation before collection or after bundle expiry;
4. maps all eleven records to `McpReadinessCheck` values;
5. transfers only reviewed tool counts and the local-policy digest;
6. commits a complete `McpConnectionReadinessObservation`;
7. returns a digest-bound `McpOperatorEvidenceCompilation`.

`evaluate_chatgpt_mcp_operator_evidence_bundle` then calls the existing readiness evaluator and
returns a digest-bound `McpOperatorEvidenceEvaluation`. Re-verification recomputes the exact
compilation and decision. Tampered records, summaries, digests, timestamps, observations,
decisions or evaluation identifiers fail closed.

## Operator workflow reserved for a later lot

A future interactive operator procedure may collect real evidence only after it defines:

1. the exact account/workspace scope being observed;
2. the approved method for sanitizing each evidence type;
3. where raw evidence exists temporarily;
4. how raw evidence is destroyed or retained under policy;
5. how endpoint and metadata values are hashed without logging them;
6. how tunnel and TLS attestations are generated;
7. how the tool scan and action review are performed;
8. how the local-policy digest is produced;
9. who may attest each check;
10. how the fifteen-minute bundle window is enforced.

That procedure must produce an unknown or failed record whenever evidence is absent,
contradictory, stale or not independently verifiable. It must never guess from labels, browser
tabs, model output or copied ChatGPT URLs.

## Current OpenAI boundaries retained

Current official documentation says that ChatGPT requires an MCP endpoint and metadata,
authentication may use OAuth/OIDC, a tool scan occurs during app configuration, persistent
OAuth/OIDC should support refresh tokens, local servers are not connected directly, and tool
changes require explicit review. Workspace and app access controls remain separate from a claim
that a connection is operational.

The general plan matrix still lists Custom (MCP) for Plus while the dedicated developer-mode
article documents the deployment path at a different level of specificity. The existing
`PLUS_CUSTOM_MCP_PLAN_SCOPE` ambiguity remains fail-closed. This bundle cannot override the
capability or reconciliation profiles it binds.

## Conversation and identity boundary

The bundle contains no ChatGPT conversation identifier and does not enumerate chats or projects.
The operator still opens the intended conversation and selects or mentions the configured app.
MCP transport state, a plugin label, an app label, a copied URL and model-generated text are not
trusted conversation identity.

## Non-goals

- collecting real operator evidence in this lot;
- installing or starting Secure MCP Tunnel;
- configuring DNS, TLS or a public endpoint;
- creating an OAuth/OIDC client or redirect URI;
- storing raw metadata, endpoint values, tool definitions or secrets;
- configuring, publishing or connecting a ChatGPT app;
- scanning live tools;
- enabling write/modify tools;
- invoking ChatGPT or another provider;
- enumerating or selecting chats/projects;
- browser automation, DOM inspection, cookie replay or private endpoints;
- durable evidence storage, signing or retention.

## Official sources

- [Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461)
- [Apps in ChatGPT](https://help.openai.com/en/articles/11487775-apps-in-chatgpt)
- [Admin controls, security, and compliance for plugins and apps](https://help.openai.com/en/articles/11509118-admin-controls-security-and-compliance-in-apps-connectors-enterprise-edu-and-business)
