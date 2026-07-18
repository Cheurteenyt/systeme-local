# ChatGPT MCP connection readiness and evidence reconciliation

Status: deterministic readiness foundation implemented; real connection not implemented

Reviewed: 2026-07-18T14:00:00Z

Revalidate no later than: 2026-08-01T14:00:00Z

## Decision

Système Local separates three facts that must never be collapsed:

```text
official product eligibility
    != observed operator/workspace configuration
    != a live authenticated MCP connection
```

This lot implements only the first two layers. It reconciles current official evidence,
commits secret-free operator observations, evaluates readiness deterministically and produces a
digest-bound handoff decision. It does not install Secure MCP Tunnel, create OAuth clients,
store tokens, configure a ChatGPT app or call a provider.

A `ready` decision authorizes only the next bounded operator step. Every decision records:

```text
real_connection_established = false
secrets_stored = false
automatic chat enumeration = false
automatic project enumeration = false
```

## Evidence ambiguity: Plus

Current official OpenAI pages do not align at the same level of specificity:

- the general Apps plan matrix lists Custom (MCP) for Plus, Pro, Business and Enterprise/Edu;
- the dedicated developer-mode article documents full MCP for Business and Enterprise/Edu and
  read/fetch MCP for Pro, but does not document a Plus developer-mode deployment path.

Système Local does not convert a general availability mark into permission to configure or use
a specific custom MCP deployment. `PLUS_CUSTOM_MCP_PLAN_SCOPE` is therefore committed as an
ambiguous finding with `FAIL_CLOSED` resolution. A Plus observation receives both a typed
readiness blocker and a warning explaining that general availability is not deployment
authorization.

This is not a claim that Plus is permanently unsupported. It is a bounded operational decision
until the dedicated OpenAI contract becomes explicit or the evidence is revalidated.

## Evidence reconciliation profile

`ChatGptMcpEvidenceReconciliationProfile` commits:

```text
reviewed_at
revalidate_after
official source statement digests
complete evidence finding set
ambiguity resolution
profile SHA-256
```

Every finding is immutable, sorted, domain-separated and digest-bound. The complete finding set
covers:

1. Plus custom-MCP plan scope;
2. remote versus Secure MCP Tunnel transport;
3. persistent OAuth/OIDC refresh-token capability;
4. reviewed tool snapshots and tool drift;
5. write-action confirmation and high-risk blocking.

Ambiguous findings require at least two official sources and must fail closed. Consistent
findings may continue to the existing deployment policy but cannot authorize a live connection
on their own. Reconciliation evidence expires after fourteen days in this profile and never
after more than thirty-one days.

## Secret-free readiness checks

`McpConnectionReadinessObservation` contains every readiness check exactly once:

| Check | What may be committed | What is forbidden |
|---|---|---|
| plan/role observation | digest of bounded operator evidence | account cookies or session exports |
| web client | digest of an operator-confirmed observation | DOM scraping |
| transport | digest of tunnel/public-endpoint verification | private keys or tunnel tokens |
| authentication metadata | digest of sanitized discovery metadata | client secrets or access tokens |
| refresh token | capability evidence only | refresh-token value |
| developer mode | operator/workspace evidence digest | browser session data |
| app configuration | configuration-state evidence digest | ChatGPT credentials |
| workspace access | access-control evidence digest | member authentication material |
| tool snapshot | snapshot digest and bounded counts | tool payload secrets |
| action review | approval-state evidence digest | automatic approval bypasses |
| local policy | exact local policy digest | mutable policy labels without digest |

A check state is one of `verified`, `failed`, `unknown` or `not_applicable`. Verified and failed
checks require evidence digests. Unknown and not-applicable checks cannot claim evidence. Failed
checks require a typed, non-secret detail code.

No model contains fields for passwords, cookies, bearer tokens, API keys, OAuth access tokens,
refresh-token values, client secrets or private keys. Endpoint and metadata contents remain
outside the public models; only validated digests may be committed.

## Tool snapshot contract

A verified tool snapshot binds:

```text
tool_snapshot_sha256
tool_count
write_tool_count
high_risk_tool_count
```

The counts are bounded and internally coherent. A read/fetch request is blocked if its reviewed
snapshot contains any write tool. Any high-risk tool blocks ordinary readiness and requires a
separate explicit review lot. This conservative rule is local policy; it does not assume that a
ChatGPT confirmation dialog guarantees approval or execution.

Tool updates are never inherited automatically. After a server-side change, the operator must
refresh, compare and recommit the snapshot before a readiness decision can be reused.

## Readiness stages

Readiness is staged rather than represented by one permissive boolean:

| Stage | Meaning |
|---|---|
| `blocked` | one or more policy, evidence or observation blockers exist |
| `ready_to_configure_draft` | prerequisites permit creating a bounded draft app |
| `ready_to_test_draft` | the draft, tool snapshot and action review are verified |
| `ready_for_publish_review` | publication prerequisites are verified; publication is not performed |
| `ready_for_use_review` | configured-use prerequisites are verified; use is not performed |

For a test request, an unconfigured app can be ready for draft configuration once plan, role,
client, transport, authentication, refresh behavior, developer mode and local policy are
verified. Once app configuration is observed, the tool snapshot and action review become
mandatory before testing.

Publish readiness requires a configured app, reviewed tool snapshot and action review in
addition to the existing plan/role policy. Managed-workspace use also requires verified
workspace access. These stages do not bypass ChatGPT workspace controls, local approval or
audit.

## Deterministic evaluation

`evaluate_chatgpt_mcp_connection_readiness` first revalidates:

1. the existing `ChatGptMcpCapabilityProfile`;
2. the evidence reconciliation profile;
3. the complete readiness observation;
4. exact profile digests and UTC ordering.

It then invokes the existing deployment-policy evaluator. A deployment refusal remains a
readiness refusal. The readiness layer adds evidence ambiguity, required-check partitioning,
tool-snapshot and high-risk controls. The result binds:

```text
capability profile SHA-256
reconciliation profile SHA-256
observation SHA-256
deployment reasons
required and verified checks
failed, unknown and invalid not-applicable checks
selected transport when ready
evaluated_at
```

Re-verification recomputes the exact decision. Tampered stages, reasons, check partitions,
digests, timestamps or transport selections are rejected.

## Sealed operator evidence bundle

The observation layer now has a separate sealed provenance contract in
[`chatgpt-mcp-operator-evidence.md`](chatgpt-mcp-operator-evidence.md). It contains exactly one
short-lived record for every readiness check, constrains which evidence sources may support each
check, and compiles deterministically into `McpConnectionReadinessObservation`.

The bundle stores only typed states, bounded counts and SHA-256 digests. Endpoint values,
metadata bodies, tool definitions, passwords, cookies, access tokens, refresh-token values,
client secrets and private keys remain outside public models. A compiled or ready result still
records `real_connection_established=false` and `secrets_stored=false`.

## Operator facts required later

A real-connection lot may start only after the operator supplies bounded evidence for:

1. actual ChatGPT plan;
2. actual workspace role;
3. intended read/fetch or write/modify access;
4. ChatGPT web availability and developer-mode state;
5. public remote endpoint or Secure MCP Tunnel readiness;
6. OAuth/OIDC metadata controlled for Système Local;
7. refresh-token issuance for persistent connectivity;
8. configured draft-app state;
9. exact scanned tool snapshot and action review;
10. workspace access controls where applicable;
11. exact local policy digest.

These facts may remain unknown. Unknown evidence produces a deterministic blocker rather than a
guess or a permissive default.

## Conversation boundary

The operator still chooses the ChatGPT conversation by opening it and selecting or mentioning
the configured Système Local app. Readiness does not enumerate personal chats or projects,
select a chat automatically, treat an MCP session as a conversation identifier, inspect the
sidebar or derive identifiers from URLs and model output.

## Non-goals

- installing or starting Secure MCP Tunnel;
- exposing the loopback MCP server publicly;
- creating DNS, TLS or public endpoint configuration;
- creating OAuth/OIDC clients or redirect URIs;
- storing passwords, cookies, tokens, secrets or private keys;
- configuring, publishing or connecting a ChatGPT app;
- scanning live tools from ChatGPT;
- enabling write/modify tools;
- invoking any provider action;
- enumerating chats or projects;
- browser automation, DOM observation or private endpoints.

## Official sources

- [Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461)
- [Apps in ChatGPT](https://help.openai.com/en/articles/11487775-apps-in-chatgpt)
