# C3 provider capability evidence lifecycle

Status: `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`

Evidence lifecycle: `current`

Reviewed: `2026-07-27T11:55:00Z`

Revalidation due from: `2026-08-03T11:55:00Z`

Expires: `2026-08-10T11:55:00Z`

Stacked base: exact C2 commit
`cf05e963ba30539f9b2c9ec2f5f71326cbba8399` from draft
[PR #68](https://github.com/Cheurteenyt/systeme-local/pull/68).

Tracking issue:
[#69](https://github.com/Cheurteenyt/systeme-local/issues/69).

The exact commands and observed results are recorded in the
[C3 test and evidence ledger](chatgpt-web-c3-test-evidence.md).

## Result

C3 revalidated the exact question from C2:

> Does current official OpenAI documentation expose a custom or local MCP
> invocation interface on the native ChatGPT Chat surface, without switching
> to Work?

The reviewed result remains **unsupported**. The official Plugins overview
states that Plugins are available with ChatGPT Work and are unavailable in
Chat. The official MCP connection, plugin packaging, and Secure MCP Tunnel
instructions still route ChatGPT MCP setup through Plugins. No reviewed
official source establishes another native Chat interface for custom or local
MCP tools.

This is a product-surface decision, not a network or implementation failure.
Secure MCP Tunnel can transport calls for a supported product surface; it
cannot make an unsupported surface supported.

## C2 gap analysis

### Existing and reusable

- strict Pydantic models with unknown-field rejection;
- provider, native-surface, surface-class, and capability separation;
- canonical JSON and SHA-256 commitments;
- sorted, unique official-source records;
- a 14-day maximum review window;
- exact reviewed-builder matching;
- one atomic fail-closed action decision;
- C1 entry-point gating before credentials, processes, or browser work;
- read-only scheduled evidence governance.

### Missing before C3

- a versioned active-profile registry separate from an individual profile;
- an explicit provider adapter owning official hosts and native-surface
  mappings;
- distinct `current`, `revalidation_due`, `expired`, `source_drift`, and
  `invalid` lifecycle states;
- a committed evidence-set digest independent of timestamps and reviewer
  state;
- a non-authoritative candidate workflow;
- deterministic candidate comparison and changed-component reporting;
- a separately protected `chatgpt_action`;
- provider-isolation, time-boundary, registry-substitution, and candidate
  mutation tests;
- a current-time CI path that warns distinctly when revalidation is due and
  fails on expired, invalid, or drifted evidence.

### Incompatible with C3

C2 embedded its single profile identity, provider allowlist, and reviewed
profile builder in one module. That remains valid historical C2 evidence but
cannot own the future multi-profile lifecycle. C3 therefore supersedes C2 as
the live-action gate while preserving the C2 profile and its seal unchanged.

### Debt outside C3

- no second provider has been researched or registered;
- no automatic official-document acquisition is implemented;
- no provider-issued immutable page revision identifier is available in the
  reviewed sources;
- no ChatGPT credential, Tunnel, Plugin, browser, or live-call workflow is
  authorized;
- public provider-package reorganization remains a separate compatibility
  decision.

## Acquisition and decision boundary

C3 separates two processes:

```text
non-deterministic official review
    OpenAI Docs interface
    -> bounded repository-authored claims
    -> candidate JSON outside Git

deterministic repository decision
    candidate schema + adapter validation
    -> canonical claim/evidence/profile SHA-256
    -> comparison with active reviewed profile
    -> independent review
    -> deliberate profile + registry commit
    -> offline fail-closed gate
```

The runtime never fetches documentation, opens a browser, or observes an
account. Remote page text is not committed. The repository stores bounded
canonical claims, their digests, review times, and exact source URLs.

A candidate is always `candidate`, never `reviewed`. Candidate comparison
denies every protected action even when the candidate is byte-for-byte
equivalent apart from timestamps. Changed claims, sources, conclusion, or
support state produce `source_drift` and require independent review.
No command automatically rewrites the active profile or registry.

## Official OpenAI evidence

All four pages were fetched through the official OpenAI documentation
interface at the review time. The conclusion is a repository-authored
inference across the exact native-surface contract; it is not a quotation.

| ID | Official source | Bounded canonical finding | Claim SHA-256 |
|---|---|---|---|
| `plugin_connection_route` | [Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt) | MCP evaluation enables developer mode, registers under Plugins, and selects the connection in a new conversation; the page does not independently establish native Chat availability. | `95797da82b7ba96e1d33be92f732cc60e55f092df1cf709476aa9020cfbab171` |
| `plugin_packaging_surface` | [Package your plugin](https://developers.openai.com/plugins/build/plugins) | Local MCP plugin setup registers through Plugins and assigns plugin creation to Work or Codex; no custom/local MCP path for Chat is documented. | `352ec0338b62af87e37dc3f2cd770e67beeab82ba20a3ba31046b05b33fe39df` |
| `plugin_surface_availability` | [Plugins](https://learn.chatgpt.com/docs/plugins) | Plugins can contain MCP servers/tools, are available with Work, and are explicitly unavailable in Chat. | `b72e809c4a9d3efc6946cd8c3987f9b1d142c6f844795f863a5c7874175f6699` |
| `secure_mcp_tunnel_route` | [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) | Tunnel is transport for supported surfaces; ChatGPT setup creates a developer-mode app through Plugins and does not override Chat exclusion. | `ab639703332ff43221112dec29cd993ca9fee97727e04285393614d0d57e6e02` |

The profile conclusion digest is
`6321434a6919246ec1c8dc2476fd85191dcd08f337b764be0ac005cae1693d82`.
The evidence-set digest is
`89f8539212d3b2ab52cbdf2fcd449a75cfe22262533f592a883359d9debe5b36`.
The complete profile digest is
`478d1651fa1b275d5158ff1fd56e1775b10a48fb650b3e2baef3808d36e357bd`.

## Registry and adapter contract

The active registry is
[`governance/c3-capability-registry.json`](../../governance/c3-capability-registry.json).
Its digest is
`eb95d8cc359b9bca6f30ae613b294dcc6247ace292ad49fab7f116a38c79631c`.

It contains exactly one adapter and one profile:

| Field | Exact value |
|---|---|
| Provider | `chatgpt` |
| Native surface | `chat` |
| Surface class | `conversational_chat` |
| Capability | `custom_or_local_mcp_tool_invocation` |
| Official hosts | `developers.openai.com`, `learn.chatgpt.com` |
| Support | `unsupported` |
| Reviewer state | `reviewed` |

The adapter is a minimal extension contract. A future provider must add its
own closed provider identifier, native-surface mapping, official-domain
allowlist, capability, source claims, review, threat model, tests, and seal.
No second provider exists in this registry. Surface-class equality is taxonomy
only and transfers no capability, policy, credentials, evidence, or test
result.

## Lifecycle and support are independent

| Lifecycle | Meaning | Gate result |
|---|---|---|
| `current` | reviewed evidence is before its warning boundary | support state is evaluated |
| `revalidation_due` | warning boundary reached, deadline not reached | all actions denied; warning reported |
| `expired` | deadline reached or passed | all actions denied; CI fails |
| `source_drift` | a valid profile differs from its reviewed registry/builder commitment, or a valid candidate changes evidence | all actions denied; independent review required |
| `invalid` | schema, digest, identity, URL, path, adapter, time, or registry invariant fails | all actions denied; CI fails |

Within `current`, support is evaluated separately:

- `supported` may pass only this capability gate; separate authorization and
  all C1 controls still apply;
- `unsupported` returns
  `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`;
- `unobservable` returns
  `BLOCKED_BY_OFFICIAL_EVIDENCE_AMBIGUOUS`.

Exact gate statuses are:

| Condition | Status |
|---|---|
| current, reviewed, supported | `READY_FOR_SEPARATE_BOUNDED_AUTHORIZATION` |
| current, reviewed, unsupported | `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE` |
| current, reviewed, unobservable | `BLOCKED_BY_OFFICIAL_EVIDENCE_AMBIGUOUS` |
| revalidation due | `BLOCKED_BY_OFFICIAL_EVIDENCE_REVALIDATION_DUE` |
| expired | `BLOCKED_BY_OFFICIAL_EVIDENCE_EXPIRED` |
| active source/profile drift | `BLOCKED_BY_OFFICIAL_EVIDENCE_SOURCE_DRIFT` |
| invalid schema, digest, identity, path, URL, registry, or time | `BLOCKED_BY_SECURITY_INVARIANT` |

The deadline is exclusive: evidence is `expired` exactly at
`2026-08-10T11:55:00Z`. The warning boundary is inclusive:
`revalidation_due` begins exactly at `2026-08-03T11:55:00Z`.

## Fail-closed action matrix

The gate decides every member of a closed action registry:

| Protected action | Current decision |
|---|---|
| `runtime_key_creation` | `false` |
| `tunnel_start` | `false` |
| `plugin_creation` | `false` |
| `browser_test` | `false` |
| `chatgpt_action` | `false` |

No mixed decision is valid. The C1 prepare, facade, Tunnel, and operator-step
entry points now import C3 before executing C1 logic. The fifth action covers
any future ChatGPT-side operation not already named by the first four.

## What the earlier C1 calls proved

Earlier bounded C1 operator cycles produced real correlation receipts for two
new synthetic test chats. Those receipts showed that, during their short
validity windows, a manually configured Plugin path invoked the one read-only
`systeme_local_connectivity_probe`, returned the matching challenge digest,
and matched local audit records. The observations recorded zero write tools,
zero high-risk tools, no existing-chat access, and `work_invoked=false`.

They did **not** prove:

- a currently supported native Chat product interface;
- a durable or reusable C1 final attestation;
- regular, production, or write-capable integration;
- conversation discovery, history access, or existing-chat detection;
- an internal model identifier or hidden routing state;
- that a time-bounded historical observation overrides current official
  product documentation.

Some C1 cycles expired before final attestation and all Runtime credentials
were revoked. C2 then identified the official Chat/Plugins incompatibility.
C3 preserves the historical correlations without promoting them into current
support.

## Operator commands

From a clean C3 branch:

```powershell
Set-Location 'D:\systeme-local-agent-gateway-github'
.\scripts\c3\Test-C3OfficialProfile.ps1
.\scripts\c3\Get-C3Lifecycle.ps1
.\scripts\c3\Test-C3Preflight.ps1
.\scripts\c3\Show-C3RevalidationSteps.ps1
```

These commands need no credential or transport variable. With the current
profile they report `current`, `unsupported`, and five denied actions.

After a future official-document review, create a candidate only in the
ignored `.systeme-local/c3` directory:

```powershell
.\scripts\c3\New-C3CandidateDraft.ps1 `
  -ReviewedAt '<UTC timestamp>' `
  -RevalidateAfter '<UTC timestamp>' `
  -OutputPath .systeme-local\c3\draft.json

# Edit only the bounded claims, conclusion, and typed support state in draft.json.

.\scripts\c3\Seal-C3Candidate.ps1 `
  -DraftPath .systeme-local\c3\draft.json `
  -OutputPath .systeme-local\c3\candidate.json

.\scripts\c3\Compare-C3Candidate.ps1 `
  -CandidatePath .systeme-local\c3\candidate.json
```

The draft copies current bounded claims without digests. The sealing step
strictly validates the draft and computes every claim, conclusion, evidence,
and profile digest. Both scripts restrict files to direct JSON children of
`.systeme-local/c3`, write UTF-8 without a BOM, and reject reparse-point inputs.
Draft and candidate files are ignored by Git. They are not active evidence.

## Exact future gate

A bounded live retest may be considered only after an official OpenAI source
explicitly establishes either:

1. Plugins containing custom/local MCP tools are available on native Chat; or
2. another documented custom/local MCP interface explicitly supports native
   Chat without Work.

A generic reference to “ChatGPT,” a Tunnel, a new conversation, developer
mode, account rollout, or a visible undocumented control is insufficient.

The changed candidate must then be independently reviewed, deliberately
promoted into both profile and registry, fully tested, sealed, and merged.
Only a `current` + `reviewed` + `supported` tuple may pass this capability
gate. Separate browser authorization, scoped credentials, revocation,
privacy, one-tool policy, audit correlation, and fresh live proof remain
mandatory.

## Privacy and network state

C3 performs documentation acquisition and offline repository checks only. It
does not open ChatGPT or Work, create a chat, or read history. It does not
inspect an existing conversation or access account/security settings. It does
not:

- read cookies/storage/private requests;
- create a Runtime key;
- create/start a Tunnel;
- create a Plugin;
- start a listener or invoke MCP;
- collect personal data.

Residual risk is official documentation changing between review and deadline.
The warning window, expiry, candidate drift state, registry commitments,
scheduled read-only governance, and mandatory human promotion bound that risk
without pretending to eliminate it.

## C4 runtime-enforcement ownership

C3 remains the sole authority for official capability evidence, candidate
comparison, lifecycle, and support. C4 consumes this decision and now owns
current runtime admission, effective tool derivation, receipts, and
process-local correlation replay protection.

C4 does not alter this profile, its registry, its deadlines, or its product
conclusion. A C4 allow is impossible while this C3 profile is
`unsupported`. See
[`chatgpt-web-c4-runtime-admission.md`](chatgpt-web-c4-runtime-admission.md).
