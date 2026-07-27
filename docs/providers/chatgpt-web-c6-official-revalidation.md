# C6 official capability revalidation

Status: `implemented`; official sources `unchanged`; review-only candidate;
runtime gate unchanged

Reviewed at: `2026-07-27T14:42:00Z`

Revalidate after: `2026-08-10T14:42:00Z`

Current ChatGPT result:
`BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`

## Purpose

C6 automates the narrow activity that C2 and C3 intentionally left manual:
retrieving the reviewed official documentation sections, normalizing them,
detecting exact drift, and preparing a bounded candidate for independent
review.

C6 is provider-neutral in its contracts, but the production policy contains
only the ChatGPT native Chat profile. It does not add a second provider,
discover provider capabilities, infer support from a user interface, or turn
provider-neutral code into portable evidence.

The current official sources still route custom or local MCP use through
ChatGPT Plugins, while Plugins are unavailable in Chat. The C3 profile
therefore remains `unsupported`; C4 continues to deny all six protected
actions and derives zero effective tools.

## Trust boundary

```text
committed C6 policy + exact C3 registry/profile digests
    -> fixed public OpenAI Docs MCP endpoint
    -> four allowlisted URL + anchor requests
    -> bounded SSE and JSON-RPC validation
    -> in-memory Markdown normalization
    -> exact SHA-256 + required-marker comparison
    -> unchanged | source_drift | acquisition failure
    -> review-only receipt and optional C3 candidate
    -> independent review remains mandatory

reviewed C3 registry
    -> unchanged by C6
    -> C4 admission remains six denials and zero tools
```

Fetched content is untrusted input. It can report drift or reproduce the
already reviewed unsupported candidate, but it cannot modify the committed C3
registry, change the current gate, expose a tool, start a live action, or
authorize promotion.

Every receipt fixes `candidate_can_change_gate=false`,
`promotion_allowed=false`, `raw_content_persisted=false`, and
`live_actions_allowed=false`. Its five C3 protected-action decisions are
false; the derived C4 matrix remains six denials and zero effective tools.

## Bound policy

The canonical policy is
[`governance/c6-revalidation-policy.json`](../../governance/c6-revalidation-policy.json).
It binds:

- policy SHA-256
  `602e4fc6313f0d7e95c3255fbaad47c77d65dc2b28c47406b6c9c323fdc4d8dd`;
- C3 registry SHA-256
  `9567dd0bbb9ec80d6bf24ea86048f6229f9c956731053b1191208ac6bcecdd62`;
- C3 profile SHA-256
  `512d26961dd33429850c2599b1c970be3910e990b92bc23aa759e92784f0dc3a`;
- identity `chatgpt` / `chat` / `conversational_chat` /
  `custom_or_local_mcp_tool_invocation`;
- the fixed endpoint `https://developers.openai.com/mcp`;
- a fourteen-day maximum review window and a seven-day warning window;
- `fetched_content_can_change_gate=false`;
- `automatic_promotion_supported=false`.

The source IDs, routes, normalized byte counts, and reviewed fingerprints are:

| Source ID | Official section | Bytes | Reviewed SHA-256 |
|---|---|---:|---|
| `plugin_connection_route` | [Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt#add-the-mcp-server) | 464 | `3cc37a424d4a5fe60e9f0921f253403794c717b8ece56e1ec24b423d823dc388` |
| `plugin_packaging_surface` | [Package your plugin](https://developers.openai.com/plugins/build/plugins#create-and-test-a-plugin-locally-with-an-mcp-server) | 2,620 | `28c1bc7403d2f21cec1aeff959a0450e0e85b21e2dbc46bcaf4b3859d6065d8c` |
| `plugin_surface_availability` | [Plugins overview](https://learn.chatgpt.com/docs/plugins#overview) | 2,682 | `1a2f67b7287610eb66162b2afcc24db7cb319f68281dbc970f2f334c9f751e7e` |
| `secure_mcp_tunnel_route` | [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels#connect-from-chatgpt) | 493 | `8b80437089c00abdb8d75a777ef3208746e87c7149feb7f9c6606c4555eed1dd` |

Required markers are deliberately short, bounded semantic checks. Exact
fingerprints remain the drift authority; markers cannot make changed content
look unchanged.

## Acquisition protocol

`OpenAIDocsMcpClient` performs one stateless, unauthenticated, read-only
`fetch_openai_doc` JSON-RPC call per policy source. It:

- uses only the exact reviewed HTTPS endpoint and source hosts;
- sends no authorization header, cookie, Runtime key, Tunnel ID, or provider
  secret;
- disables proxy environment inheritance with `trust_env=False`;
- rejects redirects;
- requires a supported SSE or JSON content type;
- streams and limits the response envelope to 262,144 bytes before buffering;
- validates the JSON-RPC identifier and rejects errors or multiple text
  blocks;
- limits normalized source content to 16,384 UTF-8 bytes;
- normalizes Unicode to NFC, line endings, trailing whitespace, and repeated
  blank lines;
- keeps the fetched document body in memory only;
- prints and optionally persists only bounded metadata, SHA-256 values, and
  the already reviewed candidate claims.

The live acquisition command refuses to run when any transport or runtime
secret is present in the process environment.

## Outcomes

### Unchanged

All source fingerprints and semantic markers match. C6 may generate a new C3
candidate that reproduces the already active support state and claims with a
fresh review window.

The candidate:

- is not the active profile;
- cannot change the gate;
- cannot be promoted by the acquisition command or workflow;
- requires an independent source review, code review, deliberate committed
  registry update, successor seal, and full CI.

### Source drift

At least one fingerprint or required marker differs. C6 reports the exact
bounded source IDs, creates no semantic candidate, exits nonzero, and keeps all
actions denied. Raw changed document content is not printed or persisted.

### Acquisition or policy failure

Invalid policy, HTTP failure, redirect, oversized response, invalid content
type, malformed SSE, malformed JSON-RPC, MCP tool error, or invalid document
produces a typed failure receipt, no candidate, a nonzero exit, and six
denials.

### Due or expired policy

`revalidation_due` warns without granting capability. `expired` exits
nonzero, even if every source remains byte-for-byte unchanged. A fresh
candidate still needs independent promotion.

## Operator commands

Deterministic offline verification:

```powershell
.\scripts\c6\Test-C6Prerequisites.ps1
.\scripts\c6\Get-C6Status.ps1 `
  -AsOf '2026-07-27T15:00:00Z'
```

Read-only official acquisition:

```powershell
.\scripts\c6\Invoke-C6OfficialRevalidation.ps1
.\scripts\c6\Show-C6ReviewSteps.ps1
```

Optional receipt and candidate files stay below `.systeme-local/c6`. Remove
them after review:

```powershell
.\scripts\c6\Clear-C6Temporary.ps1
```

These commands require a clean compatible repository unless the explicit
test-only dirty-tree override is used. They refuse configured transport
secrets, listeners on ports 8765/8766, and a running `tunnel-client`.

## Scheduled governance

The read-only
[`evidence-governance`](../../.github/workflows/evidence-governance.yml)
workflow runs daily and can be dispatched manually. It has only
`contents: read`, retrieves no repository credential into the checkout, emits
actionable GitHub warnings/errors, persists no candidate artifact, and has no
issue, pull-request, commit, tag, release, secret, or deployment permission.

Pull-request CI performs deterministic offline policy verification at
`2026-07-27T15:00:00Z`. Network acquisition remains in the scheduled/manual
governance job so ordinary tests do not depend on network state.

## Reproducible repository seal

[`governance/c6-change-manifest.json`](../../governance/c6-change-manifest.json)
enumerates the exact change set from accepted C5 `main`
`418112758d8675326835d9947ccce3a1b12f6f25`. The final
`governance/c6-change-seal.json` is created only after the covered head is
clean and committed. It binds:

- the canonical manifest SHA-256;
- the exact covered commit;
- a binary full-index Git diff SHA-256;
- a framed tree SHA-256 over path, mode, blob length, and blob bytes;
- the exact changed-file count;
- the immutable annotated tag
  `evidence/chatgpt-official-revalidation-c6-v1`;
- explicit true/false records for public-doc acquisition, raw persistence,
  automatic promotion, and provider live actions.

Both commitments exclude only the self-referential C6 seal. The tag must point
to a one-file final seal commit whose parent is the covered head. Pull-request
CI additionally requires the current C6 branch tree to equal the seal.
Historical CI verifies the immutable covered/tagged proof without blocking
later reviewed repository descendants.

Verification:

```powershell
.\scripts\c6\Test-C6Seal.ps1 -RequireCurrentTree -RequireClean
```

## Executed official revalidation

On `2026-07-27T15:12:39.842869Z`, the hardened streaming public Docs MCP acquisition
retrieved exactly the four reviewed sections. All four normalized byte counts
and SHA-256 fingerprints matched the committed policy, all required markers
were present, and the report state was `unchanged`. The report SHA-256 was
`e17ce6e9b01dfc25fd12469dc9043cae1d7de6f4803166b02192a5d363c062ea`;
the ephemeral review-candidate SHA-256 was
`aa84fe4bdf700cce81317874c7c5acab2a24bd77805cb6d6db3f7d8f50b300ea`.

The run generated only a review candidate, retained
`BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`, denied all six actions, exposed
zero effective tools, persisted no raw document content, and performed zero
ChatGPT, Plugin, browser, Work, conversation, credential, Tunnel, listener, or
provider-runtime action. The temporary local receipt and candidate were then
removed.

The complete test ledger is
[`chatgpt-web-c6-test-evidence.md`](chatgpt-web-c6-test-evidence.md).
