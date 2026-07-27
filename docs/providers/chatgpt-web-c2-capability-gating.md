# C2 ChatGPT-first Web official-capability gating

Status: `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`

Current action-gate owner: C3. C2 remains an immutable historical capability
snapshot. See the
[C3 evidence lifecycle](chatgpt-web-c3-evidence-lifecycle.md) for the active
registry, candidate comparison, lifecycle states, and five-action gate.

Reviewed: `2026-07-27T01:40:00Z`

Revalidate no later than: `2026-08-10T01:40:00Z`

Stacked base: exact C1 commit
`2aee36fdfa3d20c23acdc75eb3348bc54536ef4f` from draft
[PR #67](https://github.com/Cheurteenyt/systeme-local/pull/67)

The exact commands, outcomes, limitations, and final validation results are in
the [C2 test and evidence ledger](chatgpt-web-c2-test-evidence.md).

## Question and exact answer

C2 asks one product question:

> Can any officially documented ChatGPT Chat surface invoke a custom or local
> MCP tool without using ChatGPT Work?

The reviewed answer is **no**. OpenAI documents MCP registration and tunnel use
through developer-mode apps in **Plugins**. The current official Plugins
overview explicitly says that Plugins are available with ChatGPT Work and are
not available in Chat. No reviewed public interface provides an alternative
custom/local MCP route for Chat.

This is a capability result, not a tunnel failure. C1 previously established
bounded local and transport readiness. Secure MCP Tunnel transports requests
for supported products and surfaces; it does not make an unsupported Chat
surface supported.

## Official capability profile

The committed, reproducible profile is
[`governance/c2-official-capability-profile.json`](../../governance/c2-official-capability-profile.json).
Its SHA-256 is
`fa6f144d6867c00e995c791182cc78e7aabcc781ff6462bf885be26faa706305`.

| Field | Exact value |
|---|---|
| Provider | `chatgpt` |
| Native surface | `chat` |
| Provider-neutral surface class | `conversational_chat` |
| Capability | `custom_or_local_mcp_tool_invocation` |
| State | `unsupported` |
| Consultation | `2026-07-27T01:40:00Z` |
| Revalidation deadline | `2026-08-10T01:40:00Z` |

The surface class is taxonomy, not capability inheritance. It allows future
profiles to describe comparable interaction shapes without inheriting
ChatGPT's sources, state, policy, receipts, or test results.

### Canonical official sources

| Source | Canonical finding | Summary SHA-256 |
|---|---|---|
| [Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt) | The MCP flow registers a server in developer mode through Plugins and selects it in a new conversation. The page does not independently establish Chat availability. | `13ee146bc6fa554930e326cc818fc94890d68078b7aed926cfefcda4a735fa6d` |
| [Package your plugin](https://developers.openai.com/plugins/build/plugins) | Local plugin creation is assigned to Work or Codex, and local marketplace availability varies by surface. No Chat MCP path is established. | `50b40038cdc053b261289a02864ebb3c7099ced14eba7c19829802b9ee1ee93f` |
| [Plugins](https://learn.chatgpt.com/docs/plugins) | Plugins may contain MCP servers and tools, are available with ChatGPT Work, and are explicitly unavailable in Chat. | `565764914bdeb2b78c925750ffc7e909f49faac9b16cffe7b5cd5967b06f70fd` |
| [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) | ChatGPT connects a private MCP server by creating a developer-mode app in Plugins. Tunnel transport does not override surface availability. | `6843f9afa3f23cac1f382199bc97e1adfc6555226ad20d6922ea2f23f83cb737` |

Canonical summaries are repository-authored interpretations of the cited
official text, not verbatim snapshots. Each summary digest and the full profile
digest are recomputed by the builder. Unknown JSON fields, changed summaries,
changed digests, unofficial hosts, duplicate sources, unsorted sources,
mismatched timestamps, or windows longer than 14 days are rejected.
The CLI additionally requires the committed profile to match the reviewed
builder byte for byte. A structurally valid substituted profile with a newly
computed digest is still `BLOCKED_BY_SECURITY_INVARIANT`.

## Typed state and status mapping

| Evidence condition | Capability state | Exact C2 status | Live actions |
|---|---|---|---|
| Official documentation explicitly supports the exact Chat/custom-or-local-MCP tuple and the profile is current | `supported` | `COMPLETE_CHATGPT_CHAT_CAPABILITY_GATE_VERIFIED` | Preflight may allow; all other authorization and safety gates remain |
| Official documentation explicitly excludes the exact tuple | `unsupported` | `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE` | all denied |
| Official documentation cannot establish the exact tuple | `unobservable` | `BLOCKED_BY_OFFICIAL_EVIDENCE_DRIFT` | all denied |
| Revalidation deadline reached | prior state retained as historical data | `BLOCKED_BY_OFFICIAL_EVIDENCE_DRIFT` | all denied |
| Profile, digest, provider, surface, time, or schema invariant fails | no trusted state | `BLOCKED_BY_SECURITY_INVARIANT` | all denied |
| Required repository validation fails | no promotion | `BLOCKED_BY_TEST_FAILURE` | all denied |

`unsupported` and `unobservable` are deliberately different. The current
Plugins statement makes this profile `unsupported`; C2 does not use
`unobservable` merely because an operator account lacks a visible control.

## Protected action gate

The preflight decides every member of a closed action registry:

```text
runtime_key_creation = false
tunnel_start = false
plugin_creation = false
browser_test = false
```

The gate performs no network request and reads no browser or credential state.
It validates only the committed profile and current UTC time. The C1 live entry
points imported C2 at this historical commit. On the C3 descendant they import
the stronger C3 registry/lifecycle gate before their existing logic. Both the
C2 snapshot and the current C3 profile stop with
`BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`.

The repository cannot stop a person from manually creating a Platform key
outside the project. The enforced operator contract therefore requires C2
preflight before displaying or following any Runtime-key, Tunnel, Plugin, or
browser instruction. Bypassing the gate is outside the reviewed workflow and
cannot produce C2 or C1 evidence.

## Operator procedure

From a clean C2 worktree:

```powershell
Set-Location 'D:\systeme-local-agent-gateway-github'
.\scripts\c2\Test-C2OfficialProfile.ps1
.\scripts\c2\Test-C2Preflight.ps1
.\scripts\c2\Show-C2OperatorSteps.ps1
```

For the current profile, these commands report the exact blocked status and
deny all four actions. The operator must then stop. Do not:

- create or paste a Runtime API key;
- create, edit, or start a Tunnel;
- enable Developer mode or create a temporary Plugin;
- open ChatGPT for a live test;
- open or test Work;
- open history, the sidebar, or an existing conversation;
- inspect cookies, storage, private requests, private browser state, or
  Security/Account settings.

No secret or transport environment variable is needed to run C2 preflight.

## Revalidation procedure

Revalidation is documentation-only until the exact capability becomes
officially supported:

1. Fetch all four cited pages through the official OpenAI documentation
   interface.
2. Confirm the native surface named by each relevant instruction. A generic
   reference to “ChatGPT” or “new conversation” is insufficient when the
   Plugins overview continues to exclude Chat.
3. Search official OpenAI documentation for another public supported
   custom/local MCP interface that explicitly names Chat.
4. Rewrite canonical summaries from the current text, recompute all SHA-256
   values, and choose exactly `supported`, `unsupported`, or `unobservable`.
5. Set a new consultation timestamp and a deadline no more than 14 days later.
6. Run the full local and CI suites and regenerate the deterministic C2 seal.
7. Only a current `supported` profile may make preflight return an allowed
   decision. A separate authorization must still precede any live action.

Visible account rollout, plan entitlement, or an undocumented UI control cannot
upgrade the official capability state. Source disagreement, deleted pages, or
ambiguous wording is `unobservable` and fails closed.

## Privacy and threat boundary

C2 uses official public documentation and local repository files only. It does
not control a browser, enumerate tabs, visit ChatGPT, inspect account settings,
read existing chats, create synthetic chats, or access personal content. It
does not create credentials, processes, listeners, tunnels, apps, prompts, or
tool calls.

Threats addressed:

- transport support mistaken for surface support;
- generic “ChatGPT” wording mistaken for the native Chat surface;
- stale product documentation promoted to current evidence;
- changed summaries paired with old digests;
- an unofficial host substituted for OpenAI documentation;
- unknown or future provider values silently accepted;
- an unsupported or unobservable state partially enabling live actions;
- C1 scripts bypassing the C2 gate.

Residual risk is official documentation changing between consultation and the
deadline. The 14-day maximum window, scheduled evidence-governance check, and
fail-closed expiry bound that risk. The profile proves a documented capability
state, not every private rollout or future product behavior.

## ChatGPT priority and future AI Web providers

ChatGPT remains the only implemented Web capability profile and the current
project priority. C2 generalizes only:

- provider identifiers;
- provider-native surface plus a surface-class label;
- official capability identifiers and three-state evidence;
- source commitments and freshness;
- closed live-action decisions.

No second provider, adapter, browser flow, credential type, revocation flow, or
capability claim is implemented. A later provider must add independent
official sources, native-surface semantics, threat analysis, tests, evidence,
and a deterministic seal. ChatGPT evidence must never be copied into that
profile.
