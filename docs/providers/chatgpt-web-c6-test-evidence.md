# C6 test and evidence ledger

Status: local implementation and public-doc acquisition validated; final
branch seal and remote CI pending

Recorded at: `2026-07-27`

## Claim under test

C6 must retrieve only the reviewed official documentation sections, detect
drift deterministically, and prepare at most a review-only candidate. It must
never promote evidence, grant ChatGPT capability, expose a tool, or perform a
live provider action.

## Evidence classes

| Class | What it proves | What it does not prove |
|---|---|---|
| deterministic unit tests | schemas, normalization, comparison, lifecycle, output paths, protocol rejection, and fail-closed decisions | current network availability or official page contents |
| mocked transport tests | exact read-only request shape and redirect, size, content-type, SSE, JSON-RPC, and MCP failure handling | behavior of an unmocked remote service |
| public Docs MCP acquisition | the four bounded official sections matched their reviewed fingerprints at execution time | future source stability or independent promotion |
| PowerShell safety checks | no configured transport secrets, tunnel process, or listeners; safe local output and cleanup | ChatGPT surface capability |
| repository validation | code, docs, dependencies, Rust, and governance remain internally consistent | provider authorization |

## Deterministic Python tests

The dedicated C6 suite covers:

- exact committed policy generation and C3 profile/registry binding;
- strict unknown-field rejection;
- approved endpoint, host, route, anchor, ordering, uniqueness, and review
  window constraints;
- Unicode NFC, newline, whitespace, blank-line, size, and NUL handling;
- exact fingerprint plus semantic-marker comparison;
- unchanged acquisition producing only a sealed C3 candidate;
- one-byte drift and missing-marker cases producing no candidate;
- receipt digest tampering;
- strict SSE framing, JSON-RPC identifier, result, error, and text-block
  validation;
- read-only request construction with no authentication;
- redirect, oversized envelope, invalid content type, and tool error
  rejection;
- safe output containment and reparse defense below `.systeme-local/c6`;
- refusal when process-local transport or runtime secrets exist;
- deterministic CLI policy and offline status output;
- due and expired lifecycle behavior;
- six protected action denials and zero promotion authority on every result.

Initial focused result: `17 passed`.

The inherited C5 integration and initial C6 suites were also run together:
`24 passed` before the seal suite was added. The known Windows pytest
temporary-directory `PermissionError`
occurred only in the post-success `atexit` callback and did not change the
zero process exit code.

Final full-suite counts are recorded in the pull-request closeout rather than
invented before completion.

## Pre-seal repository validation

The clean covered-head candidate was prepared after these local results:

- Python: `1,049 passed`, `6 skipped`, and only the tag-dependent final C6
  seal test deliberately deselected; total coverage `85.25%`;
- Ruff: all checks passed; format ratchet reported 42 legacy files, 8 changed
  Python files, and zero new debt;
- Mypy: 8 changed Python files and zero new diagnostics or waivers;
- documentation: 52 Markdown files passed link checks and deterministic
  evidence governance passed;
- Python dependency audit: 76 resolved packages and no known vulnerability;
- PowerShell: 58 repository scripts/modules parsed successfully;
- Rust: check, formatting, Clippy with warnings denied, workspace tests,
  doctests, documentation with warnings denied, and RustSec audit passed;
- manifest: all 34 covered paths matched the worktree exactly;
- secret-like scan: zero matches in the covered change set;
- C5 historical integration verification and current evidence-date governance
  passed;
- `git diff --check` passed.

The Windows pytest temporary-directory cleanup warning occurred only in the
post-success `atexit` callback. It did not change the zero exit code or test
counts.

## Public official-source acquisition

The hardened uncredentialed read-only acquisition ran at
`2026-07-27T15:12:39.842869Z`, streamed only
`https://developers.openai.com/mcp`, and requested the four policy routes.

Observed outcome:

- `plugin_connection_route`: unchanged;
- `plugin_packaging_surface`: unchanged;
- `plugin_surface_availability`: unchanged;
- `secure_mcp_tunnel_route`: unchanged;
- report: `unchanged`;
- candidate generated: true;
- candidate can change gate: false;
- promotion allowed: false;
- independent review required: true;
- raw content persisted: false;
- live actions allowed: false;
- all five C3 protected actions: false;
- derived C4 matrix: six denials and zero effective tools.

The bounded receipt SHA-256 was
`e17ce6e9b01dfc25fd12469dc9043cae1d7de6f4803166b02192a5d363c062ea`.
The ephemeral candidate SHA-256 was
`aa84fe4bdf700cce81317874c7c5acab2a24bd77805cb6d6db3f7d8f50b300ea`;
it was review input only and was deleted with the receipt.

The run did not create or read a Runtime key, Tunnel ID, provider secret,
Plugin, ChatGPT chat, Work surface, history entry, existing conversation,
account/security setting, browser-private value, listener, or tunnel process.
The local candidate and receipt were deleted after inspection.

## PowerShell results

All six C6 scripts parse successfully. With the deliberate dirty-tree override
used only while developing the uncommitted branch:

- prerequisites returned `ready`;
- the policy lifecycle was `current`;
- the C3 final status remained
  `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`;
- no sensitive process variable was set;
- ports 8765 and 8766 had no listeners;
- no `tunnel-client` process existed;
- live official revalidation returned four unchanged observations;
- cleanup removed only `.systeme-local/c6` receipt/candidate state.

Cleanup did not touch committed governance files, C3/C4 evidence, runtime
state, credentials, chats, Plugins, or browser data.

## Negative and mutation expectations

The following outcomes are fail-closed:

| Mutation or failure | Required result |
|---|---|
| policy or C3 digest substitution | `policy_invalid`, no candidate |
| unknown policy/report field | validation rejection |
| unapproved host, endpoint, fragment, or duplicate route | validation rejection |
| redirect or HTTP failure | nonzero failure receipt |
| response above 262,144 bytes | `response_too_large` |
| invalid content type or SSE | typed nonzero failure |
| wrong JSON-RPC ID, error object, or multiple text blocks | typed nonzero failure |
| normalized document above 16,384 bytes or containing NUL | `document_invalid` |
| fingerprint or marker drift | `source_drift`, no candidate |
| due policy | warning, all actions denied |
| expired policy | nonzero exit, all actions denied |
| output outside `.systeme-local/c6` | refusal |
| configured transport/runtime secret | refusal before network |

## Remaining closeout

Before C6 can be considered complete:

1. run the complete Python, typing, formatting, documentation, dependency,
   secret, PowerShell, Rust, listener, process, and repository suites;
2. create and verify the reproducible C6 manifest, binary-diff commitment,
   framed-tree commitment, one-file seal commit, and annotated evidence tag;
3. publish a focused draft pull request;
4. require final-head CI and manual evidence governance to pass;
5. keep the pull request unmerged until that independent remote validation is
   green.

No result in this ledger authorizes a ChatGPT live test.
