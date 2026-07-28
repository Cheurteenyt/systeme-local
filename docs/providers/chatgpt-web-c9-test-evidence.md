# C9 test and evidence ledger

Status: `partial` — the asymmetric Work-rich/Chat-manual implementation is
aligned and consolidated offline validation passed; all live proofs are pending

Issue: [#80](https://github.com/Cheurteenyt/systeme-local/issues/80)

Runbook:
[C9 ChatGPT file and image handoff](chatgpt-web-c9-attachment-handoff.md)

Decision:
[ADR 0016](../adr/0016-bind-one-sanitized-package-to-work-mcp-and-chat-manual.md)

## Evidence vocabulary

| State | Meaning |
|---|---|
| `implemented` | code or an operator surface exists in the current C9 tree |
| `offline_verified` | a named local test exercised the behavior; no provider result is implied |
| `live_pending` | a real installed runtime or visible ChatGPT observation is still required |
| `blocked` | a required live capability was unavailable or an invariant failed |

No row becomes `live_verified` from documentation, screenshots, a plan name,
test doubles, unit tests or UI appearance alone.

## Immutable dependency

C9 descends from the annotated C8 evidence tag:

```text
tag:    evidence/chatgpt-work-live-c8-v1
target: bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5
status: COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED
```

This establishes a historical, reviewed Work transport dependency only. It
does not provide a reusable C9 grant, attachment proof, local-AI proof or
normal-Chat result.

## Official product evidence

- [Plugins](https://learn.chatgpt.com/docs/plugins) explicitly says Plugins
  are not available in Chat.
- [Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt)
  documents connection selection in a new conversation on a supported plugin
  surface.
- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
  documents the temporary Tunnel and Runtime-key path.
- The [Plugin reference](https://developers.openai.com/plugins/reference)
  permits model-visible tool-result `content` arrays.
- The [Model Context Protocol](https://learn.chatgpt.com/docs/extend/mcp)
  defines the protocol boundary.

Therefore C9 tests:

1. one rich Plugin/MCP call in Work;
2. one distinct visible manual file handoff in normal Chat.

The sources do not authorize a normal-Chat Plugin/MCP claim. They also do not
prove that Work accepts and interprets C9's exact `ImageContent` plus
embedded-resource result. That behavior remains live-pending.

## Accepted proof taxonomy

| Proof | Required transport | May claim | Must not claim |
|---|---|---|---|
| local-AI | literal-loopback installed runtime | exact sanitized PNG and TXT were inspected and both nonces reproduced | runtime privacy settings were independently detected |
| Work | one reviewed Plugin/MCP connection and rich result | exact admitted local tool call correlated to Work, endpoint, tool, cycle and audit | internal ChatGPT app ID was verified |
| normal Chat | one operator file-picker attachment in a new visible conversation | exact approved PNG and TXT were manually transferred and visibly consumed | MCP/app/local-endpoint invocation or autonomous delivery |

These receipts are non-interchangeable. Final C9 success requires one of each.

## Current implementation inventory

The C9 tree contains foundations for:

- generated synthetic PNG and strict UTF-8 TXT fixtures with independent
  nonces;
- bounded byte-level inspection, sanitization and metadata stripping;
- canonical descriptors/manifests and private mutable byte ownership;
- literal-loopback local-AI adapter and strict two-nonce verification;
- HMAC-bound installed-runtime observation;
- dynamic zero-or-one-tool MCP registry for Work;
- `systeme_local_attachment_handoff`;
- standard MCP `ImageContent` plus embedded UTF-8 resource rendering;
- metadata-only task/audit results and transactional renderer cleanup;
- private short-lived export, at-most-once picker claim and cleanup;
- bounded negative tests, stop/revocation controls and repository sealing.

The prior dual-rich Work-and-Chat proof model is superseded. Operator scripts,
proof models and final attestation treat the Chat transfer as manual evidence
only. No live run is allowed until the consolidated offline suite and reviewed
draft PR are green.

## Offline validation map

The final clean-commit snapshot must run the complete applicable suite.

| Area | Test modules | What passing may establish offline |
|---|---|---|
| input identity and sanitization | `tests/test_c9_attachment_security.py`, `tests/test_c9_synthetic_fixtures.py` | exact bounded fixture, sanitization, metadata removal, drift and link/reparse/hard-link rejection |
| private Chat handoff | `tests/test_c9_private_state.py`, `tests/test_c9_manual_export.py` | private ephemeral storage, TTL, at-most-once claim, ACL/mode checks, hash revalidation and cleanup |
| local AI | `tests/test_c9_local_ai.py`, `tests/test_c9_runtime_startup.py` | loopback request contract, bounded response, nonce validation, runtime-observation binding and startup refusal |
| Work admission and lease | `tests/test_c9_live_cycle.py`, `tests/test_c9_handoff_runtime.py` | fresh Work grant, atomic approval, one-use authority, expiry and replay rejection |
| Work tool and rich renderer | `tests/test_c9_mcp_tool.py`, `tests/test_c9_work_bridge.py`, `tests/test_mcp_rich_result.py` | one strict Work tool, standard rich blocks, metadata preservation, byte ceiling and transactional failure |
| control and evidence | `tests/test_c9_control.py`, `tests/test_c9_control_api.py`, `tests/test_c9_attestation.py`, `tests/test_c9_seal.py` | authenticated control, transport-specific receipt binding, revocation, attestation and seal invariants |
| trusted execution and scripts | `tests/test_c9_git.py`, `tests/test_c9_scripts.py`, `tests/test_c9_live_scripts.py`, `tests/test_c9_script_hardening.py` | bounded Git environment, ACL/path boundary, secret lifecycle, command surface and fail-closed orchestration |
| documentation | `tests/test_c9_docs.py`, `tests/test_documentation_governance.py` | official-surface rule, claim separation, runbook order and link integrity |

No numerical snapshot is final until it comes from the frozen clean C9 commit
after the consolidated offline suite is green. Earlier dual-rich counts are
development history only and must not be copied into the final evidence table.

## Consolidated offline validation snapshot

The following local results were obtained on 2026-07-28 immediately before
freezing the reviewed draft-PR commit. They establish only the offline
contract described above. They do not increment any live counter.

| ID | Validation | Result |
|---|---|---|
| `C9-Q01` | exact C9 matrix: `tests/test_c9_*.py` plus `tests/test_mcp_rich_result.py` | PASS: 324 passed, 8 conditional skips, 0 failed |
| `C9-Q02` | complete Python suite with coverage | PASS: 1,464 passed, 14 conditional skips, 84.07% coverage, exit 0 |
| `C9-Q03` | Ruff lint plus worktree format ratchet | PASS: lint clean; 42 changed Python files; 0 new format-debt files |
| `C9-Q04` | worktree mypy ratchet | PASS: 42 changed Python files; 0 new diagnostics |
| `C9-Q05` | all 25 C9 PowerShell files parsed by the Windows PowerShell AST parser | PASS: 0 parse errors |
| `C9-Q06` | Markdown links, documentation contracts and deterministic evidence governance | PASS: 61 Markdown files; 30 focused documentation tests; governance valid |
| `C9-Q07` | Rust workspace check, format, Clippy with warnings denied, tests, doctests and rustdoc with warnings denied | PASS: 106 tests, 0 failed; doctests and documentation clean |
| `C9-Q08` | locked Python and Rust dependency audits | PASS: no known Python vulnerability; 73 Rust dependencies scanned against 1,170 advisories with no vulnerability |
| `C9-Q09` | historical C3/C4/C6/C7/C8 gates and evidence seals | PASS: prior unsupported-Chat and sealed-Work boundaries remain intact |
| `C9-Q10` | whitespace and bounded credential-pattern review | PASS: no patch whitespace error, Runtime-key-shaped value or Tunnel-ID-shaped value; the sole assigned-secret-shaped match is an explicit synthetic cleanup fixture |

One deliberately parallel full-suite attempt caused the existing
`test_audit_anchor_cli` subprocess to return no diagnostic under concurrent
Windows load. The exact test then passed alone (`1/1`), its module passed
(`3/3`), and the authoritative serial full-suite run produced `C9-Q02`.
This was a validation-run contention artifact, not accepted as a passing
result by itself.

After successful pytest exit, Windows emitted the already documented
`pytest-current` temporary-directory cleanup `PermissionError`. It occurred
in an `atexit` callback after the exit code and did not change any test
result. The eight C9 skips are platform or optional-tool conditions such as
unavailable link primitives and local PSScriptAnalyzer; CI installs the
pinned analyzer and runs the dedicated Windows suite.

## Offline claims and non-claims

Passing offline tests may establish:

- exact package identity across the Work manifest and manual Chat manifest;
- no arbitrary-file enumeration or public path/byte disclosure;
- correct local-AI request construction and nonce checking against controlled
  servers;
- one read-only Work tool and valid standard MCP rich-content shapes;
- private export permissions, one-use path claim and cleanup;
- replay, mutation, expiry, wrong-transport and cross-proof rejection;
- final-attestation and seal invariants.

They cannot establish:

- the identity or privacy settings of an installed local runtime;
- that a real local model inspected both exact files;
- current Work entitlement, quota or app visibility;
- that Work invoked the tool or interpreted either rich block;
- that normal Chat consumed the manually attached files;
- an internal app identifier;
- a provider response, post-revocation result or C9 success.

## Live evidence status

No fresh C9 browser authorization, Runtime key, Tunnel, Plugin connection,
manual Chat export or provider action is recorded.

| Live item | Current value |
|---|---|
| fresh C9 authorization accepting both transport legs | absent |
| installed-runtime observation | `0/1` |
| real local-AI inference | `0/1` |
| Runtime key created | `false` |
| Tunnel started | `false` |
| temporary Work Plugin/MCP connection created | `false` |
| reviewed Work app visibly selectable | unobserved |
| new synthetic Work task created | `0/1` |
| qualifying Work rich call | `0/1` |
| private Chat handoff export created | `0/1` |
| new synthetic normal Chat conversation created | `0/1` |
| qualifying normal-Chat manual handoff | `0/1` |
| negative live observations | absent |
| Work Plugin connection removed | not applicable yet |
| Runtime key revoked | not applicable yet |
| manual export cleaned | not applicable yet |
| C9 final attestation | absent |
| C9 repository seal | absent |
| C9 success claim | absent |

## Required qualifying live evidence

### Installed local-AI proof

The cycle must retain metadata-only commitments showing:

- one fresh HMAC-bound operator observation for the intended installed
  runtime;
- executable basename and digest plus operator-declared product/version/PID;
- exact endpoint/model commitments;
- logging and request-persistence declarations;
- one bounded inference over both exact sanitized inputs;
- exact reproduction of both independent nonces;
- no raw bytes, paths, prompts, responses or nonces in public evidence.

A controlled HTTP server is not sufficient.

### Work proof

The Work counter becomes `1/1` only if:

- Work was explicitly selected;
- exactly one new synthetic Work task was created;
- the reviewed connection was visibly selected;
- `systeme_local_attachment_handoff(surface="work")` was invoked once;
- the result contained one image and one embedded UTF-8 resource;
- the visible response reproduced both nonces;
- the response, task, descriptor, package, lease, cycle, grant and local audit
  record all correlate.

The receipt may bind the operator-visible app label, exact local endpoint,
tool, cycle and grant. It must set the internal-app-ID claim to false or
unobservable.

### Normal-Chat manual proof

The Chat counter becomes `1/1` only if:

- normal Chat was explicitly selected after Work;
- exactly one new synthetic Chat conversation was created;
- exactly one owner-only, unexpired export of the approved package existed;
- the picker paths were claimed once by the authenticated local caller;
- identity and content hashes were revalidated immediately before release;
- the operator attached exactly the approved PNG and TXT once;
- the visible response reproduced both nonces;
- the response binds the exact manual Chat manifest and export claim;
- no Work switch, Plugin/MCP claim, private browser access or undocumented
  interface was used.

The receipt must explicitly state that no Chat app, MCP tool or local endpoint
invocation was proven.

### Authorization refusal

If the user does not explicitly authorize the manual normal-Chat handoff, or
if the visible file picker is unavailable, record:

```text
normal_chat_manual_handoff: 0/1
overall_status: PARTIAL/BLOCKED
```

A successful Work result may remain valid partial evidence but cannot create
a complete C9 attestation.

## Required negative evidence

The parameterless bounded negative suite from the final clean commit must
cover at least:

- no Work tool before fresh admission and exactly one after it;
- malformed handoff IDs, unknown fields and non-Work tool surfaces;
- Work replay, cross-task use and a second/third Work call;
- expired/tampered observation, manifest, approval, lease, grant and response;
- wrong, partial, swapped or oversized nonce proofs;
- unsafe input, path drift, link/reparse/hard-link substitution and
  unsupported formats;
- remote/authenticated/redirected/proxied local-AI endpoints and malformed,
  oversized or late responses;
- renderer metadata overwrite, invalid rich shapes, oversize output and
  pre-return failure;
- manual export replay, expiry, substitution, permission failure and cleanup;
- a Chat manual receipt being promoted to MCP/app/local-endpoint evidence;
- an internal app ID being claimed from a visible label;
- absence of arbitrary file, write, command, secret, real-evidence and
  protocol-v2 capabilities.

External post-revocation observations do not belong in the automated receipt.

## Revocation and final evidence

A successful cycle must additionally prove:

- facade and Tunnel stopped and ports closed;
- dynamic Work admission revoked and all leases/buffers removed;
- manual Chat export and picker paths removed;
- temporary Work Plugin/MCP connection removed;
- fresh Runtime key revoked;
- prior Work route and local control route unreachable;
- no false post-revocation Chat-app check, because normal Chat had no app leg;
- final attestation HMAC verified before repository sealing and private
  cleanup.

The final attestation must reject:

- only one qualifying transport;
- a manual Chat handoff represented as MCP or app evidence;
- a Work rich result represented as Chat evidence;
- more than one task/conversation;
- a stale or simulated installed-runtime proof;
- missing export cleanup, revocation or post-revocation observations;
- any “same internal app on Work and Chat” claim.

## Versioned evidence hygiene

The repository may retain only typed metadata, hashes, bounded timestamps,
counts, status literals and reviewed source/commit commitments.

Never commit:

- source or sanitized attachment bytes;
- cleartext nonces;
- local-AI request/response bodies;
- provider response bodies;
- file-picker paths or private export contents;
- Runtime keys, Tunnel IDs or Plugin connection identifiers;
- browser cookies, storage, private requests or conversation identifiers;
- audit bodies or process-local secret values.

## Current conclusion

C9 currently has an aligned and offline-testable product contract, not a live
success.
Normal Chat is a bounded manual handoff surface, not a Plugin/MCP surface.
Work rich-host behavior, the installed local runtime and both visible
provider consumptions remain live questions.

The next legitimate transition is:

```text
freeze one owner-only clean commit
    -> run and record the consolidated offline suite
    -> obtain fresh bounded authorization for Work MCP + Chat manual handoff
    -> perform one real installed local-AI inference
    -> perform one Work rich MCP call
    -> perform one normal-Chat manual file handoff
    -> clean export, revoke, attest, seal and clean
```

If Work rejects the rich result or the manual Chat handoff is not authorized,
the correct outcome is `PARTIAL/BLOCKED`.
