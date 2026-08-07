# C9 test and evidence ledger

Status: `partial` — the asymmetric Work-rich/Chat-manual implementation is
aligned, the consolidated suite and a non-qualifying installed-runtime
preflight passed, and all cycle-bound live proofs are pending

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
| `preflight_verified` | a real installed runtime passed a local-only readiness cycle that was then reset; it does not increment a cycle-bound success counter |
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

The following local results were obtained on 2026-07-28 from the current
reviewed draft-PR snapshot. They establish the offline contract described
above. The installed-runtime row is explicitly a reset preflight and does not
increment any cycle-bound success counter.

| ID | Validation | Result |
|---|---|---|
| `C9-Q01` | exact C9 matrix: `tests/test_c9_*.py` plus `tests/test_mcp_rich_result.py` | PASS: 339 passed, 8 conditional skips, 0 failed |
| `C9-Q02` | complete Python suite with coverage | PASS: 1,479 passed, 14 conditional skips, 84.10% coverage, exit 0 |
| `C9-Q03` | Ruff lint plus worktree format ratchet | PASS: lint clean; 42 current legacy format-debt files; 2 changed Python files; 0 new debt files |
| `C9-Q04` | worktree mypy ratchet | PASS: 2 changed Python files; 0 new diagnostics |
| `C9-Q05` | all 25 C9 PowerShell files parsed by the Windows PowerShell AST parser | PASS: 0 parse errors |
| `C9-Q06` | Markdown links, documentation contracts and deterministic evidence governance | PASS: 61 Markdown files; 31 focused documentation tests; governance valid |
| `C9-Q07` | Rust workspace check, format, Clippy with warnings denied, tests, doctests and rustdoc with warnings denied | PASS: 106 tests, 0 failed; doctests and documentation clean |
| `C9-Q08` | locked Python and Rust dependency audits | PASS: no known Python vulnerability; 73 Rust dependencies scanned against 1,170 advisories with no vulnerability |
| `C9-Q09` | historical C3/C4/C6/C7/C8 gates and evidence seals | PASS: prior unsupported-Chat and sealed-Work boundaries remain intact |
| `C9-Q10` | whitespace and bounded credential-pattern review | PASS: no patch whitespace error, Runtime-key-shaped value or Tunnel-ID-shaped value; the sole assigned-secret-shaped match is an explicit synthetic cleanup fixture |
| `C9-Q11` | post-publish Linux/Windows mypy portability correction for the Windows runtime handle | PASS: mypy with both `--platform linux` and `--platform win32`; 84 local-AI/runtime/config tests; Ruff and format checks clean |
| `C9-Q12` | Windows CI dependency-manager version expansion | PASS: the PowerShell runner reads the pinned version through `$env:UV_VERSION`; focused documentation regression test, YAML parse, Ruff and whitespace checks clean |
| `C9-Q13` | cross-runner security-test fixture normalization | PASS: 13 Git-boundary tests and 25 PowerShell hardening tests; leaf-specific hardlink/reparse fixtures call the component validator directly so an unrelated untrusted CI temporary ancestor cannot mask the target assertion, synthetic POSIX executables are private, the ACL test is isolated from an intentionally absent tunnel binary, multi-result `git.exe` discovery is scalarized, all 25 PowerShell files parse, Ruff and whitespace checks clean |
| `C9-Q14` | Windows volume-root ACL parity and native host check | PASS: effective content-only rights and `InheritOnly` ACEs at a volume root cannot alter an already-protected descendant and are handled consistently by the Python and PowerShell validators; effective `Modify`, generic write, delete, ACL takeover and non-root content writes remain rejected. The focused ACL suite passed 34/34, native `C:\` admission passed, native `D:\` admission failed closed, all 25 PowerShell files parsed and the independent read-only review found no remaining security defect |
| `C9-Q15` | native Windows runtime portability and listener ownership | PASS: an unversioned `llama-server.exe` is bound by its SHA-256 fallback version, lower-case digest text cannot be mistaken for a clear C9 nonce, and the façade listener must belong to the exact verified virtual-environment launcher or its exact base-Python child |
| `C9-Q16` | real installed multimodal local-AI preflight, followed by local-only reset | PREFLIGHT PASS: `other_reviewed_native` `llama-server` executable SHA-256 `143fd393d73813f88c53f68f7d51114bb1241b4db285e21c68f966602f6eecda`; visible model label `qwen2.5-vl-7b-instruct`; ten independent PNG/TXT nonce checks passed 10/10 with mean 2.562 s and maximum 2.750 s; the exact C9 stage then returned HTTP 200 in 2.985 s with two attachments and a bound local-AI receipt; stop closed the façade and local-only reset removed the state; no Tunnel, Plugin, Work or Chat action occurred |
| `C9-Q17` | bounded local-control failure diagnostics | PASS: only schema-checked HTTP 400/404/409 metadata may be surfaced; unexpected content type, oversized or malformed JSON, extra fields, unsafe reasons, exception text, server errors and response-less failures remain hidden; 38 focused control-API and PowerShell-hardening tests passed |

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

No fresh cycle-bound C9 authorization receipt, Runtime key, Tunnel, Plugin
connection, manual Chat export or provider action is recorded. The Q16
preflight was fully stopped and reset, so it cannot be promoted into the
required single live cycle.

| Live item | Current value |
|---|---|
| fresh C9 authorization accepting both transport legs | absent |
| local-only installed-runtime preflight | `1/1`, reset and non-qualifying |
| local-only real local-AI stage preflight | `1/1`, reset and non-qualifying |
| cycle-bound installed-runtime observation | `0/1` |
| cycle-bound real local-AI inference | `0/1` |
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

One non-qualifying browser reconnaissance opened ChatGPT directly before any
C9 cycle existed. ChatGPT automatically exposed its expanded sidebar. No
conversation was opened and no title, identifier or browser-private value was
recorded in repository evidence, but the visit is excluded from C9 because
the strict cycle must begin with the sidebar collapsed and history untouched.

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

C9 currently has an aligned and fully tested product contract plus a real
installed-runtime preflight, not a cycle-bound live success.
Normal Chat is a bounded manual handoff surface, not a Plugin/MCP surface.
Work rich-host behavior and both visible provider consumptions remain live
questions; the installed runtime must also be observed again inside that same
fresh cycle.

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

## Known CI status (verified 2026-08-07)

The repository currently carries open Dependabot PRs (mcp, uv, mypy, serde,
serde_json, time, actions/checkout, actions/setup-python). Their `test` and
`compatibility (Python 3.14)` checks show `FAILURE`, but this is a **false
negative inherited from `main`**, not a break introduced by the dependency
bumps:

- The failing check is
  `tests/test_c7_seal.py::test_c7_historical_seal_verifies_tag_diff_manifest_and_tree`,
  which raises `ValueError: C7 current tree differs from the sealed tree`.
- That test verifies `require_current_tree=True` against the C7 change seal.
  `main` has diverged from the sealed C7 tree since the seal was cut, so any
  branch based on `main` (including every Dependabot PR) fails this anchor
  test. The same failure is visible on `main` itself via `gh run list`.
- The broader matrix is healthy: that single C7 anchor test is the only
  failure (`1 failed, 1101 passed, 2 skipped`). The dependency bumps are not
  implicated.

Consequence for review:

- The C9 PR (#81, branch `codex/chatgpt-file-image-handoff-c9`) is `MERGEABLE`
  with a **green** CI (its tree matches the sealed C7 tree locally and the
  suite passes).
- The Dependabot PRs should **not** be merged solely to clear the red — the
  red is a stale C7 seal anchor, not a dependency regression. Merging them
  would only carry the false-negative red forward.
- The correct remediation, if we want the anchor green again, is to **re-seal
  C7** against the current `main` tree (a proof update, not a code fix). This
  is deferred until there is a reason to touch the C7 seal; it is intentionally
  not done automatically because it alters a security anchor.

Local note: `tests/test_c9_git_executable_resolution_is_absolute_and_fail_closed`
fails under MSYS because `shutil.which("git")` resolves to `/mingw64/bin/git`
(without `.exe`) and is not a singly-linked regular file to `c9_git`. This is an
environment artifact of the MSYS shell, not a code defect; the check passes on
the CI runner.

## Dependency vulnerability note (verified 2026-08-07)

A Dependabot alert flags `cryptography` (CVE-2026-69247, HIGH: PKCS#7
EnvelopedData Bleichenbacher oracle) on the default branch. Verification:

- `cryptography` is present only as a **transitive** dependency, pinned at
  `49.0.0` in `uv.lock`; it is not a direct dependency in `pyproject.toml`.
- A source scan of `src/` shows **no** import of `cryptography`, and **no** use
  of `PKCS7` / `EnvelopedData` / `enveloped_data` anywhere in the codebase.
- The vulnerable code path (PKCS#7 EnvelopedData decryption) is therefore never
  reached by this project.

Conclusion: the alert is a transitive-surface finding with **no reachable
exploit path** in this repository. No dependency bump is required to remediate
it from a functional standpoint. The open Dependabot PRs do not touch
`cryptography`, so they neither introduce nor fix this alert; they remain
independent of it.
