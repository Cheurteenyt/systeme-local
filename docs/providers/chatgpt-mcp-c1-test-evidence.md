# C1 test and evidence ledger

Status at `2026-07-27T00:59:09Z`:
`BLOCKED_BY_PLUGIN_UNAVAILABLE_IN_CHAT`

This ledger records what was actually executed for C1. It is an evidence
index, not a substitute for the signed C1 receipts. A row is successful only
when the cited command completed successfully. A pending row is never evidence
of a passed test.

## Evidence classes

- `local`: exercised repository code without a ChatGPT Web call;
- `live-setup`: exercised real local processes and the Secure MCP Tunnel, but
  did not send a ChatGPT Web prompt;
- `visible-web`: inspected only visible controls on a new sterile Chat page
  after bounded browser authorization, without sending a prompt;
- `live-chat`: exercised a newly created sterile Chat page after bounded
  goal-scoped browser authorization;
- `not-run`: no execution evidence exists.

Work is detected but never invoked or tested. Existing ChatGPT conversations,
the sidebar, history, storage, cookies, private requests, personal content,
API-key pages, and unrelated tabs are outside the evidence boundary.

## Bound baseline

| Field | Value |
|---|---|
| Repository | `Cheurteenyt/systeme-local` |
| C1 issue | `#66` |
| C1 branch | `interop/chatgpt-web-chat-observability-c1` |
| Current committed C1 baseline | `7c5b41507ffa4eca8f30abe6945dadc97b43d3f0` |
| C0 dependency | `912d0d33e119469ff957965104cf20af5e491923` |
| Policy SHA-256 | `17a53ee929232bae5901037c26c23ad1379dbdb09998c698b1ed85c60a75700e` |
| Tool snapshot SHA-256 | `6d9a8e0f6dadb9f3a615abcca8c882cb37fb257944922151e97c65a8575da14b` |
| Tunnel client | `v0.0.10` |
| Tunnel binary SHA-256 | `d893d8127eee35070d265c1be29bfe008f8d9fcb476e7febf56c8fdc6c0615c8` |

## Executed tests

| ID | Time or window (UTC) | Class | Command or test | Result | Evidence and limitation |
|---|---|---|---|---|---|
| `C1-L01` | `2026-07-26T18:33:10Z`–`18:34:11Z` | local | `.venv\Scripts\python.exe -m pytest --cov=systeme_local_gateway --cov-report=term --cov-fail-under=60` | PASS: 858 passed, 5 skipped, 86.11% coverage, exit 0 | Direct terminal result on the tested commit. The five skips are classified below. |
| `C1-L02` | Same window as `C1-L01` | local | C1 contract tests inside the full suite | PASS: 72 C1 tests | `tests/test_c1_docs.py`: 14; `tests/test_c1_observability.py`: 51; `tests/test_c1_proof_check.py`: 7. |
| `C1-L03` | `2026-07-26`, pre-live implementation window | local | Actual facade startup and `Test-C1LocalProbe.ps1` against `127.0.0.1:8765/mcp` | PASS: exactly one tool; `read_only=true`; `write_actions_enabled=false`; `real_evidence_access=false`; `protocol_v2_reachable=false` | Direct prior terminal result on the tested commit. Preflight cleanup intentionally deleted the raw local challenge, response, audit, and database. Exact start/end timestamps were not retained, so this is not final live evidence. |
| `C1-L04` | `2026-07-26T19:15:00Z`–`19:16:01Z` | local | Windows PowerShell operator-script regression for `New-C1VisibleModelObservation.ps1 -VisibleReasoningLabelUtf8Base64 "VHLDqHMgw6lsZXbDqWU="` on commit `59a56365c3f847dcef5035ad0d3e47061b002ec7` | PASS: ASCII-only evidence file; strict UTF-8 parse; exact `Très élevée` code points; `simulated=false`; cleanup complete | Fresh independent process secrets were generated and never printed. The temporary observation was deliberately removed. No tunnel, Chat prompt, or tool call was used. |
| `C1-S01` | Observation at `2026-07-26T18:23:29Z` | live-setup | `Prepare-C1.ps1`, prerequisite validation, and `New-C1RuntimeSetupObservation.ps1 -RuntimeModel gpt-5.6-sol -ReasoningEffort xhigh` | PASS: prerequisites ready; direct runtime model/effort recorded; worktree clean | Private typed observation `.systeme-local/c1/runtime-setup.json`; file SHA-256 `93c6330eaf38fc33d28f10467893b935d206dda5eb594bfd9464e3c584869ddc`; 5,947 bytes. The configured default and active runtime remain separate fields. |
| `C1-S02` | Checks at `2026-07-26T18:25:56Z` and before this ledger | live-setup | `Start-C1Facade.ps1`, `Start-C1Tunnel.ps1`, loopback listener inspection, and `GET http://127.0.0.1:8766/readyz` | PASS: facade on `127.0.0.1:8765`; tunnel health `ready` on `127.0.0.1:8766`; raw logging/UI off; 20-minute TTL | Real processes and real Tunnel client. This proves transport readiness only; it is not a ChatGPT Web call. No credential value is retained. |
| `C1-W01` | Before `2026-07-26T19:06:43Z` | visible-web | Bounded visible-only inspection of a new Chat page and the Plugin marketplace | PASS with limits: surface visibly `Chat`; reasoning label visibly `Très élevée`; no visible model label or internal ID; Work not opened; no Plugin created or selected | Browser authorization was supplied. The Plugin add/create control was not visible while Developer mode was not enabled. No sidebar, history, existing conversation, private state, API-key page, prompt, or tool result was accessed. |

## Pre-final quality checks

These checks include the new ledger, but they precede the live Chat evidence
and final seal. They must be repeated after the last live-evidence
documentation change.

| ID | Time or window (UTC) | Command or check | Result |
|---|---|---|---|
| `C1-Q01` | `2026-07-26T18:37:20Z`–`18:37:26Z` | `uv lock --check` | PASS: frozen lock resolved 76 packages without change. |
| `C1-Q02` | Same window | `ruff check .` and `check_python_format.py --worktree` | PASS: lint clean; 42 approved legacy format files; 1 changed Python file; 0 new debt. Ruff first identified and then formatted the new test file. |
| `C1-Q03` | Same window | `check_python_typing.py --worktree` | PASS: 0 approved legacy diagnostics and 0 new diagnostics for 1 changed Python file. |
| `C1-Q04` | Same window | `check_evidence_governance.py --as-of 2026-07-26T20:00:00Z --fail-within-days 0` | PASS: evidence governance valid at the fixed review instant. |
| `C1-Q05` | Same window | `audit_python_dependencies.py` | PASS: 76 frozen packages resolved; no known vulnerabilities. |
| `C1-Q06` | `2026-07-26T18:37:27Z` | Windows PowerShell parser over `scripts/c1/*.ps1` and `*.psm1` | PASS: all 18 C1 PowerShell files parsed without errors. |
| `C1-Q07` | `2026-07-26T18:37:45Z`–`18:37:47Z` | `check_markdown_links.py` | PASS: links valid across 38 Markdown files. |
| `C1-Q08` | Same window | `pytest -q tests/test_c1_docs.py -k "not change_seal"` | PASS: 15 passed, 1 seal test deliberately deselected because the documentation edit invalidated the old seal. |
| `C1-Q09` | `2026-07-26T18:38:20Z`–`18:38:31Z` | Rust 1.97.1: workspace check, format, Clippy with warnings denied, tests, doctests, docs with warnings denied, and `cargo audit` | PASS: all build/lint/doc stages; 106 tests passed, 0 failed; doctests passed; 73 locked dependencies scanned against 1,169 RustSec advisories with no vulnerability reported. |
| `C1-Q10` | `2026-07-26T18:39:25Z` | `git diff --check` and bounded credential-pattern scan of all 5 changed/untracked files | PASS: diff clean; 0 Runtime-key, Tunnel-ID, or assigned process-secret findings. Match values would not have been printed. |
| `C1-Q11` | `2026-07-26T18:42:09Z`–`18:42:10Z` | Full `tests/test_c1_docs.py`, including deterministic self-excluding change-seal verification | PASS: 16 passed; the ledger is one of 37 sealed C1 files. |
| `C1-Q12` | `2026-07-26T18:42:51Z`–`18:43:51Z` | Full Python suite with coverage after adding the two ledger contracts | PASS: 860 passed, 5 skipped, 86.11% coverage, exit 0. |
| `C1-Q13` | `2026-07-26T23:16Z`–`23:17Z` | C1 observability, proof, documentation, PowerShell parsing, Ruff, and self-excluding seal regression after the expiry-window fix | PASS: 82 targeted C1 tests; all 18 C1 PowerShell scripts parsed; Ruff check/format clean. |
| `C1-Q14` | `2026-07-26T23:17:19Z`–`23:18:21Z` | Full Python suite with coverage on the expiry-window fix | PASS: 868 passed, 5 skipped, 87.09% coverage, exit 0. The known post-exit Windows pytest temporary-symlink warning recurred after the successful result. |

| `C1-Q15` | `2026-07-27T00:23Z` | Documentation, targeted C1, PowerShell parsing, and deterministic seal checkpoint on commit `c88ad81` | PASS: 20 documentation tests; 83 targeted C1 tests; all 19 C1 PowerShell scripts parsed; the 39-file self-excluding seal matched SHA-256 `7789faf109ac53a7ac635cb137378c4a6ca7f3365a078763dc0ff58556fe9678`. The known post-exit Windows pytest temporary-directory warning followed exit 0. |
| `C1-Q16` | `2026-07-27T01:00Z` | Lock, Ruff, format and Mypy ratchets, evidence governance, Python dependency audit, Markdown links, and PowerShell parsing after fail-closed cleanup | PASS: 76 locked packages resolved; Ruff clean; 42 approved legacy format files and no new debt; zero Mypy diagnostics; evidence governance valid at `2026-07-27T01:00:00Z`; no known Python vulnerabilities; links valid across 38 Markdown files; all 20 C1 PowerShell files parsed. The first ratchet invocation omitted the virtual-environment executable directory from `PATH`; the three affected commands were immediately rerun with the correct environment and passed. |
| `C1-Q17` | `2026-07-27T01:01Z` to `01:02Z` | Full Python suite with coverage after the official product-surface guard | PASS: 870 passed, 5 skipped, 87.10% coverage, exit 0. The known post-exit Windows pytest temporary-directory warning recurred after the successful result. |
| `C1-Q18` | `2026-07-27T01:02Z` | Rust workspace check, format, Clippy with warnings denied, tests, doctests, docs with warnings denied, and `cargo audit` | PASS: all build/lint/doc stages; 106 tests passed, 0 failed; doctests passed; 73 locked dependencies scanned against 1,169 RustSec advisories with no vulnerability reported. |
| `C1-Q19` | `2026-07-27T01:03Z` | Final documentation, official-profile, deterministic seal, Markdown-link, diff, and bounded credential checks | PASS: 21 documentation tests including byte-for-byte official-profile and self-excluding seal verification; links valid across 38 Markdown files; `git diff --check` clean; zero Runtime-key, Tunnel-ID, or assigned process-secret findings. |

## Skips and non-failing warning

The five `C1-L01` skips are explicit and do not cover the C1 Web claim:

- two Docker integration tests require
  `SYSTEME_LOCAL_RUN_DOCKER_TESTS=1`;
- three Windows symbolic-link tests skipped because the current process could
  not create the required symbolic links.

After both full-suite runs returned exit code zero, pytest emitted a Windows `atexit`
`PermissionError` while resolving
`%LOCALAPPDATA%\Temp\pytest-of-cheur\pytest-current`. The test process had
already reported all results and exit zero. This warning is recorded rather
than suppressed; it does not prove or disprove the live C1 claim.

## Live Chat tests not yet executed

The operator subsequently supplied bounded browser authorization. Visible-only
inspection of a new Chat page classified the surface as `Chat`, directly
observed the reasoning label `Très élevée`, found no visible model label or
internal model ID, and did not open or test Work. The Plugin marketplace was
also inspected without selecting or creating a Plugin. Developer mode still
requires a separate action-time authorization, and no ChatGPT Web prompt has
been sent. Therefore all of the following remain `not-run`:

- positive Chat A and Chat B calls;
- visible Chat/model/reasoning observations;
- same-chat and cross-chat replay checks;
- unknown-field and malformed-challenge checks;
- prompt-injection and file/command/secret/protocol-v2/write refusals;
- non-Chat refusal;
- Plugin removal, C1 Runtime-key revocation, and post-revocation failure;
- final signed C1 attestation.

The final documentation update must replace this section with exact result
rows and hashes only after the signed receipts exist. It must not rewrite
`not-run` as `PASS` from memory, screenshots, or local-only evidence.

## Live encoding defect discovered after authorization

At `2026-07-26T19:06:43Z`, the first authorized visible-label observation
exposed a Windows console code-page defect: the intended French label
`Très élevée` reached the evidence file as `TrÞs ÚlevÚe`, and the file was not
valid UTF-8. The observation was rejected, the tunnel/facade were stopped,
ports `8765/8766` were verified closed, and the entire preflight state was
irrecoverably removed before any Chat prompt or tool call.

The regression fix requires non-ASCII visible labels as canonical UTF-8
Base64, decodes them with strict UTF-8, rejects ambiguous raw non-ASCII input,
and makes all C1 Python CLI JSON output ASCII-safe with `\u` escapes. A new
clean live session and a new signed visible-label observation are required;
the rejected observation is not C1 evidence.

## Rejected browser-scope cycle

An earlier authorized cycle reached two positive Chat calls and local
correlations, but a broad browser inspection then crossed the approved C1
boundary by including private sidebar/history state. No private title,
identifier, or content from that inspection is retained in this ledger. The
entire cycle was rejected rather than partially reused: the processes were
stopped, the temporary Plugin was removed, the Runtime key was revoked, and
the local C1 state was irrecoverably cleared. Its positive calls are not final
C1 evidence.

## Expired-evidence defect discovered by a complete manual cycle

A later clean cycle on committed baseline
`d5eae184290dd90832386d6700ccc9c209aa60a8` stayed within the browser boundary
and exercised the full intended sequence:

- runtime setup was signed at `2026-07-26T21:59:14Z`;
- Chat A returned one read-only result at `22:05:46Z`, correlated to audit ID
  `a4fc6a0a-7279-483b-b225-d426f480aeee`, and its proof was signed at
  `22:19:10Z`;
- Chat B returned one read-only result at `22:20:16Z`, correlated to audit ID
  `4a26bec3-aaac-43a7-8686-078980bc961e`, and its proof was signed at
  `22:48:06Z`;
- same-chat and cross-chat replays produced two failed audit records; unknown
  fields and a malformed challenge were rejected by schema; local-file,
  command, secret, B2-evidence, and write capabilities remained unavailable;
- Work was not invoked, existing chats were not accessed, and private browser
  state was not accessed;
- the facade and tunnel stopped, ports `8765/8766` closed, the temporary Plugin
  was removed, the temporary Runtime key was revoked, and a fresh Chat page
  returned `C1_APP_UNAVAILABLE_AFTER_REVOCATION`;
- the audit remained exactly four records: two completed probes and two failed
  replay attempts, all for the single reviewed probe capability.

The signed negative and revocation receipts were created at
`2026-07-26T23:05Z`. Final attestation then failed closed because the 30-minute
surface/proof evidence for Chat A and Chat B had expired at `22:32:27Z` and
`22:49:16Z`, and the visible-label observation had expired at `23:02:26Z`.
`Clear-C1Temporary.ps1` correctly refused to erase raw state without a valid
attestation.

This cycle is a real regression result, not final success evidence. The fix
extends signed manual artifacts to a two-hour window while retaining a
30-minute challenge lifetime and a 30-minute maximum from pre-prompt surface
observation to strict response. It also adds an explicit fail-closed
`Reject-C1ExpiredCycle.ps1` path that requires stopped listeners, Plugin
removal, Runtime-key revocation, and at least one expired typed artifact before
irreversible cleanup. A completely fresh cycle is still required.

## Rejected Work-surface transition cycle

A later fresh cycle reached one validated Chat A call at commit `5740e57`.
The local verifier correlated exactly one completed read-only probe and
confirmed that write actions, real-evidence access, and protocol v2 remained
disabled. Before Chat B received any prompt, the official
`Essayer dans le chat` control for the temporary development Plugin opened the
Work surface (`?surface=work`) and the visible selector reported Chat as off.

This is not a successful C1 run. Work received no prompt and no tool call, but
opening it exceeded the operator's explicit Chat-only authorization. Both test
tabs were closed, the temporary Plugin was removed, the tunnel and facade were
stopped, and the Runtime key required immediate revocation. The validated Chat
A proof is rejected and cannot contribute to a final attestation.
`Reject-C1ScopeViolationCycle.ps1` was added so a non-expired correlated cycle
can be erased immediately after the required shutdown, Plugin removal, key
revocation, and tab-closure confirmations.

This proposed retry path was superseded by the official product-surface
finding below. It must not be attempted while Plugins remain unavailable in
Chat.

## Current official product-surface blocker

At `2026-07-27T00:45Z`, the operator granted one persistent but bounded
authorization for the current C1 goal. It covers only the Plugins surface and
at most two newly created synthetic Chat pages per cycle, remains valid across
strictly necessary retries, and still permanently excludes Work, existing
chats, history, account/security settings, and private browser state.

One fresh cycle then produced only the following setup observations:

- the temporary development Plugin
  `systeme-local-c1-chatonly-20260727` connected through the reviewed Tunnel;
- its visible metadata exposed exactly one `LECTURE` action,
  `systeme_local_connectivity_probe`, with `additionalProperties=false` and the
  exact `^c0_[0-9a-f]{32}$` challenge pattern;
- exactly two new pages were opened and classified only through the visible
  surface selector;
- both pages reported `Chat=off` and `Work=on` before any prompt;
- no prompt was sent, no tool was invoked, the local audit remained zero
  records, and no existing chat, history, private browser state, or personal
  content was accessed.

Both test pages were immediately closed without switching the surface. The
temporary Plugin was disconnected, the facade and Tunnel were stopped, ports
`8765/8766` closed, and process-local transport secrets were cleared.

The current official [Plugins](https://learn.chatgpt.com/docs/plugins)
documentation was then fetched directly. It states that Plugins are available
with ChatGPT Work on the Web and are not available in Chat. This makes the
intended Chat-only Plugin invocation unavailable by product contract, not by a
Tunnel, schema, or local implementation failure. Because Work remains outside
the operator's authorization and the C1 claim boundary, the exact status is
`BLOCKED_BY_PLUGIN_UNAVAILABLE_IN_CHAT`.

This cycle created no positive, negative, or final C1 receipt. At
`2026-07-27T00:59Z`, the operator confirmed revocation of its temporary Runtime
key. `Clear-C1Preflight.ps1` then completed with `status=preflight_clean`,
removed the private runtime observation, logs, replay/approval databases, and
audit lock, reported `correlated_evidence_removed=false`, and cleared every
process secret. Independent checks found zero listeners on ports `8765/8766`
and zero remaining C1 state items.

No new live cycle may start until official revalidation shows Plugins
available in Chat or a separate goal explicitly authorizes another supported
surface.

## Final validation completed

The complete local quality suite was rerun after the fail-closed cleanup and
the official product-surface guard. Exact results are recorded in `C1-Q16`
through `C1-Q18`; the final deterministic seal, diff, and bounded credential
checks are recorded in `C1-Q19`.

No C1 final attestation exists or was attempted for this cycle. That check is
correctly unavailable because the official Plugin surface prevents the two
required Chat calls, and manufacturing an attestation from setup-only evidence
would violate the C1 contract. The five Python skips remain the explicitly
classified environment-dependent skips above and do not cover this blocker.
