# C2 test and evidence ledger

Status: `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`

Review time: `2026-07-27T01:40:00Z`

Revalidation deadline: `2026-08-10T01:40:00Z`

This ledger separates official-document review, local deterministic tests,
repository quality checks, and live actions. A command is `PASS` only from its
direct result. An action prohibited by preflight is `BLOCKED`, never `PASS` and
never fabricated live evidence.

## Bound baseline

| Field | Exact value |
|---|---|
| Repository | `Cheurteenyt/systeme-local` |
| C2 branch | `interop/chatgpt-web-capability-gating-c2` |
| Exact C1 base | `2aee36fdfa3d20c23acdc75eb3348bc54536ef4f` |
| C1 draft PR | [#67](https://github.com/Cheurteenyt/systeme-local/pull/67) |
| C1 CI at C2 start | four jobs successful |
| Capability profile | `chatgpt_chat_c2_20260727` |
| Profile SHA-256 | `fa6f144d6867c00e995c791182cc78e7aabcc781ff6462bf885be26faa706305` |
| C2 live credential count | `0` |
| C2 tunnel start count | `0` |
| C2 Plugin creation count | `0` |
| C2 browser test count | `0` |

## Official evidence review

All searches and reads used the official OpenAI documentation interface. No
ChatGPT account, private UI state, or browser session was used as evidence.

| ID | Source or query | Result | Classification |
|---|---|---|---|
| `C2-E01` | [Plugins](https://learn.chatgpt.com/docs/plugins) | Explicitly available with Work and unavailable in Chat; Plugins may contain MCP tools. | decisive `unsupported` evidence |
| `C2-E02` | [Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt) | MCP registration and conversation selection use the Plugins route. | corroborating route evidence |
| `C2-E03` | [Package your plugin](https://developers.openai.com/plugins/build/plugins) | Local authoring uses Work or Codex; availability varies by surface. | corroborating surface evidence |
| `C2-E04` | [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) | ChatGPT Tunnel setup creates a developer-mode app in Plugins. | transport is not Chat capability |
| `C2-E05` | Official searches for Chat, custom/local MCP, apps, connectors, Plugins, and Tunnel | No alternative official custom/local MCP interface explicitly supporting Chat was found. | does not override explicit exclusion |

The conclusion is an inference across the four committed sources: the only
documented ChatGPT custom/local MCP registration route is Plugin-based, and
the Plugins contract explicitly excludes Chat. The canonical profile records
the inference and its source-specific summary digests.

## Implemented deterministic tests

| ID | Scope | Result |
|---|---|---|
| `C2-L01` | New strict profile and preflight unit suite | PASS: 16 tests in the first focused run |
| `C2-L02` | Current profile byte-for-byte regeneration and fixed profile digest | PASS |
| `C2-L03` | Official-host, summary digest, profile digest, sorted/unique source, and unknown-field rejection | PASS |
| `C2-L04` | `unsupported`, stale, `unobservable`, pre-review, malformed, and synthetic `supported` state matrix | PASS |
| `C2-L05` | All four live actions denied together for every blocked state | PASS |
| `C2-L06` | CLI preflight, action-denial exit code, and non-echoing malformed-profile behavior | PASS |
| `C2-L07` | Closed provider registry and no browser/network/tunnel dependency in the gate | PASS |
| `C2-L08` | Ruff and direct Mypy check for the new Python module | PASS |
| `C2-L09` | Real PowerShell `Invoke-C2Preflight -AllowDirty` during implementation | PASS: exact blocked status, `unsupported`, all four actions `false`, no live side effect |

## Pre-seal quality checks

| ID | Time (UTC) | Command or scope | Exact result |
|---|---|---|---|
| `C2-Q01` | `2026-07-27T01:52Z` | `uv lock --check`, Ruff lint, changed-file format check, format ratchet, and Mypy ratchet | PASS: 76 packages resolved; Ruff clean; 3 changed Python files formatted; 42 approved legacy format files; 0 new format debt; 0 Mypy diagnostics |
| `C2-Q02` | `2026-07-27T01:52Z` | Evidence governance at a fixed time | PASS: all registered profiles valid |
| `C2-Q03` | `2026-07-27T01:52Z` | Frozen Python dependency audit | PASS: no known vulnerabilities. The first invocation lacked `.venv/Scripts` in `PATH` and stopped before audit; the corrected invocation passed and is the evidence-bearing run. |
| `C2-Q04` | `2026-07-27T01:52Z` | Markdown link validation | PASS: links valid across 41 Markdown files |
| `C2-Q05` | `2026-07-27T01:52Z` | PowerShell parser over all C1 and C2 scripts/modules | PASS: 24 files, 0 parse errors |
| `C2-Q06` | `2026-07-27T01:52Z` | Process safety inventory | PASS: five credential/secret environment variables absent; no listener on 8765/8766; no `tunnel-client` process |
| `C2-Q07` | `2026-07-27T01:53Z` to `01:54Z` | First near-full Python suite excluding the pending C2 seal | Correctly found one stacked-branch test defect after 897 passes and 5 skips: the C1 seal test compared historical C1 metadata with the C2 worktree. Coverage was 87.12%. |
| `C2-Q08` | `2026-07-27T01:55Z` | Historical C1 seal recalculation and focused regression after correction | PASS: exact C1 diff remained 259,820 bytes with SHA-256 `d82f6b53221e467a8ecea380586e93489410f647e0bc5d2858390ad97523c72b`; 27 focused tests passed and 1 pending C2 seal test was deselected |
| `C2-Q09` | `2026-07-27T01:55Z` | Rust workspace check, format, Clippy with warnings denied, tests, doctests, docs with warnings denied, and `cargo audit` | PASS: all stages; 106 tests; 0 failures; 73 dependencies scanned against 1,169 advisories with no vulnerability reported |
| `C2-Q10` | `2026-07-27T01:56Z` | Bounded scan of 25 changed/untracked files for Runtime keys, exact Tunnel IDs, and assigned process-secret values; `git diff --check` | PASS: 0 secret-value matches; diff check clean |
| `C2-Q11` | `2026-07-27T01:58Z` to `01:59Z` | First full Python suite with the C2 seal | Correctly found one missing documentation-index link after 898 passes and 5 skips; coverage was 87.12%. ADR 0009 was then added to the exhaustive index. |
| `C2-Q12` | `2026-07-27T01:59Z` to `02:00Z` | Documentation contracts followed by the complete Python suite with both historical and C2 seals | PASS: 36 focused documentation tests; 899 full-suite tests passed, 5 skipped, 87.12% coverage, exit 0 |
| `C2-Q13` | `2026-07-27T02:03Z` | Post-review substituted-profile and Python-launcher hardening | PASS: 17 capability tests; Ruff and direct Mypy clean; 4 C2 PowerShell files parsed; real preflight denied all 4 actions |
| `C2-Q14` | `2026-07-27T02:04Z` to `02:05Z` | Complete Python suite after hardening with the deterministic C1 and C2 seals | PASS: 900 tests passed, 5 skipped, 87.16% coverage, exit 0 |
| `C2-Q15` | `2026-07-27T02:06Z` | Clean-commit PowerShell operator flow on `028bdb4`: official-profile verification, preflight, operator steps, and attempted C1 preparation | PASS: all three C2 commands returned the exact blocked status; 4 actions denied; C1 preparation stopped at C2 before secret initialization; 0 sensitive variables before/after; 0 listeners; 0 `tunnel-client` processes |

The C1 seal correction does not modify the C1 seal or its historical digest.
It makes the test verify the artifact against exact sealed C1 commit
`2aee36fdfa3d20c23acdc75eb3348bc54536ef4f` instead of an arbitrary descendant
worktree.

## Live-action ledger

| Action | Gate decision | Executed in C2 | Evidence status |
|---|---|---|---|
| Runtime-key creation | `false` | no | correctly blocked |
| Tunnel startup | `false` | no | correctly blocked |
| temporary Plugin creation | `false` | no | correctly blocked |
| browser testing | `false` | no | correctly blocked |
| Work testing | prohibited independently | no | out of scope |
| existing-chat/history access | prohibited independently | no | out of scope |
| private browser or account-state access | prohibited independently | no | out of scope |

Prior C1 local and Tunnel results remain documented in the C1 ledger. C2 does
not repeat, relabel, or promote them. In particular, no C2 live Chat proof,
conversation identifier, screenshot, Plugin receipt, Runtime-key receipt,
Tunnel receipt, or browser observation exists.

## Validation closeout

The final closeout must record exact exit-zero results for:

- frozen Python lock;
- Ruff lint and format ratchets;
- Mypy typing ratchet;
- evidence governance;
- Python dependency audit;
- Markdown links;
- all C2 PowerShell parses;
- full Python tests and coverage;
- Rust check, formatting, Clippy, tests, doctests, docs, and dependency audit;
- deterministic C2 change seal;
- bounded secret scan;
- GitHub Actions on the stacked draft PR.

Any required failure changes the final status to `BLOCKED_BY_TEST_FAILURE`; the
ledger must not soften, omit, or rewrite the failure.

The five full-suite skips are unchanged from C1: two opt-in Docker integration
tests and three Windows symbolic-link tests unsupported by the current process.
After pytest returned exit zero, its known Windows temporary-directory
`PermissionError` appeared in an `atexit` cleanup callback. It occurred after
the successful result and is recorded rather than hidden.
