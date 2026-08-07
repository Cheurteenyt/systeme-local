# C3 test and evidence ledger

Status: C3 lifecycle validation complete; final-head CI is reported on the PR

C3 is immutable historical evidence on descendants. C4 now owns runtime
admission but continues to consume this exact sealed profile and registry.

Review time: `2026-07-27T11:55:00Z`

Revalidation due from: `2026-08-03T11:55:00Z`

Expiry: `2026-08-10T11:55:00Z`

## Bound baseline

| Field | Exact value |
|---|---|
| Repository | `Cheurteenyt/systeme-local` |
| Issue | [#69](https://github.com/Cheurteenyt/systeme-local/issues/69) |
| C3 branch | `interop/provider-capability-revalidation-c3` |
| Exact C2 base | `cf05e963ba30539f9b2c9ec2f5f71326cbba8399` |
| C2 draft PR | [#68](https://github.com/Cheurteenyt/systeme-local/pull/68) |
| C3 draft PR | [#70](https://github.com/Cheurteenyt/systeme-local/pull/70) |
| Profile | `chatgpt_chat_c3_20260727` |
| Profile SHA-256 | `478d1651fa1b275d5158ff1fd56e1775b10a48fb650b3e2baef3808d36e357bd` |
| Registry SHA-256 | `eb95d8cc359b9bca6f30ae613b294dcc6247ace292ad49fab7f116a38c79631c` |
| Runtime credentials created | `0` |
| Tunnels created or started | `0` |
| Plugins created | `0` |
| Browser or ChatGPT actions | `0` |

## Official-document review

All source acquisition used the official OpenAI documentation interface. No
browser account, ChatGPT UI, private state, or third-party source was used.

| ID | Source | Observed result |
|---|---|---|
| `C3-E01` | [Plugins](https://learn.chatgpt.com/docs/plugins) | Plugins may include MCP servers/tools, are available with Work, and are explicitly unavailable in Chat. |
| `C3-E02` | [Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt) | The MCP connection route remains under Settings > Plugins; no independent native Chat support is stated. |
| `C3-E03` | [Package your plugin](https://developers.openai.com/plugins/build/plugins) | Local MCP plugin creation uses Work or Codex; no native Chat route is documented. |
| `C3-E04` | [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) | ChatGPT Tunnel setup creates a developer-mode app through Plugins; transport does not override surface availability. |
| `C3-E05` | Official searches for native Chat, custom/local MCP, Plugins, apps, connectors, and Tunnel | No alternative official native Chat custom/local MCP interface was found. |

## Gap analysis evidence

The C2 audit covered:

- `src/systeme_local_gateway/c2_capability.py`;
- `governance/c2-official-capability-profile.json`;
- all four C2 PowerShell files;
- C2 unit and documentation tests;
- ADR 0009;
- the scheduled evidence-governance workflow and main CI;
- roadmap, architecture, threat model, ChatGPT provider documents, and the C2
  evidence ledger.

The resulting reusable, missing, incompatible, and out-of-scope categories are
recorded in the
[C3 lifecycle document](chatgpt-web-c3-evidence-lifecycle.md#c2-gap-analysis).

## Focused implementation tests

| ID | Scope | Direct result |
|---|---|---|
| `C3-L01` | Profile/registry builders, fixed digests, and current fail-closed decision | PASS |
| `C3-L02` | Lifecycle boundaries before review, current, warning threshold, and exact expiry | PASS |
| `C3-L03` | Supported/unsupported/unobservable and reviewed/candidate separation | PASS |
| `C3-L04` | Claim, conclusion, evidence, profile, and registry digest substitution | PASS |
| `C3-L05` | Unknown fields, duplicates, missing sources, time inversion, and path escape | PASS |
| `C3-L06` | HTTPS canonicalization, official-host allowlist, and lookalike-domain rejection | PASS after the test detected and the implementation fixed uppercase-host normalization |
| `C3-L07` | Active-profile drift, registry substitution, missing/malformed bundle, and provider isolation | PASS |
| `C3-L08` | Strict candidate draft, digest sealing, unchanged/changed comparison, stale/future/cross-profile/wrong-reviewer rejection | PASS |
| `C3-L09` | CLI preflight, all five denied actions, due warning, expiry failure, and secret-free invalid input | PASS |
| `C3-L10` | No browser, HTTP client, Tunnel credential, secret, or process dependency in the C3 module | PASS |
| `C3-L11` | Initial focused suite | PASS: 39 tests |
| `C3-L12` | Ruff format/lint and direct Mypy on the C3 module | PASS |
| `C3-L13` | Eight C3 PowerShell files parsed and real dirty-worktree preflight at `2026-07-27T12:00:00Z` | PASS: `current`, `unsupported`, five actions `false` |
| `C3-L14` | Candidate-draft generation, strict sealing, and extended C3 suite | PASS: 42 lifecycle tests; 53 focused C3 tests including docs, with the pending seal test deselected |

The known Windows pytest temporary-directory `PermissionError` occurred in an
`atexit` cleanup callback after the focused suite returned success. It did not
change the exit-zero test result and is recorded rather than hidden.

## Live-action ledger

| Action | C3 gate | Executed in C3 |
|---|---|---|
| Runtime-key creation | `false` | no |
| Tunnel startup | `false` | no |
| Plugin creation | `false` | no |
| browser test | `false` | no |
| any ChatGPT action | `false` | no |
| Work/history/existing chats/private state | prohibited independently | no |

C3 creates no live receipt. Historical C1 receipts remain historical and are
not relabeled as C3 evidence.

## Validation closeout

| ID | Gate | Direct local result |
|---|---|---|
| `C3-Q01` | `uv lock --check` | PASS |
| `C3-Q02` | Ruff lint | PASS |
| `C3-Q03` | Format ratchet | PASS: 42 approved legacy paths, 4 changed Python paths, 0 new debt |
| `C3-Q04` | Mypy ratchet and direct C3 Mypy | PASS: 0 approved legacy diagnostics, 4 changed Python paths, 0 new diagnostics |
| `C3-Q05` | Evidence governance at `2026-07-27T12:00:00Z` | PASS |
| `C3-Q06` | C3 official profile and preflight at `2026-07-27T12:00:00Z` | PASS: `current`, `unsupported`, all five protected actions denied |
| `C3-Q07` | Complete Python suite with the generated seal test | PASS: 954 passed, 5 skipped; coverage 86.41% |
| `C3-Q08` | C2/C3/documentation regression slice | PASS: 47 tests |
| `C3-Q09` | Markdown-link validation | PASS: 44 Markdown files |
| `C3-Q10` | Python dependency audit | PASS: 76 packages, no known vulnerabilities |
| `C3-Q11` | PowerShell parser inventory | PASS: 32 C1/C2/C3 files, 0 parser errors |
| `C3-Q12` | Rust check, format, strict Clippy, tests, doctests, private-item docs with warnings denied, and dependency audit | PASS: every command exited zero |
| `C3-Q13` | Bounded changed-file secret scan | PASS: 34 paths before the seal, 0 potential credential assignments or credential-shaped values |
| `C3-Q14` | Runtime and network safety inventory | PASS: no sensitive process environment variable, listener on 8765/8766, or `tunnel-client` process |
| `C3-Q15` | `git diff --check` | PASS |
| `C3-Q16` | Self-excluding C3 seal and focused C2/C3 regression | PASS: exact diff bytes/digest reproduced; 65 focused tests |
| `C3-Q17` | Clean-commit offline operator replay | PASS on `6b48b00b0ffef9b751ba2f520259adaa44aab141`: `current`, `unsupported`, five actions denied, candidate sealed, comparison `unchanged`, candidate cannot change the gate |
| `C3-Q18` | Initial stacked draft-PR CI | PASS: [run `30266197962`](https://github.com/Cheurteenyt/systeme-local/actions/runs/30266197962), all 4 jobs green (`test`, Python 3.14 compatibility, Rust quality, Rust tests on Windows) |

The complete Python run again emitted the known Windows pytest
temporary-directory `PermissionError` from an `atexit` cleanup callback after
pytest had returned exit zero. The successful result and the cleanup warning
are both retained in this ledger.

The final-head CI rerun after this ledger and seal update is intentionally
reported on draft PR #70 and in the C3 handoff. Updating this ledger again
solely to cite that rerun would create an unbounded documentation/CI loop.

Required failures remain failures and change the C3 final status. They are not
deleted or softened.
