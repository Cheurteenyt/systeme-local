# C8 test and evidence ledger

Status: `COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED`; final
repository validation and evidence seal in progress

Recorded at: `2026-07-28`

## Evidence classes

| Class | What it can prove | What it cannot prove |
|---|---|---|
| official C8 revalidation | the current documented Work/Plugins/MCP route | visible entitlement, quota or a call |
| deterministic model tests | strict HMAC, digest, freshness, chronology and fail-closed behavior | provider behavior |
| PowerShell parsing and local probe | safe operator flow and exact local one-tool surface | Work selection |
| two live Work proof bundles | two bounded calls and local audit correlation | regular use or Chat support |
| revocation receipt | stopped local transport plus operator-confirmed Plugin/key removal | future product behavior |

## Offline results recorded before live execution

- C8 default admission denies every effect and exposes zero tools.
- Fresh exact authorization, Work surface, entitlement and quota evidence can
  admit one reviewed probe in deterministic tests.
- Wrong HMAC, stale UI evidence, cross-cycle substitution, scope mutation,
  unknown fields and hidden-model claims fail closed.
- Runtime configuration requires an absolute ignored
  `.systeme-local/c8/live-cycle.json` file only in `chatgpt_work_c8` mode.
- Final-attestation tests require ordered Work A and B evidence, distinct
  challenges/responses/audit records and valid revocation.
- Final attestation validates that calls occurred inside the grant window but
  does not incorrectly require that used live evidence remain current after
  revocation.
- All C8 PowerShell files parse without syntax errors.

The focused pre-documentation run selected 22 tests: all 22 passed. The
combined C4/config/main/C7/C8 regression run selected 109 cases: 108 passed
and one existing environment-dependent case skipped.

The first repository-wide C8 run correctly exposed one branch-coupled C7 test:
it required the current C8 tree to equal the historical C7 sealed tree.
The test now verifies the historical annotated C7 seal without confusing it
with the separate C7-branch-only current-tree CI gate. After that correction:

- Python collected 1,132 cases: 1,126 passed and 6 intentionally skipped;
- total Python coverage was 84.22%, above the unchanged 60% floor;
- Ruff lint was clean; the format ratchet found 10 changed Python files and
  zero new debt;
- the mypy ratchet found 10 changed Python files and zero new diagnostics;
- `uv lock --check`, Markdown links across 58 files, deterministic evidence
  governance and the frozen Python dependency audit all passed;
- all 79 tracked PowerShell files parsed without errors;
- 43 changed C8 files contained zero high-confidence credential shapes;
- Rust check, rustfmt, clippy with warnings denied, workspace tests, doctests
  and rustdoc with warnings denied all passed;
- `cargo audit` scanned 73 locked dependencies against 1,170 advisories with
  no vulnerability reported.

The pre-live repository-wide run is historical. Post-live and post-seal
results are recorded separately below so that offline quality, provider
behavior and final repository integrity are never conflated.

The pre-live implementation head
`6b791b2e843192e0db2449cabbe51e196eb3b5a5` was then validated by
[GitHub Actions run 30291087715](https://github.com/Cheurteenyt/systeme-local/actions/runs/30291087715):

- `test`: passed;
- `compatibility (Python 3.14)`: passed;
- `rust quality`: passed;
- `rust tests (Windows)`: passed.

This remote CI result validates the pre-live implementation only. It is not
evidence of a ChatGPT Work invocation.

## Pre-live visible and official refresh

At `2026-07-27T17:33:00Z`, C8 fetched the six previously reviewed official
guides again and inspected the official ChatGPT Work product page:

- the MCP guide now directly states that ChatGPT web can use remote
  MCP-backed tools supplied by Plugins, resolving the earlier fetched-body
  inconsistency;
- the signed-in Plugins directory was visibly reachable;
- the official Work product page stated that desktop access was available and
  that Web/mobile availability was rolling out progressively;
- the direct Work URL showed the product page and a Windows download control,
  not an authenticated Work task composer;
- no visible account-specific Work entitlement control or usable quota signal
  was observed.

Consequently, no Work-surface, entitlement or quota observation was signed,
no C8 grant was issued, no Runtime key or Tunnel was started, and the task
counter remains `0/2`. The refreshed governance and recovery checks selected
51 tests: all 51 passed. This is evidence of a correctly closed admission
gate, not a live connectivity result.

### Resumed visible-surface check

At `2026-07-27T22:46:00Z` (`2026-07-28` in Europe/Paris), the blocked C8
cycle was resumed without running any operator command:

- the direct `https://chatgpt.com/work` route still resolved to the public
  product page rather than an authenticated Work task composer;
- the signed-in Plugins directory was reachable, but its navigation exposed
  no Work or Travail control;
- the operator identified a separately opened Chat tab; C8 left that tab
  unclaimed and uninspected;
- no history, existing conversation, Chat composer, account setting, private
  browser state or desktop application was opened;
- no Work observation was signed because surface, entitlement and quota were
  still not independently observable.

The resumed check therefore preserves the exact fail-closed result
`BLOCKED_BY_WORK_SURFACE_AMBIGUITY`. Preparation, Runtime-key creation,
Tunnel startup and synthetic task creation remain premature.

### First admitted local cycle and freshness refusal

At `2026-07-27T22:59Z`, current operator screenshots established a distinct
Work composer, visible tools entry, available entitlement, no visible quota
exhaustion, and the labels `GPT-5.6 Sol` / `Minimal`. C8 admitted one
twenty-minute grant and started the loopback facade with exactly one effective
tool. The reviewed local probe completed with:

- `read_only = true`;
- `write_actions_enabled = false`;
- `real_evidence_access = false`;
- `protocol_v2_reachable = false`;
- one matching local audit correlation.

Creating the operator-managed Runtime key and Tunnel resource exceeded the
separate five-minute observation window. The credentialed prerequisite
correctly returned `BLOCKED_BY_SECURITY_INVARIANT` with zero effective tools
before `Start-C8Tunnel.ps1` ran. No tunnel-client, Plugin connection, Work
task or remote call existed. The facade was stopped and ports `8765` and
`8766` were verified closed.

This real refusal exposed a recovery gap between the narrower pre-grant reset
and final-attestation cleanup. `Reset-C8LocalOnly.ps1` now provides a distinct
fail-closed recovery for exactly one verified loopback probe and zero remote
or Work evidence. It never refreshes stale observations, and it continues to
require platform revocation of any operator-created Runtime key.

The committed recovery was then exercised against that exact interrupted
state. It verified the one safe local probe and its audit correlation, refused
no invariant, removed the 11 allowlisted local-cycle artifacts, left the C8
state directory empty, and reconfirmed that ports `8765` and `8766` were
closed. The unused Tunnel resource remains reusable. Platform revocation of
the operator-created Runtime key remains an explicit operator action and is
not claimed by the local reset.

At `2026-07-27T23:16:00Z`, the operator confirmed that the interrupted
cycle's Runtime key had been revoked and its process variables cleared. This
confirmation closes the aborted credential lifecycle but is not the final C8
revocation receipt, which still requires two live Work correlations first.
The retry procedure now stages the fresh operator-managed key and existing
Tunnel ID before creating the five-minute Work observations. No transport is
started by credential staging, and the live sequence remains fail-closed.

## Completed live evidence

The fresh retry staged the operator-managed Runtime key and existing Tunnel
ID before opening the five-minute UI evidence window. At
`2026-07-27T23:29:05Z`, the signed-in web UI showed:

- an explicitly selected Work surface;
- available Work entitlement and usable quota;
- the Plugins surface;
- the visible labels `GPT-5.6 Sol` and `Minimal`;
- no exact internal model identifier.

The grant exposed exactly one tool,
`systeme_local_connectivity_probe`, for at most twenty minutes. The local
probe completed at `23:29:11Z` with the four required safety values:

```text
read_only = true
write_actions_enabled = false
real_evidence_access = false
protocol_v2_reachable = false
```

The temporary Plugin was then connected through the reviewed Secure MCP
Tunnel and displayed exactly that one read-only tool. No file, command,
secret, write, real-evidence, high-risk or protocol-v2 capability was present.

### Two bounded Work calls

| Evidence | Work A | Work B |
|---|---:|---:|
| task observation | `2026-07-27T23:39:54Z` | `2026-07-27T23:44:11Z` |
| live tool response | `2026-07-27T23:42:23Z` | `2026-07-27T23:45:55Z` |
| local correlation check | `2026-07-27T23:44:10Z` | `2026-07-27T23:49:02Z` |
| positive invocation count | 1 | 1 |
| tool count / write count / high-risk count | `1 / 0 / 0` | `1 / 0 / 0` |
| source | `manual_chatgpt_work` | `manual_chatgpt_work` |

Both calls used distinct challenges, responses, correlations and audit
records. The proof checker verified the active cycle, build, policy and tool
snapshot for each call. Conversation identifiers were not read or retained.
No pre-existing conversation was opened or used. The Plugins route rendered
its ordinary global navigation, but no history operation occurred and no
sidebar value entered a C8 receipt or committed artifact.

### Negative and revocation results

The final-cycle audit contained exactly five records:

- three `completed` records: the local probe, Work A and Work B;
- two `failed` records: same-Work replay and cross-Work replay.

The unknown-field and malformed-challenge inputs were rejected by the visible
tool schema before a new audit record could be created. Requests for files,
commands, secrets, writes, real evidence and protocol v2 remained absent from
the effective one-tool capability surface; unsafe requests were not forced.
Capability expansion stayed `false`.

The Tunnel and facade were stopped, ports `8765` and `8766` were closed, and
the Plugin connection was uninstalled. The operator revoked the fresh Runtime
key. A subsequent prompt in one of the two synthetic Work tasks returned
exactly `unreachable_after_revocation`, produced no audit record and did not
reconnect or reinstall anything.

The signed negative receipt was created at `2026-07-27T23:59:28Z`; the
revocation receipt followed at `23:59:30Z`. The final verifier then returned:

```text
COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED
```

Cleanup removed thirteen transient items, including both raw challenges, both
structured responses, the HMAC audit log, logs and SQLite databases. Eleven
typed receipts remain in the ignored local state directory. Process secrets
were cleared and live connectivity is not recoverable from the preserved
receipts.

## Post-live repository validation

After the final attestation and cleanup were recorded, the covered C8 tree
passed the following local checks before creation of the annotated evidence
tag:

- `uv lock --check`;
- Ruff lint plus the formatting ratchet: three changed Python files and zero
  new formatting debt;
- the mypy ratchet: three changed Python files and zero diagnostics;
- Markdown links across 58 files;
- deterministic evidence governance and the frozen Python dependency audit:
  76 resolved packages and no known vulnerability;
- Python, excluding only the not-yet-creatable historical C8 tag check:
  1,128 passed, 6 intentionally skipped, 82.10% coverage;
- all 81 tracked PowerShell modules and scripts parsed without syntax errors;
- `cargo fmt`, `cargo check`, strict Clippy, 106 Rust tests, doctests and
  rustdoc with warnings denied;
- `cargo audit`: 73 locked dependencies scanned against 1,170 advisories with
  no vulnerability reported.

The four tag-independent C8 seal tests also passed before sealing. The fifth
seal test requires the annotated tag by construction and therefore belongs
to the final tagged-tree validation and remote CI, not to pre-seal evidence.
The Windows pytest process emitted a non-fatal temporary-directory cleanup
warning after reporting the successful result; it did not change the test
status or repository tree.

### Irreversible commitments

| Commitment | SHA-256 |
|---|---|
| final attestation | `f2399d98fca34fe2c5496cc2d4e9ce3ab4d87453d1f4302b7933617878144346` |
| authorization | `f01047666d02c7f44872f9cceab6e6661524c2f5684a1976d2f728718cd19ec0` |
| grant | `5c925ee1a6c9daaa91d3a15e8df7498273803b282798bf7d060f8273484c29af` |
| Work A correlation receipt | `5a739d8039d876ea0fdacb9406cbde6532d1576583a9b9fdd798724211e36961` |
| Work B correlation receipt | `d68b62da81b6635ca958a9b60d3b0410b63ec5ab283e43be0e64d5798e91037b` |
| negative-test receipt | `c04e90065962b736281e4697995d9995d24769dbb073b43daa2366b9723cd05c` |
| revocation receipt | `d80080863899ec291c4326d0b122f4ccadd93304db5cf5d14c97f7be83496eca` |
| local policy | `17a53ee929232bae5901037c26c23ad1379dbdb09998c698b1ed85c60a75700e` |
| tool snapshot | `6d9a8e0f6dadb9f3a615abcca8c882cb37fb257944922151e97c65a8575da14b` |

Runtime keys, Tunnel IDs, raw challenges, structured live responses, audit
logs, database contents, Plugin IDs and conversation identifiers are not
versioned.

## Completion boundary

This result proves one bounded, dated, two-call ChatGPT Work connectivity
cycle with complete revocation. It does not prove native Chat support, which
remains `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`. It does not claim
regular-use readiness, a stable Work quota, a stable visible label, or an
exact internal model identity. A future provider must define and test its own
surface, authorization, transport, capability and revocation adapter rather
than inheriting ChatGPT-specific evidence.
