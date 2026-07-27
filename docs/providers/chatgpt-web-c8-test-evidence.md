# C8 test and evidence ledger

Status: offline implementation validation in progress; live Work evidence not
yet claimed

Recorded at: `2026-07-27`

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

The post-live and post-seal repository-wide reruns remain pending because C8
has not admitted a Work cycle.

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

## Live evidence

No live success is recorded in this section until all of these local ignored
artifacts exist and validate:

```text
authorization.json
work-surface.json
work-quota.json
live-cycle.json
task-surface-a.json
task-surface-b.json
proof-a.json
proof-b.json
negative-tests.json
revocation.json
attestation.json
```

Runtime keys, Tunnel IDs, raw challenges, structured live responses, audit
logs and databases are never versioned. Final documentation records only
bounded states, counts and irreversible SHA-256 commitments.
