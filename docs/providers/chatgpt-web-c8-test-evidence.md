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
