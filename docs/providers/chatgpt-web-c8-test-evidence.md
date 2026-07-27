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
and one existing environment-dependent case skipped. The exact repository-wide
and post-seal results will be added only after they run.

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
