# C4 test and evidence ledger

Status: local validation complete; publication and final-head CI pending

Fixed CI evaluation time: `2026-07-27T12:00:00Z`

## Bound baseline

| Field | Exact value |
|---|---|
| Repository | `Cheurteenyt/systeme-local` |
| Issue | [#71](https://github.com/Cheurteenyt/systeme-local/issues/71) |
| C4 branch | `interop/provider-runtime-admission-c4` |
| Exact C3 base | `9140801e88ed44afca9481ac06288783a0d52da2` |
| C3 draft PR | [#70](https://github.com/Cheurteenyt/systeme-local/pull/70) |
| Runtime-adapter registry SHA-256 | `c63ae8d266ba25f7871b60f4f36b659b97a4f17e6fd13fc32b7acd6dcf85c20d` |
| Registered production providers | `chatgpt` only |
| Live credentials, Tunnels, Plugins, browser actions, or chats | `0` |

## Bypass-audit evidence

The audit covered:

- C0 and C1 PowerShell preparation, process, Tunnel, Plugin-guidance,
  evidence, cleanup, and branch guards;
- C2/C3 gate ownership and historical seal behavior;
- `main.py`, `McpToolRegistry`, `McpRuntime`, `TaskProcessor`, and
  `CapabilityExecutor`;
- provider deployment/readiness/live-probe modules;
- main and scheduled CI workflows;
- architecture, roadmap, threat model, provider documents, ADRs, and
  documentation governance.

The resulting boundary-by-boundary map and explicit out-of-repository limits
are recorded in the
[C4 runtime-admission contract](chatgpt-web-c4-runtime-admission.md#bypass-audit).

## Focused implementation tests

| ID | Scope | Direct result |
|---|---|---|
| `C4-L01` | Canonical requests, decisions, registry, and receipt commitments | PASS |
| `C4-L02` | Current committed ChatGPT decision over all six actions | PASS: six denied, zero effective tools |
| `C4-L03` | Synthetic supported non-tool and exact read-only tool paths | PASS |
| `C4-L04` | Due, expired, drifted, invalid, unsupported, unobservable, and candidate evidence | PASS |
| `C4-L05` | Unknown provider, native-surface substitution, and evidence identity substitution | PASS |
| `C4-L06` | Missing/extra fields, naive time, malformed correlation, duplicate tools, and digest mutation | PASS |
| `C4-L07` | Unapproved tool, protocol mutation, write privilege expansion, and action/tool mismatch | PASS |
| `C4-L08` | Receipt mutation and deterministic reproduction | PASS |
| `C4-L09` | Same-request replay and cross-request correlation collision | PASS |
| `C4-L10` | Forty concurrent uses of one correlation | PASS: exactly one allow in the synthetic supported controller |
| `C4-L11` | Provider-bound MCP registry construction and generic-registry reduction-only filter | PASS |
| `C4-L12` | Production-registry tamper and bounded secret-free CLI output | PASS |
| `C4-L13` | Initial C4 plus MCP registry suite | PASS: 50 tests |
| `C4-L14` | Four C4 PowerShell files and fixed-time real preflight/matrix | PASS: parser clean, six denials, zero tools |
| `C4-L15` | Direct Ruff and Mypy checks for changed admission/tool modules | PASS |
| `C4-L16` | Evidence-time substitution, immutable action bindings, defensive model revalidation, and closed decision invariants | PASS |
| `C4-L17` | Forged, cross-controller, and reused tool authority | PASS: all rejected; issued authority consumed once |
| `C4-L18` | Missing reviewed C3 path and C4 reparse path | PASS: missing evidence denied; reparse test skips if Windows denies symlink creation |
| `C4-L19` | Direct provider-bound Python import | PASS: denied before runtime initialization with secret-free error |
| `C4-L20` | Admission, docs, configuration, MCP registry focused suite | PASS: 79 passed, 1 Windows symlink test skipped |
| `C4-L21` | Direct Ruff and expanded Mypy for admission, config, main, and MCP registry | PASS |
| `C4-L22` | Bounded correlation table capacity exhaustion | PASS: denied without eviction or tool exposure |
| `C4-L23` | Complete Python suite with unchanged coverage threshold | PASS: 1,016 passed, 6 skipped; 86.62% total, 90% C4 |
| `C4-L24` | Lock, Ruff, format ratchet, Mypy ratchet, Markdown links, deterministic governance, Python dependency audit | PASS: 0 new format debt, 0 typing diagnostics, 47 linked files, no known vulnerability |
| `C4-L25` | Rust check, format, strict Clippy, workspace tests, doctests, docs, and RustSec audit | PASS: 106 tests; no warning or reported vulnerability |
| `C4-L26` | C0-C4 PowerShell parser and actual fixed-time C4 scripts | PASS: 50 files; six denials and zero tools |
| `C4-L27` | Fixed-time and real-time C3/C4 governance | PASS: C3 current/reviewed/unsupported; C4 six denials and zero tools |
| `C4-L28` | Changed-file credential-shape scan and local runtime safety state | PASS: 40 files, 0 findings; 0 sensitive process variables, listeners, or Tunnel processes |
| `C4-L29` | Self-excluding C4 change seal | PASS: exact C3 base, covered head, 41-file manifest, byte count, and SHA-256 reproduced |
| `C4-L30` | Clean-commit offline operator replay | PASS at `13d7fa168f4fd6ad3fd8d33e0e268081d8fb6075`: preflight denied; six matrix denials; zero tools |

The known Windows pytest temporary-directory `PermissionError` occurred in an
`atexit` cleanup callback after pytest returned success. It did not alter the
exit-zero test result and remains recorded.

## Current action/tool evidence

| Action | Admission | Effective tool count | Executed live |
|---|---|---|---|
| Runtime-key creation | deny | 0 | no |
| Tunnel startup | deny | 0 | no |
| Plugin creation | deny | 0 | no |
| Browser test | deny | 0 | no |
| ChatGPT action | deny | 0 | no |
| Tool-surface exposure | deny | 0 | no |

No C4 live receipt exists. C1 receipts remain historical evidence and are not
reclassified as C4 admission.

## Validation closeout

Before publication, this ledger must record:

- lock, Ruff, format and Mypy ratchets;
- complete Python suite and coverage;
- C0-C4 regressions, documentation contracts, and Markdown links;
- fixed-time CI admission and real-time evidence-governance behavior;
- Python and Rust dependency audits;
- bounded secret, process-environment, listener, and process scans;
- all applicable PowerShell parser checks;
- Rust check, format, strict Clippy, tests, doctests, and docs;
- clean-commit offline operator replay;
- self-excluding C4 seal;
- stacked draft-PR final-head CI.

No failed check may be deleted, softened, or relabeled.

The local closeout above satisfies every locally executable item. Stacked
draft-PR final-head CI and manual evidence-governance dispatch remain external
publication steps and are not predeclared as successful here.
