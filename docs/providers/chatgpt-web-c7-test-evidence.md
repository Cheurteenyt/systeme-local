# C7 test and evidence ledger

Status: local pre-seal validation complete; final repository seal and remote
CI pending

Recorded at: `2026-07-27`

## Claim under test

C7 must represent ChatGPT Work as an independent supported surface while
keeping native Chat denied and all live effects disabled until a fresh,
HMAC-authenticated future C8 authorization exists.

## Evidence classes

| Class | What it proves | What it does not prove |
|---|---|---|
| official documentation review | current public Work, Plugin and MCP surface contract | current account entitlement, quota or live behavior |
| deterministic Python tests | exact identity, commitments, lifecycle, grant and default-deny behavior | a ChatGPT call |
| PowerShell checks | offline boundary, branch/base ancestry and zero default effects | Work availability in the user interface |
| repository validation | code, docs, dependencies and governance remain consistent | live connectivity or production readiness |

## Focused C7 validation

- 47 C7 Python tests passed in the pre-seal repository run; the one test that
  requires the final annotated tag was deliberately deselected until the seal
  exists;
- generated and committed Work profile matched byte-for-byte;
- generated and committed pre-live policy matched byte-for-byte;
- default evaluation denied all six protected effects and exposed zero tools;
- a synthetic valid HMAC grant admitted only the exact reviewed probe in
  memory;
- missing, short or wrong audit keys failed closed;
- expired, cross-profile and cross-policy grants failed closed;
- privacy/capability expansion and surface substitution were rejected;
- missing entitlement, unusable quota, stale surface observation, stale quota
  observation and non-Work visible surface were rejected;
- due and expired official evidence denied all effects;
- unknown fields and modified commitments were rejected;
- all five C7 PowerShell files parsed;
- prerequisite, status and C8-gate scripts ran successfully with the
  deliberate development-only dirty-tree override.

## Complete local pre-seal validation

The repository-wide Python command selected 1,103 tests and deliberately
deselected only the final C7 tag-and-seal test:

- 1,097 passed;
- 6 skipped by their existing platform or environment conditions;
- 1 deliberately deselected;
- 85.05% total statement coverage against a 60% required floor.

Pytest returned exit code zero. Windows then reported a best-effort temporary
directory cleanup warning for `pytest-current` (`WinError 5`). This happened
after the successful result and did not change or suppress a test outcome.

The complete Rust validation passed:

- `cargo check --workspace --all-targets --all-features --locked`;
- `cargo fmt --all -- --check`;
- Clippy across the workspace, all targets and all features with warnings
  denied;
- 106 unit and integration tests;
- documentation tests;
- documentation generation with rustdoc warnings denied;
- `cargo audit`, scanning the 73 dependencies in `Cargo.lock` without a known
  vulnerability finding.

The repository quality and governance checks passed:

- `uv lock --check`;
- Ruff lint;
- Ruff-format ratchet: 42 approved legacy files, 5 changed Python files and
  zero new debt;
- mypy ratchet: zero approved legacy diagnostics, 5 changed Python files and
  zero new diagnostics;
- Markdown links across 55 files;
- evidence governance at `2026-07-27T16:00:00Z`;
- frozen Python dependency audit with no known vulnerability;
- GitHub Actions YAML parsing;
- every repository PowerShell file parsing;
- `git diff --check`;
- bounded scanning of all 28 changed or untracked text files: zero
  credential-shaped Runtime keys, zero exact Tunnel IDs and zero assigned
  process-secret values.

The deterministic product gates also passed:

- C3 remained `BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE`;
- C4 denied every derived Chat action and exposed zero tools;
- the C5 integrated tree and ancestry verified;
- C6 remained review-only and its historical annotated seal verified;
- C7 returned
  `COMPLETE_C7_WORK_PROFILE_READY_FOR_BOUNDED_LIVE_VALIDATION`, while denying
  all six protected effects and exposing zero tools;
- C7 PowerShell prerequisites confirmed zero sensitive process variables,
  zero listeners on the C0/C1 ports and zero Tunnel client processes.

Final seal commitments and the remote check results are recorded only after
those commands have run. They are not predicted here.

## Official-source activity

The six source pages or relevant sections were retrieved through the public
OpenAI documentation interface. No credential or private account state was
used. Only canonical summaries and SHA-256 commitments are versioned.

No raw page body, browser state, Runtime key, Tunnel ID, Plugin ID, chat,
conversation identifier or account setting is retained.

## Live activity

The following are all `not-run` in C7:

- ChatGPT UI control;
- Work selection or invocation;
- creation of a Work thread or Chat conversation;
- Runtime-key or Tunnel credential creation;
- Tunnel or facade startup;
- Plugin creation or installation;
- MCP tool invocation;
- positive or negative Web calls;
- live revocation testing.

These belong only to a separately authorized C8 lot.
