# Documentation governance

Status: normative ownership contract

## Purpose

Système Local separates overview, target architecture, implemented architecture, normative
contracts, provider facts and delivery planning. A document must not silently take over the role
of another document.

## Authority matrix

| Path | Authority |
|---|---|
| `README.md` | concise overview, safe operator entry points and links |
| `docs/blueprint-v2.md` | target product architecture |
| `docs/architecture.md` | architecture implemented on `main` |
| `docs/connectivity-model.md` | sole normative cross-provider connectivity contract |
| `docs/provider-context-registry.md` | provider-neutral account/project/conversation context |
| `docs/provider-attachments.md` | provider-neutral attachment metadata and batching |
| `docs/providers/chatgpt.md` | ChatGPT surface characterization and implementation status |
| `docs/providers/chatgpt-mcp-*.md` | expiring ChatGPT MCP evidence and operator contracts |
| `docs/operator-evidence-custodian-protocol.md` | private Python/Rust custody subprocess contract |
| `docs/operator-evidence-session-lifecycle.md` | private Rust custody-session state and transition contract |
| `docs/operator-evidence-staging.md` | private Rust capability-rooted synthetic staging contract |
| `docs/threat-model.md` | current threats, controls and residual risks |
| `docs/roadmap.md` | ordered delivery status and gates |
| `docs/adr/*.md` | accepted decisions and consequences |
| `docs/github-governance.md` | bounded snapshot of repository settings and unknowns |

Provider-specific facts never become cross-provider defaults. Target architecture never implies
implementation. A roadmap entry never authorizes a capability.

## Status vocabulary

Documents that describe implementation use only:

- `implemented`;
- `partial`;
- `planned`;
- `research`;
- `blocked_by_evidence`;
- `out_of_scope`.

Provider evidence documents additionally record review and revalidation timestamps. Expired
evidence cannot be described as current even when historical tests remain green.

## Change rules

A change must update every affected authority:

- architecture changes update implemented architecture and, when structural, an ADR;
- new provider facts update the provider document and evidence manifest;
- new capability or trust boundary updates the threat model;
- public schema or digest changes require an explicit compatibility decision;
- roadmap status changes only after merge evidence exists;
- README remains concise and links to normative details instead of duplicating them.

## Automated checks

CI verifies:

- the Ruff formatting ratchet: no new debt and every touched Python file formatted;
- the Mypy ratchet: governance scripts type-clean, no new provider-model diagnostics and touched
  debt-bearing files repaired;
- the exported lock dependency audit: frozen `uv.lock`, hashes required and local project omitted;
- the Python test security floor: `pytest>=9.0.3,<10`, with `pytest 9.0.3` locked to
  remediate `PYSEC-2026-1845` without an audit ignore;
- relative Markdown links;
- source-of-truth markers;
- implemented/planned status consistency;
- provider phase references;
- evidence review and revalidation dates;
- CODEOWNERS and PR-template governance markers.

The scheduled evidence-governance workflow intentionally uses current time. Unit and pull-request
tests use an explicit `--as-of` timestamp so they remain deterministic.
