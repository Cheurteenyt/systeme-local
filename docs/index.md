# Documentation index

Status: descriptive navigation index

This page is **descriptive navigation only**. It summarizes and links to the
repository’s existing documents; it **does not own normative facts**. When a summary
here conflicts with a linked document, the linked document remains authoritative.

## Start here

- [Project overview and safe entry points](../README.md)
- [Target architecture](blueprint-v2.md)
- [Implemented architecture](architecture.md)
- [Delivery roadmap](roadmap.md)
- [Threat model](threat-model.md)
- [Documentation governance](documentation-governance.md)

## Authority boundary

- README remains the concise project entry point.
- This index maps documents but does not redefine their authority.
- Architecture, protocols, security controls, provider facts, ADRs, and roadmap status
  remain owned by their linked documents.
- A roadmap entry does not authorize a capability.

## Complete document map

### Project entry points and contributor contracts

| Document | Descriptive role |
|---|---|
| [Système Local Agent Gateway](../README.md) | Project entry point, onboarding, or contribution contract. |

### Architecture and delivery

| Document | Descriptive role |
|---|---|
| [Architecture actuellement implémentée](architecture.md) | Target or implemented architecture; the linked document defines its scope. |
| [Roadmap](roadmap.md) | Delivery sequencing, status, and gates. |

### Architectural decisions

| Document | Descriptive role |
|---|---|
| [ADR 0001: Separate provider channels](adr/0001-provider-channel-separation.md) | Durable architectural decision and consequences. |
| [ADR 0002: Keep provider context locally canonical](adr/0002-local-canonical-provider-context.md) | Durable architectural decision and consequences. |
| [ADR 0003: Use evidence-bound staged ChatGPT MCP readiness](adr/0003-evidence-bound-chatgpt-mcp-readiness.md) | Durable architectural decision and consequences. |
| [ADR 0004: Exclude raw provider evidence from public models](adr/0004-raw-provider-evidence-exclusion.md) | Durable architectural decision and consequences. |
| [ADR 0005: Split operator-evidence authority between Python and Rust](adr/0005-python-rust-operator-evidence-custody.md) | Durable architectural decision and consequences. |

### Security and operator evidence

| Document | Descriptive role |
|---|---|
| [Modèle de menace](threat-model.md) | Threats, controls, and residual risks. |

### Connectivity, protocols, and provider integration

| Document | Descriptive role |
|---|---|
| [Connectivity model — provider-specific web AI channels](connectivity-model.md) | Provider-specific characterization, evidence, or integration contract. |
| [Operator-evidence custodian protocol](operator-evidence-custodian-protocol.md) | Protocol, wire, data, or custody contract. |
| [Provider attachment manifests and deterministic batching](provider-attachments.md) | Provider-specific characterization, evidence, or integration contract. |
| [Provider context registry](provider-context-registry.md) | Provider-specific characterization, evidence, or integration contract. |
| [Provider package compatibility audit](provider-package-audit.md) | Provider-specific characterization, evidence, or integration contract. |
| [ChatGPT MCP connection readiness and evidence reconciliation](providers/chatgpt-mcp-connection-readiness.md) | Provider-specific characterization, evidence, or integration contract. |
| [ChatGPT MCP deployment evidence and operator contract](providers/chatgpt-mcp-deployment.md) | Provider-specific characterization, evidence, or integration contract. |
| [ChatGPT MCP sealed operator evidence bundle](providers/chatgpt-mcp-operator-evidence.md) | Provider-specific characterization, evidence, or integration contract. |
| [ChatGPT provider characterization](providers/chatgpt.md) | Provider-specific characterization, evidence, or integration contract. |

### Governance and repository policy

| Document | Descriptive role |
|---|---|
| [Documentation governance](documentation-governance.md) | Documentation, contribution, security, or evidence governance. |
| [GitHub governance evidence](github-governance.md) | Bounded repository-settings and policy snapshot. |

### Audit, reference, and component guidance

| Document | Descriptive role |
|---|---|
| [pull request template](../.github/pull_request_template.md) | Contributor or component guidance. |
| [Contribuer à Système Local](../CONTRIBUTING.md) | Contributor or component guidance. |
| [Security Policy](../SECURITY.md) | Contributor or component guidance. |
| [Système Local Audit Watchdog](../crates/audit-watchdog/README.md) | Historical measurement or audit record. |
| [Blueprint v2 — Système Local](blueprint-v2.md) | Contributor or component guidance. |
| [Operator-evidence session lifecycle](operator-evidence-session-lifecycle.md) | Contributor or component guidance. |
| [Operator-evidence synthetic staging](operator-evidence-staging.md) | Contributor or component guidance. |
| [Rust audit watchdog](rust-audit-watchdog.md) | Historical measurement or audit record. |
| [Windows audit witness contract](windows-audit-witness.md) | Historical measurement or audit record. |
