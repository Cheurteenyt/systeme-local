# Provider package compatibility audit

Status: measured at commit `164b69bbfebab18db65b2ae5b990756db59c5518`

## Current public surface

`src/systeme_local_gateway/providers/__init__.py` contains **179 public `__all__` exports** across **397 lines**.

The façade currently combines:

- lifecycle and event-store models;
- provider context and selection policy;
- attachment inspection, manifests, plans and receipts;
- deterministic fake providers;
- ChatGPT MCP deployment models and policy;
- readiness and evidence-reconciliation models;
- sealed operator-evidence models and evaluation.

## Repeated canonicalization primitives

| Helper | Module count | Locations |
|---|---:|---|
| `_canonical_json` | 3 | `src/systeme_local_gateway/providers/mcp_deployment_models.py`, `src/systeme_local_gateway/providers/mcp_readiness_models.py`, `src/systeme_local_gateway/providers/mcp_operator_evidence_models.py` |
| `_require_aware` | 3 | `src/systeme_local_gateway/providers/mcp_deployment_models.py`, `src/systeme_local_gateway/providers/mcp_readiness_models.py`, `src/systeme_local_gateway/providers/mcp_operator_evidence_models.py` |
| `_validate_sorted_unique_enum_tuple` | 3 | `src/systeme_local_gateway/providers/mcp_deployment_models.py`, `src/systeme_local_gateway/providers/mcp_readiness_models.py`, `src/systeme_local_gateway/providers/mcp_operator_evidence_models.py` |
| `_validate_sorted_unique_string_tuple` | 2 | `src/systeme_local_gateway/providers/mcp_deployment_models.py`, `src/systeme_local_gateway/providers/mcp_readiness_models.py` |

These helpers are intentionally measured rather than extracted in this lot.

## Formatting baseline

Ruff 0.15.22 identified 57 legacy Python files that predate repository-wide formatter
enforcement. Reformatting them in this documentation and governance lot would create a broad
unrelated diff across security-sensitive runtime and tests.

`governance/ruff-format-baseline.txt` records that exact debt. The formatting ratchet:

- rejects every unformatted Python file outside the baseline;
- requires every Python file touched by a change to be formatted;
- permits baseline debt to shrink;
- never permits the baseline to grow implicitly.

A dedicated mechanical-format lot may retire the remaining baseline after semantic review.

## Incremental typing boundary

Mypy 1.20.2 currently reports three diagnostics in two provider-model files:

- one missing annotation for `LIFECYCLE_EVENT_ADAPTER` in `models.py`;
- two `sorted(...)` argument diagnostics in `mcp_deployment_models.py`.

These files are not modified in this architecture lot. `governance/mypy-baseline.json` records the
exact path, error code, stable message fragment and count. `scripts/check_python_typing.py`
requires every governance script to be type-clean, rejects diagnostics outside that baseline,
rejects baseline growth and requires a touched debt-bearing file to retire its diagnostics.

The provider-package compatibility refactor must remove this baseline without changing model
fields, enum values, canonical bytes or digest domains.

## Compatibility contract for the follow-up refactor

- No public import or digest domain changes without a separate compatibility decision.
- Every current `systeme_local_gateway.providers` export remains importable.
- Pydantic field names, enum values and strict/frozen behavior remain unchanged.
- Canonical JSON byte representation and UTC normalization remain byte-for-byte compatible.
- Domain-separated SHA-256 prefixes remain unchanged.
- Existing lifecycle, context, attachment, deployment, readiness and operator-evidence tests remain
  authoritative.
- New subpackages may own implementation details, while the current façade remains a compatibility
  layer.

The next refactor should extract common helpers first, then separate provider-neutral and
ChatGPT-specific modules in bounded steps.
