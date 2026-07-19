# Provider package compatibility audit

Status: compatibility-preserving canonicalization refactor for issue #41, rooted at
`c720f4ae9d295e3e2af6993b40a0b03bfd14c2b9`.

## Public compatibility surface

`src/systeme_local_gateway/providers/__init__.py` remains a compatibility façade with **179
ordered public exports** across **397 lines**. The façade continues to combine:

- lifecycle and event-store models;
- provider context and selection policy;
- attachment inspection, manifests, plans and receipts;
- deterministic fake providers;
- ChatGPT MCP deployment models and policy;
- readiness and evidence-reconciliation models;
- sealed operator-evidence models and evaluation.

No public import is moved, renamed, removed or added by this refactor.
The package therefore preserves 179 public `__all__` exports in their exact order.
No public import or digest domain changes are introduced.

## Compatibility oracles

The refactor is guarded by
`tests/fixtures/provider_canonicalization_compatibility_v1.json`, which is bound to the fixed base
commit and the pre-refactor audit report.

The fixture and its executable tests preserve:

- the exact order, origin and identity contract of all 179 façade exports;
- 18 affected public Pydantic model contracts and schemas;
- 22 affected public enum definitions and values;
- canonical JSON bytes, aware-datetime validation and UTC normalization;
- duplicate-before-sort validation behavior and exact error messages;
- all 13 domain-separated SHA-256 prefixes;
- one behavioral message-and-digest vector for every direct digest function in the deployment,
  readiness and operator-evidence model layers.

The fixture contains no secrets, account data, personal paths, live provider data or raw operator
evidence.

## Private canonicalization ownership

`src/systeme_local_gateway/providers/_canonicalization.py` privately owns the shared MCP
canonicalization family:

| Helper | Ownership |
|---|---|
| `_canonical_json` | private provider-neutral implementation |
| `_require_aware` | private provider-neutral implementation |
| `_validate_sorted_unique_enum_tuple` | private generic `StrEnum` implementation |
| `_validate_sorted_unique_string_tuple` | private string implementation |

The deployment, readiness and operator-evidence model modules import these private helpers. They no
longer define local copies. Domain constants, model fields, enum values, digest call ordering and
public object origins remain in their original modules.

The private helper module is not exported through `systeme_local_gateway.providers.__all__` and does
not create a new public API commitment.

## Formatting ratchet

Ruff formatting debt decreases from 57 to 54 files because the three touched MCP model modules are
fully formatted and removed from `governance/ruff-format-baseline.txt`.

Unrelated legacy files remain governed by the non-growing ratchet and are not mechanically
reformatted in this lot.

## Typing boundary

The provider-model Mypy baseline is retired from three diagnostics to zero:

- the shared enum validator is precisely generic and produces a typed `tuple[str, ...]`;
- `LIFECYCLE_EVENT_ADAPTER` has an explicit `TypeAdapter[LifecycleEvent]` annotation;
- the private canonicalization module is part of the configured Mypy scope;
- no ignore, broad cast, wildcard rule or replacement suppression is introduced.

`governance/mypy-baseline.json` remains as the deterministic zero-debt governance contract.

## Compatibility contract

- Every current `systeme_local_gateway.providers` export remains importable in the same order.
- Pydantic field names, aliases, defaults, strictness, frozen behavior and schemas remain unchanged.
- Canonical JSON byte representation and UTC normalization remain byte-for-byte compatible.
- Validation order, exception types and migrated helper messages remain unchanged.
- Domain-separated SHA-256 prefixes, message bytes and digests remain unchanged.
- Existing lifecycle, context, attachment, deployment, readiness and operator-evidence tests remain
  authoritative.
- No remote or local capability, provider call, tunnel, OAuth/OIDC configuration, credential,
  browser automation or evidence collection is introduced.

## Remaining package-separation boundary

This lot does not split the public façade or move public classes and functions into new subpackages.
A later provider-neutral versus ChatGPT-specific package reorganization requires a separate
compatibility and versioning decision.

The unrelated Python 3.14 SQLite `ResourceWarning` debt also remains outside this refactor.
