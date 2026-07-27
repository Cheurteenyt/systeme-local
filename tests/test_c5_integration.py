from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c5_integration import (
    C4_SEALED_COMMIT,
    C5_ACCEPTED_MAIN_COMMIT,
    C5_EVIDENCE_TAG,
    C5_MAIN_BASE,
    IntegrationManifest,
    canonical_sha256,
    compute_tree_commitment,
    verify_integration,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "governance/c5-integration-manifest.json"
SEAL_PATH = ROOT / "governance/c5-change-seal.json"
C5_DOC = ROOT / "docs/providers/chatgpt-web-c5-main-integration.md"


def test_c5_manifest_binds_exact_stack_and_no_live_actions() -> None:
    manifest = IntegrationManifest.model_validate_json(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert manifest.base_commit == C5_MAIN_BASE
    assert manifest.evidence_tag == C5_EVIDENCE_TAG
    assert manifest.merge_method == "squash"
    assert tuple(layer.gate for layer in manifest.source_stack) == (
        "C0",
        "C1",
        "C2",
        "C3",
        "C4",
    )
    assert manifest.source_stack[-1].head == C4_SEALED_COMMIT
    assert manifest.historical_branches_are_evidence is True
    assert manifest.live_actions_permitted is False


def test_c5_manifest_rejects_unknown_fields_and_substituted_head() -> None:
    value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    value["unexpected"] = True
    with pytest.raises(ValidationError):
        IntegrationManifest.model_validate(value)

    value.pop("unexpected")
    value["source_stack"][-1]["head"] = "a" * 40
    with pytest.raises(ValidationError, match="heads are not exact"):
        IntegrationManifest.model_validate(value)


def test_c5_tree_commitment_is_content_framed_and_deterministic() -> None:
    first = compute_tree_commitment(ROOT, "HEAD")
    second = compute_tree_commitment(ROOT, "HEAD")

    assert first == second
    assert first.algorithm == "sha256-framed-tree-v1"
    assert first.file_count > 100
    assert first.blob_bytes > 100_000


def test_c5_integration_verifies_exact_tag_diff_tree_and_ancestry() -> None:
    result = verify_integration(ROOT)

    assert result.status == "verified"
    assert result.base_commit == C5_MAIN_BASE
    assert result.source_head == C4_SEALED_COMMIT
    assert result.accepted_main_commit == C5_ACCEPTED_MAIN_COMMIT
    assert result.tree_file_count > 100
    assert result.tree_blob_bytes > 100_000
    assert result.live_actions_performed is False


def test_c5_manifest_commitment_is_canonical() -> None:
    manifest = IntegrationManifest.model_validate_json(MANIFEST_PATH.read_text(encoding="utf-8"))
    digest = canonical_sha256(manifest.model_dump(mode="json"))

    assert len(digest) == 64
    assert digest == canonical_sha256(manifest.model_dump(mode="json"))


def test_c5_document_records_simulation_failure_and_integration_contract() -> None:
    text = C5_DOC.read_text(encoding="utf-8")

    for marker in (
        "1,015 passed",
        "C4 seal/HEAD invariant",
        "squash-only",
        C5_EVIDENCE_TAG,
        "framed SHA-256 tree commitment",
        "zero live actions",
        "PRs #65, #67, #68, #70, and #72",
        "must not be merged independently",
        C5_ACCEPTED_MAIN_COMMIT,
        "current head to descend from accepted `main`",
    ):
        assert marker in text


def test_c5_module_has_no_network_browser_or_secret_dependency() -> None:
    source = (ROOT / "src/systeme_local_gateway/c5_integration.py").read_text(encoding="utf-8")

    for forbidden in (
        "import http",
        "import requests",
        "import socket",
        "import webbrowser",
        "CONTROL_PLANE_API_KEY",
        "CONTROL_PLANE_TUNNEL_ID",
        "SLG_SHARED_SECRET",
        "SLG_AUDIT_KEY",
        "SLG_MCP_TOKEN",
    ):
        assert forbidden not in source


def test_c5_scheduled_governance_fetches_complete_tagged_ancestry() -> None:
    workflow = (ROOT / ".github/workflows/evidence-governance.yml").read_text(encoding="utf-8")

    checkout = workflow.split("- name: Check out repository", maxsplit=1)[1].split(
        "- name: Set up Python", maxsplit=1
    )[0]
    assert "persist-credentials: false" in checkout
    assert "fetch-depth: 0" in checkout
    assert "contents: write" not in workflow
