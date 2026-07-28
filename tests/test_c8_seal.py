from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c8_seal import (
    C8_BASE_COMMIT,
    C8_BRANCH,
    C8_EVIDENCE_TAG,
    C8_FINAL_STATUS,
    C8_MANIFEST_PATH,
    C8_SEAL_PATH,
    C8ChangeManifest,
    canonical_sha256,
    compute_c8_tree_commitment,
    verify_c8_seal,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / C8_MANIFEST_PATH


def test_c8_manifest_is_exact_live_revoked_and_self_covering() -> None:
    manifest = C8ChangeManifest.model_validate_json(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest.base_commit == C8_BASE_COMMIT
    assert manifest.branch == C8_BRANCH
    assert manifest.evidence_tag == C8_EVIDENCE_TAG
    assert manifest.issue == 78
    assert manifest.official_source_count == 7
    assert manifest.reviewed_outcome == C8_FINAL_STATUS
    assert manifest.native_chat_outcome == "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"
    assert C8_MANIFEST_PATH in manifest.changed_files
    assert C8_SEAL_PATH not in manifest.changed_files
    assert manifest.browser_actions_performed is True
    assert manifest.runtime_key_platform_revocation_confirmed is True
    assert manifest.tunnel_started is True
    assert manifest.plugin_connection_created is True
    assert manifest.plugin_connection_removed is True
    assert manifest.live_work_calls_correlated == 2
    assert manifest.work_tasks_created == 2
    assert manifest.completed_audit_records == 3
    assert manifest.failed_audit_records == 2
    assert manifest.capability_expanded is False
    assert manifest.revocation_verified is True
    assert manifest.regular_use_readiness_claimed is False
    assert manifest.raw_sensitive_evidence_versioned is False
    assert len(canonical_sha256(manifest.model_dump(mode="json"))) == 64


def test_c8_manifest_rejects_unknown_duplicate_and_seal_paths() -> None:
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    payload["unknown"] = True
    with pytest.raises(ValidationError):
        C8ChangeManifest.model_validate(payload)

    payload.pop("unknown")
    payload["changed_files"].append(payload["changed_files"][-1])
    with pytest.raises(ValidationError, match="sorted and unique"):
        C8ChangeManifest.model_validate(payload)

    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    payload["changed_files"].append(C8_SEAL_PATH)
    payload["changed_files"].sort()
    with pytest.raises(ValidationError, match="self-referential seal"):
        C8ChangeManifest.model_validate(payload)


def test_c8_tree_commitment_is_content_framed_and_deterministic() -> None:
    first = compute_c8_tree_commitment(ROOT, "HEAD")
    second = compute_c8_tree_commitment(ROOT, "HEAD")
    assert first == second
    assert first.algorithm == "sha256-framed-tree-v1"
    assert first.excluded_paths == (C8_SEAL_PATH,)
    assert first.file_count > 350
    assert first.blob_bytes > 3_000_000


def test_c8_historical_seal_verifies_tag_diff_manifest_tree_and_live_boundary() -> None:
    result = verify_c8_seal(ROOT)
    assert result.status == "verified"
    assert result.base_commit == C8_BASE_COMMIT
    assert result.current_tree_required is False
    assert result.covered_changed_file_count > 40
    assert result.tree_file_count > 350
    assert result.tree_blob_bytes > 3_000_000
    assert result.reviewed_outcome == C8_FINAL_STATUS
    assert result.provider_live_actions_performed is True
    assert result.work_call_count == 2
    assert result.revocation_verified is True
    assert result.effective_tool_count == 1


def test_c8_seal_module_has_no_provider_runtime_or_browser_dependency() -> None:
    source = (ROOT / "src/systeme_local_gateway/c8_seal.py").read_text(encoding="utf-8")
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
        "chatgpt.com",
    ):
        assert forbidden not in source
