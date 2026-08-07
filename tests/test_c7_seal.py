from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c7_seal import (
    C7_BASE_COMMIT,
    C7_BRANCH,
    C7_EVIDENCE_TAG,
    C7_MANIFEST_PATH,
    C7_SEAL_PATH,
    C7ChangeManifest,
    canonical_sha256,
    compute_c7_tree_commitment,
    verify_c7_seal,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / C7_MANIFEST_PATH


def test_c7_manifest_is_exact_no_live_and_self_covering() -> None:
    manifest = C7ChangeManifest.model_validate_json(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest.base_commit == C7_BASE_COMMIT
    assert manifest.branch == C7_BRANCH
    assert manifest.evidence_tag == C7_EVIDENCE_TAG
    assert manifest.issue == 76
    assert manifest.official_source_count == 6
    assert manifest.reviewed_outcome == "COMPLETE_C7_WORK_PROFILE_READY_FOR_BOUNDED_LIVE_VALIDATION"
    assert manifest.native_chat_outcome == "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"
    assert C7_MANIFEST_PATH in manifest.changed_files
    assert C7_SEAL_PATH not in manifest.changed_files
    assert manifest.official_docs_review_performed is True
    assert manifest.browser_actions_performed is False
    assert manifest.credentials_created is False
    assert manifest.tunnel_started is False
    assert manifest.plugin_created is False
    assert manifest.provider_live_actions_performed is False
    assert manifest.effective_tool_count == 0
    assert len(canonical_sha256(manifest.model_dump(mode="json"))) == 64


def test_c7_manifest_rejects_unknown_duplicate_and_seal_paths() -> None:
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    payload["unknown"] = True
    with pytest.raises(ValidationError):
        C7ChangeManifest.model_validate(payload)

    payload.pop("unknown")
    payload["changed_files"].append(payload["changed_files"][-1])
    with pytest.raises(ValidationError, match="sorted and unique"):
        C7ChangeManifest.model_validate(payload)

    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    payload["changed_files"].append(C7_SEAL_PATH)
    payload["changed_files"].sort()
    with pytest.raises(ValidationError, match="self-referential seal"):
        C7ChangeManifest.model_validate(payload)


def test_c7_tree_commitment_is_content_framed_and_deterministic() -> None:
    first = compute_c7_tree_commitment(ROOT, "HEAD")
    second = compute_c7_tree_commitment(ROOT, "HEAD")
    assert first == second
    assert first.algorithm == "sha256-framed-tree-v1"
    assert first.excluded_paths == (C7_SEAL_PATH,)
    assert first.file_count > 300
    assert first.blob_bytes > 3_000_000


def test_c7_historical_seal_verifies_tag_diff_manifest_and_tree() -> None:
    result = verify_c7_seal(ROOT)
    assert result.status == "verified"
    assert result.base_commit == C7_BASE_COMMIT
    assert result.current_tree_required is False
    assert result.covered_changed_file_count > 15
    assert result.tree_file_count > 300
    assert result.tree_blob_bytes > 3_000_000
    assert result.provider_live_actions_performed is False
    assert result.effective_tool_count == 0


def test_c7_seal_module_has_no_provider_runtime_or_browser_dependency() -> None:
    source = (ROOT / "src/systeme_local_gateway/c7_seal.py").read_text(encoding="utf-8")
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
