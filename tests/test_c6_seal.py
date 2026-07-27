import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from systeme_local_gateway.c6_seal import (
    C6_BASE_COMMIT,
    C6_BRANCH,
    C6_EVIDENCE_TAG,
    C6_MANIFEST_PATH,
    C6_SEAL_PATH,
    C6ChangeManifest,
    canonical_sha256,
    compute_c6_tree_commitment,
    verify_c6_seal,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / C6_MANIFEST_PATH


def test_c6_manifest_is_exact_fail_closed_and_self_covering() -> None:
    manifest = C6ChangeManifest.model_validate_json(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert manifest.base_commit == C6_BASE_COMMIT
    assert manifest.branch == C6_BRANCH
    assert manifest.evidence_tag == C6_EVIDENCE_TAG
    assert manifest.official_source_count == 4
    assert manifest.reviewed_outcome == "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"
    assert C6_MANIFEST_PATH in manifest.changed_files
    assert C6_SEAL_PATH not in manifest.changed_files
    assert manifest.public_docs_acquisition_performed is True
    assert manifest.raw_content_persisted is False
    assert manifest.automatic_promotion_performed is False
    assert manifest.provider_live_actions_performed is False
    assert len(canonical_sha256(manifest.model_dump(mode="json"))) == 64


def test_c6_manifest_rejects_unknown_fields_duplicate_paths_and_seal_coverage() -> None:
    value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    value["unknown"] = True
    with pytest.raises(ValidationError):
        C6ChangeManifest.model_validate(value)

    value.pop("unknown")
    value["changed_files"].append(value["changed_files"][-1])
    with pytest.raises(ValidationError, match="sorted and unique"):
        C6ChangeManifest.model_validate(value)

    value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    value["changed_files"].append(C6_SEAL_PATH)
    value["changed_files"].sort()
    with pytest.raises(ValidationError, match="self-referential seal"):
        C6ChangeManifest.model_validate(value)


def test_c6_tree_commitment_is_content_framed_and_deterministic() -> None:
    first = compute_c6_tree_commitment(ROOT, "HEAD")
    second = compute_c6_tree_commitment(ROOT, "HEAD")

    assert first == second
    assert first.algorithm == "sha256-framed-tree-v1"
    assert first.excluded_paths == (C6_SEAL_PATH,)
    assert first.file_count > 300
    assert first.blob_bytes > 3_000_000


def test_c6_final_seal_verifies_tag_diff_manifest_and_tree() -> None:
    result = verify_c6_seal(ROOT, require_current_tree=True)

    assert result.status == "verified"
    assert result.base_commit == C6_BASE_COMMIT
    assert result.current_tree_required is True
    assert result.covered_changed_file_count > 20
    assert result.tree_file_count > 300
    assert result.tree_blob_bytes > 3_000_000
    assert result.provider_live_actions_performed is False


def test_c6_seal_module_has_no_provider_runtime_or_browser_dependency() -> None:
    source = (ROOT / "src/systeme_local_gateway/c6_seal.py").read_text(encoding="utf-8")

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
