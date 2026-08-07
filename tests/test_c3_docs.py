from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from systeme_local_gateway.c3_evidence import (
    C3GateStatus,
    C3ProtectedAction,
    EvidenceLifecycleState,
    build_current_c3_official_capability_profile,
    build_current_c3_registry,
)

ROOT = Path(__file__).resolve().parents[1]
C3_DOC = ROOT / "docs/providers/chatgpt-web-c3-evidence-lifecycle.md"
C3_LEDGER = ROOT / "docs/providers/chatgpt-web-c3-test-evidence.md"
C3_SCRIPTS = ROOT / "scripts/c3"


def test_c3_document_records_exact_result_dates_and_base() -> None:
    text = C3_DOC.read_text(encoding="utf-8")

    for marker in (
        "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE",
        "2026-08-07T11:55:00Z",
        "2026-08-14T11:55:00Z",
        "2026-08-21T11:55:00Z",
        "cf05e963ba30539f9b2c9ec2f5f71326cbba8399",
        "issues/69",
        "product-surface decision, not a network or implementation failure",
    ):
        assert marker in text


def test_c3_document_binds_every_official_claim_and_registry_digest() -> None:
    text = C3_DOC.read_text(encoding="utf-8")
    profile = build_current_c3_official_capability_profile()
    registry = build_current_c3_registry()

    for source in profile.sources:
        assert source.url in text
        assert source.claim_sha256 in text
    for digest in (
        profile.conclusion_sha256,
        profile.evidence_sha256,
        profile.profile_sha256,
        registry.registry_sha256,
    ):
        assert digest in text


def test_c3_document_defines_lifecycle_support_and_action_matrices() -> None:
    text = C3_DOC.read_text(encoding="utf-8")

    for lifecycle in EvidenceLifecycleState:
        assert f"`{lifecycle.value}`" in text
    for state in ("`supported`", "`unsupported`", "`unobservable`"):
        assert state in text
    for action in C3ProtectedAction:
        assert f"`{action.value}`" in text
    for status in C3GateStatus:
        if status is C3GateStatus.READY:
            continue
        assert f"`{status.value}`" in text


def test_c3_document_records_gap_analysis_and_candidate_non_authority() -> None:
    text = C3_DOC.read_text(encoding="utf-8")

    for marker in (
        "Existing and reusable",
        "Missing before C3",
        "Incompatible with C3",
        "Debt outside C3",
        "A candidate is always `candidate`, never `reviewed`.",
        "No command automatically rewrites the active profile or registry.",
        "No second provider exists in this registry.",
    ):
        assert marker in text


def test_c3_document_bounds_prior_c1_proof_and_future_gate() -> None:
    text = C3_DOC.read_text(encoding="utf-8")

    for marker in (
        "What the earlier C1 calls proved",
        "real correlation receipts for two",
        "did **not** prove",
        "a currently supported native Chat product interface",
        "Some C1 cycles expired before final attestation",
        "Exact future gate",
        "explicitly establishes",
        "A generic reference to “ChatGPT,” a Tunnel, a new conversation",
    ):
        assert marker in text


def test_c3_document_excludes_every_private_or_live_surface() -> None:
    text = C3_DOC.read_text(encoding="utf-8")
    ledger = C3_LEDGER.read_text(encoding="utf-8")

    for marker in (
        "does not open ChatGPT or Work",
        "read history",
        "account/security settings",
        "cookies/storage/private requests",
        "create a Runtime key",
        "create/start a Tunnel",
        "create a Plugin",
    ):
        assert marker in text
    for marker in (
        "| Runtime credentials created | `0` |",
        "| Tunnels created or started | `0` |",
        "| Plugins created | `0` |",
        "| Browser or ChatGPT actions | `0` |",
        "C3 creates no live receipt.",
    ):
        assert marker in ledger


def test_c3_operator_scripts_are_strict_secret_free_and_complete() -> None:
    scripts = sorted((*C3_SCRIPTS.glob("*.ps1"), *C3_SCRIPTS.glob("*.psm1")))

    assert len(scripts) == 8
    for script in scripts:
        text = script.read_text(encoding="utf-8")
        assert "Set-StrictMode -Version Latest" in text
        assert '$ErrorActionPreference = "Stop"' in text
        assert "CONTROL_PLANE_API_KEY" not in text
        assert "CONTROL_PLANE_TUNNEL_ID" not in text
        assert "SLG_SHARED_SECRET" not in text
    common = (C3_SCRIPTS / "C3.Common.psm1").read_text(encoding="utf-8")
    assert "direct .systeme-local\\c3 child" in common
    assert "cannot be a reparse point" in common


def test_c3_is_historical_and_c4_owns_current_c1_runtime_admission() -> None:
    expected = {
        "Prepare-C1.ps1": "runtime_key_creation",
        "Start-C1Facade.ps1": "tool_surface_exposure",
        "Start-C1Tunnel.ps1": "tunnel_start",
        "Show-C1OperatorSteps.ps1": "plugin_creation",
    }
    for name, action in expected.items():
        text = (ROOT / "scripts/c1" / name).read_text(encoding="utf-8")

        assert "..\\c4\\C4.Common.psm1" in text
        assert "Assert-C4ProtectedActionAllowed" in text
        assert f'"{action}"' in text
        assert text.index("Assert-C4ProtectedActionAllowed") < text.index("Assert-C1GitState")
        assert "..\\c3\\C3.Common.psm1" not in text


def test_c3_governance_and_ci_are_read_only_and_deterministic() -> None:
    manifest = (ROOT / "governance/evidence-profiles.toml").read_text(encoding="utf-8")
    scheduled = (ROOT / ".github/workflows/evidence-governance.yml").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for marker in (
        'id = "chatgpt_chat_c3_official_capability_profile"',
        'source = "src/systeme_local_gateway/c3_evidence.py"',
        'document = "docs/providers/chatgpt-web-c3-evidence-lifecycle.md"',
        'reviewed_at = "2026-08-07T11:55:00Z"',
        'revalidate_after = "2026-08-21T11:55:00Z"',
    ):
        assert marker in manifest
    assert "permissions:\n  contents: read" in scheduled
    assert "c3_evidence\n          governance\n          --github-annotations" in scheduled
    assert "--as-of 2026-08-10T12:00:00Z" in ci
    assert "issues: write" not in scheduled
    assert "contents: write" not in scheduled


def test_c3_docs_are_linked_from_navigation_and_project_authorities() -> None:
    expected = {
        "README.md": "docs/providers/chatgpt-web-c3-evidence-lifecycle.md",
        "docs/index.md": "providers/chatgpt-web-c3-evidence-lifecycle.md",
        "docs/architecture.md": "providers/chatgpt-web-c3-evidence-lifecycle.md",
        "docs/roadmap.md": "C3",
        "docs/threat-model.md": "C3",
        "docs/providers/chatgpt.md": "C3",
    }
    for name, marker in expected.items():
        assert marker in (ROOT / name).read_text(encoding="utf-8")


def test_c3_ledger_separates_official_local_live_and_closeout_evidence() -> None:
    text = C3_LEDGER.read_text(encoding="utf-8")

    for marker in (
        "Official-document review",
        "Gap analysis evidence",
        "Focused implementation tests",
        "Live-action ledger",
        "Validation closeout",
        "C3-E01",
        "C3-L13",
        "Required failures remain failures",
    ):
        assert marker in text


def test_c3_change_seal_is_complete_self_excluding_and_stacked() -> None:
    seal = json.loads((ROOT / "governance/c3-change-seal.json").read_text(encoding="utf-8"))
    changed = seal["changed_files"]

    assert seal["base_commit"] == "cf05e963ba30539f9b2c9ec2f5f71326cbba8399"
    assert seal["stacked_base_branch"] == "interop/chatgpt-web-capability-gating-c2"
    assert seal["branch"] == "interop/provider-capability-revalidation-c3"
    assert seal["changed_file_count"] == len(changed)
    assert changed == sorted(set(changed))
    assert "governance/c3-change-seal.json" in changed
    assert "governance/c3-capability-registry.json" in changed
    assert "src/systeme_local_gateway/c3_evidence.py" in changed
    assert "tests/test_c3_evidence.py" in changed
    assert "tests/test_c3_docs.py" in changed
    assert seal["diff"]["excluded_paths"] == ["governance/c3-change-seal.json"]

    diff = subprocess.run(
        [
            "git",
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            seal["base_commit"],
            "9140801e88ed44afca9481ac06288783a0d52da2",
            "--",
            ".",
            ":(exclude)governance/c3-change-seal.json",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    assert len(diff) == seal["diff"]["bytes"]
    assert hashlib.sha256(diff).hexdigest() == seal["diff"]["sha256"]
