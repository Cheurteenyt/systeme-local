from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from systeme_local_gateway.c2_capability import (
    C2FinalStatus,
    C2LiveAction,
    build_current_c2_official_capability_profile,
)

ROOT = Path(__file__).resolve().parents[1]
C2_SEALED_COMMIT = "cf05e963ba30539f9b2c9ec2f5f71326cbba8399"
C2_DOC = ROOT / "docs/providers/chatgpt-web-c2-capability-gating.md"
C2_LEDGER = ROOT / "docs/providers/chatgpt-web-c2-test-evidence.md"
C2_SCRIPTS = ROOT / "scripts/c2"


def test_c2_document_records_exact_question_result_and_freshness() -> None:
    text = C2_DOC.read_text(encoding="utf-8")

    for marker in (
        "Can any officially documented ChatGPT Chat surface invoke a custom or local",
        "without using ChatGPT Work?",
        "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE",
        "2026-08-07T01:40:00Z",
        "2026-08-21T01:40:00Z",
        "This is a capability result, not a tunnel failure.",
        "No reviewed public interface provides an alternative",
    ):
        assert marker in text


def test_c2_document_binds_profile_and_every_canonical_source() -> None:
    text = C2_DOC.read_text(encoding="utf-8")
    profile = build_current_c2_official_capability_profile()

    assert profile.profile_sha256 in text
    for source in profile.sources:
        assert source.url in text
        assert source.summary_sha256 in text


def test_c2_document_defines_exact_three_state_fail_closed_matrix() -> None:
    text = C2_DOC.read_text(encoding="utf-8")

    for state in ("`supported`", "`unsupported`", "`unobservable`"):
        assert state in text
    for status in C2FinalStatus:
        assert f"`{status.value}`" in text
    for action in C2LiveAction:
        assert action.value in text


def test_c2_document_excludes_private_surfaces_and_all_live_actions() -> None:
    text = C2_DOC.read_text(encoding="utf-8")
    ledger = C2_LEDGER.read_text(encoding="utf-8")

    for marker in (
        "open or test Work",
        "history, the sidebar, or an existing conversation",
        "cookies, storage, private requests, private browser state",
        "Security/Account settings",
        "No secret or transport environment variable is needed",
    ):
        assert marker in text
    for marker in (
        "| C2 live credential count | `0` |",
        "| C2 tunnel start count | `0` |",
        "| C2 Plugin creation count | `0` |",
        "| C2 browser test count | `0` |",
        "no C2 live Chat proof",
        "never fabricated live evidence",
    ):
        assert marker in ledger


def test_c2_provider_neutrality_is_minimal_and_nonportable() -> None:
    text = C2_DOC.read_text(encoding="utf-8")
    adr = (ROOT / "docs/adr/0009-chatgpt-chat-official-capability-gate.md").read_text(
        encoding="utf-8"
    )

    for marker in (
        "ChatGPT remains the only implemented Web capability profile",
        "No second provider",
        "ChatGPT evidence must never be copied",
        "The surface class is taxonomy, not capability inheritance.",
    ):
        assert marker in text
    for marker in (
        "reusable data shapes only",
        "requires its own identifier, native-surface mapping, sources",
        "creates no portability or",
    ):
        assert marker in adr


def test_c2_operator_scripts_have_strict_safety_prologues() -> None:
    scripts = sorted((*C2_SCRIPTS.glob("*.ps1"), *C2_SCRIPTS.glob("*.psm1")))

    assert len(scripts) == 4
    for script in scripts:
        text = script.read_text(encoding="utf-8")
        assert "Set-StrictMode -Version Latest" in text
        assert '$ErrorActionPreference = "Stop"' in text
        assert "CONTROL_PLANE_API_KEY" not in text
        assert "CONTROL_PLANE_TUNNEL_ID" not in text


def test_c2_document_records_stronger_c3_gate_ownership_without_rewriting_history() -> None:
    text = C2_DOC.read_text(encoding="utf-8")

    for marker in (
        "Current action-gate owner: C3.",
        "C2 remains an immutable historical capability",
        "C1 live entry",
        "imported C2 at this historical commit",
        "On the C3 descendant they import",
        "stronger C3 registry/lifecycle gate",
    ):
        assert marker in text


def test_c2_evidence_governance_profile_is_registered() -> None:
    manifest = (ROOT / "governance/evidence-profiles.toml").read_text(encoding="utf-8")

    for marker in (
        'id = "chatgpt_chat_c2_official_capability_profile"',
        'source = "src/systeme_local_gateway/c2_capability.py"',
        'document = "docs/providers/chatgpt-web-c2-capability-gating.md"',
        'reviewed_assignment = "C2_REVIEWED_AT"',
        'revalidate_assignment = "C2_REVALIDATE_AFTER"',
        'reviewed_at = "2026-08-07T01:40:00Z"',
        'revalidate_after = "2026-08-21T01:40:00Z"',
    ):
        assert marker in manifest


def test_c2_docs_are_linked_from_navigation_and_project_docs() -> None:
    paths = {
        "README.md": "docs/providers/chatgpt-web-c2-capability-gating.md",
        "docs/index.md": "providers/chatgpt-web-c2-capability-gating.md",
        "docs/architecture.md": "providers/chatgpt-web-c2-capability-gating.md",
    }
    for name, marker in paths.items():
        assert marker in (ROOT / name).read_text(encoding="utf-8")
    for name in ("docs/roadmap.md", "docs/threat-model.md"):
        assert "C2" in (ROOT / name).read_text(encoding="utf-8")


def test_c2_ledger_separates_official_local_live_and_final_validation() -> None:
    text = C2_LEDGER.read_text(encoding="utf-8")

    for marker in (
        "Official evidence review",
        "Implemented deterministic tests",
        "Live-action ledger",
        "Validation closeout",
        "C2-E01",
        "C2-L08",
        "correctly blocked",
        "must not soften, omit, or rewrite the failure",
    ):
        assert marker in text


def test_c2_change_seal_is_complete_self_excluding_and_stacked() -> None:
    seal = json.loads((ROOT / "governance/c2-change-seal.json").read_text(encoding="utf-8"))
    changed = seal["changed_files"]

    assert seal["base_commit"] == "2aee36fdfa3d20c23acdc75eb3348bc54536ef4f"
    assert seal["stacked_base_branch"] == "interop/chatgpt-web-chat-observability-c1"
    assert seal["branch"] == "interop/chatgpt-web-capability-gating-c2"
    assert seal["changed_file_count"] == len(changed)
    assert changed == sorted(set(changed))
    assert "governance/c2-change-seal.json" in changed
    assert "governance/c2-official-capability-profile.json" in changed
    assert "src/systeme_local_gateway/c2_capability.py" in changed
    assert "tests/test_c2_capability.py" in changed
    assert "tests/test_c2_docs.py" in changed
    assert seal["diff"]["excluded_paths"] == ["governance/c2-change-seal.json"]

    diff = subprocess.run(
        [
            "git",
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            seal["base_commit"],
            C2_SEALED_COMMIT,
            "--",
            ".",
            ":(exclude)governance/c2-change-seal.json",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    assert len(diff) == seal["diff"]["bytes"]
    assert hashlib.sha256(diff).hexdigest() == seal["diff"]["sha256"]
