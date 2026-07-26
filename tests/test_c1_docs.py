import json
import hashlib
from pathlib import Path
import subprocess

from systeme_local_gateway.c1_observability import (
    C1NegativeCheckId,
    C1SetupField,
    build_current_c1_official_evidence_profile,
)
from systeme_local_gateway.mcp_tools import McpToolRegistry
from systeme_local_gateway.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
C1_DOC = ROOT / "docs/providers/chatgpt-mcp-c1-observability.md"
C1_LEDGER = ROOT / "docs/providers/chatgpt-mcp-c1-test-evidence.md"
C1_SCRIPTS = ROOT / "scripts/c1"


def test_committed_official_profile_matches_builder_byte_for_byte() -> None:
    committed = json.loads(
        (ROOT / "governance/c1-official-evidence-profile.json").read_text(encoding="utf-8")
    )
    current = build_current_c1_official_evidence_profile()

    assert committed == current.model_dump(mode="json")
    assert current.profile_sha256 in C1_DOC.read_text(encoding="utf-8")
    for source in current.sources:
        assert source.url in C1_DOC.read_text(encoding="utf-8")
        assert source.summary_sha256 in C1_DOC.read_text(encoding="utf-8")


def test_c1_document_keeps_chat_work_runtime_and_visible_labels_separate() -> None:
    text = C1_DOC.read_text(encoding="utf-8")

    for marker in (
        "C1 does not detect, enumerate, search, identify, or read",
        "It does not test",
        "ChatGPT Work.",
        "active Codex runtime model",
        "Codex configuration defaults",
        "ChatGPT-visible model and reasoning labels",
        "does not infer ChatGPT's internal model routing",
        "No reviewed official integration contract exposes existing ChatGPT Web chat",
        "BLOCKED_BY_NO_OFFICIAL_CHAT_HISTORY_INTERFACE",
    ):
        assert marker in text


def test_c1_document_binds_exact_unchanged_c0_tool_snapshot() -> None:
    text = C1_DOC.read_text(encoding="utf-8")
    policy = PolicyEngine(ROOT / "policy.c0.yaml")
    registry = McpToolRegistry(policy, c0_mode=True)

    assert registry.tool_snapshot_sha256 in text
    assert policy.policy_sha256 in text
    for marker in (
        "tool_count = 1",
        "write_tool_count = 0",
        "high_risk_tool_count = 0",
        "readOnlyHint = true",
        "destructiveHint = false",
        "idempotentHint = true",
        "openWorldHint = false",
    ):
        assert marker in text


def test_c1_document_lists_all_runtime_setup_fields_and_precedence() -> None:
    source = (ROOT / "src/systeme_local_gateway/c1_observability.py").read_text(encoding="utf-8")
    for field in C1SetupField:
        assert f'"{field.value}"' in source

    text = C1_DOC.read_text(encoding="utf-8")
    for index, marker in enumerate(
        (
            "CLI override",
            "project configuration",
            "profile configuration",
            "user configuration",
            "system configuration",
            "built-in default",
        ),
        start=1,
    ):
        assert f"{index}. {marker}" in text


def test_c1_document_lists_exactly_two_test_chats_and_all_negative_checks() -> None:
    text = C1_DOC.read_text(encoding="utf-8")

    assert "c1-test-chat-a" in text
    assert "c1-test-chat-b" in text
    assert "exactly two new pages" in text
    for check_id in C1NegativeCheckId:
        assert (
            check_id.value.replace("_", "-")
            in (ROOT / "scripts/c1/Confirm-C1NegativeTests.ps1").read_text(encoding="utf-8").lower()
        )


def test_c1_operator_scripts_have_required_safety_prologue() -> None:
    scripts = sorted(C1_SCRIPTS.glob("*.ps1"))

    assert len(scripts) >= 14
    for script in scripts:
        text = script.read_text(encoding="utf-8")
        assert "Set-StrictMode -Version Latest" in text
        assert '$ErrorActionPreference = "Stop"' in text
        assert (
            "ConvertTo-Json" in text
            or '$result -join "`n"' in text
            or script.name == "Show-C1OperatorSteps.ps1"
        )


def test_c1_common_requires_dedicated_stacked_branch_and_private_state() -> None:
    text = (C1_SCRIPTS / "C1.Common.psm1").read_text(encoding="utf-8")

    assert 'C1ExpectedBranch = "interop/chatgpt-web-chat-observability-c1"' in text
    assert '".systeme-local\\c1"' in text
    assert "escaped the repository-private state root" in text
    assert "Assert-C1StateFile" in text


def test_c1_surface_script_has_chat_work_codex_unknown_guard() -> None:
    text = (C1_SCRIPTS / "New-C1SurfaceObservation.ps1").read_text(encoding="utf-8")
    source = (ROOT / "src/systeme_local_gateway/c1_observability.py").read_text(encoding="utf-8")

    assert '[ValidateSet("chat", "work", "codex", "unknown")]' in text
    assert '"prompt_sent": False' in source
    assert "refuses prompts and Plugin selection outside Chat" in source


def test_c1_visible_label_script_requires_base64_for_non_ascii_labels() -> None:
    text = (C1_SCRIPTS / "New-C1VisibleModelObservation.ps1").read_text(encoding="utf-8")
    common = (C1_SCRIPTS / "C1.Common.psm1").read_text(encoding="utf-8")

    for marker in (
        "$VisibleModelLabelUtf8Base64",
        "$VisibleReasoningLabelUtf8Base64",
        "Non-ASCII model labels must use VisibleModelLabelUtf8Base64.",
        "Non-ASCII reasoning labels must use ",
        "VisibleReasoningLabelUtf8Base64.",
        "not both",
    ):
        assert marker in text
    for marker in (
        "ConvertFrom-C1Utf8Base64",
        "UTF8Encoding($false, $true)",
        "valid canonical UTF-8 Base64",
    ):
        assert marker in common


def test_c1_final_script_requires_every_live_receipt_and_noncomplete_c0_status() -> None:
    text = (C1_SCRIPTS / "Commit-C1FinalAttestation.ps1").read_text(encoding="utf-8")

    for marker in (
        "runtime-setup.json",
        "visible-model.json",
        "surface-a.json",
        "surface-b.json",
        "proof-a.json",
        "proof-b.json",
        "negative-tests.json",
        "revocation.json",
        "audit.jsonl",
        "READY_BUT_MANUAL_CHATGPT_WEB_GATE_PENDING",
        "COMPLETE_BOUNDED_CHAT_SURFACE_OBSERVABILITY_VERIFIED",
    ):
        assert marker in text


def test_c1_revocation_requires_manual_plugin_key_and_failed_call_facts() -> None:
    text = (C1_SCRIPTS / "Confirm-C1Revocation.ps1").read_text(encoding="utf-8")

    for marker in (
        "$PluginConnectionRemoved",
        "$RuntimeApiKeyRevoked",
        "$PostRevocationChatCallFailed",
        "proof-a.json",
        "proof-b.json",
        "8765",
        "8766",
    ):
        assert marker in text
    assert text.count("[Parameter(Mandatory = $true)]") == 3


def test_c1_cleanup_removes_raw_material_and_preserves_only_typed_receipts() -> None:
    text = (C1_SCRIPTS / "Clear-C1Temporary.ps1").read_text(encoding="utf-8")

    for marker in (
        "attestation.json",
        "negative-tests.json",
        "proof-a.json",
        "proof-b.json",
        "revocation.json",
        "runtime-setup.json",
        "surface-a.json",
        "surface-b.json",
        "visible-model.json",
        "SLG_AUDIT_KEY",
        "process_secrets_cleared",
        "recoverable = $false",
    ):
        assert marker in text
    for raw in ("challenge-a.txt", "challenge-b.txt", "live-response-a.json"):
        assert raw not in text


def test_c1_preflight_cleanup_refuses_correlated_or_final_evidence() -> None:
    text = (C1_SCRIPTS / "Clear-C1Preflight.ps1").read_text(encoding="utf-8")

    for marker in (
        "attestation.json",
        "proof-a.json",
        "proof-b.json",
        "revocation.json",
        "Preflight cleanup refuses correlated or final C1 evidence.",
        "correlated_evidence_removed = $false",
        "process_secrets_cleared = $true",
    ):
        assert marker in text


def test_c1_browser_scope_excludes_private_and_existing_chat_state() -> None:
    text = (C1_SCRIPTS / "Show-C1OperatorSteps.ps1").read_text(encoding="utf-8")

    for marker in (
        "Never open the sidebar",
        "history",
        "existing chats",
        "storage",
        "cookies",
        "private requests",
        "unrelated tabs",
        "Work is detected but never prompted",
    ):
        assert marker in text


def test_c1_change_seal_is_complete_self_excluding_and_stacked() -> None:
    seal = json.loads((ROOT / "governance/c1-change-seal.json").read_text(encoding="utf-8"))
    changed = seal["changed_files"]

    assert seal["base_commit"] == "912d0d33e119469ff957965104cf20af5e491923"
    assert seal["main_at_start"] == "32515ac9cbb9d658b2ddcb2723ab3c0a71f2b418"
    assert seal["stacked_base_branch"] == "interop/chatgpt-web-mcp-connectivity-c0"
    assert seal["changed_file_count"] == len(changed) == 37
    assert changed == sorted(set(changed))
    assert "governance/c1-change-seal.json" in changed
    assert "docs/providers/chatgpt-mcp-c1-test-evidence.md" in changed
    assert seal["diff"]["excluded_paths"] == ["governance/c1-change-seal.json"]
    assert len(seal["diff"]["sha256"]) == 64
    assert seal["diff"]["bytes"] > 0

    diff = subprocess.run(
        [
            "git",
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            seal["base_commit"],
            "--",
            ".",
            ":(exclude)governance/c1-change-seal.json",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    assert len(diff) == seal["diff"]["bytes"]
    assert hashlib.sha256(diff).hexdigest() == seal["diff"]["sha256"]


def test_c1_evidence_ledger_separates_executed_and_pending_tests() -> None:
    text = C1_LEDGER.read_text(encoding="utf-8")
    runbook = C1_DOC.read_text(encoding="utf-8")

    assert "C1 test and evidence ledger" in runbook
    for marker in (
        "DEVELOPER_MODE_AUTHORIZATION_AND_PLAN_PENDING",
        "858 passed, 5 skipped, 86.11% coverage",
        "72 C1 tests",
        "live-setup",
        "This proves transport readiness only",
        "Live Chat tests not yet executed",
        "operator subsequently supplied bounded browser authorization",
        "Developer mode still",
        "requires a separate action-time authorization",
        "same-chat and cross-chat replay checks",
        "post-revocation failure",
        "Final validation still required",
        "must not rewrite",
        "`not-run` as `PASS`",
    ):
        assert marker in text


def test_c1_evidence_ledger_is_linked_from_navigation() -> None:
    ledger_path = "docs/providers/chatgpt-mcp-c1-test-evidence.md"

    assert ledger_path in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "providers/chatgpt-mcp-c1-test-evidence.md" in (ROOT / "docs/index.md").read_text(
        encoding="utf-8"
    )
