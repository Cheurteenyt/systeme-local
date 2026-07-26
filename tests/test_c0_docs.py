import json
from pathlib import Path

from systeme_local_gateway.providers import (
    build_current_chatgpt_mcp_capability_profile,
    build_current_chatgpt_mcp_evidence_reconciliation_profile,
)
from systeme_local_gateway.mcp_tools import McpToolRegistry
from systeme_local_gateway.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
C0_DOC = ROOT / "docs/providers/chatgpt-mcp-c0-connectivity.md"


def test_c0_document_binds_current_official_profiles() -> None:
    text = C0_DOC.read_text(encoding="utf-8")
    capability = build_current_chatgpt_mcp_capability_profile()
    reconciliation = build_current_chatgpt_mcp_evidence_reconciliation_profile()

    assert capability.profile_sha256 in text
    assert reconciliation.profile_sha256 in text
    for source in capability.sources:
        assert source.url in text
        assert source.statement_sha256 in text or source.source_id == "openai_chatgpt_projects"


def test_committed_c0_tool_snapshot_matches_runtime_exactly() -> None:
    snapshot = json.loads((ROOT / "governance/c0-tool-snapshot.json").read_text(encoding="utf-8"))
    policy = PolicyEngine(ROOT / "policy.c0.yaml")
    registry = McpToolRegistry(policy, c0_mode=True)

    assert snapshot["tool_count"] == 1
    assert snapshot["write_tool_count"] == 0
    assert snapshot["high_risk_tool_count"] == 0
    assert snapshot["local_policy_sha256"] == policy.policy_sha256
    assert snapshot["tool_snapshot_sha256"] == registry.tool_snapshot_sha256
    assert snapshot["tools"] == registry.protocol_tools()


def test_c0_change_seal_is_complete_and_self_excluding() -> None:
    seal = json.loads((ROOT / "governance/c0-change-seal.json").read_text(encoding="utf-8"))
    changed_files = seal["changed_files"]

    assert seal["base_commit"] == "32515ac9cbb9d658b2ddcb2723ab3c0a71f2b418"
    assert seal["changed_file_count"] == len(changed_files)
    assert len(changed_files) == len(set(changed_files))
    assert "governance/c0-change-seal.json" in changed_files
    assert seal["diff"]["excluded_paths"] == ["governance/c0-change-seal.json"]
    assert len(seal["diff"]["sha256"]) == 64


def test_tunnel_client_manifest_pins_official_origin_version_and_integrity() -> None:
    manifest = json.loads((ROOT / "governance/c0-tunnel-client.json").read_text(encoding="utf-8"))

    assert manifest["project"] == "openai/tunnel-client"
    assert manifest["version"] == "v0.0.10"
    assert manifest["release_url"].startswith("https://github.com/openai/tunnel-client/releases/")
    assert manifest["asset"]["url"].startswith("https://github.com/openai/tunnel-client/releases/")
    assert len(manifest["asset"]["sha256"]) == 64
    assert len(manifest["binary_sha256"]) == 64


def test_c0_document_records_exact_one_tool_and_fixed_security_claims() -> None:
    text = C0_DOC.read_text(encoding="utf-8")

    for marker in (
        "tool_count = 1",
        "write_tool_count = 0",
        "high_risk_tool_count = 0",
        "readOnlyHint = true",
        "destructiveHint = false",
        "idempotentHint = true",
        "openWorldHint = false",
        "real_evidence_access=false",
        "protocol_v2_reachable=false",
    ):
        assert marker in text


def test_c0_document_lists_exactly_the_existing_eleven_checks() -> None:
    text = C0_DOC.read_text(encoding="utf-8")
    for marker in (
        "`plan_role_observation`",
        "`web_client`",
        "`transport`",
        "`authentication_metadata`",
        "`refresh_token`",
        "`developer_mode`",
        "`app_configuration`",
        "`workspace_access`",
        "`tool_snapshot`",
        "`action_review`",
        "`local_policy`",
    ):
        assert marker in text


def test_c0_document_has_ten_step_rollback_and_no_live_claim() -> None:
    text = C0_DOC.read_text(encoding="utf-8")

    for index in range(1, 11):
        assert f"{index}. " in text
    assert "manual ChatGPT Web gate not yet observed" in text
    assert "The repository contains no live ChatGPT Web observation" in text


def test_c0_operator_scripts_have_required_safety_prologue() -> None:
    scripts = sorted((ROOT / "scripts/c0").glob("*.ps1"))
    assert len(scripts) >= 10
    for script in scripts:
        text = script.read_text(encoding="utf-8")
        assert "Set-StrictMode -Version Latest" in text
        assert '$ErrorActionPreference = "Stop"' in text
        assert (
            "ConvertTo-Json" in text
            or '$result -join "`n"' in text
            or script.name == "Show-C0ChatGptSteps.ps1"
        )


def test_revocation_script_requires_each_manual_fact_explicitly() -> None:
    text = (ROOT / "scripts/c0/Confirm-C0Revocation.ps1").read_text(encoding="utf-8")

    for switch in (
        "$PluginConnectionRemoved",
        "$RuntimeApiKeyRevoked",
        "$ManualCallFailedAfterRevocation",
    ):
        assert switch in text
    assert text.count("[Parameter(Mandatory = $true)]") == 3
