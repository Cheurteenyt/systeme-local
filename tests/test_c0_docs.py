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
    assert manifest["source_commit"] == "105e17a79a36e4e5c897fd698ed2b8dbf935b144"
    assert manifest["release_url"].startswith("https://github.com/openai/tunnel-client/releases/")
    assert manifest["configuration_url"].startswith(
        "https://github.com/openai/tunnel-client/blob/v0.0.10/"
    )
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


def test_stop_script_clears_every_c0_process_secret_and_runtime_setting() -> None:
    text = (ROOT / "scripts/c0/Stop-C0.ps1").read_text(encoding="utf-8")

    for variable in (
        "CONTROL_PLANE_API_KEY",
        "CONTROL_PLANE_TUNNEL_ID",
        "SLG_SHARED_SECRET",
        "SLG_AUDIT_KEY",
        "SLG_AUDIT_ANCHOR_LOG",
        "SLG_AUDIT_ANCHOR_KEY",
        "SLG_MCP_TOKEN",
        "SLG_MCP_AUTHORIZATION",
        "SLG_MCP_MAX_REQUEST_BYTES",
        "SLG_MCP_REQUESTS_PER_MINUTE",
        "SLG_MCP_MAX_CONCURRENCY",
        "SLG_POLICY_FILE",
        "SLG_WORKSPACE",
        "SLG_AUDIT_LOG",
        "SLG_REPLAY_DB",
        "SLG_APPROVAL_DB",
        "SLG_SANDBOX_ROOT",
    ):
        assert f'"{variable}"' in text


def test_facade_starts_outside_repo_env_and_rejects_inherited_anchor() -> None:
    text = (ROOT / "scripts/c0/Start-C0Facade.ps1").read_text(encoding="utf-8")

    assert "-WorkingDirectory $state" in text
    assert "-WorkingDirectory $root" not in text
    assert '"SLG_AUDIT_ANCHOR_LOG"' in text
    assert '"SLG_AUDIT_ANCHOR_KEY"' in text


def test_facade_tracks_windows_launcher_and_socket_owner_separately() -> None:
    start = (ROOT / "scripts/c0/Start-C0Facade.ps1").read_text(encoding="utf-8")
    stop = (ROOT / "scripts/c0/Stop-C0.ps1").read_text(encoding="utf-8")
    common = (ROOT / "scripts/c0/C0.Common.psm1").read_text(encoding="utf-8")

    assert '"facade-launcher.pid"' in start
    assert "Get-CimInstance Win32_Process" in start
    assert "$runtimeMetadata.ParentProcessId -ne $process.Id" in start
    assert "Assert-C0LoopbackListener -ProcessId $runtimePid -Port 8765" in start
    assert "Stop-C0PythonLauncher" in stop
    assert "Wait-Process -Id $processId -Timeout 5" in common


def test_local_tunnel_client_probe_is_bounded_and_never_claims_web() -> None:
    text = (ROOT / "scripts/c0/Test-C0TunnelClientLocal.ps1").read_text(encoding="utf-8")

    assert '"dev",' in text
    assert '"proxy",' in text
    assert '"channel=main,url=http://127.0.0.1:8765/mcp"' in text
    assert "Authorization: env:SLG_MCP_AUTHORIZATION" in text
    assert "refuses hosted control-plane credentials" in text
    assert "LOG_HTTP_RAW_UNSAFE" in text
    assert "real_chatgpt_web = $false" in text


def test_final_attestation_requires_authenticated_pending_live_proof() -> None:
    script = (ROOT / "scripts/c0/Commit-C0LiveAttestation.ps1").read_text(encoding="utf-8")
    source = (ROOT / "src/systeme_local_gateway/c0_attest.py").read_text(encoding="utf-8")

    assert "--pending-live-proof $paths.pending" in script
    assert "verify_c0_pending_live_proof_receipt" in source
