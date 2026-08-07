from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_c8_normative_docs_keep_work_chat_and_readiness_separate() -> None:
    provider = _text("docs/providers/chatgpt-web-c8-work-live-validation.md")
    roadmap = _text("docs/roadmap.md")
    chatgpt = _text("docs/providers/chatgpt.md")
    for text in (provider, roadmap, chatgpt):
        assert "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED" in text
        assert "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE" in text
        assert "regular-use" in text or "regular use" in text
    assert "No automatic Chat-to-Work switch" in provider
    assert "at most two new synthetic Work tasks" in provider


def test_c8_security_and_architecture_docs_bind_revocation() -> None:
    adr = _text("docs/adr/0015-bind-live-work-effects-to-one-revocable-c8-cycle.md")
    threat = _text("docs/threat-model.md")
    architecture = _text("docs/architecture.md")
    assert "one revocable C8 cycle" in adr
    assert "C8 bounded Work live-cycle threats" in threat
    assert "chatgpt_work_c8" in architecture
    for text in (adr, threat, architecture):
        assert "Runtime key" in text
        assert "revocation" in text


def test_c8_governance_and_operator_paths_are_documented() -> None:
    provider = _text("docs/providers/chatgpt-web-c8-work-live-validation.md")
    index = _text("docs/index.md")
    readme = _text("README.md")
    assert "governance/c8-official-work-revalidation.json" in provider
    assert "governance/c8-live-work-policy.json" in provider
    assert "chatgpt-web-c8-work-live-validation.md" in index
    assert "0015-bind-live-work-effects-to-one-revocable-c8-cycle.md" in index
    assert "chatgpt-web-c8-work-live-validation.md" in readme


def test_c8_policy_defaults_to_zero_effect_and_exact_probe() -> None:
    policy = json.loads(_text("governance/c8-live-work-policy.json"))
    assert policy["default_live_actions_allowed"] is False
    assert policy["only_eligible_tool"] == "systeme_local_connectivity_probe"
    assert policy["max_new_synthetic_work_tasks"] == 2
    assert policy["max_live_cycle_seconds"] == 1200
    assert policy["max_observation_age_seconds"] == 300
    assert policy["write_actions_allowed"] is False
    assert policy["real_evidence_access_allowed"] is False
    assert policy["protocol_v2_allowed"] is False
    assert policy["native_chat_gate_status"] == ("BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE")


def test_c8_scripts_cover_complete_bounded_lifecycle() -> None:
    scripts = {
        path.name: path.read_text(encoding="utf-8")
        for path in (ROOT / "scripts" / "c8").glob("*")
        if path.is_file()
    }
    assert set(scripts) == {
        "C8.Common.psm1",
        "Clear-C8Temporary.ps1",
        "Commit-C8FinalAttestation.ps1",
        "Confirm-C8NegativeTests.ps1",
        "Confirm-C8Revocation.ps1",
        "Confirm-C8WorkProof.ps1",
        "New-C8Challenge.ps1",
        "New-C8WorkAdmission.ps1",
        "New-C8WorkTaskObservation.ps1",
        "Prepare-C8.ps1",
        "Reset-C8LocalOnly.ps1",
        "Reset-C8PreLive.ps1",
        "Start-C8Facade.ps1",
        "Start-C8Tunnel.ps1",
        "Stop-C8.ps1",
        "Test-C8LocalProbe.ps1",
        "Test-C8Prerequisites.ps1",
        "Test-C8Seal.ps1",
    }
    combined = "\n".join(scripts.values())
    assert "chatgpt_work_c8" in combined
    assert "systeme_local_connectivity_probe" in combined
    assert "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE" not in combined
    assert "CONTROL_PLANE_API_KEY" in combined
    assert "CONTROL_PLANE_TUNNEL_ID" in combined
    assert 'LOG_HTTP_RAW_UNSAFE = "false"' in combined
    assert 'ALLOW_REMOTE_UI = "false"' in combined
    assert "Read-Host" not in combined


def test_c8_pre_live_reset_is_narrow_and_fails_closed() -> None:
    script = _text("scripts/c8/Reset-C8PreLive.ps1")
    provider = _text("docs/providers/chatgpt-web-c8-work-live-validation.md")
    assert "ConfirmedNoLiveActions" in script
    assert "authorization.json" in script
    assert "work-surface.json" in script
    assert "work-quota.json" in script
    assert "live-cycle.json" not in script
    assert "proof-a.json" not in script
    assert "Get-NetTCPConnection" in script
    assert "unexpected" in script
    assert "one PowerShell terminal" in provider
    assert "Reset-C8PreLive.ps1 -ConfirmedNoLiveActions" in provider


def test_c8_local_only_reset_requires_exact_safe_probe_and_zero_remote_state() -> None:
    script = _text("scripts/c8/Reset-C8LocalOnly.ps1")
    provider = _text("docs/providers/chatgpt-web-c8-work-live-validation.md")
    assert "ConfirmedNoRemoteOrWorkActions" in script
    assert "exactly one local probe audit record" in script
    assert "systeme_local_connectivity_probe" in script
    assert "local-response.json" in script
    assert "audit_correlation" in script
    assert "task-surface-a.json" in script
    assert "proof-a.json" in script
    assert "tunnel.pid" in script
    assert "Get-NetTCPConnection" in script
    assert "unexpected" in script
    assert "Reset-C8LocalOnly.ps1 -ConfirmedNoRemoteOrWorkActions" in provider
    assert "does not refresh" in provider
    assert "bypass stale evidence" in provider


def test_c8_ledger_records_exact_live_success_without_overclaiming() -> None:
    ledger = _text("docs/providers/chatgpt-web-c8-test-evidence.md")
    assert "Completed live evidence" in ledger
    assert "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED" in ledger
    assert "two `completed` records: Work A and Work B" not in ledger
    assert "three `completed` records: the local probe, Work A and Work B" in ledger
    assert "unreachable_after_revocation" in ledger
    assert "regular-use readiness" in ledger
    assert "22 passed" in ledger


def test_c8_manifest_records_exact_live_revoked_boundary() -> None:
    manifest = json.loads(_text("governance/c8-change-manifest.json"))
    assert manifest["branch"] == "codex/chatgpt-work-live-c8"
    assert manifest["base_commit"] == "e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"
    assert manifest["evidence_tag"] == "evidence/chatgpt-work-live-c8-v1"
    assert manifest["issue"] == 78
    assert manifest["reviewed_outcome"] == "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED"
    assert manifest["operator_authorization_received"] is True
    assert manifest["browser_actions_performed"] is True
    assert manifest["visible_plugins_surface_confirmed"] is True
    assert manifest["visible_work_task_surface_confirmed"] is True
    assert manifest["visible_work_entitlement_confirmed"] is True
    assert manifest["visible_work_quota_confirmed"] is True
    assert manifest["visible_model_label"] == "GPT-5.6 Sol"
    assert manifest["visible_reasoning_label"] == "Minimal"
    assert manifest["exact_internal_model_id_claimed"] is False
    assert manifest["runtime_key_created"] is True
    assert manifest["runtime_key_platform_revocation_confirmed"] is True
    assert (
        manifest["interrupted_cycle_runtime_key_revocation_confirmed_at"] == "2026-07-27T23:16:00Z"
    )
    assert manifest["tunnel_started"] is True
    assert manifest["plugin_connection_created"] is True
    assert manifest["plugin_connection_removed"] is True
    assert manifest["work_tasks_created"] == 2
    assert manifest["local_probe_calls_correlated"] == 1
    assert manifest["live_work_calls_correlated"] == 2
    assert manifest["completed_audit_records"] == 3
    assert manifest["failed_audit_records"] == 2
    assert manifest["same_work_replay"] == "rejected"
    assert manifest["cross_work_replay"] == "rejected"
    assert manifest["unknown_field"] == "rejected"
    assert manifest["malformed_challenge"] == "rejected"
    assert manifest["capability_expanded"] is False
    assert manifest["post_revocation_call"] == "unreachable_after_revocation"
    assert manifest["revocation_verified"] is True
    assert manifest["native_chat_tested"] is False
    assert manifest["existing_conversations_accessed"] is False
    assert manifest["private_browser_state_accessed"] is False
    assert manifest["write_tool_count"] == 0
    assert manifest["high_risk_tool_count"] == 0
    assert manifest["effective_tool_count_before_grant"] == 0
    assert manifest["effective_tool_count_during_grant"] == 1
    assert manifest["regular_use_readiness_claimed"] is False
    assert manifest["final_cleanup_performed"] is True
    assert manifest["transient_artifacts_removed"] == 13
    assert manifest["preserved_receipt_count"] == 11
    assert manifest["process_secrets_cleared"] is True
    assert manifest["live_connectivity_recoverable"] is False
    assert manifest["raw_sensitive_evidence_versioned"] is False
    assert manifest["attestation_sha256"] == (
        "f2399d98fca34fe2c5496cc2d4e9ce3ab4d87453d1f4302b7933617878144346"
    )
    assert manifest["changed_files"] == sorted(set(manifest["changed_files"]))


def test_c8_docs_bind_reproducible_seal_without_provider_access() -> None:
    provider = _text("docs/providers/chatgpt-web-c8-work-live-validation.md")
    governance = _text("docs/documentation-governance.md")
    workflow = _text(".github/workflows/ci.yml")
    assert "evidence/chatgpt-work-live-c8-v1" in provider
    assert "governance/c8-change-seal.json" in provider
    assert "scripts/c8/Test-C8Seal.ps1" in provider
    assert "self-excluding repository seal" in governance
    assert "Verify historical C8 Work live evidence seal" in workflow
    assert "Verify current C8 pull request tree matches its seal" in workflow
