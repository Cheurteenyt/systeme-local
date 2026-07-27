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
        "Reset-C8PreLive.ps1",
        "Start-C8Facade.ps1",
        "Start-C8Tunnel.ps1",
        "Stop-C8.ps1",
        "Test-C8LocalProbe.ps1",
        "Test-C8Prerequisites.ps1",
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


def test_c8_ledger_does_not_claim_unexecuted_live_success() -> None:
    ledger = _text("docs/providers/chatgpt-web-c8-test-evidence.md")
    assert "live Work evidence not" in ledger
    assert "No live success is recorded" in ledger
    assert "22 passed" in ledger


def test_c8_manifest_records_exact_pre_live_boundary() -> None:
    manifest = json.loads(_text("governance/c8-change-manifest.json"))
    assert manifest["branch"] == "codex/chatgpt-work-live-c8"
    assert manifest["base_commit"] == "e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"
    assert manifest["issue"] == 78
    assert manifest["operator_authorization_received"] is True
    assert manifest["browser_actions_performed"] is True
    assert manifest["visible_plugins_surface_confirmed"] is True
    assert manifest["visible_work_task_surface_confirmed"] is False
    assert manifest["visible_work_entitlement_confirmed"] is False
    assert manifest["visible_work_quota_confirmed"] is False
    assert manifest["official_work_product_rollout_observed"] is True
    assert manifest["runtime_key_created"] is False
    assert manifest["work_tasks_created"] == 0
    assert manifest["live_work_calls_correlated"] == 0
    assert manifest["revocation_verified"] is False
    assert manifest["effective_tool_count_before_grant"] == 0
    assert manifest["changed_files"] == sorted(set(manifest["changed_files"]))
