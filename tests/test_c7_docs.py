from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_c7_normative_documents_bind_exact_surface_and_status() -> None:
    provider = _text("docs/providers/chatgpt-web-c7-work-prelive-admission.md")
    roadmap = _text("docs/roadmap.md")
    chatgpt = _text("docs/providers/chatgpt.md")
    for text in (provider, roadmap, chatgpt):
        assert "COMPLETE_C7_WORK_PROFILE_READY_FOR_BOUNDED_LIVE_VALIDATION" in text
        assert "agentic_work" in text
        assert "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE" in text
    assert "automatic Chat-to-Work switching" in provider
    assert "zero tools" in provider


def test_c7_security_documents_preserve_no_live_boundary() -> None:
    adr = _text("docs/adr/0014-separate-chatgpt-work-prelive-admission.md")
    threat = _text("docs/threat-model.md")
    architecture = _text("docs/architecture.md")
    ledger = _text("docs/providers/chatgpt-web-c7-test-evidence.md")
    assert "default decision denies all six protected actions" in adr
    assert "C7 Work-profile and pre-live authorization threats" in threat
    assert "default decision: six denials, zero tools" in architecture
    assert "The following are all `not-run` in C7" in ledger
    assert "Work selection or invocation" in ledger


def test_c7_profile_and_policy_paths_are_documented_and_indexed() -> None:
    provider = _text("docs/providers/chatgpt-web-c7-work-prelive-admission.md")
    index = _text("docs/index.md")
    readme = _text("README.md")
    assert "governance/c7-chatgpt-work-capability-profile.json" in provider
    assert "governance/c7-work-prelive-policy.json" in provider
    assert "chatgpt-web-c7-work-prelive-admission.md" in index
    assert "0014-separate-chatgpt-work-prelive-admission.md" in index
    assert "chatgpt-web-c7-work-prelive-admission.md" in readme


def test_c7_committed_json_has_no_unknown_live_authority() -> None:
    policy = json.loads(_text("governance/c7-work-prelive-policy.json"))
    assert policy["default_boundary"]["live_actions_allowed"] is False
    assert policy["default_boundary"]["effective_tool_count"] == 0
    assert policy["default_boundary"]["automatic_chat_to_work_switch_allowed"] is False
    assert policy["native_chat_gate_status"] == "BLOCKED_BY_NO_OFFICIAL_CHAT_TOOL_INTERFACE"
    assert policy["protected_actions"] == [
        "browser_test",
        "chatgpt_work_action",
        "plugin_creation",
        "runtime_key_creation",
        "tool_surface_exposure",
        "tunnel_start",
    ]
    assert policy["approved_tool"]["name"] == "systeme_local_connectivity_probe"
    assert policy["approved_tool"]["read_only"] is True
    assert policy["approved_tool"]["real_evidence_access"] is False
    assert policy["approved_tool"]["protocol_v2_reachable"] is False


def test_c7_scripts_are_offline_status_only() -> None:
    scripts = {
        path.name: path.read_text(encoding="utf-8")
        for path in (ROOT / "scripts" / "c7").glob("*")
        if path.is_file()
    }
    assert set(scripts) == {
        "C7.Common.psm1",
        "Get-C7Status.ps1",
        "Show-C8Gates.ps1",
        "Test-C7Prerequisites.ps1",
        "Test-C7Seal.ps1",
    }
    combined = "\n".join(scripts.values())
    assert "Start-C7" not in combined
    assert "CONTROL_PLANE_API_KEY" in combined
    assert "tunnel-client" in combined
    assert "Get-NetTCPConnection" in combined
    assert "systeme_local_gateway.c7_work_admission" in combined
    assert "Read-Host" not in combined


def test_c7_issue_and_base_are_recorded() -> None:
    roadmap = _text("docs/roadmap.md")
    provider = _text("docs/providers/chatgpt-web-c7-work-prelive-admission.md")
    assert "https://github.com/Cheurteenyt/systeme-local/issues/76" in roadmap
    assert "https://github.com/Cheurteenyt/systeme-local/issues/76" in provider
    assert "81bed9b81f266709fab0ea4178f98f0607c3da44" in roadmap
    assert "81bed9b81f266709fab0ea4178f98f0607c3da44" in provider
