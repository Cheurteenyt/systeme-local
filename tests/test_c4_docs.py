from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
C4_DOC = ROOT / "docs/providers/chatgpt-web-c4-runtime-admission.md"
C4_LEDGER = ROOT / "docs/providers/chatgpt-web-c4-test-evidence.md"
C4_SCRIPTS = ROOT / "scripts/c4"


def test_c4_contract_binds_exact_base_issue_registry_and_chatgpt_identity() -> None:
    text = C4_DOC.read_text(encoding="utf-8")

    for marker in (
        "9140801e88ed44afca9481ac06288783a0d52da2",
        "issues/71",
        "c63ae8d266ba25f7871b60f4f36b659b97a4f17e6fd13fc32b7acd6dcf85c20d",
        "de0389f0a2329daa8afa3ad8126eb6e3e80aba1b77ed2e0f29998c37c383c65b",
        "`chatgpt`",
        "`chat`",
        "`conversational_chat`",
        "`custom_or_local_mcp_tool_invocation`",
    ):
        assert marker in text


def test_c4_contract_separates_evidence_admission_tools_and_live_validation() -> None:
    text = C4_DOC.read_text(encoding="utf-8")

    for marker in (
        "Evidence acquisition, evidence promotion, admission, MCP tool construction",
        "cannot modify C3",
        "The maximum grant is not an effective grant",
        "A denial always contains zero effective tools",
        "Exact future gate",
    ):
        assert marker in text


def test_c4_bypass_audit_covers_every_in_scope_boundary_and_limits() -> None:
    text = C4_DOC.read_text(encoding="utf-8")

    for marker in (
        "`Prepare-C1.ps1`",
        "`Start-C1Facade.ps1`",
        "`Start-C1Tunnel.ps1`",
        "`Show-C1OperatorSteps.ps1`",
        "`McpToolRegistry`",
        "provider-bound MCP construction",
        "provider-bound Python startup",
        "lower-level executor/runtime",
        "C0 scripts remain historical",
        "C4 is not an OS sandbox",
        "independently launched external binary",
    ):
        assert marker in text


def test_c4_matrix_denies_all_actions_and_tools() -> None:
    text = C4_DOC.read_text(encoding="utf-8")

    for action in (
        "Runtime-key creation",
        "Tunnel startup",
        "Plugin creation",
        "Browser test",
        "ChatGPT action",
        "Provider tool-surface exposure",
    ):
        assert f"| {action} | deny | none |" in text


def test_c4_production_registry_has_only_chatgpt_and_exact_read_only_tool() -> None:
    registry = json.loads(
        (ROOT / "governance/c4-runtime-adapters.json").read_text(encoding="utf-8")
    )

    assert registry["version"] == "1"
    assert len(registry["adapters"]) == 1
    adapter = registry["adapters"][0]
    assert adapter["identity"]["provider_id"] == "chatgpt"
    assert len(adapter["approved_tools"]) == 1
    tool = adapter["approved_tools"][0]
    assert tool == {
        "name": "systeme_local_connectivity_probe",
        "access_mode": "read_only",
        "protocol_sha256": ("de0389f0a2329daa8afa3ad8126eb6e3e80aba1b77ed2e0f29998c37c383c65b"),
        "read_only": True,
        "destructive": False,
        "high_risk": False,
    }


def test_c4_scripts_are_strict_offline_secret_free_and_path_defensive() -> None:
    scripts = sorted((*C4_SCRIPTS.glob("*.ps1"), *C4_SCRIPTS.glob("*.psm1")))

    assert len(scripts) == 4
    for script in scripts:
        text = script.read_text(encoding="utf-8")
        assert "Set-StrictMode -Version Latest" in text
        assert '$ErrorActionPreference = "Stop"' in text
        for forbidden in (
            "CONTROL_PLANE_API_KEY",
            "CONTROL_PLANE_TUNNEL_ID",
            "SLG_SHARED_SECRET",
            "SLG_AUDIT_KEY",
            "SLG_MCP_TOKEN",
            "Start-Process",
            "Invoke-WebRequest",
            "Invoke-RestMethod",
        ):
            assert forbidden not in text
    common = (C4_SCRIPTS / "C4.Common.psm1").read_text(encoding="utf-8")
    assert "governance\\c4-runtime-adapters.json" in common
    assert "cannot be a reparse point" in common
    assert "interop/provider-runtime-admission-c4" in common


def test_c1_protected_boundaries_call_c4_before_c1_and_effects() -> None:
    expected = {
        "Prepare-C1.ps1": ("runtime_key_creation", "Initialize-C1StateDirectory"),
        "Start-C1Facade.ps1": ("tool_surface_exposure", "Start-Process"),
        "Start-C1Tunnel.ps1": ("tunnel_start", "Assert-C1TunnelEnvironment"),
        "Show-C1OperatorSteps.ps1": ("plugin_creation", "Assert-C1GitState"),
    }
    for name, (action, first_effect) in expected.items():
        text = (ROOT / "scripts/c1" / name).read_text(encoding="utf-8")
        gate_position = text.index("Assert-C4ProtectedActionAllowed")

        assert "..\\c4\\C4.Common.psm1" in text
        assert f'"{action}"' in text
        assert gate_position < text.index("Assert-C1GitState")
        assert gate_position < text.index(first_effect)

    facade = (ROOT / "scripts/c1/Start-C1Facade.ps1").read_text(encoding="utf-8")
    assert "-RequestApprovedTools" in facade


def test_python_provider_runtime_rechecks_c4_before_tool_registry_exposure() -> None:
    main = (ROOT / "src/systeme_local_gateway/main.py").read_text(encoding="utf-8")
    mode = main.index('settings.provider_runtime_mode == "chatgpt_chat_c4"')
    controller = main.index("create_committed_runtime_admission_controller", mode)
    decision = main.index("controller.decide(request)", controller)
    admitted_registry = main.index("build_admitted_mcp_registry(", decision)
    generic_registry = main.index("McpToolRegistry(", admitted_registry)

    assert mode < controller < decision < admitted_registry < generic_registry
    assert "if not decision.allowed:" in main[decision:admitted_registry]


def test_c1_runtime_branch_is_c4_but_historical_branch_is_preserved() -> None:
    common = (ROOT / "scripts/c1/C1.Common.psm1").read_text(encoding="utf-8")

    assert 'C1HistoricalBranch = "interop/chatgpt-web-chat-observability-c1"' in common
    assert 'C1RuntimeBranch = "interop/provider-runtime-admission-c4"' in common
    assert 'C1ReviewedCommit = "2aee36fdfa3d20c23acdc75eb3348bc54536ef4f"' in common
    assert "merge-base --is-ancestor $script:C1ReviewedCommit HEAD" in common


def test_c4_python_module_has_no_live_transport_or_secret_dependency() -> None:
    source = (ROOT / "src/systeme_local_gateway/c4_admission.py").read_text(encoding="utf-8")

    for forbidden in (
        "import http",
        "import requests",
        "import socket",
        "import subprocess",
        "import webbrowser",
        "CONTROL_PLANE_API_KEY",
        "CONTROL_PLANE_TUNNEL_ID",
        "SLG_SHARED_SECRET",
        "Start-Process",
    ):
        assert forbidden not in source


def test_c4_ci_is_fixed_time_and_scheduled_check_derives_from_c3() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    scheduled = (ROOT / ".github/workflows/evidence-governance.yml").read_text(encoding="utf-8")

    for text in (ci, scheduled):
        assert "systeme_local_gateway.c4_admission" in text
        assert "--expect-all-denied" in text
        assert "governance/c4-runtime-adapters.json" in text
    assert "--as-of 2026-07-27T12:00:00Z" in ci
    assert "permissions:\n  contents: read" in scheduled
    assert scheduled.index("Evaluate C3 capability evidence lifecycle") < scheduled.index(
        "Verify derived C4 runtime admission remains denied"
    )
    assert "contents: write" not in scheduled
    assert "issues: write" not in scheduled


def test_c4_docs_are_linked_and_adr_records_rejected_alternatives() -> None:
    paths = (
        ROOT / "README.md",
        ROOT / "docs/index.md",
        ROOT / "docs/roadmap.md",
        ROOT / "docs/architecture.md",
        ROOT / "docs/threat-model.md",
        ROOT / "docs/providers/chatgpt.md",
        ROOT / "docs/providers/chatgpt-web-c3-evidence-lifecycle.md",
        ROOT / "docs/documentation-governance.md",
    )
    for path in paths:
        assert "C4" in path.read_text(encoding="utf-8")

    adr = (ROOT / "docs/adr/0011-provider-runtime-admission.md").read_text(encoding="utf-8")
    assert "Status: accepted" in adr
    assert "Rejected alternatives" in adr
    assert "not an OS sandbox" in adr


def test_c4_ledger_separates_audit_local_live_and_closeout_evidence() -> None:
    text = C4_LEDGER.read_text(encoding="utf-8")

    for marker in (
        "Bypass-audit evidence",
        "Focused implementation tests",
        "Current action/tool evidence",
        "Validation closeout",
        "C4-L01",
        "C4-L15",
        "C4-L22",
        "No C4 live receipt exists",
        "No failed check may be deleted",
    ):
        assert marker in text


def test_c4_change_seal_is_complete_self_excluding_and_stacked() -> None:
    seal = json.loads((ROOT / "governance/c4-change-seal.json").read_text(encoding="utf-8"))
    changed = seal["changed_files"]

    assert seal["base_commit"] == "9140801e88ed44afca9481ac06288783a0d52da2"
    assert seal["stacked_base_branch"] == "interop/provider-capability-revalidation-c3"
    assert seal["branch"] == "interop/provider-runtime-admission-c4"
    assert seal["changed_file_count"] == len(changed)
    assert changed == sorted(set(changed))
    assert "governance/c4-change-seal.json" in changed
    assert "governance/c4-runtime-adapters.json" in changed
    assert "src/systeme_local_gateway/c4_admission.py" in changed
    assert "src/systeme_local_gateway/main.py" in changed
    assert "tests/test_c4_admission.py" in changed
    assert "tests/test_c4_docs.py" in changed
    assert seal["diff"]["excluded_paths"] == ["governance/c4-change-seal.json"]

    diff = subprocess.run(
        [
            "git",
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            seal["base_commit"],
            seal["covered_head"],
            "--",
            ".",
            ":(exclude)governance/c4-change-seal.json",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    assert len(diff) == seal["diff"]["bytes"]
    assert hashlib.sha256(diff).hexdigest() == seal["diff"]["sha256"]

    post_covered = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            seal["covered_head"],
            "HEAD",
            "--",
            ".",
        ],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    ).stdout.splitlines()
    assert post_covered == ["governance/c4-change-seal.json"]
