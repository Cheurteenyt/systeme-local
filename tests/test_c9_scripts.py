from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = ROOT / "scripts" / "c9"
POWERSHELL = shutil.which("powershell")

EXPECTED_SCRIPTS = {
    "Approve-C9CombinedHandoff.ps1",
    "C9.Common.psm1",
    "Clear-C9Temporary.ps1",
    "Commit-C9FinalAttestation.ps1",
    "Commit-C9Correlations.ps1",
    "Confirm-C9ChatManualProof.ps1",
    "Confirm-C9NegativeTests.ps1",
    "Confirm-C9Revocation.ps1",
    "Confirm-C9WorkProof.ps1",
    "Get-C9ChatHandoffPickerPaths.ps1",
    "Get-C9Status.ps1",
    "New-C9ChatHandoffExport.ps1",
    "New-C9LocalAIRuntimeObservation.ps1",
    "New-C9Seal.ps1",
    "New-C9SyntheticHandoff.ps1",
    "Prepare-C9.ps1",
    "Reset-C9LocalOnly.ps1",
    "Show-C9WebSteps.ps1",
    "Set-C9ProviderResponse.ps1",
    "Start-C9Facade.ps1",
    "Start-C9Tunnel.ps1",
    "Stop-C9.ps1",
    "Test-C9LocalProbe.ps1",
    "Test-C9Prerequisites.ps1",
    "Test-C9Seal.ps1",
}


def _text(name: str) -> str:
    return (SCRIPT_ROOT / name).read_text(encoding="utf-8")


def _powershell(command: str) -> subprocess.CompletedProcess[str]:
    assert POWERSHELL is not None
    environment = os.environ.copy()
    environment.pop("SLG_AUDIT_ANCHOR_LOG", None)
    environment.pop("SLG_AUDIT_ANCHOR_KEY", None)
    return subprocess.run(
        [
            POWERSHELL,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        capture_output=True,
    )


def _ps_literal(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def test_c9_script_set_is_exact_and_bounded() -> None:
    scripts = {path.name for path in SCRIPT_ROOT.iterdir() if path.is_file()}

    assert scripts == EXPECTED_SCRIPTS


def test_ci_has_bounded_windows_c9_security_and_script_coverage() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["c9-windows-python"]

    assert job["runs-on"] == "windows-latest"
    assert job["timeout-minutes"] == 15
    rendered_steps = "\n".join(
        str(step.get("run", "")) for step in job["steps"] if isinstance(step, dict)
    )
    assert "PSScriptAnalyzer" in rendered_steps
    assert "RequiredVersion 1.25.0" in rendered_steps
    for test_file in (
        "tests/test_c9_attachment_security.py",
        "tests/test_c9_git.py",
        "tests/test_c9_local_ai.py",
        "tests/test_c9_manual_export.py",
        "tests/test_c9_private_state.py",
        "tests/test_c9_scripts.py",
        "tests/test_c9_script_hardening.py",
    ):
        assert test_file in rendered_steps


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_every_c9_script_parses_with_the_powershell_ast() -> None:
    command = (
        "$failed = $false; "
        f"Get-ChildItem -LiteralPath {_ps_literal(SCRIPT_ROOT)} -File | "
        "ForEach-Object { "
        "$tokens = $null; $errors = $null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile("
        "$_.FullName, [ref]$tokens, [ref]$errors); "
        "if ($errors.Count -ne 0) { "
        "$failed = $true; $errors | ForEach-Object { $_.Message } "
        "} }; "
        "if ($failed) { exit 1 }; 'ast=valid'"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "ast=valid"


def test_c9_common_binds_branch_c8_ancestry_and_private_state() -> None:
    common = _text("C9.Common.psm1")

    assert 'C9Branch = "codex/chatgpt-file-image-handoff-c9"' in common
    assert 'C9AcceptedC8Commit = "bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5"' in common
    assert '"merge-base"' in common
    assert '"--is-ancestor"' in common
    assert "requires a clean worktree" in common
    assert '".systeme-local"' in common
    assert '"c9"' in common
    assert "Assert-C9StateFile" in common
    assert "ReparsePoint" in common


def test_c9_secrets_and_local_ai_are_process_local_and_exact() -> None:
    non_response_scripts = EXPECTED_SCRIPTS - {"Set-C9ProviderResponse.ps1"}
    combined = "\n".join(_text(name) for name in sorted(non_response_scripts))
    common = _text("C9.Common.psm1")
    prepare = _text("Prepare-C9.ps1")

    for name in (
        "SLG_SHARED_SECRET",
        "SLG_AUDIT_KEY",
        "SLG_MCP_TOKEN",
        "SLG_C9_CONTROL_TOKEN",
    ):
        assert name in common
    assert '"Process"' in prepare
    assert "pairwise independent" in common
    assert "Initialize-C9ProcessSecrets" in prepare
    assert "inherited_process_secrets_reused = $false" in prepare
    assert "process_secrets_rotated = $true" in prepare
    assert "$existing" not in prepare
    assert "^[A-Za-z0-9+/]{43}=$" in common
    assert "^http://127[.]0[.]0[.]1:([1-9][0-9]{0,4})/v1/chat/completions$" in common
    assert "SLG_C9_LOCAL_AI_MODEL" in common
    assert "localhost" not in common
    assert "Read-Host" not in combined
    assert "SetEnvironmentVariable(" in prepare
    assert '"User"' not in prepare
    assert '"Machine"' not in prepare


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_c9_common_accepts_independent_secrets_and_rejects_reuse() -> None:
    module = _ps_literal(SCRIPT_ROOT / "C9.Common.psm1")
    command = (
        f"Import-Module {module} -Force; "
        "$names = @('SLG_SHARED_SECRET','SLG_AUDIT_KEY',"
        "'SLG_MCP_TOKEN','SLG_C9_CONTROL_TOKEN'); "
        "$before = @{}; foreach ($name in $names) { "
        "$value = [Convert]::ToBase64String("
        "[Text.Encoding]::ASCII.GetBytes(($name[0].ToString() * 32))); "
        "[Environment]::SetEnvironmentVariable($name,$value,'Process'); "
        "$before[$name] = $value }; "
        "$rotated = @(Initialize-C9ProcessSecrets); "
        "if ($rotated.Count -ne 4) { exit 6 }; "
        "$values = @($names | ForEach-Object { "
        "[Environment]::GetEnvironmentVariable($_,'Process') }); "
        "if (@($values | Select-Object -Unique).Count -ne 4) { exit 7 }; "
        "foreach ($name in $names) { "
        "$value = [Environment]::GetEnvironmentVariable($name,'Process'); "
        "if ($value -ceq $before[$name] -or "
        "$value -cnotmatch '^[A-Za-z0-9+/]{43}=$') { exit 8 } }; "
        "Assert-C9SecretEnvironment; "
        "$env:SLG_C9_CONTROL_TOKEN = $env:SLG_MCP_TOKEN; "
        "try { Assert-C9SecretEnvironment; exit 9 } "
        "catch { 'fresh=rotated; independent=accepted; reused=rejected' }"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "fresh=rotated; independent=accepted; reused=rejected"


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_c9_local_ai_validator_rejects_non_exact_loopback_routes() -> None:
    module = _ps_literal(SCRIPT_ROOT / "C9.Common.psm1")
    invalid = (
        "http://localhost:1234/v1/chat/completions",
        "http://127.0.0.1:1234/v1/models",
        "https://127.0.0.1:1234/v1/chat/completions",
        "http://127.0.0.1:70000/v1/chat/completions",
        "http://127.0.0.2:1234/v1/chat/completions",
    )
    invalid_array = ",".join(f"'{item}'" for item in invalid)
    command = (
        f"Import-Module {module} -Force; "
        "$env:SLG_C9_LOCAL_AI_ENDPOINT = "
        "'http://127.0.0.1:1234/v1/chat/completions'; "
        "$env:SLG_C9_LOCAL_AI_MODEL = 'local-vlm'; "
        "Assert-C9LocalAIEnvironment; "
        f"foreach ($candidate in @({invalid_array})) {{ "
        "$env:SLG_C9_LOCAL_AI_ENDPOINT = $candidate; "
        "try { Assert-C9LocalAIEnvironment; exit 9 } catch {} "
        "}; 'exact_loopback=accepted; invalid_routes=rejected'"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "exact_loopback=accepted; invalid_routes=rejected"


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_c9_state_confinement_is_enforced_without_creating_state() -> None:
    module = _ps_literal(SCRIPT_ROOT / "C9.Common.psm1")
    outside = _ps_literal(ROOT / "outside-c9.json")
    command = (
        f"Import-Module {module} -Force; "
        "$state = Get-C9StateDirectory; "
        "$inside = Assert-C9StateFile -Path "
        "(Join-Path $state 'inside.json'); "
        f"try {{ Assert-C9StateFile -Path {outside}; exit 11 }} "
        "catch { "
        "if ($inside -notlike '*\\.systeme-local\\c9\\inside.json') { exit 12 }; "
        "'state=confined' "
        "}"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "state=confined"
    assert not (ROOT / "outside-c9.json").exists()


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_c9_state_confinement_rejects_an_ancestor_junction() -> None:
    module = _ps_literal(SCRIPT_ROOT / "C9.Common.psm1")
    command = (
        f"Import-Module {module} -Force; "
        "$state = Initialize-C9StateDirectory; "
        "$suffix = [Guid]::NewGuid().ToString('N'); "
        "$outside = Join-Path ([IO.Path]::GetTempPath()) ('slg-c9-' + $suffix); "
        "$junction = Join-Path $state ('junction-' + $suffix); "
        "[void][IO.Directory]::CreateDirectory($outside); "
        "$escaped = $false; "
        "try { "
        "[void](New-Item -ItemType Junction -Path $junction -Target $outside); "
        "try { [void](Assert-C9StateFile -Path "
        "(Join-Path $junction 'outside.json')); $escaped = $true } catch {}; "
        "if ($escaped) { throw 'ancestor junction was accepted' }; "
        "'ancestor_reparse=rejected' "
        "} finally { "
        "if (Test-Path -LiteralPath $junction) { [IO.Directory]::Delete($junction) }; "
        "if (Test-Path -LiteralPath $outside) { [IO.Directory]::Delete($outside) } "
        "}"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "ancestor_reparse=rejected"


def test_c9_facade_starts_before_admission_with_zero_tools_and_no_c0() -> None:
    facade = _text("Start-C9Facade.ps1")

    assert "Get-C9AdmissionDecision" not in facade
    assert 'SLG_PROVIDER_RUNTIME_MODE = "chatgpt_web_c9"' in facade
    assert 'SLG_C0_ENABLED = "false"' in facade
    assert "SLG_C0_SERVER_BUILD_COMMIT" in facade
    assert "policy.c9.yaml" in facade
    assert "policy.c0.yaml" not in facade
    assert "admission.json" in facade
    assert "requires zero admission and zero effective tools" in facade
    assert "@($probeJson.tools).Count -ne 0" in facade
    assert 'status = "started_unadmitted"' in facade
    assert "effective_tool_count = 0" in facade
    assert "Write-C9ProcessRecord" in facade
    assert '"127.0.0.1"' in facade
    assert "-WindowStyle Hidden" in facade


def test_c9_tunnel_requires_fresh_outer_admission_and_exact_dynamic_tool() -> None:
    common = _text("C9.Common.psm1")
    tunnel = _text("Start-C9Tunnel.ps1")

    assert "C9HandoffAdmission" in common
    assert "admission.live_cycle_bundle" in common
    assert "verify_c9_live_cycle_bundle" in common
    assert "stored.live_actions_allowed" in common
    assert "decision.live_actions_allowed -ne $true" in common
    assert "decision.effective_tool_count -ne 1" in common
    assert "decision.c8_live_cycle_grant_reused -ne $false" in common
    assert "Get-C9AdmissionDecision" in tunnel
    assert "systeme_local_attachment_handoff" in tunnel
    assert "systeme_local_connectivity_probe" not in tunnel
    assert "tunnel-attempt.json" in tunnel
    assert "MCP_EXTRA_HEADERS" in tunnel
    assert "Authorization: env:SLG_MCP_AUTHORIZATION" in tunnel
    assert 'LOG_HTTP_RAW_UNSAFE = "false"' in tunnel
    assert 'ALLOW_REMOTE_UI = "false"' in tunnel
    assert 'HEALTH_LISTEN_ADDR = "127.0.0.1:8766"' in tunnel
    assert "childEnvironmentAllowlist" in tunnel
    assert 'GetEnvironmentVariables("Process")' in tunnel
    assert "$removedChildEnvironment" in tunnel
    child_allowlist = tunnel.split(
        "$childEnvironmentAllowlist = @(",
        maxsplit=1,
    )[1].split(")\n$removedChildEnvironment", maxsplit=1)[0]
    assert '"SLG_MCP_AUTHORIZATION"' in child_allowlist
    for secret in (
        "SLG_AUDIT_KEY",
        "SLG_C9_CONTROL_TOKEN",
        "SLG_SHARED_SECRET",
        "SLG_MCP_TOKEN",
        "SLG_C9_LOCAL_AI_ENDPOINT",
    ):
        assert f'"{secret}"' not in child_allowlist


def test_c9_local_probe_never_invokes_a_tool() -> None:
    probe = _text("Test-C9LocalProbe.ps1")

    assert "systeme_local_gateway.mcp_smoke" in probe
    assert "--call-tool" not in probe
    assert "ExpectedToolCount = 0" in probe
    assert "systeme_local_attachment_handoff" in probe
    assert "systeme_local_connectivity_probe" in probe
    assert "SLG_C0_CHALLENGE" not in probe


def test_c9_stop_closes_coordinator_then_clears_transport_and_secrets() -> None:
    stop = _text("Stop-C9.ps1")

    assert "http://127.0.0.1:8765/_local/c9/close" in stop
    assert '-Body "{}"' in stop
    assert 'Authorization = "Bearer $controlToken"' in stop
    assert "use -Emergency only after review" in stop
    assert "C9 emergency cleanup refuses a reparse point" in stop
    assert "Stop-C9Process" in stop
    for name in (
        "CONTROL_PLANE_API_KEY",
        "CONTROL_PLANE_TUNNEL_ID",
        "SLG_SHARED_SECRET",
        "SLG_MCP_TOKEN",
        "SLG_C9_CONTROL_TOKEN",
        "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE",
        "SLG_C9_LOCAL_AI_ENDPOINT",
        "SLG_C9_LOCAL_AI_MODEL",
    ):
        assert f'"{name}"' in stop
    assert "runtime_api_key_platform_revocation_required" in stop
    assert "plugin_connection_removal_required" in stop
    assert '"work-response.json", "chat-response.json"' in stop
    assert "private_raw_responses_removed" in stop
    assert "unsafe private provider-response object" in stop


def test_c9_local_only_reset_is_narrow_and_refuses_remote_evidence() -> None:
    reset = _text("Reset-C9LocalOnly.ps1")

    assert "ConfirmedNoRemoteWorkOrChatActions" in reset
    assert "tunnel-attempt.json" in reset
    assert "refuses a recorded remote Tunnel attempt" in reset
    assert "refuses runtime capability audit records" in reset
    assert "refuses unexpected private state" in reset
    assert "manual-exports" in reset
    assert '"chat-handoff-export.json"' in reset
    assert '"chat-handoff-picker-claim.json"' in reset
    assert '"chat-manual-proof.json"' in reset
    assert '"work-rich-correlation.json"' in reset
    assert '"chat-rich-correlation.json"' not in reset
    assert "work_plugin_mcp_invoked = $false" in reset
    assert "chat_plugin_mcp_invoked = $false" in reset
    assert "native_chat_manual_handoff_used = $false" in reset
    assert "unapproved_fallback_used = $false" in reset
    assert "native_chat_provider_audit_correlation_claimed = $false" in reset
    assert "synthetic-fixtures" in reset
    assert '"local-ai-runtime-observation.json"' in reset
    assert '"SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE"' in reset
    assert "ReparsePoint" in reset
    assert "Remove-Item -LiteralPath $resolved -Recurse -Force" in reset
    assert "Remove-Item -Path" not in reset
    assert "runtime_api_key_platform_revocation_required = $false" in reset


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_c9_scripts_pass_psscriptanalyzer_when_available() -> None:
    available = _powershell(
        "if (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue) "
        "{ 'available' } else { 'missing' }"
    )
    assert available.returncode == 0
    if available.stdout.strip() != "available":
        pytest.skip("PSScriptAnalyzer is not installed")

    command = (
        f"$findings = @(Invoke-ScriptAnalyzer -Path {_ps_literal(SCRIPT_ROOT)} "
        "-Recurse -Severity Error); "
        "if ($findings.Count -ne 0) { "
        "$findings | ForEach-Object { $_.ToString() }; exit 1 "
        "}; 'psscriptanalyzer=valid'"
    )
    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "psscriptanalyzer=valid"
