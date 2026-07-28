from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = ROOT / "scripts" / "c9"
POWERSHELL = shutil.which("powershell")


def _text(name: str) -> str:
    return (SCRIPT_ROOT / name).read_text(encoding="utf-8")


def _ps_literal(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _powershell(command: str) -> subprocess.CompletedProcess[str]:
    assert POWERSHELL is not None
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.upper().startswith(("CONTROL_PLANE_", "GIT_", "PYTHON")):
            environment.pop(name, None)
    return subprocess.run(
        (
            POWERSHELL,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ),
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        capture_output=True,
    )


def test_facade_uses_an_exact_minimal_child_environment() -> None:
    facade = _text("Start-C9Facade.ps1")
    common = _text("C9.Common.psm1")

    assert "Assert-C9FacadeLaunchEnvironment" in facade
    assert facade.index("Assert-C9FacadeLaunchEnvironment") < facade.index("Start-Process")
    assert "Invoke-C9MinimalChildEnvironment" in facade
    assert '"-I"' in facade
    assert '"utf8"' in facade
    allowlist = facade.split("$childEnvironmentAllowlist = @(", maxsplit=1)[1].split(
        ")\n$process =",
        maxsplit=1,
    )[0]
    for name in (
        "SLG_SHARED_SECRET",
        "SLG_AUDIT_KEY",
        "SLG_MCP_TOKEN",
        "SLG_C9_CONTROL_TOKEN",
        "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE",
        "SLG_C9_LOCAL_AI_ENDPOINT",
        "SLG_C9_LOCAL_AI_MODEL",
        "SLG_C9_STATE_DIRECTORY",
        "SLG_C9_ADMISSION_FILE",
    ):
        assert f'"{name}"' in allowlist
    assert "CONTROL_PLANE_" not in allowlist
    assert "PYTHONPATH" not in allowlist
    assert "PYTHONHOME" not in allowlist
    assert 'GetEnvironmentVariables("Process")' in common
    assert "SetEnvironmentVariable(" in common


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_minimal_environment_is_narrow_and_restored_without_disclosure() -> None:
    module = _ps_literal(SCRIPT_ROOT / "C9.Common.psm1")
    command = (
        f"Import-Module {module} -Force; "
        "$env:C9_TEST_KEEP = 'present'; "
        "$env:C9_TEST_DROP = 'private-value'; "
        "$inside = Invoke-C9MinimalChildEnvironment "
        "-AllowedNames @('C9_TEST_KEEP','SYSTEMROOT') -ScriptBlock { "
        "if ($env:C9_TEST_KEEP -cne 'present') { throw 'keep missing' }; "
        "if ($null -ne $env:C9_TEST_DROP) { throw 'drop inherited' }; "
        "'child=minimal' }; "
        "if ($env:C9_TEST_DROP -cne 'private-value') { throw 'restore failed' }; "
        "Remove-Item Env:C9_TEST_KEEP,Env:C9_TEST_DROP; $inside"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "child=minimal"
    assert "private-value" not in completed.stdout


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_facade_rejects_control_plane_and_python_injection_environment() -> None:
    module = _ps_literal(SCRIPT_ROOT / "C9.Common.psm1")
    command = (
        f"Import-Module {module} -Force; "
        "$env:CONTROL_PLANE_TEST = 'present'; "
        "try { Assert-C9FacadeLaunchEnvironment; exit 31 } catch {}; "
        "Remove-Item Env:CONTROL_PLANE_TEST; "
        "$env:PYTHONSTARTUP = 'present'; "
        "try { Assert-C9FacadeLaunchEnvironment; exit 32 } catch {}; "
        "Remove-Item Env:PYTHONSTARTUP; "
        "$env:GIT_CONFIG_COUNT = '1'; "
        "try { Assert-C9FacadeLaunchEnvironment; exit 33 } catch {}; "
        "Remove-Item Env:GIT_CONFIG_COUNT; "
        "Assert-C9FacadeLaunchEnvironment; 'ambient_injection=rejected'"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "ambient_injection=rejected"


def test_trusted_execution_boundary_is_read_only_and_complete() -> None:
    common = _text("C9.Common.psm1")
    prerequisites = _text("Test-C9Prerequisites.ps1")
    facade = _text("Start-C9Facade.ps1")
    tunnel = _text("Start-C9Tunnel.ps1")

    assert "function Assert-C9TrustedExecutionBoundary" in common
    for value in (
        'Join-Path $root ".venv"',
        "Get-C9PythonBaseDirectory",
        "Get-C9GitTrustRoot",
        "Assert-C9TunnelBinary",
        '"policy.c9.yaml"',
        '"scripts\\c9"',
        '"src"',
        '".git"',
        "c0-tunnel-client.json",
    ):
        assert value in common
    assert "Get-ChildItem -LiteralPath $current -Force" in common
    assert "MaximumObjects = 50000" in common
    assert "refuses reparse point" in common
    assert "refuses hardlinked leaf" in common
    assert "Get-C9FileLinkCount" in common
    assert "Get-Acl -LiteralPath" in common
    assert "Set-Acl" not in common
    assert "icacls" not in common
    assert "another ordinary principal" in common
    assert "Assert-C9TrustedExecutionBoundary" in prerequisites
    assert "Assert-C9TrustedExecutionBoundary" in facade
    assert "Assert-C9TrustedExecutionBoundary" in tunnel


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_trusted_execution_boundary_rejects_a_mock_writable_ordinary_sid() -> None:
    module = _ps_literal(SCRIPT_ROOT / "C9.Common.psm1")
    command = (
        f"$module = Import-Module {module} -Force -PassThru; "
        "$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
        "$child = [IO.Path]::GetFullPath((Join-Path "
        "(Get-C9RepositoryRoot) 'src\\systeme_local_gateway\\__init__.py')); "
        "$rule = [pscustomobject]@{"
        "AccessControlType=[Security.AccessControl.AccessControlType]::Allow;"
        "FileSystemRights=[Security.AccessControl.FileSystemRights]::Modify;"
        "IdentityReference='S-1-1-0'}; "
        "$provider = { param($path) "
        "if ([IO.Path]::GetFullPath($path).Equals($child, "
        "[StringComparison]::OrdinalIgnoreCase)) { "
        "[pscustomobject]@{Owner=$sid;Access=@($rule)} "
        "} else { [pscustomobject]@{Owner=$sid;Access=@()} } }.GetNewClosure(); "
        "$oneLink = { param($path) 1 }; "
        "try { & $module { param($target,$aclProvider,$linkProvider) "
        "$roots = @([pscustomobject]@{path=$target;recurse=$false}); "
        "[void](Invoke-C9TrustedExecutionTraversal -Roots $roots "
        "-AclProvider $aclProvider -LinkCountProvider $linkProvider) "
        "} $child $provider $oneLink; "
        "exit 41 } catch { "
        "if ($_.Exception.Message -notlike ('*' + $child + '*')) { exit 42 } "
        "}; 'ordinary_write=rejected'"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "ordinary_write=rejected"


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_native_hardlink_count_detects_a_multi_link_leaf(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"synthetic-c9")
    os.link(first, second)
    module = _ps_literal(SCRIPT_ROOT / "C9.Common.psm1")
    command = (
        f"$module = Import-Module {module} -Force -PassThru; "
        f"$count = & $module {{ param($path) Get-C9FileLinkCount -Path $path }} "
        f"{_ps_literal(first)}; "
        "if ($count -lt 2) { exit 42 }; 'hardlink=detected'"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "hardlink=detected"


def test_git_invocation_is_absolute_closed_and_configuration_neutralized() -> None:
    common = _text("C9.Common.psm1")
    scripts = "\n".join(path.read_text(encoding="utf-8") for path in SCRIPT_ROOT.glob("*.ps*"))

    assert "function Get-C9GitExecutable" in common
    assert "Get-Command git.exe -CommandType Application" in common
    assert "[System.IO.Path]::IsPathRooted" in common
    assert "function Invoke-C9Git" in common
    assert '"GIT_CONFIG_NOSYSTEM"' in common
    assert '"GIT_CONFIG_GLOBAL"' in common
    assert '"GIT_OPTIONAL_LOCKS"' in common
    assert '"GIT_TERMINAL_PROMPT"' in common
    assert '"core.fsmonitor=false"' in common
    assert '"core.hooksPath=NUL"' in common
    assert "Invoke-C9MinimalChildEnvironment" in common
    assert "function Test-C9GitWorktreeClean" in common
    assert "status --porcelain" not in scripts
    assert "& git " not in scripts
    assert scripts.count("& $git `") == 1


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_git_helper_refuses_ambient_git_configuration() -> None:
    module = _ps_literal(SCRIPT_ROOT / "C9.Common.psm1")
    command = (
        f"$module = Import-Module {module} -Force -PassThru; "
        "$env:GIT_CONFIG_COUNT = '1'; "
        "try { [void](Get-C9GitExecutable); exit 43 } catch {}; "
        "Remove-Item Env:GIT_CONFIG_COUNT; "
        "$ambientApplications = @("
        "Get-Command git.exe -CommandType Application -ErrorAction Stop); "
        "if ($ambientApplications.Count -lt 1) { exit 44 }; "
        "$ambient = [string]$ambientApplications[0].Source; "
        "$git = Get-C9GitExecutable; "
        "if (-not [IO.Path]::IsPathRooted($git)) { exit 44 }; "
        "if ([IO.Path]::GetFileName($git) -cne 'git.exe') { exit 45 }; "
        "$gitLinks = & $module { param($path) Get-C9FileLinkCount -Path $path } "
        "$git; if ($gitLinks -ne 1) { exit 46 }; "
        "$ambientLinks = & $module { param($path) Get-C9FileLinkCount -Path $path } "
        "$ambient; if ($ambientLinks -gt 1 -and "
        "[IO.Path]::GetFileName([IO.Path]::GetDirectoryName($ambient)) "
        "-ieq 'cmd' -and "
        "[IO.Path]::GetFileName([IO.Path]::GetDirectoryName($git)) "
        "-ine 'bin') { exit 47 }; "
        "'ambient_git=rejected; absolute_git=valid'"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "ambient_git=rejected; absolute_git=valid"


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_git_wrapper_ignores_global_config_closes_child_env_and_restores_parent(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "git-wrapper"
    script_root = sandbox / "scripts" / "c9"
    evil_home = sandbox / "evil-home"
    script_root.mkdir(parents=True)
    evil_home.mkdir()
    shutil.copy2(SCRIPT_ROOT / "C9.Common.psm1", script_root)
    (evil_home / ".gitconfig").write_text(
        "[alias]\n    c9ambient = status\n",
        encoding="utf-8",
    )
    module = _ps_literal(script_root / "C9.Common.psm1")
    command = (
        f"$module = Import-Module {module} -Force -PassThru; "
        "& $module { Set-Item Function:Assert-C9TrustedPathChain "
        "-Value { param($Path,$AclProvider,$LinkCountProvider) $true } }; "
        f"$env:HOME = {_ps_literal(evil_home)}; "
        "$env:C9_TEST_SECRET = 'parent-only-secret'; "
        "$beforePath = $env:PATH; $beforeHome = $env:HOME; "
        "$ambient = @(Invoke-C9Git -Arguments @("
        "'config','--global','--get','alias.c9ambient')); "
        "if ($LASTEXITCODE -ne 1 -or $ambient.Count -ne 0) { exit 48 }; "
        "$alias = '!test -z \"$C9_TEST_SECRET\"'; "
        "[void](Invoke-C9Git -Arguments @("
        "'-c',('alias.c9env=' + $alias),'c9env')); "
        "if ($LASTEXITCODE -ne 0 -or $env:PATH -cne $beforePath -or "
        "$env:HOME -cne $beforeHome -or "
        "$env:C9_TEST_SECRET -cne 'parent-only-secret') { exit 49 }; "
        "$config = Join-Path (Get-C9StateDirectory) 'git-global-config.empty'; "
        "if ((Get-Item -LiteralPath $config).Length -ne 0) { exit 50 }; "
        "Remove-Item Env:C9_TEST_SECRET; "
        "'git_env=closed_and_restored'"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "git_env=closed_and_restored"
    assert "parent-only-secret" not in completed.stdout


def test_facade_revalidates_the_full_boundary_immediately_before_launch() -> None:
    facade = _text("Start-C9Facade.ps1")
    launch_block = facade.split(
        "-ScriptBlock {",
        maxsplit=1,
    )[1].split("Start-Process", maxsplit=1)[0]

    assert "Assert-C9TrustedExecutionBoundary" in launch_block
    assert '"SLG_C9_GIT_EXECUTABLE"' in facade
    assert "$gitDirectory" in facade
    assert "$system32" in facade
    assert "$minimalChildPath" in facade
    assert "$parentPath" in facade
    assert "finally {" in facade
    assert '"PATH",\n        $parentPath' in facade


def test_git_pin_is_preserved_for_attestation_then_removed_by_final_cleanup() -> None:
    stop = _text("Stop-C9.ps1")
    clear = _text("Clear-C9Temporary.ps1")
    reset = _text("Reset-C9LocalOnly.ps1")
    prepare = _text("Prepare-C9.ps1")

    assert '"SLG_C9_GIT_EXECUTABLE"' not in stop
    assert '"SLG_C9_GIT_EXECUTABLE"' in clear
    assert '"SLG_C9_GIT_EXECUTABLE"' in reset
    assert '"SLG_C9_GIT_EXECUTABLE"' in prepare


def test_final_cleanup_has_an_explicit_two_phase_audit_key_contract() -> None:
    cleanup = _text("Clear-C9Temporary.ps1")

    assert "[switch]$PreserveAuditKeyForSeal" in cleanup
    assert '"finalized_for_seal"' in cleanup
    assert '"finalized"' in cleanup
    assert "audit_key_preserved_for_seal" in cleanup
    assert "cleanup_idempotent_after_seal" in cleanup
    assert "if (-not $PreserveAuditKeyForSeal)" in cleanup
    assert '$environmentToClear += "SLG_AUDIT_KEY"' in cleanup
    assert "Assert-C9AuditKeyEnvironment" in cleanup
    assert "$verifiedAttestation.attestation_sha256" in cleanup
    assert "$attestation.attestation_sha256" in cleanup


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_final_cleanup_preserves_then_clears_only_the_audit_key(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "cleanup"
    script_root = sandbox / "scripts" / "c9"
    state = sandbox / ".systeme-local" / "c9"
    script_root.mkdir(parents=True)
    state.mkdir(parents=True)
    shutil.copy2(SCRIPT_ROOT / "Clear-C9Temporary.ps1", script_root)
    (state / "attestation.json").write_text(
        json.dumps(
            {
                "status": (
                    "COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_"
                    "ATTACHMENTS_VERIFIED_AND_REVOKED"
                ),
                "work_rich_call_count": 1,
                "chat_manual_handoff_count": 1,
                "total_rich_mcp_call_count": 1,
                "work_rich_mcp_verified": True,
                "chat_manual_visible_handoff_verified": True,
                "same_sanitized_package_verified": True,
                "native_chat_plugin_invoked": False,
                "native_chat_provider_audit_correlation_claimed": False,
                "unapproved_fallback_used": False,
                "local_ai_loopback_receipt_committed": True,
                "local_ai_native_runtime_observation_committed": True,
                "chat_export_id": "c9_export_" + "1" * 32,
                "chat_export_descriptor_sha256": "2" * 64,
                "chat_export_sha256": "3" * 64,
                "chat_picker_claim_receipt_sha256": "4" * 64,
                "revocation_verified": True,
                "attestation_sha256": "a" * 64,
            }
        ),
        encoding="utf-8",
    )
    module = """
Set-StrictMode -Version Latest
function Assert-C9GitState {}
function Assert-C9AuditKeyEnvironment {
    if ([string]::IsNullOrWhiteSpace($env:SLG_AUDIT_KEY)) {
        throw 'audit key missing'
    }
}
function Get-C9StateDirectory {
    return [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\\..\\.systeme-local\\c9'))
}
function Read-C9Pid { param([string]$Name) return $null }
function Assert-C9StateFile {
    param([string]$Path)
    $resolved = [IO.Path]::GetFullPath($Path)
    $state = [IO.Path]::GetFullPath((Get-C9StateDirectory))
    if (-not $resolved.StartsWith($state, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'escaped state'
    }
    return $resolved
}
function Read-C9PrivateJson {
    param([string]$Path)
    $global:C9_ATTESTATION_READS += 1
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}
function Invoke-C9FakePython {
    $index = [Array]::IndexOf($args, '--attestation')
    if ($index -lt 0 -or ($index + 1) -ge $args.Count) {
        throw 'attestation argument missing'
    }
    $global:LASTEXITCODE = 0
    Get-Content -LiteralPath $args[$index + 1] -Raw
}
function Get-C9Python { return 'Invoke-C9FakePython' }
Export-ModuleMember -Function @(
    'Assert-C9GitState',
    'Assert-C9AuditKeyEnvironment',
    'Get-C9StateDirectory',
    'Read-C9Pid',
    'Assert-C9StateFile',
    'Read-C9PrivateJson',
    'Invoke-C9FakePython',
    'Get-C9Python'
)
"""
    (script_root / "C9.Common.psm1").write_text(module, encoding="utf-8")
    cleanup = _ps_literal(script_root / "Clear-C9Temporary.ps1")
    command = (
        "$global:C9_ATTESTATION_READS = 0; "
        "function Get-NetTCPConnection { @() }; "
        "$env:SLG_AUDIT_KEY = 'audit-key-for-synthetic-test-1234567890'; "
        "$env:SLG_SHARED_SECRET = 'must-clear'; "
        "$env:SLG_MCP_TOKEN = 'must-clear'; "
        "$env:SLG_C9_CONTROL_TOKEN = 'must-clear'; "
        f"$first = (& {cleanup} -PreserveAuditKeyForSeal | ConvertFrom-Json); "
        "if ($first.status -cne 'finalized_for_seal' -or "
        "-not $first.audit_key_preserved_for_seal -or "
        "[string]::IsNullOrWhiteSpace($env:SLG_AUDIT_KEY) -or "
        "$null -ne $env:SLG_SHARED_SECRET -or "
        "$null -ne $env:SLG_MCP_TOKEN -or "
        "$null -ne $env:SLG_C9_CONTROL_TOKEN) { exit 46 }; "
        f"$second = (& {cleanup} | ConvertFrom-Json); "
        "if ($second.status -cne 'finalized' -or "
        "$second.audit_key_preserved_for_seal -or "
        "$null -ne $env:SLG_AUDIT_KEY -or "
        "$global:C9_ATTESTATION_READS -ne 2) { exit 47 }; "
        "'cleanup=two_phase_and_idempotent'"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "cleanup=two_phase_and_idempotent"


def test_local_ai_prerequisite_requires_the_private_runtime_observation() -> None:
    common = _text("C9.Common.psm1")
    prerequisites = _text("Test-C9Prerequisites.ps1")
    facade = _text("Start-C9Facade.ps1")

    assert "function Assert-C9LocalAIRuntimeObservationEnvironment" in common
    assert "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE" in common
    local_ai_block = prerequisites.split(
        "if ($RequireLocalAI -or $RequireLiveCycle)",
        maxsplit=1,
    )[1].split("}", maxsplit=1)[0]
    assert "Assert-C9LocalAIRuntimeObservationEnvironment" in local_ai_block
    assert "Assert-C9LocalAIRuntimeObservationEnvironment" in facade


def test_local_probe_commits_metadata_atomically() -> None:
    probe = _text("Test-C9LocalProbe.ps1")

    assert "Write-C9MetadataReceipt" in probe
    assert "-Receipt $json" in probe
    assert "-AllowOverwrite" in probe
    assert "Set-Content" not in probe


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_private_response_writer_round_trips_and_rejects_replay(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "response-writer"
    script_root = sandbox / "scripts" / "c9"
    script_root.mkdir(parents=True)
    module_path = script_root / "C9.Common.psm1"
    shutil.copy2(SCRIPT_ROOT / "C9.Common.psm1", module_path)
    command = (
        f"Import-Module {_ps_literal(module_path)} -Force; "
        "$state = Initialize-C9StateDirectory; "
        "$path = Join-Path $state 'work-response.json'; "
        "[void](Write-C9PrivateUtf8Text -Path $path "
        "-Value 'synthetic-response' -MaximumBytes 64); "
        "$observed = Read-C9PrivateUtf8Text -Path $path -MaximumBytes 64; "
        "if ($observed -cne 'synthetic-response') { exit 51 }; "
        "try { [void](Write-C9PrivateUtf8Text -Path $path "
        "-Value 'replay' -MaximumBytes 64); exit 52 } catch {}; "
        "'private_response=atomic_and_one_use'"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "private_response=atomic_and_one_use"
    response = sandbox / ".systeme-local" / "c9" / "work-response.json"
    assert response.read_bytes() == b"synthetic-response"
    assert not tuple(response.parent.glob("*.tmp"))


def test_stop_is_fail_safe_before_private_response_cleanup() -> None:
    stop = _text("Stop-C9.ps1")

    assert "finally {" in stop
    assert stop.index("Stop-C9Process `\n                -Name $phase.name") < stop.index(
        'foreach ($name in @("work-response.json", "chat-response.json"))'
    )
    assert "cleanup_incomplete" in stop
    assert "cleanup_failures = @($cleanupFailures)" in stop
    assert 'Add-C9StopFailure -Phase "coordinator_close"' in stop
    assert 'Add-C9StopFailure -Phase "provider_response_cleanup"' in stop
    assert 'Add-C9StopFailure -Phase "ports_closed"' in stop
    assert 'Add-C9StopFailure -Phase "environment_cleanup"' in stop
    assert 'SetEnvironmentVariable($name, $null, "Process")' in stop
    assert stop.index("$result | ConvertTo-Json") < stop.rindex(
        "C9 shutdown completed its fail-safe stop phase"
    )


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_stop_reports_incomplete_after_unsafe_response_and_clears_secrets(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    script_root = sandbox / "scripts" / "c9"
    script_root.mkdir(parents=True)
    shutil.copy2(SCRIPT_ROOT / "C9.Common.psm1", script_root)
    shutil.copy2(SCRIPT_ROOT / "Stop-C9.ps1", script_root)
    state = sandbox / ".systeme-local" / "c9"
    unsafe_response = state / "work-response.json"
    unsafe_response.mkdir(parents=True)
    environment = os.environ.copy()
    environment.update(
        {
            "CONTROL_PLANE_API_KEY": "synthetic-runtime-key",
            "CONTROL_PLANE_TUNNEL_ID": "tunnel_" + "a" * 32,
            "SLG_SHARED_SECRET": "s" * 48,
            "SLG_MCP_TOKEN": "m" * 48,
            "SLG_C9_CONTROL_TOKEN": "c" * 48,
        }
    )

    completed = subprocess.run(
        (
            POWERSHELL,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_root / "Stop-C9.ps1"),
        ),
        cwd=sandbox,
        env=environment,
        check=False,
        text=True,
        capture_output=True,
    )

    assert completed.returncode != 0
    status = json.loads(completed.stdout)
    assert status["status"] == "cleanup_incomplete"
    assert "git_state" in status["cleanup_failures"]
    assert "provider_response_cleanup" in status["cleanup_failures"]
    assert status["transport_credentials_cleared"] is True
    assert status["runtime_secrets_cleared"] is True
    assert unsafe_response.is_dir()
