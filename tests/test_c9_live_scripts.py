from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = ROOT / "scripts" / "c9"
POWERSHELL = shutil.which("powershell")

LIVE_SCRIPTS = {
    "New-C9LocalAIRuntimeObservation.ps1",
    "New-C9SyntheticHandoff.ps1",
    "Approve-C9CombinedHandoff.ps1",
    "Show-C9WebSteps.ps1",
    "New-C9ChatHandoffExport.ps1",
    "Get-C9ChatHandoffPickerPaths.ps1",
    "Confirm-C9WorkProof.ps1",
    "Confirm-C9ChatManualProof.ps1",
    "Set-C9ProviderResponse.ps1",
    "Get-C9Status.ps1",
}

EVIDENCE_SCRIPTS = {
    "Commit-C9Correlations.ps1",
    "Confirm-C9NegativeTests.ps1",
    "Confirm-C9Revocation.ps1",
    "Commit-C9FinalAttestation.ps1",
    "Clear-C9Temporary.ps1",
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


def test_c9_live_operator_script_set_is_complete() -> None:
    actual = {path.name for path in SCRIPT_ROOT.glob("*.ps1")}

    assert LIVE_SCRIPTS <= actual


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_all_c9_scripts_parse_with_windows_powershell_ast() -> None:
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


def test_common_control_client_is_loopback_bearer_bounded_and_allowlisted() -> None:
    common = _text("C9.Common.psm1")

    assert '"http://127.0.0.1:$script:C9Port/_local/c9/$Operation"' in common
    assert '"SLG_C9_CONTROL_TOKEN"' in common
    assert 'Authorization = "Bearer $controlToken"' in common
    assert "Assert-C9LoopbackListener" in common
    assert "$bodyBytes.Length -gt 16384" in common
    assert '-ContentType "application/json"' in common
    assert "-TimeoutSec 15" in common
    assert "Origin" not in common
    assert "localhost" not in common
    for operation in (
        "status",
        "stage",
        "approve",
        "chat/export",
        "chat/claim",
        "work/confirm",
        "chat/confirm",
    ):
        assert f'"{operation}"' in common


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is unavailable")
def test_common_utf8_base64_decoder_is_strict_and_bounded() -> None:
    module = _ps_literal(SCRIPT_ROOT / "C9.Common.psm1")
    command = (
        f"Import-Module {module} -Force; "
        "$raw = [Text.Encoding]::UTF8.GetBytes('C9-safe-value'); "
        "$encoded = [Convert]::ToBase64String($raw); "
        "$decoded = ConvertFrom-C9Utf8Base64 -Value $encoded "
        "-FieldName value -MaximumBytes 64; "
        "if ($decoded -cne 'C9-safe-value') { exit 4 }; "
        "try { ConvertFrom-C9Utf8Base64 -Value 'not base64' "
        "-FieldName value -MaximumBytes 64; exit 5 } catch {}; "
        "'utf8_base64=strict'"
    )

    completed = _powershell(command)

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip() == "utf8_base64=strict"


def test_stage_is_exactly_one_synthetic_image_and_text_handoff() -> None:
    script = _text("New-C9SyntheticHandoff.ps1")

    assert '-Operation "status" -Method Get' in script
    assert '-Operation "stage"' in script
    assert "confirmed_exact_synthetic_files = $true" in script
    assert '"handoff-stage.json"' in script
    assert "already staged; replay refused" in script
    assert '$receipt.attachments[0].kind -ne "image"' in script
    assert '$receipt.attachments[1].kind -ne "text"' in script
    assert "Assert-C9FreshExpiration" in script
    assert "Write-C9MetadataReceipt" in script


def test_combined_approval_has_the_exact_c9_boolean_scope() -> None:
    script = _text("Approve-C9CombinedHandoff.ps1")

    assert "ConfirmedOneCombinedApproval" in script
    assert "ConfirmedExactVisibleSurfaceObservation" in script
    true_fields = (
        "operator_confirmed_combined_handoff",
        "confirmed_exact_c9_scope",
        "work_surface_visible",
        "explicit_work_selected",
        "plugin_surface_visible",
        "work_entitlement_available",
        "work_quota_usable",
        "work_plugin_mcp_app_visible",
        "work_plugin_mcp_app_eligible",
        "work_plugin_mcp_app_selectable",
        "native_chat_surface_visible",
        "explicit_native_chat_selected",
        "native_chat_attachment_control_visible",
        "native_chat_file_picker_visible",
        "native_chat_manual_attachment_handoff_available",
    )
    false_fields = (
        "native_chat_manual_attachment_handoff_used",
        "prompt_sent",
        "existing_conversations_accessed",
        "history_accessed",
        "account_or_security_settings_accessed",
        "private_browser_state_accessed",
        "automatic_chat_to_work_switch_used",
    )
    for field in true_fields:
        assert f"{field} = $true" in script
    for field in false_fields:
        assert f"{field} = $false" in script
    assert '-Operation "approve"' in script
    assert "OperatorIdentityUtf8Base64" in script
    assert "systeme_local_attachment_handoff" in script
    assert "c8_live_cycle_grant_reused -ne $false" in script
    assert "already approved; replay refused" in script


def test_web_steps_are_one_work_mcp_call_then_one_native_chat_manual_handoff() -> None:
    script = _text("Show-C9WebSteps.ps1")

    assert script.count("systeme_local_attachment_handoff exactly once") == 1
    assert '{"handoff_id":"$HandoffId","surface":"work"}' in script
    assert '{"handoff_id":"$HandoffId","surface":"chat"}' not in script
    assert script.count('"surface_task_id"') == 1
    assert script.count('"manifest_sha256"') == 1
    assert "the exact expansion_descriptor_sha256 from the tool result" in script
    assert "the exact surface_manifest_sha256 from the tool result" in script
    assert "the exact C9 nonce visible in the image" in script
    assert "the exact C9 nonce in the text resource" in script
    assert "No Plugin/MCP app is available or allowed for this step" in script
    assert "visible file picker" in script
    assert "work_task_limit = 1" in script
    assert "normal_chat_conversation_limit = 1" in script
    assert 'work_delivery = "plugin_mcp_rich_content"' in script
    assert 'native_chat_delivery = "operator_performed_manual_attachment_handoff"' in script
    assert "native_chat_plugin_mcp_app_allowed = $false" in script
    assert "native_chat_manual_handoff_qualifies_as_success = $true" in script
    assert 'order = "work_then_chat"' in script
    assert "Get-C9ChatHandoffPickerPaths.ps1" in script
    assert "Invoke-C9LocalControl" not in script
    assert "Start-Process" not in script


def test_chat_picker_handoff_is_explicit_qualifying_and_never_claims_mcp() -> None:
    export = _text("New-C9ChatHandoffExport.ps1")
    claim = _text("Get-C9ChatHandoffPickerPaths.ps1")

    assert "OperatorIdentityUtf8Base64" not in export
    assert '-Operation "chat/export"' in export
    assert '"chat-handoff-export.json"' in export
    assert "already exists; replay refused" in export
    assert '$receipt.status -cne "ready_for_operator_file_picker"' in export
    assert "$receipt.qualifies_as_native_chat_success -ne $false" in export
    assert "$receipt.plugin_mcp_invocation_claimed -ne $false" in export
    assert "$receipt.automated_attachment_claimed -ne $false" in export
    assert '"chat-manual-proof.json"' in export
    assert "$status.work_confirmed -ne $true" in export
    assert "$status.native_chat_mcp_invoked -ne $false" in export
    assert "Assert-C9FreshExpiration" in export

    assert '-Operation "chat/claim"' in claim
    assert '"chat-handoff-picker-claim.json"' in claim
    assert "already claimed; replay refused" in claim
    assert "$exportReceipt.handoff_id -cne $HandoffId" in claim
    assert "$exportReceipt.export_id -cne $ExportId" in claim
    assert '"manual-exports"' in claim
    assert "PathType Leaf" in claim
    assert "one image and one text file" in claim
    assert "qualifies_as_native_chat_success = $false" in claim
    assert "plugin_mcp_invocation_claimed = $false" in claim
    assert "automated_attachment_claimed = $false" in claim
    assert "never an MCP or automated Chat invocation" in claim
    assert claim.count("Assert-C9StateFile -Path") >= 3
    assert "Get-FileHash -LiteralPath $resolved -Algorithm SHA256" in claim
    assert "content_sha256" in claim
    assert "changed after its committed export" in claim
    persisted_section = claim.split("$claimReceipt =", maxsplit=1)[1].split(
        "Write-C9MetadataReceipt", maxsplit=1
    )[0]
    assert "paths =" not in persisted_section

    confirmation = _text("Confirm-C9ChatManualProof.ps1")
    assert "chat_picker_claim_receipt_sha256 = $claimReceiptSha256" in confirmation
    assert "$receipt.chat_export_id -cne $export.export_id" in confirmation
    assert "$receipt.chat_export_descriptor_sha256 -cne $export.descriptor_sha256" in confirmation
    assert "$receipt.chat_picker_claim_receipt_sha256 -cne $claimReceiptSha256" in confirmation


@pytest.mark.parametrize(
    ("name", "operation", "receipt", "surface", "parses_exact_json"),
    (
        (
            "Confirm-C9WorkProof.ps1",
            "work/confirm",
            "work-proof.json",
            "Work",
            False,
        ),
        (
            "Confirm-C9ChatManualProof.ps1",
            "chat/confirm",
            "chat-manual-proof.json",
            "native Chat manual",
            True,
        ),
    ),
)
def test_proof_confirmation_is_private_bounded_cross_bound_and_one_use(
    name: str,
    operation: str,
    receipt: str,
    surface: str,
    parses_exact_json: bool,
) -> None:
    script = _text(name)

    assert f'-Operation "{operation}"' in script
    assert f'"{receipt}"' in script
    assert "replay refused" in script
    assert "Read-C9PrivateUtf8Text" in script
    assert "-MaximumBytes 12288" in script
    assert "ResponseTextUtf8Base64" not in script
    assert "ObservedImageNonceUtf8Base64" not in script
    assert "ObservedDocumentNonceUtf8Base64" not in script
    assert "[string]$ResponseFile" not in script
    assert ("ConvertFrom-Json" in script) is parses_exact_json
    assert "response_text = $responseText" in script
    assert "Assert-C9FreshExpiration" in script
    assert "Write-C9MetadataReceipt" in script
    assert "$responseText = $null" in script
    assert "Remove-Item -LiteralPath $responsePath -Force" in script
    assert script.index("Write-C9MetadataReceipt") < script.index(
        "Remove-Item -LiteralPath $responsePath -Force"
    )
    assert f"C9 {surface}" in script


def test_work_prompt_and_confirmation_bind_the_expansion_descriptor() -> None:
    prompt = _text("Show-C9WebSteps.ps1")
    work_confirmation = _text("Confirm-C9WorkProof.ps1")
    chat_confirmation = _text("Confirm-C9ChatManualProof.ps1")

    assert "expansion_descriptor_sha256" in prompt
    assert "ExpansionDescriptorSha256" not in work_confirmation
    assert "descriptor_sha256" in work_confirmation
    assert '"^[0-9a-f]{64}$"' in work_confirmation
    assert "surface_task_id" in work_confirmation
    assert "manifest_sha256" in work_confirmation
    assert "expansion_descriptor_sha256" not in chat_confirmation
    assert "surface_task_id" not in chat_confirmation
    assert "plugin_mcp_invocation_claimed -ne $false" in chat_confirmation
    assert "automated_attachment_claimed -ne $false" in chat_confirmation
    assert "work_attachments_visibly_consumed" in work_confirmation
    assert "native_chat_attachments_visibly_consumed" in chat_confirmation
    assert "$status.native_chat_mcp_invoked -ne $false" in work_confirmation
    assert "$status.work_confirmed -ne $true" in chat_confirmation
    assert "$status.rich_call_count -ne 1" in work_confirmation
    assert "$status.rich_call_count -ne 1" in chat_confirmation


def test_status_is_metadata_only_and_cross_checks_committed_identifiers() -> None:
    script = _text("Get-C9Status.ps1")

    assert '-Operation "status" -Method Get' in script
    assert '"status-latest.json"' in script
    assert "-AllowOverwrite" in script
    assert "$status.handoff_id -cne $stage.handoff_id" in script
    assert "$status.c9_cycle_id -cne $approval.live_cycle_bundle.grant.cycle_id" in script
    assert "$status.c9_grant_id -cne $approval.live_cycle_bundle.grant.grant_id" in script
    assert "$status.rich_call_count -ne" in script
    assert "$status.rich_confirmation_count -ne" in script
    assert "$status.native_chat_mcp_invoked" in script
    assert "$status.native_chat_handoff_exported" in script
    assert "$status.native_chat_picker_claimed" in script
    assert "$status.native_chat_handoff_confirmed" in script
    assert "Write-C9MetadataReceipt" in script


def test_live_scripts_never_drive_a_browser_or_accept_plain_shell_responses() -> None:
    direct_scripts = LIVE_SCRIPTS - {"Set-C9ProviderResponse.ps1"}
    combined = "\n".join(_text(name) for name in sorted(direct_scripts))

    assert "Read-Host" not in combined
    assert "Start-Process" not in combined
    assert "chatgpt.com/" not in combined
    assert "Invoke-WebRequest" not in combined
    assert "CONTROL_PLANE_API_KEY" not in combined
    assert "ResponseTextUtf8Base64" not in combined
    assert "ObservedImageNonceUtf8Base64" not in combined
    assert "ObservedDocumentNonceUtf8Base64" not in combined
    assert "Read-C9PrivateUtf8Text" in combined


def test_provider_response_is_interactive_private_atomic_and_bounded() -> None:
    script = _text("Set-C9ProviderResponse.ps1")
    common = _text("C9.Common.psm1")

    assert '[ValidateSet("work", "chat")]' in script
    assert "ConfirmedExactResponseCopiedToClipboard" in script
    assert "Get-Clipboard -Raw" in script
    assert 'Set-Clipboard -Value ""' in script
    assert "Read-Host" not in script
    assert "Write-C9PrivateUtf8Text" in script
    assert "-MaximumBytes 12288" in script
    assert "response_contents_echoed = $false" in script
    assert "clipboard_cleared = $clipboardCleared" in script
    assert "ResponseTextUtf8Base64" not in script
    for field in (
        "handoff_id",
        "surface",
        "surface_task_id",
        "expansion_descriptor_sha256",
        "manifest_sha256",
        "observed_image_nonce",
        "observed_document_nonce",
    ):
        assert f'"{field}"' in script
    assert '"^c9_work_[0-9a-f]{32}$"' in script
    assert "$status.rich_call_count -ne 1" in script
    assert "$status.rich_confirmation_count -ne 0" in script
    assert "$status.rich_confirmation_count -ne 1" in script
    assert "operator_performed_manual_attachment_handoff" in script
    assert "$status.native_chat_mcp_invoked -ne $false" in script
    assert "Set-Content" not in script
    assert "function Write-C9PrivateUtf8Text" in common
    assert "[System.IO.FileMode]::CreateNew" in common
    assert "[System.IO.FileShare]::None" in common
    assert "$stream.Flush($true)" in common
    assert "[System.IO.File]::Move($temporary, $resolved)" in common
    assert "[Array]::Clear($bytes, 0, $bytes.Length)" in common


def test_native_runtime_observation_is_fresh_local_and_operator_attested() -> None:
    script = _text("New-C9LocalAIRuntimeObservation.ps1")
    common = _text("C9.Common.psm1")

    assert "Get-NetTCPConnection -State Listen" in script
    assert '$listeners[0].LocalAddress -cne "127.0.0.1"' in script
    assert "Get-Process -Id $listeners[0].OwningProcess" in script
    assert "Get-C9NativeRuntimeProductMetadata" in script
    assert "$runtimeProcess.VersionInfo" not in script
    assert "[System.Diagnostics.FileVersionInfo]::GetVersionInfo" in common
    assert "Get-FileHash -LiteralPath $resolved -Algorithm SHA256" in common
    assert '"unversioned-binary-sha256:$fallbackBinarySha256"' in common
    assert "$receipt.product_name -cne $productName" in script
    assert "$receipt.product_version -cne $productVersion" in script
    assert "$receipt.executable_sha256 -cne" in script
    assert "commit-runtime-observation" in script
    assert "--executable-path" in script
    assert "--confirmed-native-runtime" in script
    assert "--confirmed-runtime-request-logging-disabled" in script
    assert "--confirmed-runtime-request-persistence-disabled" in script
    assert "--confirmed-runtime-privacy-settings" in script
    assert "operator_attested_not_programmatically_verified" in script
    assert '"local-ai-runtime-observation.json"' in script
    assert '"SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE"' in script
    assert "Write-C9MetadataReceipt" in script
    assert "Read-Host" not in script


def test_facade_tracks_the_verified_venv_launcher_and_base_runtime() -> None:
    start = _text("Start-C9Facade.ps1")
    stop = _text("Stop-C9.ps1")
    common = _text("C9.Common.psm1")

    assert "function Get-C9PythonRuntimeExecutables" in common
    assert '(Join-Path (Get-C9PythonBaseDirectory) "python.exe")' in common
    assert "Assert-C9NotReparsePoint -Path $base" in common
    assert "Get-C9PythonRuntimeExecutables" in start
    assert "$matchingRuntimePaths.Count -ne 1" in start
    assert "$metadata.ParentProcessId -ne $process.Id" in start
    assert "-AllowedExecutablePaths $pythonRuntimeExecutables" in start
    assert "Get-C9PythonRuntimeExecutables" in stop
    assert "paths = $pythonRuntimeExecutables" in stop


def test_final_evidence_scripts_are_complete_and_use_the_immutable_admission_copy() -> None:
    actual = {path.name for path in SCRIPT_ROOT.glob("*.ps1")}
    assert EVIDENCE_SCRIPTS <= actual

    correlation = _text("Commit-C9Correlations.ps1")
    final = _text("Commit-C9FinalAttestation.ps1")
    revocation = _text("Confirm-C9Revocation.ps1")
    cleanup = _text("Clear-C9Temporary.ps1")

    assert '"combined-approval.json"' in correlation
    assert '"admission.json"' not in correlation
    assert "commit-rich-correlation" in correlation
    assert "--surface work" in correlation
    assert "work-execution.json" in correlation
    assert "work-rich-correlation.json" in correlation
    assert '"chat-manual-proof.json"' in correlation
    assert '--receipt (Join-Path $state "work-proof.json")' in correlation
    assert "audit.jsonl" in correlation
    assert "render_content_recorded -ne $false" in correlation
    assert "c9_tool_audit_record_count -ne 2" in correlation
    assert "native_chat_plugin_attempt_audit_record_count -ne 0" in correlation
    assert "native_chat_provider_audit_correlation_claimed = $false" in correlation
    assert "native_chat_plugin_invoked = $false" in correlation
    assert "chat_correlation" not in correlation

    assert "commit-final" in final
    assert "--local-ai-runtime-observation" in final
    assert '--admission (Join-Path $state "combined-approval.json")' in final
    assert "COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_" in final
    assert "--chat-correlation" not in final
    assert '--chat-export (Join-Path $state "chat-handoff-export.json")' in final
    assert "--chat-picker-claim" in final
    assert '"chat-handoff-picker-claim.json"' in final
    assert '--chat (Join-Path $state "chat-manual-proof.json")' in final
    assert "work_rich_call_count -ne 1" in final
    assert "chat_manual_handoff_count -ne 1" in final
    assert "total_rich_mcp_call_count -ne 1" in final
    assert "work_rich_mcp_verified -ne $true" in final
    assert "chat_manual_visible_handoff_verified -ne $true" in final
    assert "same_sanitized_package_verified -ne $true" in final
    assert "native_chat_plugin_invoked -ne $false" in final
    assert "native_chat_provider_audit_correlation_claimed -ne $false" in final
    assert "unapproved_fallback_used -ne $false" in final
    assert "local_ai_loopback_receipt_committed -ne $true" in final
    assert "local_ai_native_runtime_observation_committed -ne $true" in final
    assert "chat_export_descriptor_sha256 -cnotmatch" in final
    assert "chat_picker_claim_receipt_sha256 -cnotmatch" in final
    assert "regular_arbitrary_files_tested -ne $false" in final
    assert "automatic_chat_to_work_switch_used -ne $false" in final
    assert "chat_export_id -cnotmatch" in cleanup
    assert "chat_export_descriptor_sha256 -cnotmatch" in cleanup
    assert "chat_picker_claim_receipt_sha256 -cnotmatch" in cleanup

    new_seal = _text("New-C9Seal.ps1")
    verify_seal = _text("Test-C9Seal.ps1")
    assert "chat_export_id_sha256 -cnotmatch" in new_seal
    assert "chat_export_sha256 -cnotmatch" in new_seal
    for field in (
        "chat_export_descriptor_sha256",
        "chat_picker_claim_receipt_sha256",
    ):
        assert f"{field} -cnotmatch" in new_seal
        assert f"{field} -cnotmatch" in verify_seal

    assert '"admission.json"' in revocation
    assert "requires the active admission file to be removed" in revocation
    assert "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE" in revocation
    assert "commit-revocation" in revocation
    assert "--confirmed-post-revocation-work-app-call-failed" in revocation
    assert "--confirmed-post-revocation-chat-export-and-claim-failed" in revocation
    assert "-not $item.PSIsContainer" in revocation
    assert "[IO.FileAttributes]::ReparsePoint" in revocation
    assert "Get-ChildItem -LiteralPath $directory -Force" in revocation

    assert "validated final attestation" in cleanup
    assert "active admission to remain revoked" in cleanup
    assert "raw_attachment_paths_absent_after_logical_cleanup" in cleanup
    assert "raw_attachment_material_recoverable" not in cleanup


def test_negative_evidence_is_executed_automatically_and_not_operator_declared() -> None:
    negative = _text("Confirm-C9NegativeTests.ps1")
    revocation = _text("Confirm-C9Revocation.ps1")

    assert "param()" in negative
    assert "run-negative" in negative
    assert "--metadata-root" in negative
    assert '"combined-approval.json"' in negative
    assert '"coordinator-close.json"' in negative
    assert "automated_bounded_c9_negative_tests" in negative
    assert "isolated_pytest_subprocess" in negative
    assert "c9_bounded_negative_contract_v1" in negative
    assert "ValidateSet" not in negative
    assert "--outcome" not in negative
    assert "PostRevocationWorkPluginMcpAppCallFailed" not in negative
    assert "PostRevocationWorkPluginMcpAppCallFailed" in revocation
    assert "PostRevocationChatExportAndClaimFailed" in revocation
