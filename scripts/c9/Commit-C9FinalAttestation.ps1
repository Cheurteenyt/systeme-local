[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9GitState
Assert-C9AuditKeyEnvironment
$root = Get-C9RepositoryRoot
$state = Initialize-C9StateDirectory
$required = @(
    "handoff-stage.json",
    "combined-approval.json",
    "local-ai-runtime-observation.json",
    "work-proof.json",
    "work-rich-correlation.json",
    "chat-handoff-export.json",
    "chat-handoff-picker-claim.json",
    "chat-manual-proof.json",
    "coordinator-close.json",
    "negative-tests.json",
    "revocation.json"
)
foreach ($name in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $state $name) -PathType Leaf)) {
        throw "C9 final attestation input is missing: $name"
    }
}
foreach ($name in @(
    "chat-fallback-export.json",
    "chat-fallback-picker-claim.json",
    "chat-execution.json",
    "chat-proof.json",
    "chat-rich-correlation.json"
)) {
    if (Test-Path -LiteralPath (Join-Path $state $name) -PathType Leaf) {
        throw (
            "C9 final attestation refuses obsolete Chat MCP or fallback " +
            "evidence: $name"
        )
    }
}
if (
    $null -ne (Read-C9Pid -Name "facade") -or
    $null -ne (Read-C9Pid -Name "facade-launcher") -or
    $null -ne (Read-C9Pid -Name "tunnel")
) {
    throw "C9 final attestation refuses a live process."
}
if (@(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(8765, 8766) }
).Count -ne 0) {
    throw "C9 final attestation refuses a live C9 listener."
}
$receiptPath = Assert-C9StateFile -Path (
    Join-Path $state "attestation.json"
)
if (Test-Path -LiteralPath $receiptPath) {
    throw "C9 final attestation already exists; replay refused."
}
$python = Get-C9Python
$result = & $python -I -X utf8 `
    -m systeme_local_gateway.c9_attestation `
    commit-final `
    --metadata-root $state `
    --stage (Join-Path $state "handoff-stage.json") `
    --admission (Join-Path $state "combined-approval.json") `
    --local-ai-runtime-observation (
        Join-Path $state "local-ai-runtime-observation.json"
    ) `
    --work (Join-Path $state "work-proof.json") `
    --work-correlation (Join-Path $state "work-rich-correlation.json") `
    --chat-export (Join-Path $state "chat-handoff-export.json") `
    --chat-picker-claim (
        Join-Path $state "chat-handoff-picker-claim.json"
    ) `
    --chat (Join-Path $state "chat-manual-proof.json") `
    --close (Join-Path $state "coordinator-close.json") `
    --negative (Join-Path $state "negative-tests.json") `
    --revocation (Join-Path $state "revocation.json") `
    --repository-root $root
if ($LASTEXITCODE -ne 0) {
    throw "C9 final live attestation validation failed."
}
try {
    $receipt = ($result -join "`n") | ConvertFrom-Json
} catch {
    throw "C9 final attestation returned invalid metadata."
}
if (
    $receipt.status -cne (
        "COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_" +
        "ATTACHMENTS_VERIFIED_AND_REVOKED"
    ) -or
    $receipt.simulated -ne $false -or
    $receipt.work_rich_call_count -ne 1 -or
    $receipt.chat_manual_handoff_count -ne 1 -or
    $receipt.total_rich_mcp_call_count -ne 1 -or
    $receipt.work_rich_mcp_verified -ne $true -or
    $receipt.chat_manual_visible_handoff_verified -ne $true -or
    $receipt.same_sanitized_package_verified -ne $true -or
    $receipt.native_chat_plugin_invoked -ne $false -or
    $receipt.native_chat_provider_audit_correlation_claimed -ne $false -or
    $receipt.unapproved_fallback_used -ne $false -or
    $receipt.local_ai_loopback_receipt_committed -ne $true -or
    $receipt.local_ai_native_runtime_observation_committed -ne $true -or
    $receipt.chat_export_id -cnotmatch "^c9_export_[0-9a-f]{32}$" -or
    $receipt.chat_export_descriptor_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
    $receipt.chat_export_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
    $receipt.chat_picker_claim_receipt_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
    $receipt.regular_arbitrary_files_tested -ne $false -or
    $receipt.regular_use_readiness_claimed -ne $false -or
    $receipt.automatic_chat_to_work_switch_used -ne $false -or
    $receipt.revocation_verified -ne $true
) {
    throw "C9 final attestation returned an invalid completion boundary."
}
[void](Write-C9MetadataReceipt -Path $receiptPath -Receipt $receipt)
$receipt | ConvertTo-Json -Depth 16
