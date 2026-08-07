[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9GitState
Assert-C9AuditKeyEnvironment
$root = Get-C9RepositoryRoot
$state = Initialize-C9StateDirectory
if (
    $null -ne (Read-C9Pid -Name "facade") -or
    $null -ne (Read-C9Pid -Name "facade-launcher") -or
    $null -ne (Read-C9Pid -Name "tunnel")
) {
    throw "Stop every C9 process before committing the Work audit correlation."
}
foreach ($name in @(
    "audit.jsonl",
    "combined-approval.json",
    "work-execution.json",
    "work-proof.json",
    "chat-manual-proof.json",
    "coordinator-close.json"
)) {
    $path = Assert-C9StateFile -Path (Join-Path $state $name)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "C9 correlation input is missing: $name"
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
            "C9 Work-only correlation refuses obsolete Chat MCP or " +
            "fallback evidence: $name"
        )
    }
}
$chat = Read-C9PrivateJson -Path (
    Join-Path $state "chat-manual-proof.json"
)
if (
    $chat.status -cne "native_chat_attachments_visibly_consumed" -or
    $chat.delivery_mode -cne
        "operator_performed_manual_attachment_handoff" -or
    $chat.qualifies_as_native_chat_success -ne $true -or
    $chat.plugin_mcp_invocation_claimed -ne $false -or
    $chat.automated_attachment_claimed -ne $false
) {
    throw "C9 correlation refuses an invalid native Chat manual proof."
}
$correlationPath = Assert-C9StateFile -Path (
    Join-Path $state "work-rich-correlation.json"
)
if (Test-Path -LiteralPath $correlationPath) {
    throw "C9 Work rich correlation already exists; replay refused."
}
$python = Get-C9Python
$result = & $python -I -X utf8 `
    -m systeme_local_gateway.c9_attestation `
    commit-rich-correlation `
    --surface work `
    --metadata-root $state `
    --audit-log (Join-Path $state "audit.jsonl") `
    --admission (Join-Path $state "combined-approval.json") `
    --execution (Join-Path $state "work-execution.json") `
    --receipt (Join-Path $state "work-proof.json")
if ($LASTEXITCODE -ne 0) {
    throw "C9 Work rich audit correlation validation failed."
}
try {
    $receipt = ($result -join "`n") | ConvertFrom-Json
} catch {
    throw "C9 Work rich audit correlation returned invalid metadata."
}
if (
    $receipt.source -cne "verified_local_c9_hmac_audit_log" -or
    $receipt.simulated -ne $false -or
    $receipt.surface -cne "work" -or
    $receipt.capability -cne "systeme_local_attachment_handoff" -or
    $receipt.task_status -cne "completed" -or
    $receipt.render_status -cne "render_completed" -or
    $receipt.render_content_recorded -ne $false -or
    $receipt.c9_tool_audit_record_count -ne 2 -or
    $receipt.native_chat_plugin_attempt_audit_record_count -ne 0 -or
    $receipt.audit_records_verified -lt 2
) {
    throw "C9 Work rich correlation crossed its exact evidence boundary."
}
[void](Write-C9MetadataReceipt `
    -Path $correlationPath `
    -Receipt $receipt)
[pscustomobject]@{
    status = "work_rich_correlation_and_chat_manual_proof_bound"
    work_correlation = $receipt
    native_chat_manual_visible_handoff_verified = $true
    native_chat_plugin_invoked = $false
    native_chat_provider_audit_correlation_claimed = $false
    unapproved_fallback_used = $false
} | ConvertTo-Json -Depth 16
