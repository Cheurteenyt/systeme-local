[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HandoffId,
    [Parameter(Mandatory = $true)]
    [string]$OperatorIdentityUtf8Base64,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedOneCombinedApproval,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedExactVisibleSurfaceObservation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

if (-not (
    $ConfirmedOneCombinedApproval -and
    $ConfirmedExactVisibleSurfaceObservation
)) {
    throw (
        "C9 approval requires one explicit combined approval and one exact " +
        "visible-surface confirmation."
    )
}
Assert-C9GitState
Assert-C9SecretEnvironment
Assert-C9LocalAIEnvironment
[void](Assert-C9Identifier -Value $HandoffId -Kind handoff)
$state = Initialize-C9StateDirectory
$stage = Read-C9PrivateJson -Path (Join-Path $state "handoff-stage.json")
if ($stage.handoff_id -cne $HandoffId) {
    throw "C9 approval targets another staged handoff."
}
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$stage.expires_at) `
    -EvidenceName "C9 staged handoff")
$receiptPath = Assert-C9StateFile -Path (
    Join-Path $state "combined-approval.json"
)
if (Test-Path -LiteralPath $receiptPath) {
    throw "The C9 combined handoff was already approved; replay refused."
}
$status = Invoke-C9LocalControl -Operation "status" -Method Get
if (
    $status.state -ne "staged" -or
    $status.handoff_id -cne $HandoffId -or
    $status.effective_tool_count -ne 0
) {
    throw "C9 combined approval requires the exact staged, unadmitted handoff."
}
$operatorIdentity = ConvertFrom-C9Utf8Base64 `
    -Value $OperatorIdentityUtf8Base64 `
    -FieldName "OperatorIdentityUtf8Base64" `
    -MaximumBytes 256
try {
    $receipt = Invoke-C9LocalControl `
        -Operation "approve" `
        -Body ([ordered]@{
            handoff_id = $HandoffId
            operator_confirmed_combined_handoff = $true
            operator_identity = $operatorIdentity
            confirmed_exact_c9_scope = $true
            work_surface_visible = $true
            explicit_work_selected = $true
            plugin_surface_visible = $true
            work_entitlement_available = $true
            work_quota_usable = $true
            work_plugin_mcp_app_visible = $true
            work_plugin_mcp_app_eligible = $true
            work_plugin_mcp_app_selectable = $true
            native_chat_surface_visible = $true
            explicit_native_chat_selected = $true
            native_chat_attachment_control_visible = $true
            native_chat_file_picker_visible = $true
            native_chat_manual_attachment_handoff_available = $true
            native_chat_manual_attachment_handoff_used = $false
            prompt_sent = $false
            existing_conversations_accessed = $false
            history_accessed = $false
            account_or_security_settings_accessed = $false
            private_browser_state_accessed = $false
            automatic_chat_to_work_switch_used = $false
        })
} finally {
    $operatorIdentity = $null
}
if (
    $receipt.handoff_id -cne $HandoffId -or
    $receipt.combined_approval.handoff_id -cne $HandoffId -or
    $receipt.admission_decision.live_actions_allowed -ne $true -or
    $receipt.admission_decision.effective_tool_count -ne 1 -or
    @($receipt.admission_decision.effective_tools).Count -ne 1 -or
    $receipt.admission_decision.effective_tools[0] -cne
        "systeme_local_attachment_handoff" -or
    $receipt.admission_decision.c8_live_cycle_grant_reused -ne $false
) {
    throw "C9 combined approval did not preserve the exact one-tool scope."
}
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$receipt.combined_approval.expires_at) `
    -EvidenceName "C9 combined approval")
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$receipt.live_cycle_bundle.grant.expires_at) `
    -EvidenceName "C9 live grant")
[void](Write-C9MetadataReceipt -Path $receiptPath -Receipt $receipt)
$receipt | ConvertTo-Json -Depth 24
