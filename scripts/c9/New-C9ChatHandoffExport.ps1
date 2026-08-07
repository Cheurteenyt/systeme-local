[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HandoffId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9GitState
Assert-C9SecretEnvironment
[void](Assert-C9Identifier -Value $HandoffId -Kind handoff)
$state = Initialize-C9StateDirectory
$stage = Read-C9PrivateJson -Path (Join-Path $state "handoff-stage.json")
$approval = Read-C9PrivateJson -Path (Join-Path $state "combined-approval.json")
if (
    $stage.handoff_id -cne $HandoffId -or
    $approval.handoff_id -cne $HandoffId
) {
    throw "C9 native Chat handoff targets another staged handoff."
}
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$approval.combined_approval.expires_at) `
    -EvidenceName "C9 combined approval")
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$approval.live_cycle_bundle.grant.expires_at) `
    -EvidenceName "C9 live grant")
$receiptPath = Assert-C9StateFile -Path (
    Join-Path $state "chat-handoff-export.json"
)
if (Test-Path -LiteralPath $receiptPath) {
    throw "The C9 native Chat handoff export already exists; replay refused."
}
if (
    -not (Test-Path -LiteralPath (Join-Path $state "work-proof.json") -PathType Leaf)
) {
    throw "C9 native Chat handoff requires the confirmed Work proof first."
}
if (
    Test-Path -LiteralPath (Join-Path $state "chat-manual-proof.json") -PathType Leaf
) {
    throw "C9 native Chat manual proof already exists; replay refused."
}
$status = Invoke-C9LocalControl -Operation "status" -Method Get
if (
    $status.state -ne "admitted" -or
    $status.handoff_id -cne $HandoffId -or
    $status.work_confirmed -ne $true -or
    $status.native_chat_mcp_invoked -ne $false -or
    $status.native_chat_handoff_exported -ne $false -or
    $status.native_chat_picker_claimed -ne $false -or
    $status.native_chat_handoff_confirmed -ne $false -or
    $status.rich_call_count -ne 1 -or
    $status.rich_confirmation_count -ne 1
) {
    throw "C9 native Chat handoff requires the exact Work-confirmed cycle."
}
$receipt = Invoke-C9LocalControl `
    -Operation "chat/export" `
    -Body ([ordered]@{
        handoff_id = $HandoffId
    })
if (
    $receipt.status -cne "ready_for_operator_file_picker" -or
    $receipt.delivery_mode -cne
        "operator_performed_manual_attachment_handoff" -or
    $receipt.qualifies_as_native_chat_success -ne $false -or
    $receipt.plugin_mcp_invocation_claimed -ne $false -or
    $receipt.automated_attachment_claimed -ne $false -or
    $receipt.handoff_id -cne $HandoffId -or
    $receipt.attachment_count -ne 2 -or
    $receipt.chat_manifest_sha256 -cne $stage.chat_manifest_sha256
) {
    throw "C9 native Chat handoff returned an invalid evidence boundary."
}
[void](Assert-C9Identifier -Value ([string]$receipt.export_id) -Kind export)
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$receipt.expires_at) `
    -EvidenceName "C9 native Chat handoff export")
[void](Write-C9MetadataReceipt -Path $receiptPath -Receipt $receipt)
$receipt | ConvertTo-Json -Depth 12
