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
    throw "C9 Work confirmation targets another handoff."
}
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$approval.combined_approval.expires_at) `
    -EvidenceName "C9 combined approval")
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$approval.live_cycle_bundle.grant.expires_at) `
    -EvidenceName "C9 live grant")
$receiptPath = Assert-C9StateFile -Path (Join-Path $state "work-proof.json")
if (Test-Path -LiteralPath $receiptPath) {
    throw "C9 Work proof was already confirmed; replay refused."
}
$status = Invoke-C9LocalControl -Operation "status" -Method Get
if (
    $status.handoff_id -cne $HandoffId -or
    $status.work_executed -ne $true -or
    $status.work_rendered -ne $true -or
    $status.work_confirmed -ne $false -or
    $status.native_chat_mcp_invoked -ne $false -or
    $status.native_chat_handoff_exported -ne $false -or
    $status.native_chat_picker_claimed -ne $false -or
    $status.native_chat_handoff_confirmed -ne $false -or
    $status.rich_call_count -ne 1 -or
    $status.rich_confirmation_count -ne 0
) {
    throw "C9 Work proof requires one rendered and unconfirmed handoff."
}

$responsePath = Assert-C9StateFile -Path (
    Join-Path $state "work-response.json"
)
$responseText = Read-C9PrivateUtf8Text `
    -Path $responsePath `
    -MaximumBytes 12288
try {
    $receipt = Invoke-C9LocalControl `
        -Operation "work/confirm" `
        -Body ([ordered]@{
            handoff_id = $HandoffId
            response_text = $responseText
        })
} finally {
    $responseText = $null
}
if (
    $receipt.status -cne "work_attachments_visibly_consumed" -or
    $receipt.surface -cne "work" -or
    $receipt.surface_task_id -cne $stage.work_task_id -or
    $receipt.manifest_sha256 -cne $stage.work_manifest_sha256 -or
    $receipt.c9_cycle_id -cne $approval.live_cycle_bundle.grant.cycle_id -or
    $receipt.c9_grant_id -cne $approval.live_cycle_bundle.grant.grant_id -or
    ([string]$receipt.descriptor_sha256) -cnotmatch "^[0-9a-f]{64}$" -or
    @($receipt.verified_nonce_sha256s).Count -ne 2
) {
    throw "C9 Work confirmation returned an invalid or cross-handoff receipt."
}
[void](Write-C9MetadataReceipt -Path $receiptPath -Receipt $receipt)
Remove-Item -LiteralPath $responsePath -Force
$receipt | ConvertTo-Json -Depth 12
