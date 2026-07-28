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
$exportPath = Assert-C9StateFile -Path (
    Join-Path $state "chat-handoff-export.json"
)
$claimPath = Assert-C9StateFile -Path (
    Join-Path $state "chat-handoff-picker-claim.json"
)
$export = Read-C9PrivateJson -Path $exportPath
$claim = Read-C9PrivateJson -Path $claimPath
$claimReceiptSha256 = [string]$claim.receipt_sha256
[void](Assert-C9Identifier -Value $claimReceiptSha256 -Kind sha256)
if (
    $stage.handoff_id -cne $HandoffId -or
    $approval.handoff_id -cne $HandoffId -or
    $export.handoff_id -cne $HandoffId -or
    $claim.handoff_id -cne $HandoffId -or
    $claim.export_id -cne $export.export_id -or
    $claim.export_descriptor_sha256 -cne $export.descriptor_sha256 -or
    $claim.attachment_count -ne 2 -or
    $export.status -cne "ready_for_operator_file_picker" -or
    $claim.status -cne "native_chat_manual_attachment_paths_claimed" -or
    $export.delivery_mode -cne
        "operator_performed_manual_attachment_handoff" -or
    $export.qualifies_as_native_chat_success -ne $false -or
    $claim.qualifies_as_native_chat_success -ne $false -or
    $export.plugin_mcp_invocation_claimed -ne $false -or
    $claim.plugin_mcp_invocation_claimed -ne $false -or
    $export.automated_attachment_claimed -ne $false -or
    $claim.automated_attachment_claimed -ne $false -or
    $export.chat_manifest_sha256 -cne $stage.chat_manifest_sha256
) {
    throw "C9 native Chat manual confirmation has invalid export evidence."
}
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$export.expires_at) `
    -EvidenceName "C9 native Chat handoff export")
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$approval.combined_approval.expires_at) `
    -EvidenceName "C9 combined approval")
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$approval.live_cycle_bundle.grant.expires_at) `
    -EvidenceName "C9 live grant")
$receiptPath = Assert-C9StateFile -Path (
    Join-Path $state "chat-manual-proof.json"
)
if (Test-Path -LiteralPath $receiptPath) {
    throw "C9 native Chat manual proof was already confirmed; replay refused."
}
$status = Invoke-C9LocalControl -Operation "status" -Method Get
if (
    $status.handoff_id -cne $HandoffId -or
    $status.work_confirmed -ne $true -or
    $status.native_chat_mcp_invoked -ne $false -or
    $status.native_chat_handoff_exported -ne $true -or
    $status.native_chat_picker_claimed -ne $true -or
    $status.native_chat_handoff_confirmed -ne $false -or
    $status.rich_call_count -ne 1 -or
    $status.rich_confirmation_count -ne 1
) {
    throw "C9 Chat proof requires one claimed and unconfirmed manual handoff."
}

$responsePath = Assert-C9StateFile -Path (
    Join-Path $state "chat-response.json"
)
$responseText = Read-C9PrivateUtf8Text `
    -Path $responsePath `
    -MaximumBytes 12288
try {
    try {
        $responseObject = $responseText | ConvertFrom-Json
    } catch {
        throw "C9 native Chat response is not the exact bounded JSON object."
    }
    $expectedFields = @(
        "delivery_mode",
        "handoff_id",
        "observed_document_nonce",
        "observed_image_nonce",
        "surface"
    )
    Assert-C9ExactObjectFields `
        -Object $responseObject `
        -ExpectedFields $expectedFields `
        -ObjectName "C9 native Chat response"
    if (
        [string]$responseObject.handoff_id -cne $HandoffId -or
        [string]$responseObject.surface -cne "chat" -or
        [string]$responseObject.delivery_mode -cne
            "operator_performed_manual_attachment_handoff"
    ) {
        throw "C9 native Chat response targets another handoff or delivery mode."
    }
    $receipt = Invoke-C9LocalControl `
        -Operation "chat/confirm" `
        -Body ([ordered]@{
            handoff_id = $HandoffId
            chat_picker_claim_receipt_sha256 = $claimReceiptSha256
            observed_image_nonce = [string]$responseObject.observed_image_nonce
            observed_document_nonce = (
                [string]$responseObject.observed_document_nonce
            )
            response_text = $responseText
        })
} finally {
    $responseText = $null
    $responseObject = $null
}
if (
    $receipt.status -cne "native_chat_attachments_visibly_consumed" -or
    $receipt.source -cne
        "operator_visible_native_chat_and_local_nonce_verification" -or
    $receipt.delivery_mode -cne
        "operator_performed_manual_attachment_handoff" -or
    $receipt.qualifies_as_native_chat_success -ne $true -or
    $receipt.plugin_mcp_invocation_claimed -ne $false -or
    $receipt.automated_attachment_claimed -ne $false -or
    $receipt.operator_file_picker_used -ne $true -or
    $receipt.new_synthetic_native_chat_conversation -ne $true -or
    $receipt.visible_response_observed -ne $true -or
    $receipt.conversation_identifier_collected -ne $false -or
    $receipt.chat_manifest_sha256 -cne $stage.chat_manifest_sha256 -or
    $receipt.chat_export_id -cne $export.export_id -or
    $receipt.chat_export_descriptor_sha256 -cne $export.descriptor_sha256 -or
    $receipt.chat_picker_claim_receipt_sha256 -cne $claimReceiptSha256 -or
    $receipt.c9_cycle_id -cne $approval.live_cycle_bundle.grant.cycle_id -or
    $receipt.c9_grant_id -cne $approval.live_cycle_bundle.grant.grant_id -or
    @($receipt.verified_nonce_sha256s).Count -ne 2
) {
    throw "C9 native Chat manual confirmation returned an invalid receipt."
}
[void](Write-C9MetadataReceipt -Path $receiptPath -Receipt $receipt)
Remove-Item -LiteralPath $responsePath -Force
$receipt | ConvertTo-Json -Depth 12
