[CmdletBinding()]
param(
    [string]$PurposeUtf8Base64
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9GitState
Assert-C9SecretEnvironment
Assert-C9LocalAIEnvironment
$state = Initialize-C9StateDirectory
$receiptPath = Assert-C9StateFile -Path (Join-Path $state "handoff-stage.json")
if (Test-Path -LiteralPath $receiptPath) {
    throw "A C9 synthetic handoff is already staged; replay refused."
}
$status = Invoke-C9LocalControl -Operation "status" -Method Get
if (
    $status.state -ne "empty" -or
    $null -ne $status.handoff_id -or
    $status.effective_tool_count -ne 0
) {
    throw "C9 staging requires one empty, unadmitted coordinator."
}

$purpose = (
    "C9 synthetic image-and-text handoff from one local AI into " +
    "ChatGPT Work and native Chat."
)
if (-not [string]::IsNullOrWhiteSpace($PurposeUtf8Base64)) {
    $purpose = ConvertFrom-C9Utf8Base64 `
        -Value $PurposeUtf8Base64 `
        -FieldName "PurposeUtf8Base64" `
        -MaximumBytes 1024
}
try {
    $receipt = Invoke-C9LocalControl `
        -Operation "stage" `
        -Body ([ordered]@{
            confirmed_exact_synthetic_files = $true
            purpose = $purpose
        })
} finally {
    $purpose = $null
}

[void](Assert-C9Identifier -Value ([string]$receipt.handoff_id) -Kind handoff)
[void](Assert-C9Identifier -Value ([string]$receipt.stage_sha256) -Kind sha256)
if (
    @($receipt.attachments).Count -ne 2 -or
    $receipt.attachments[0].kind -ne "image" -or
    $receipt.attachments[1].kind -ne "text" -or
    $receipt.work_manifest_sha256 -ceq $receipt.chat_manifest_sha256
) {
    throw "C9 staging did not return the exact independent Work/Chat package."
}
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$receipt.expires_at) `
    -EvidenceName "C9 staged handoff")
[void](Write-C9MetadataReceipt -Path $receiptPath -Receipt $receipt)
$receipt | ConvertTo-Json -Depth 12
