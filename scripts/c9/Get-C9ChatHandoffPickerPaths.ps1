[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HandoffId,
    [Parameter(Mandatory = $true)]
    [string]$ExportId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9GitState
Assert-C9SecretEnvironment
[void](Assert-C9Identifier -Value $HandoffId -Kind handoff)
[void](Assert-C9Identifier -Value $ExportId -Kind export)
$state = Initialize-C9StateDirectory
$stage = Read-C9PrivateJson -Path (Join-Path $state "handoff-stage.json")
$exportReceipt = Read-C9PrivateJson -Path (
    Join-Path $state "chat-handoff-export.json"
)
if (
    $exportReceipt.status -cne "ready_for_operator_file_picker" -or
    $exportReceipt.delivery_mode -cne
        "operator_performed_manual_attachment_handoff" -or
    $exportReceipt.qualifies_as_native_chat_success -ne $false -or
    $exportReceipt.plugin_mcp_invocation_claimed -ne $false -or
    $stage.handoff_id -cne $HandoffId -or
    $exportReceipt.handoff_id -cne $HandoffId -or
    $exportReceipt.export_id -cne $ExportId
) {
    throw "C9 native Chat picker claim targets another handoff or export."
}
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$exportReceipt.expires_at) `
    -EvidenceName "C9 native Chat export")
$claimPath = Assert-C9StateFile -Path (
    Join-Path $state "chat-handoff-picker-claim.json"
)
if (Test-Path -LiteralPath $claimPath) {
    throw "C9 native Chat picker paths were already claimed; replay refused."
}
$status = Invoke-C9LocalControl -Operation "status" -Method Get
if (
    $status.handoff_id -cne $HandoffId -or
    $status.work_confirmed -ne $true -or
    $status.native_chat_mcp_invoked -ne $false -or
    $status.native_chat_handoff_exported -ne $true -or
    $status.native_chat_picker_claimed -ne $false -or
    $status.native_chat_handoff_confirmed -ne $false
) {
    throw "C9 picker paths require the exact unclaimed native Chat export."
}
$response = Invoke-C9LocalControl `
    -Operation "chat/claim" `
    -Body ([ordered]@{
        handoff_id = $HandoffId
        export_id = $ExportId
    })
if (
    $response.status -cne "native_chat_manual_attachment_paths_claimed" -or
    $response.qualifies_as_native_chat_success -ne $false -or
    $response.plugin_mcp_invocation_claimed -ne $false -or
    $response.automated_attachment_claimed -ne $false -or
    $response.handoff_id -cne $HandoffId -or
    $response.c9_cycle_id -cne $exportReceipt.c9_cycle_id -or
    $response.c9_grant_id -cne $exportReceipt.c9_grant_id -or
    $response.export_id -cne $ExportId -or
    $response.export_descriptor_sha256 -cne
        $exportReceipt.descriptor_sha256 -or
    $response.chat_manifest_sha256 -cne $stage.chat_manifest_sha256 -or
    $response.attachment_count -ne 2
) {
    throw "C9 picker claim crossed its native Chat manual-handoff boundary."
}
[void](Assert-C9Identifier `
    -Value ([string]$response.receipt_sha256) `
    -Kind sha256)
$paths = @($response.paths)
if ($paths.Count -ne 2 -or @($paths | Select-Object -Unique).Count -ne 2) {
    throw "C9 Chat picker claim did not return exactly two unique paths."
}
$manualRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $state "manual-exports")
) + [System.IO.Path]::DirectorySeparatorChar
$validatedPaths = @()
foreach ($candidate in $paths) {
    if (
        [string]::IsNullOrWhiteSpace([string]$candidate) -or
        -not [System.IO.Path]::IsPathRooted([string]$candidate)
    ) {
        throw "C9 Chat picker returned a non-absolute path."
    }
    $resolved = Assert-C9StateFile -Path ([string]$candidate)
    if (
        -not $resolved.StartsWith(
            $manualRoot,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not (Test-Path -LiteralPath $resolved -PathType Leaf)
    ) {
        throw "C9 Chat picker path escaped its private manual-export root."
    }
    $validatedPaths += $resolved
}
$extensions = @(
    $validatedPaths |
        ForEach-Object { [System.IO.Path]::GetExtension($_).ToLowerInvariant() }
)
if (
    @($extensions | Where-Object { $_ -in @(".png", ".jpg", ".jpeg") }).Count -ne 1 -or
    @($extensions | Where-Object { $_ -eq ".txt" }).Count -ne 1
) {
    throw "C9 Chat picker paths are not exactly one image and one text file."
}
$claimReceipt = [pscustomobject]@{
    version = [string]$response.version
    status = [string]$response.status
    qualifies_as_native_chat_success = [bool](
        $response.qualifies_as_native_chat_success
    )
    plugin_mcp_invocation_claimed = [bool](
        $response.plugin_mcp_invocation_claimed
    )
    automated_attachment_claimed = [bool](
        $response.automated_attachment_claimed
    )
    handoff_id = [string]$response.handoff_id
    c9_cycle_id = [string]$response.c9_cycle_id
    c9_grant_id = [string]$response.c9_grant_id
    export_id = [string]$response.export_id
    export_descriptor_sha256 = [string](
        $response.export_descriptor_sha256
    )
    chat_manifest_sha256 = [string]$response.chat_manifest_sha256
    attachment_count = [int]$response.attachment_count
    claimed_at = [string]$response.claimed_at
    receipt_sha256 = [string]$response.receipt_sha256
}

$imageDescriptor = @(
    $stage.attachments | Where-Object { $_.kind -eq "image" }
)[0]
$documentDescriptor = @(
    $stage.attachments | Where-Object { $_.kind -eq "text" }
)[0]
$revalidatedPaths = @()
foreach ($candidate in $validatedPaths) {
    $resolved = Assert-C9StateFile -Path $candidate
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "C9 Chat picker path disappeared before operator handoff."
    }
    $extension = [System.IO.Path]::GetExtension($resolved).ToLowerInvariant()
    $expectedSha256 = if ($extension -eq ".txt") {
        [string]$documentDescriptor.content_sha256
    } else {
        [string]$imageDescriptor.content_sha256
    }
    $observedSha256 = (
        Get-FileHash -LiteralPath $resolved -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($observedSha256 -cne $expectedSha256) {
        throw "C9 Chat picker file changed after its committed export."
    }
    $revalidatedPaths += $resolved
}
$validatedPaths = $revalidatedPaths
[void](Write-C9MetadataReceipt -Path $claimPath -Receipt $claimReceipt)

[pscustomobject]@{
    status = "native_chat_manual_attachment_paths_ready"
    qualifies_as_native_chat_success = $false
    plugin_mcp_invocation_claimed = $false
    automated_attachment_claimed = $false
    instruction = (
        "Select exactly these two private temporary files in the one new " +
        "synthetic native Chat conversation. This proves only the visible " +
        "manual handoff, never an MCP or automated Chat invocation."
    )
    handoff_id = $HandoffId
    export_id = $ExportId
    claim_receipt_sha256 = [string]$response.receipt_sha256
    paths = $validatedPaths
} | ConvertTo-Json -Depth 5
