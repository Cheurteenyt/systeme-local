[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("work", "chat")]
    [string]$Surface,
    [Parameter(Mandatory = $true)]
    [string]$HandoffId,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedExactResponseCopiedToClipboard
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

if (-not $ConfirmedExactResponseCopiedToClipboard) {
    throw "C9 response staging requires an exact copied synthetic response."
}
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
    throw "C9 provider response targets another handoff."
}
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$approval.combined_approval.expires_at) `
    -EvidenceName "C9 combined approval")
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$approval.live_cycle_bundle.grant.expires_at) `
    -EvidenceName "C9 live grant")

$status = Invoke-C9LocalControl -Operation "status" -Method Get
$responseName = if ($Surface -ceq "work") {
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
        throw "C9 Work response requires one rendered and unconfirmed handoff."
    }
    "work-response.json"
} else {
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
        throw (
            "C9 Chat response requires the claimed manual handoff after the " +
            "confirmed Work proof."
        )
    }
    "chat-response.json"
}
$responsePath = Assert-C9StateFile -Path (Join-Path $state $responseName)
if (Test-Path -LiteralPath $responsePath) {
    throw "C9 provider response already exists; replay refused."
}

$responseText = $null
$clipboardCleared = $false
try {
    $responseText = [string](Get-Clipboard -Raw -ErrorAction Stop)
    Set-Clipboard -Value "" -ErrorAction Stop
    $clipboardCleared = $true
    if ([string]::IsNullOrWhiteSpace($responseText)) {
        throw "C9 provider response is empty."
    }
    try {
        $response = $responseText | ConvertFrom-Json
    } catch {
        throw "C9 provider response is not a JSON object."
    }
    if ($null -eq $response -or $response -is [array]) {
        throw "C9 provider response must be exactly one JSON object."
    }
    $expectedFields = if ($Surface -ceq "work") {
        @(
            "expansion_descriptor_sha256",
            "handoff_id",
            "manifest_sha256",
            "observed_document_nonce",
            "observed_image_nonce",
            "surface",
            "surface_task_id"
        )
    } else {
        @(
            "delivery_mode",
            "handoff_id",
            "observed_document_nonce",
            "observed_image_nonce",
            "surface"
        )
    }
    Assert-C9ExactObjectFields `
        -Object $response `
        -ExpectedFields $expectedFields `
        -ObjectName "C9 provider response"
    if ($response.handoff_id -cne $HandoffId) {
        throw "C9 provider response targets another handoff."
    }
    if ([string]$response.surface -cne $Surface) {
        throw "C9 provider response targets another visible surface."
    }
    if ($Surface -ceq "work") {
        if (
            ([string]$response.surface_task_id) -cnotmatch
                "^c9_work_[0-9a-f]{32}$" -or
            ([string]$response.surface_task_id) -cne
                ([string]$stage.work_task_id)
        ) {
            throw "C9 provider response targets another Work task."
        }
        if (
            ([string]$response.manifest_sha256) -cnotmatch
                "^[0-9a-f]{64}$" -or
            ([string]$response.manifest_sha256) -cne
                ([string]$stage.work_manifest_sha256)
        ) {
            throw "C9 provider response targets another Work manifest."
        }
        if (
            ([string]$response.expansion_descriptor_sha256) -cnotmatch
                "^[0-9a-f]{64}$"
        ) {
            throw "C9 Work response contains an invalid descriptor commitment."
        }
    } elseif (
        ([string]$response.delivery_mode) -cne
            "operator_performed_manual_attachment_handoff"
    ) {
        throw "C9 Chat response does not identify the manual handoff mode."
    }
    if (
        ([string]$response.observed_image_nonce) -cnotmatch
            "^C9[0-9A-F]{32}$" -or
        ([string]$response.observed_document_nonce) -cnotmatch
            "^C9[0-9A-F]{32}$"
    ) {
        throw "C9 provider response contains an invalid synthetic nonce."
    }
    [void](Write-C9PrivateUtf8Text `
        -Path $responsePath `
        -Value $responseText `
        -MaximumBytes 12288)
} finally {
    $responseText = $null
    $response = $null
}

[pscustomobject]@{
    status = "private_provider_response_staged"
    surface = $Surface
    handoff_id = $HandoffId
    response_file = $responseName
    response_contents_echoed = $false
    clipboard_cleared = $clipboardCleared
} | ConvertTo-Json
