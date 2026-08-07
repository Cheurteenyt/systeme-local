[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$WorkPluginConnectionRemoved,
    [Parameter(Mandatory = $true)]
    [switch]$RuntimeApiKeyRevoked,
    [Parameter(Mandatory = $true)]
    [switch]$PostRevocationWorkPluginMcpAppCallFailed,
    [Parameter(Mandatory = $true)]
    [switch]$PostRevocationChatExportAndClaimFailed,
    [Parameter(Mandatory = $true)]
    [switch]$PostRevocationControlCallFailed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

if (-not (
    $WorkPluginConnectionRemoved -and
    $RuntimeApiKeyRevoked -and
    $PostRevocationWorkPluginMcpAppCallFailed -and
    $PostRevocationChatExportAndClaimFailed -and
    $PostRevocationControlCallFailed
)) {
    throw "C9 revocation requires every exact operator confirmation."
}
Assert-C9GitState
Assert-C9AuditKeyEnvironment
$state = Initialize-C9StateDirectory
foreach ($name in @("combined-approval.json", "coordinator-close.json")) {
    if (-not (Test-Path -LiteralPath (Join-Path $state $name) -PathType Leaf)) {
        throw "C9 revocation input is missing: $name"
    }
}
if (
    $null -ne (Read-C9Pid -Name "facade") -or
    $null -ne (Read-C9Pid -Name "facade-launcher") -or
    $null -ne (Read-C9Pid -Name "tunnel")
) {
    throw "C9 revocation refuses a recorded live process."
}
$listeners = @(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(8765, 8766) }
)
if ($listeners.Count -ne 0) {
    throw "C9 revocation refuses an active C9 listener."
}
$admissionPath = Assert-C9StateFile -Path (Join-Path $state "admission.json")
if (Test-Path -LiteralPath $admissionPath) {
    throw "C9 revocation requires the active admission file to be removed."
}
$mustBeCleared = @(
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "MCP_SERVER_URL",
    "MCP_EXTRA_HEADERS",
    "MCP_DISCOVERY_EXTRA_HEADERS",
    "SLG_MCP_AUTHORIZATION",
    "SLG_MCP_TOKEN",
    "SLG_SHARED_SECRET",
    "SLG_C9_CONTROL_TOKEN",
    "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE",
    "SLG_C9_LOCAL_AI_ENDPOINT",
    "SLG_C9_LOCAL_AI_MODEL"
)
foreach ($name in $mustBeCleared) {
    if ($null -ne [Environment]::GetEnvironmentVariable($name, "Process")) {
        throw "C9 revocation requires the process variable to be cleared: $name"
    }
}
foreach ($directoryName in @("manual-exports", "synthetic-fixtures")) {
    $directory = Assert-C9StateFile -Path (Join-Path $state $directoryName)
    if (Test-Path -LiteralPath $directory) {
        $item = Get-Item -LiteralPath $directory -Force
        if (
            -not $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw (
                "C9 revocation refuses a non-directory or reparse-point " +
                "private attachment-state path."
            )
        }
        if (@(Get-ChildItem -LiteralPath $directory -Force).Count -ne 0) {
            throw "C9 revocation requires empty private attachment state."
        }
    }
}
$approval = Read-C9PrivateJson -Path (
    Join-Path $state "combined-approval.json"
)
$cycleId = [string]$approval.live_cycle_bundle.authorization.cycle_id
$grantId = [string]$approval.live_cycle_bundle.grant.grant_id
$receiptPath = Assert-C9StateFile -Path (Join-Path $state "revocation.json")
if (Test-Path -LiteralPath $receiptPath) {
    throw "C9 revocation receipt already exists; replay refused."
}
$python = Get-C9Python
$result = & $python -I -X utf8 `
    -m systeme_local_gateway.c9_attestation `
    commit-revocation `
    --metadata-root $state `
    --cycle-id $cycleId `
    --grant-id $grantId `
    --close (Join-Path $state "coordinator-close.json") `
    --confirmed-complete-revocation `
    --confirmed-listener-8765-stopped `
    --confirmed-listener-8766-stopped `
    --confirmed-plugin-connection-removed `
    --confirmed-runtime-api-key-revoked `
    --confirmed-transport-secrets-cleared `
    --confirmed-runtime-secrets-cleared `
    --confirmed-control-secret-cleared `
    --confirmed-manual-export-absent `
    --confirmed-synthetic-fixtures-absent `
    --confirmed-post-revocation-work-app-call-failed `
    --confirmed-post-revocation-chat-export-and-claim-failed `
    --confirmed-post-revocation-control-call-failed
if ($LASTEXITCODE -ne 0) {
    throw "C9 revocation receipt validation failed."
}
try {
    $receipt = ($result -join "`n") | ConvertFrom-Json
} catch {
    throw "C9 revocation receipt returned invalid metadata."
}
if (
    $receipt.simulated -ne $false -or
    $receipt.coordinator_closed -ne $true -or
    $receipt.admission_file_removed -ne $true -or
    $receipt.runtime_api_key_revoked -ne $true -or
    $receipt.plugin_connection_removed -ne $true -or
    $receipt.post_revocation_work_app_call_failed -ne $true -or
    $receipt.post_revocation_chat_export_and_claim_failed -ne $true -or
    $receipt.post_revocation_control_call_failed -ne $true
) {
    throw "C9 revocation receipt crossed its exact completion boundary."
}
[void](Write-C9MetadataReceipt -Path $receiptPath -Receipt $receipt)
$receipt | ConvertTo-Json -Depth 12
