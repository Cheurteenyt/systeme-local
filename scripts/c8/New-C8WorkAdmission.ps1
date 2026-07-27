[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$WorkVisible,
    [Parameter(Mandatory = $true)]
    [switch]$EntitlementAvailable,
    [Parameter(Mandatory = $true)]
    [switch]$QuotaUsable,
    [Parameter(Mandatory = $true)]
    [switch]$PluginSurfaceVisible,
    [string]$VisibleModelLabelUtf8Base64,
    [string]$VisibleReasoningLabelUtf8Base64
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

if (
    -not $WorkVisible -or
    -not $EntitlementAvailable -or
    -not $QuotaUsable -or
    -not $PluginSurfaceVisible
) {
    throw "C8 refuses ambiguous Work entitlement, quota, or Plugin surface evidence."
}
Assert-C8GitState
Assert-C8SecretEnvironment
$root = Get-C8RepositoryRoot
$state = Initialize-C8StateDirectory
$authorizationPath = Join-Path $state "authorization.json"
if (-not (Test-Path -LiteralPath $authorizationPath -PathType Leaf)) {
    throw "C8 operator authorization receipt is missing."
}
$liveCyclePath = Join-Path $state "live-cycle.json"
if (Test-Path -LiteralPath $liveCyclePath -PathType Leaf) {
    throw "An existing C8 live-cycle grant must be resolved first."
}
$authorization = Get-Content -LiteralPath $authorizationPath -Raw | ConvertFrom-Json
$cycleId = [string]$authorization.cycle_id
if ($cycleId -notmatch "^c8_cycle_[0-9a-f]{32}$") {
    throw "C8 authorization receipt has an invalid cycle ID."
}

$python = Join-Path $root ".venv\Scripts\python.exe"
$surfaceArguments = @(
    "-m", "systeme_local_gateway.c8_live_cycle", "observe-surface",
    "--cycle-id", $cycleId
)
if (-not [string]::IsNullOrWhiteSpace($VisibleModelLabelUtf8Base64)) {
    $surfaceArguments += @(
        "--visible-model-label",
        (ConvertFrom-C8Utf8Base64 `
            -Value $VisibleModelLabelUtf8Base64 `
            -FieldName "Visible model label")
    )
}
if (-not [string]::IsNullOrWhiteSpace($VisibleReasoningLabelUtf8Base64)) {
    $surfaceArguments += @(
        "--visible-reasoning-label",
        (ConvertFrom-C8Utf8Base64 `
            -Value $VisibleReasoningLabelUtf8Base64 `
            -FieldName "Visible reasoning label")
    )
}
$surfaceResult = & $python @surfaceArguments
if ($LASTEXITCODE -ne 0) {
    throw "C8 Work surface observation creation failed."
}
$surfacePath = Join-Path $state "work-surface.json"
$surfaceResult -join "`n" | Set-Content -LiteralPath $surfacePath

$quotaResult = & $python -m systeme_local_gateway.c8_live_cycle observe-quota `
    --cycle-id $cycleId
if ($LASTEXITCODE -ne 0) {
    throw "C8 Work quota observation creation failed."
}
$quotaPath = Join-Path $state "work-quota.json"
$quotaResult -join "`n" | Set-Content -LiteralPath $quotaPath

$expiresAt = [DateTime]::UtcNow.AddMinutes(20).ToString("o")
$grantResult = & $python -m systeme_local_gateway.c8_live_cycle issue-grant `
    --authorization $authorizationPath `
    --surface-observation $surfacePath `
    --quota-observation $quotaPath `
    --expires-at $expiresAt
if ($LASTEXITCODE -ne 0) {
    throw "C8 Work live-cycle grant creation failed."
}
$grantResult -join "`n" | Set-Content -LiteralPath $liveCyclePath
$cycle = ($grantResult -join "`n") | ConvertFrom-Json

[pscustomobject]@{
    status = "live_cycle_admitted"
    cycle_id = $cycle.authorization.cycle_id
    grant_id = $cycle.grant.grant_id
    expires_at = $cycle.grant.expires_at
    visible_surface = "work"
    entitlement = "available"
    quota = "usable"
    effective_tool_count = 1
    native_chat_allowed = $false
    automatic_chat_to_work_switch_allowed = $false
} | ConvertTo-Json
