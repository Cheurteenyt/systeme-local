[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$PluginConnectionRemoved,
    [Parameter(Mandatory = $true)]
    [switch]$RuntimeApiKeyRevoked,
    [Parameter(Mandatory = $true)]
    [switch]$PostRevocationWorkCallFailed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

if (
    -not $PluginConnectionRemoved -or
    -not $RuntimeApiKeyRevoked -or
    -not $PostRevocationWorkCallFailed
) {
    throw "C8 requires complete Plugin, Runtime-key, and post-revocation confirmation."
}
Assert-C8GitState
Assert-C8AuditKeyEnvironment
$root = Get-C8RepositoryRoot
$state = Initialize-C8StateDirectory
if (-not (Test-Path -LiteralPath (Join-Path $state "negative-tests.json"))) {
    throw "C8 revocation receipt requires the bounded negative-test receipt."
}
if (
    $null -ne (Read-C8Pid -Name "facade") -or
    $null -ne (Read-C8Pid -Name "facade-launcher") -or
    $null -ne (Read-C8Pid -Name "tunnel")
) {
    throw "C8 revocation confirmation found a tracked live process."
}
if (@(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(8765, 8766) }
).Count -ne 0) {
    throw "C8 revocation confirmation found a remaining listener."
}
foreach ($name in @(
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "SLG_SHARED_SECRET",
    "SLG_MCP_TOKEN",
    "SLG_MCP_AUTHORIZATION"
)) {
    if (-not [string]::IsNullOrWhiteSpace(
        [Environment]::GetEnvironmentVariable($name, "Process")
    )) {
        throw "C8 revocation confirmation found uncleared process variable $name."
    }
}
$cycle = Get-C8LiveCycle
$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python -m systeme_local_gateway.c8_live_cycle `
    commit-revocation `
    --cycle-id $cycle.authorization.cycle_id `
    --grant-id $cycle.grant.grant_id `
    --confirmed-complete-revocation
if ($LASTEXITCODE -ne 0) {
    throw "C8 revocation receipt validation failed."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "revocation.json"
)
$result -join "`n"
