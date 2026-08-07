[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

Assert-C8GitState
$state = Get-C8StateDirectory
if (
    $null -ne (Read-C8Pid -Name "facade") -or
    $null -ne (Read-C8Pid -Name "facade-launcher") -or
    $null -ne (Read-C8Pid -Name "tunnel")
) {
    throw "Stop all C8 processes before final cleanup."
}
if (-not (Test-Path -LiteralPath (Join-Path $state "attestation.json"))) {
    throw "C8 final cleanup requires the validated final attestation."
}
$preserve = @(
    "attestation.json",
    "authorization.json",
    "live-cycle.json",
    "negative-tests.json",
    "proof-a.json",
    "proof-b.json",
    "revocation.json",
    "task-surface-a.json",
    "task-surface-b.json",
    "work-quota.json",
    "work-surface.json"
)
$removed = @()
foreach ($child in Get-ChildItem -LiteralPath $state -Force) {
    if ($child.Name -in $preserve) {
        continue
    }
    $resolved = [System.IO.Path]::GetFullPath($child.FullName)
    $prefix = [System.IO.Path]::GetFullPath($state) +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith(
        $prefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing C8 cleanup outside the private state directory."
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    $removed += $child.Name
}
$secretPattern = (
    "(?i)(Bearer\s+\S+|sk-[A-Za-z0-9_-]{20,}|" +
    "tunnel_[0-9a-f]{32}|(?:cookie|authorization)\s*[:=]\s*\S+)"
)
foreach ($name in $preserve) {
    $path = Join-Path $state $name
    if ((Get-Content -LiteralPath $path -Raw) -match $secretPattern) {
        throw "Preserved C8 receipt contains a secret-like value: $name"
    }
}
foreach ($name in @(
    "SLG_AUDIT_KEY",
    "SLG_SHARED_SECRET",
    "SLG_MCP_TOKEN",
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "SLG_PROVIDER_RUNTIME_MODE",
    "SLG_PROVIDER_RUNTIME_ROOT",
    "SLG_C8_LIVE_CYCLE_FILE"
)) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    status = "finalized"
    removed = @($removed | Sort-Object)
    preserved = @($preserve | Sort-Object)
    process_secrets_cleared = $true
    recoverable_local_evidence = $true
    live_connectivity_recoverable = $false
} | ConvertTo-Json
