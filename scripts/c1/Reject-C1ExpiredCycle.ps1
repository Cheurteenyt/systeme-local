[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$PluginConnectionRemoved,
    [Parameter(Mandatory = $true)]
    [switch]$RuntimeApiKeyRevoked
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
$state = Get-C1StateDirectory
if (
    $null -ne (Read-C1Pid -Name "facade") -or
    $null -ne (Read-C1Pid -Name "facade-launcher") -or
    $null -ne (Read-C1Pid -Name "tunnel")
) {
    throw "Stop all C1 processes before rejecting an expired cycle."
}
$listeners = @(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(8765, 8766) }
)
if ($listeners.Count -gt 0) {
    throw "C1 loopback listeners remain open."
}
if (Test-Path -LiteralPath (Join-Path $state "attestation.json") -PathType Leaf) {
    throw "A validated C1 attestation must use final cleanup, not expired-cycle rejection."
}

$now = [DateTimeOffset]::UtcNow
$expired = @()
foreach ($name in @(
    "runtime-setup.json",
    "visible-model.json",
    "surface-a.json",
    "surface-b.json",
    "proof-a.json",
    "proof-b.json",
    "negative-tests.json",
    "revocation.json"
)) {
    $path = Join-Path $state $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        continue
    }
    $value = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $expiresAt = $null
    if ($value.PSObject.Properties.Name -contains "expires_at") {
        $expiresAt = $value.expires_at
    } elseif (
        $value.PSObject.Properties.Name -contains "correlation_receipt" -and
        $value.correlation_receipt.PSObject.Properties.Name -contains "expires_at"
    ) {
        $expiresAt = $value.correlation_receipt.expires_at
    }
    if (
        $null -ne $expiresAt -and
        [DateTimeOffset]::Parse([string]$expiresAt) -le $now
    ) {
        $expired += $name
    }
}
if ($expired.Count -eq 0) {
    throw "Expired-cycle rejection requires at least one expired typed C1 evidence file."
}

$removed = @()
if (Test-Path -LiteralPath $state -PathType Container) {
    foreach ($child in Get-ChildItem -LiteralPath $state -Force) {
        $resolved = [System.IO.Path]::GetFullPath($child.FullName)
        $prefix = [System.IO.Path]::GetFullPath($state) +
            [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith(
            $prefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Refusing expired-cycle cleanup outside the private C1 state directory."
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
        $removed += $child.Name
    }
}
foreach ($name in @(
    "SLG_AUDIT_KEY",
    "SLG_SHARED_SECRET",
    "SLG_MCP_TOKEN",
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID"
)) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    status = "expired_cycle_rejected"
    reason = "expired_evidence"
    expired_evidence = @($expired | Sort-Object)
    removed = @($removed | Sort-Object)
    plugin_connection_removed = [bool]$PluginConnectionRemoved
    runtime_api_key_revoked = [bool]$RuntimeApiKeyRevoked
    listeners_closed = $true
    process_secrets_cleared = $true
    recoverable = $false
} | ConvertTo-Json
