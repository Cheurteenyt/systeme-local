[CmdletBinding()]
param()

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
    throw "Stop all C1 processes before preflight cleanup."
}
foreach ($protected in @(
    "attestation.json",
    "proof-a.json",
    "proof-b.json",
    "revocation.json"
)) {
    if (Test-Path -LiteralPath (Join-Path $state $protected) -PathType Leaf) {
        throw "Preflight cleanup refuses correlated or final C1 evidence."
    }
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
            throw "Refusing preflight cleanup outside the private C1 state directory."
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
    status = "preflight_clean"
    removed = @($removed | Sort-Object)
    process_secrets_cleared = $true
    correlated_evidence_removed = $false
    recoverable = $false
} | ConvertTo-Json
