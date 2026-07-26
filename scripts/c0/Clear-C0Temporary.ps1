[CmdletBinding()]
param(
    [switch]$IncludeVerifiedTunnelClient
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
if (
    $null -ne (Read-C0Pid -Name "facade") -or
    $null -ne (Read-C0Pid -Name "facade-launcher") -or
    $null -ne (Read-C0Pid -Name "tunnel") -or
    $null -ne (Read-C0Pid -Name "tunnel-local")
) {
    throw "Stop C0 processes before cleanup."
}
$state = Get-C0StateDirectory
if (-not (Test-Path -LiteralPath $state -PathType Container)) {
    '{"status":"already_clean"}'
    exit 0
}

$preserve = @("attestation.json")
if (-not $IncludeVerifiedTunnelClient) {
    $preserve += @("bin")
    $preserve += @("expanded-v0.0.10")
    $preserve += @("tunnel-client-v0.0.10-windows-amd64.zip")
}

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
        throw "Refusing cleanup outside the C0 state directory."
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    $removed += $child.Name
}

[pscustomobject]@{
    status = "cleaned"
    removed = @($removed | Sort-Object)
    preserved = @($preserve | Sort-Object)
    recoverable = $false
} | ConvertTo-Json
