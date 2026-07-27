[CmdletBinding()]
param(
    [switch]$AllowDirty,
    [string]$AsOf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C3.Common.psm1") -Force

Assert-C3GitState -AllowDirty:$AllowDirty
$effectiveAsOf = $AsOf
if ([string]::IsNullOrWhiteSpace($effectiveAsOf)) {
    $effectiveAsOf = [DateTime]::UtcNow.ToString("o")
}
$invocation = Invoke-C3PythonCommand -Arguments @(
    "-m",
    "systeme_local_gateway.c3_evidence",
    "verify-profile",
    "--root",
    (Get-C3RepositoryRoot),
    "--registry",
    (Get-C3RegistryPath),
    "--as-of",
    $effectiveAsOf
)
$decision = ConvertFrom-C3JsonResult `
    -Invocation $invocation `
    -Operation "official-profile verification"
$decision | ConvertTo-Json -Depth 10
if ($invocation.exit_code -ne 0) {
    throw "$($decision.final_status): C3 official profile verification failed."
}
