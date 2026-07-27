[CmdletBinding()]
param(
    [switch]$AllowDirty,
    [string]$AsOf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C6.Common.psm1") -Force

Assert-C6GitState -AllowDirty:$AllowDirty
Assert-C6OfflineBoundary

$arguments = @(
    "-m",
    "systeme_local_gateway.c6_revalidation",
    "verify",
    "--root",
    (Get-C6RepositoryRoot),
    "--policy",
    (Get-C6PolicyPath),
    "--c3-registry",
    (Get-C6C3RegistryPath),
    "--expect-all-denied"
)
if (-not [string]::IsNullOrWhiteSpace($AsOf)) {
    $arguments += @("--as-of", $AsOf)
}
$invocation = Invoke-C6PythonCommand -Arguments $arguments
$status = ConvertFrom-C6JsonResult -Invocation $invocation -Operation "status"
$status | ConvertTo-Json -Depth 8
if ($invocation.exit_code -notin @(0, 5)) {
    throw "C6 status verification failed closed."
}
