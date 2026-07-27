[CmdletBinding()]
param(
    [switch]$AllowDirty,
    [string]$AsOf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C7.Common.psm1") -Force

Assert-C7GitState -AllowDirty:$AllowDirty
Assert-C7OfflineBoundary

$arguments = @(
    "-m",
    "systeme_local_gateway.c7_work_admission",
    "status"
)
if (-not [string]::IsNullOrWhiteSpace($AsOf)) {
    $arguments += @("--as-of", $AsOf)
}
$invocation = Invoke-C7PythonCommand -Arguments $arguments
$status = ConvertFrom-C7JsonResult -Invocation $invocation -Operation "status"
$status | ConvertTo-Json -Depth 8
if ($invocation.exit_code -ne 0) {
    throw "C7 status failed closed."
}
