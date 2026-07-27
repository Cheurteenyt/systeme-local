[CmdletBinding()]
param(
    [switch]$RequireCurrentTree,
    [switch]$RequireClean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C7.Common.psm1") -Force

Assert-C7GitState -AllowDirty:(-not $RequireClean)
Assert-C7OfflineBoundary

$arguments = @(
    "-m",
    "systeme_local_gateway.c7_seal",
    "verify"
)
if ($RequireCurrentTree) {
    $arguments += "--require-current-tree"
}
if ($RequireClean) {
    $arguments += "--require-clean"
}
$invocation = Invoke-C7PythonCommand -Arguments $arguments
$result = ConvertFrom-C7JsonResult -Invocation $invocation -Operation "seal verification"
$result | ConvertTo-Json -Depth 8
if ($invocation.exit_code -ne 0) {
    throw "C7 final seal verification failed."
}
