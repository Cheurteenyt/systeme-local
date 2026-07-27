[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C6.Common.psm1") -Force

$invocation = Invoke-C6PythonCommand -Arguments @(
    "-m",
    "systeme_local_gateway.c6_revalidation",
    "guidance"
)
if ($invocation.exit_code -ne 0) {
    throw "C6 review guidance failed."
}
$guidance = ConvertFrom-C6JsonResult -Invocation $invocation -Operation "guidance"
$guidance | ConvertTo-Json -Depth 8
