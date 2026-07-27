[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C7.Common.psm1") -Force

Assert-C7OfflineBoundary

$invocation = Invoke-C7PythonCommand -Arguments @(
    "-m",
    "systeme_local_gateway.c7_work_admission",
    "show-c8-gates"
)
$gates = ConvertFrom-C7JsonResult -Invocation $invocation -Operation "C8 guidance"
$gates | ConvertTo-Json -Depth 8
if ($invocation.exit_code -ne 0) {
    throw "C7 could not render the future C8 gates."
}
