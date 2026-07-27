[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C2.Common.psm1") -Force

Assert-C2GitState
$invocation = Invoke-C2PythonCommand -Arguments @(
    "-m",
    "systeme_local_gateway.c2_capability",
    "verify-profile",
    "--profile",
    (Get-C2OfficialProfilePath)
)
if ($invocation.exit_code -ne 0) {
    throw "C2 committed official-capability profile verification failed."
}
($invocation.output -join "`n") | ConvertFrom-Json | ConvertTo-Json -Depth 8
