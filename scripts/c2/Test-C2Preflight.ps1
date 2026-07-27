[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C2.Common.psm1") -Force

$decision = Invoke-C2Preflight
$decision | ConvertTo-Json -Depth 8
