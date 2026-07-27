[CmdletBinding()]
param(
    [switch]$AllowDirty,
    [string]$AsOf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C3.Common.psm1") -Force

$decision = Invoke-C3Preflight -AllowDirty:$AllowDirty -AsOf $AsOf
$decision | ConvertTo-Json -Depth 10
