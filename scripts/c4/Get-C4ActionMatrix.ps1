[CmdletBinding()]
param(
    [switch]$AllowDirty,
    [string]$AsOf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C4.Common.psm1") -Force

$matrix = Get-C4ActionMatrix -AllowDirty:$AllowDirty -AsOf $AsOf
$matrix | ConvertTo-Json -Depth 12
