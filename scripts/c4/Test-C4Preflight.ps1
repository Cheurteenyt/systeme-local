[CmdletBinding()]
param(
    [ValidateSet(
        "runtime_key_creation",
        "tunnel_start",
        "plugin_creation",
        "browser_test",
        "chatgpt_action",
        "tool_surface_exposure"
    )]
    [string]$Action = "tunnel_start",
    [switch]$RequestApprovedTools,
    [switch]$AllowDirty,
    [string]$AsOf,
    [string]$Correlation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C4.Common.psm1") -Force

$decision = Invoke-C4Admission `
    -Action $Action `
    -RequestApprovedTools:$RequestApprovedTools `
    -AllowDirty:$AllowDirty `
    -AsOf $AsOf `
    -Correlation $Correlation
$decision | ConvertTo-Json -Depth 12
