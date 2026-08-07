[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedNoLiveActions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

if (-not $ConfirmedNoLiveActions) {
    throw "C8 pre-live reset requires explicit confirmation of zero live actions."
}
Assert-C8GitState
$state = Get-C8StateDirectory
if (
    $null -ne (Read-C8Pid -Name "facade") -or
    $null -ne (Read-C8Pid -Name "facade-launcher") -or
    $null -ne (Read-C8Pid -Name "tunnel")
) {
    throw "C8 pre-live reset refuses tracked live processes."
}
if (@(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(8765, 8766) }
).Count -ne 0) {
    throw "C8 pre-live reset refuses active listeners on C8 ports."
}

$allowed = @(
    "authorization.json",
    "work-quota.json",
    "work-surface.json"
)
$removed = @()
if (Test-Path -LiteralPath $state -PathType Container) {
    $children = @(Get-ChildItem -LiteralPath $state -Force)
    $unexpected = @($children | Where-Object { $_.Name -notin $allowed })
    if ($unexpected.Count -ne 0) {
        $names = ($unexpected.Name | Sort-Object) -join ", "
        throw "C8 pre-live reset refuses non-pre-live state: $names"
    }
    $prefix = [System.IO.Path]::GetFullPath($state) +
        [System.IO.Path]::DirectorySeparatorChar
    foreach ($child in $children) {
        $resolved = [System.IO.Path]::GetFullPath($child.FullName)
        if (-not $resolved.StartsWith(
            $prefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Refusing C8 pre-live reset outside the private state directory."
        }
        Remove-Item -LiteralPath $resolved -Force
        $removed += $child.Name
    }
}

foreach ($name in @(
    "SLG_AUDIT_KEY",
    "SLG_SHARED_SECRET",
    "SLG_MCP_TOKEN",
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "SLG_PROVIDER_RUNTIME_MODE",
    "SLG_PROVIDER_RUNTIME_ROOT",
    "SLG_C8_LIVE_CYCLE_FILE"
)) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    status = "pre_live_reset"
    removed = @($removed | Sort-Object)
    process_secrets_cleared = $true
    live_actions_removed = $false
    correlated_evidence_removed = $false
} | ConvertTo-Json
