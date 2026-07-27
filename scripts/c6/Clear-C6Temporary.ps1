[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C6.Common.psm1") -Force

Assert-C6OfflineBoundary
$stateDirectory = Get-C6StateDirectory
$removed = @()
foreach ($name in @("candidate-profile.json", "revalidation-receipt.json")) {
    $path = Join-Path $stateDirectory $name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $item = Get-Item -LiteralPath $path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "C6 cleanup refuses a reparse file."
        }
        Remove-Item -LiteralPath $item.FullName -Force
        $removed += $name
    }
}
if (Test-Path -LiteralPath $stateDirectory -PathType Container) {
    $stateItem = Get-Item -LiteralPath $stateDirectory -Force
    if (($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "C6 cleanup refuses a reparse directory."
    }
    $remaining = @(Get-ChildItem -LiteralPath $stateDirectory -Force)
    if ($remaining.Count -eq 0) {
        Remove-Item -LiteralPath $stateDirectory -Force
    }
}

[pscustomobject]@{
    status = "temporary_c6_artifacts_cleared"
    removed = $removed
    runtime_secrets_touched = $false
    reviewed_governance_touched = $false
} | ConvertTo-Json -Depth 4
