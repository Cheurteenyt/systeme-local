[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReviewedAt,
    [Parameter(Mandatory = $true)]
    [string]$RevalidateAfter,
    [string]$OutputPath,
    [switch]$AllowDirty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C3.Common.psm1") -Force

Assert-C3GitState -AllowDirty:$AllowDirty
$invocation = Invoke-C3PythonCommand -Arguments @(
    "-m",
    "systeme_local_gateway.c3_evidence",
    "new-candidate-draft",
    "--reviewed-at",
    $ReviewedAt,
    "--revalidate-after",
    $RevalidateAfter
)
if ($invocation.exit_code -ne 0) {
    throw "C3 candidate draft generation failed."
}
$draft = ConvertFrom-C3JsonResult `
    -Invocation $invocation `
    -Operation "candidate draft generation"
$json = $draft | ConvertTo-Json -Depth 10
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $json
}
else {
    $resolvedOutput = Resolve-C3LocalJsonPath -Path $OutputPath
    Write-C3Utf8JsonFile -Path $resolvedOutput -Json $json
    [pscustomobject]@{
        status = "candidate_draft_written"
        path = $resolvedOutput
        sha256 = (Get-FileHash -LiteralPath $resolvedOutput -Algorithm SHA256).Hash.ToLower()
    } | ConvertTo-Json
}
