[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DraftPath,
    [string]$OutputPath,
    [switch]$AllowDirty,
    [string]$AsOf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C3.Common.psm1") -Force

Assert-C3GitState -AllowDirty:$AllowDirty
$resolvedDraft = Resolve-C3LocalJsonPath -Path $DraftPath -MustExist
$effectiveAsOf = $AsOf
if ([string]::IsNullOrWhiteSpace($effectiveAsOf)) {
    $effectiveAsOf = [DateTime]::UtcNow.ToString("o")
}
$invocation = Invoke-C3PythonCommand -Arguments @(
    "-m",
    "systeme_local_gateway.c3_evidence",
    "seal-candidate",
    "--root",
    (Get-C3RepositoryRoot),
    "--registry",
    (Get-C3RegistryPath),
    "--draft",
    $resolvedDraft,
    "--as-of",
    $effectiveAsOf
)
if ($invocation.exit_code -ne 0) {
    throw "C3 candidate sealing rejected the draft."
}
$candidate = ConvertFrom-C3JsonResult `
    -Invocation $invocation `
    -Operation "candidate sealing"
$json = $candidate | ConvertTo-Json -Depth 10
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $json
}
else {
    $resolvedOutput = Resolve-C3LocalJsonPath -Path $OutputPath
    Write-C3Utf8JsonFile -Path $resolvedOutput -Json $json
    [pscustomobject]@{
        status = "candidate_sealed"
        path = $resolvedOutput
        sha256 = (Get-FileHash -LiteralPath $resolvedOutput -Algorithm SHA256).Hash.ToLower()
    } | ConvertTo-Json
}
