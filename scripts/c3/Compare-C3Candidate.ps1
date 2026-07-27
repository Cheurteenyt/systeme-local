[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CandidatePath,
    [switch]$AllowDirty,
    [string]$AsOf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C3.Common.psm1") -Force

Assert-C3GitState -AllowDirty:$AllowDirty
$resolvedCandidate = Resolve-C3LocalJsonPath -Path $CandidatePath -MustExist
$effectiveAsOf = $AsOf
if ([string]::IsNullOrWhiteSpace($effectiveAsOf)) {
    $effectiveAsOf = [DateTime]::UtcNow.ToString("o")
}
$invocation = Invoke-C3PythonCommand -Arguments @(
    "-m",
    "systeme_local_gateway.c3_evidence",
    "compare-candidate",
    "--root",
    (Get-C3RepositoryRoot),
    "--registry",
    (Get-C3RegistryPath),
    "--candidate",
    $resolvedCandidate,
    "--as-of",
    $effectiveAsOf
)
$comparison = ConvertFrom-C3JsonResult `
    -Invocation $invocation `
    -Operation "candidate comparison"
$comparison | ConvertTo-Json -Depth 10
if ($invocation.exit_code -eq 4) {
    throw "C3 candidate comparison rejected invalid evidence."
}
if ($invocation.exit_code -notin @(0, 6)) {
    throw "C3 candidate comparison returned an unexpected exit code."
}
