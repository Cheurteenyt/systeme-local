[CmdletBinding()]
param(
    [switch]$AllowDirty,
    [string]$AsOf,
    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C6.Common.psm1") -Force

Assert-C6GitState -AllowDirty:$AllowDirty
Assert-C6OfflineBoundary

$receipt = Resolve-C6LocalJsonPath -Name "revalidation-receipt.json"
$candidate = Resolve-C6LocalJsonPath -Name "candidate-profile.json"
$arguments = @(
    "-m",
    "systeme_local_gateway.c6_revalidation",
    "acquire",
    "--root",
    (Get-C6RepositoryRoot),
    "--policy",
    (Get-C6PolicyPath),
    "--c3-registry",
    (Get-C6C3RegistryPath),
    "--timeout-seconds",
    $TimeoutSeconds.ToString(),
    "--receipt-output",
    $receipt,
    "--candidate-output",
    $candidate,
    "--expect-all-denied"
)
if (-not [string]::IsNullOrWhiteSpace($AsOf)) {
    $arguments += @("--as-of", $AsOf)
}
$invocation = Invoke-C6PythonCommand -Arguments $arguments
$report = ConvertFrom-C6JsonResult `
    -Invocation $invocation `
    -Operation "official revalidation"
$report | ConvertTo-Json -Depth 10

if ($invocation.exit_code -eq 6) {
    throw "C6 detected official source drift; independent review is required."
}
if ($invocation.exit_code -eq 5) {
    throw "C6 evidence expired; the generated candidate still requires review."
}
if ($invocation.exit_code -ne 0) {
    throw "C6 official acquisition failed closed."
}
