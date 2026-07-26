[CmdletBinding()]
param(
    [string]$ManualObservationPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
Assert-C0SecretEnvironment
$root = Get-C0RepositoryRoot
$state = Get-C0StateDirectory
if ($null -ne (Read-C0Pid -Name "facade") -or $null -ne (Read-C0Pid -Name "tunnel")) {
    throw "C0 processes must be stopped before committing the revocation-bound attestation."
}
if ([string]::IsNullOrWhiteSpace($ManualObservationPath)) {
    $ManualObservationPath = Join-Path $state "manual-web-observation.json"
}
$paths = @{
    manual = [System.IO.Path]::GetFullPath($ManualObservationPath)
    response = Join-Path $state "live-response.json"
    challenge = Join-Path $state "challenge.txt"
    audit = Join-Path $state "audit.jsonl"
    revocation = Join-Path $state "revocation-receipt.json"
}
$statePrefix = [System.IO.Path]::GetFullPath($state) +
    [System.IO.Path]::DirectorySeparatorChar
foreach ($path in $paths.Values) {
    $resolved = [System.IO.Path]::GetFullPath($path)
    if (-not $resolved.StartsWith(
        $statePrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Attestation inputs must remain inside the ignored C0 state directory."
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Required C0 attestation input is missing: $resolved"
    }
}

$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python -m systeme_local_gateway.c0_attest `
    --manual-observation $paths.manual `
    --response $paths.response `
    --challenge $paths.challenge `
    --audit-log $paths.audit `
    --revocation-receipt $paths.revocation `
    --policy (Join-Path $root "policy.c0.yaml")
if ($LASTEXITCODE -ne 0) {
    throw "C0 live attestation validation failed."
}
$attestation = ($result -join "`n") | ConvertFrom-Json
if (
    $attestation.real_connection_established -ne $true -or
    $attestation.revocation_verified -ne $true -or
    $attestation.source -ne "manual_chatgpt_web"
) {
    throw "Committed C0 attestation violated its live-proof invariants."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "attestation.json"
)
$result -join "`n"
