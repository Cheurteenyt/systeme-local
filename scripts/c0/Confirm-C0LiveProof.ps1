[CmdletBinding()]
param(
    [string]$ResponsePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
Assert-C0SecretEnvironment
$root = Get-C0RepositoryRoot
$state = Get-C0StateDirectory
if ([string]::IsNullOrWhiteSpace($ResponsePath)) {
    $ResponsePath = Join-Path $state "live-response.json"
}
$resolvedResponse = [System.IO.Path]::GetFullPath($ResponsePath)
$statePrefix = [System.IO.Path]::GetFullPath($state) +
    [System.IO.Path]::DirectorySeparatorChar
if (-not $resolvedResponse.StartsWith(
    $statePrefix,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "Live response must be stored inside the ignored C0 state directory."
}

$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python -m systeme_local_gateway.c0_proof_check `
    --response $resolvedResponse `
    --challenge (Join-Path $state "challenge.txt") `
    --audit-log (Join-Path $state "audit.jsonl") `
    --policy (Join-Path $root "policy.c0.yaml")
if ($LASTEXITCODE -ne 0) {
    throw "Manual C0 response or audit correlation validation failed."
}
$json = ($result -join "`n") | ConvertFrom-Json
if (
    $json.status -ne "live_call_correlated_pending_revocation" -or
    $json.real_connection_established -ne $false -or
    $json.receipt_hmac -notmatch "^[0-9a-f]{64}$" -or
    $json.audit_record_sha256 -notmatch "^[0-9a-f]{64}$" -or
    $json.response_sha256 -notmatch "^[0-9a-f]{64}$"
) {
    throw "C0 proof checker attempted an invalid live-state transition."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "live-proof-pending-revocation.json"
)
$result -join "`n"
