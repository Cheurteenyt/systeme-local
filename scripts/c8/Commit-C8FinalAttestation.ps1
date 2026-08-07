[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

Assert-C8GitState
Assert-C8AuditKeyEnvironment
$root = Get-C8RepositoryRoot
$state = Initialize-C8StateDirectory
$required = @(
    "live-cycle.json",
    "proof-a.json",
    "proof-b.json",
    "negative-tests.json",
    "revocation.json"
)
foreach ($name in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $state $name) -PathType Leaf)) {
        throw "C8 final attestation input is missing: $name"
    }
}
if (
    $null -ne (Read-C8Pid -Name "facade") -or
    $null -ne (Read-C8Pid -Name "facade-launcher") -or
    $null -ne (Read-C8Pid -Name "tunnel")
) {
    throw "C8 final attestation refuses a live process."
}
$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python -m systeme_local_gateway.c8_live_cycle commit-final `
    --live-cycle (Join-Path $state "live-cycle.json") `
    --proof-a (Join-Path $state "proof-a.json") `
    --proof-b (Join-Path $state "proof-b.json") `
    --negative (Join-Path $state "negative-tests.json") `
    --revocation (Join-Path $state "revocation.json")
if ($LASTEXITCODE -ne 0) {
    throw "C8 final live attestation validation failed."
}
$attestation = ($result -join "`n") | ConvertFrom-Json
if (
    $attestation.status -ne
        "COMPLETE_C8_TWO_WORK_CALLS_LIVE_CORRELATED_AND_REVOKED" -or
    $attestation.work_call_count -ne 2 -or
    $attestation.revocation_verified -ne $true -or
    $attestation.native_chat_tested -ne $false -or
    $attestation.regular_use_readiness_claimed -ne $false
) {
    throw "C8 final attestation returned an invalid completion boundary."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "attestation.json"
)
$result -join "`n"
