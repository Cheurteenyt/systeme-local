[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("a", "b")]
    [string]$TestWork,
    [string]$ResponsePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

Assert-C8GitState
Assert-C8SecretEnvironment
$root = Get-C8RepositoryRoot
$state = Initialize-C8StateDirectory
if ([string]::IsNullOrWhiteSpace($ResponsePath)) {
    $ResponsePath = Join-Path $state "live-response-$TestWork.json"
}
$response = Assert-C8StateFile -Path $ResponsePath
$required = @(
    $response,
    (Join-Path $state "live-cycle.json"),
    (Join-Path $state "task-surface-$TestWork.json"),
    (Join-Path $state "challenge-$TestWork.txt"),
    (Join-Path $state "audit.jsonl")
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required C8 Work proof input is missing: $path"
    }
}
$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python -m systeme_local_gateway.c8_proof_check `
    --test-work $TestWork `
    --live-cycle (Join-Path $state "live-cycle.json") `
    --task-surface-observation (Join-Path $state "task-surface-$TestWork.json") `
    --response $response `
    --challenge (Join-Path $state "challenge-$TestWork.txt") `
    --audit-log (Join-Path $state "audit.jsonl") `
    --policy (Join-Path $root "policy.c0.yaml") `
    --root $root
if ($LASTEXITCODE -ne 0) {
    throw "C8 Work $TestWork response or local audit correlation failed."
}
$bundle = ($result -join "`n") | ConvertFrom-Json
if (
    $bundle.version -ne "1" -or
    $bundle.observation.test_work_label -ne "c8-test-work-$TestWork" -or
    $bundle.correlation_receipt.status -ne "live_work_call_correlated"
) {
    throw "C8 proof checker returned an invalid bundle."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "proof-$TestWork.json"
)
$result -join "`n"
