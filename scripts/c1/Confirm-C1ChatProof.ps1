[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("a", "b")]
    [string]$TestChat,
    [string]$ResponsePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
Assert-C1SecretEnvironment
$root = Get-C1RepositoryRoot
$state = Initialize-C1StateDirectory
if ([string]::IsNullOrWhiteSpace($ResponsePath)) {
    $ResponsePath = Join-Path $state "live-response-$TestChat.json"
}
$response = Assert-C1StateFile -Path $ResponsePath
$required = @(
    $response,
    (Join-Path $state "surface-$TestChat.json"),
    (Join-Path $state "challenge-$TestChat.txt"),
    (Join-Path $state "audit.jsonl")
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required C1 proof input is missing: $path"
    }
}
$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python -m systeme_local_gateway.c1_proof_check `
    --test-chat $TestChat `
    --surface-observation (Join-Path $state "surface-$TestChat.json") `
    --response $response `
    --challenge (Join-Path $state "challenge-$TestChat.txt") `
    --audit-log (Join-Path $state "audit.jsonl") `
    --policy (Join-Path $root "policy.c0.yaml")
if ($LASTEXITCODE -ne 0) {
    throw "C1 Chat $TestChat response or audit correlation failed."
}
$bundle = ($result -join "`n") | ConvertFrom-Json
if (
    $bundle.version -ne "1" -or
    $bundle.observation.test_chat_label -ne "c1-test-chat-$TestChat" -or
    $bundle.correlation_receipt.status -ne "live_chat_call_correlated"
) {
    throw "C1 proof checker returned an invalid bundle."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "proof-$TestChat.json"
)
$result -join "`n"
