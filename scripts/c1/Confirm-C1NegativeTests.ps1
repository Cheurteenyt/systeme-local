[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected", "capability_not_exposed")]
    [string]$SameChatReplay,
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected", "capability_not_exposed")]
    [string]$CrossChatReplay,
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected", "capability_not_exposed")]
    [string]$UnknownField,
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected", "capability_not_exposed")]
    [string]$MalformedChallenge,
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected", "capability_not_exposed")]
    [string]$LocalFileRequest,
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected", "capability_not_exposed")]
    [string]$CommandExecutionRequest,
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected", "capability_not_exposed")]
    [string]$SecretRequest,
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected", "capability_not_exposed")]
    [string]$B2EvidenceRequest,
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected", "capability_not_exposed")]
    [string]$WriteOperationRequest,
    [Parameter(Mandatory = $true)]
    [ValidateSet("unreachable_after_revocation")]
    [string]$PostRevocationCall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
Assert-C1AuditKeyEnvironment
$root = Get-C1RepositoryRoot
$state = Initialize-C1StateDirectory
$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python -m systeme_local_gateway.c1_evidence negative `
    --same-chat-replay $SameChatReplay `
    --cross-chat-replay $CrossChatReplay `
    --unknown-field $UnknownField `
    --malformed-challenge $MalformedChallenge `
    --local-file-request $LocalFileRequest `
    --command-execution-request $CommandExecutionRequest `
    --secret-request $SecretRequest `
    --b2-evidence-request $B2EvidenceRequest `
    --write-operation-request $WriteOperationRequest `
    --post-revocation-call $PostRevocationCall
if ($LASTEXITCODE -ne 0) {
    throw "C1 negative-test receipt failed closed."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "negative-tests.json"
)
$result -join "`n"
