[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected")]
    [string]$SameWorkReplay,
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected")]
    [string]$CrossWorkReplay,
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected")]
    [string]$UnknownField,
    [Parameter(Mandatory = $true)]
    [ValidateSet("rejected")]
    [string]$MalformedChallenge,
    [Parameter(Mandatory = $true)]
    [ValidateSet("capability_not_exposed", "not_safely_exposed")]
    [string]$LocalFileRequest,
    [Parameter(Mandatory = $true)]
    [ValidateSet("capability_not_exposed", "not_safely_exposed")]
    [string]$CommandExecutionRequest,
    [Parameter(Mandatory = $true)]
    [ValidateSet("capability_not_exposed", "not_safely_exposed")]
    [string]$SecretRequest,
    [Parameter(Mandatory = $true)]
    [ValidateSet("capability_not_exposed", "not_safely_exposed")]
    [string]$RealEvidenceRequest,
    [Parameter(Mandatory = $true)]
    [ValidateSet("capability_not_exposed", "not_safely_exposed")]
    [string]$WriteOperationRequest,
    [Parameter(Mandatory = $true)]
    [ValidateSet("capability_not_exposed", "not_safely_exposed")]
    [string]$ProtocolV2Request,
    [Parameter(Mandatory = $true)]
    [ValidateSet("unreachable_after_revocation")]
    [string]$PostRevocationCall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

Assert-C8GitState
Assert-C8AuditKeyEnvironment
$root = Get-C8RepositoryRoot
$state = Initialize-C8StateDirectory
foreach ($name in @("proof-a.json", "proof-b.json")) {
    if (-not (Test-Path -LiteralPath (Join-Path $state $name) -PathType Leaf)) {
        throw "C8 negative receipt requires both positive Work proofs first."
    }
}
if (
    $null -ne (Read-C8Pid -Name "facade") -or
    $null -ne (Read-C8Pid -Name "facade-launcher") -or
    $null -ne (Read-C8Pid -Name "tunnel")
) {
    throw "C8 negative receipt with post-revocation state requires stopped processes."
}
$cycle = Get-C8LiveCycle
$arguments = @(
    "-m", "systeme_local_gateway.c8_live_cycle", "commit-negative",
    "--cycle-id", [string]$cycle.authorization.cycle_id,
    "--grant-id", [string]$cycle.grant.grant_id,
    "--outcome", "same_work_replay=$SameWorkReplay",
    "--outcome", "cross_work_replay=$CrossWorkReplay",
    "--outcome", "unknown_field=$UnknownField",
    "--outcome", "malformed_challenge=$MalformedChallenge",
    "--outcome", "local_file_request=$LocalFileRequest",
    "--outcome", "command_execution_request=$CommandExecutionRequest",
    "--outcome", "secret_request=$SecretRequest",
    "--outcome", "real_evidence_request=$RealEvidenceRequest",
    "--outcome", "write_operation_request=$WriteOperationRequest",
    "--outcome", "protocol_v2_request=$ProtocolV2Request",
    "--outcome", "post_revocation_call=$PostRevocationCall"
)
$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "C8 negative-test receipt validation failed."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "negative-tests.json"
)
$result -join "`n"
