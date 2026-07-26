[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
Assert-C1AuditKeyEnvironment
$root = Get-C1RepositoryRoot
$state = Initialize-C1StateDirectory
if (
    $null -ne (Read-C1Pid -Name "facade") -or
    $null -ne (Read-C1Pid -Name "facade-launcher") -or
    $null -ne (Read-C1Pid -Name "tunnel")
) {
    throw "C1 processes must be stopped before final attestation."
}
$paths = @{
    runtime = Join-Path $state "runtime-setup.json"
    visible = Join-Path $state "visible-model.json"
    surfaceA = Join-Path $state "surface-a.json"
    surfaceB = Join-Path $state "surface-b.json"
    proofA = Join-Path $state "proof-a.json"
    proofB = Join-Path $state "proof-b.json"
    negative = Join-Path $state "negative-tests.json"
    revocation = Join-Path $state "revocation.json"
    audit = Join-Path $state "audit.jsonl"
}
foreach ($path in $paths.Values) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required C1 final-attestation input is missing: $path"
    }
}
$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python -m systeme_local_gateway.c1_attest `
    --runtime-setup $paths.runtime `
    --visible-model $paths.visible `
    --surface-a $paths.surfaceA `
    --surface-b $paths.surfaceB `
    --proof-a $paths.proofA `
    --proof-b $paths.proofB `
    --negative-tests $paths.negative `
    --revocation $paths.revocation `
    --audit-log $paths.audit `
    --policy (Join-Path $root "policy.c0.yaml") `
    --c0-status "READY_BUT_MANUAL_CHATGPT_WEB_GATE_PENDING"
if ($LASTEXITCODE -ne 0) {
    throw "C1 final live attestation validation failed."
}
$attestation = ($result -join "`n") | ConvertFrom-Json
if (
    $attestation.status -ne "COMPLETE_BOUNDED_CHAT_SURFACE_OBSERVABILITY_VERIFIED" -or
    $attestation.test_chat_count -ne 2 -or
    $attestation.work_tested -ne $false
) {
    throw "C1 final attestation violated its completion invariants."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "attestation.json"
)
$result -join "`n"
