[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$PluginConnectionRemoved,
    [Parameter(Mandatory = $true)]
    [switch]$RuntimeApiKeyRevoked,
    [Parameter(Mandatory = $true)]
    [switch]$PostRevocationChatCallFailed
)

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
    throw "C1 processes must be stopped before revocation is recorded."
}
$listeners = @(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(8765, 8766) }
)
if ($listeners.Count -gt 0) {
    throw "C1 loopback listeners remain after shutdown."
}
foreach ($name in @("proof-a.json", "proof-b.json")) {
    if (-not (Test-Path -LiteralPath (Join-Path $state $name) -PathType Leaf)) {
        throw "Both correlated C1 Chat proofs are required before revocation."
    }
}
$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python -m systeme_local_gateway.c1_evidence revocation `
    --plugin-removed `
    --runtime-key-revoked `
    --tunnel-stopped `
    --facade-stopped `
    --no-listener `
    --post-revocation-call-failed
if ($LASTEXITCODE -ne 0) {
    throw "C1 revocation receipt failed closed."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "revocation.json"
)
$result -join "`n"
