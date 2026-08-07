[CmdletBinding()]
param(
    [switch]$RequireSecrets,
    [switch]$RequireLocalAI,
    [switch]$RequireTunnelCredentials,
    [switch]$RequireLiveCycle
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9TrustedExecutionBoundary
Assert-C9GitState
$root = Get-C9RepositoryRoot
[void](Initialize-C9StateDirectory)
if ($RequireSecrets -or $RequireLiveCycle) {
    Assert-C9SecretEnvironment
}
if ($RequireLocalAI -or $RequireLiveCycle) {
    Assert-C9LocalAIEnvironment
    [void](Assert-C9LocalAIRuntimeObservationEnvironment)
}
if ($RequireTunnelCredentials) {
    Assert-C9TunnelEnvironment
}
$binary = Assert-C9TunnelBinary
$liveAllowed = $false
$effectiveToolCount = 0
$cycleId = $null
$grantId = $null
if ($RequireLiveCycle) {
    $decision = Get-C9AdmissionDecision
    $liveAllowed = $true
    $effectiveToolCount = 1
    $cycleId = $decision.cycle_id
    $grantId = $decision.grant_id
}

[pscustomobject]@{
    status = "ready"
    branch = (
        @(
            Invoke-C9Git -Arguments @(
                "-C",
                $root,
                "branch",
                "--show-current"
            )
        ) -join "`n"
    ).Trim()
    commit = Get-C9BuildCommit
    accepted_c8_commit = "bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5"
    tunnel_client_binary_sha256 = (
        Get-FileHash -LiteralPath $binary -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    local_ai_required = ($RequireLocalAI -or $RequireLiveCycle)
    live_cycle_admitted = $liveAllowed
    effective_tool_count = $effectiveToolCount
    cycle_id = $cycleId
    grant_id = $grantId
    c0_enabled = $false
    loopback_mcp_url = "http://127.0.0.1:8765/mcp"
} | ConvertTo-Json
