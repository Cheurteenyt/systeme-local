[CmdletBinding()]
param(
    [switch]$RequireSecrets,
    [switch]$RequireTunnelCredentials,
    [switch]$RequireLiveCycle
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

Assert-C8GitState
$root = Get-C8RepositoryRoot
$state = Initialize-C8StateDirectory
if ($RequireSecrets) {
    Assert-C8SecretEnvironment
}
if ($RequireTunnelCredentials) {
    Assert-C8TunnelEnvironment
}
$binary = Assert-C8TunnelBinary
$liveAllowed = $false
if ($RequireLiveCycle) {
    Assert-C8AuditKeyEnvironment
    $liveCyclePath = Join-Path $state "live-cycle.json"
    $python = Join-Path $root ".venv\Scripts\python.exe"
    $result = & $python -m systeme_local_gateway.c8_live_cycle verify-bundle `
        --bundle $liveCyclePath
    if ($LASTEXITCODE -ne 0) {
        throw "Fresh C8 live-cycle admission failed."
    }
    $decision = ($result -join "`n") | ConvertFrom-Json
    if (
        $decision.live_actions_allowed -ne $true -or
        $decision.effective_tool_count -ne 1
    ) {
        throw "C8 live-cycle admission did not preserve the exact one-tool boundary."
    }
    $liveAllowed = $true
}

[pscustomobject]@{
    status = "ready"
    branch = (& git -C $root branch --show-current).Trim()
    commit = Get-C8BuildCommit
    accepted_c7_commit = "e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"
    tunnel_client_binary_sha256 = (
        Get-FileHash -LiteralPath $binary -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    live_cycle_admitted = $liveAllowed
    loopback_mcp_url = "http://127.0.0.1:8765/mcp"
} | ConvertTo-Json
