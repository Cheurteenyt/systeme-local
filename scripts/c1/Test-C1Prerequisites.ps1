[CmdletBinding()]
param(
    [switch]$RequireSecrets,
    [switch]$RequireTunnelCredentials
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
$root = Get-C1RepositoryRoot
$manifest = Get-Content -LiteralPath (
    Join-Path $root "governance\c0-tunnel-client.json"
) -Raw | ConvertFrom-Json
if ($RequireSecrets) {
    Assert-C1SecretEnvironment
}
if ($RequireTunnelCredentials) {
    Assert-C1TunnelEnvironment
}
$binary = Assert-C1TunnelBinary
$policyHash = (
    Get-FileHash -LiteralPath (Join-Path $root "policy.c0.yaml") -Algorithm SHA256
).Hash.ToLowerInvariant()

[pscustomobject]@{
    status = "ready"
    branch = (& git -C $root branch --show-current).Trim()
    commit = Get-C1BuildCommit
    dependency_commit = "912d0d33e119469ff957965104cf20af5e491923"
    tunnel_client_version = $manifest.version
    tunnel_client_binary_sha256 = (
        Get-FileHash -LiteralPath $binary -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    local_policy_file_sha256 = $policyHash
    loopback_mcp_url = "http://127.0.0.1:8765/mcp"
} | ConvertTo-Json
