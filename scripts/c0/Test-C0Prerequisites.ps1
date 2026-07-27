[CmdletBinding()]
param(
    [switch]$RequireSecrets,
    [switch]$RequireTunnelCredentials
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
$root = Get-C0RepositoryRoot
$state = Get-C0StateDirectory
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "The repository virtual environment is unavailable."
}
$tunnel = Assert-C0TunnelBinary
if ($RequireSecrets) {
    Assert-C0SecretEnvironment
}
if ($RequireTunnelCredentials) {
    Assert-C0TunnelEnvironment
}

$manifest = Get-Content -LiteralPath (
    Join-Path $root "governance\c0-tunnel-client.json"
) -Raw | ConvertFrom-Json
$archive = Join-Path $state $manifest.asset.name
if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    throw "Pinned tunnel-client archive is unavailable."
}
$archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($archiveHash -ne $manifest.asset.sha256) {
    throw "Pinned tunnel-client archive integrity check failed."
}

[pscustomobject]@{
    status = "ready"
    branch = "interop/chatgpt-web-mcp-connectivity-c0"
    commit = Get-C0BuildCommit
    tunnel_client_version = $manifest.version
    tunnel_client_binary_sha256 = $manifest.binary_sha256
    loopback_mcp_url = "http://127.0.0.1:8765/mcp"
} | ConvertTo-Json
