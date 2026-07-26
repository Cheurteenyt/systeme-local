[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
$root = Get-C1RepositoryRoot
$state = Initialize-C1StateDirectory
$manifest = Get-Content -LiteralPath (
    Join-Path $root "governance\c0-tunnel-client.json"
) -Raw | ConvertFrom-Json
$initialized = @()
foreach ($name in @("SLG_SHARED_SECRET", "SLG_AUDIT_KEY", "SLG_MCP_TOKEN")) {
    $existing = [Environment]::GetEnvironmentVariable($name, "Process")
    if (-not [string]::IsNullOrWhiteSpace($existing)) {
        if ($existing.Length -lt 32) {
            throw "$name is already set but does not satisfy the C1 minimum length."
        }
        continue
    }
    $bytes = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    [Environment]::SetEnvironmentVariable(
        $name,
        [Convert]::ToBase64String($bytes),
        "Process"
    )
    $initialized += $name
}
Assert-C1SecretEnvironment
$binary = Assert-C1TunnelBinary

[pscustomobject]@{
    status = "prepared"
    state_directory = $state
    dependency = "C0 exact reviewed probe"
    tunnel_client_version = $manifest.version
    tunnel_client_binary_sha256 = $manifest.binary_sha256
    tunnel_client_binary = $binary
    process_secrets_initialized = $initialized
} | ConvertTo-Json
