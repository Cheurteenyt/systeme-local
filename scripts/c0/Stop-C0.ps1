[CmdletBinding()]
param(
    [switch]$Emergency
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

if ($Emergency) {
    Assert-C0GitState -AllowDirty
} else {
    Assert-C0GitState
}
Stop-C0Process -Name "tunnel" -AllowedExecutableNames @("tunnel-client.exe")
Stop-C0Process -Name "tunnel-local" -AllowedExecutableNames @("tunnel-client.exe")
Stop-C0Process -Name "facade" -AllowedExecutableNames @("python.exe")
Stop-C0Process -Name "facade-launcher" -AllowedExecutableNames @("python.exe")

$remaining = @(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(8765, 8766) }
)
if ($remaining.Count -gt 0) {
    throw "A C0 loopback port remains open after shutdown."
}

foreach ($name in @(
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "MCP_SERVER_URL",
    "MCP_EXTRA_HEADERS",
    "MCP_DISCOVERY_EXTRA_HEADERS",
    "MCP_MAX_CONCURRENT_REQUESTS",
    "MCP_CONNECTION_MAX_TTL",
    "CONTROL_PLANE_MAX_INFLIGHT_REQUESTS",
    "HEALTH_LISTEN_ADDR",
    "LOG_HTTP_RAW_UNSAFE",
    "OPEN_WEB_UI",
    "ALLOW_REMOTE_UI",
    "SLG_SHARED_SECRET",
    "SLG_AUDIT_KEY",
    "SLG_AUDIT_ANCHOR_LOG",
    "SLG_AUDIT_ANCHOR_KEY",
    "SLG_C0_ENABLED",
    "SLG_C0_SERVER_BUILD_COMMIT",
    "SLG_MCP_ENABLED",
    "SLG_MCP_TOKEN",
    "SLG_MCP_MAX_REQUEST_BYTES",
    "SLG_MCP_REQUESTS_PER_MINUTE",
    "SLG_MCP_MAX_CONCURRENCY",
    "SLG_POLICY_FILE",
    "SLG_WORKSPACE",
    "SLG_AUDIT_LOG",
    "SLG_REPLAY_DB",
    "SLG_APPROVAL_DB",
    "SLG_SANDBOX_ROOT"
)) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    status = "stopped"
    ports_closed = @(8765, 8766)
    process_environment_cleared = $true
} | ConvertTo-Json
