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
Stop-C0Process -Name "facade" -AllowedExecutableNames @("python.exe")

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
    "HEALTH_LISTEN_ADDR",
    "LOG_HTTP_RAW_UNSAFE",
    "OPEN_WEB_UI",
    "ALLOW_REMOTE_UI",
    "SLG_C0_ENABLED",
    "SLG_C0_SERVER_BUILD_COMMIT",
    "SLG_MCP_ENABLED",
    "SLG_MCP_TOKEN"
)) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    status = "stopped"
    ports_closed = @(8765, 8766)
    process_environment_cleared = $true
} | ConvertTo-Json
