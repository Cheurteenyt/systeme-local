[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
Assert-C0SecretEnvironment
Assert-C0TunnelEnvironment
$state = Initialize-C0StateDirectory
$facadePid = Read-C0Pid -Name "facade"
if ($null -eq $facadePid) {
    throw "Start the C0 facade before the tunnel."
}
Assert-C0LoopbackListener -ProcessId $facadePid -Port 8765
if (
    $null -ne (Read-C0Pid -Name "tunnel") -or
    $null -ne (Read-C0Pid -Name "tunnel-local")
) {
    throw "C0 tunnel-client PID file already exists."
}

$tunnel = Assert-C0TunnelBinary
$existing = @(Get-NetTCPConnection -State Listen -LocalPort 8766 -ErrorAction SilentlyContinue)
if ($existing.Count -gt 0) {
    throw "Port 8766 already has a listener."
}

$env:MCP_SERVER_URL = "channel=main,url=http://127.0.0.1:8765/mcp"
$mcpToken = [Environment]::GetEnvironmentVariable("SLG_MCP_TOKEN", "Process")
$env:SLG_MCP_AUTHORIZATION = "Bearer " + $mcpToken
$mcpToken = $null
$env:MCP_EXTRA_HEADERS = "Authorization: env:SLG_MCP_AUTHORIZATION"
$env:MCP_DISCOVERY_EXTRA_HEADERS = (
    "Authorization: env:SLG_MCP_AUTHORIZATION, " +
    "Content-Type: application/json"
)
$env:MCP_MAX_CONCURRENT_REQUESTS = "1"
$env:MCP_CONNECTION_MAX_TTL = "5m"
$env:CONTROL_PLANE_MAX_INFLIGHT_REQUESTS = "1"
$env:HEALTH_LISTEN_ADDR = "127.0.0.1:8766"
$env:LOG_HTTP_RAW_UNSAFE = "false"
$env:OPEN_WEB_UI = "false"
$env:ALLOW_REMOTE_UI = "false"
$env:LOG_FORMAT = "json"
$env:LOG_LEVEL = "info"

$stdout = Join-Path $state "tunnel.stdout.log"
$stderr = Join-Path $state "tunnel.stderr.log"
$process = Start-Process -FilePath $tunnel `
    -ArgumentList @("run") `
    -WorkingDirectory $state `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -PassThru
$process.Id | Set-Content -LiteralPath (Join-Path $state "tunnel.pid") -NoNewline

try {
    $ready = $false
    foreach ($attempt in 1..20) {
        if ($process.HasExited) {
            throw "Secure MCP Tunnel client exited during startup."
        }
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:8766/readyz" `
                -UseBasicParsing `
                -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                $ready = $true
                break
            }
        } catch {
            Start-Sleep -Milliseconds 750
        }
    }
    if (-not $ready) {
        throw "Secure MCP Tunnel readiness timed out."
    }
    Assert-C0LoopbackListener -ProcessId $process.Id -Port 8766
} catch {
    Stop-C0Process -Name "tunnel" -AllowedExecutableNames @("tunnel-client.exe")
    throw
}

[pscustomobject]@{
    status = "started"
    pid = $process.Id
    transport = "secure_mcp_tunnel"
    local_mcp_endpoint = "http://127.0.0.1:8765/mcp"
    health_endpoint = "http://127.0.0.1:8766/readyz"
    raw_http_logging = $false
    remote_ui = $false
} | ConvertTo-Json
