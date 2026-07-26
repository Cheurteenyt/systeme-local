[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
Assert-C0SecretEnvironment
$root = Get-C0RepositoryRoot
$state = Get-C0StateDirectory
$facadePid = Read-C0Pid -Name "facade"
if ($null -eq $facadePid) {
    throw "Start the C0 facade before the local tunnel-client test."
}
Assert-C0LoopbackListener -ProcessId $facadePid -Port 8765
foreach ($name in @("CONTROL_PLANE_TUNNEL_ID", "CONTROL_PLANE_API_KEY")) {
    if ($null -ne [Environment]::GetEnvironmentVariable($name, "Process")) {
        throw "Local tunnel-client test refuses hosted control-plane credentials."
    }
}

$challengePath = Join-Path $state "challenge.txt"
if (-not (Test-Path -LiteralPath $challengePath -PathType Leaf)) {
    throw "Generate a fresh C0 challenge before the local tunnel-client test."
}
if (
    $null -ne (Read-C0Pid -Name "tunnel-local") -or
    $null -ne (Read-C0Pid -Name "tunnel")
) {
    throw "Another C0 tunnel-client PID file already exists."
}

$tunnel = Assert-C0TunnelBinary
$urlFile = Join-Path $state "tunnel-local.json"
$healthFile = Join-Path $state "tunnel-local-health.txt"
$stdout = Join-Path $state "tunnel-local.stdout.log"
$stderr = Join-Path $state "tunnel-local.stderr.log"
foreach ($path in @($urlFile, $healthFile, $stdout, $stderr)) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}

$env:MCP_EXTRA_HEADERS = "Authorization: env:SLG_MCP_TOKEN"
$env:MCP_DISCOVERY_EXTRA_HEADERS = "Authorization: env:SLG_MCP_TOKEN"
$env:MCP_MAX_CONCURRENT_REQUESTS = "1"
$env:MCP_CONNECTION_MAX_TTL = "5m"
$env:LOG_HTTP_RAW_UNSAFE = "false"
$env:OPEN_WEB_UI = "false"
$env:ALLOW_REMOTE_UI = "false"
$env:LOG_FORMAT = "json"
$env:LOG_LEVEL = "info"

$process = Start-Process -FilePath $tunnel `
    -ArgumentList @(
        "dev",
        "proxy",
        "--backend",
        "go",
        "--duration",
        "60s",
        "--listen",
        "127.0.0.1:0",
        "--url-file",
        $urlFile,
        "--health-url-file",
        $healthFile,
        "--mcp-server-url",
        "channel=main,url=http://127.0.0.1:8765/mcp"
    ) `
    -WorkingDirectory $state `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -PassThru
$process.Id | Set-Content -LiteralPath (
    Join-Path $state "tunnel-local.pid"
) -NoNewline

try {
    $ready = $false
    foreach ($attempt in 1..30) {
        if (Test-Path -LiteralPath $urlFile -PathType Leaf) {
            $ready = $true
            break
        }
        if ($process.HasExited) {
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        throw "Official tunnel-client local proxy readiness timed out."
    }

    $info = Get-Content -LiteralPath $urlFile -Raw | ConvertFrom-Json
    if (
        $info.tunnel_id -ne "tunnel_22222222222222222222222222222222" -or
        $info.mcp_url -notmatch "^http://127\.0\.0\.1:[0-9]+/mcp$" -or
        $info.control_plane_base_url -notmatch "^http://127\.0\.0\.1:[0-9]+$" -or
        $info.backend -ne "go-in-memory"
    ) {
        throw "Official tunnel-client local proxy returned unexpected routing metadata."
    }

    $mcpUri = [Uri]$info.mcp_url
    Assert-C0LoopbackListener -ProcessId $process.Id -Port $mcpUri.Port
    if (-not [string]::IsNullOrWhiteSpace($info.health_url)) {
        $healthUri = [Uri]$info.health_url
        Assert-C0LoopbackListener -ProcessId $process.Id -Port $healthUri.Port
    }

    $env:SLG_C0_CHALLENGE = (
        Get-Content -LiteralPath $challengePath -Raw
    ).Trim()
    $python = Join-Path $root ".venv\Scripts\python.exe"
    $result = & $python -m systeme_local_gateway.c0_smoke `
        --url $info.mcp_url
    if ($LASTEXITCODE -ne 0) {
        throw "C0 probe through official tunnel-client local proxy failed."
    }
    $response = ($result -join "`n") | ConvertFrom-Json
    if (
        $response.status -ne "ok" -or
        @($response.tools).Count -ne 1 -or
        $response.tools[0] -ne "systeme_local_connectivity_probe"
    ) {
        throw "Local tunnel-client result violated the one-tool invariant."
    }
    $result -join "`n" | Set-Content -LiteralPath (
        Join-Path $state "tunnel-local-response.json"
    )
} finally {
    Remove-Item Env:SLG_C0_CHALLENGE -ErrorAction SilentlyContinue
    Stop-C0Process -Name "tunnel-local" `
        -AllowedExecutableNames @("tunnel-client.exe")
    foreach ($name in @(
        "MCP_EXTRA_HEADERS",
        "MCP_DISCOVERY_EXTRA_HEADERS",
        "MCP_MAX_CONCURRENT_REQUESTS",
        "MCP_CONNECTION_MAX_TTL",
        "LOG_HTTP_RAW_UNSAFE",
        "OPEN_WEB_UI",
        "ALLOW_REMOTE_UI",
        "LOG_FORMAT",
        "LOG_LEVEL"
    )) {
        Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    }
}

[pscustomobject]@{
    status = "verified"
    transport = "official_tunnel_client_dev_proxy"
    backend = $info.backend
    loopback_ingress = $info.mcp_url
    tool_count = 1
    write_tool_count = 0
    high_risk_tool_count = 0
    real_chatgpt_web = $false
} | ConvertTo-Json
