[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9TrustedExecutionBoundary
Assert-C9GitState
Assert-C9SecretEnvironment
Assert-C9LocalAIEnvironment
[void](Assert-C9LocalAIRuntimeObservationEnvironment)
Assert-C9TunnelEnvironment
$root = Get-C9RepositoryRoot
$state = Initialize-C9StateDirectory
$decision = Get-C9AdmissionDecision
$facadePid = Read-C9Pid -Name "facade"
if ($null -eq $facadePid) {
    throw "Start the unadmitted C9 facade and complete local admission first."
}
Assert-C9LoopbackListener -ProcessId $facadePid -Port 8765
if ($null -ne (Read-C9Pid -Name "tunnel")) {
    throw "A C9 tunnel-client process record already exists."
}
$attemptPath = Assert-C9StateFile -Path (
    Join-Path $state "tunnel-attempt.json"
)
if (Test-Path -LiteralPath $attemptPath) {
    throw "C9 permits only one recorded Tunnel attempt per private cycle."
}
if (
    @(Get-NetTCPConnection -State Listen -LocalPort 8766 `
        -ErrorAction SilentlyContinue).Count -ne 0
) {
    throw "Port 8766 already has a listener."
}

$python = Get-C9Python
$probe = & $python -m systeme_local_gateway.mcp_smoke `
    --url "http://127.0.0.1:8765/mcp" `
    --timeout-seconds 10
if ($LASTEXITCODE -ne 0) {
    throw "C9 Tunnel preflight could not inspect the local MCP registry."
}
$probeJson = ($probe -join "`n") | ConvertFrom-Json
$tools = @($probeJson.tools)
if (
    $probeJson.status -ne "ok" -or
    $tools.Count -ne 1 -or
    $tools[0] -ne "systeme_local_attachment_handoff"
) {
    throw "C9 Tunnel preflight requires exactly the admitted handoff tool."
}

$tunnel = Assert-C9TunnelBinary
$tunnelAttempt = [pscustomobject]@{
    version = "1"
    status = "remote_transport_attempt_committed"
    cycle_id = $decision.cycle_id
    grant_id = $decision.grant_id
    attempted_at = [DateTime]::UtcNow.ToString("o")
    live_actions_allowed = $true
    effective_tool_count = 1
}
[void](Write-C9MetadataReceipt `
    -Path $attemptPath `
    -Receipt $tunnelAttempt)
$tunnelAttempt = $null

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
$env:MCP_CONNECTION_MAX_TTL = "20m"
$env:CONTROL_PLANE_MAX_INFLIGHT_REQUESTS = "1"
$env:HEALTH_LISTEN_ADDR = "127.0.0.1:8766"
$env:LOG_HTTP_RAW_UNSAFE = "false"
$env:OPEN_WEB_UI = "false"
$env:ALLOW_REMOTE_UI = "false"
$env:LOG_FORMAT = "json"
$env:LOG_LEVEL = "info"

$stdout = Assert-C9StateFile -Path (Join-Path $state "tunnel.stdout.log")
$stderr = Assert-C9StateFile -Path (Join-Path $state "tunnel.stderr.log")
$childEnvironmentAllowlist = @(
    "ALLOW_REMOTE_UI",
    "APPDATA",
    "COMSPEC",
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_MAX_INFLIGHT_REQUESTS",
    "CONTROL_PLANE_TUNNEL_ID",
    "HEALTH_LISTEN_ADDR",
    "LOCALAPPDATA",
    "LOG_FORMAT",
    "LOG_HTTP_RAW_UNSAFE",
    "LOG_LEVEL",
    "MCP_CONNECTION_MAX_TTL",
    "MCP_DISCOVERY_EXTRA_HEADERS",
    "MCP_EXTRA_HEADERS",
    "MCP_MAX_CONCURRENT_REQUESTS",
    "MCP_SERVER_URL",
    "OPEN_WEB_UI",
    "PATH",
    "PATHEXT",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "SLG_MCP_AUTHORIZATION",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "WINDIR"
)
$removedChildEnvironment = @{}
try {
    $processEnvironment = [Environment]::GetEnvironmentVariables("Process")
    foreach ($name in @($processEnvironment.Keys)) {
        if ([string]$name -notin $childEnvironmentAllowlist) {
            $removedChildEnvironment[[string]$name] = [string]$processEnvironment[$name]
            [Environment]::SetEnvironmentVariable(
                [string]$name,
                $null,
                "Process"
            )
        }
    }
    Assert-C9TrustedExecutionBoundary
    $process = Start-Process -FilePath $tunnel `
        -ArgumentList @("run") `
        -WorkingDirectory $state `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru
} finally {
    foreach ($name in $removedChildEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable(
            [string]$name,
            [string]$removedChildEnvironment[$name],
            "Process"
        )
    }
    $removedChildEnvironment.Clear()
}
Write-C9ProcessRecord -Name "tunnel" -Process $process

try {
    $ready = $false
    foreach ($attempt in 1..20) {
        if ($process.HasExited) {
            throw "Secure MCP Tunnel client exited during C9 startup."
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
        throw "Secure MCP Tunnel C9 readiness timed out."
    }
    Assert-C9LoopbackListener -ProcessId $process.Id -Port 8766
} catch {
    Stop-C9Process -Name "tunnel" -AllowedExecutablePaths @($tunnel)
    throw
}

[pscustomobject]@{
    status = "started"
    pid = $process.Id
    transport = "secure_mcp_tunnel"
    local_mcp_endpoint = "http://127.0.0.1:8765/mcp"
    health_endpoint = "http://127.0.0.1:8766/readyz"
    cycle_id = $decision.cycle_id
    grant_id = $decision.grant_id
    effective_tool_count = 1
    raw_http_logging = $false
    remote_ui = $false
    connection_ttl = "20m"
} | ConvertTo-Json
