[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

Assert-C8GitState
Assert-C8SecretEnvironment
$root = Get-C8RepositoryRoot
$state = Initialize-C8StateDirectory
$liveCyclePath = Join-Path $state "live-cycle.json"
$python = Join-Path $root ".venv\Scripts\python.exe"
$admission = & $python -m systeme_local_gateway.c8_live_cycle verify-bundle `
    --bundle $liveCyclePath
if ($LASTEXITCODE -ne 0) {
    throw "C8 facade startup refused an invalid or stale live-cycle grant."
}
$decision = ($admission -join "`n") | ConvertFrom-Json
if (
    $decision.live_actions_allowed -ne $true -or
    $decision.effective_tool_count -ne 1
) {
    throw "C8 facade startup did not preserve the exact one-tool boundary."
}
if (
    $null -ne (Read-C8Pid -Name "facade") -or
    $null -ne (Read-C8Pid -Name "facade-launcher")
) {
    throw "C8 facade PID file already exists."
}
foreach ($name in @(
    "SLG_AUDIT_ANCHOR_LOG",
    "SLG_AUDIT_ANCHOR_KEY"
)) {
    if ($null -ne [Environment]::GetEnvironmentVariable($name, "Process")) {
        throw "C8 refuses inherited audit-anchor configuration: $name."
    }
}
if (@(Get-NetTCPConnection -State Listen -LocalPort 8765 -ErrorAction SilentlyContinue).Count) {
    throw "Port 8765 already has a listener."
}

$env:SLG_MCP_ENABLED = "true"
$env:SLG_C0_ENABLED = "true"
$env:SLG_C0_SERVER_BUILD_COMMIT = Get-C8BuildCommit
$env:SLG_PROVIDER_RUNTIME_MODE = "chatgpt_work_c8"
$env:SLG_PROVIDER_RUNTIME_ROOT = $root
$env:SLG_C8_LIVE_CYCLE_FILE = $liveCyclePath
$env:SLG_MCP_MAX_REQUEST_BYTES = "4096"
$env:SLG_MCP_REQUESTS_PER_MINUTE = "30"
$env:SLG_MCP_MAX_CONCURRENCY = "1"
$env:SLG_POLICY_FILE = Join-Path $root "policy.c0.yaml"
$env:SLG_WORKSPACE = $root
$env:SLG_AUDIT_LOG = Join-Path $state "audit.jsonl"
$env:SLG_REPLAY_DB = Join-Path $state "replay.sqlite3"
$env:SLG_APPROVAL_DB = Join-Path $state "approvals.sqlite3"
$env:SLG_SANDBOX_ROOT = Join-Path $state "sandboxes"

$stdout = Join-Path $state "facade.stdout.log"
$stderr = Join-Path $state "facade.stderr.log"
$process = Start-Process -FilePath $python `
    -ArgumentList @(
        "-m",
        "uvicorn",
        "systeme_local_gateway.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8765",
        "--no-access-log"
    ) `
    -WorkingDirectory $state `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -PassThru
$process.Id | Set-Content -LiteralPath (
    Join-Path $state "facade-launcher.pid"
) -NoNewline

try {
    $healthy = $false
    foreach ($attempt in 1..15) {
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:8765/health" `
                -TimeoutSec 2
            if ($health.status -eq "ok") {
                $healthy = $true
                break
            }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $healthy) {
        throw "C8 facade health check timed out."
    }
    $listeners = @(
        Get-NetTCPConnection -State Listen -LocalPort 8765 `
            -ErrorAction SilentlyContinue
    )
    if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -ne "127.0.0.1") {
        throw "C8 facade did not create exactly one IPv4 loopback listener."
    }
    $runtimePid = $listeners[0].OwningProcess
    $runtime = Get-Process -Id $runtimePid -ErrorAction Stop
    if ([System.IO.Path]::GetFileName($runtime.Path) -ne "python.exe") {
        throw "C8 facade listener is not owned by python.exe."
    }
    $metadata = Get-CimInstance Win32_Process -Filter "ProcessId = $runtimePid"
    if ($runtimePid -ne $process.Id -and $metadata.ParentProcessId -ne $process.Id) {
        throw "C8 facade listener is unrelated to the launched Python process."
    }
    $runtimePid | Set-Content -LiteralPath (
        Join-Path $state "facade.pid"
    ) -NoNewline
    if ($runtimePid -eq $process.Id) {
        Remove-Item -LiteralPath (
            Join-Path $state "facade-launcher.pid"
        ) -Force
    }
    Assert-C8LoopbackListener -ProcessId $runtimePid -Port 8765
} catch {
    Stop-C8Process -Name "facade" -AllowedExecutableNames @("python.exe")
    Stop-C8PythonLauncher
    throw
}

[pscustomobject]@{
    status = "started"
    pid = $runtimePid
    endpoint = "http://127.0.0.1:8765/mcp"
    build_commit = $env:SLG_C0_SERVER_BUILD_COMMIT
    provider_runtime_mode = "chatgpt_work_c8"
    cycle_id = $decision.cycle_id
    grant_id = $decision.grant_id
    effective_tool_count = 1
} | ConvertTo-Json
