[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
Assert-C0SecretEnvironment
$root = Get-C0RepositoryRoot
$state = Initialize-C0StateDirectory
if (
    $null -ne (Read-C0Pid -Name "facade") -or
    $null -ne (Read-C0Pid -Name "facade-launcher")
) {
    throw "C0 facade PID file already exists."
}
foreach ($name in @("SLG_AUDIT_ANCHOR_LOG", "SLG_AUDIT_ANCHOR_KEY")) {
    if ($null -ne [Environment]::GetEnvironmentVariable($name, "Process")) {
        throw "C0 refuses inherited audit-anchor configuration: $name."
    }
}

$existing = @(Get-NetTCPConnection -State Listen -LocalPort 8765 -ErrorAction SilentlyContinue)
if ($existing.Count -gt 0) {
    throw "Port 8765 already has a listener."
}

$env:SLG_MCP_ENABLED = "true"
$env:SLG_C0_ENABLED = "true"
$env:SLG_C0_SERVER_BUILD_COMMIT = Get-C0BuildCommit
$env:SLG_MCP_MAX_REQUEST_BYTES = "4096"
$env:SLG_MCP_REQUESTS_PER_MINUTE = "30"
$env:SLG_MCP_MAX_CONCURRENCY = "1"
$env:SLG_POLICY_FILE = Join-Path $root "policy.c0.yaml"
$env:SLG_WORKSPACE = $root
$env:SLG_AUDIT_LOG = Join-Path $state "audit.jsonl"
$env:SLG_REPLAY_DB = Join-Path $state "replay.sqlite3"
$env:SLG_APPROVAL_DB = Join-Path $state "approvals.sqlite3"
$env:SLG_SANDBOX_ROOT = Join-Path $state "sandboxes"

$python = Join-Path $root ".venv\Scripts\python.exe"
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
        throw "C0 facade health check timed out."
    }
    $listeners = @(
        Get-NetTCPConnection -State Listen -LocalPort 8765 `
            -ErrorAction SilentlyContinue
    )
    if (
        $listeners.Count -ne 1 -or
        $listeners[0].LocalAddress -ne "127.0.0.1"
    ) {
        throw "C0 facade did not create exactly one IPv4 loopback listener."
    }
    $runtimePid = $listeners[0].OwningProcess
    $runtimeProcess = Get-Process -Id $runtimePid -ErrorAction Stop
    if (
        [System.IO.Path]::GetFileName($runtimeProcess.Path) -ne "python.exe"
    ) {
        throw "C0 facade listener is not owned by python.exe."
    }
    $runtimeMetadata = Get-CimInstance Win32_Process -Filter (
        "ProcessId = $runtimePid"
    )
    if (
        $runtimePid -ne $process.Id -and
        $runtimeMetadata.ParentProcessId -ne $process.Id
    ) {
        throw "C0 facade listener is unrelated to the launched Python process."
    }
    $runtimePid | Set-Content -LiteralPath (
        Join-Path $state "facade.pid"
    ) -NoNewline
    if ($runtimePid -eq $process.Id) {
        Remove-Item -LiteralPath (
            Join-Path $state "facade-launcher.pid"
        ) -Force
    }
    Assert-C0LoopbackListener -ProcessId $runtimePid -Port 8765
} catch {
    Stop-C0Process -Name "facade" -AllowedExecutableNames @("python.exe")
    Stop-C0Process -Name "facade-launcher" -AllowedExecutableNames @("python.exe")
    throw
}

[pscustomobject]@{
    status = "started"
    pid = $runtimePid
    endpoint = "http://127.0.0.1:8765/mcp"
    build_commit = $env:SLG_C0_SERVER_BUILD_COMMIT
    policy = $env:SLG_POLICY_FILE
} | ConvertTo-Json
