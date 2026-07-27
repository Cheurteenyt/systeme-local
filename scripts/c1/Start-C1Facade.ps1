[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "..\c3\C3.Common.psm1") -Force
Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C3ProtectedActionAllowed -Action "browser_test"
Assert-C1GitState
Assert-C1SecretEnvironment
$root = Get-C1RepositoryRoot
$state = Initialize-C1StateDirectory
if (
    $null -ne (Read-C1Pid -Name "facade") -or
    $null -ne (Read-C1Pid -Name "facade-launcher")
) {
    throw "C1 facade PID file already exists."
}
foreach ($name in @("SLG_AUDIT_ANCHOR_LOG", "SLG_AUDIT_ANCHOR_KEY")) {
    if ($null -ne [Environment]::GetEnvironmentVariable($name, "Process")) {
        throw "C1 refuses inherited audit-anchor configuration: $name."
    }
}
if (@(Get-NetTCPConnection -State Listen -LocalPort 8765 -ErrorAction SilentlyContinue).Count) {
    throw "Port 8765 already has a listener."
}

$env:SLG_MCP_ENABLED = "true"
$env:SLG_C0_ENABLED = "true"
$env:SLG_C0_SERVER_BUILD_COMMIT = Get-C1BuildCommit
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
        throw "C1 facade health check timed out."
    }
    $listeners = @(
        Get-NetTCPConnection -State Listen -LocalPort 8765 `
            -ErrorAction SilentlyContinue
    )
    if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -ne "127.0.0.1") {
        throw "C1 facade did not create exactly one IPv4 loopback listener."
    }
    $runtimePid = $listeners[0].OwningProcess
    $runtime = Get-Process -Id $runtimePid -ErrorAction Stop
    if ([System.IO.Path]::GetFileName($runtime.Path) -ne "python.exe") {
        throw "C1 facade listener is not owned by python.exe."
    }
    $metadata = Get-CimInstance Win32_Process -Filter "ProcessId = $runtimePid"
    if (
        $runtimePid -ne $process.Id -and
        $metadata.ParentProcessId -ne $process.Id
    ) {
        throw "C1 facade listener is unrelated to the launched Python process."
    }
    $runtimePid | Set-Content -LiteralPath (
        Join-Path $state "facade.pid"
    ) -NoNewline
    if ($runtimePid -eq $process.Id) {
        Remove-Item -LiteralPath (
            Join-Path $state "facade-launcher.pid"
        ) -Force
    }
    Assert-C1LoopbackListener -ProcessId $runtimePid -Port 8765
} catch {
    Stop-C1Process -Name "facade" -AllowedExecutableNames @("python.exe")
    Stop-C1PythonLauncher
    throw
}

[pscustomobject]@{
    status = "started"
    pid = $runtimePid
    endpoint = "http://127.0.0.1:8765/mcp"
    build_commit = $env:SLG_C0_SERVER_BUILD_COMMIT
    policy = $env:SLG_POLICY_FILE
    c1_scope = "two sterile Chat tests only"
} | ConvertTo-Json
