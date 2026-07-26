[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
Assert-C0SecretEnvironment
$root = Get-C0RepositoryRoot
$state = Initialize-C0StateDirectory
if ($null -ne (Read-C0Pid -Name "facade")) {
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
$process.Id | Set-Content -LiteralPath (Join-Path $state "facade.pid") -NoNewline

try {
    $healthy = $false
    foreach ($attempt in 1..15) {
        if ($process.HasExited) {
            throw "C0 facade exited during startup."
        }
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
    Assert-C0LoopbackListener -ProcessId $process.Id -Port 8765
} catch {
    Stop-C0Process -Name "facade" -AllowedExecutableNames @("python.exe")
    throw
}

[pscustomobject]@{
    status = "started"
    pid = $process.Id
    endpoint = "http://127.0.0.1:8765/mcp"
    build_commit = $env:SLG_C0_SERVER_BUILD_COMMIT
    policy = $env:SLG_POLICY_FILE
} | ConvertTo-Json
