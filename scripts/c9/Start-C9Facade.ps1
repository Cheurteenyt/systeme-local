[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9FacadeLaunchEnvironment
Assert-C9TrustedExecutionBoundary
Assert-C9GitState
Assert-C9SecretEnvironment
Assert-C9LocalAIEnvironment
[void](Assert-C9LocalAIRuntimeObservationEnvironment)
$root = Get-C9RepositoryRoot
$git = Get-C9GitExecutable
[Environment]::SetEnvironmentVariable(
    "SLG_C9_GIT_EXECUTABLE",
    $git,
    "Process"
)
$state = Initialize-C9StateDirectory
$python = Get-C9Python
$admissionPath = Assert-C9StateFile -Path (Join-Path $state "admission.json")
if (Test-Path -LiteralPath $admissionPath) {
    throw "C9 facade startup requires zero admission and zero effective tools."
}
if (Test-Path -LiteralPath (Join-Path $state "tunnel-attempt.json")) {
    throw "C9 facade startup refuses a state directory used for a Tunnel attempt."
}
if (
    $null -ne (Read-C9Pid -Name "facade") -or
    $null -ne (Read-C9Pid -Name "facade-launcher") -or
    $null -ne (Read-C9Pid -Name "tunnel")
) {
    throw "A tracked C9 process record already exists."
}
foreach ($name in @(
    "SLG_AUDIT_ANCHOR_LOG",
    "SLG_AUDIT_ANCHOR_KEY"
)) {
    if ($null -ne [Environment]::GetEnvironmentVariable($name, "Process")) {
        throw "C9 refuses inherited audit-anchor configuration."
    }
}
if (
    @(Get-NetTCPConnection -State Listen -LocalPort 8765 `
        -ErrorAction SilentlyContinue).Count -ne 0
) {
    throw "Port 8765 already has a listener."
}

$env:SLG_MCP_ENABLED = "true"
$env:SLG_C0_ENABLED = "false"
Remove-Item Env:SLG_C0_SERVER_BUILD_COMMIT -ErrorAction SilentlyContinue
$env:SLG_PROVIDER_RUNTIME_MODE = "chatgpt_web_c9"
$env:SLG_PROVIDER_RUNTIME_ROOT = $root
$env:SLG_C9_SERVER_BUILD_COMMIT = Get-C9BuildCommit
$env:SLG_C9_STATE_DIRECTORY = $state
$env:SLG_C9_ADMISSION_FILE = $admissionPath
$env:SLG_MCP_MAX_REQUEST_BYTES = "4096"
$env:SLG_MCP_REQUESTS_PER_MINUTE = "30"
$env:SLG_MCP_MAX_CONCURRENCY = "1"
$env:SLG_MCP_MAX_RENDERED_RESPONSE_BYTES = "8388608"
$env:SLG_POLICY_FILE = Join-Path $root "policy.c9.yaml"
$env:SLG_WORKSPACE = $root
$env:SLG_AUDIT_LOG = Join-Path $state "audit.jsonl"
$env:SLG_REPLAY_DB = Join-Path $state "replay.sqlite3"
$env:SLG_APPROVAL_DB = Join-Path $state "approvals.sqlite3"
$env:SLG_SANDBOX_ROOT = Join-Path $state "sandboxes"

$stdout = Assert-C9StateFile -Path (Join-Path $state "facade.stdout.log")
$stderr = Assert-C9StateFile -Path (Join-Path $state "facade.stderr.log")
$childEnvironmentAllowlist = @(
    "COMSPEC",
    "NUMBER_OF_PROCESSORS",
    "PATH",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
    "SLG_SHARED_SECRET",
    "SLG_AUDIT_KEY",
    "SLG_MCP_TOKEN",
    "SLG_C9_CONTROL_TOKEN",
    "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE",
    "SLG_C9_LOCAL_AI_ENDPOINT",
    "SLG_C9_LOCAL_AI_MODEL",
    "SLG_C9_GIT_EXECUTABLE",
    "SLG_MCP_ENABLED",
    "SLG_C0_ENABLED",
    "SLG_PROVIDER_RUNTIME_MODE",
    "SLG_PROVIDER_RUNTIME_ROOT",
    "SLG_C9_SERVER_BUILD_COMMIT",
    "SLG_C9_STATE_DIRECTORY",
    "SLG_C9_ADMISSION_FILE",
    "SLG_MCP_MAX_REQUEST_BYTES",
    "SLG_MCP_REQUESTS_PER_MINUTE",
    "SLG_MCP_MAX_CONCURRENCY",
    "SLG_MCP_MAX_RENDERED_RESPONSE_BYTES",
    "SLG_POLICY_FILE",
    "SLG_WORKSPACE",
    "SLG_AUDIT_LOG",
    "SLG_REPLAY_DB",
    "SLG_APPROVAL_DB",
    "SLG_SANDBOX_ROOT"
)
$gitDirectory = [System.IO.Path]::GetDirectoryName($git)
$system32 = [System.IO.Path]::GetFullPath(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
)
$windowsRoot = [System.IO.Path]::GetDirectoryName($system32)
if (
    -not (Test-Path -LiteralPath $gitDirectory -PathType Container) -or
    -not (Test-Path -LiteralPath $system32 -PathType Container) -or
    -not ([System.IO.Path]::GetFullPath($env:SystemRoot)).Equals(
        $windowsRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    )
) {
    throw "C9 cannot construct its minimal trusted child PATH."
}
Assert-C9NotReparsePoint -Path $gitDirectory
Assert-C9NotReparsePoint -Path $system32
$minimalChildPath = $gitDirectory +
    [System.IO.Path]::PathSeparator +
    $system32
$parentPath = [Environment]::GetEnvironmentVariable("PATH", "Process")
try {
    [Environment]::SetEnvironmentVariable(
        "PATH",
        $minimalChildPath,
        "Process"
    )
    $process = Invoke-C9MinimalChildEnvironment `
        -AllowedNames $childEnvironmentAllowlist `
        -ScriptBlock {
            Assert-C9TrustedExecutionBoundary
            Start-Process -FilePath $python `
                -ArgumentList @(
                    "-I",
                    "-X",
                    "utf8",
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
        }
} finally {
    [Environment]::SetEnvironmentVariable(
        "PATH",
        $parentPath,
        "Process"
    )
    $minimalChildPath = $null
    $parentPath = $null
}
Write-C9ProcessRecord -Name "facade-launcher" -Process $process

try {
    $healthy = $false
    foreach ($attempt in 1..15) {
        if ($process.HasExited) {
            throw "C9 facade exited during startup."
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
        throw "C9 facade health check timed out."
    }

    $listeners = @(
        Get-NetTCPConnection -State Listen -LocalPort 8765 `
            -ErrorAction SilentlyContinue
    )
    if (
        $listeners.Count -ne 1 -or
        $listeners[0].LocalAddress -ne "127.0.0.1"
    ) {
        throw "C9 facade did not create exactly one IPv4 loopback listener."
    }
    $runtimePid = $listeners[0].OwningProcess
    $runtime = Get-Process -Id $runtimePid -ErrorAction Stop
    if (
        [System.IO.Path]::GetFullPath($runtime.Path) -ne
        [System.IO.Path]::GetFullPath($python)
    ) {
        throw "C9 facade listener is not owned by the repository Python runtime."
    }
    $metadata = Get-CimInstance Win32_Process -Filter "ProcessId = $runtimePid"
    if ($runtimePid -ne $process.Id -and $metadata.ParentProcessId -ne $process.Id) {
        throw "C9 facade listener is unrelated to the launched Python process."
    }
    Write-C9ProcessRecord -Name "facade" -Process $runtime
    if ($runtimePid -eq $process.Id) {
        $launcher = Read-C9ProcessRecord -Name "facade-launcher"
        Remove-Item -LiteralPath $launcher.path -Force
    }
    Assert-C9LoopbackListener -ProcessId $runtimePid -Port 8765

    $probe = & $python -m systeme_local_gateway.mcp_smoke `
        --url "http://127.0.0.1:8765/mcp" `
        --timeout-seconds 10
    if ($LASTEXITCODE -ne 0) {
        throw "C9 pre-admission MCP probe failed."
    }
    $probeJson = ($probe -join "`n") | ConvertFrom-Json
    if ($probeJson.status -ne "ok" -or @($probeJson.tools).Count -ne 0) {
        throw "C9 facade did not start with the required zero-tool registry."
    }
} catch {
    Stop-C9Process -Name "facade" -AllowedExecutablePaths @($python)
    Stop-C9PythonLauncher
    throw
}

[pscustomobject]@{
    status = "started_unadmitted"
    pid = $runtimePid
    endpoint = "http://127.0.0.1:8765/mcp"
    build_commit = $env:SLG_C9_SERVER_BUILD_COMMIT
    provider_runtime_mode = "chatgpt_web_c9"
    live_cycle_admitted = $false
    effective_tool_count = 0
    c0_enabled = $false
} | ConvertTo-Json
