Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:C8Branch = "codex/chatgpt-work-live-c8"
$script:C8AcceptedC7Commit = "e0a1dccfa13c95a1ce077d2b6f9ef4f1ed70231f"
$script:C8Port = 8765
$script:C8HealthPort = 8766

function Get-C8RepositoryRoot {
    return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
}

function Get-C8StateDirectory {
    $root = Get-C8RepositoryRoot
    $state = [System.IO.Path]::GetFullPath((Join-Path $root ".systeme-local\c8"))
    $prefix = [System.IO.Path]::GetFullPath((Join-Path $root ".systeme-local")) +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $state.StartsWith(
        $prefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "C8 state directory escaped the repository-private state root."
    }
    return $state
}

function Initialize-C8StateDirectory {
    $state = Get-C8StateDirectory
    if (-not (Test-Path -LiteralPath $state -PathType Container)) {
        New-Item -ItemType Directory -Path $state | Out-Null
    }
    return $state
}

function Assert-C8GitState {
    param([switch]$AllowDirty)

    $root = Get-C8RepositoryRoot
    $branch = (& git -C $root branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne $script:C8Branch) {
        throw "C8 protected runtime requires branch $script:C8Branch; observed '$branch'."
    }
    & git -C $root merge-base --is-ancestor $script:C8AcceptedC7Commit HEAD
    if ($LASTEXITCODE -ne 0) {
        throw "C8 protected runtime does not descend from accepted C7."
    }
    if (-not $AllowDirty) {
        $dirty = @(& git -C $root status --porcelain)
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to inspect the C8 worktree."
        }
        if ($dirty.Count -gt 0) {
            throw "C8 protected runtime requires a clean worktree."
        }
    }
}

function Get-C8BuildCommit {
    $commit = (& git -C (Get-C8RepositoryRoot) rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch "^[0-9a-f]{40}$") {
        throw "Unable to resolve a full lowercase C8 build commit."
    }
    return $commit
}

function Assert-C8SecretEnvironment {
    $values = @{}
    foreach ($name in @("SLG_SHARED_SECRET", "SLG_AUDIT_KEY", "SLG_MCP_TOKEN")) {
        $value = [Environment]::GetEnvironmentVariable($name, "Process")
        if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -lt 32) {
            throw "$name must be a process-local random value of at least 32 characters."
        }
        $values[$name] = $value
    }
    if (
        $values["SLG_SHARED_SECRET"] -eq $values["SLG_AUDIT_KEY"] -or
        $values["SLG_SHARED_SECRET"] -eq $values["SLG_MCP_TOKEN"] -or
        $values["SLG_AUDIT_KEY"] -eq $values["SLG_MCP_TOKEN"]
    ) {
        throw "C8 secrets must be pairwise independent."
    }
}

function Assert-C8AuditKeyEnvironment {
    $value = [Environment]::GetEnvironmentVariable("SLG_AUDIT_KEY", "Process")
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -lt 32) {
        throw "SLG_AUDIT_KEY must remain available through C8 final attestation."
    }
}

function Assert-C8TunnelEnvironment {
    $tunnelId = [Environment]::GetEnvironmentVariable(
        "CONTROL_PLANE_TUNNEL_ID",
        "Process"
    )
    if ($tunnelId -notmatch "^tunnel_[0-9a-f]{32}$") {
        throw "CONTROL_PLANE_TUNNEL_ID has an invalid format."
    }
    $apiKey = [Environment]::GetEnvironmentVariable(
        "CONTROL_PLANE_API_KEY",
        "Process"
    )
    if ([string]::IsNullOrWhiteSpace($apiKey) -or $apiKey.Length -lt 20) {
        throw "CONTROL_PLANE_API_KEY is missing from the process environment."
    }
}

function Assert-C8TunnelBinary {
    $root = Get-C8RepositoryRoot
    $manifest = Get-Content -LiteralPath (
        Join-Path $root "governance\c0-tunnel-client.json"
    ) -Raw | ConvertFrom-Json
    $binary = Join-Path $root ".systeme-local\c0\bin\tunnel-client.exe"
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "The verified C0 tunnel-client binary is unavailable."
    }
    $actual = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $manifest.binary_sha256) {
        throw "Installed tunnel-client binary integrity check failed."
    }
    return $binary
}

function Assert-C8StateFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolved = [System.IO.Path]::GetFullPath($Path)
    $prefix = [System.IO.Path]::GetFullPath((Get-C8StateDirectory)) +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith(
        $prefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "C8 evidence paths must remain inside the ignored C8 state directory."
    }
    return $resolved
}

function Get-C8LiveCycle {
    $path = Join-Path (Get-C8StateDirectory) "live-cycle.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "C8 live-cycle grant is missing."
    }
    $cycle = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if (
        $cycle.version -ne "1" -or
        $cycle.authorization.cycle_id -notmatch "^c8_cycle_[0-9a-f]{32}$" -or
        $cycle.grant.grant_id -notmatch "^c8_[0-9a-f]{32}$"
    ) {
        throw "C8 live-cycle grant has an invalid shape."
    }
    return $cycle
}

function Assert-C8LoopbackListener {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $matching = @(
        Get-NetTCPConnection -State Listen -OwningProcess $ProcessId `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -eq $Port }
    )
    if ($matching.Count -ne 1) {
        throw "Expected exactly one C8 listener for PID $ProcessId on port $Port."
    }
    if ($matching[0].LocalAddress -notin @("127.0.0.1", "::1")) {
        throw "C8 listener is not bound to loopback."
    }
}

function Read-C8Pid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $path = Join-Path (Get-C8StateDirectory) "$Name.pid"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return $null
    }
    $raw = (Get-Content -LiteralPath $path -Raw).Trim()
    $parsed = 0
    if (-not [int]::TryParse($raw, [ref]$parsed) -or $parsed -lt 1) {
        throw "Invalid C8 PID file: $path"
    }
    return $parsed
}

function Stop-C8Process {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$AllowedExecutableNames
    )

    $pidPath = Join-Path (Get-C8StateDirectory) "$Name.pid"
    $processId = Read-C8Pid -Name $Name
    if ($null -eq $processId) {
        return
    }
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($null -ne $process) {
        $actual = [System.IO.Path]::GetFileName($process.Path)
        if ($actual -notin $AllowedExecutableNames) {
            throw "Refusing to stop unexpected executable '$actual' for C8 $Name."
        }
        Stop-Process -Id $processId
        Wait-Process -Id $processId -Timeout 15 -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue
}

function Stop-C8PythonLauncher {
    $processId = Read-C8Pid -Name "facade-launcher"
    if ($null -eq $processId) {
        return
    }
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        Remove-Item -LiteralPath (
            Join-Path (Get-C8StateDirectory) "facade-launcher.pid"
        ) -Force -ErrorAction SilentlyContinue
        return
    }
    Wait-Process -Id $processId -Timeout 5 -ErrorAction SilentlyContinue
    if ($null -ne (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
        Stop-C8Process -Name "facade-launcher" -AllowedExecutableNames @("python.exe")
    }
}

function ConvertFrom-C8Utf8Base64 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    try {
        $bytes = [Convert]::FromBase64String($Value)
    } catch {
        throw "$FieldName must use canonical UTF-8 Base64."
    }
    if ([Convert]::ToBase64String($bytes) -cne $Value) {
        throw "$FieldName must use canonical UTF-8 Base64."
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    try {
        return $utf8.GetString($bytes)
    } catch {
        throw "$FieldName Base64 payload must contain valid UTF-8."
    }
}

Export-ModuleMember -Function @(
    "Assert-C8AuditKeyEnvironment",
    "Assert-C8GitState",
    "Assert-C8LoopbackListener",
    "Assert-C8SecretEnvironment",
    "Assert-C8StateFile",
    "Assert-C8TunnelBinary",
    "Assert-C8TunnelEnvironment",
    "ConvertFrom-C8Utf8Base64",
    "Get-C8BuildCommit",
    "Get-C8LiveCycle",
    "Get-C8RepositoryRoot",
    "Get-C8StateDirectory",
    "Initialize-C8StateDirectory",
    "Read-C8Pid",
    "Stop-C8Process",
    "Stop-C8PythonLauncher"
)
