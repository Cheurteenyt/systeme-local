Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:C0ExpectedBranch = "interop/chatgpt-web-mcp-connectivity-c0"
$script:C0ToolName = "systeme_local_connectivity_probe"
$script:C0Port = 8765
$script:C0HealthPort = 8766

function Get-C0RepositoryRoot {
    $root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")
    return $root.Path
}

function Get-C0StateDirectory {
    $root = Get-C0RepositoryRoot
    $state = [System.IO.Path]::GetFullPath(
        (Join-Path $root ".systeme-local\c0")
    )
    $requiredPrefix = [System.IO.Path]::GetFullPath(
        (Join-Path $root ".systeme-local")
    ) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $state.StartsWith(
        $requiredPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "C0 state directory escaped the repository-private state root."
    }
    return $state
}

function Initialize-C0StateDirectory {
    $state = Get-C0StateDirectory
    if (-not (Test-Path -LiteralPath $state -PathType Container)) {
        New-Item -ItemType Directory -Path $state | Out-Null
    }
    return $state
}

function Assert-C0GitState {
    param(
        [switch]$AllowDirty
    )

    $root = Get-C0RepositoryRoot
    $branch = (& git -C $root branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne $script:C0ExpectedBranch) {
        throw "C0 requires branch $script:C0ExpectedBranch; observed '$branch'."
    }
    if (-not $AllowDirty) {
        $dirty = & git -C $root status --porcelain
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to inspect Git worktree state."
        }
        if ($null -ne $dirty -and @($dirty).Count -gt 0) {
            throw "C0 runtime requires a clean worktree."
        }
    }
}

function Get-C0BuildCommit {
    $root = Get-C0RepositoryRoot
    $commit = (& git -C $root rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch "^[0-9a-f]{40}$") {
        throw "Unable to resolve a full lowercase Git build commit."
    }
    return $commit
}

function Assert-C0SecretEnvironment {
    $names = @(
        "SLG_SHARED_SECRET",
        "SLG_AUDIT_KEY",
        "SLG_MCP_TOKEN"
    )
    $values = @{}
    foreach ($name in $names) {
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
        throw "C0 secrets must be pairwise independent."
    }
}

function Assert-C0TunnelEnvironment {
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

function Assert-C0TunnelBinary {
    $root = Get-C0RepositoryRoot
    $state = Get-C0StateDirectory
    $manifest = Get-Content -LiteralPath (
        Join-Path $root "governance\c0-tunnel-client.json"
    ) -Raw | ConvertFrom-Json
    $binary = Join-Path $state "bin\tunnel-client.exe"
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "Verified tunnel-client binary is unavailable."
    }
    $actual = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $manifest.binary_sha256) {
        throw "Installed tunnel-client binary integrity check failed."
    }
    return $binary
}

function Assert-C0LoopbackListener {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId,
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $listeners = @(
        Get-NetTCPConnection -State Listen -OwningProcess $ProcessId `
            -ErrorAction SilentlyContinue
    )
    $matching = @($listeners | Where-Object { $_.LocalPort -eq $Port })
    if ($matching.Count -ne 1) {
        throw "Expected exactly one listener for PID $ProcessId on port $Port."
    }
    if ($matching[0].LocalAddress -notin @("127.0.0.1", "::1")) {
        throw "C0 listener is not bound to loopback."
    }
}

function Read-C0Pid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $state = Get-C0StateDirectory
    $path = Join-Path $state "$Name.pid"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return $null
    }
    $raw = (Get-Content -LiteralPath $path -Raw).Trim()
    $parsed = 0
    if (-not [int]::TryParse($raw, [ref]$parsed) -or $parsed -lt 1) {
        throw "Invalid PID file: $path"
    }
    return $parsed
}

function Stop-C0Process {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$AllowedExecutableNames
    )

    $state = Get-C0StateDirectory
    $pidPath = Join-Path $state "$Name.pid"
    $processId = Read-C0Pid -Name $Name
    if ($null -eq $processId) {
        return
    }
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($null -ne $process) {
        $actual = [System.IO.Path]::GetFileName($process.Path)
        if ($actual -notin $AllowedExecutableNames) {
            throw "Refusing to stop unexpected executable '$actual' for $Name."
        }
        Stop-Process -Id $processId
        Wait-Process -Id $processId -Timeout 15 -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue
}

Export-ModuleMember -Function @(
    "Assert-C0GitState",
    "Assert-C0LoopbackListener",
    "Assert-C0SecretEnvironment",
    "Assert-C0TunnelBinary",
    "Assert-C0TunnelEnvironment",
    "Get-C0BuildCommit",
    "Get-C0RepositoryRoot",
    "Get-C0StateDirectory",
    "Initialize-C0StateDirectory",
    "Read-C0Pid",
    "Stop-C0Process"
)
