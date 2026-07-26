Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:C1ExpectedBranch = "interop/chatgpt-web-chat-observability-c1"
$script:C1ToolName = "systeme_local_connectivity_probe"
$script:C1Port = 8765
$script:C1HealthPort = 8766

function Get-C1RepositoryRoot {
    $root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")
    return $root.Path
}

function Get-C1StateDirectory {
    $root = Get-C1RepositoryRoot
    $state = [System.IO.Path]::GetFullPath(
        (Join-Path $root ".systeme-local\c1")
    )
    $requiredPrefix = [System.IO.Path]::GetFullPath(
        (Join-Path $root ".systeme-local")
    ) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $state.StartsWith(
        $requiredPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "C1 state directory escaped the repository-private state root."
    }
    return $state
}

function Initialize-C1StateDirectory {
    $state = Get-C1StateDirectory
    if (-not (Test-Path -LiteralPath $state -PathType Container)) {
        New-Item -ItemType Directory -Path $state | Out-Null
    }
    return $state
}

function Assert-C1GitState {
    param(
        [switch]$AllowDirty
    )

    $root = Get-C1RepositoryRoot
    $branch = (& git -C $root branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne $script:C1ExpectedBranch) {
        throw "C1 requires branch $script:C1ExpectedBranch; observed '$branch'."
    }
    if (-not $AllowDirty) {
        $dirty = & git -C $root status --porcelain
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to inspect Git worktree state."
        }
        if ($null -ne $dirty -and @($dirty).Count -gt 0) {
            throw "C1 runtime requires a clean worktree."
        }
    }
}

function Get-C1BuildCommit {
    $root = Get-C1RepositoryRoot
    $commit = (& git -C $root rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch "^[0-9a-f]{40}$") {
        throw "Unable to resolve a full lowercase Git build commit."
    }
    return $commit
}

function Assert-C1SecretEnvironment {
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
        throw "C1 secrets must be pairwise independent."
    }
}

function Assert-C1AuditKeyEnvironment {
    $value = [Environment]::GetEnvironmentVariable("SLG_AUDIT_KEY", "Process")
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -lt 32) {
        throw "SLG_AUDIT_KEY must remain available until C1 final attestation."
    }
}

function Assert-C1TunnelEnvironment {
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

function Assert-C1TunnelBinary {
    $root = Get-C1RepositoryRoot
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

function Assert-C1LoopbackListener {
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
        throw "C1 listener is not bound to loopback."
    }
}

function Read-C1Pid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $path = Join-Path (Get-C1StateDirectory) "$Name.pid"
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

function Stop-C1Process {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$AllowedExecutableNames
    )

    $state = Get-C1StateDirectory
    $pidPath = Join-Path $state "$Name.pid"
    $processId = Read-C1Pid -Name $Name
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

function Stop-C1PythonLauncher {
    $state = Get-C1StateDirectory
    $pidPath = Join-Path $state "facade-launcher.pid"
    $processId = Read-C1Pid -Name "facade-launcher"
    if ($null -eq $processId) {
        return
    }
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue
        return
    }
    Wait-Process -Id $processId -Timeout 5 -ErrorAction SilentlyContinue
    if ($null -eq (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue
        return
    }
    Stop-C1Process -Name "facade-launcher" -AllowedExecutableNames @("python.exe")
}

function Assert-C1StateFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolved = [System.IO.Path]::GetFullPath($Path)
    $prefix = [System.IO.Path]::GetFullPath(
        (Get-C1StateDirectory)
    ) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith(
        $prefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "C1 evidence paths must remain inside the ignored C1 state directory."
    }
    return $resolved
}

function ConvertFrom-C1Utf8Base64 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$FieldName UTF-8 Base64 value must not be empty."
    }
    try {
        $bytes = [Convert]::FromBase64String($Value)
    } catch {
        throw "$FieldName must use valid canonical UTF-8 Base64."
    }
    if ([Convert]::ToBase64String($bytes) -cne $Value) {
        throw "$FieldName must use valid canonical UTF-8 Base64."
    }
    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    try {
        $decoded = $strictUtf8.GetString($bytes)
    } catch {
        throw "$FieldName Base64 payload must contain valid UTF-8."
    }
    if ([string]::IsNullOrWhiteSpace($decoded)) {
        throw "$FieldName decoded value must not be empty."
    }
    return $decoded
}

Export-ModuleMember -Function @(
    "Assert-C1GitState",
    "Assert-C1AuditKeyEnvironment",
    "Assert-C1LoopbackListener",
    "Assert-C1SecretEnvironment",
    "Assert-C1StateFile",
    "Assert-C1TunnelBinary",
    "Assert-C1TunnelEnvironment",
    "ConvertFrom-C1Utf8Base64",
    "Get-C1BuildCommit",
    "Get-C1RepositoryRoot",
    "Get-C1StateDirectory",
    "Initialize-C1StateDirectory",
    "Read-C1Pid",
    "Stop-C1Process",
    "Stop-C1PythonLauncher"
)
