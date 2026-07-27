Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:C6BaseCommit = "418112758d8675326835d9947ccce3a1b12f6f25"
$script:C6AllowedBranches = @(
    "main",
    "codex/chatgpt-official-revalidation-c6"
)
$script:C6SensitiveVariables = @(
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "SLG_AUDIT_KEY",
    "SLG_MCP_TOKEN",
    "SLG_SHARED_SECRET"
)

function Get-C6RepositoryRoot {
    $root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")
    return $root.Path
}

function Assert-C6GitState {
    param(
        [switch]$AllowDirty
    )

    $root = Get-C6RepositoryRoot
    $branch = (& git -C $root branch --show-current).Trim()
    if (
        $LASTEXITCODE -ne 0 -or
        $branch -notin $script:C6AllowedBranches
    ) {
        throw "C6 requires main or its reviewed C6 branch; observed '$branch'."
    }
    & git -C $root merge-base --is-ancestor $script:C6BaseCommit HEAD
    if ($LASTEXITCODE -ne 0) {
        throw "C6 HEAD does not descend from the exact integrated C5 commit."
    }
    if (-not $AllowDirty) {
        $dirty = & git -C $root status --porcelain
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to inspect the C6 Git worktree state."
        }
        if ($null -ne $dirty -and @($dirty).Count -gt 0) {
            throw "C6 operator checks require a clean worktree."
        }
    }
}

function Assert-C6OfflineBoundary {
    $configured = @(
        $script:C6SensitiveVariables |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace(
                    [Environment]::GetEnvironmentVariable($_, "Process")
                )
            }
    )
    if ($configured.Count -ne 0) {
        throw "C6 refuses configured transport or runtime secrets."
    }

    $tunnelProcesses = @(Get-Process -Name "tunnel-client" -ErrorAction SilentlyContinue)
    if ($tunnelProcesses.Count -ne 0) {
        throw "C6 refuses to run while tunnel-client is active."
    }

    if ($null -ne (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        $listeners = @(
            Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalPort -in @(8765, 8766) }
        )
        if ($listeners.Count -ne 0) {
            throw "C6 refuses active C0/C1 listeners."
        }
    }
}

function Get-C6PythonLauncher {
    $root = Get-C6RepositoryRoot
    $venv = Join-Path $root ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venv -PathType Leaf) {
        return $venv
    }
    $python = Get-Command python -ErrorAction Stop
    return $python.Source
}

function Get-C6PolicyPath {
    return Join-Path (Get-C6RepositoryRoot) "governance\c6-revalidation-policy.json"
}

function Get-C6C3RegistryPath {
    return Join-Path (Get-C6RepositoryRoot) "governance\c3-capability-registry.json"
}

function Get-C6StateDirectory {
    return Join-Path (Get-C6RepositoryRoot) ".systeme-local\c6"
}

function Resolve-C6LocalJsonPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [switch]$MustExist
    )

    if ($Name -notmatch "^[a-z0-9][a-z0-9._-]{0,95}\.json$") {
        throw "C6 local JSON name is invalid."
    }
    $stateRoot = [System.IO.Path]::GetFullPath((Get-C6StateDirectory))
    if (-not (Test-Path -LiteralPath $stateRoot -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $stateRoot -Force)
    }
    $stateItem = Get-Item -LiteralPath $stateRoot -Force
    if (($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "C6 local state directory cannot be a reparse point."
    }
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $stateRoot $Name))
    if (
        -not [string]::Equals(
            [System.IO.Path]::GetDirectoryName($candidate),
            $stateRoot,
            [StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "C6 local JSON must be a direct state child."
    }
    if ($MustExist) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "C6 local JSON does not exist."
        }
        $item = Get-Item -LiteralPath $candidate -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "C6 local JSON cannot be a reparse point."
        }
        return $item.FullName
    }
    return $candidate
}

function Invoke-C6PythonCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $root = Get-C6RepositoryRoot
    $python = Get-C6PythonLauncher
    $priorPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
    try {
        $pythonPath = Join-Path $root "src"
        if (-not [string]::IsNullOrWhiteSpace($priorPythonPath)) {
            $pythonPath += [System.IO.Path]::PathSeparator + $priorPythonPath
        }
        [Environment]::SetEnvironmentVariable("PYTHONPATH", $pythonPath, "Process")
        $output = & $python @Arguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        [Environment]::SetEnvironmentVariable(
            "PYTHONPATH",
            $priorPythonPath,
            "Process"
        )
    }
    return [pscustomobject]@{
        exit_code = $exitCode
        output = @($output)
    }
}

function ConvertFrom-C6JsonResult {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Invocation,
        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $text = $Invocation.output -join "`n"
    try {
        return $text | ConvertFrom-Json
    }
    catch {
        throw "C6 $Operation returned invalid JSON."
    }
}

Export-ModuleMember -Function @(
    "Assert-C6GitState",
    "Assert-C6OfflineBoundary",
    "ConvertFrom-C6JsonResult",
    "Get-C6C3RegistryPath",
    "Get-C6PolicyPath",
    "Get-C6RepositoryRoot",
    "Get-C6StateDirectory",
    "Invoke-C6PythonCommand",
    "Resolve-C6LocalJsonPath"
)
