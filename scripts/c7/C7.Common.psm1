Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:C7BaseCommit = "81bed9b81f266709fab0ea4178f98f0607c3da44"
$script:C7AllowedBranches = @(
    "main",
    "codex/chatgpt-work-capability-c7"
)
$script:C7SensitiveVariables = @(
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "SLG_AUDIT_KEY",
    "SLG_MCP_TOKEN",
    "SLG_SHARED_SECRET"
)

function Get-C7RepositoryRoot {
    $root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")
    return $root.Path
}

function Assert-C7GitState {
    param(
        [switch]$AllowDirty
    )

    $root = Get-C7RepositoryRoot
    $branch = (& git -C $root branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -notin $script:C7AllowedBranches) {
        throw "C7 requires main or its reviewed C7 branch; observed '$branch'."
    }
    & git -C $root merge-base --is-ancestor $script:C7BaseCommit HEAD
    if ($LASTEXITCODE -ne 0) {
        throw "C7 HEAD does not descend from the exact accepted C6 main commit."
    }
    if (-not $AllowDirty) {
        $dirty = & git -C $root status --porcelain
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to inspect the C7 Git worktree state."
        }
        if ($null -ne $dirty -and @($dirty).Count -gt 0) {
            throw "C7 operator checks require a clean worktree."
        }
    }
}

function Assert-C7OfflineBoundary {
    $configured = @(
        $script:C7SensitiveVariables |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace(
                    [Environment]::GetEnvironmentVariable($_, "Process")
                )
            }
    )
    if ($configured.Count -ne 0) {
        throw "C7 refuses configured transport or runtime secrets."
    }

    if (@(Get-Process -Name "tunnel-client" -ErrorAction SilentlyContinue).Count -ne 0) {
        throw "C7 refuses to run while tunnel-client is active."
    }
    if ($null -ne (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        $listeners = @(
            Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalPort -in @(8765, 8766) }
        )
        if ($listeners.Count -ne 0) {
            throw "C7 refuses active C0/C1 listeners."
        }
    }
}

function Get-C7PythonLauncher {
    $root = Get-C7RepositoryRoot
    $venv = Join-Path $root ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venv -PathType Leaf) {
        return $venv
    }
    return (Get-Command python -ErrorAction Stop).Source
}

function Invoke-C7PythonCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $root = Get-C7RepositoryRoot
    $python = Get-C7PythonLauncher
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
        [Environment]::SetEnvironmentVariable("PYTHONPATH", $priorPythonPath, "Process")
    }
    return [pscustomobject]@{
        exit_code = $exitCode
        output = @($output)
    }
}

function ConvertFrom-C7JsonResult {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Invocation,
        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    try {
        return ($Invocation.output -join "`n") | ConvertFrom-Json
    }
    catch {
        throw "C7 $Operation returned invalid JSON."
    }
}

Export-ModuleMember -Function @(
    "Assert-C7GitState",
    "Assert-C7OfflineBoundary",
    "ConvertFrom-C7JsonResult",
    "Get-C7RepositoryRoot",
    "Invoke-C7PythonCommand"
)
