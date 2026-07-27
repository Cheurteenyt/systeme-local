Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:C2ExpectedBranch = "interop/chatgpt-web-capability-gating-c2"
$script:C2BaseCommit = "2aee36fdfa3d20c23acdc75eb3348bc54536ef4f"

function Get-C2RepositoryRoot {
    $root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")
    return $root.Path
}

function Assert-C2GitState {
    param(
        [switch]$AllowDirty
    )

    $root = Get-C2RepositoryRoot
    $branch = (& git -C $root branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne $script:C2ExpectedBranch) {
        throw "C2 requires branch $script:C2ExpectedBranch; observed '$branch'."
    }
    & git -C $root merge-base --is-ancestor $script:C2BaseCommit HEAD
    if ($LASTEXITCODE -ne 0) {
        throw "C2 HEAD does not descend from the exact reviewed C1 commit."
    }
    if (-not $AllowDirty) {
        $dirty = & git -C $root status --porcelain
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to inspect the C2 Git worktree state."
        }
        if ($null -ne $dirty -and @($dirty).Count -gt 0) {
            throw "C2 live preflight requires a clean worktree."
        }
    }
}

function Get-C2PythonLauncher {
    $root = Get-C2RepositoryRoot
    $venv = Join-Path $root ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venv -PathType Leaf) {
        return $venv
    }
    $python = Get-Command python -ErrorAction Stop
    return $python.Source
}

function Get-C2OfficialProfilePath {
    return Join-Path (Get-C2RepositoryRoot) "governance\c2-official-capability-profile.json"
}

function Invoke-C2PythonCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $root = Get-C2RepositoryRoot
    $python = Get-C2PythonLauncher
    $priorPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
    $sourceRoot = Join-Path $root "src"
    try {
        $pythonPath = $sourceRoot
        if (-not [string]::IsNullOrWhiteSpace($priorPythonPath)) {
            $pythonPath += [System.IO.Path]::PathSeparator + $priorPythonPath
        }
        [Environment]::SetEnvironmentVariable("PYTHONPATH", $pythonPath, "Process")
        $output = & $python @Arguments
        $exitCode = $LASTEXITCODE
    } finally {
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

function Invoke-C2Preflight {
    param(
        [switch]$AllowDirty
    )

    Assert-C2GitState -AllowDirty:$AllowDirty
    $asOf = [DateTime]::UtcNow.ToString("o")
    $invocation = Invoke-C2PythonCommand -Arguments @(
        "-m",
        "systeme_local_gateway.c2_capability",
        "preflight",
        "--profile",
        (Get-C2OfficialProfilePath),
        "--as-of",
        $asOf
    )
    if ($invocation.exit_code -ne 0) {
        throw "C2 preflight could not validate the committed official-capability profile."
    }
    $text = $invocation.output -join "`n"
    try {
        return $text | ConvertFrom-Json
    } catch {
        throw "C2 preflight returned invalid JSON."
    }
}

function Assert-C2LiveActionAllowed {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "runtime_key_creation",
            "tunnel_start",
            "plugin_creation",
            "browser_test"
        )]
        [string]$Action,
        [switch]$AllowDirty
    )

    $decision = Invoke-C2Preflight -AllowDirty:$AllowDirty
    $property = $decision.action_decisions.PSObject.Properties[$Action]
    if (
        $null -eq $property -or
        $property.Value -ne $true -or
        $decision.live_actions_allowed -ne $true
    ) {
        throw "$($decision.final_status): C2 preflight denied $Action."
    }
    return $decision
}

Export-ModuleMember -Function @(
    "Assert-C2GitState",
    "Assert-C2LiveActionAllowed",
    "Get-C2OfficialProfilePath",
    "Get-C2RepositoryRoot",
    "Invoke-C2PythonCommand",
    "Invoke-C2Preflight"
)
