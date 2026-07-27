Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:C3ExpectedBranch = "interop/provider-capability-revalidation-c3"
$script:C3BaseCommit = "cf05e963ba30539f9b2c9ec2f5f71326cbba8399"

function Get-C3RepositoryRoot {
    $root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")
    return $root.Path
}

function Assert-C3GitState {
    param(
        [switch]$AllowDirty
    )

    $root = Get-C3RepositoryRoot
    $branch = (& git -C $root branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne $script:C3ExpectedBranch) {
        throw "C3 requires branch $script:C3ExpectedBranch; observed '$branch'."
    }
    & git -C $root merge-base --is-ancestor $script:C3BaseCommit HEAD
    if ($LASTEXITCODE -ne 0) {
        throw "C3 HEAD does not descend from the exact reviewed C2 commit."
    }
    if (-not $AllowDirty) {
        $dirty = & git -C $root status --porcelain
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to inspect the C3 Git worktree state."
        }
        if ($null -ne $dirty -and @($dirty).Count -gt 0) {
            throw "C3 operator checks require a clean worktree."
        }
    }
}

function Get-C3PythonLauncher {
    $root = Get-C3RepositoryRoot
    $venv = Join-Path $root ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venv -PathType Leaf) {
        return $venv
    }
    $python = Get-Command python -ErrorAction Stop
    return $python.Source
}

function Get-C3RegistryPath {
    return Join-Path (Get-C3RepositoryRoot) "governance\c3-capability-registry.json"
}

function Get-C3OfficialProfilePath {
    return (
        Join-Path (
            Get-C3RepositoryRoot
        ) "governance\c3-chatgpt-chat-capability-profile.json"
    )
}

function Resolve-C3LocalJsonPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$MustExist
    )

    $root = Get-C3RepositoryRoot
    $stateRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $root ".systeme-local\c3")
    )
    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
        [System.IO.Path]::GetFullPath($Path)
    }
    else {
        [System.IO.Path]::GetFullPath((Join-Path $root $Path))
    }
    $parent = [System.IO.Path]::GetDirectoryName($candidate)
    $name = [System.IO.Path]::GetFileName($candidate)
    if (
        -not [string]::Equals(
            $parent,
            $stateRoot,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $name -notmatch "^[a-z0-9][a-z0-9._-]{0,95}\.json$"
    ) {
        throw "C3 local JSON must be a direct .systeme-local\c3 child."
    }

    if ($MustExist) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "C3 local JSON does not exist."
        }
        $item = Get-Item -LiteralPath $candidate -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "C3 local JSON cannot be a reparse point."
        }
        return $item.FullName
    }

    if (-not (Test-Path -LiteralPath $stateRoot -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $stateRoot -Force)
    }
    $stateItem = Get-Item -LiteralPath $stateRoot -Force
    if (($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "C3 local state directory cannot be a reparse point."
    }
    return $candidate
}

function Write-C3Utf8JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Json
    )

    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    [System.IO.File]::WriteAllText($Path, $Json + "`n", $encoding)
}

function Invoke-C3PythonCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $root = Get-C3RepositoryRoot
    $python = Get-C3PythonLauncher
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

function ConvertFrom-C3JsonResult {
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
        throw "C3 $Operation returned invalid JSON."
    }
}

function Invoke-C3Preflight {
    param(
        [switch]$AllowDirty,
        [string]$AsOf
    )

    Assert-C3GitState -AllowDirty:$AllowDirty
    $effectiveAsOf = $AsOf
    if ([string]::IsNullOrWhiteSpace($effectiveAsOf)) {
        $effectiveAsOf = [DateTime]::UtcNow.ToString("o")
    }
    $invocation = Invoke-C3PythonCommand -Arguments @(
        "-m",
        "systeme_local_gateway.c3_evidence",
        "preflight",
        "--root",
        (Get-C3RepositoryRoot),
        "--registry",
        (Get-C3RegistryPath),
        "--as-of",
        $effectiveAsOf
    )
    $decision = ConvertFrom-C3JsonResult `
        -Invocation $invocation `
        -Operation "preflight"
    if ($invocation.exit_code -ne 0) {
        throw "$($decision.final_status): C3 preflight rejected its evidence bundle."
    }
    return $decision
}

function Assert-C3ProtectedActionAllowed {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "runtime_key_creation",
            "tunnel_start",
            "plugin_creation",
            "browser_test",
            "chatgpt_action"
        )]
        [string]$Action,
        [switch]$AllowDirty
    )

    $decision = Invoke-C3Preflight -AllowDirty:$AllowDirty
    $property = $decision.action_decisions.PSObject.Properties[$Action]
    if (
        $null -eq $property -or
        $property.Value -ne $true -or
        $decision.live_actions_allowed -ne $true
    ) {
        throw "$($decision.final_status): C3 preflight denied $Action."
    }
    return $decision
}

Export-ModuleMember -Function @(
    "Assert-C3GitState",
    "Assert-C3ProtectedActionAllowed",
    "ConvertFrom-C3JsonResult",
    "Get-C3OfficialProfilePath",
    "Get-C3RegistryPath",
    "Get-C3RepositoryRoot",
    "Invoke-C3Preflight",
    "Invoke-C3PythonCommand",
    "Resolve-C3LocalJsonPath",
    "Write-C3Utf8JsonFile"
)
