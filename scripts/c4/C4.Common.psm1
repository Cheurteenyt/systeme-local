Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:C4ExpectedBranch = "interop/provider-runtime-admission-c4"
$script:C4BaseCommit = "9140801e88ed44afca9481ac06288783a0d52da2"

function Get-C4RepositoryRoot {
    $root = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")
    return $root.Path
}

function Assert-C4GitState {
    param(
        [switch]$AllowDirty
    )

    $root = Get-C4RepositoryRoot
    $branch = (& git -C $root branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne $script:C4ExpectedBranch) {
        throw "C4 requires branch $script:C4ExpectedBranch; observed '$branch'."
    }
    & git -C $root merge-base --is-ancestor $script:C4BaseCommit HEAD
    if ($LASTEXITCODE -ne 0) {
        throw "C4 HEAD does not descend from the exact reviewed C3 commit."
    }
    if (-not $AllowDirty) {
        $dirty = & git -C $root status --porcelain
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to inspect the C4 Git worktree state."
        }
        if ($null -ne $dirty -and @($dirty).Count -gt 0) {
            throw "C4 operator checks require a clean worktree."
        }
    }
}

function Get-C4PythonLauncher {
    $root = Get-C4RepositoryRoot
    $venv = Join-Path $root ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venv -PathType Leaf) {
        return $venv
    }
    $python = Get-Command python -ErrorAction Stop
    return $python.Source
}

function Assert-C4ReviewedJsonPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    if (
        $RelativePath -notmatch "^governance\\[a-z0-9][a-z0-9._-]{0,127}\.json$"
    ) {
        throw "C4 reviewed JSON path is outside governance."
    }
    $root = Get-C4RepositoryRoot
    $governance = Get-Item -LiteralPath (Join-Path $root "governance") -Force
    if (($governance.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "C4 governance directory cannot be a reparse point."
    }
    $path = Join-Path $root $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "C4 reviewed JSON is missing."
    }
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "C4 reviewed JSON cannot be a reparse point."
    }
    return $item.FullName
}

function Get-C4C3RegistryPath {
    return Assert-C4ReviewedJsonPath `
        -RelativePath "governance\c3-capability-registry.json"
}

function Get-C4C3ProfilePath {
    return Assert-C4ReviewedJsonPath `
        -RelativePath "governance\c3-chatgpt-chat-capability-profile.json"
}

function Get-C4RuntimeRegistryPath {
    return Assert-C4ReviewedJsonPath `
        -RelativePath "governance\c4-runtime-adapters.json"
}

function New-C4Correlation {
    $bytes = [byte[]]::new(16)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return "c4_" + (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Invoke-C4PythonCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $root = Get-C4RepositoryRoot
    $python = Get-C4PythonLauncher
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

function ConvertFrom-C4JsonResult {
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
        throw "C4 $Operation returned invalid JSON."
    }
}

function Invoke-C4Admission {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "runtime_key_creation",
            "tunnel_start",
            "plugin_creation",
            "browser_test",
            "chatgpt_action",
            "tool_surface_exposure"
        )]
        [string]$Action,
        [switch]$RequestApprovedTools,
        [switch]$AllowDirty,
        [string]$AsOf,
        [string]$Correlation
    )

    Assert-C4GitState -AllowDirty:$AllowDirty
    $effectiveAsOf = $AsOf
    if ([string]::IsNullOrWhiteSpace($effectiveAsOf)) {
        $effectiveAsOf = [DateTime]::UtcNow.ToString("o")
    }
    $effectiveCorrelation = $Correlation
    if ([string]::IsNullOrWhiteSpace($effectiveCorrelation)) {
        $effectiveCorrelation = New-C4Correlation
    }
    if ($effectiveCorrelation -notmatch "^c4_[0-9a-f]{32}$") {
        throw "C4 request correlation has an invalid format."
    }
    $arguments = @(
        "-m",
        "systeme_local_gateway.c4_admission",
        "preflight",
        "--root",
        (Get-C4RepositoryRoot),
        "--c3-registry",
        (Get-C4C3RegistryPath),
        "--c4-registry",
        (Get-C4RuntimeRegistryPath),
        "--as-of",
        $effectiveAsOf,
        "--action",
        $Action,
        "--correlation",
        $effectiveCorrelation
    )
    [void](Get-C4C3ProfilePath)
    if ($RequestApprovedTools) {
        $arguments += "--request-approved-tools"
    }
    $invocation = Invoke-C4PythonCommand -Arguments $arguments
    $decision = ConvertFrom-C4JsonResult `
        -Invocation $invocation `
        -Operation "runtime admission"
    if ($invocation.exit_code -notin @(0, 3)) {
        throw "C4 runtime admission rejected invalid input or evidence."
    }
    return $decision
}

function Assert-C4ProtectedActionAllowed {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "runtime_key_creation",
            "tunnel_start",
            "plugin_creation",
            "browser_test",
            "chatgpt_action",
            "tool_surface_exposure"
        )]
        [string]$Action,
        [switch]$RequestApprovedTools,
        [switch]$AllowDirty
    )

    $decision = Invoke-C4Admission `
        -Action $Action `
        -RequestApprovedTools:$RequestApprovedTools `
        -AllowDirty:$AllowDirty
    if ($decision.allowed -ne $true) {
        throw "C4 runtime admission denied ${Action}: $($decision.reason_code)."
    }
    if (
        $Action -in @("chatgpt_action", "tool_surface_exposure") -and
        $RequestApprovedTools -and
        @($decision.effective_tools).Count -ne 1
    ) {
        throw "C4 allowed tool action did not preserve the exact approved tool."
    }
    return $decision
}

function Get-C4ActionMatrix {
    param(
        [switch]$AllowDirty,
        [string]$AsOf
    )

    Assert-C4GitState -AllowDirty:$AllowDirty
    $effectiveAsOf = $AsOf
    if ([string]::IsNullOrWhiteSpace($effectiveAsOf)) {
        $effectiveAsOf = [DateTime]::UtcNow.ToString("o")
    }
    [void](Get-C4C3ProfilePath)
    $invocation = Invoke-C4PythonCommand -Arguments @(
        "-m",
        "systeme_local_gateway.c4_admission",
        "matrix",
        "--root",
        (Get-C4RepositoryRoot),
        "--c3-registry",
        (Get-C4C3RegistryPath),
        "--c4-registry",
        (Get-C4RuntimeRegistryPath),
        "--as-of",
        $effectiveAsOf
    )
    if ($invocation.exit_code -ne 0) {
        throw "C4 runtime admission matrix failed."
    }
    return ConvertFrom-C4JsonResult `
        -Invocation $invocation `
        -Operation "action matrix"
}

Export-ModuleMember -Function @(
    "Assert-C4GitState",
    "Assert-C4ProtectedActionAllowed",
    "ConvertFrom-C4JsonResult",
    "Get-C4ActionMatrix",
    "Get-C4C3ProfilePath",
    "Get-C4C3RegistryPath",
    "Get-C4RepositoryRoot",
    "Get-C4RuntimeRegistryPath",
    "Invoke-C4Admission",
    "Invoke-C4PythonCommand",
    "New-C4Correlation"
)
