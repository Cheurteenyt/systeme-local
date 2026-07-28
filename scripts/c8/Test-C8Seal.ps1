[CmdletBinding()]
param(
    [switch]$RequireCurrentTree,
    [switch]$RequireClean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$branch = (& git -C $root branch --show-current).Trim()
if ($LASTEXITCODE -ne 0 -or $branch -notin @("main", "codex/chatgpt-work-live-c8")) {
    throw "C8 seal verification requires main or the reviewed C8 branch."
}
if ($RequireClean -and @(& git -C $root status --porcelain).Count -ne 0) {
    throw "C8 seal verification requires a clean worktree."
}

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    $python = (Get-Command python -ErrorAction Stop).Source
}
$arguments = @("-m", "systeme_local_gateway.c8_seal", "verify")
if ($RequireCurrentTree) {
    $arguments += "--require-current-tree"
}
if ($RequireClean) {
    $arguments += "--require-clean"
}
$priorPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
try {
    $pythonPath = Join-Path $root "src"
    if (-not [string]::IsNullOrWhiteSpace($priorPythonPath)) {
        $pythonPath += [System.IO.Path]::PathSeparator + $priorPythonPath
    }
    [Environment]::SetEnvironmentVariable("PYTHONPATH", $pythonPath, "Process")
    $result = & $python @arguments
    $exitCode = $LASTEXITCODE
}
finally {
    [Environment]::SetEnvironmentVariable("PYTHONPATH", $priorPythonPath, "Process")
}
try {
    $parsed = ($result -join "`n") | ConvertFrom-Json
}
catch {
    throw "C8 seal verification returned invalid JSON."
}
$parsed | ConvertTo-Json -Depth 8
if ($exitCode -ne 0) {
    throw "C8 final seal verification failed."
}
