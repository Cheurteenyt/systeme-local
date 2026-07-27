[CmdletBinding()]
param(
    [switch] $RequireCurrentTree,
    [switch] $RequireClean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C6.Common.psm1") -Force
$root = Get-C6RepositoryRoot
Assert-C6OfflineBoundary

$arguments = @(
    "run",
    "--frozen",
    "python",
    "-m",
    "systeme_local_gateway.c6_seal",
    "--root",
    $root,
    "verify"
)
if ($RequireCurrentTree) {
    $arguments += "--require-current-tree"
}
if ($RequireClean) {
    $arguments += "--require-clean"
}

& uv @arguments
if ($LASTEXITCODE -ne 0) {
    throw "C6 repository seal verification failed."
}
