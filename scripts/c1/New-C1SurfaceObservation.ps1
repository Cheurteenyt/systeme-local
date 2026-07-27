[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("a", "b")]
    [string]$TestChat,
    [Parameter(Mandatory = $true)]
    [ValidateSet("chat", "work", "codex", "unknown")]
    [string]$Surface,
    [switch]$PluginSelected
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
Assert-C1SecretEnvironment
$root = Get-C1RepositoryRoot
$state = Initialize-C1StateDirectory
$python = Join-Path $root ".venv\Scripts\python.exe"
$arguments = @(
    "-m",
    "systeme_local_gateway.c1_evidence",
    "surface",
    "--test-chat",
    $TestChat,
    "--surface",
    $Surface
)
if ($PluginSelected) {
    $arguments += "--plugin-selected"
}
$result = & $python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "C1 surface observation failed closed."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "surface-$TestChat.json"
)
$result -join "`n"
