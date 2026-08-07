[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("a", "b")]
    [string]$TestWork,
    [Parameter(Mandatory = $true)]
    [switch]$VisibleWorkAndPluginSelected
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

if (-not $VisibleWorkAndPluginSelected) {
    throw "C8 refuses an ambiguous Work task or Plugin selection."
}
Assert-C8GitState
Assert-C8AuditKeyEnvironment
$root = Get-C8RepositoryRoot
$state = Initialize-C8StateDirectory
$cycle = Get-C8LiveCycle
$path = Join-Path $state "task-surface-$TestWork.json"
if (Test-Path -LiteralPath $path -PathType Leaf) {
    throw "C8 Work $TestWork task observation already exists."
}
$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python -m systeme_local_gateway.c8_live_cycle `
    observe-task-surface `
    --cycle-id $cycle.authorization.cycle_id `
    --grant-id $cycle.grant.grant_id `
    --test-work $TestWork
if ($LASTEXITCODE -ne 0) {
    throw "C8 Work task surface observation failed."
}
$result -join "`n" | Set-Content -LiteralPath $path
$result -join "`n"
