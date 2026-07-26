[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RuntimeModel,
    [Parameter(Mandatory = $true)]
    [ValidateSet("low", "medium", "high", "xhigh", "max", "ultra")]
    [string]$ReasoningEffort
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
Assert-C1SecretEnvironment
$root = Get-C1RepositoryRoot
$state = Initialize-C1StateDirectory
$python = Join-Path $root ".venv\Scripts\python.exe"
$plugins = @(
    "browser",
    "chrome",
    "computer-use",
    "figma",
    "github",
    "gmail",
    "linear",
    "sites",
    "supabase"
)
$arguments = @(
    "-m",
    "systeme_local_gateway.c1_evidence",
    "runtime",
    "--runtime-model",
    $RuntimeModel,
    "--codex-version",
    ((codex --version) -join "`n").Trim(),
    "--reasoning-effort",
    $ReasoningEffort,
    "--codex-product-surface",
    "codex_desktop_app",
    "--permission-mode",
    "filesystem_unrestricted",
    "--sandbox-mode",
    "none",
    "--approval-policy",
    "never",
    "--network-access-policy",
    "enabled",
    "--browser-surface",
    "in_app_browser"
)
foreach ($plugin in $plugins) {
    $arguments += @("--enabled-plugin", $plugin)
}
$result = & $python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "C1 runtime setup observation failed."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "runtime-setup.json"
)
$result -join "`n"
