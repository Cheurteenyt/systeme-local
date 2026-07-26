[CmdletBinding()]
param(
    [string]$VisibleModelLabel,
    [string]$VisibleReasoningLabel,
    [string]$ExactInternalModelId,
    [ValidateSet("low", "medium", "high", "xhigh", "max", "ultra")]
    [string]$CanonicalReasoning,
    [ValidatePattern("^[0-9a-f]{64}$")]
    [string]$ReasoningMappingSourceSha256
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
    "visible-model"
)
foreach ($item in @(
    @("--visible-model-label", $VisibleModelLabel),
    @("--visible-reasoning-label", $VisibleReasoningLabel),
    @("--exact-internal-model-id", $ExactInternalModelId),
    @("--canonical-reasoning", $CanonicalReasoning),
    @("--reasoning-mapping-source-sha256", $ReasoningMappingSourceSha256)
)) {
    if (-not [string]::IsNullOrWhiteSpace($item[1])) {
        $arguments += $item
    }
}
$result = & $python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "C1 visible-model observation failed closed."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "visible-model.json"
)
$result -join "`n"
