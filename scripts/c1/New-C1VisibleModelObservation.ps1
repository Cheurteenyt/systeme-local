[CmdletBinding()]
param(
    [string]$VisibleModelLabel,
    [string]$VisibleModelLabelUtf8Base64,
    [string]$VisibleReasoningLabel,
    [string]$VisibleReasoningLabelUtf8Base64,
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
$modelLabelFromBase64 = -not [string]::IsNullOrWhiteSpace(
    $VisibleModelLabelUtf8Base64
)
$reasoningLabelFromBase64 = -not [string]::IsNullOrWhiteSpace(
    $VisibleReasoningLabelUtf8Base64
)
if (
    $modelLabelFromBase64 -and
    -not [string]::IsNullOrWhiteSpace($VisibleModelLabel)
) {
    throw "Supply either VisibleModelLabel or VisibleModelLabelUtf8Base64, not both."
}
if (
    $reasoningLabelFromBase64 -and
    -not [string]::IsNullOrWhiteSpace($VisibleReasoningLabel)
) {
    throw (
        "Supply either VisibleReasoningLabel or " +
        "VisibleReasoningLabelUtf8Base64, not both."
    )
}
if ($modelLabelFromBase64) {
    $VisibleModelLabel = ConvertFrom-C1Utf8Base64 `
        -Value $VisibleModelLabelUtf8Base64 `
        -FieldName "VisibleModelLabel"
}
if ($reasoningLabelFromBase64) {
    $VisibleReasoningLabel = ConvertFrom-C1Utf8Base64 `
        -Value $VisibleReasoningLabelUtf8Base64 `
        -FieldName "VisibleReasoningLabel"
}
if (
    -not $modelLabelFromBase64 -and
    $VisibleModelLabel -match "[^\x20-\x7e]"
) {
    throw "Non-ASCII model labels must use VisibleModelLabelUtf8Base64."
}
if (
    -not $reasoningLabelFromBase64 -and
    $VisibleReasoningLabel -match "[^\x20-\x7e]"
) {
    throw (
        "Non-ASCII reasoning labels must use " +
        "VisibleReasoningLabelUtf8Base64."
    )
}
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
