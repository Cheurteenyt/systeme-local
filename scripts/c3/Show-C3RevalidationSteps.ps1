[CmdletBinding()]
param(
    [switch]$AllowDirty,
    [string]$AsOf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C3.Common.psm1") -Force

$decision = Invoke-C3Preflight -AllowDirty:$AllowDirty -AsOf $AsOf
$invocation = Invoke-C3PythonCommand -Arguments @(
    "-m",
    "systeme_local_gateway.c3_evidence",
    "revalidation-steps"
)
if ($invocation.exit_code -ne 0) {
    throw "C3 revalidation guidance generation failed."
}
$guidance = ConvertFrom-C3JsonResult `
    -Invocation $invocation `
    -Operation "revalidation guidance"

[pscustomobject]@{
    final_status = $decision.final_status
    support_state = $decision.support_state
    lifecycle_state = $decision.lifecycle_state
    live_actions_allowed = $decision.live_actions_allowed
    action_decisions = $decision.action_decisions
    revalidate_after = "2026-08-10T11:55:00Z"
    guidance = $guidance
} | ConvertTo-Json -Depth 12
