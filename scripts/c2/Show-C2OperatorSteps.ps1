[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C2.Common.psm1") -Force

$decision = Invoke-C2Preflight
$steps = if ($decision.live_actions_allowed -eq $true) {
    @(
        "A separate reviewed goal may now authorize a bounded C1 live cycle.",
        "Continue to exclude Work, existing chats, history, and private browser state."
    )
}
else {
    @(
        "STOP before creating a Runtime key, starting a tunnel, creating a Plugin, or opening a browser test.",
        "Revalidate only the four committed official OpenAI sources on or before the deadline.",
        "Do not reinterpret tunnel transport availability as Chat-surface capability."
    )
}

[pscustomobject]@{
    final_status = $decision.final_status
    live_actions_allowed = $decision.live_actions_allowed
    action_decisions = $decision.action_decisions
    revalidate_after = "2026-08-10T01:40:00Z"
    operator_steps = $steps
} | ConvertTo-Json -Depth 8
