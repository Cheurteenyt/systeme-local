[CmdletBinding()]
param(
    [switch]$AllowDirty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C7.Common.psm1") -Force

Assert-C7GitState -AllowDirty:$AllowDirty
Assert-C7OfflineBoundary

$invocation = Invoke-C7PythonCommand -Arguments @(
    "-m",
    "systeme_local_gateway.c7_work_admission",
    "status",
    "--as-of",
    "2026-07-27T16:00:00Z"
)
$status = ConvertFrom-C7JsonResult -Invocation $invocation -Operation "prerequisite check"
if ($invocation.exit_code -ne 0) {
    throw "C7 prerequisite check failed closed."
}
if (
    $status.live_actions_allowed -ne $false -or
    @($status.effective_tools).Count -ne 0 -or
    $status.automatic_chat_to_work_switch_allowed -ne $false
) {
    throw "C7 prerequisite check observed an expanded default boundary."
}

[pscustomobject]@{
    status = "ready_for_offline_work_profile_only"
    branch = (& git -C (Get-C7RepositoryRoot) branch --show-current).Trim()
    commit = (& git -C (Get-C7RepositoryRoot) rev-parse HEAD).Trim()
    final_status = $status.final_status
    work_support_state = $status.support_state
    native_chat_gate_status = $status.native_chat_gate_status
    live_actions_allowed = $false
    effective_tool_count = 0
    sensitive_process_variables = 0
    c0_c1_listeners = 0
    tunnel_client_processes = 0
} | ConvertTo-Json -Depth 6
