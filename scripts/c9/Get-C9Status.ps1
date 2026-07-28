[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9GitState
Assert-C9SecretEnvironment
$state = Initialize-C9StateDirectory
$status = Invoke-C9LocalControl -Operation "status" -Method Get
if (
    $status.version -cne "1" -or
    $status.state -notin @("empty", "staged", "admitted", "closed") -or
    $status.effective_tool_count -notin @(0, 1) -or
    @($status.effective_tools).Count -ne $status.effective_tool_count -or
    $status.native_chat_mcp_invoked -ne $false -or
    $status.rich_call_count -ne [int][bool]$status.work_executed -or
    $status.rich_confirmation_count -ne [int][bool]$status.work_confirmed -or
    ($status.work_rendered -and -not $status.work_executed) -or
    ($status.work_confirmed -and -not $status.work_rendered) -or
    (
        $status.native_chat_picker_claimed -and
        -not $status.native_chat_handoff_exported
    ) -or
    (
        $status.native_chat_handoff_confirmed -and
        -not $status.native_chat_picker_claimed
    ) -or
    (
        $status.native_chat_handoff_exported -and
        -not $status.work_confirmed
    )
) {
    throw "C9 coordinator returned an invalid status receipt."
}
$stagePath = Assert-C9StateFile -Path (Join-Path $state "handoff-stage.json")
if (Test-Path -LiteralPath $stagePath -PathType Leaf) {
    $stage = Read-C9PrivateJson -Path $stagePath
    if ($status.handoff_id -cne $stage.handoff_id) {
        throw "C9 status targets another staged handoff."
    }
} elseif ($null -ne $status.handoff_id) {
    throw "C9 status exposes an uncommitted handoff identifier."
}
$approvalPath = Assert-C9StateFile -Path (
    Join-Path $state "combined-approval.json"
)
if (Test-Path -LiteralPath $approvalPath -PathType Leaf) {
    $approval = Read-C9PrivateJson -Path $approvalPath
    if (
        $status.handoff_id -cne $approval.handoff_id -or
        $status.c9_cycle_id -cne $approval.live_cycle_bundle.grant.cycle_id -or
        $status.c9_grant_id -cne $approval.live_cycle_bundle.grant.grant_id
    ) {
        throw "C9 status does not bind the committed combined approval."
    }
}
$statusPath = Assert-C9StateFile -Path (Join-Path $state "status-latest.json")
[void](Write-C9MetadataReceipt `
    -Path $statusPath `
    -Receipt $status `
    -AllowOverwrite)
$status | ConvertTo-Json -Depth 12
