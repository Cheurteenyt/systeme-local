[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedNoRemoteWorkOrChatActions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

if (-not $ConfirmedNoRemoteWorkOrChatActions) {
    throw "C9 local-only reset requires confirmation of zero remote, Work, or Chat actions."
}
Assert-C9GitState
$state = Get-C9StateDirectory
if (
    $null -ne (Read-C9Pid -Name "facade") -or
    $null -ne (Read-C9Pid -Name "facade-launcher") -or
    $null -ne (Read-C9Pid -Name "tunnel")
) {
    throw "C9 local-only reset refuses tracked processes."
}
if (@(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(8765, 8766) }
).Count -ne 0) {
    throw "C9 local-only reset refuses active listeners on C9 ports."
}

$removed = @()
if (Test-Path -LiteralPath $state -PathType Container) {
    $attemptPath = Assert-C9StateFile -Path (
        Join-Path $state "tunnel-attempt.json"
    )
    if (Test-Path -LiteralPath $attemptPath) {
        throw "C9 local-only reset refuses a recorded remote Tunnel attempt."
    }
    $auditPath = Assert-C9StateFile -Path (Join-Path $state "audit.jsonl")
    if (
        (Test-Path -LiteralPath $auditPath -PathType Leaf) -and
        @(
            Get-Content -LiteralPath $auditPath |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        ).Count -ne 0
    ) {
        throw "C9 local-only reset refuses runtime capability audit records."
    }

    $allowed = @(
        "admission.json",
        "approvals.sqlite3",
        "attestation.json",
        "audit.jsonl",
        "audit.jsonl.lock",
        "chat-handoff-export.json",
        "chat-handoff-picker-claim.json",
        "chat-manual-proof.json",
        "chat-response.json",
        "combined-approval.json",
        "coordinator-close.json",
        "facade.stderr.log",
        "facade.stdout.log",
        "git-global-config.empty",
        "handoff-stage.json",
        "local-probe-admitted.json",
        "local-probe-pre-admission.json",
        "local-ai-runtime-observation.json",
        "manual-exports",
        "negative-tests.json",
        "replay.sqlite3",
        "revocation.json",
        "sandboxes",
        "status-latest.json",
        "synthetic-fixtures",
        "tunnel.stderr.log",
        "tunnel.stdout.log",
        "web-steps.json",
        "work-rich-correlation.json",
        "work-execution.json",
        "work-proof.json",
        "work-response.json"
    )
    $children = @(Get-ChildItem -LiteralPath $state -Force)
    $unexpected = @($children | Where-Object { $_.Name -notin $allowed })
    if ($unexpected.Count -ne 0) {
        $names = ($unexpected.Name | Sort-Object) -join ", "
        throw "C9 local-only reset refuses unexpected private state: $names"
    }
    foreach ($directoryName in @("manual-exports", "synthetic-fixtures")) {
        $directory = Join-Path $state $directoryName
        if (
            (Test-Path -LiteralPath $directory -PathType Container) -and
            @(Get-ChildItem -LiteralPath $directory -Force).Count -ne 0
        ) {
            throw "Stop C9 cleanly before resetting non-empty private attachment state."
        }
    }

    $allItems = @(
        Get-Item -LiteralPath $state -Force
        Get-ChildItem -LiteralPath $state -Recurse -Force
    )
    if (@(
        $allItems |
            Where-Object {
                ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            }
    ).Count -ne 0) {
        throw "C9 local-only reset refuses a reparse point."
    }

    $prefix = [System.IO.Path]::GetFullPath($state) +
        [System.IO.Path]::DirectorySeparatorChar
    foreach ($child in $children) {
        $resolved = [System.IO.Path]::GetFullPath($child.FullName)
        if (-not $resolved.StartsWith(
            $prefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Refusing C9 local-only reset outside the private state directory."
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
        $removed += $child.Name
    }
}

foreach ($name in @(
    "SLG_AUDIT_KEY",
    "SLG_SHARED_SECRET",
    "SLG_MCP_TOKEN",
    "SLG_C9_CONTROL_TOKEN",
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "SLG_C9_GIT_EXECUTABLE",
    "SLG_C9_LOCAL_AI_ENDPOINT",
    "SLG_C9_LOCAL_AI_MODEL",
    "SLG_PROVIDER_RUNTIME_MODE",
    "SLG_PROVIDER_RUNTIME_ROOT",
    "SLG_C9_SERVER_BUILD_COMMIT",
    "SLG_C9_STATE_DIRECTORY",
    "SLG_C9_ADMISSION_FILE",
    "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE"
)) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    status = "local_only_reset"
    removed = @($removed | Sort-Object)
    process_secrets_cleared = $true
    local_ai_configuration_cleared = $true
    remote_transport_attempted = $false
    work_plugin_mcp_invoked = $false
    chat_plugin_mcp_invoked = $false
    native_chat_manual_handoff_used = $false
    unapproved_fallback_used = $false
    native_chat_provider_audit_correlation_claimed = $false
    runtime_api_key_platform_revocation_required = $false
    tunnel_resource_reusable = $true
} | ConvertTo-Json
