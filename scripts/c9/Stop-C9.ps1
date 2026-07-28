[CmdletBinding()]
param(
    [switch]$Emergency,
    [switch]$ClearAuditKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

$root = Get-C9RepositoryRoot
$state = Get-C9StateDirectory
$python = Join-Path $root ".venv\Scripts\python.exe"
$tunnel = Join-Path $root ".systeme-local\c0\bin\tunnel-client.exe"
$hadApiKey = -not [string]::IsNullOrWhiteSpace(
    [Environment]::GetEnvironmentVariable("CONTROL_PLANE_API_KEY", "Process")
)
$hadTunnelAttempt = Test-Path -LiteralPath (
    Join-Path $state "tunnel-attempt.json"
)
$coordinatorClosed = $false
$coordinatorCloseReceiptRecorded = $false
$emergencyCleanup = $false
$privateRawResponsesRemoved = 0
$cleanupFailures = New-Object "System.Collections.Generic.List[string]"
function Add-C9StopFailure {
    param([Parameter(Mandatory = $true)][string]$Phase)
    if (-not $cleanupFailures.Contains($Phase)) {
        $cleanupFailures.Add($Phase)
    }
}
$clear = @(
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "MCP_SERVER_URL",
    "MCP_EXTRA_HEADERS",
    "MCP_DISCOVERY_EXTRA_HEADERS",
    "MCP_MAX_CONCURRENT_REQUESTS",
    "MCP_CONNECTION_MAX_TTL",
    "CONTROL_PLANE_MAX_INFLIGHT_REQUESTS",
    "HEALTH_LISTEN_ADDR",
    "LOG_HTTP_RAW_UNSAFE",
    "OPEN_WEB_UI",
    "ALLOW_REMOTE_UI",
    "LOG_FORMAT",
    "LOG_LEVEL",
    "SLG_SHARED_SECRET",
    "SLG_MCP_TOKEN",
    "SLG_MCP_AUTHORIZATION",
    "SLG_C9_CONTROL_TOKEN",
    "SLG_C0_ENABLED",
    "SLG_C0_SERVER_BUILD_COMMIT",
    "SLG_PROVIDER_RUNTIME_MODE",
    "SLG_PROVIDER_RUNTIME_ROOT",
    "SLG_C9_SERVER_BUILD_COMMIT",
    "SLG_C9_STATE_DIRECTORY",
    "SLG_C9_ADMISSION_FILE",
    "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE",
    "SLG_C9_LOCAL_AI_ENDPOINT",
    "SLG_C9_LOCAL_AI_MODEL",
    "SLG_MCP_ENABLED",
    "SLG_MCP_MAX_REQUEST_BYTES",
    "SLG_MCP_REQUESTS_PER_MINUTE",
    "SLG_MCP_MAX_CONCURRENCY",
    "SLG_MCP_MAX_RENDERED_RESPONSE_BYTES",
    "SLG_POLICY_FILE",
    "SLG_WORKSPACE",
    "SLG_AUDIT_LOG",
    "SLG_REPLAY_DB",
    "SLG_APPROVAL_DB",
    "SLG_SANDBOX_ROOT"
)
if ($ClearAuditKey) {
    $clear += "SLG_AUDIT_KEY"
}

try {
    try {
        Assert-C9GitState -AllowDirty:$Emergency
    } catch {
        Add-C9StopFailure -Phase "git_state"
    }

    $facadePid = $null
    try {
        $facadePid = Read-C9Pid -Name "facade"
    } catch {
        Add-C9StopFailure -Phase "facade_record"
    }
    if ($null -ne $facadePid) {
        $controlToken = $null
        $closeReceipt = $null
        try {
            Assert-C9LoopbackListener -ProcessId $facadePid -Port 8765
            $controlToken = [Environment]::GetEnvironmentVariable(
                "SLG_C9_CONTROL_TOKEN",
                "Process"
            )
            if ([string]::IsNullOrWhiteSpace($controlToken)) {
                throw "C9 control token is unavailable."
            }
            $closeReceipt = Invoke-RestMethod `
                -Method Post `
                -Uri "http://127.0.0.1:8765/_local/c9/close" `
                -Headers @{ Authorization = "Bearer $controlToken" } `
                -ContentType "application/json" `
                -Body "{}" `
                -TimeoutSec 10
            if (
                $closeReceipt.version -cne "1" -or
                $closeReceipt.status -cne "closed" -or
                $closeReceipt.rich_call_count -notin @(0, 1) -or
                $closeReceipt.rich_confirmation_count -notin @(0, 1) -or
                $closeReceipt.rich_confirmation_count -gt
                    $closeReceipt.rich_call_count -or
                $closeReceipt.native_chat_manual_handoff_used -notin
                    @($true, $false)
            ) {
                throw "C9 coordinator returned an invalid close receipt."
            }
            $workProofExists = Test-Path -LiteralPath (
                Join-Path $state "work-proof.json"
            ) -PathType Leaf
            $chatProofExists = Test-Path -LiteralPath (
                Join-Path $state "chat-manual-proof.json"
            ) -PathType Leaf
            if (
                ($workProofExists -or $chatProofExists) -and
                (
                    -not ($workProofExists -and $chatProofExists) -or
                    $closeReceipt.rich_call_count -ne 1 -or
                    $closeReceipt.rich_confirmation_count -ne 1 -or
                    $closeReceipt.native_chat_manual_handoff_used -ne $true
                )
            ) {
                throw "C9 completed proof files do not match the close receipt."
            }
            $coordinatorClosed = $true
            $closeReceiptPath = Assert-C9StateFile -Path (
                Join-Path $state "coordinator-close.json"
            )
            [void](Write-C9MetadataReceipt `
                -Path $closeReceiptPath `
                -Receipt $closeReceipt)
            $coordinatorCloseReceiptRecorded = $true
        } catch {
            Add-C9StopFailure -Phase "coordinator_close"
            if ($Emergency) {
                Write-Warning (
                    "C9 emergency stop is continuing after local " +
                    "coordinator cleanup failed."
                )
            } else {
                Write-Warning (
                    "C9 coordinator cleanup failed; " +
                    "use -Emergency only after review."
                )
            }
        } finally {
            $controlToken = $null
            $closeReceipt = $null
        }
    }
} finally {
    foreach ($phase in @(
        [pscustomobject]@{
            name = "tunnel"
            paths = @($tunnel)
        },
        [pscustomobject]@{
            name = "facade"
            paths = @($python)
        }
    )) {
        try {
            Stop-C9Process `
                -Name $phase.name `
                -AllowedExecutablePaths $phase.paths
        } catch {
            Add-C9StopFailure -Phase ("stop_" + $phase.name)
        }
    }
    try {
        Stop-C9PythonLauncher
    } catch {
        Add-C9StopFailure -Phase "stop_facade_launcher"
    }

    foreach ($name in @("work-response.json", "chat-response.json")) {
        try {
            $responsePath = Assert-C9StateFile -Path (Join-Path $state $name)
            if (-not (Test-Path -LiteralPath $responsePath)) {
                continue
            }
            $responseItem = Get-Item -LiteralPath $responsePath -Force
            if (
                $responseItem.PSIsContainer -or
                ($responseItem.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                throw "C9 stop refuses an unsafe private provider-response object."
            }
            Remove-Item -LiteralPath $responsePath -Force
            if (Test-Path -LiteralPath $responsePath) {
                throw "C9 private provider response remains after cleanup."
            }
            $privateRawResponsesRemoved += 1
        } catch {
            Add-C9StopFailure -Phase "provider_response_cleanup"
        }
    }

    if ($Emergency -and -not $coordinatorClosed) {
        foreach ($name in @("manual-exports", "synthetic-fixtures")) {
            try {
                $path = Assert-C9StateFile -Path (Join-Path $state $name)
                if (-not (Test-Path -LiteralPath $path)) {
                    continue
                }
                $items = @(
                    Get-Item -LiteralPath $path -Force
                    Get-ChildItem -LiteralPath $path -Recurse -Force
                )
                if (@(
                    $items |
                        Where-Object {
                            ($_.Attributes -band
                                [System.IO.FileAttributes]::ReparsePoint) -ne 0
                        }
                ).Count -ne 0) {
                    throw "C9 emergency cleanup refuses a reparse point."
                }
                Remove-Item -LiteralPath $path -Recurse -Force
                $emergencyCleanup = $true
            } catch {
                Add-C9StopFailure -Phase "emergency_private_cleanup"
            }
        }
        try {
            $admissionPath = Assert-C9StateFile -Path (
                Join-Path $state "admission.json"
            )
            if (Test-Path -LiteralPath $admissionPath -PathType Leaf) {
                Remove-Item -LiteralPath $admissionPath -Force
                $emergencyCleanup = $true
            }
        } catch {
            Add-C9StopFailure -Phase "emergency_admission_cleanup"
        }
    }

    try {
        $remaining = @(
            Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalPort -in @(8765, 8766) }
        )
        if ($remaining.Count -gt 0) {
            throw "A C9 loopback port remains open after shutdown."
        }
    } catch {
        Add-C9StopFailure -Phase "ports_closed"
    }

    foreach ($name in $clear) {
        try {
            [Environment]::SetEnvironmentVariable($name, $null, "Process")
        } catch {
            Add-C9StopFailure -Phase "environment_cleanup"
        }
    }
}

$uncleared = @(
    $clear |
        Where-Object {
            $null -ne [Environment]::GetEnvironmentVariable($_, "Process")
        }
)
if ($uncleared.Count -ne 0) {
    Add-C9StopFailure -Phase "environment_cleanup"
}
$status = if ($cleanupFailures.Count -eq 0) {
    "stopped"
} else {
    "cleanup_incomplete"
}
$result = [pscustomobject]@{
    status = $status
    ports_closed = @(8765, 8766)
    coordinator_closed = $coordinatorClosed
    coordinator_close_receipt_recorded = $coordinatorCloseReceiptRecorded
    private_raw_responses_removed = $privateRawResponsesRemoved
    emergency_cleanup_performed = $emergencyCleanup
    transport_credentials_cleared = (
        $uncleared -notcontains "CONTROL_PLANE_API_KEY" -and
        $uncleared -notcontains "CONTROL_PLANE_TUNNEL_ID"
    )
    runtime_secrets_cleared = (
        $uncleared -notcontains "SLG_SHARED_SECRET" -and
        $uncleared -notcontains "SLG_MCP_TOKEN" -and
        $uncleared -notcontains "SLG_C9_CONTROL_TOKEN"
    )
    local_ai_configuration_cleared = (
        $uncleared -notcontains "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE" -and
        $uncleared -notcontains "SLG_C9_LOCAL_AI_ENDPOINT" -and
        $uncleared -notcontains "SLG_C9_LOCAL_AI_MODEL"
    )
    audit_key_preserved_for_final_receipts = (-not $ClearAuditKey)
    runtime_api_key_platform_revocation_required = $hadApiKey
    plugin_connection_removal_required = $hadTunnelAttempt
    native_chat_plugin_invoked = $false
    native_chat_provider_audit_correlation_claimed = $false
    cleanup_failures = @($cleanupFailures)
}
$result | ConvertTo-Json
if ($cleanupFailures.Count -ne 0) {
    throw (
        "C9 shutdown completed its fail-safe stop phase but cleanup is " +
        "incomplete: " + ($cleanupFailures -join ", ")
    )
}
