[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedNoRemoteOrWorkActions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

if (-not $ConfirmedNoRemoteOrWorkActions) {
    throw "C8 local-only reset requires confirmation of zero remote or Work actions."
}
Assert-C8GitState
$state = Get-C8StateDirectory
if (
    $null -ne (Read-C8Pid -Name "facade") -or
    $null -ne (Read-C8Pid -Name "facade-launcher") -or
    $null -ne (Read-C8Pid -Name "tunnel")
) {
    throw "C8 local-only reset refuses tracked processes."
}
if (@(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(8765, 8766) }
).Count -ne 0) {
    throw "C8 local-only reset refuses active listeners on C8 ports."
}

$remoteEvidence = @(
    "attestation.json",
    "challenge-a.txt",
    "challenge-b.txt",
    "negative-tests.json",
    "proof-a.json",
    "proof-b.json",
    "response-a.json",
    "response-b.json",
    "revocation.json",
    "task-surface-a.json",
    "task-surface-b.json",
    "tunnel.pid"
)
foreach ($name in $remoteEvidence) {
    if (Test-Path -LiteralPath (Join-Path $state $name)) {
        throw "C8 local-only reset refuses remote or Work evidence: $name"
    }
}

$allowed = @(
    "approvals.sqlite3",
    "audit.jsonl",
    "audit.jsonl.lock",
    "authorization.json",
    "facade.stderr.log",
    "facade.stdout.log",
    "live-cycle.json",
    "local-response.json",
    "replay.sqlite3",
    "work-quota.json",
    "work-surface.json"
)
$required = @(
    "audit.jsonl",
    "authorization.json",
    "live-cycle.json",
    "local-response.json",
    "work-quota.json",
    "work-surface.json"
)
foreach ($name in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $state $name) -PathType Leaf)) {
        throw "C8 local-only reset input is missing: $name"
    }
}

$children = @(Get-ChildItem -LiteralPath $state -Force)
$unexpected = @($children | Where-Object { $_.Name -notin $allowed })
if ($unexpected.Count -ne 0) {
    $names = ($unexpected.Name | Sort-Object) -join ", "
    throw "C8 local-only reset refuses unexpected state: $names"
}

$auditLines = @(
    Get-Content -LiteralPath (Join-Path $state "audit.jsonl") |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
)
if ($auditLines.Count -ne 1) {
    throw "C8 local-only reset requires exactly one local probe audit record."
}
try {
    $audit = $auditLines[0] | ConvertFrom-Json
    $response = Get-Content -LiteralPath (
        Join-Path $state "local-response.json"
    ) -Raw | ConvertFrom-Json
} catch {
    throw "C8 local-only reset could not parse the local probe evidence."
}
$tools = @($response.tools)
if (
    $audit.status -ne "completed" -or
    $audit.capability -ne "systeme_local_connectivity_probe" -or
    $response.status -ne "ok" -or
    $tools.Count -ne 1 -or
    $tools[0] -ne "systeme_local_connectivity_probe" -or
    $response.response.audit_correlation -ne $audit.audit_id -or
    $response.response.read_only -ne $true -or
    $response.response.write_actions_enabled -ne $false -or
    $response.response.real_evidence_access -ne $false -or
    $response.response.protocol_v2_reachable -ne $false
) {
    throw "C8 local-only reset refuses non-local or unsafe probe evidence."
}

$removed = @()
$prefix = [System.IO.Path]::GetFullPath($state) +
    [System.IO.Path]::DirectorySeparatorChar
foreach ($child in $children) {
    $resolved = [System.IO.Path]::GetFullPath($child.FullName)
    if (-not $resolved.StartsWith(
        $prefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing C8 local-only reset outside the private state directory."
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    $removed += $child.Name
}

foreach ($name in @(
    "SLG_AUDIT_KEY",
    "SLG_SHARED_SECRET",
    "SLG_MCP_TOKEN",
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "SLG_PROVIDER_RUNTIME_MODE",
    "SLG_PROVIDER_RUNTIME_ROOT",
    "SLG_C8_LIVE_CYCLE_FILE"
)) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    status = "local_only_reset"
    verified_local_probe_count = 1
    removed = @($removed | Sort-Object)
    process_secrets_cleared = $true
    live_correlated_evidence_removed = $false
    local_probe_evidence_removed = $true
    runtime_api_key_platform_revocation_required = $true
    tunnel_resource_reusable = $true
} | ConvertTo-Json
