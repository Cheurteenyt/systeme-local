[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "work_surface_opened_without_prompt",
        "codex_surface_opened_without_prompt",
        "unknown_surface_detected",
        "existing_chat_or_history_accessed",
        "private_browser_state_accessed",
        "unexpected_prompt_or_tool_invocation",
        "other_bounded_scope_violation"
    )]
    [string]$Violation,
    [Parameter(Mandatory = $true)]
    [switch]$TestTabsClosed,
    [Parameter(Mandatory = $true)]
    [switch]$PluginConnectionRemoved,
    [Parameter(Mandatory = $true)]
    [switch]$RuntimeApiKeyRevoked
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
if (-not $TestTabsClosed) {
    throw "Scope-violation rejection requires all C1 test tabs closed."
}
if (-not $PluginConnectionRemoved) {
    throw "Scope-violation rejection requires the temporary Plugin removed."
}
if (-not $RuntimeApiKeyRevoked) {
    throw "Scope-violation rejection requires the Runtime API key revoked."
}

$state = Get-C1StateDirectory
if (
    $null -ne (Read-C1Pid -Name "facade") -or
    $null -ne (Read-C1Pid -Name "facade-launcher") -or
    $null -ne (Read-C1Pid -Name "tunnel")
) {
    throw "Stop all C1 processes before rejecting a scope-violation cycle."
}
$listeners = @(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(8765, 8766) }
)
if ($listeners.Count -gt 0) {
    throw "C1 loopback listeners remain open."
}
if (Test-Path -LiteralPath (Join-Path $state "attestation.json") -PathType Leaf) {
    throw "A validated C1 attestation must use final cleanup, not scope rejection."
}

$typedEvidence = @()
foreach ($name in @(
    "runtime-setup.json",
    "visible-model.json",
    "surface-a.json",
    "surface-b.json",
    "proof-a.json",
    "proof-b.json",
    "negative-tests.json",
    "revocation.json"
)) {
    if (Test-Path -LiteralPath (Join-Path $state $name) -PathType Leaf) {
        $typedEvidence += $name
    }
}
if ($typedEvidence.Count -eq 0) {
    throw "Scope-violation rejection requires typed C1 evidence from an active cycle."
}

$auditRecords = 0
$auditPath = Join-Path $state "audit.jsonl"
if (Test-Path -LiteralPath $auditPath -PathType Leaf) {
    $auditRecords = @(
        Get-Content -LiteralPath $auditPath |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    ).Count
}

$removed = @()
if (Test-Path -LiteralPath $state -PathType Container) {
    foreach ($child in Get-ChildItem -LiteralPath $state -Force) {
        $resolved = [System.IO.Path]::GetFullPath($child.FullName)
        $prefix = [System.IO.Path]::GetFullPath($state) +
            [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolved.StartsWith(
            $prefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Refusing scope-violation cleanup outside the private C1 state directory."
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
        $removed += $child.Name
    }
}
foreach ($name in @(
    "SLG_AUDIT_KEY",
    "SLG_SHARED_SECRET",
    "SLG_MCP_TOKEN",
    "SLG_MCP_AUTHORIZATION",
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID"
)) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    status = "scope_violation_cycle_rejected"
    reason = $Violation
    typed_evidence = @($typedEvidence | Sort-Object)
    audit_records_discarded = $auditRecords
    removed = @($removed | Sort-Object)
    test_tabs_closed = [bool]$TestTabsClosed
    plugin_connection_removed = [bool]$PluginConnectionRemoved
    runtime_api_key_revoked = [bool]$RuntimeApiKeyRevoked
    listeners_closed = $true
    process_secrets_cleared = $true
    recoverable = $false
} | ConvertTo-Json
