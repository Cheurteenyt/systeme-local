[CmdletBinding()]
param(
    [switch]$PreserveAuditKeyForSeal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9GitState
Assert-C9AuditKeyEnvironment
$state = Get-C9StateDirectory
if (
    $null -ne (Read-C9Pid -Name "facade") -or
    $null -ne (Read-C9Pid -Name "facade-launcher") -or
    $null -ne (Read-C9Pid -Name "tunnel")
) {
    throw "Stop all C9 processes before final cleanup."
}
if (@(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in @(8765, 8766) }
).Count -ne 0) {
    throw "C9 final cleanup refuses a live C9 listener."
}
$attestationPath = Assert-C9StateFile -Path (
    Join-Path $state "attestation.json"
)
if (-not (Test-Path -LiteralPath $attestationPath -PathType Leaf)) {
    throw "C9 final cleanup requires the validated final attestation."
}
$activeAdmission = Assert-C9StateFile -Path (Join-Path $state "admission.json")
if (Test-Path -LiteralPath $activeAdmission) {
    throw "C9 final cleanup requires the active admission to remain revoked."
}
$attestation = Read-C9PrivateJson -Path $attestationPath
$python = Get-C9Python
$verifiedRaw = & $python -I -X utf8 `
    -m systeme_local_gateway.c9_attestation `
    verify-final `
    --metadata-root $state `
    --attestation $attestationPath
if ($LASTEXITCODE -ne 0) {
    throw "C9 final cleanup refuses an unauthenticated attestation."
}
try {
    $verifiedAttestation = ($verifiedRaw -join "`n") | ConvertFrom-Json
} catch {
    throw "C9 final cleanup received invalid attestation verification metadata."
}
if (
    $verifiedAttestation.status -cne $attestation.status -or
    $verifiedAttestation.attestation_sha256 -cne (
        $attestation.attestation_sha256
    ) -or
    $attestation.status -cne (
        "COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_" +
        "ATTACHMENTS_VERIFIED_AND_REVOKED"
    ) -or
    $attestation.work_rich_call_count -ne 1 -or
    $attestation.chat_manual_handoff_count -ne 1 -or
    $attestation.total_rich_mcp_call_count -ne 1 -or
    $attestation.work_rich_mcp_verified -ne $true -or
    $attestation.chat_manual_visible_handoff_verified -ne $true -or
    $attestation.same_sanitized_package_verified -ne $true -or
    $attestation.native_chat_plugin_invoked -ne $false -or
    $attestation.native_chat_provider_audit_correlation_claimed -ne $false -or
    $attestation.unapproved_fallback_used -ne $false -or
    $attestation.local_ai_loopback_receipt_committed -ne $true -or
    $attestation.local_ai_native_runtime_observation_committed -ne $true -or
    $attestation.chat_export_id -cnotmatch "^c9_export_[0-9a-f]{32}$" -or
    $attestation.chat_export_descriptor_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
    $attestation.chat_export_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
    $attestation.chat_picker_claim_receipt_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
    $attestation.revocation_verified -ne $true -or
    $verifiedAttestation.revocation_verified -ne $true
) {
    throw "C9 final cleanup refuses an invalid attestation."
}
$preserve = @(
    "attestation.json",
    "audit.jsonl",
    "chat-manual-proof.json",
    "combined-approval.json",
    "coordinator-close.json",
    "handoff-stage.json",
    "local-ai-runtime-observation.json",
    "local-probe-admitted.json",
    "local-probe-pre-admission.json",
    "negative-tests.json",
    "revocation.json",
    "tunnel-attempt.json",
    "web-steps.json",
    "work-rich-correlation.json",
    "work-proof.json"
)
$allItems = @(
    Get-Item -LiteralPath $state -Force
    Get-ChildItem -LiteralPath $state -Recurse -Force
)
if (@(
    $allItems |
        Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        }
).Count -ne 0) {
    throw "C9 final cleanup refuses a reparse point."
}
$removed = @()
foreach ($child in Get-ChildItem -LiteralPath $state -Force) {
    if ($child.Name -in $preserve) {
        continue
    }
    $resolved = [IO.Path]::GetFullPath($child.FullName)
    $prefix = [IO.Path]::GetFullPath($state) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith(
        $prefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing C9 cleanup outside the private state directory."
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    if (Test-Path -LiteralPath $resolved) {
        throw "C9 temporary state remains after cleanup."
    }
    $removed += $child.Name
}
$secretPattern = (
    "(?i)(Bearer\s+\S+|sk-[A-Za-z0-9_-]{20,}|" +
    "tunnel_[0-9a-f]{32}|(?:cookie|authorization)\s*[:=]\s*\S+|" +
    '"(?:paths|response_text|observed_image_nonce|observed_document_nonce)"\s*:)'
)
foreach ($name in $preserve) {
    $path = Join-Path $state $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        continue
    }
    $content = Get-Content -LiteralPath $path -Raw
    if ($content -match $secretPattern -or $content -match "C9[0-9A-F]{32}") {
        throw "Preserved C9 receipt contains secret or raw-proof material: $name"
    }
}
$environmentToClear = @(
    "SLG_SHARED_SECRET",
    "SLG_MCP_TOKEN",
    "SLG_C9_CONTROL_TOKEN",
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "SLG_C9_GIT_EXECUTABLE",
    "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE",
    "SLG_C9_LOCAL_AI_ENDPOINT",
    "SLG_C9_LOCAL_AI_MODEL"
)
if (-not $PreserveAuditKeyForSeal) {
    $environmentToClear += "SLG_AUDIT_KEY"
}
foreach ($name in $environmentToClear) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}
$uncleared = @(
    $environmentToClear |
        Where-Object {
            $null -ne [Environment]::GetEnvironmentVariable($_, "Process")
        }
)
if ($uncleared.Count -ne 0) {
    throw "C9 final cleanup could not clear its reviewed process environment."
}
if ($PreserveAuditKeyForSeal) {
    Assert-C9AuditKeyEnvironment
} elseif (
    $null -ne [Environment]::GetEnvironmentVariable(
        "SLG_AUDIT_KEY",
        "Process"
    )
) {
    throw "C9 final cleanup did not clear the audit key."
}

[pscustomobject]@{
    status = if ($PreserveAuditKeyForSeal) {
        "finalized_for_seal"
    } else {
        "finalized"
    }
    removed = @($removed | Sort-Object)
    preserved = @($preserve | Sort-Object)
    process_secrets_cleared = (-not $PreserveAuditKeyForSeal)
    non_audit_process_secrets_cleared = $true
    audit_key_preserved_for_seal = [bool]$PreserveAuditKeyForSeal
    cleanup_idempotent_after_seal = $true
    recoverable_local_metadata_evidence = $true
    raw_attachment_paths_absent_after_logical_cleanup = $true
    live_connectivity_recoverable = $false
} | ConvertTo-Json
