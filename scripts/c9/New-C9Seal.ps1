[CmdletBinding(DefaultParameterSetName = "Seal")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Manifest")]
    [switch]$CreateManifest,

    [Parameter(Mandatory = $true, ParameterSetName = "Seal")]
    [switch]$CreateSeal,

    [Parameter(ParameterSetName = "Manifest")]
    [string]$FinalAttestationPath,

    [ValidatePattern("^[0-9A-Za-z_./-]+$")]
    [string]$CoveredHead = "HEAD"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9GitState
$root = Get-C9RepositoryRoot
$git = Get-C9GitExecutable
if (-not (Test-C9GitWorktreeClean -RepositoryRoot $root)) {
    throw "C9 seal metadata generation requires a clean worktree."
}
$python = Get-C9Python
$arguments = @("-m", "systeme_local_gateway.c9_seal")

if ($PSCmdlet.ParameterSetName -eq "Manifest") {
    Assert-C9AuditKeyEnvironment
    if ([string]::IsNullOrWhiteSpace($FinalAttestationPath)) {
        $FinalAttestationPath = Join-Path (Get-C9StateDirectory) "attestation.json"
    }
    $attestation = (Resolve-Path -LiteralPath $FinalAttestationPath).Path
    $arguments += @(
        "create-manifest",
        "--final-attestation",
        $attestation,
        "--covered-head",
        $CoveredHead
    )
}
else {
    $arguments += @(
        "create",
        "--covered-head",
        $CoveredHead
    )
}

$priorPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
$priorGitExecutable = [Environment]::GetEnvironmentVariable(
    "SLG_C9_GIT_EXECUTABLE",
    "Process"
)
try {
    [Environment]::SetEnvironmentVariable(
        "PYTHONPATH",
        (Join-Path $root "src"),
        "Process"
    )
    [Environment]::SetEnvironmentVariable(
        "SLG_C9_GIT_EXECUTABLE",
        $git,
        "Process"
    )
    $result = & $python @arguments
    $exitCode = $LASTEXITCODE
}
finally {
    [Environment]::SetEnvironmentVariable(
        "PYTHONPATH",
        $priorPythonPath,
        "Process"
    )
    [Environment]::SetEnvironmentVariable(
        "SLG_C9_GIT_EXECUTABLE",
        $priorGitExecutable,
        "Process"
    )
}

try {
    $parsed = ($result -join "`n") | ConvertFrom-Json
}
catch {
    throw "C9 seal metadata generation returned invalid JSON."
}
if ($exitCode -ne 0) {
    $parsed | ConvertTo-Json -Depth 12
    throw "C9 seal metadata generation failed closed."
}

if ($PSCmdlet.ParameterSetName -eq "Manifest") {
    if (
        $parsed.issue -ne 80 -or
        $parsed.reviewed_outcome -cne (
            "COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_" +
            "ATTACHMENTS_VERIFIED_AND_REVOKED"
        ) -or
        $parsed.work_rich_call_count -ne 1 -or
        $parsed.chat_manual_handoff_count -ne 1 -or
        $parsed.total_rich_mcp_call_count -ne 1 -or
        $parsed.work_rich_mcp_verified -ne $true -or
        $parsed.chat_manual_visible_handoff_verified -ne $true -or
        $parsed.same_sanitized_package_verified -ne $true -or
        $parsed.native_chat_plugin_invoked -ne $false -or
        $parsed.native_chat_provider_audit_correlation_claimed -ne $false -or
        $parsed.unapproved_fallback_used -ne $false -or
        $parsed.local_ai_loopback_receipt_committed -ne $true -or
        $parsed.local_ai_native_runtime_observation_committed -ne $true -or
        $parsed.chat_export_id_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
        $parsed.chat_export_descriptor_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
        $parsed.chat_export_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
        $parsed.chat_picker_claim_receipt_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
        $parsed.provider_live_actions_performed -ne $true -or
        $parsed.regular_arbitrary_files_tested -ne $false -or
        $parsed.regular_use_readiness_claimed -ne $false -or
        $parsed.automatic_chat_to_work_switch_used -ne $false -or
        $parsed.revocation_verified -ne $true -or
        $parsed.raw_sensitive_evidence_versioned -ne $false -or
        @($parsed.changed_files) -notcontains "governance/c9-change-manifest.json" -or
        @($parsed.changed_files) -contains "governance/c9-change-seal.json"
    ) {
        throw "C9 manifest generation returned an invalid live boundary."
    }
}
elseif (
    $parsed.validation_status -cne (
        "C9_WORK_RICH_MCP_AND_CHAT_MANUAL_LIVE_EVIDENCE_SEALED"
    ) -or
    $parsed.work_rich_call_count -ne 1 -or
    $parsed.chat_manual_handoff_count -ne 1 -or
    $parsed.total_rich_mcp_call_count -ne 1 -or
    $parsed.work_rich_mcp_verified -ne $true -or
    $parsed.chat_manual_visible_handoff_verified -ne $true -or
    $parsed.same_sanitized_package_verified -ne $true -or
    $parsed.native_chat_plugin_invoked -ne $false -or
    $parsed.native_chat_provider_audit_correlation_claimed -ne $false -or
    $parsed.unapproved_fallback_used -ne $false -or
    $parsed.chat_export_descriptor_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
    $parsed.chat_picker_claim_receipt_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
    $parsed.provider_live_actions_performed -ne $true -or
    $parsed.revocation_verified -ne $true -or
    $parsed.automatic_chat_to_work_switch_used -ne $false -or
    $parsed.regular_arbitrary_files_tested -ne $false -or
    $parsed.raw_sensitive_evidence_versioned -ne $false -or
    $parsed.regular_use_readiness_claimed -ne $false
) {
    throw "C9 seal generation returned an invalid completion boundary."
}

$parsed | ConvertTo-Json -Depth 12
