[CmdletBinding()]
param(
    [switch]$RequireCurrentTree,
    [switch]$RequireClean,
    [string]$FinalAttestationPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

$root = Get-C9RepositoryRoot
Assert-C9TrustedExecutionBoundary
$git = Get-C9GitExecutable
$branch = (
    @(
        Invoke-C9Git -Arguments @(
            "-C",
            $root,
            "branch",
            "--show-current"
        )
    ) -join "`n"
).Trim()
if (
    $LASTEXITCODE -ne 0 -or
    $branch -notin @("main", "codex/chatgpt-file-image-handoff-c9")
) {
    throw "C9 seal verification requires main or the reviewed C9 branch."
}
if (
    $RequireClean -and
    -not (Test-C9GitWorktreeClean -RepositoryRoot $root)
) {
    throw "C9 seal verification requires a clean worktree."
}

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    $python = (Get-Command python -ErrorAction Stop).Source
}
$arguments = @("-m", "systeme_local_gateway.c9_seal", "verify")
if ($RequireCurrentTree) {
    $arguments += "--require-current-tree"
}
if ($RequireClean) {
    $arguments += "--require-clean"
}
if ([string]::IsNullOrWhiteSpace($FinalAttestationPath)) {
    $FinalAttestationPath = Join-Path (Get-C9StateDirectory) "attestation.json"
}
if (
    [string]::IsNullOrWhiteSpace(
        [Environment]::GetEnvironmentVariable("SLG_AUDIT_KEY", "Process")
    )
) {
    throw "C9 live seal verification requires the process audit key."
}
$arguments += @(
    "--final-attestation",
    (Resolve-Path -LiteralPath $FinalAttestationPath).Path
)

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
    throw "C9 seal verification returned invalid JSON."
}
$parsed | ConvertTo-Json -Depth 12
if (
    $exitCode -ne 0 -or
    $parsed.status -cne "verified" -or
    $parsed.exact_attestation_reverified -ne $true -or
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
    $parsed.chat_export_descriptor_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
    $parsed.chat_picker_claim_receipt_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
    $parsed.provider_live_actions_performed -ne $true -or
    $parsed.revocation_verified -ne $true -or
    $parsed.automatic_chat_to_work_switch_used -ne $false -or
    $parsed.regular_use_readiness_claimed -ne $false
) {
    throw "C9 final seal verification failed."
}
