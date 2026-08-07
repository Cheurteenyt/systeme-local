[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedLocalPreparation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

if (-not $ConfirmedLocalPreparation) {
    throw "C9 preparation requires explicit confirmation of local-only preparation."
}
Assert-C9TrustedExecutionBoundary
Assert-C9GitState
Assert-C9LocalAIEnvironment
$root = Get-C9RepositoryRoot
$git = Get-C9GitExecutable
[Environment]::SetEnvironmentVariable(
    "SLG_C9_GIT_EXECUTABLE",
    $git,
    "Process"
)
$state = Initialize-C9StateDirectory
$gitConfig = Get-C9GitGlobalConfig
$unexpectedState = @(
    Get-ChildItem -LiteralPath $state -Force |
        Where-Object {
            -not $_.FullName.Equals(
                $gitConfig,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        }
)
if ($unexpectedState.Count -ne 0) {
    throw "C9 preparation requires an empty private C9 state directory."
}
foreach ($name in @(
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "SLG_AUDIT_ANCHOR_LOG",
    "SLG_AUDIT_ANCHOR_KEY"
)) {
    if ($null -ne [Environment]::GetEnvironmentVariable($name, "Process")) {
        throw "C9 local preparation refuses inherited remote or audit-anchor configuration."
    }
}
$binary = Assert-C9TunnelBinary
$initialized = @(Initialize-C9ProcessSecrets)

[pscustomobject]@{
    status = "locally_prepared"
    branch = "codex/chatgpt-file-image-handoff-c9"
    commit = Get-C9BuildCommit
    accepted_c8_commit = "bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5"
    state_directory = $state
    git_executable = $git
    tunnel_client_binary_sha256 = (
        Get-FileHash -LiteralPath $binary -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    process_secrets_initialized = $initialized
    inherited_process_secrets_reused = $false
    process_secrets_rotated = $true
    local_ai_configured = $true
    admission_created = $false
    effective_tool_count = 0
    runtime_api_key_created = $false
    tunnel_started = $false
    browser_action_performed = $false
} | ConvertTo-Json
