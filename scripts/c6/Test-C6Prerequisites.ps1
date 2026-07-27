[CmdletBinding()]
param(
    [switch]$AllowDirty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C6.Common.psm1") -Force

Assert-C6GitState -AllowDirty:$AllowDirty
Assert-C6OfflineBoundary

$invocation = Invoke-C6PythonCommand -Arguments @(
    "-m",
    "systeme_local_gateway.c6_revalidation",
    "verify",
    "--root",
    (Get-C6RepositoryRoot),
    "--policy",
    (Get-C6PolicyPath),
    "--c3-registry",
    (Get-C6C3RegistryPath),
    "--expect-all-denied"
)
$status = ConvertFrom-C6JsonResult `
    -Invocation $invocation `
    -Operation "prerequisite verification"
if ($invocation.exit_code -notin @(0, 5)) {
    throw "C6 prerequisite verification failed closed."
}

[pscustomobject]@{
    status = "ready_for_official_docs_only"
    branch = (& git -C (Get-C6RepositoryRoot) branch --show-current).Trim()
    commit = (& git -C (Get-C6RepositoryRoot) rev-parse HEAD).Trim()
    policy_sha256 = $status.policy_sha256
    policy_lifecycle = $status.policy_lifecycle
    c3_final_status = $status.c3_final_status
    live_actions_allowed = $status.live_actions_allowed
    sensitive_process_variables = 0
    c0_c1_listeners = 0
    tunnel_client_processes = 0
} | ConvertTo-Json -Depth 6
