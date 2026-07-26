[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$PluginConnectionRemoved,
    [Parameter(Mandatory = $true)]
    [switch]$RuntimeApiKeyRevoked,
    [Parameter(Mandatory = $true)]
    [switch]$ManualCallFailedAfterRevocation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
$state = Get-C0StateDirectory
if ($null -ne (Read-C0Pid -Name "facade") -or $null -ne (Read-C0Pid -Name "tunnel")) {
    throw "Local C0 processes must be stopped before recording revocation."
}
$pending = Join-Path $state "live-proof-pending-revocation.json"
if (-not (Test-Path -LiteralPath $pending -PathType Leaf)) {
    throw "A correlated live proof is required before revocation."
}
if (
    -not $PluginConnectionRemoved -or
    -not $RuntimeApiKeyRevoked -or
    -not $ManualCallFailedAfterRevocation
) {
    throw (
        "Revocation requires explicit confirmation of Plugin removal, " +
        "Runtime API key revocation, and a failed post-revocation call."
    )
}

$receipt = [ordered]@{
    version = "1"
    source = "manual_chatgpt_web"
    plugin_connection_removed = $true
    runtime_api_key_revoked = $true
    tunnel_stopped = $true
    facade_stopped = $true
    post_revocation_call_failed = $true
    verified_at = [DateTimeOffset]::UtcNow.ToString("o")
}
$receipt | ConvertTo-Json | Set-Content -LiteralPath (
    Join-Path $state "revocation-receipt.json"
)
$receipt | ConvertTo-Json
