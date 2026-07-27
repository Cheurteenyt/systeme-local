[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
$state = Get-C1StateDirectory
if (
    $null -ne (Read-C1Pid -Name "facade") -or
    $null -ne (Read-C1Pid -Name "facade-launcher") -or
    $null -ne (Read-C1Pid -Name "tunnel")
) {
    throw "Stop all C1 processes before final cleanup."
}
$attestation = Join-Path $state "attestation.json"
if (-not (Test-Path -LiteralPath $attestation -PathType Leaf)) {
    throw "C1 final cleanup requires the validated final attestation."
}
$preserve = @(
    "attestation.json",
    "negative-tests.json",
    "proof-a.json",
    "proof-b.json",
    "revocation.json",
    "runtime-setup.json",
    "surface-a.json",
    "surface-b.json",
    "visible-model.json"
)
$removed = @()
foreach ($child in Get-ChildItem -LiteralPath $state -Force) {
    if ($child.Name -in $preserve) {
        continue
    }
    $resolved = [System.IO.Path]::GetFullPath($child.FullName)
    $prefix = [System.IO.Path]::GetFullPath($state) +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith(
        $prefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing C1 cleanup outside the private state directory."
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    $removed += $child.Name
}
$secretPattern = (
    "(?i)(Bearer\s+\S+|(?:sk|gh[opusr])_[A-Za-z0-9_-]{8,}|" +
    "(?:cookie|authorization)\s*[:=]\s*\S+)"
)
foreach ($name in $preserve) {
    $path = Join-Path $state $name
    if ((Get-Content -LiteralPath $path -Raw) -match $secretPattern) {
        throw "Preserved C1 receipt contains a secret-like value: $name"
    }
}
foreach ($name in @(
    "SLG_AUDIT_KEY",
    "SLG_SHARED_SECRET",
    "SLG_MCP_TOKEN",
    "CONTROL_PLANE_API_KEY",
    "CONTROL_PLANE_TUNNEL_ID",
    "SLG_PROVIDER_RUNTIME_MODE",
    "SLG_PROVIDER_RUNTIME_ROOT"
)) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    status = "finalized"
    removed = @($removed | Sort-Object)
    preserved = @($preserve | Sort-Object)
    process_secrets_cleared = $true
    recoverable = $false
} | ConvertTo-Json
