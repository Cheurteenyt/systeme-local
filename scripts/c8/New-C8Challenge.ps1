[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("a", "b")]
    [string]$TestWork
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

Assert-C8GitState
$state = Initialize-C8StateDirectory
if (Test-Path -LiteralPath (Join-Path $state "proof-$TestWork.json")) {
    throw "Resolve or clean the existing C8 Work $TestWork proof first."
}
$bytes = [byte[]]::new(16)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($bytes)
} finally {
    $rng.Dispose()
}
$challenge = "c0_" + (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
if ($challenge -notmatch "^c0_[0-9a-f]{32}$") {
    throw "Generated C8 challenge failed the reviewed C0 format."
}
$other = if ($TestWork -eq "a") { "b" } else { "a" }
$otherPath = Join-Path $state "challenge-$other.txt"
if (
    (Test-Path -LiteralPath $otherPath -PathType Leaf) -and
    (Get-Content -LiteralPath $otherPath -Raw).Trim() -eq $challenge
) {
    throw "C8 generated a duplicate Work challenge."
}
$path = Join-Path $state "challenge-$TestWork.txt"
$challenge | Set-Content -LiteralPath $path -NoNewline
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $digest = $sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes($challenge))
} finally {
    $sha256.Dispose()
}

[pscustomobject]@{
    test_work_label = "c8-test-work-$TestWork"
    challenge = $challenge
    challenge_sha256 = (($digest | ForEach-Object { $_.ToString("x2") }) -join "")
    format = "documented bounded C0 challenge reuse"
    stored_at = $path
} | ConvertTo-Json
