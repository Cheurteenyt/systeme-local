[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
$state = Initialize-C0StateDirectory
if (Test-Path -LiteralPath (
    Join-Path $state "live-proof-pending-revocation.json"
) -PathType Leaf) {
    throw "Resolve or clean the pending live proof before replacing its challenge."
}
$bytes = [byte[]]::new(16)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($bytes)
} finally {
    $rng.Dispose()
}
$challenge = "c0_" + (
    ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
)
if ($challenge -notmatch "^c0_[0-9a-f]{32}$") {
    throw "Generated C0 challenge failed its format invariant."
}
$path = Join-Path $state "challenge.txt"
$challenge | Set-Content -LiteralPath $path -NoNewline

$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $challengeDigest = $sha256.ComputeHash(
        [Text.Encoding]::ASCII.GetBytes($challenge)
    )
} finally {
    $sha256.Dispose()
}

[pscustomobject]@{
    challenge = $challenge
    challenge_sha256 = (
        ($challengeDigest | ForEach-Object { $_.ToString("x2") }) -join ""
    )
    stored_at = $path
} | ConvertTo-Json
