[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("a", "b")]
    [string]$TestChat
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
$state = Initialize-C1StateDirectory
$proof = Join-Path $state "proof-$TestChat.json"
if (Test-Path -LiteralPath $proof -PathType Leaf) {
    throw "Resolve or clean the existing C1 Chat $TestChat proof first."
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
    throw "Generated C1 challenge failed the documented C0 format invariant."
}
$other = if ($TestChat -eq "a") { "b" } else { "a" }
$otherPath = Join-Path $state "challenge-$other.txt"
if (
    (Test-Path -LiteralPath $otherPath -PathType Leaf) -and
    (Get-Content -LiteralPath $otherPath -Raw).Trim() -eq $challenge
) {
    throw "C1 generated a duplicate Chat challenge."
}
$path = Join-Path $state "challenge-$TestChat.txt"
$challenge | Set-Content -LiteralPath $path -NoNewline
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $digest = $sha256.ComputeHash(
        [Text.Encoding]::ASCII.GetBytes($challenge)
    )
} finally {
    $sha256.Dispose()
}

[pscustomobject]@{
    test_chat_label = "c1-test-chat-$TestChat"
    challenge = $challenge
    challenge_sha256 = (($digest | ForEach-Object { $_.ToString("x2") }) -join "")
    format = "documented bounded C0 challenge reuse"
    stored_at = $path
} | ConvertTo-Json
