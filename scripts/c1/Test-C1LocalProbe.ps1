[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState
Assert-C1SecretEnvironment
$root = Get-C1RepositoryRoot
$state = Initialize-C1StateDirectory
$facadePid = Read-C1Pid -Name "facade"
if ($null -eq $facadePid) {
    throw "Start the C1 facade before the local probe."
}
Assert-C1LoopbackListener -ProcessId $facadePid -Port 8765

$bytes = [byte[]]::new(16)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($bytes)
} finally {
    $rng.Dispose()
}
$env:SLG_C0_CHALLENGE = (
    "c0_" + (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
)
$python = Join-Path $root ".venv\Scripts\python.exe"
try {
    $result = & $python -m systeme_local_gateway.c0_smoke
    if ($LASTEXITCODE -ne 0) {
        throw "Local C1 probe failed."
    }
} finally {
    Remove-Item Env:SLG_C0_CHALLENGE -ErrorAction SilentlyContinue
}
$json = ($result -join "`n") | ConvertFrom-Json
if (
    $json.status -ne "ok" -or
    @($json.tools).Count -ne 1 -or
    $json.tools[0] -ne "systeme_local_connectivity_probe" -or
    $json.response.read_only -ne $true -or
    $json.response.write_actions_enabled -ne $false -or
    $json.response.real_evidence_access -ne $false -or
    $json.response.protocol_v2_reachable -ne $false
) {
    throw "Local C1 result violated the exact one-tool safety invariant."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "local-response.json"
)
$result -join "`n"
