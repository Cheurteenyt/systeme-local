[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
Assert-C0SecretEnvironment
$root = Get-C0RepositoryRoot
$state = Get-C0StateDirectory
$facadePid = Read-C0Pid -Name "facade"
if ($null -eq $facadePid) {
    throw "Start the C0 facade before the local probe."
}
Assert-C0LoopbackListener -ProcessId $facadePid -Port 8765

$challengePath = Join-Path $state "challenge.txt"
if (-not (Test-Path -LiteralPath $challengePath -PathType Leaf)) {
    throw "Generate a C0 challenge before the local probe."
}
$env:SLG_C0_CHALLENGE = (Get-Content -LiteralPath $challengePath -Raw).Trim()
$python = Join-Path $root ".venv\Scripts\python.exe"
try {
    $result = & $python -m systeme_local_gateway.c0_smoke
    if ($LASTEXITCODE -ne 0) {
        throw "Local C0 probe failed."
    }
} finally {
    Remove-Item Env:SLG_C0_CHALLENGE -ErrorAction SilentlyContinue
}
$json = ($result -join "`n") | ConvertFrom-Json
if (
    $json.status -ne "ok" -or
    @($json.tools).Count -ne 1 -or
    $json.tools[0] -ne "systeme_local_connectivity_probe"
) {
    throw "Local C0 result violated the one-tool invariant."
}
$result -join "`n" | Set-Content -LiteralPath (
    Join-Path $state "local-response.json"
)
$result -join "`n"
