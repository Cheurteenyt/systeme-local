[CmdletBinding()]
param(
    [ValidateSet(0, 1)]
    [int]$ExpectedToolCount = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9GitState
Assert-C9SecretEnvironment
$state = Initialize-C9StateDirectory
$facadePid = Read-C9Pid -Name "facade"
if ($null -eq $facadePid) {
    throw "Start the C9 facade before the local MCP probe."
}
Assert-C9LoopbackListener -ProcessId $facadePid -Port 8765
if ($ExpectedToolCount -eq 1) {
    [void](Get-C9AdmissionDecision)
}

$python = Get-C9Python
$result = & $python -m systeme_local_gateway.mcp_smoke `
    --url "http://127.0.0.1:8765/mcp" `
    --timeout-seconds 10
if ($LASTEXITCODE -ne 0) {
    throw "Local C9 MCP probe failed."
}
$json = ($result -join "`n") | ConvertFrom-Json
$tools = @($json.tools)
if ($json.status -ne "ok" -or $tools.Count -ne $ExpectedToolCount) {
    throw "Local C9 probe returned an unexpected tool count."
}
if (
    $ExpectedToolCount -eq 1 -and
    $tools[0] -ne "systeme_local_attachment_handoff"
) {
    throw "Local C9 admitted probe did not expose the exact handoff tool."
}
if (
    $ExpectedToolCount -eq 0 -and
    $tools -contains "systeme_local_connectivity_probe"
) {
    throw "Local C9 pre-admission probe exposed the forbidden C0 capability."
}

$evidenceName = if ($ExpectedToolCount -eq 0) {
    "local-probe-pre-admission.json"
} else {
    "local-probe-admitted.json"
}
[void](Write-C9MetadataReceipt `
    -Path (Assert-C9StateFile -Path (Join-Path $state $evidenceName)) `
    -Receipt $json `
    -AllowOverwrite)
$result -join "`n"
