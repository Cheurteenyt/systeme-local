[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedExactScope
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C8.Common.psm1") -Force

if (-not $ConfirmedExactScope) {
    throw "C8 preparation requires exact cycle-wide operator authorization."
}
Assert-C8GitState
$root = Get-C8RepositoryRoot
$state = Initialize-C8StateDirectory
$authorizationPath = Join-Path $state "authorization.json"
if (Test-Path -LiteralPath $authorizationPath -PathType Leaf) {
    throw "An existing C8 authorization receipt must be resolved before a new cycle."
}

$initialized = @()
foreach ($name in @("SLG_SHARED_SECRET", "SLG_AUDIT_KEY", "SLG_MCP_TOKEN")) {
    $existing = [Environment]::GetEnvironmentVariable($name, "Process")
    if (-not [string]::IsNullOrWhiteSpace($existing)) {
        if ($existing.Length -lt 32) {
            throw "$name is already set but fails the C8 minimum length."
        }
        continue
    }
    $bytes = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    [Environment]::SetEnvironmentVariable(
        $name,
        [Convert]::ToBase64String($bytes),
        "Process"
    )
    $initialized += $name
}
Assert-C8SecretEnvironment
[void](Assert-C8TunnelBinary)

$cycleBytes = [byte[]]::new(16)
$cycleRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $cycleRng.GetBytes($cycleBytes)
} finally {
    $cycleRng.Dispose()
}
$cycleId = "c8_cycle_" + (
    ($cycleBytes | ForEach-Object { $_.ToString("x2") }) -join ""
)
$expiresAt = [DateTime]::UtcNow.AddHours(24).ToString("o")
$python = Join-Path $root ".venv\Scripts\python.exe"
$result = & $python -m systeme_local_gateway.c8_live_cycle authorize `
    --cycle-id $cycleId `
    --expires-at $expiresAt `
    --confirmed-exact-scope
if ($LASTEXITCODE -ne 0) {
    throw "C8 operator authorization receipt creation failed."
}
$result -join "`n" | Set-Content -LiteralPath $authorizationPath

[pscustomobject]@{
    status = "authorized_and_prepared"
    cycle_id = $cycleId
    authorization_scope = "Work and Plugins only; at most two synthetic Work tasks"
    authorization_receipt = $authorizationPath
    state_directory = $state
    process_secrets_initialized = $initialized
    runtime_api_key_created = $false
    tunnel_started = $false
    browser_or_work_action_performed = $false
} | ConvertTo-Json
