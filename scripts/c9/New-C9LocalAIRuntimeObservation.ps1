[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("ollama", "lm_studio", "other_reviewed_native")]
    [string]$ProviderKind,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedNativeRuntime,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedRuntimeRequestLoggingDisabled,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedRuntimeRequestPersistenceDisabled,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmedRuntimePrivacySettings
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

if (-not (
    $ConfirmedNativeRuntime -and
    $ConfirmedRuntimeRequestLoggingDisabled -and
    $ConfirmedRuntimeRequestPersistenceDisabled -and
    $ConfirmedRuntimePrivacySettings
)) {
    throw "C9 requires every exact native-runtime and privacy confirmation."
}
Assert-C9GitState
Assert-C9SecretEnvironment
Assert-C9LocalAIEnvironment
$root = Get-C9RepositoryRoot
$state = Initialize-C9StateDirectory
$receiptPath = Assert-C9StateFile -Path (
    Join-Path $state "local-ai-runtime-observation.json"
)
if (Test-Path -LiteralPath $receiptPath) {
    throw "A C9 local-AI runtime observation already exists; replay refused."
}
if (
    $null -ne (Read-C9Pid -Name "facade") -or
    $null -ne (Read-C9Pid -Name "facade-launcher") -or
    $null -ne (Read-C9Pid -Name "tunnel")
) {
    throw "Observe the local-AI runtime before starting any C9 process."
}

$endpoint = [Environment]::GetEnvironmentVariable(
    "SLG_C9_LOCAL_AI_ENDPOINT",
    "Process"
)
$model = [Environment]::GetEnvironmentVariable(
    "SLG_C9_LOCAL_AI_MODEL",
    "Process"
)
$uri = [Uri]$endpoint
$listeners = @(
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq $uri.Port }
)
if (
    $listeners.Count -ne 1 -or
    $listeners[0].LocalAddress -cne "127.0.0.1"
) {
    throw (
        "C9 requires exactly one native local-AI listener on the configured " +
        "literal IPv4 loopback endpoint."
    )
}
$runtimeProcess = Get-Process -Id $listeners[0].OwningProcess -ErrorAction Stop
$executablePath = [IO.Path]::GetFullPath($runtimeProcess.Path)
Assert-C9NotReparsePoint -Path $executablePath
if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
    throw "The observed local-AI executable is unavailable."
}
$productMetadata = Get-C9NativeRuntimeProductMetadata `
    -Path $executablePath `
    -FallbackName ([string]$runtimeProcess.ProcessName)
$productName = [string]$productMetadata.product_name
$productVersion = [string]$productMetadata.product_version

$cycleId = "c9_cycle_" + [Guid]::NewGuid().ToString("N")
$observedAt = [DateTimeOffset]::UtcNow
$expiresAt = $observedAt.AddMinutes(20)
$python = Get-C9Python
$arguments = @(
    "-m", "systeme_local_gateway.c9_local_ai",
    "commit-runtime-observation",
    "--cycle-id", $cycleId,
    "--provider-kind", $ProviderKind,
    "--product-name", $productName,
    "--product-version", $productVersion,
    "--listening-pid", [string]$runtimeProcess.Id,
    "--executable-path", $executablePath,
    "--endpoint", $endpoint,
    "--visible-model-label", $model,
    "--observed-at", $observedAt.ToString("o"),
    "--expires-at", $expiresAt.ToString("o"),
    "--confirmed-native-runtime",
    "--confirmed-runtime-request-logging-disabled",
    "--confirmed-runtime-request-persistence-disabled",
    "--confirmed-runtime-privacy-settings"
)
$result = & $python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "C9 native local-AI runtime observation validation failed."
}
try {
    $receipt = ($result -join "`n") | ConvertFrom-Json
} catch {
    throw "C9 native local-AI runtime observation returned invalid metadata."
}
if (
    $receipt.cycle_id -cne $cycleId -or
    $receipt.product_name -cne $productName -or
    $receipt.product_version -cne $productVersion -or
    $receipt.listening_pid -ne $runtimeProcess.Id -or
    $receipt.simulated -ne $false -or
    $receipt.operator_confirmed_native_runtime -ne $true -or
    $receipt.operator_confirmed_runtime_privacy_settings -ne $true -or
    $receipt.process_identity_observation -cne
        "operator_attested_not_programmatically_verified"
) {
    throw "C9 native local-AI runtime observation crossed its reviewed boundary."
}
if (
    $null -ne $productMetadata.fallback_binary_sha256 -and
    $receipt.executable_sha256 -cne
        [string]$productMetadata.fallback_binary_sha256
) {
    throw "C9 native local-AI fallback version does not bind the executable."
}
[void](Write-C9MetadataReceipt -Path $receiptPath -Receipt $receipt)
[Environment]::SetEnvironmentVariable(
    "SLG_C9_LOCAL_AI_RUNTIME_OBSERVATION_FILE",
    $receiptPath,
    "Process"
)
$receipt | ConvertTo-Json -Depth 12
