[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
$root = Get-C0RepositoryRoot
$state = Initialize-C0StateDirectory
$manifestPath = Join-Path $root "governance\c0-tunnel-client.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

if (
    $manifest.project -ne "openai/tunnel-client" -or
    $manifest.asset.url -notlike "https://github.com/openai/tunnel-client/*" -or
    $manifest.asset.sha256 -notmatch "^[0-9a-f]{64}$"
) {
    throw "Pinned tunnel-client manifest is invalid."
}

$download = Join-Path $state $manifest.asset.name
if (-not (Test-Path -LiteralPath $download -PathType Leaf)) {
    Invoke-WebRequest -Uri $manifest.asset.url -OutFile $download
}
$actualArchiveHash = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualArchiveHash -ne $manifest.asset.sha256) {
    throw "Downloaded tunnel-client archive failed SHA-256 verification."
}

$expanded = Join-Path $state ("expanded-" + $manifest.version)
if (-not (Test-Path -LiteralPath $expanded -PathType Container)) {
    New-Item -ItemType Directory -Path $expanded | Out-Null
    Expand-Archive -LiteralPath $download -DestinationPath $expanded
}
$executables = @(Get-ChildItem -LiteralPath $expanded -Recurse -File -Filter "tunnel-client.exe")
if ($executables.Count -ne 1) {
    throw "Expected exactly one tunnel-client.exe in the verified archive."
}

$bin = Join-Path $state "bin"
if (-not (Test-Path -LiteralPath $bin -PathType Container)) {
    New-Item -ItemType Directory -Path $bin | Out-Null
}
$destination = Join-Path $bin "tunnel-client.exe"
Copy-Item -LiteralPath $executables[0].FullName -Destination $destination -Force
$actualBinaryHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualBinaryHash -ne $manifest.binary_sha256) {
    throw "Installed tunnel-client binary failed SHA-256 verification."
}

$versionOutput = & $destination --version 2>&1
$expectedVersion = $manifest.version.TrimStart("v")
if (
    $LASTEXITCODE -ne 0 -or
    ($versionOutput -join "`n") -notmatch (
        "^" + [regex]::Escape($expectedVersion) + "[+ ]"
    )
) {
    throw "Installed tunnel-client did not report pinned version $($manifest.version)."
}

[pscustomobject]@{
    status = "prepared"
    project = $manifest.project
    version = $manifest.version
    archive_sha256 = $actualArchiveHash
    binary_sha256 = $actualBinaryHash
    binary = $destination
} | ConvertTo-Json
