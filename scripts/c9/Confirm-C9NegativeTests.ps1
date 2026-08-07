[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9GitState
Assert-C9AuditKeyEnvironment
$root = Get-C9RepositoryRoot
$state = Initialize-C9StateDirectory
foreach ($name in @(
    "combined-approval.json",
    "work-proof.json",
    "chat-manual-proof.json",
    "coordinator-close.json"
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $state $name) -PathType Leaf)) {
        throw "C9 automated negative tests require completed evidence: $name"
    }
}
if (
    $null -ne (Read-C9Pid -Name "facade") -or
    $null -ne (Read-C9Pid -Name "facade-launcher") -or
    $null -ne (Read-C9Pid -Name "tunnel")
) {
    throw "C9 automated negative tests require stopped processes."
}
$receiptPath = Assert-C9StateFile -Path (
    Join-Path $state "negative-tests.json"
)
if (Test-Path -LiteralPath $receiptPath) {
    throw "C9 automated negative-test receipt already exists; replay refused."
}
$arguments = @(
    "-I",
    "-X", "utf8",
    "-m", "systeme_local_gateway.c9_attestation",
    "run-negative",
    "--metadata-root", $state,
    "--admission", (Join-Path $state "combined-approval.json"),
    "--close", (Join-Path $state "coordinator-close.json"),
    "--repository-root", $root
)
$python = Get-C9Python
$result = & $python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "C9 automated negative-test execution or validation failed."
}
try {
    $receipt = ($result -join "`n") | ConvertFrom-Json
} catch {
    throw "C9 automated negative-test receipt returned invalid metadata."
}
if (
    $receipt.source -cne "automated_bounded_c9_negative_tests" -or
    $receipt.simulated -ne $false -or
    $receipt.capability_expanded -ne $false -or
    $receipt.work_task_count -ne 1 -or
    $receipt.native_chat_task_count -ne 1 -or
    $receipt.work_rich_mcp_call_count -ne 1 -or
    $receipt.native_chat_manual_handoff_count -ne 1 -or
    $receipt.total_rich_mcp_call_count -ne 1 -or
    $receipt.native_chat_delivery_mode -cne
        "operator_performed_manual_attachment_handoff" -or
    $receipt.native_chat_plugin_invoked -ne $false -or
    $receipt.native_chat_provider_audit_correlation_claimed -ne $false -or
    $receipt.unapproved_fallback_used -ne $false -or
    $receipt.automatic_chat_to_work_switch_used -ne $false -or
    $receipt.regular_arbitrary_files_tested -ne $false -or
    $receipt.automated_suite.source -cne "isolated_pytest_subprocess" -or
    $receipt.automated_suite.suite_id -cne "c9_bounded_negative_contract_v1" -or
    $receipt.automated_suite.exit_code -ne 0 -or
    $receipt.automated_suite.failed_count -ne 0 -or
    $receipt.automated_suite.skipped_count -ne 0 -or
    $receipt.automated_suite.passed_count -lt
        @($receipt.automated_suite.node_ids).Count
) {
    throw "C9 automated negative-test receipt crossed its bounded claim."
}
[void](Write-C9MetadataReceipt -Path $receiptPath -Receipt $receipt)
$receipt | ConvertTo-Json -Depth 16
