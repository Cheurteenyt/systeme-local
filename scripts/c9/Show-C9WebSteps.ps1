[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HandoffId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C9.Common.psm1") -Force

Assert-C9GitState
[void](Assert-C9Identifier -Value $HandoffId -Kind handoff)
$state = Initialize-C9StateDirectory
$stage = Read-C9PrivateJson -Path (Join-Path $state "handoff-stage.json")
$approval = Read-C9PrivateJson -Path (Join-Path $state "combined-approval.json")
if (
    $stage.handoff_id -cne $HandoffId -or
    $approval.handoff_id -cne $HandoffId
) {
    throw "C9 web steps target another handoff."
}
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$stage.expires_at) `
    -EvidenceName "C9 staged handoff")
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$approval.combined_approval.expires_at) `
    -EvidenceName "C9 combined approval")
[void](Assert-C9FreshExpiration `
    -ExpiresAt ([string]$approval.live_cycle_bundle.grant.expires_at) `
    -EvidenceName "C9 live grant")
$surfaceObservation = $approval.live_cycle_bundle.surface_observation
if (
    $surfaceObservation.work_surface_visible -ne $true -or
    $surfaceObservation.explicit_work_selected -ne $true -or
    $surfaceObservation.work_plugin_mcp_app_visible -ne $true -or
    $surfaceObservation.work_plugin_mcp_app_eligible -ne $true -or
    $surfaceObservation.work_plugin_mcp_app_selectable -ne $true -or
    $surfaceObservation.native_chat_surface_visible -ne $true -or
    $surfaceObservation.explicit_native_chat_selected -ne $true -or
    $surfaceObservation.native_chat_attachment_control_visible -ne $true -or
    $surfaceObservation.native_chat_file_picker_visible -ne $true -or
    $surfaceObservation.native_chat_manual_attachment_handoff_available -ne
        $true -or
    $surfaceObservation.native_chat_manual_attachment_handoff_used -ne $false
) {
    throw (
        "C9 primary web steps require one explicit Work Plugin/MCP surface " +
        "and one explicit native Chat surface with its manual attachment " +
        "control visible before either prompt is sent."
    )
}
$stepsPath = Assert-C9StateFile -Path (Join-Path $state "web-steps.json")
if (Test-Path -LiteralPath $stepsPath) {
    throw "C9 web prompts were already committed for this handoff; replay refused."
}

$workPrompt = @"
You are explicitly in ChatGPT Work. Select the reviewed Plugin/MCP app, then use exactly its systeme_local_attachment_handoff tool once with this exact JSON argument:
{"handoff_id":"$HandoffId","surface":"work"}
Do not use any other tool, do not open Chat, and do not switch surfaces. Inspect the returned image and embedded UTF-8 text resource. Then reply with exactly one JSON object and no Markdown:
{"handoff_id":"$HandoffId","surface":"work","surface_task_id":"<the exact surface_task_id from the tool result>","expansion_descriptor_sha256":"<the exact expansion_descriptor_sha256 from the tool result>","manifest_sha256":"<the exact surface_manifest_sha256 from the tool result>","observed_image_nonce":"<the exact C9 nonce visible in the image>","observed_document_nonce":"<the exact C9 nonce in the text resource>"}
"@.Trim()

$chatPrompt = @"
You are explicitly in one new normal Chat conversation, not Work. No Plugin/MCP app is available or allowed for this step. The operator will attach exactly one generated synthetic image and one generated UTF-8 text document through the visible file picker.
Do not use any tool, do not switch to Work, and do not inspect any other conversation or file. After both attachments are visibly present, inspect only those two attachments. Then reply with exactly one JSON object and no Markdown:
{"delivery_mode":"operator_performed_manual_attachment_handoff","handoff_id":"$HandoffId","observed_document_nonce":"<the exact C9 nonce in the attached UTF-8 text document>","observed_image_nonce":"<the exact C9 nonce visible in the attached image>","surface":"chat"}
"@.Trim()

$receipt = [pscustomobject]@{
    version = "1"
    status = "exact_web_steps_committed"
    handoff_id = $HandoffId
    work_prompt_sha256 = Get-C9Utf8Sha256 -Value $workPrompt
    chat_prompt_sha256 = Get-C9Utf8Sha256 -Value $chatPrompt
    work_task_limit = 1
    normal_chat_conversation_limit = 1
    order = "work_then_chat"
    work_delivery = "plugin_mcp_rich_content"
    native_chat_delivery = "operator_performed_manual_attachment_handoff"
    work_tool_argument_surface = "work"
    native_chat_plugin_mcp_app_allowed = $false
    native_chat_manual_handoff_qualifies_as_success = $true
    automatic_chat_to_work_switch_used = $false
    created_at = [DateTimeOffset]::UtcNow.ToString("o")
}
[void](Write-C9MetadataReceipt -Path $stepsPath -Receipt $receipt)

@"
C9 exact bounded web steps

- Run the Work leg first and the normal Chat leg second.
- Use exactly one new synthetic Work task and one new synthetic normal Chat conversation.
- Select the reviewed Plugin/MCP app only in Work.
- Invoke systeme_local_attachment_handoff exactly once in Work with surface="work".
- Confirm Work before creating the private native-Chat export.
- In normal Chat, select no Plugin and never switch Chat to Work.
- Use the one-use private picker paths returned by Get-C9ChatHandoffPickerPaths.ps1.
- Verify that exactly the generated image and UTF-8 document are visibly attached before sending the Chat prompt.
- Never open history, existing conversations, Account/Security, private browser data, files other than the two generated fixtures, or any other tool.
- If a receipt or grant expires, send nothing: stop C9 and begin a fresh cycle.

EXACT WORK PROMPT
$workPrompt

EXACT NORMAL CHAT PROMPT
$chatPrompt

Copy the Work JSON reply and stage it first:
- .\scripts\c9\Set-C9ProviderResponse.ps1 -Surface work -HandoffId $HandoffId -ConfirmedExactResponseCopiedToClipboard
- .\scripts\c9\Confirm-C9WorkProof.ps1 -HandoffId $HandoffId

After Work confirmation, create and claim the native-Chat handoff:
- .\scripts\c9\New-C9ChatHandoffExport.ps1 -HandoffId $HandoffId
- .\scripts\c9\Get-C9ChatHandoffPickerPaths.ps1 -HandoffId $HandoffId -ExportId <exact export_id>

After the operator attaches exactly those two files and sends the exact normal
Chat prompt, copy the JSON reply and stage it:
- .\scripts\c9\Set-C9ProviderResponse.ps1 -Surface chat -HandoffId $HandoffId -ConfirmedExactResponseCopiedToClipboard
- .\scripts\c9\Confirm-C9ChatManualProof.ps1 -HandoffId $HandoffId

The writer reads only the exact response you just copied, clears the clipboard,
validates the exact surface-specific shape and stores bounded strict UTF-8
atomically. Never put a provider reply in PowerShell command text or command
history.
"@
