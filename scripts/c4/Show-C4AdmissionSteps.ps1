[CmdletBinding()]
param(
    [switch]$AllowDirty,
    [string]$AsOf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C4.Common.psm1") -Force

$matrix = Get-C4ActionMatrix -AllowDirty:$AllowDirty -AsOf $AsOf

[pscustomobject]@{
    status = "offline_admission_inspection"
    all_actions_denied = $matrix.all_actions_denied
    effective_tool_count = $matrix.effective_tool_count
    next_gate = @(
        "Obtain explicit official native Chat support.",
        "Independently review and promote a new C3 profile.",
        "Re-run C4 and require only the reviewed read-only tool.",
        "Request separate authorization before any bounded live validation."
    )
    prohibited_now = @(
        "runtime key creation",
        "tunnel startup",
        "Plugin creation",
        "browser or ChatGPT action",
        "Work, history, existing chats, or private browser state"
    )
} | ConvertTo-Json -Depth 8
