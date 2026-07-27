[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C1GitState

@'
C1 browser gate (manual or freshly authorized bounded in-app browser control):

1. Confirm an eligible ChatGPT plan/role and enable Developer mode.
2. Create a fresh temporary Runtime API key and configure the existing Tunnel ID.
3. Start C1 facade and Secure MCP Tunnel.
4. Create/select the reviewed draft Plugin; verify exactly one read-only tool.
5. Before every prompt, visibly classify the surface. If Work/Codex/unknown: STOP.
6. Use exactly two new sterile Chat pages, locally labeled c1-test-chat-a/b.
7. Never open the sidebar, history, existing chats, storage, cookies, private requests,
   API-key pages, billing pages, developer tools, or unrelated tabs.
8. For each Chat, record the pre-prompt Chat surface, generate its distinct challenge,
   call systeme_local_connectivity_probe once within 30 minutes, and save only strict
   response JSON. Signed manual evidence remains bounded to two hours.
9. Correlate both responses locally, then perform the nine bounded negative checks in Chat.
10. Stop tunnel/facade, remove the draft Plugin, revoke the Runtime API key, and verify
    a fresh sterile Chat call is unavailable.
11. Commit the signed negative and revocation receipts, final attestation, then cleanup.
12. If Chat/Work/Codex classification, browser privacy, prompt count, or tool invocation
    leaves the bounded scope, send no further prompt. Close both test tabs, stop both
    processes, remove the Plugin, revoke the Runtime key, and run
    Reject-C1ScopeViolationCycle.ps1. Reuse nothing from that cycle.
13. If final attestation rejects expired evidence, reuse nothing. With processes stopped,
    the Plugin removed, and the Runtime key revoked, run Reject-C1ExpiredCycle.ps1.

Work is detected but never prompted, invoked, or tested.
Existing chats are never accessed or enumerated.
'@
