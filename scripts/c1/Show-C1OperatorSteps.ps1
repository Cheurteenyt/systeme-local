[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "..\c4\C4.Common.psm1") -Force
Import-Module (Join-Path $PSScriptRoot "C1.Common.psm1") -Force

Assert-C4ProtectedActionAllowed -Action "plugin_creation"
Assert-C1GitState

@'
C1 browser gate (manual or goal-scoped bounded in-app browser control):

1. Revalidate the official Plugins surface contract before creating credentials or
   starting processes. As of 2026-07-27, Plugins are available on ChatGPT Web only in
   Work and are unavailable in Chat. While C1 forbids Work, STOP with
   BLOCKED_BY_PLUGIN_UNAVAILABLE_IN_CHAT before any live prompt.
2. Browser control requires explicit goal-scoped authorization. It may remain valid
   across strictly bounded retries until revoked, the goal ends, or scope changes;
   do not request it again for every cycle. Allow at most two new sterile Chat pages
   per cycle.
3. Only if a revalidated official contract makes Plugins available in Chat, confirm
   an eligible ChatGPT plan/role and enable Developer mode.
4. Create a fresh temporary Runtime API key and configure the existing Tunnel ID.
5. Start C1 facade and Secure MCP Tunnel.
6. Create the reviewed draft Plugin and verify exactly one read-only tool.
   Never use "Try in chat"; it may open Work and cannot establish Chat support.
7. Before every prompt, visibly classify the surface. If Work/Codex/unknown: STOP.
8. Use exactly two new sterile Chat pages, locally labeled c1-test-chat-a/b.
9. Never open the sidebar, history, existing chats, storage, cookies, private requests,
   API-key pages, billing pages, developer tools, or unrelated tabs.
10. For each Chat, record the pre-prompt Chat surface, generate its distinct challenge,
   call systeme_local_connectivity_probe once within 30 minutes, and save only strict
   response JSON. Signed manual evidence remains bounded to two hours.
11. Correlate both responses locally, then perform the nine bounded negative checks in Chat.
12. Stop tunnel/facade, remove the draft Plugin, revoke the Runtime API key, and verify
    a fresh sterile Chat call is unavailable.
13. Commit the signed negative and revocation receipts, final attestation, then cleanup.
14. If Chat/Work/Codex classification, browser privacy, prompt count, or tool invocation
    leaves the bounded scope, send no further prompt. Close both test tabs, stop both
    processes, remove the Plugin, revoke the Runtime key, and run
    Reject-C1ScopeViolationCycle.ps1. Reuse nothing from that cycle.
15. If final attestation rejects expired evidence, reuse nothing. With processes stopped,
    the Plugin removed, and the Runtime key revoked, run Reject-C1ExpiredCycle.ps1.

Work is detected but never prompted, invoked, or tested.
Existing chats are never accessed or enumerated.
'@
