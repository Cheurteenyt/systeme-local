[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path $PSScriptRoot "C0.Common.psm1") -Force

Assert-C0GitState
$state = Get-C0StateDirectory
$challengePath = Join-Path $state "challenge.txt"
if (-not (Test-Path -LiteralPath $challengePath -PathType Leaf)) {
    throw "Generate a fresh C0 challenge first."
}
$challenge = (Get-Content -LiteralPath $challengePath -Raw).Trim()

@"
C0 MANUAL CHATGPT WEB CHECKLIST — no browser automation

1. Confirm the eligible ChatGPT plan, seat, workspace, role, RBAC grant, and web client.
2. In ChatGPT Web, open Settings > Apps (or Workspace Settings > Apps).
3. Enable Developer mode through Advanced Settings if the eligible plan/role exposes it.
4. Add a draft Plugin, choose Tunnel, and select the pre-created Secure MCP Tunnel ID.
5. Select no authentication for this unpublished synthetic read-only C0 probe.
6. Scan tools and verify exactly:
   - tool_count = 1
   - write_tool_count = 0
   - high_risk_tool_count = 0
   - name = systeme_local_connectivity_probe
   - readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false
7. Verify the displayed input and output schemas match the local snapshot digest.
8. Save one bounded, secret-free observation to:
   $state\manual-web-observation.json
   It must contain only the typed plan, role, fixed Web/Tunnel/noauth/draft values,
   1/0/0 counts, local policy/tool snapshot SHA-256 values, all eleven check states,
   and UTC observed_at/started_at timestamps. Do not capture cookies, tokens, HAR,
   screenshots, endpoint IDs, or raw UI state.
9. Start a new normal ChatGPT Web conversation and select the draft Plugin.
10. Ask ChatGPT to call systeme_local_connectivity_probe exactly once with:
    challenge = $challenge
11. Copy only the strict JSON tool response to:
    $state\live-response.json
12. Run Confirm-C0LiveProof.ps1.
13. Remove/disable the draft Plugin connection, run Stop-C0.ps1, and revoke the Runtime API key manually.
14. In a fresh chat, verify the Plugin/tool can no longer be selected or called.
15. Run Confirm-C0Revocation.ps1 -PluginConnectionRemoved `
    -RuntimeApiKeyRevoked -ManualCallFailedAfterRevocation.
16. Run Commit-C0LiveAttestation.ps1. It will fail closed unless the bounded
    observation, response, HMAC audit chain, stopped processes, revoked key,
    failed post-revocation call, current profiles, and exact snapshots all agree.

UI labels are volatile. If the eligible plan/role does not expose the documented controls,
stop and classify the result; do not substitute browser automation or a public proxy.
"@
