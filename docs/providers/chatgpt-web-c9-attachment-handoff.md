# C9 ChatGPT file and image handoff

Status: `partial` — the asymmetric Work-rich/Chat-manual contract is
accepted, implemented and validated offline; all three live proofs are pending

Issue: [#80](https://github.com/Cheurteenyt/systeme-local/issues/80)

Branch: `codex/chatgpt-file-image-handoff-c9`

Immutable C8 dependency: `evidence/chatgpt-work-live-c8-v1` at
`bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5`

Decision:
[ADR 0016](../adr/0016-bind-one-sanitized-package-to-work-mcp-and-chat-manual.md)

Evidence ledger:
[C9 test and evidence ledger](chatgpt-web-c9-test-evidence.md)

## Exact objective and current claim

C9 is designed to establish only this statement:

> During one explicitly authorized and fully revoked cycle, one real
> installed local-AI runtime consumed one generated synthetic PNG image and
> one generated synthetic UTF-8 document. ChatGPT Work then consumed that
> exact sanitized package through one read-only Plugin/MCP rich result, and
> one new normal Chat conversation consumed the same package through one
> bounded, visible, operator-performed file-picker handoff.

That statement is **not yet established**.

```text
real installed local-AI inferences verified: 0/1
qualifying Work rich MCP transfers:           0/1
qualifying normal-Chat manual handoffs:       0/1
C9 final attestation:                         absent
C9 success claim:                             absent
```

The two Web proofs are intentionally different:

| Surface | Transport | What a positive proof may claim |
|---|---|---|
| Work | reviewed Plugin/MCP connection and rich tool result | one correlated invocation of the admitted local tool returned the exact package |
| normal Chat | operator file picker in one new visible conversation | Chat visibly consumed the exact operator-attached package |

A normal-Chat manual proof does not establish an MCP call, local endpoint
reachability, app invocation or internal app identity. A Work proof does not
establish native-Chat consumption. Both are required for the accepted C9
outcome.

C9 does not claim:

- autonomous local-to-normal-Chat delivery;
- arbitrary user-file access or a reusable upload service;
- access to history or existing conversations;
- automatic Chat-to-Work switching;
- browser-private or undocumented ChatGPT interfaces;
- writes, commands, secrets, real evidence or protocol v2;
- exact internal model or app identity;
- production readiness or portability to another Web AI.

## Official product rule and evidence limit

The current official product rule is decisive:

- [Plugins](https://learn.chatgpt.com/docs/plugins) explicitly states that
  Plugins are not available in Chat;
- [Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt)
  documents a new conversation and tools-menu selection on a supported plugin
  surface, not an exception for normal Chat;
- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
  documents temporary local tunnel and Runtime-key setup;
- the [Plugin reference](https://developers.openai.com/plugins/reference)
  permits model-visible tool-result `content` arrays;
- the [Model Context Protocol](https://learn.chatgpt.com/docs/extend/mcp)
  describes the protocol boundary.

These sources support a Work Plugin/MCP test. They forbid representing normal
Chat as another Plugin/MCP leg. They also do not prove that ChatGPT Work will
accept and interpret C9's particular MCP `ImageContent` plus embedded-resource
pair. That exact rich-host behavior remains live-pending.

No plan label, UI screenshot, offline renderer test or historical C8 receipt
may convert either pending counter into a live result.

## Exact synthetic package

The reproducible C9 v1 package contains exactly:

1. `c9-synthetic-proof.png`;
2. `c9-synthetic-proof.txt`, encoded as strict UTF-8 and advertised as
   `text/plain`.

Each generated file carries a different cryptographically random proof nonce.
The public fixture receipt contains names, media types, sizes and SHA-256
commitments, never paths, bytes or nonce values.

The offline sanitizer also covers bounded JPEG input, but the live proof is
fixed to PNG plus TXT. PDF, JSON, archives, office files, generic binaries,
extra attachments, real screenshots and personal documents are rejected.

The process-local attachment authority:

- accepts only its generated C9 fixtures for the live path;
- rejects traversal, links, Windows reparse points and unexpected hard links;
- fingerprints opened objects and detects source drift;
- identifies type from bytes rather than extension;
- applies byte, dimension, pixel, decoded-size, chunk, segment and line
  limits;
- strips non-essential image metadata;
- normalizes strict UTF-8 text;
- re-inspects sanitized output;
- commits canonical descriptors, manifests and content hashes;
- keeps paths and mutable sanitized bytes in private process state only.

## Real local-AI gate

The exact sanitized package must be consumed by a real installed local
multimodal runtime before either Web transfer.

The adapter accepts only:

```text
http://127.0.0.1:<explicit-port>/v1/chat/completions
```

It forbids authentication, redirects and inherited proxy routing. It applies
explicit request, response and timeout limits, treats both inputs as
untrusted data rather than instructions, and requires strict JSON containing
both expected nonces.

A fresh HMAC-bound observation records:

- operator-declared runtime product, version and listening PID;
- inspected executable basename and SHA-256;
- endpoint and visible model-label commitments;
- operator confirmation that the intended native runtime is active;
- operator confirmation that runtime request logging and request persistence
  are disabled;
- the explicit fact that PID identity and privacy settings are
  operator-attested, not independently detected.

An offline HTTP server validates the adapter protocol only. It is not a real
installed-runtime inference. Public receipts retain hashes, sizes, timings and
bounded commitments only. `adapter_persistent_storage_used=false` applies to
the C9 adapter, not to the installed runtime.

## Work rich Plugin/MCP proof

The only admitted remote tool is:

```text
systeme_local_attachment_handoff
```

For C9 it is invoked exactly once in one new Work task with
`surface="work"`. The tool is read-only with respect to external and user
resources. Its one-use lease transition is local anti-replay state, not an
open-world write.

Local execution and audit remain metadata-only. After policy and audit, the
renderer returns:

- one standard MCP `ImageContent` block for the sanitized PNG;
- one embedded UTF-8 text resource for the sanitized document.

The Work response must reproduce both nonces and bind the exact task,
manifest, descriptor, package, cycle, grant and local audit record. Host
acceptance and interpretation of both content shapes are live-pending.

### Work app identity scope

C9 records the operator-visible app label and selection, reviewed local
endpoint, exact tool, cycle and grant. It neither reads a hidden ChatGPT app
identifier nor proves an internal app ID. A positive result therefore means
that the visibly selected Work connection produced a response correlated with
the exact local endpoint/tool/cycle.

Residual risk remains: an operator can mis-select a visually similar app or
misreport the visible label. Local endpoint, tool and audit correlation narrow
that risk but do not eliminate it.

## Normal-Chat bounded manual proof

After the Work proof, C9 creates one owner-only short-lived export containing
the same sanitized PNG and TXT. An authenticated local caller claims the two
picker paths at most once. Immediately before release, C9 revalidates:

- export and handoff identity;
- one image plus one text file;
- expected filenames and extensions;
- regular-file, no-link and owner-only permission constraints;
- exact content hashes;
- unexpired approval and export lifetime.

The operator then:

1. explicitly selects normal Chat;
2. creates exactly one new synthetic conversation;
3. attaches exactly the two released files once using the visible file
   picker;
4. sends the bounded synthetic prompt once;
5. copies the strict JSON response for immediate local verification.

The response must reproduce both independent nonces and bind the exact manual
Chat manifest and export claim. A filename, thumbnail, upload indicator or
unverified prose response is insufficient.

Picker operations remain path-based. Owner-only permissions, component and
identity checks, and content-hash revalidation narrow but cannot eliminate a
privileged local TOCTOU race between the final check and visible selection.

The manual handoff is a qualifying **normal-Chat transfer proof** under this
ADR. It is not and must never be labelled:

- a Chat Plugin/MCP proof;
- a local-app invocation;
- a same-app-on-both-surfaces proof;
- autonomous browser control;
- regular-use readiness.

If the user or a future authorization forbids the file picker, C9 stops
`PARTIAL/BLOCKED` after any valid Work proof. It must not silently switch the
Chat leg to Work.

## Browser and authorization boundary

A fresh C9 authorization may permit only:

- the Plugins surface and ChatGPT Work;
- exactly one new synthetic Work task;
- selecting one temporary reviewed Plugin/MCP connection in Work;
- one Work tool call;
- normal Chat's visible file picker;
- exactly one new synthetic normal Chat conversation;
- one manual attachment of the generated PNG/TXT package;
- one temporary Secure MCP Tunnel and Plugin connection for Work only;
- operator-managed creation and revocation of one Runtime key;
- copying each exact bounded provider JSON reply for immediate local
  verification.

It must continue to forbid:

- any normal-Chat Plugin/MCP claim;
- automatic Chat-to-Work switching;
- history and existing conversations;
- account and security settings;
- cookies, browser storage, private requests and hidden identifiers;
- DOM scraping or private endpoints;
- arbitrary files or more than the generated PNG/TXT package;
- writes, commands, secrets, real evidence and protocol v2;
- any third task/conversation or retry after ambiguous consumption.

Visible public product controls are the only permitted browser interface.

## Implementation-readiness gate

Do not start the live cycle until every row is green on one clean commit.
This table is an acceptance gate, not a report of current results.

| Gate | Required state |
|---|---|
| package security and identity | implemented; focused tests pass |
| real-runtime observation and local-AI adapter | implemented; focused tests pass |
| Work-only rich MCP tool and renderer | implemented; strict schema and renderer tests pass |
| Work one-use proof | replay, mutation and audit-correlation tests pass |
| Chat manual export and claim | owner-only, bounded, at-most-once and hash-revalidation tests pass |
| Chat manual proof | exact manifest/claim/nonce binding tests pass |
| claim separation | tests reject every Chat MCP/app/same-app promotion |
| final attestation | requires one Work rich proof and one Chat manual proof |
| operator scripts and documentation | match this asymmetric contract |
| repository security boundary | owner-only live clone passes trusted execution checks |
| consolidated validation | exact command, commit, counts and digest recorded in the ledger |

The earlier dual-rich Work-and-Chat script and status model is superseded by
this ADR. No live run is allowed until the aligned scripts and attestation
tests are green.

## Trusted execution preconditions

Keep one PowerShell process open for the complete cycle because secrets and
transport credentials are process-local. Before creating a Runtime key,
starting a Tunnel or using ChatGPT:

1. record an exact C9 authorization that explicitly permits the Work
   Plugin/MCP leg and normal-Chat manual file-picker leg;
2. use the reviewed clean C9 commit descending from the accepted C8 tag;
3. require a clean worktree and exact committed scripts, policy and
   dependencies;
4. pass repository, `.git`, `src`, `scripts/c9`, policy, virtual environment,
   base Python, Git and tunnel-client trust checks;
5. reject reparse points, unexpected hard links, untrusted ownership or a
   write-capable ordinary-principal ACL on an executed object;
6. use an owner-only clean clone if the development checkout fails those
   checks;
7. start one reviewed multimodal runtime on literal loopback with request
   logging and persistence disabled;
8. visibly confirm Work entitlement/quota and the reviewed connection;
9. confirm normal Chat's visible file-picker control;
10. confirm the operator can remove the Work connection and revoke the fresh
    Runtime key.

The checks fail closed but do not prove that Windows, an administrator or the
kernel is uncompromised.

## Deterministic operator sequence

The target operator protocol is:

```text
prepare owner-only clean environment
    -> observe installed local runtime
    -> start zero-tool local facade
    -> generate/sanitize PNG + TXT and prove both nonces locally
    -> visibly observe Work and approve exact package
    -> admit exactly one Work tool
    -> create Runtime key, start Tunnel, connect Work app
    -> create one Work task and invoke rich tool once
    -> verify Work response
    -> materialize and claim owner-only Chat handoff export once
    -> create one normal Chat conversation and attach both files once
    -> verify Chat response as manual-transfer evidence
    -> stop and zero private buffers
    -> correlate Work audit and run negative suite
    -> remove Work Plugin connection and revoke Runtime key
    -> record failed post-revocation Work and local-control calls
    -> attest, seal and clean
```

Work is always first. Normal Chat is always second. No ambiguous call is
retried and no lease/export claim is regenerated.

### Exact operator commands

Run one cycle in one PowerShell process. The installed multimodal runtime must
already listen on literal IPv4 loopback. Set only its reviewed endpoint and
visible model label before local preparation:

```powershell
Set-Location '<absolute-path-to-the-trusted-clean-c9-clone>'
$env:SLG_C9_LOCAL_AI_ENDPOINT = `
    'http://127.0.0.1:11434/v1/chat/completions'
$env:SLG_C9_LOCAL_AI_MODEL = '<exact-installed-model-label>'

.\scripts\c9\Prepare-C9.ps1 -ConfirmedLocalPreparation
.\scripts\c9\Test-C9Prerequisites.ps1 -RequireSecrets
.\scripts\c9\New-C9LocalAIRuntimeObservation.ps1 `
    -ProviderKind ollama `
    -ConfirmedNativeRuntime `
    -ConfirmedRuntimeRequestLoggingDisabled `
    -ConfirmedRuntimeRequestPersistenceDisabled `
    -ConfirmedRuntimePrivacySettings
.\scripts\c9\Test-C9Prerequisites.ps1 -RequireSecrets -RequireLocalAI
.\scripts\c9\Start-C9Facade.ps1
.\scripts\c9\Test-C9LocalProbe.ps1 -ExpectedToolCount 0
$stage = .\scripts\c9\New-C9SyntheticHandoff.ps1 | ConvertFrom-Json
$handoffId = [string]$stage.handoff_id
```

Use `-ProviderKind lm_studio` or
`-ProviderKind other_reviewed_native` only when that exact installed native
runtime was reviewed. Never copy a remote URL or secret into the local-AI
variables.

Before either prompt is sent, visibly inspect Work, the reviewed Work
Plugin/MCP connection, and normal Chat's file-picker control. Then record one
combined approval and verify that admission exposes exactly one Work tool:

```powershell
$operatorIdentityUtf8Base64 = 'bG9jYWwtYzktb3BlcmF0b3I='
.\scripts\c9\Approve-C9CombinedHandoff.ps1 `
    -HandoffId $handoffId `
    -OperatorIdentityUtf8Base64 $operatorIdentityUtf8Base64 `
    -ConfirmedOneCombinedApproval `
    -ConfirmedExactVisibleSurfaceObservation
.\scripts\c9\Test-C9LocalProbe.ps1 -ExpectedToolCount 1
```

Only now may the operator create one fresh Runtime key and place it, together
with the exact existing Tunnel ID, in `CONTROL_PLANE_API_KEY` and
`CONTROL_PLANE_TUNNEL_ID` in this same process. Do not print either value.
Load both values without echoing them, validate them, and start the one-use
Work transport:

```powershell
function Set-C9ProtectedProcessVariable {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Prompt
    )
    $secureValue = Read-Host $Prompt -AsSecureString
    $credential = New-Object `
        -TypeName System.Management.Automation.PSCredential `
        -ArgumentList "c9", $secureValue
    try {
        $plainValue = (
            $credential.GetNetworkCredential().Password
        ).Trim()
        Set-Item -Path "Env:$Name" -Value $plainValue
    }
    finally {
        $plainValue = $null
        Remove-Variable secureValue, credential -ErrorAction SilentlyContinue
    }
}
Set-C9ProtectedProcessVariable `
    -Name CONTROL_PLANE_API_KEY `
    -Prompt "Paste the fresh C9 Runtime key"
Set-C9ProtectedProcessVariable `
    -Name CONTROL_PLANE_TUNNEL_ID `
    -Prompt "Paste the exact C9 Tunnel ID"
if (
    -not $env:CONTROL_PLANE_API_KEY -or
    $env:CONTROL_PLANE_API_KEY.Length -lt 20
) {
    throw "C9 Runtime key is absent or invalid."
}
if ($env:CONTROL_PLANE_TUNNEL_ID -cnotmatch "^tunnel_[0-9a-f]{32}$") {
    throw "C9 Tunnel ID is absent or invalid."
}
.\scripts\c9\Test-C9Prerequisites.ps1 `
    -RequireSecrets `
    -RequireLocalAI `
    -RequireLiveCycle `
    -RequireTunnelCredentials
.\scripts\c9\Start-C9Tunnel.ps1
.\scripts\c9\Show-C9WebSteps.ps1 -HandoffId $handoffId
```

Follow the emitted Work prompt once in exactly one new Work task. Copy only
its exact JSON response, then run:

```powershell
.\scripts\c9\Set-C9ProviderResponse.ps1 `
    -Surface work `
    -HandoffId $handoffId `
    -ConfirmedExactResponseCopiedToClipboard
.\scripts\c9\Confirm-C9WorkProof.ps1 -HandoffId $handoffId
```

Materialize and claim the normal-Chat export only after Work succeeds:

```powershell
$export = .\scripts\c9\New-C9ChatHandoffExport.ps1 `
    -HandoffId $handoffId | ConvertFrom-Json
$exportId = [string]$export.export_id
$picker = .\scripts\c9\Get-C9ChatHandoffPickerPaths.ps1 `
    -HandoffId $handoffId `
    -ExportId $exportId | ConvertFrom-Json
$picker.paths
```

In exactly one new normal Chat conversation, use the visible file picker to
attach exactly those two paths once, send the exact normal-Chat prompt emitted
by `Show-C9WebSteps.ps1`, and copy only its exact JSON response. Then run:

```powershell
.\scripts\c9\Set-C9ProviderResponse.ps1 `
    -Surface chat `
    -HandoffId $handoffId `
    -ConfirmedExactResponseCopiedToClipboard
.\scripts\c9\Confirm-C9ChatManualProof.ps1 -HandoffId $handoffId
.\scripts\c9\Stop-C9.ps1
.\scripts\c9\Commit-C9Correlations.ps1
.\scripts\c9\Confirm-C9NegativeTests.ps1
```

After stop, remove the temporary Work Plugin connection, revoke the Runtime
key on the platform, and verify that the former Work route, local Chat-export
claim and local control route fail. Commit those operator observations and
the final attestation:

```powershell
.\scripts\c9\Confirm-C9Revocation.ps1 `
    -WorkPluginConnectionRemoved `
    -RuntimeApiKeyRevoked `
    -PostRevocationWorkPluginMcpAppCallFailed `
    -PostRevocationChatExportAndClaimFailed `
    -PostRevocationControlCallFailed
.\scripts\c9\Commit-C9FinalAttestation.ps1
.\scripts\c9\Clear-C9Temporary.ps1 -PreserveAuditKeyForSeal
```

Update the evidence ledger with metadata-only live results and receipt
commitments—never raw responses, nonces, paths, credentials or attachment
bytes—then create a dedicated clean live-proof commit. Confirm that the
worktree is clean before creating and committing the manifest and seal as two
separate commits. Create the annotated evidence tag, verify it, and finally
clear the preserved audit key:

```powershell
# First update only:
# docs/providers/chatgpt-web-c9-test-evidence.md
git add -- docs/providers/chatgpt-web-c9-test-evidence.md
git commit -m 'docs(evidence): record C9 live proof'
if ((git status --short).Count -ne 0) {
    throw "C9 live-proof commit did not leave a clean worktree."
}
.\scripts\c9\New-C9Seal.ps1 -CreateManifest
git add -- governance/c9-change-manifest.json
git commit -m 'docs(evidence): record C9 live manifest'
.\scripts\c9\New-C9Seal.ps1 -CreateSeal
git add -- governance/c9-change-seal.json
git commit -m 'docs(evidence): seal C9 live evidence'
git tag -a evidence/chatgpt-file-image-handoff-c9-v1 `
    -m 'C9 live evidence seal'
.\scripts\c9\Test-C9Seal.ps1 -RequireCurrentTree -RequireClean
.\scripts\c9\Clear-C9Temporary.ps1
```

Scripts named as a Chat “fallback” or a Chat rich/MCP proof are not
authoritative for this ADR. Normal Chat never receives the Tunnel, app or
local endpoint; it receives only the two operator-selected temporary files.

## Stop, revocation and final evidence

Normal stop must revoke admission, zero sanitized buffers, remove the manual
export, stop facade/Tunnel listeners, close ports and clear
transport/local-AI secrets while preserving only the audit key needed to
verify final receipts.

The final evidence must separately establish:

- Work execution/audit correlation;
- the parameterless automated negative suite;
- owner-only Chat export cleanup;
- temporary Work Plugin/MCP connection removal;
- Runtime key revocation;
- prior Work Plugin/MCP route unreachable;
- local control route unreachable;
- no claim that normal Chat became unreachable after Runtime-key revocation,
  because its manual file-picker path is independent of that key;
- one HMAC-authenticated final attestation.

The former post-revocation Chat-app-call condition is invalid under this
contract because there is no normal-Chat Plugin/MCP route to revoke.

The implemented final status is
`COMPLETE_C9_WORK_RICH_MCP_AND_CHAT_MANUAL_VISIBLE_ATTACHMENTS_VERIFIED_AND_REVOKED`;
the seal status is
`C9_WORK_RICH_MCP_AND_CHAT_MANUAL_LIVE_EVIDENCE_SEALED`. Both explicitly
distinguish:

```text
Work: rich Plugin/MCP proof
Chat: bounded manual handoff proof
```

No prior dual-rich Work-and-Chat status may be reused.

## Required offline and negative validation

The final clean-commit snapshot must cover:

- exact PNG/TXT generation, sanitization and manifest identity;
- rejection of traversal, links/reparse points, hard-link substitution,
  source drift, unsupported formats and oversized content;
- literal-loopback-only local AI, no auth/redirect/proxy, bounded timeout and
  response, strict nonce proof and fresh runtime observation;
- zero tools without admission and exactly one read-only Work tool after it;
- one-use Work execution and rich-result correlation;
- renderer transactionality, metadata preservation, byte bounds and failure
  audit;
- private Chat export ACL/mode, TTL, at-most-once path claim, identity/hash
  revalidation and cleanup;
- one-use manual Chat response proof bound to the exact export and manifest;
- rejection of any Chat MCP/app/local-endpoint/same-app promotion;
- absence of arbitrary file, write, command, secret, real-evidence and
  protocol-v2 capabilities;
- shutdown, revocation, final-attestation freshness and authenticated cleanup;
- trusted Git/Python/repository execution boundaries.

The evidence ledger must name exact tests and record counts from the final
clean commit. Design text is not an executed result.

## Completion criteria

C9 is complete only if all of the following are present and verified:

1. one fresh operator-attested installed-runtime observation;
2. one real local-AI inference receipt for the exact sanitized package;
3. one live Work rich MCP receipt reproducing both nonces;
4. one live normal-Chat manual-handoff receipt reproducing both nonces;
5. equal package commitments with transport-specific one-use authority;
6. no Chat MCP/app/local-endpoint invocation claim;
7. the parameterless automated negative-test receipt;
8. stopped facade and Tunnel listeners;
9. removed temporary Work Plugin connection;
10. revoked Runtime key and cleared process secrets;
11. failed post-revocation Work and local-control reachability;
12. deleted manual export and picker paths;
13. one HMAC-authenticated final attestation;
14. one reproducible repository seal and authenticated final cleanup.

If the Work host rejects the rich content or the user does not authorize the
manual Chat handoff, the correct final state is `PARTIAL/BLOCKED`.

Raw files, sanitized bytes, local-AI bodies, nonce values, picker paths,
Runtime keys, Tunnel/Plugin identifiers, browser state, clipboard history,
raw provider responses, ChatGPT conversation identifiers and audit bodies
must never enter versioned evidence.

## Recovery rules

- Before local-AI verification: cancel and zero private package state.
- After local-AI verification but before approval: expose no tool or export.
- After approval but before Tunnel startup: expire the grant and clean
  private state.
- After Work succeeds: never retry it; complete the manual Chat leg within
  the same fresh window or stop with partial non-success evidence.
- After an ambiguous Work call or Chat attachment: do not resend, reattach or
  replace the one-use authority.
- On any invariant failure: stop, remove the Work app, revoke the Runtime key,
  delete the Chat export, clear secrets and verify cleanup.

An interrupted or partial cycle never authorizes another cycle.

## Portability

Provider-neutral foundations include canonical attachment identity, bounded
sanitization, in-memory one-use authority, local-AI nonce proof,
metadata-only audit and standard MCP rich-content blocks.

ChatGPT Work app discovery, Secure MCP Tunnel, workspace policy, quota,
normal-Chat manual attachment UI and revocation remain ChatGPT-specific. A
later Web AI provider must obtain its own official evidence, define a
transport contract, map rich or manual content, run independent live tests
and produce separate revocation receipts.
