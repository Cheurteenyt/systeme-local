# ADR 0016: Bind one sanitized package to Work MCP and a bounded manual Chat handoff

Status: accepted and implemented C9 product contract; consolidated offline
validation passed; live outcome pending

Date: 2026-07-28

Immutable dependency: C8 evidence tag
`evidence/chatgpt-work-live-c8-v1`, tag target
`bb30b7989c2cbdaa688e0e9c34d8df71aea75cd5`

Issue: [#80](https://github.com/Cheurteenyt/systeme-local/issues/80)

## Context

C8 proved that ChatGPT Work could invoke one read-only MCP tool during a
bounded, revoked cycle. It did not transfer file content, run a local
multimodal model or prove a native-Chat file handoff.

Current OpenAI documentation creates an asymmetric product boundary:

- the plugin connection guide documents connecting an MCP server, starting a
  new conversation and selecting the connection from the tools menu on a
  supported plugin surface;
- the Plugins guide explicitly states that Plugins are not available in
  Chat;
- Secure MCP Tunnel documents the temporary Tunnel and Runtime-key path;
- the Plugin reference permits model-visible tool-result `content` arrays.

Sources:

- [Connect and test your plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt)
- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [Plugin reference](https://developers.openai.com/plugins/reference)
- [Plugins](https://learn.chatgpt.com/docs/plugins)
- [Model Context Protocol](https://learn.chatgpt.com/docs/extend/mcp)

The “new conversation” instruction does not override the explicit
unavailability of Plugins in normal Chat. C9 must therefore not model a
normal-Chat Plugin/MCP call as implemented, pending or secretly available.

The Plugin reference also does not establish that ChatGPT Work will accept
and interpret C9's exact MCP `ImageContent` plus embedded-resource pair. That
rich-host behavior remains a live question.

## Decision

The qualifying C9 path is deliberately asymmetric and deterministic:

```text
two generated synthetic inputs (one PNG + one UTF-8 TXT)
    -> bounded inspection, decoding and metadata stripping
    -> one canonical sanitized package
    -> real local-AI loopback inference over both exact sanitized inputs
    -> proof that the local model reproduced both independent nonces
    -> one atomic operator approval
       -> exactly one new Work task
          -> reviewed Plugin/MCP connection
          -> systeme_local_attachment_handoff(surface="work")
          -> MCP ImageContent + embedded UTF-8 text resource
          -> Work response and local-audit correlation
       -> exactly one new normal Chat conversation
          -> owner-only, short-lived export of the same sanitized package
          -> one at-most-once operator file-picker claim
          -> operator attaches exactly the PNG and TXT
          -> visible Chat response proves both nonce values
    -> typed, non-interchangeable Work and Chat receipts
    -> negative tests, shutdown, export cleanup, app removal,
       Runtime-key revocation and final attestation
```

The exact package contains two and only two generated synthetic files:

1. one PNG image containing an independent random nonce;
2. one strict UTF-8 text document containing another independent random
   nonce.

JPEG remains supported by the bounded sanitization layer but the reproducible
C9 live fixture is PNG plus TXT. PDF, JSON, archives, office files, generic
binary files, extra attachments and real user material are outside C9 v1.

### One local-AI proof before either Web transfer

The local AI must be an installed runtime reached through a literal-loopback
endpoint. The request uses the configured OpenAI-compatible
chat-completions path with redirects and proxy inheritance disabled. A fresh,
HMAC-bound observation records the operator-declared product, version and
listening PID, inspected executable basename and SHA-256, endpoint/model
commitments, and explicit declarations about runtime logging and persistence.

The model must consume both sanitized inputs and reproduce both nonces. An
HTTP response from a test double is useful offline but cannot satisfy the live
local-AI requirement. The runtime declarations are operator attestations;
they are not independent programmatic proof of the product's privacy
settings.

Public receipts retain hashes, sizes, timings, capability commitments and
receipt digests only. Raw model output, attachment bytes and cleartext nonces
remain private and ephemeral. `adapter_persistent_storage_used=false`
describes the C9 adapter, not the installed runtime.

### Work uses one read-only rich MCP tool

The Work Plugin/MCP path admits only
`systeme_local_attachment_handoff`. It does not read arbitrary files, write,
execute commands, return secrets, expose real evidence or enable protocol v2.

Local task execution and audit remain metadata-only. The MCP transport
renderer alone expands the already authorized result into one standard
`ImageContent` block and one embedded UTF-8 text resource backed by the
approved sanitized bytes.

Work success requires one live provider response reproducing both nonces and
binding the exact task, manifest, descriptor, cycle, grant and local audit.
Documentation and offline shape tests cannot establish that ChatGPT Work
interpreted either content block.

### Normal Chat uses a bounded visible manual handoff

Normal Chat does not expose the Plugin/MCP app under the current official
product rule. C9 therefore uses one explicit operator file-picker transfer of
the same sanitized package into exactly one new normal Chat conversation.

The export is private, owner-only, maximum-ten-minute, at-most-once and bound
to the approved Chat manifest. Paths are released only to the authenticated
loopback control caller, immediately revalidated by identity and content hash,
and removed on completion, cancellation, expiry or shutdown.

A qualifying Chat receipt means only:

- the operator attached the exact approved PNG and TXT in the authorized new
  Chat conversation;
- the visible Chat response reproduced both independent nonce values;
- the receipt binds that response to the exact Chat manifest and manual
  export claim.

It does **not** mean that Chat invoked an MCP tool, reached the local endpoint,
used the Work connection or verified any internal app identifier. The Work
MCP proof and normal-Chat manual proof are intentionally non-interchangeable.

If the current authorization or product decision does not accept a manual
Chat handoff as this distinct proof, the correct result is
`PARTIAL/BLOCKED`, even when Work succeeds.

### UI observation and app identity limit

C9 may record the operator-visible Work app label and selection together with
the locally reviewed endpoint, exact tool, cycle and grant. It does not
collect a hidden ChatGPT identifier and cannot prove an internal app ID. The
remaining risk is operator mis-selection or a visually ambiguous label; exact
local endpoint/tool/cycle correlation narrows but does not eliminate it.

No same-app claim spans Work and normal Chat because normal Chat has no plugin
leg.

### Bounded Web authority

C9 authorizes at most one new synthetic Work task followed by one new
synthetic normal Chat conversation. It never authorizes automatic
Chat-to-Work switching, existing conversations, history, account or security
settings, private browser state, arbitrary user files, writes, commands,
secrets, real evidence or protocol v2.

The C8 seal is an immutable transport dependency only. C9 verifies its tag
target but never reuses or extends the completed C8 grant. C9 requires fresh
authorization, a Work surface observation, a new Runtime key, a new Tunnel
connection and a fresh short-lived grant.

## Implementation and evidence state

The C9 branch contains the package-security, local-AI, private-export,
rich-renderer, audit, cleanup, operator scripts, proof models and final
attestation aligned to this asymmetric contract. One consolidated
clean-commit validation and a reviewed draft PR must be green before any live
run.

No real local-AI inference or live C9 Web delivery has been recorded. Current
counters are:

```text
installed local-AI inference:       0/1
Work rich Plugin/MCP proof:         0/1
normal-Chat manual handoff proof:   0/1
```

## Rejected alternatives

- **Treat a normal-Chat Plugin/MCP call as primary or pending.** Rejected
  because current official documentation explicitly says Plugins are not
  available in Chat.
- **Describe the manual Chat handoff as an app invocation.** Rejected because
  the file picker neither invokes the local tool nor reaches the local
  endpoint.
- **Infer rich-content host support from the MCP or Plugin schema.** Rejected
  because the specific Work behavior still requires a live call.
- **Declare capability from documentation or a plan name.** Rejected because
  Work availability depends on the current account/workspace and must be
  observed live.
- **Automate Chat through private endpoints, DOM heuristics or browser
  storage.** Rejected because those are undocumented and cross the browser
  privacy boundary.
- **Automatically switch a Chat prompt into Work.** Rejected because it would
  not test normal Chat and would violate the surface authorization.
- **Persist raw bytes, nonces, provider responses or picker paths in public
  evidence.** Rejected because commitments are sufficient and recoverable
  content is unnecessary.
- **Send the package before real local-AI verification.** Rejected because it
  would not prove that the installed model consumed the exact outbound bytes.
- **Infer consumption from filenames, thumbnails or UI appearance.**
  Rejected because both provider responses must reproduce the independent
  nonce values.
- **Reuse the completed C8 grant.** Rejected because historical evidence is
  not renewable authority.

## Consequences

- C9 can test both requested Web experiences without contradicting the
  current product contract.
- Work and Chat results have different transport semantics and must never be
  merged into a “same app on both surfaces” claim.
- The Chat proof is useful but operator-assisted; it does not establish
  autonomous local-to-Chat delivery.
- Manual picker path exposure and local TOCTOU remain residual risks despite
  owner-only permissions, identity checks and content-hash revalidation.
- Offline tests cannot establish the installed local-AI inference, Work rich
  interpretation or visible Chat consumption.
- Until both live proofs, negative tests, cleanup, Plugin/Tunnel removal,
  Runtime-key revocation and final attestation are complete, C9 has no live
  success claim.
- Another Web AI must define and live-test its own app surface, manual
  handoff, content rendering, approval, quota and revocation contract. C9
  receipts are not portable authority.
