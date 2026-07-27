# ADR 0007: Permit a bounded Secure MCP Tunnel connectivity probe

- Status: accepted
- Date: 2026-07-26
- Issue: [#64](https://github.com/Cheurteenyt/systeme-local/issues/64)

## Context

The roadmap previously placed real operator-evidence collection before any
broader provider connectivity work. That sequence cannot prove whether the
already implemented loopback MCP facade is reachable from a real ChatGPT Web
draft integration. C0 needs one live network path but must not make future B2
operator-evidence collection wire-reachable.

## Decision

Permit one explicitly activated, time-bounded connectivity probe through the
official Secure MCP Tunnel. The local facade remains loopback-only and
bearer-protected. C0 uses a separate default-deny policy and advertises exactly
one synthetic, read-only, closed-world tool. It cannot read operator evidence,
write files, run commands, call providers, reach protocol v2, publish a Plugin,
or automate ChatGPT Web.

The tunnel is customer-run and outbound-only. Its release asset and SHA-256 are
pinned. Credentials remain process-local. Existing Host, Origin,
authentication, request-size, rate, and concurrency controls are not relaxed.

A distinct live attestation may become true only after an operator manually
proves the Web call, correlated HMAC audit entry, and failed post-revocation
call. Existing readiness observations remain non-live.

## Consequences

- C0 is a narrow sequencing exception, not B2 evidence collection.
- Secure MCP Tunnel becomes an optional operator dependency, never a default
  runtime dependency.
- The repository records source summaries, digests, scripts, and typed models,
  but no credentials, cookies, raw UI evidence, or live endpoint identifiers.
- OAuth remains a separate gate if the real draft configuration requires it.
- Tool metadata drift, unknown eligibility, public binding, or revocation
  failure blocks the attestation.
- Removal of the draft Plugin, revocation of the Runtime API key, process
  shutdown, and contained local cleanup restore the pre-C0 boundary.
