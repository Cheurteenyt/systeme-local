# ADR 0003: Use evidence-bound staged ChatGPT MCP readiness

- Status: Accepted
- Date: 2026-07-18

## Context

Official product eligibility, observed workspace configuration and a live authenticated MCP
connection are distinct facts. Current OpenAI documentation also contains a Plus-plan ambiguity
between general availability and the dedicated developer-mode path.

## Decision

Commit expiring official-source profiles, reconcile contradictions fail-closed, require a complete
eleven-check readiness observation and authorize only bounded stages:

- configure draft;
- test draft;
- publication review;
- use review.

A ready decision never claims that a tunnel, OAuth client, app or real connection exists.

## Consequences

- profile expiry blocks authorization;
- ambiguous official evidence cannot inherit permissive rights;
- tool drift and high-risk actions require renewed review;
- every decision binds exact profile and observation digests.
