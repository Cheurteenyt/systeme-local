# Security Policy

## Project status

Système Local is experimental and must not yet be used to protect production
machines, secrets, or safety-critical workloads.

## Reporting a vulnerability

Do not disclose exploitable vulnerabilities in a public issue.

Use GitHub private vulnerability reporting:

https://github.com/Cheurteenyt/systeme-local/security/advisories/new

Include:

- the affected commit or version;
- the expected and observed behavior;
- the minimum reproduction steps;
- the potential impact;
- any suggested mitigation.

Do not include real credentials, private user data, persistence mechanisms, or
instructions targeting machines that you do not own.

## Security boundaries

The project follows these rules:

- no unrestricted host shell exposed to remote agents;
- no remote control without explicit local consent;
- no bypass of AI-provider restrictions;
- no secrets in prompts, source control, task results, or audit logs;
- deny-by-default capabilities;
- every new capability requires tests, policy declarations, and threat-model updates.

## Supported versions

Only the latest commit on `main` is currently supported during the experimental
phase. Security fixes may change internal APIs without backward compatibility.
