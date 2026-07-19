# GitHub governance evidence

Status: bounded repository-settings snapshot

Observed: 2026-07-18T22:06:49Z

Repository: `Cheurteenyt/systeme-local`

Commit observed: `164b69bbfebab18db65b2ae5b990756db59c5518`

## Directly observed repository settings

| Setting | Observed value |
|---|---|
| visibility | public |
| default branch | main |
| archived | disabled |
| squash merge | enabled |
| rebase merge | disabled |
| merge commit | disabled |
| delete branch on merge | enabled |
| secret scanning | enabled |
| secret-scanning push protection | enabled |
| Dependabot security updates | enabled |
| advanced security | unknown |

## Endpoint observations

| Endpoint | Status |
|---|---|
| `main` branch protection | unknown |
| repository rulesets | observed; count=unknown |
| private vulnerability reporting | observed |
| code-security configuration | observed |

The raw, sanitized response envelope is committed in
[`../governance/github-settings-snapshot.json`](../governance/github-settings-snapshot.json).

## Interpretation rules

- `observed` means the authenticated owner CLI returned a parseable response.
- `unknown` means the endpoint was unavailable, unsupported or returned a non-success response.
- An unknown value is not treated as enabled or disabled.
- This snapshot is evidence for one time and commit; it is not a permanent guarantee.
- Repository UI settings must be rechecked before releases or security-sensitive capability
  promotion.

## Required repository policy

Independent of API visibility, the intended policy is:

- `main` accepts changes through reviewed pull requests;
- required CI includes Python, Rust, documentation and evidence-governance checks;
- squash merge is the normal single-lot merge method;
- feature branches are deleted after verified merge;
- private vulnerability reporting remains the security-reporting path;
- secrets, raw provider evidence and personal paths are prohibited from Git history;
- CODEOWNERS covers workflows, provider contracts, security runtime and normative documentation.

Unsupported API queries remain explicitly **unknown** and require manual owner verification.
