# ADR 0012: Preserve reviewed evidence across squash-only integration

Status: accepted

Date: 2026-07-27

## Context

C0 through C4 were deliberately reviewed as five stacked pull requests with
exact base and head commits. Their seals bind those commits, and several
historical tests recompute the sealed diffs.

The repository protects `main` with required linear history and permits only
squash merges. It also deletes a merged head branch automatically. Merging the
five stacked pull requests independently would rewrite their commit identities
and make later pull requests depend on deleted bases.

An exact local simulation of the aggregate C4 tree on `main` had no content
conflict. Under Python 3.12, 1,015 tests passed and the C4 seal/HEAD invariant
failed as designed because the simulated `HEAD` still identified the old main
commit rather than the sealed C4 tree.

## Decision

Integrate C0 through C4 with one aggregate pull request targeting `main`.

The integration has three independent commitments:

1. `governance/c5-integration-manifest.json` binds the exact main base, five
   historical pull requests, branches, heads, squash method, issue, and
   evidence tag.
2. `governance/c5-change-seal.json` binds the aggregate binary diff and a
   framed SHA-256 commitment over every tracked blob, mode, and UTF-8 path
   except the self-referential seal.
3. `evidence/c0-c4-main-integration-v2` points to the final integration-branch
   seal commit and therefore keeps every C0 through C4 commit reachable after
   the aggregate pull request is squash-merged.

Historical C4 verification compares its covered commit with the exact final
C4 seal commit. It does not compare a historical seal to an unrelated future
`HEAD`. C5 separately proves that the current tree is byte-for-byte and
mode-for-mode equal to the sealed aggregate tree.

The historical stacked pull requests must not be merged independently. After
the aggregate pull request and `main` CI succeed, they may be closed as
superseded. Their branches remain evidence references and are not runtime
authorization.

## Consequences

- `main` can receive the reviewed aggregate tree without weakening C0 through
  C4 decisions or losing their commit objects.
- Any later tracked-file change invalidates the C5 tree commitment until a
  deliberate successor seal is reviewed.
- A Git tag is evidence retention, not release authorization and not provider
  capability evidence.
- C1 and C4 live boundaries remain fail closed. Integration performs no
  credential, Tunnel, Plugin, browser, ChatGPT, listener, or tool action.
- The aggregate pull request is intentionally large because splitting it
  would recreate the squash/base-identity problem.

## Rejected alternatives

- **Merge each stacked pull request with squash.** This rewrites exact
  identities and destabilizes dependent bases.
- **Enable merge commits or bypass the ruleset.** This changes repository
  governance to accommodate one stack and bypasses the required review path.
- **Remove historical SHA checks.** This weakens evidence instead of adapting
  its lifecycle.
- **Leave the stack open indefinitely.** This preserves evidence but prevents
  the validated implementation from reaching `main`.
- **Trust only a tag or only a tree hash.** The tag preserves ancestry while
  the framed tree commitment proves integrated content; both are required.

The initially published `v1` tag identifies the pre-correction candidate whose
manual governance run failed because the workflow used a shallow checkout. It
is retained as rejected evidence and is never moved. Only `v2` is accepted by
the strict manifest and verifier.
