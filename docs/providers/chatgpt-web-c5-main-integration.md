# C5 squash-safe C0-C4 main integration

Status: `implemented` on the C5 integration branch; merge requires final-head
CI and post-merge `main` CI.

Issue: [#73](https://github.com/Cheurteenyt/systeme-local/issues/73)

## Purpose

C5 changes no ChatGPT capability and grants no runtime action. It preserves
the reviewed C0 through C4 evidence while moving their aggregate tree through
the repository's squash-only `main` boundary.

PRs #65, #67, #68, #70, and #72 are historical stacked review units. They
must not be merged independently. Their exact heads are committed in
`governance/c5-integration-manifest.json`.

## Merge-readiness audit

GitHub reports all five historical pull requests as clean, draft, and green.
None has a submitted review. The active repository ruleset requires a pull
request, strict up-to-date `test`, linear history, and squash; it permits zero
required approvals. Automatic merged-branch deletion is enabled.

An isolated worktree reproduced the aggregate squash of exact C4 head
`3a1d2b8286773eaaf69b0b41fade978f09403adb` onto exact main
`32515ac9cbb9d658b2ddcb2723ab3c0a71f2b418`:

- 146 changed files;
- zero merge conflicts;
- lock and Ruff checks passed;
- under the accidental Python 3.11 environment, 1,015 passed, 6 skipped, and
  two tests failed;
- the provider canonicalization result was confirmed environment-specific and
  passed when repeated under the required Python 3.12 environment;
- under Python 3.12, the sole remaining failure was the C4 seal/HEAD invariant.

The final failure was required evidence that a direct squash must not proceed.
It is not removed: historical C4 verification is now bound to the exact final
C4 seal commit, while C5 owns future-tree integration.

## Exact contract

The C5 manifest binds:

- main base `32515ac9cbb9d658b2ddcb2723ab3c0a71f2b418`;
- C0 head `912d0d33e119469ff957965104cf20af5e491923`;
- C1 head `2aee36fdfa3d20c23acdc75eb3348bc54536ef4f`;
- C2 head `cf05e963ba30539f9b2c9ec2f5f71326cbba8399`;
- C3 head `9140801e88ed44afca9481ac06288783a0d52da2`;
- C4 head `3a1d2b8286773eaaf69b0b41fade978f09403adb`;
- branch `interop/c0-c4-main-integration-c5`;
- merge method `squash`;
- evidence tag `evidence/c0-c4-main-integration-v1`;
- zero live actions.

The self-excluding C5 seal commits two independent values:

1. a SHA-256 of the exact binary diff from the main base to the covered C5
   head, excluding only the seal;
2. a framed SHA-256 tree commitment over each tracked UTF-8 path, Git mode,
   blob length, and blob bytes, again excluding only the seal.

The outer SHA-256 hashes actual blob bytes, not Git SHA-1 identifiers.
Changing, adding, removing, renaming, or changing the mode of a tracked file
changes the commitment.

## Verification sequence

The verifier is local, deterministic, secret-free, and network-free:

```powershell
uv run --frozen python -m systeme_local_gateway.c5_integration verify `
  --root . `
  --require-clean
```

It verifies strict schemas, the canonical manifest digest, exact ancestry,
the one-file final seal commit, aggregate binary-diff bytes, evidence tag,
covered tree, tagged tree, and current tree. It returns no environment values.

## Merge sequence

1. finish local Python, PowerShell, Rust, dependency, documentation, secret,
   governance, and clean-tree checks;
2. commit the covered C5 head;
3. generate and commit only `governance/c5-change-seal.json`;
4. create the immutable evidence tag at the seal commit;
5. push the branch and tag, then open one aggregate pull request to `main`;
6. require all final-head CI jobs and manual evidence governance to pass;
7. squash-merge with expected-head protection;
8. require the resulting `main` CI to pass and rerun C5 verification;
9. close PRs #65, #67, #68, #70, and #72 as superseded without deleting
   their evidence branches.

No step creates or reads a Runtime key, Tunnel ID, provider secret, Plugin,
browser state, ChatGPT chat, listener, or tunnel process.

## Pre-seal local validation

The covered-head candidate was checked under Python 3.12:

- Ruff passed for all files and the C5 Python files pass Ruff formatting;
- Mypy passed across 30 configured source files;
- 49 Markdown files passed link validation;
- 1,023 tests passed, 6 platform tests skipped, and only the final
  tag-dependent C5 verification test was deliberately deselected before the
  tag existed;
- `git diff --check` passed;
- sensitive process variables, listeners on 8765/8766, and `tunnel-client`
  processes were all absent.

The first complete typing-ratchet invocation correctly rejected a scope
mismatch: `c5_integration.py` was present in `pyproject.toml` but absent from
the governance mirror. C5 added the exact scope entry to
`governance/mypy-baseline.json`; it added no diagnostic or waiver.

The known Windows pytest temporary-directory `PermissionError` occurred only
in its post-success `atexit` callback and did not change the zero test exit
code. Final verification, coverage, Rust, dependency, PowerShell, CI, and
manual-governance results are recorded in the aggregate pull-request
closeout rather than rewritten into the sealed source tree.

## Security boundary

C5 is repository evidence governance. It is not official provider evidence,
does not promote C3, does not create C4 admission, and does not turn an
unsupported Chat capability into a supported one. Current ChatGPT admission
remains six denials, zero effective tools, and zero live actions.

The evidence tag is intentionally not a release or authorization tag. A moved
or missing tag fails ancestry/tree verification. A matching tag cannot grant a
runtime capability.
