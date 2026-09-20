# Owner Handoff

## What Was Set Up

- Replaced the old Flask demonstration with one bounded external verifier.
- Added an explicit Hivra plugin catalog trust root.
- Added catalog signature, package digest, canonical ZIP, manifest, and WASM
  checks.
- Added offline positive and negative mutation tests.
- Added one live consumer probe in GitHub Actions.
- Documented contribution and security boundaries.

No Hivra runtime code, private material, VPS state, or release authority was
copied into this repository.

## Your Responsibility

Own the external-consumer view of Hivra public surfaces:

1. Run verification against every published plugin catalog entry and package.
2. Keep failures reproducible from a clean clone.
3. Open focused upstream issues when a public package cannot be independently
   verified.
4. Maintain bounded public website and Capsule release checks here only when
   they consume public artifacts and do not duplicate implementation.
5. Submit product fixes through focused forks and upstream pull requests rather
   than implementing an alternative runtime here.
6. Keep this repository external and read-only; reject signing, deployment,
   trading, Capsule data, VPS access, and unrelated DevOps work.

## First Owner Actions

### Start With One Small Contribution

First run these commands from this repository, not from Hivra-App:

```bash
python3 -m unittest discover -s tests -v
./verify.sh --self-test
```

The live command checks published packages only. It does not test trading,
chat delivery, or the safety of executing a plugin.

Read `test_rejects_signed_package_with_unsupported_abi` in
`tests/test_verifier.py` as a worked example. It changes the manifest, rebuilds
the archive, updates its digest, and signs the catalog with an ephemeral test
key. Signature verification succeeds, but the incompatible ABI is rejected.
Keeping the old digest would test only hash mismatch, not ABI validation.

Your first task: add equivalent tests for an unsupported `entry_export` and a
wrong `module_path`. Reuse the existing fixture and verifier. Assert the specific
validation error and retain the valid-package test. Do not change the real trust
store, download or execute WASM, or copy Hivra runtime code. Run the offline suite
and the live command, then open one PR in this repository with the test results.
If a mutation is unexpectedly accepted, report the observed input and output
before broadening the implementation. No Hivra-App PR is needed for these tests.

### Repository Setup

1. Review the initial implementation and MIT license.
2. The `opsnex/Hivra-App` fork exists. Sync it before a separately agreed upstream
   product fix; this verifier task does not require changing it.
3. Enable branch protection for `main` and require the `verify` check.
4. Rotate or revoke any temporary SSH credential delegated for bootstrap after
   confirming your own access.
5. Review any trust-root change manually before merging it.

## Definition Of Done For Future Changes

A fresh clone can run one documented command, accept the authentic published
package, reject mutated catalog/package bytes, and explain the result without
access to any Hivra development worktree.
