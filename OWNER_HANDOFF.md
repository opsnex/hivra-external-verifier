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

1. Review the initial implementation and MIT license.
2. Create or restore your fork of `WSorr/Hivra-App` before upstream work.
3. Enable branch protection for `main` and require the `verify` check.
4. Rotate or revoke any temporary SSH credential delegated for bootstrap after
   confirming your own access.
5. Review any trust-root change manually before merging it.

## Definition Of Done For Future Changes

A fresh clone can run one documented command, accept the authentic published
package, reject mutated catalog/package bytes, and explain the result without
access to any Hivra development worktree.
