# Security Policy

## Supported Surface

Only the latest `main` branch is maintained. The verifier handles remote
catalog and ZIP bytes as untrusted input, verifies signatures and digests before
trusting metadata, and inspects archives without extracting or executing them.

## Report A Vulnerability

Do not open a public issue for a vulnerability that could expose secrets or
allow a malicious package to pass verification. Contact the repository owner
privately through their GitHub profile and include:

- the affected commit;
- the smallest reproducing input;
- expected and actual behavior;
- whether the issue also affects Hivra-App or hivra-plugins.

Never include private keys, credentials, Capsule data, or production evidence.

## Trust Changes

`trust/hivra-plugin-signers.json` is security-sensitive. A signer addition,
replacement, or removal must be reviewed independently against the canonical
Hivra-App trust root before merge.
