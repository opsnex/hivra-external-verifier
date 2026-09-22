# Security Policy

## Supported Surface

Only the latest `main` branch is maintained. The verifier handles remote
catalogs, release documents, metadata, checksums, ZIPs, and application
binaries as untrusted input. It verifies signatures or publication digests
before trusting metadata and inspects plugin archives without extracting or
executing them.

GitHub is the publication source for Capsule release assets and tag lineage.
Release verification proves consistency with that source; it is not an
independent release signature, notarization, or execution-safety assessment.

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
