# Opxnex Hivra External Verifier

This repository is an independent consumer workspace for published Hivra
surfaces. Its current implementation verifies the WASM plugin supply chain
from outside the Hivra source tree.

It is not a Hivra mirror, a second plugin registry, or an alternative runtime.
The canonical projects remain:

- [WSorr/Hivra-App](https://github.com/WSorr/Hivra-App)
- [WSorr/hivra-plugins](https://github.com/WSorr/hivra-plugins)

Hivra changes should be proposed from an Opxnex fork of `WSorr/Hivra-App`.
Create or restore that fork before the first upstream contribution. This
repository owns only external verification. Public website and Capsule release
checks may be added here when they consume public artifacts without copying
product implementation or creating another deployment path.

## What It Proves

The verifier starts from bounded untrusted bytes and checks:

1. the catalog schema and immutable release URLs;
2. the Ed25519 catalog signature against an explicit local trust root;
3. each selected package SHA-256 digest;
4. canonical ZIP entry order and metadata;
5. manifest identity, version, ABI, and entry export;
6. the WASM magic header;
7. rejection of mutated catalog and package bytes.

It never executes plugin WASM and never accesses Capsule data, credentials,
release signing keys, a VPS, or an exchange.

## Requirements

- Python 3.11 or newer
- OpenSSL with Ed25519 support
- HTTPS access to GitHub release assets

No Python packages are required.

## Run

Verify every entry in the current signed catalog:

```bash
./verify.sh --self-test
```

Verify one catalog entry:

```bash
./verify.sh --plugin-id capsule-chat-test --self-test
```

Use `--catalog-url` only when intentionally testing another signed catalog.
Changing `trust/hivra-plugin-signers.json` changes the trust boundary and must
receive explicit review.

## Test

The offline suite creates an ephemeral Ed25519 signer and canonical test
archive, then proves positive verification and negative mutations:

```bash
python3 -m unittest discover -s tests -v
```

## Contribution Boundary

Opxnex owns external consumer evidence and reports upstream defects through
issues or focused pull requests. Hivra Core, Ledger, package production,
catalog signing, and release publication stay in their canonical repositories.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[OWNER_HANDOFF.md](OWNER_HANDOFF.md).
