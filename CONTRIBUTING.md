# Contributing

## Scope

Changes must improve independent verification of published Hivra plugin
packages. Keep the implementation dependency-free unless a concrete security
requirement cannot be met with Python and OpenSSL.

## Rules

- Use English in code, documentation, issues, and pull requests.
- Start from untrusted bytes and fail closed.
- Do not execute WASM or extract archives to the filesystem.
- Do not copy Hivra Core, Ledger, host, or plugin implementation code here.
- Do not add credentials, private keys, Capsule exports, VPS data, or release
  signing material.
- Do not create a second catalog or package publication path.
- Report upstream defects in the repository that owns the defective behavior.

## Before A Pull Request

```bash
python3 -m unittest discover -s tests -v
./verify.sh --plugin-id capsule-chat-test --self-test
```

Describe the external behavior that changed and the exact untrusted input that
is now accepted or rejected.
