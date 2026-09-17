#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

command -v python3 >/dev/null 2>&1 || {
  printf 'error: python3 is required\n' >&2
  exit 1
}
command -v openssl >/dev/null 2>&1 || {
  printf 'error: openssl is required\n' >&2
  exit 1
}

exec python3 -m opsnex_verifier "$@"
