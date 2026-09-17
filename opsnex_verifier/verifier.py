from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_CATALOG_URL = (
    "https://raw.githubusercontent.com/WSorr/hivra-plugins/"
    "refs/heads/main/catalog/plugin_catalog.json"
)
DEFAULT_TRUST_STORE = (
    Path(__file__).resolve().parent.parent
    / "trust"
    / "hivra-plugin-signers.json"
)
MAX_CATALOG_BYTES = 1_000_000
MAX_PACKAGE_BYTES = 16_000_000
EXPECTED_ARCHIVE_ENTRIES = (
    "plugin/manifest.json",
    "plugin/module.wasm",
)
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class ValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class TrustedSigner:
    source_id: str
    key_id: str
    public_key_hex: str


@dataclass(frozen=True)
class VerificationResult:
    entry_id: str
    plugin_id: str
    version: str
    package_sha256: str
    manifest_sha256: str
    wasm_sha256: str


def _require_hex(value: Any, length: int, field: str) -> str:
    normalized = str(value or "").strip().lower()
    if re.fullmatch(rf"[0-9a-f]{{{length}}}", normalized) is None:
        raise ValidationError(f"{field} must be {length} lowercase hex chars")
    return normalized


def _require_non_empty(value: Any, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValidationError(f"{field} must be non-empty")
    return normalized


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def load_trust_store(path: Path = DEFAULT_TRUST_STORE) -> dict[str, TrustedSigner]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"cannot read trust store: {error}") from error

    if document.get("schema") != "opsnex.hivra.plugin.signers":
        raise ValidationError("unsupported trust-store schema")
    if document.get("version") != 1:
        raise ValidationError("unsupported trust-store version")
    signers = document.get("signers")
    if not isinstance(signers, list) or not signers:
        raise ValidationError("trust store must contain signers")

    result: dict[str, TrustedSigner] = {}
    for index, raw in enumerate(signers):
        if not isinstance(raw, dict):
            raise ValidationError(f"signers[{index}] must be an object")
        source_id = _require_non_empty(raw.get("source_id"), "source_id")
        key_id = _require_hex(raw.get("key_id"), 64, "key_id")
        public_key_hex = _require_hex(
            raw.get("public_key_hex"), 64, "public_key_hex"
        )
        actual_key_id = hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()
        if actual_key_id != key_id:
            raise ValidationError(f"public key does not match key id {key_id}")
        if key_id in result:
            raise ValidationError(f"duplicate trusted key id {key_id}")
        result[key_id] = TrustedSigner(source_id, key_id, public_key_hex)
    return result


def _verify_ed25519(public_key_hex: str, signature_hex: str, payload: bytes) -> bool:
    public_der = ED25519_SPKI_PREFIX + bytes.fromhex(public_key_hex)
    with tempfile.TemporaryDirectory(prefix="opsnex_plugin_verify_") as temp:
        root = Path(temp)
        payload_path = root / "payload.json"
        signature_path = root / "signature.bin"
        public_key_path = root / "public-key.der"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(bytes.fromhex(signature_hex))
        public_key_path.write_bytes(public_der)
        try:
            completed = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    str(public_key_path),
                    "-in",
                    str(payload_path),
                    "-sigfile",
                    str(signature_path),
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError as error:
            raise ValidationError("openssl is required") from error
    return completed.returncode == 0


def _validated_entries(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    if catalog.get("schema") != "hivra.plugin.catalog":
        raise ValidationError("unsupported catalog schema")
    if catalog.get("version") != 2:
        raise ValidationError("unsupported catalog version")
    _require_non_empty(catalog.get("source_id"), "source_id")

    entries = catalog.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValidationError("catalog must contain entries")
    seen_entry_ids: set[str] = set()
    seen_plugin_ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValidationError(f"entries[{index}] must be an object")
        entry_id = _require_non_empty(entry.get("id"), "entry.id")
        plugin_id = _require_non_empty(entry.get("plugin_id"), "entry.plugin_id")
        _require_non_empty(entry.get("version"), "entry.version")
        if entry.get("package_kind") != "zip":
            raise ValidationError(f"{entry_id}: package_kind must be zip")
        _require_hex(entry.get("sha256_hex"), 64, f"{entry_id}.sha256_hex")
        if entry_id in seen_entry_ids or plugin_id in seen_plugin_ids:
            raise ValidationError("catalog contains duplicate entry or plugin id")
        seen_entry_ids.add(entry_id)
        seen_plugin_ids.add(plugin_id)

        download_url = _require_non_empty(
            entry.get("download_url"), f"{entry_id}.download_url"
        )
        parsed = urlparse(download_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValidationError(f"{entry_id}: package URL must use HTTPS")
        if "/releases/latest/" in parsed.path:
            raise ValidationError(f"{entry_id}: latest release URL is forbidden")
        if re.search(r"/releases/download/[^/]+/[^/]+$", parsed.path) is None:
            raise ValidationError(f"{entry_id}: package URL must pin a release tag")
    return entries


def verify_catalog_document(
    catalog: dict[str, Any],
    trusted_signers: dict[str, TrustedSigner],
) -> list[dict[str, Any]]:
    entries = _validated_entries(catalog)
    signatures = catalog.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise ValidationError("catalog must contain signatures")

    unsigned = dict(catalog)
    unsigned.pop("signatures", None)
    payload = canonical_json(unsigned)
    source_id = str(catalog["source_id"])
    for index, signature in enumerate(signatures):
        if not isinstance(signature, dict):
            raise ValidationError(f"signatures[{index}] must be an object")
        if signature.get("algorithm") != "ed25519":
            continue
        key_id = _require_hex(signature.get("key_id"), 64, "signature.key_id")
        signature_hex = _require_hex(
            signature.get("signature_hex"), 128, "signature.signature_hex"
        )
        signer = trusted_signers.get(key_id)
        if signer is None or signer.source_id != source_id:
            continue
        if _verify_ed25519(signer.public_key_hex, signature_hex, payload):
            return entries
    raise ValidationError("catalog has no valid trusted signature")


def _decode_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValidationError(f"{label} root must be an object")
    return value


def verify_archive_bytes(
    entry: dict[str, Any], package_bytes: bytes
) -> VerificationResult:
    entry_id = str(entry["id"])
    expected_digest = str(entry["sha256_hex"]).lower()
    actual_digest = hashlib.sha256(package_bytes).hexdigest()
    if actual_digest != expected_digest:
        raise ValidationError(
            f"{entry_id}: package digest mismatch; "
            f"expected={expected_digest} actual={actual_digest}"
        )

    try:
        with zipfile.ZipFile(io.BytesIO(package_bytes), "r") as archive:
            if archive.comment:
                raise ValidationError(f"{entry_id}: ZIP comment is forbidden")
            members = archive.infolist()
            if tuple(member.filename for member in members) != EXPECTED_ARCHIVE_ENTRIES:
                raise ValidationError(f"{entry_id}: non-canonical archive entries")
            for member in members:
                if (
                    member.date_time != (1980, 1, 1, 0, 0, 0)
                    or member.compress_type != zipfile.ZIP_STORED
                    or member.create_system != 3
                    or member.external_attr != 0o100644 << 16
                    or member.extra
                    or member.comment
                    or member.flag_bits & 0x1
                ):
                    raise ValidationError(
                        f"{entry_id}: non-canonical metadata for {member.filename}"
                    )
            manifest_bytes = archive.read("plugin/manifest.json")
            wasm_bytes = archive.read("plugin/module.wasm")
    except (KeyError, zipfile.BadZipFile) as error:
        raise ValidationError(f"{entry_id}: invalid plugin archive") from error

    manifest = _decode_json(manifest_bytes, f"{entry_id} manifest")
    if (
        manifest.get("schema") != "hivra.plugin.manifest"
        or manifest.get("version") != 1
    ):
        raise ValidationError(f"{entry_id}: unsupported manifest contract")
    if manifest.get("plugin_id") != entry.get("plugin_id"):
        raise ValidationError(f"{entry_id}: manifest plugin_id mismatch")
    if str(manifest.get("release_version")) != str(entry.get("version")):
        raise ValidationError(f"{entry_id}: manifest version mismatch")
    runtime = manifest.get("runtime")
    if not isinstance(runtime, dict):
        raise ValidationError(f"{entry_id}: manifest runtime is missing")
    if runtime.get("abi") != "hivra_host_abi_v2":
        raise ValidationError(f"{entry_id}: unsupported host ABI")
    if runtime.get("entry_export") != "hivra_evaluate_v1":
        raise ValidationError(f"{entry_id}: unsupported entry export")
    if runtime.get("module_path") != "plugin/module.wasm":
        raise ValidationError(f"{entry_id}: module path mismatch")
    contract = manifest.get("contract")
    if not isinstance(contract, dict) or not str(contract.get("kind") or "").strip():
        raise ValidationError(f"{entry_id}: contract kind is missing")
    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        raise ValidationError(f"{entry_id}: capabilities are missing")
    normalized_capabilities = [str(value or "").strip() for value in capabilities]
    if (
        any(not value for value in normalized_capabilities)
        or len(set(normalized_capabilities)) != len(normalized_capabilities)
    ):
        raise ValidationError(f"{entry_id}: capabilities are invalid or duplicated")
    if not wasm_bytes.startswith(b"\x00asm"):
        raise ValidationError(f"{entry_id}: module has no WASM magic")

    return VerificationResult(
        entry_id=entry_id,
        plugin_id=str(entry["plugin_id"]),
        version=str(entry["version"]),
        package_sha256=actual_digest,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        wasm_sha256=hashlib.sha256(wasm_bytes).hexdigest(),
    )


def _fetch_bytes(url: str, max_bytes: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "opsnex-hivra-plugin-verifier/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if urlparse(response.geturl()).scheme != "https":
                raise ValidationError("redirect left HTTPS")
            payload = response.read(max_bytes + 1)
    except ValidationError:
        raise
    except Exception as error:
        raise ValidationError(f"download failed for {url}: {error}") from error
    if len(payload) > max_bytes:
        raise ValidationError(f"download exceeded {max_bytes} bytes")
    return payload


def _select_entries(
    entries: list[dict[str, Any]], requested_ids: list[str]
) -> list[dict[str, Any]]:
    if not requested_ids:
        return entries
    by_id = {str(entry["id"]): entry for entry in entries}
    missing = sorted(set(requested_ids) - set(by_id))
    if missing:
        raise ValidationError(f"unknown plugin ids: {', '.join(missing)}")
    return [by_id[entry_id] for entry_id in requested_ids]


def _run_live(args: argparse.Namespace) -> list[VerificationResult]:
    catalog_bytes = _fetch_bytes(args.catalog_url, MAX_CATALOG_BYTES)
    catalog = _decode_json(catalog_bytes, "catalog")
    trusted_signers = load_trust_store(args.trust_store)
    entries = verify_catalog_document(catalog, trusted_signers)

    if args.self_test:
        mutated = copy.deepcopy(catalog)
        mutated["entries"][0]["display_name"] = (
            str(mutated["entries"][0].get("display_name", "")) + " mutation"
        )
        try:
            verify_catalog_document(mutated, trusted_signers)
        except ValidationError:
            pass
        else:
            raise ValidationError("catalog mutation was accepted")

    results: list[VerificationResult] = []
    for entry in _select_entries(entries, args.plugin_id):
        package_bytes = _fetch_bytes(str(entry["download_url"]), MAX_PACKAGE_BYTES)
        result = verify_archive_bytes(entry, package_bytes)
        if args.self_test:
            mutated_package = bytearray(package_bytes)
            mutated_package[-1] ^= 0x01
            try:
                verify_archive_bytes(entry, bytes(mutated_package))
            except ValidationError:
                pass
            else:
                raise ValidationError(
                    f"{result.entry_id}: package mutation was accepted"
                )
        results.append(result)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify published Hivra plugin packages as an external consumer."
    )
    parser.add_argument("--catalog-url", default=DEFAULT_CATALOG_URL)
    parser.add_argument("--trust-store", type=Path, default=DEFAULT_TRUST_STORE)
    parser.add_argument(
        "--plugin-id",
        action="append",
        default=[],
        help="Catalog entry id to verify; repeat for multiple entries.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Also require catalog and package mutations to fail.",
    )
    args = parser.parse_args()

    try:
        results = _run_live(args)
    except ValidationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error

    for result in results:
        print(
            "verified "
            f"id={result.entry_id} plugin={result.plugin_id} "
            f"version={result.version} zip_sha256={result.package_sha256} "
            f"manifest_sha256={result.manifest_sha256} "
            f"wasm_sha256={result.wasm_sha256}"
        )
    print(f"verification passed: {len(results)} package(s)")
