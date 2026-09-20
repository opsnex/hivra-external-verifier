import copy
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from opsnex_verifier.verifier import (
    TrustedSigner,
    ValidationError,
    canonical_json,
    verify_archive_bytes,
    verify_catalog_document,
)


def canonical_archive(manifest: dict) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, payload in (
            (
                "plugin/manifest.json",
                (json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8"),
            ),
            ("plugin/module.wasm", b"\x00asm\x01\x00\x00\x00"),
        ):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, payload)
    return output.getvalue()


class VerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="opsnex_verifier_test_")
        self.root = Path(self.temp.name)
        self.private_key = self.root / "key.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                str(self.private_key),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        public_der = subprocess.check_output(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-outform",
                "DER",
            ],
            stderr=subprocess.DEVNULL,
        )
        self.public_key_hex = public_der[-32:].hex()
        self.key_id = hashlib.sha256(bytes.fromhex(self.public_key_hex)).hexdigest()
        self.trust = {
            self.key_id: TrustedSigner(
                source_id="test.source",
                key_id=self.key_id,
                public_key_hex=self.public_key_hex,
            )
        }
        self.manifest = {
            "schema": "hivra.plugin.manifest",
            "version": 1,
            "release_version": "1.2.3",
            "plugin_id": "example.plugin",
            "capabilities": ["example.read"],
            "contract": {"kind": "example_contract"},
            "runtime": {
                "abi": "hivra_host_abi_v2",
                "entry_export": "hivra_evaluate_v1",
                "module_path": "plugin/module.wasm",
            },
        }
        self.package = canonical_archive(self.manifest)
        self.entry = {
            "id": "example",
            "plugin_id": "example.plugin",
            "version": "1.2.3",
            "package_kind": "zip",
            "download_url": (
                "https://example.invalid/releases/download/v1/example-1.2.3.zip"
            ),
            "sha256_hex": hashlib.sha256(self.package).hexdigest(),
        }
        self.catalog = self._signed_catalog(self.entry)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _signed_catalog(self, entry: dict) -> dict:
        unsigned = {
            "schema": "hivra.plugin.catalog",
            "version": 2,
            "source_id": "test.source",
            "source_name": "Test Source",
            "entries": [copy.deepcopy(entry)],
        }
        payload = self.root / "catalog.json"
        signature = self.root / "catalog.sig"
        payload.write_bytes(canonical_json(unsigned))
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(self.private_key),
                "-in",
                str(payload),
                "-out",
                str(signature),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return {
            **unsigned,
            "signatures": [
                {
                    "algorithm": "ed25519",
                    "key_id": self.key_id,
                    "signature_hex": signature.read_bytes().hex(),
                }
            ],
        }

    def test_accepts_signed_catalog_and_canonical_package(self) -> None:
        entries = verify_catalog_document(self.catalog, self.trust)
        result = verify_archive_bytes(entries[0], self.package)
        self.assertEqual(result.plugin_id, "example.plugin")
        self.assertEqual(result.version, "1.2.3")

    def test_rejects_catalog_mutation(self) -> None:
        mutated = copy.deepcopy(self.catalog)
        mutated["entries"][0]["version"] = "9.9.9"
        with self.assertRaisesRegex(ValidationError, "trusted signature"):
            verify_catalog_document(mutated, self.trust)

    def test_rejects_package_mutation(self) -> None:
        mutated = bytearray(self.package)
        mutated[-1] ^= 0x01
        with self.assertRaisesRegex(ValidationError, "digest mismatch"):
            verify_archive_bytes(self.entry, bytes(mutated))

    def test_rejects_manifest_identity_mismatch(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["plugin_id"] = "other.plugin"
        package = canonical_archive(manifest)
        entry = {**self.entry, "sha256_hex": hashlib.sha256(package).hexdigest()}
        with self.assertRaisesRegex(ValidationError, "plugin_id mismatch"):
            verify_archive_bytes(entry, package)

    def test_rejects_duplicate_capability(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["capabilities"] = ["example.read", "example.read"]
        package = canonical_archive(manifest)
        entry = {**self.entry, "sha256_hex": hashlib.sha256(package).hexdigest()}
        with self.assertRaisesRegex(ValidationError, "duplicated"):
            verify_archive_bytes(entry, package)

    def test_rejects_signed_package_with_unsupported_abi(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["runtime"]["abi"] = "unsupported_abi"
        package = canonical_archive(manifest)
        entry = {**self.entry, "sha256_hex": hashlib.sha256(package).hexdigest()}
        # A valid signature and matching digest must not bypass compatibility.
        catalog = self._signed_catalog(entry)
        verified_entries = verify_catalog_document(catalog, self.trust)
        with self.assertRaisesRegex(ValidationError, "unsupported host ABI"):
            verify_archive_bytes(verified_entries[0], package)


if __name__ == "__main__":
    unittest.main()
