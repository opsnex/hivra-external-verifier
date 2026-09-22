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
    parse_checksum_document,
    parse_release_metadata,
    validate_release_document,
    validate_release_lineage,
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


class ReleaseVerifierTest(unittest.TestCase):
    tag = "v1.0.3-test21"
    source_commit = "1" * 40
    tag_commit = "2" * 40
    mac_name = f"hivra_app-{tag}-macos-universal.zip"
    android_name = f"hivra_app-{tag}-android-universal.apk"
    mac_meta_name = "RELEASE-METADATA-macos.txt"
    android_meta_name = "RELEASE-METADATA-android.txt"
    sums_name = f"SHA256SUMS-{tag}.txt"

    def setUp(self) -> None:
        self.digests = {
            self.mac_name: "a" * 64,
            self.android_name: "b" * 64,
            self.mac_meta_name: "c" * 64,
            self.android_meta_name: "d" * 64,
        }
        names = (
            self.mac_name,
            self.android_name,
            self.mac_meta_name,
            self.android_meta_name,
            self.sums_name,
        )
        self.release = {
            "tag_name": self.tag,
            "draft": False,
            "prerelease": True,
            "assets": [
                {
                    "name": name,
                    "state": "uploaded",
                    "digest": f"sha256:{'e' * 64}",
                    "browser_download_url": (
                        "https://github.com/WSorr/Hivra-App/releases/download/"
                        f"{self.tag}/{name}"
                    ),
                }
                for name in names
            ],
        }

    def test_accepts_complete_pinned_release_document(self) -> None:
        assets = validate_release_document(self.release, self.tag)
        self.assertEqual(
            set(assets),
            {asset["name"] for asset in self.release["assets"]},
        )

    def test_rejects_unpinned_release_asset_url(self) -> None:
        mutated = copy.deepcopy(self.release)
        mutated["assets"][0]["browser_download_url"] = (
            "https://example.invalid/release.zip"
        )
        with self.assertRaisesRegex(ValidationError, "not pinned"):
            validate_release_document(mutated, self.tag)

    def test_binds_release_urls_to_selected_repository(self) -> None:
        with self.assertRaisesRegex(ValidationError, "not pinned"):
            validate_release_document(
                self.release,
                self.tag,
                repository="opsnex/hivra-external-verifier",
            )

    def test_rejects_duplicate_release_asset(self) -> None:
        mutated = copy.deepcopy(self.release)
        mutated["assets"].append(copy.deepcopy(mutated["assets"][0]))
        with self.assertRaisesRegex(ValidationError, "duplicate release asset"):
            validate_release_document(mutated, self.tag)

    def test_accepts_canonical_checksum_document(self) -> None:
        raw = "".join(
            f"{digest}  {name}\n" for name, digest in self.digests.items()
        ).encode()
        self.assertEqual(
            parse_checksum_document(raw, set(self.digests)), self.digests
        )

    def test_rejects_checksum_path_or_duplicate(self) -> None:
        raw = (
            f"{'a' * 64}  {self.mac_name}\n"
            f"{'a' * 64}  {self.mac_name}\n"
            f"{'b' * 64}  ../{self.android_name}\n"
        ).encode()
        with self.assertRaises(ValidationError):
            parse_checksum_document(raw, set(self.digests))

    def test_accepts_clean_release_metadata(self) -> None:
        raw = self._metadata(self.mac_name, self.digests[self.mac_name])
        values = parse_release_metadata(
            raw,
            tag=self.tag,
            channel="test",
            asset_name=self.mac_name,
            asset_sha256=self.digests[self.mac_name],
        )
        self.assertEqual(values["source_commit"], self.source_commit)

    def test_rejects_dirty_or_mismatched_release_metadata(self) -> None:
        raw = self._metadata(
            self.mac_name,
            self.digests[self.mac_name],
            dirty="yes",
        )
        with self.assertRaisesRegex(ValidationError, "dirty source tree"):
            parse_release_metadata(
                raw,
                tag=self.tag,
                channel="test",
                asset_name=self.mac_name,
                asset_sha256=self.digests[self.mac_name],
            )

    def test_accepts_only_signoff_change_after_build(self) -> None:
        validate_release_lineage(
            source_commit=self.source_commit,
            tag_commit=self.tag_commit,
            changed_files={"docs/checklists/release-manual-signoff-log.md"},
        )

    def test_rejects_runtime_change_after_build(self) -> None:
        with self.assertRaisesRegex(ValidationError, "runtime-affecting"):
            validate_release_lineage(
                source_commit=self.source_commit,
                tag_commit=self.tag_commit,
                changed_files={"flutter/lib/main.dart"},
            )

    def _metadata(
        self, asset_name: str, asset_sha256: str, *, dirty: str = "no"
    ) -> bytes:
        return (
            f"version={self.tag}\n"
            f"source_commit={self.source_commit}\n"
            f"source_tree_dirty={dirty}\n"
            "flutter_build_name=1.0.3\n"
            "flutter_build_number=100030219\n"
            "channel=test\n"
            f"asset={asset_name}\n"
            f"asset_sha256={asset_sha256}\n"
        ).encode()


if __name__ == "__main__":
    unittest.main()
