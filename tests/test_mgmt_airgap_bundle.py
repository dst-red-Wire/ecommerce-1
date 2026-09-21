"""Deterministic source-lock tests for the local MGMT air-gap bundle builder."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json"
SPEC = importlib.util.spec_from_file_location(
    "build_mgmt_airgap_bundle", ROOT / "scripts/build_mgmt_airgap_bundle.py"
)
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
AIRGAP_SPEC = importlib.util.spec_from_file_location("mgmt_airgap", ROOT / "scripts/mgmt_airgap.py")
AIRGAP = importlib.util.module_from_spec(AIRGAP_SPEC)
AIRGAP_SPEC.loader.exec_module(AIRGAP)


class MgmtAirgapBundleLockTests(unittest.TestCase):
    def setUp(self):
        self.lock = BUILDER.checked_lock(LOCK, "v1.37.0+rke2r1")

    def test_lock_reproduces_independently_approved_manifest(self):
        body = json.dumps(BUILDER.manifest_from_lock(self.lock), sort_keys=True, indent=2) + "\n"
        self.assertEqual(
            self.lock["approved_manifest_sha256"],
            hashlib.sha256(body.encode()).hexdigest(),
        )

    def test_lock_covers_canonical_packages_and_release_artifacts(self):
        packages = {item["package"] for item in self.lock["rpms"]}
        self.assertLessEqual(AIRGAP.REQUIRED_RPMS, packages)
        self.assertEqual(set(AIRGAP.REQUIRED_ARTIFACTS), set(self.lock["release_artifacts"]))
        self.assertEqual(len(self.lock["rpms"]), len(packages))

    def test_every_network_source_and_preparer_is_pinned(self):
        entries = [
            *self.lock["release_artifacts"].values(),
            *self.lock["rpm_signing_keys"],
            *self.lock["rpms"],
        ]
        self.assertTrue(all(item["url"].startswith("https://") for item in entries))
        self.assertRegex(self.lock["preparer_image"], r"@sha256:[0-9a-f]{64}$")

    def test_offline_compressed_only_source_fails_before_decompression(self):
        compressed = b"locked compressed bytes"
        uncompressed = b"locked uncompressed bytes"
        entry = {
            "file": "images.tar",
            "sha256": hashlib.sha256(uncompressed).hexdigest(),
            "compressed_file": "images.tar.zst",
            "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
            "url": "https://example.invalid/images.tar.zst",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            cache = root / "cache"
            source.mkdir()
            cache.mkdir()
            (source / entry["compressed_file"]).write_bytes(compressed)
            with (
                mock.patch.object(BUILDER, "decompress_zstd") as decompressor,
                self.assertRaisesRegex(BUILDER.BuildError, "networked decompression is forbidden"),
            ):
                BUILDER.materialize_release(
                    entry, cache, source, root / entry["file"],
                    "example.invalid/preparer@sha256:" + "0" * 64, True,
                )
            decompressor.assert_not_called()

    def test_offline_prefers_verified_uncompressed_bytes(self):
        compressed = b"locked compressed bytes"
        uncompressed = b"locked uncompressed bytes"
        entry = {
            "file": "images.tar",
            "sha256": hashlib.sha256(uncompressed).hexdigest(),
            "compressed_file": "images.tar.zst",
            "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
            "url": "https://example.invalid/images.tar.zst",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            cache = root / "cache"
            source.mkdir()
            cache.mkdir()
            (source / entry["compressed_file"]).write_bytes(compressed)
            (source / entry["file"]).write_bytes(uncompressed)
            output = root / "output.tar"
            with mock.patch.object(BUILDER, "decompress_zstd") as decompressor:
                BUILDER.materialize_release(
                    entry, cache, source, output,
                    "example.invalid/preparer@sha256:" + "0" * 64, True,
                )
            self.assertEqual(output.read_bytes(), uncompressed)
            decompressor.assert_not_called()

    def test_fixture_services_have_one_contract_and_both_consumers(self):
        fixture = ROOT / "platform/ansible/tests/mgmt_offline_vm"
        contract = yaml.safe_load((fixture / "contract.yml").read_text())
        services = contract["mgmt_local_vm_contract"]["services"]
        normalized = BUILDER.checked_services(json.dumps(services))
        self.assertEqual(json.loads(normalized), services)
        main = (fixture / "main.yml").read_text()
        builder = (fixture / "build_bundle.yml").read_text()
        self.assertIn("mgmt_local_vm_contract.services.dns", main)
        self.assertIn("mgmt_local_vm_contract.services.ntp", main)
        self.assertIn("mgmt_local_vm_contract.services | to_json", builder)
        for address in services["dns"] + services["ntp"]:
            self.assertNotIn(address, main)
            self.assertNotIn(address, builder)


if __name__ == "__main__":
    unittest.main()
