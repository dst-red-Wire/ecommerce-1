"""Deterministic source-lock tests for the local MGMT air-gap bundle builder."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
