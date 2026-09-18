from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("canonical_contracts", ROOT / "scripts" / "canonical_contracts.py")
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)


class CanonicalContractSystemTest(unittest.TestCase):
    def test_repository_contract_system_is_valid(self):
        MOD.validate_repository(ROOT)

    def test_security_policy_has_no_parallel_committed_gitleaks_authority(self):
        self.assertFalse((ROOT / ".gitleaks.toml").exists())

    def test_toolchain_legacy_files_are_projections_only(self):
        lock = MOD.load_yaml(ROOT, "config/contracts/toolchain-lock.yaml")
        self.assertEqual("derived-projection", lock["legacy_projections"]["versions_env"]["authority"])
        self.assertEqual("derived-projection", lock["legacy_projections"]["capabilities_json"]["authority"])

    def test_materializers_do_not_treat_legacy_versions_as_authority(self):
        ansible_defaults = (
            ROOT / "platform/ansible/roles/developer_toolchain/defaults/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("config/contracts/toolchain-lock.yaml", ansible_defaults)
        self.assertNotIn("config/toolchain/versions.env", ansible_defaults)

    def test_inherited_contracts_use_the_common_envelope(self):
        self.assertEqual("SourceQualityPolicy", MOD.load_yaml(
            ROOT, "config/contracts/source-quality-policy.yaml"
        )["kind"])
        self.assertEqual("TerraformProviderLock", MOD.load_yaml(
            ROOT, "config/contracts/terraform-provider-lock.yaml"
        )["kind"])

    def test_toolchain_pins_are_exact_and_sha256_checksums_are_valid(self):
        lock = MOD.load_yaml(ROOT, "config/contracts/toolchain-lock.yaml")
        floating = {"latest", "stable", "main", "master", "head", "edge", "nightly", "*"}
        for key, raw_value in lock["versions"].items():
            value = str(raw_value)
            if "SHA256" in key.upper():
                self.assertRegex(value, r"^[0-9a-fA-F]{64}$", key)
            else:
                self.assertNotIn(value.lower(), floating, key)
                self.assertNotRegex(value, r"[<>^~*]|\.x$", key)

    def test_cache_policy_requires_sha256_and_forbids_floating_versions(self):
        policy = MOD.load_yaml(ROOT, "config/contracts/cache-policy.yaml")
        self.assertEqual("sha256", policy["pinning"]["digest_algorithm"])
        self.assertEqual("forbidden", policy["pinning"]["floating_versions"])
        self.assertEqual("required", policy["pinning"]["executable_sha256_in_cache_key"])


if __name__ == "__main__":
    unittest.main()
