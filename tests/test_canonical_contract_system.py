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


if __name__ == "__main__":
    unittest.main()
