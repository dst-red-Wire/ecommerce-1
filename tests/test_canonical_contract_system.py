from __future__ import annotations

import importlib.util
import json
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
        path = ROOT / "config/contracts/toolchain-lock.yaml"
        lock = MOD.load_yaml(ROOT, "config/contracts/toolchain-lock.yaml")
        self.assertEqual("json", lock["serialization"])
        self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), dict)
        self.assertEqual("derived-projection", lock["legacy_projections"]["versions_env"]["authority"])
        self.assertEqual("derived-projection", lock["legacy_projections"]["capabilities_json"]["authority"])

    def test_ci_evidence_is_a_required_canonical_contract(self):
        lock = MOD.load_yaml(ROOT, "architecture.lock.yaml")
        required = lock["repository_governance"]["canonical_contract_system"]["required_contracts"]
        self.assertIn("ci_evidence", required)
        evidence = MOD.load_yaml(ROOT, lock["machine_contracts"]["ci_evidence"])
        self.assertEqual("CIEvidencePolicy", evidence["kind"])
        self.assertIn("repository.ci.base-resolution", evidence["authority_claims"])

    def test_materializers_do_not_treat_legacy_versions_as_authority(self):
        ansible_defaults = (
            ROOT / "platform/ansible/roles/developer_toolchain/defaults/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("config/contracts/toolchain-lock.yaml", ansible_defaults)
        self.assertNotIn("config/toolchain/versions.env", ansible_defaults)

    def test_execution_environment_centralizes_qualification_isolation(self):
        policy = MOD.load_yaml(
            ROOT, "config/contracts/execution-environment-policy.yaml"
        )
        isolation = policy["qualification_isolation"]
        git_policy = isolation["git"]

        self.assertEqual("forbidden", git_policy["inherited_repository_context"])
        self.assertIn("GIT_", git_policy["drop_inherited_prefixes"])
        self.assertEqual("disabled", git_policy["system_config"])
        self.assertEqual("disabled", git_policy["global_config"])
        self.assertEqual("disabled", git_policy["nested_hooks"])
        self.assertEqual("/dev/null", git_policy["hooks_path"])
        self.assertEqual("forbidden", git_policy["parent_index_mutation"])
        self.assertEqual("forbidden", git_policy["parent_worktree_mutation"])

        projection = isolation["temporary_repository_projection"]
        self.assertTrue(projection["preserve_repository_relative_paths"])
        self.assertEqual("forbidden", projection["source_mutation"])
        self.assertEqual("isolated", projection["projection_mutation"])

    def test_inherited_contracts_use_the_common_envelope(self):
        self.assertEqual("SourceQualityPolicy", MOD.load_yaml(
            ROOT, "config/contracts/source-quality-policy.yaml"
        )["kind"])
        self.assertEqual("TerraformProviderLock", MOD.load_yaml(
            ROOT, "config/contracts/terraform-provider-lock.yaml"
        )["kind"])


if __name__ == "__main__":
    unittest.main()
