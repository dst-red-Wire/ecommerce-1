from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
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
        self.assertEqual("forbidden", projection["symlinks"])

    def test_architecture_governance_keys_are_not_self_authorizing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copy2(
                ROOT / "scripts" / "architecture_authority.py",
                scripts / "architecture_authority.py",
            )
            # architecture_authority.py loads canonical machine contracts at import
            # time. Reproduce that startup environment so the regression exercises
            # schema rejection rather than failing on missing fixture dependencies.
            shutil.copytree(ROOT / "config", root / "config")

            lock = (ROOT / "architecture.lock.yaml").read_text(encoding="utf-8")
            lock = lock.replace(
                "repository_governance:\n",
                "repository_governance:\n  injected_self_authorized_key: true\n",
                1,
            )
            (root / "architecture.lock.yaml").write_text(lock, encoding="utf-8")

            probe = (
                "import importlib.util, json, pathlib; "
                "p=pathlib.Path(r'" + str(scripts / "architecture_authority.py") + "'); "
                "s=importlib.util.spec_from_file_location('probe_architecture_authority', p); "
                "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                "errors=m.lock_schema_errors(m._CANONICAL_LOCK); "
                "print(json.dumps(errors)); "
                "raise SystemExit(0 if any('unknown=injected_self_authorized_key' in e for e in errors) else 1)"
            )
            result = subprocess.run(
                [sys.executable, "-c", probe],
                cwd=root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(0, result.returncode, result.stderr or result.stdout)
            self.assertIn("unknown=injected_self_authorized_key", result.stdout)

    def test_inherited_contracts_use_the_common_envelope(self):
        self.assertEqual("SourceQualityPolicy", MOD.load_yaml(
            ROOT, "config/contracts/source-quality-policy.yaml"
        )["kind"])
        self.assertEqual("TerraformProviderLock", MOD.load_yaml(
            ROOT, "config/contracts/terraform-provider-lock.yaml"
        )["kind"])


if __name__ == "__main__":
    unittest.main()
