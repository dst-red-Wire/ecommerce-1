import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("repoctl_api_compat", ROOT / "scripts/repoctl.py")
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class RepoctlApiCompatibilityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / "contracts/openapi").mkdir(parents=True)
        (self.root / "config/contracts").mkdir(parents=True)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.root, check=True)

    def write_lock(self, registry="config/contracts/public-api-contracts.yaml"):
        (self.root / "architecture.lock.yaml").write_text(
            f"machine_contracts:\n  public_api_contracts: {registry}\n", encoding="utf-8"
        )

    def write_registry(self, path, contracts, common="contracts/openapi/common.v1.yaml"):
        lines = [f"common_components: {common}", "contracts:"]
        for name, spec in contracts.items():
            lines += [f"  {name}:", f"    owner: {name}", f"    path: {spec}"]
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def commit(self, message):
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-q", "-m", message], cwd=self.root, check=True)
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.root, text=True).strip()

    def seed(self):
        self.write_lock()
        self.write_registry("config/contracts/public-api-contracts.yaml", {"product": "contracts/openapi/product.v1.yaml"})
        (self.root / "contracts/openapi/common.v1.yaml").write_text("openapi: 3.1.0\n", encoding="utf-8")
        (self.root / "contracts/openapi/product.v1.yaml").write_text("openapi: 3.1.0\ninfo: {title: product, version: v1}\n", encoding="utf-8")
        return self.commit("base")

    def run_compat(self, base, head):
        calls = []
        real_run = MOD.run

        def fake_run(command, **kwargs):
            if command[0] == "oasdiff":
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, "", "")
            return real_run(command, **kwargs)

        with mock.patch.object(MOD, "ROOT", self.root), mock.patch.object(MOD, "require"), mock.patch.object(
            MOD, "run", side_effect=fake_run
        ):
            result = MOD.api_compat(base, head)
        return result, calls

    def test_unchanged_registry_and_specs_skip_but_spec_and_common_changes_check(self):
        base = self.seed()
        self.assertEqual((0, []), self.run_compat(base, base))
        product = self.root / "contracts/openapi/product.v1.yaml"
        product.write_text(product.read_text() + "paths: {}\n", encoding="utf-8")
        spec_head = self.commit("spec")
        self.assertEqual(1, len(self.run_compat(base, spec_head)[1]))
        common = self.root / "contracts/openapi/common.v1.yaml"
        common.write_text(common.read_text() + "info: {title: common, version: v1}\n", encoding="utf-8")
        common_head = self.commit("common")
        self.assertEqual(1, len(self.run_compat(spec_head, common_head)[1]))

    def test_registry_authority_redirect_without_spec_change_checks_every_existing_api(self):
        base = self.seed()
        new_registry = "config/contracts/public-api-contracts-v2.yaml"
        self.write_registry(new_registry, {"product": "contracts/openapi/product.v1.yaml"})
        self.write_lock(new_registry)
        head = self.commit("redirect authority")
        self.assertEqual(1, len(self.run_compat(base, head)[1]))

    def test_spec_path_replacement_checks_base_against_head(self):
        base = self.seed()
        replacement = "contracts/openapi/product.v2.yaml"
        (self.root / replacement).write_text("openapi: 3.1.0\ninfo: {title: product, version: v2}\n", encoding="utf-8")
        self.write_registry("config/contracts/public-api-contracts.yaml", {"product": replacement})
        head = self.commit("replace")
        _, calls = self.run_compat(base, head)
        self.assertEqual(1, len(calls))
        self.assertTrue(calls[0][-2].endswith("product.v1.yaml"))
        self.assertTrue(calls[0][-1].endswith("product.v2.yaml"))

    def test_addition_is_explicit_and_does_not_compare_nonexistent_base(self):
        base = self.seed()
        added = "contracts/openapi/catalog.v1.yaml"
        (self.root / added).write_text("openapi: 3.1.0\n", encoding="utf-8")
        self.write_registry("config/contracts/public-api-contracts.yaml", {
            "product": "contracts/openapi/product.v1.yaml", "catalog": added
        })
        head = self.commit("add")
        self.assertEqual([], self.run_compat(base, head)[1])

    def test_contract_removal_fails_closed(self):
        base = self.seed()
        self.write_registry("config/contracts/public-api-contracts.yaml", {})
        head = self.commit("remove")
        with self.assertRaisesRegex(RuntimeError, "removal is forbidden.*product"):
            self.run_compat(base, head)


if __name__ == "__main__":
    unittest.main()
