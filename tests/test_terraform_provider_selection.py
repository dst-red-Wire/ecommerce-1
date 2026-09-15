"""Provider selection/reconciliation without touching infrastructure or host tools."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import repoctl as ctl


class TerraformProviderSelection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="terraform-provider-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "platform").mkdir()
        (self.root / "platform/main.tf").write_text("terraform {}\n")
        self.cache = self.root / "custom-provider-cache"
        self.cache.mkdir()
        self.marker = self.cache / "retain"
        self.marker.write_bytes(b"existing cache data")
        self.pins = ctl.pinned_versions()
        self.providers = {}
        self.reconcile = True
        self.reconciliations = 0
        self.executions = []
        self.probes = []
        self.after_probe = lambda _: None

    def which(self, name):
        if name == "ansible-playbook" or name in self.providers:
            return str(self.root / "bin" / name)
        return None

    def fake_run(self, command, **kwargs):
        name = Path(command[0]).name
        if name == "ansible-playbook":
            self.reconciliations += 1
            if self.reconcile:
                self.providers["terraform"] = self.pins["TERRAFORM_VERSION"]
        elif command[1:] == ["version", "-json"]:
            self.probes.append(name)
            output = json.dumps({"terraform_version": self.providers[name]})
            self.after_probe(name)
            return subprocess.CompletedProcess(command, 0, output, "")
        else:
            self.executions.append(command)
            self.assertNotIn("apply", command)
        return subprocess.CompletedProcess(command, 0, "", "")

    def gate(self):
        with (
            mock.patch.object(ctl, "ROOT", self.root),
            mock.patch.object(ctl, "pinned_versions", return_value=self.pins),
            mock.patch.object(ctl.shutil, "which", side_effect=self.which),
            mock.patch.object(ctl, "run", side_effect=self.fake_run),
            mock.patch.dict(os.environ, {"TF_PLUGIN_CACHE_DIR": str(self.cache)}),
        ):
            result = ctl.terraform_check()
            self.assertEqual(str(self.cache), os.environ["TF_PLUGIN_CACHE_DIR"])
            self.assertEqual(b"existing cache data", self.marker.read_bytes())
            return result

    def assert_executed(self, provider):
        self.assertTrue(self.executions)
        self.assertTrue(all(command[0] == str(self.root / "bin" / provider) for command in self.executions))
        self.assertTrue(any(command[1:] == ["init", "-backend=false", "-input=false"] for command in self.executions))

    def test_conforming_tofu_has_priority_and_warm_path(self):
        self.providers = {"tofu": self.pins["OPENTOFU_VERSION"], "terraform": self.pins["TERRAFORM_VERSION"]}
        self.assertEqual(0, self.gate())
        self.assert_executed("tofu")
        self.assertEqual(0, self.reconciliations)
        self.assertNotIn("terraform", self.probes)

    def test_stale_tofu_does_not_mask_conforming_terraform(self):
        self.providers = {"tofu": "0.0.0", "terraform": self.pins["TERRAFORM_VERSION"]}
        self.assertEqual(0, self.gate())
        self.assert_executed("terraform")
        self.assertEqual(0, self.reconciliations)
        self.assertEqual("0.0.0", self.providers["tofu"], "system tofu is preserved")

    def test_stale_tofu_then_terraform_reconciled_once(self):
        self.providers = {"tofu": "0.0.0"}
        self.assertEqual(0, self.gate())
        self.assertEqual(1, self.reconciliations)
        self.assert_executed("terraform")
        self.assertEqual(0, self.gate())
        self.assertEqual(1, self.reconciliations, "warm execution must not reconcile again")
        self.assertEqual("0.0.0", self.providers["tofu"])

    def test_no_conforming_provider_after_reconciliation_is_explicit(self):
        self.providers = {"tofu": "0.0.0", "terraform": "0.0.0"}
        self.reconcile = False
        with self.assertRaisesRegex(RuntimeError, "no conforming Terraform/OpenTofu provider"):
            self.gate()
        self.assertEqual(1, self.reconciliations)
        self.assertEqual([], self.executions)

    def test_executes_the_provider_it_validated_even_if_path_availability_changes(self):
        self.providers = {"terraform": self.pins["TERRAFORM_VERSION"]}

        def new_tofu(name):
            if name == "terraform" and self.probes.count("terraform") == 2:
                self.providers["tofu"] = self.pins["OPENTOFU_VERSION"]

        self.after_probe = new_tofu
        self.assertEqual(0, self.gate())
        self.assert_executed("terraform")
        self.assertIn("tofu", self.providers)

    def test_relative_path_is_bound_before_changing_working_directory(self):
        self.providers = {"tofu": self.pins["OPENTOFU_VERSION"]}
        with (
            mock.patch.object(ctl.shutil, "which", return_value="relative-bin/tofu"),
            mock.patch.object(ctl, "run", side_effect=self.fake_run),
        ):
            self.assertEqual(str(Path("relative-bin/tofu").absolute()), ctl.conforming_terraform_provider())

    def test_real_pinned_terraform_is_selected_beside_stale_tofu(self):
        terraform = shutil.which("terraform")
        self.assertIsNotNone(terraform, "canonical bootstrap must prepare Terraform")
        tofu = self.root / "tofu"
        tofu.write_text(f'#!{sys.executable}\nprint(\'{{"terraform_version":"0.0.0"}}\')\n')
        tofu.chmod(0o755)
        before = tofu.read_bytes()
        with mock.patch.object(
            ctl.shutil, "which", side_effect=lambda name: {"tofu": str(tofu), "terraform": terraform}.get(name)
        ):
            self.assertEqual(terraform, ctl.conforming_terraform_provider())
        self.assertEqual(before, tofu.read_bytes())
