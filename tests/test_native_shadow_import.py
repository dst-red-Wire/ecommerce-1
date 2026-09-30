"""Native network evidence must be imported from its protected exact-SHA copy."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import m25_runtime_evidence
import rocky_box_catalog

SPEC = importlib.util.spec_from_file_location("repoctl_native_shadow_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
repoctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repoctl)


class NativeShadowImportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.campaign = "20260929T163821Z-9da62296f3d5"
        self.head = "a" * 40
        self.tree = "b" * 40
        self.box_sha = "c" * 64
        self.vm_id = "e80d60f3-a12e-4734-a654-0cd24dce0fa1"
        self.laboratory = self.root / "laboratory"
        self.shadows = self.root / "protected"
        self.shadow = self.shadows / f"{self.campaign}-{self.head}"
        self.stage = self.shadow / self.campaign
        self.result_path = self.shadow / "evidence/network-smoke" / self.campaign / "result.json"
        self.result_path.parent.mkdir(parents=True)
        self.stage.mkdir(parents=True)
        (self.stage / "prepared.json").write_text(json.dumps({
            "campaign_id": self.campaign, "source_sha": self.head,
            "box_sha256": self.box_sha,
        }), encoding="utf-8")
        self.vagrantfile = self.root / "platform/vagrant/rocky-image-smoke/Vagrantfile"
        self.vagrantfile.parent.mkdir(parents=True)
        self.vagrantfile.write_text("Vagrant.configure('2') {}\n", encoding="utf-8")
        self.package_relative = "config/artifacts/rocky-10.2-base-packages.lock.json"
        package_source = self.root / self.package_relative
        package_source.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / self.package_relative, package_source)
        package_staged = self.stage / self.package_relative
        package_staged.parent.mkdir(parents=True)
        shutil.copyfile(package_source, package_staged)
        self.package_sha = hashlib.sha256(package_source.read_bytes()).hexdigest()
        (self.stage / "SHA256SUMS").write_text(
            f"{self.package_sha}  {self.package_relative}\n", encoding="utf-8"
        )
        self.result = {
            "campaign_id": self.campaign,
            "cleanup": {"vm_id": self.vm_id},
            "resume_runner_files": {},
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        self.log_relative = "logs/ssh-resume-20260929T163821Z/VBox.log"
        self.log_path = self.stage / self.log_relative
        self.log_path.parent.mkdir(parents=True)
        self.log_path.write_text("00:00:01 HM: VT-x enabled\n", encoding="utf-8")
        self.result["image_qualification"] = {
            "status": "PASS", "source_sha": self.head, "source_tree_sha": self.tree,
            "box_sha256": self.box_sha, "vm_id": self.vm_id,
            "virtualbox_backend": "NATIVE_VTX",
            "virtualbox_log_relative": self.log_relative,
            "virtualbox_log_sha256": hashlib.sha256(self.log_path.read_bytes()).hexdigest(),
        }
        self.write_result()
        self.runner_path = self.shadow / f"runner-{self.head}" / "runner.json"
        self.runner_path.parent.mkdir(parents=True)
        self.runner_path.write_text(json.dumps({
            "campaign_id": self.campaign, "source_sha": self.head,
            "source_tree_sha": self.tree, "runner_files": {},
            "package_lock_sha256": self.package_sha,
        }), encoding="utf-8")
        self.boot_path = self.shadow / "native-boot.json"
        self.write_boot()

    def write_result(self) -> None:
        self.result_path.write_text(json.dumps(self.result), encoding="utf-8")

    def write_boot(self) -> None:
        self.boot = {
            "mode": "NETWORK_SMOKE_NATIVE", "campaign_id": self.campaign,
            "phase": "RECOVERED", "run_status": "PASS",
            "source_sha": self.head, "source_tree_sha": self.tree,
            "vm_id": self.vm_id, "expected_vm_id": self.vm_id,
            "box_sha256": self.box_sha,
            "shadow_root": repoctl._native_shadow_windows_path(self.shadow),
            "runner_manifest_sha256": hashlib.sha256(self.runner_path.read_bytes()).hexdigest(),
            "result_sha256": hashlib.sha256(self.result_path.read_bytes()).hexdigest(),
        }
        self.boot_path.write_text(json.dumps(self.boot), encoding="utf-8")

    def import_result(self) -> int:
        def git_value(*args, check=True):
            if args == ("status", "--porcelain", "--untracked-files=all"):
                return ""
            if args == ("rev-parse", "HEAD"):
                return self.head
            if args == ("rev-parse", "HEAD^{tree}"):
                return self.tree
            raise AssertionError(args)

        with (mock.patch.object(repoctl, "ROOT", self.root),
              mock.patch.object(repoctl, "git", side_effect=git_value),
              mock.patch.object(rocky_box_catalog, "find_matching_box", return_value=self.root / "box"),
              mock.patch.object(rocky_box_catalog, "verify", return_value={"box_sha256": self.box_sha}),
              mock.patch.object(rocky_box_catalog, "source_file", return_value=self.vagrantfile.read_bytes()),
              mock.patch.object(m25_runtime_evidence, "validate_current_smoke")):
            return repoctl.lab_network_import(
                self.campaign, laboratory_root=self.laboratory, shadow_root=self.shadows,
            )

    def test_protected_result_is_imported_and_lab_result_is_ignored(self) -> None:
        stale = self.laboratory / "evidence/network-smoke" / self.campaign / "result.json"
        stale.parent.mkdir(parents=True)
        stale.write_text('{"status":"FAIL"}', encoding="utf-8")
        self.assertEqual(0, self.import_result())
        retained = self.root / ".context/evidence/network-smoke/current.json"
        self.assertEqual(self.result_path.read_bytes(), retained.read_bytes())

    def test_shadow_result_digest_and_state_are_required(self) -> None:
        self.assertEqual(0, self.import_result())
        retained = self.root / ".context/evidence/network-smoke/current.json"
        first = retained.read_bytes()
        self.result["guest_security"] = "NOT_EXECUTED"
        self.write_result()
        self.assertEqual(2, self.import_result())
        self.assertEqual(first, retained.read_bytes())
        self.write_boot()
        self.boot_path.unlink()
        self.assertEqual(2, self.import_result())
        self.assertEqual(first, retained.read_bytes())

    def test_stale_shadow_prevents_historical_fallback(self) -> None:
        self.shadow.rename(self.shadows / f"{self.campaign}-{'d' * 40}")
        self.assertEqual(2, self.import_result())

    def test_package_lock_tamper_prevents_import(self) -> None:
        (self.stage / self.package_relative).write_text("{}\n", encoding="utf-8")
        self.assertEqual(2, self.import_result())

    def test_virtualbox_log_tamper_and_nem_are_rejected(self) -> None:
        self.assertEqual(0, self.import_result())
        self.log_path.write_text("00:00:01 NEM: fallback\n", encoding="utf-8")
        self.assertEqual(2, self.import_result())
        self.result["image_qualification"]["virtualbox_log_sha256"] = hashlib.sha256(
            self.log_path.read_bytes()
        ).hexdigest()
        self.write_result()
        self.write_boot()
        self.assertEqual(2, self.import_result())

    def test_resume_executes_the_shadow_runner_without_importing_a_result(self) -> None:
        runner = self.shadow / f"runner-{self.head}" / "scripts/windows/LabNetworkSmoke.ps1"
        runner.parent.mkdir(parents=True)
        runner.write_text("# protected fixture\n", encoding="utf-8")
        (self.stage / "prepared.json").write_text(json.dumps({
            "box_path": r"C:\ecommerce-lab\artifacts\source.box",
        }), encoding="utf-8")

        def output(command):
            if command == ["git", "status", "--porcelain", "--untracked-files=all"]:
                return ""
            if command == ["git", "rev-parse", "HEAD"]:
                return self.head
            if command[:2] == ["wslpath", "-u"]:
                return str(self.root / "source.box")
            if command[:2] == ["wslpath", "-w"]:
                return command[2]
            raise AssertionError(command)

        with (mock.patch.object(repoctl, "NATIVE_SHADOW_BASE", self.shadows),
              mock.patch.object(repoctl, "ROOT", self.root),
              mock.patch.object(repoctl, "output", side_effect=output),
              mock.patch.object(repoctl, "_windows_powershell_environment", return_value={}),
              mock.patch.object(rocky_box_catalog, "verify", return_value={}),
              mock.patch.object(repoctl, "run", return_value=subprocess.CompletedProcess([], 0)) as run):
            self.assertEqual(0, repoctl.lab_network_action("Resume", self.campaign))
        command = run.call_args.args[0]
        self.assertEqual(str(runner), command[command.index("-File") + 1])
        self.assertEqual(str(self.stage), command[command.index("-StageRoot") + 1])
        self.assertEqual(str(self.shadow), command[command.index("-ShadowRoot") + 1])
        self.assertFalse((self.root / ".context/evidence/network-smoke/current.json").exists())

    def test_native_prepare_rejects_prepositioned_runner_symlink(self) -> None:
        stage = self.laboratory / "network-smoke" / self.campaign
        stage.mkdir(parents=True)
        (stage / "prepared.json").write_text(json.dumps({
            "campaign_id": self.campaign, "box_sha256": self.box_sha,
            "source_sha": self.head,
        }), encoding="utf-8")
        for relative in ("platform/vagrant/rocky-image-smoke/Vagrantfile", "smoke-run/Vagrantfile"):
            target = stage / relative
            target.parent.mkdir(parents=True)
            shutil.copyfile(self.vagrantfile, target)
        evidence = self.laboratory / "evidence/network-smoke" / self.campaign / "result.json"
        evidence.parent.mkdir(parents=True)
        evidence.write_text(json.dumps({
            "campaign_id": self.campaign, "cleanup": {"vm_preserved": True},
        }), encoding="utf-8")
        outside = self.root / "outside-runner"
        outside.mkdir()
        (stage.parent / f"runner-{self.head}").symlink_to(outside, target_is_directory=True)
        before = list(outside.iterdir())

        def git_value(*args, check=True):
            if args == ("status", "--porcelain", "--untracked-files=all"):
                return ""
            if args == ("rev-parse", "HEAD"):
                return self.head
            if args == ("rev-parse", "HEAD^{tree}"):
                return self.tree
            raise AssertionError(args)

        with (mock.patch.object(repoctl, "ROOT", self.root),
              mock.patch.object(repoctl, "git", side_effect=git_value),
              mock.patch.object(rocky_box_catalog, "find_matching_box", return_value=self.root / "box"),
              mock.patch.object(rocky_box_catalog, "verify", return_value={"box_sha256": self.box_sha}),
              mock.patch.object(rocky_box_catalog, "source_file", return_value=self.vagrantfile.read_bytes())):
            self.assertEqual(2, repoctl.lab_network_native_prepare(
                self.campaign, laboratory_root=self.laboratory,
            ))
        self.assertEqual(before, list(outside.iterdir()))


if __name__ == "__main__":
    unittest.main()
