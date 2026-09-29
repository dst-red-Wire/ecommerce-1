"""M2.5 proof must remain tied to observed Rocky, VM, and RKE2 results."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import m25_runtime_evidence as m25
import qualification_steps
import roadmap_sync


HEAD = "a" * 40
TREE = "b" * 40
ORIGINAL = "1" * 40
ORIGINAL_TREE = "2" * 40
QUALIFIED = "6" * 40
QUALIFIED_TREE = "7" * 40
UUID = "12345678-1234-1234-1234-123456789abc"
BOX_SHA = "c" * 64
INPUTS = "d" * 64
TEMPLATE = "3" * 64
STAGING = "4" * 64
VM = "ecommerce-mgmt-test-proof"


class M25RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for relative in ("config/contracts/machine-image-lock.yaml",
                         "config/contracts/qualification-execution-policy.yaml",
                         "config/contracts/roadmap-policy.yaml",
                         "platform/vagrant/rocky-image-smoke/Vagrantfile",
                         *(f"scripts/windows/{name}" for name in m25.NETWORK_RUNNER_FILES),
                         "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json"):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        lock = json.loads((self.root / "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json").read_text())
        self.manifest_sha = lock["approved_manifest_sha256"]
        self.manifest = {
            "box_sha256": BOX_SHA, "inputs_digest": INPUTS,
            "packer_template_digest": TEMPLATE, "staging_manifest_sha256": STAGING,
            "source_sha": ORIGINAL, "source_tree_sha": ORIGINAL_TREE,
            "rocky_version": "10.2", "virtualbox_version": "7.2.18",
            "native_vtx": "PASS", "nem_detected": False,
        }
        self.campaign_epoch = int(datetime.now(timezone.utc).timestamp())
        source_payloads = {
            "image_build": {"status": "PASS", "source_sha": ORIGINAL, "source_tree": ORIGINAL_TREE,
                            "sha256": BOX_SHA, "artifact": "rocky-10.2-rke2-virtualbox.box",
                            "virtualbox_backend": "NATIVE_VTX", "virtualbox_version": "7.2.18",
                            "packer_build": "PASS"},
            "image_qualification": {"status": "PASS", "source_sha": ORIGINAL,
                                    "artifact_sha256": BOX_SHA, "artifact": "rocky-10.2-rke2-virtualbox.box",
                                    "qualification": {key: "PASS" for key in (
                                        "boot", "ssh", "rocky_release", "kernel", "systemd",
                                        "rke2_prerequisites", "security", "cleanup", "key_cleanup",
                                        "swap_absent", "rpm_profile")}},
            "image_release": {"status": "PASS", "source_sha": ORIGINAL,
                              "artifact_sha256": BOX_SHA, "artifact": "rocky-10.2-rke2-virtualbox.box",
                              "checks": {key: "PASS" for key in (
                                  "exact_source_sha", "build_evidence", "checksum",
                                  "qualification_evidence", "cleanup", "ephemeral_key_absent",
                                  "sbom", "package_manifest", "profile_inventory")}},
            "native_import": {"status": "PASS", "source_git_sha": ORIGINAL,
                              "source_tree_sha": ORIGINAL_TREE, "artifact_sha256": BOX_SHA,
                              "staging_manifest_sha256": STAGING,
                              "virtualbox_backend": "NATIVE_VTX", "wsl2_restored": "PASS",
                              "bcd_restored": "PASS"},
            "native_result": {"status": "PASS", "source_git_sha": ORIGINAL,
                              "source_tree_sha": ORIGINAL_TREE, "artifact_sha256": BOX_SHA,
                              "staging_manifest_sha256": STAGING, "native_vtx": "PASS",
                              "nem_detected": False, "virtualbox_backend": "NATIVE_VTX",
                              "packer": {"build": "PASS"},
                              "vagrant_smoke": {"rocky_version": "PASS"},
                              "observations": {"rocky_version": "Rocky Linux release 10.2 (Red Quartz)"}},
            "image_reuse": qualification_steps.checkpoint(
                qualification="m2.5", step="image", source_sha=HEAD,
                input_digest=INPUTS, artifact_digest=BOX_SHA,
                status="SKIPPED_REUSED_VERIFIED", started_at=datetime.now(timezone.utc),
                reused_from={"source_sha": ORIGINAL, "input_digest": INPUTS,
                             "artifact_digest": BOX_SHA}),
            "current_network_smoke": {
                "status": "PASS", "resume_runner_source_sha": HEAD,
                "resume_runner_files": {name: m25._digest(self.root / "scripts/windows" / name)
                                        for name in m25.NETWORK_RUNNER_FILES},
                "resume_vagrantfile_sha256": m25._digest(
                    self.root / "platform/vagrant/rocky-image-smoke/Vagrantfile"),
                "campaign_id": "20260929T163821Z-9da62296f3d5",
                "vm_name": "ecommerce-rocky-10-2-smoke-4e935faff986",
                "virtualbox_backend": "NATIVE_VTX", "box_digest_verified": "PASS",
                "box_digest": BOX_SHA, "packer": {"inputs_digest": INPUTS},
                "guest_security": "PASS", "vm_recreate": "NOT_REQUIRED",
                "cleanup": {"vm_preserved": True,
                            "vm_name": "ecommerce-rocky-10-2-smoke-4e935faff986", "vm_id": UUID},
                "checkpoints": {name: "PASS" for name in (
                    "03-vm-smoke", "04-network-ssh", "05-rocky-runtime")},
                "network_smoke": {"vm_name": "ecommerce-rocky-10-2-smoke-4e935faff986",
                                  "tcp_22_ready": "PASS", "ssh_auth_ready": "PASS",
                                  "remote_command_ready": "PASS", "rocky_runtime": "PASS",
                                  "rocky_version": "10.2"},
                "completed_at": datetime.fromtimestamp(self.campaign_epoch, timezone.utc).isoformat(),
            },
            "backend_probe": {"schema_version": 1, "status": "PASS",
                              "head_sha": HEAD, "head_tree_sha": TREE,
                              "box_sha256": BOX_SHA, "vm_uuid": UUID,
                              "virtualbox_backend": "NATIVE_VTX",
                              "virtualbox_version": "7.2.18r175117",
                              "hypervisor_present": False, "host_logical_processors": 8,
                              "vm_cpus": 4, "vm_memory_mib": 4096,
                              "virtualbox_log_sha256": "5" * 64},
            "vm_preflight": {"rocky_release": "Rocky Linux release 10.2 (Red Quartz)",
                             "kernel": "6.12.0-rocky", "systemd": "running",
                             "boot_id": "87654321-4321-4321-4321-abcdef123456",
                             "selinux": "Enforcing", "online_cpus": 4,
                             "memory_kib": 3900000,
                             "nft_policies": {"output": "drop", "forward": "drop"},
                             "public_connect_errno": 101,
                             "cold_artifact_target": True},
            "server_source": {"git_sha": HEAD},
            "rke2_result": {"node_ready": True, "cilium_ready": 1, "selinux": "Enforcing",
                            "rke2_service": "active",
                            "nft_policies": {"output": "drop", "forward": "drop"},
                            "public_connect_error": 101, "rke2_version": "rke2 version v1.37.0+rke2r1"},
            "role_result": {"exit_code": 0, "vm_uuid": UUID,
                            "bundle_manifest_sha256": self.manifest_sha},
            "cold_role_result": {"exit_code": 0, "vm_uuid": UUID,
                                 "bundle_manifest_sha256": self.manifest_sha,
                                 "trial": {"vm_uuid": UUID,
                                           "boot_id": "87654321-4321-4321-4321-abcdef123456",
                                           "cold_trial": True, "previous_attempt": False}},
            "tamper_result": {"blocked_task": "Revalidate every staged byte immediately before privileged installation",
                              "rke2_service": "inactive", "mutation": {
                                  "before_sha256": "e" * 64, "after_sha256": "f" * 64}},
            "campaign_result": {
                "schema_version": 1, "status": "PASS", "head_sha": HEAD,
                "head_tree_sha": TREE, "vm_uuid": UUID, "box_sha256": BOX_SHA,
                "virtualbox_backend": "NATIVE_VTX",
                "vm_memory_mib": 4096, "created_at_epoch": self.campaign_epoch,
                "manifest_sha256": self.manifest_sha,
                "actions": [
                    {"action": action, "status": "PASS", "duration_seconds": 1.0,
                     **({"vm_uuid": UUID, "install_required": install} if action == "server" else {})}
                    for action, install in zip(
                        ["validate", "create", "test", "diagnostics", "server", "server", "restage",
                         "tamper", "restage", "server", "destroy"],
                        [None, None, None, None, True, False, None, None, None, True, None],
                    )
                ],
            },
        }
        refs = {}
        for name, relative in m25._paths(VM).items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(source_payloads[name]), encoding="utf-8")
            refs[name] = {"path": relative.as_posix(), "sha256": m25._digest(path)}
        self.evidence = {
            "schema_version": 1, "status": "PASS", "exact_commit_evidence": True,
            "runtime_execution": True, "head_sha": HEAD, "head_tree_sha": TREE,
            "created_at_epoch": self.campaign_epoch,
            "milestone": "M2.5", "environment": "lab", "outcome": "PASS",
            "runtime_identity": {"kind": "virtualbox-vm", "id": UUID},
            "vm_name": VM, "source_evidence": refs,
            "rocky_version": "10.2", "virtualbox_version": "7.2.18",
            "native_vtx": "PASS", "nem_detected": False,
            "box_sha256": BOX_SHA, "inputs_digest": INPUTS,
            "ready_for_real_provisioning": True, "deployment_state": "NOT_DEPLOYED",
            "paid_resources_created": 0,
            "six_node_rocky_rke2": "pending-real-target-and-service-inputs",
        }
        destination = self.root / m25.OUTPUT
        destination.parent.mkdir(parents=True)
        destination.write_text(json.dumps(self.evidence), encoding="utf-8")
        self.destination = destination
        for name, value in (("find_matching_box", Path("/unused/box")),
                            ("verify", self.manifest),
                            ("build_inputs", {"inputs_digest": INPUTS,
                                              "packer_template_digest": TEMPLATE})):
            patcher = mock.patch.object(m25.rocky_box_catalog, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(
            m25.rocky_box_catalog, "source_tree",
            side_effect=lambda sha: {ORIGINAL: ORIGINAL_TREE, QUALIFIED: QUALIFIED_TREE,
                                     HEAD: TREE}[sha],
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.real_source_match = m25._qualification_sources_match
        patcher = mock.patch.object(m25, "_qualification_sources_match", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def result(self, *, now=None):
        if now and now.timestamp() - self.evidence["created_at_epoch"] > 86400:
            return False, "stale"
        try:
            m25.validate(self.root, self.evidence, HEAD, TREE)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return False, str(exc)
        return True, "valid lab proof"

    def roadmap_result(self):
        contract = roadmap_sync.policy()["status_derivation"]["runtime_evidence_contract"]
        return roadmap_sync._runtime_evidence_result(
            self.root, {"path": m25.OUTPUT.as_posix(), "environments": ["lab"]},
            "M2.5", HEAD, TREE, contract, 86400, datetime.now(timezone.utc),
        )

    def write(self):
        self.destination.write_text(json.dumps(self.evidence), encoding="utf-8")

    def rewrite_source(self, name, mutation):
        path = self.root / m25._paths(VM)[name]
        payload = json.loads(path.read_text())
        mutation(payload)
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.evidence["source_evidence"][name]["sha256"] = m25._digest(path)
        self.write()

    def test_valid_sources_pass_and_missing_source_fails(self):
        self.assertTrue(self.result()[0])
        self.assertFalse(self.roadmap_result()[0])
        self.assertIn("does not prove persistent MGMT deployment", self.roadmap_result()[1])
        (self.root / m25._paths(VM)["rke2_result"]).unlink()
        self.assertFalse(self.result()[0])

    def test_wrong_head_tree_expiry_blocked_and_rocky9_fail(self):
        for change in ({"head_sha": "f" * 40}, {"head_tree_sha": "f" * 40},
                       {"status": "BLOCKED_RUNTIME"}, {"rocky_version": "9.8"},
                       {"native_vtx": "NOT_MEASURED"}):
            with self.subTest(change=change):
                original = dict(self.evidence)
                self.evidence.update(change)
                self.write()
                self.assertFalse(self.result()[0])
                self.evidence = original
        self.write()
        self.assertFalse(self.result(now=datetime.now(timezone.utc) + timedelta(days=2))[0])

    def test_source_digest_and_runtime_failures_are_rejected(self):
        self.evidence["source_evidence"]["image_build"]["sha256"] = "f" * 64
        self.write()
        self.assertFalse(self.result()[0])
        self.evidence["source_evidence"]["image_build"]["sha256"] = m25._digest(
            self.root / m25._paths(VM)["image_build"])
        self.write()
        runtime = self.root / m25._paths(VM)["rke2_result"]
        data = json.loads(runtime.read_text())
        data["node_ready"] = False
        runtime.write_text(json.dumps(data))
        self.evidence["source_evidence"]["rke2_result"]["sha256"] = m25._digest(runtime)
        self.write()
        self.assertFalse(self.result()[0])

    def test_changed_input_digest_and_box_digest_are_rejected(self):
        with mock.patch.object(m25.rocky_box_catalog, "build_inputs",
                               return_value={"inputs_digest": "f" * 64,
                                             "packer_template_digest": TEMPLATE}):
            self.assertFalse(self.result()[0])
        self.manifest["box_sha256"] = "f" * 64
        self.assertFalse(self.result()[0])

    def test_unknown_provenance_and_fake_execution_rebinding_are_rejected(self):
        self.rewrite_source("image_reuse", lambda value: value["reused_from"].update(source_sha="f" * 40))
        self.assertFalse(self.result()[0])
        self.rewrite_source("image_reuse", lambda value: value["reused_from"].update(source_sha=ORIGINAL))
        self.rewrite_source("image_build", lambda value: value.update(source_sha=HEAD, source_tree=TREE))
        self.assertFalse(self.result()[0])

    def test_original_native_proof_missing_or_nem_is_rejected(self):
        native = self.root / m25._paths(VM)["native_result"]
        original = native.read_text()
        native.unlink()
        self.assertFalse(self.result()[0])
        native.write_text(original)
        self.rewrite_source("native_result", lambda value: value.update(nem_detected=True,
                                                                       virtualbox_backend="NEM"))
        self.assertFalse(self.result()[0])

    def test_functional_rke2_nem_is_recorded_separately_from_native_image(self):
        self.rewrite_source("backend_probe", lambda value: value.update(
            virtualbox_backend="NEM", hypervisor_present=True))
        self.rewrite_source("campaign_result", lambda value: value.update(virtualbox_backend="NEM"))
        self.assertTrue(self.result()[0])

    def test_current_runner_and_guest_security_must_have_native_smoke_proof(self):
        self.rewrite_source("current_network_smoke", lambda value: value.update(
            resume_vagrantfile_sha256="0" * 64))
        self.assertFalse(self.result()[0])
        self.rewrite_source("current_network_smoke", lambda value: value.update(
            resume_vagrantfile_sha256=m25._digest(
                self.root / "platform/vagrant/rocky-image-smoke/Vagrantfile")))
        self.rewrite_source("current_network_smoke", lambda value: value.update(
            resume_runner_source_sha=ORIGINAL))
        self.assertFalse(self.result()[0])
        self.rewrite_source("current_network_smoke", lambda value: value.update(
            resume_runner_source_sha=HEAD, guest_security="NOT_EXECUTED"))
        self.assertFalse(self.result()[0])
        self.rewrite_source("current_network_smoke", lambda value: value.update(
            guest_security="PASS", status="BLOCKED_RUNTIME", virtualbox_backend="NEM"))
        self.assertFalse(self.result()[0])

    def test_stale_source_campaign_cannot_be_refreshed_by_new_wrapper(self):
        old_epoch = self.campaign_epoch - 90000
        self.rewrite_source("campaign_result", lambda value: value.update(created_at_epoch=old_epoch))
        self.evidence["created_at_epoch"] = int(datetime.now(timezone.utc).timestamp())
        self.write()
        self.assertFalse(self.result()[0])
        self.evidence["created_at_epoch"] = old_epoch
        self.write()
        self.assertFalse(self.result()[0])

    def test_created_proof_uses_source_campaign_time(self):
        campaign_epoch = self.campaign_epoch - 300
        self.rewrite_source("campaign_result", lambda value: value.update(created_at_epoch=campaign_epoch))
        self.rewrite_source("current_network_smoke", lambda value: value.update(
            completed_at=datetime.fromtimestamp(campaign_epoch - 1, timezone.utc).isoformat()))
        self.evidence["created_at_epoch"] = campaign_epoch
        self.write()
        m25.create(self.root, HEAD, TREE, VM)
        created = json.loads(self.destination.read_text(encoding="utf-8"))
        self.assertEqual(campaign_epoch, created["created_at_epoch"])

    def test_supported_higher_memory_profile_and_mismatch(self):
        self.rewrite_source("campaign_result", lambda value: value.update(vm_memory_mib=8192))
        self.rewrite_source("backend_probe", lambda value: value.update(vm_memory_mib=8192))
        self.rewrite_source("vm_preflight", lambda value: value.update(memory_kib=7800000))
        self.assertTrue(self.result()[0])
        self.rewrite_source("backend_probe", lambda value: value.update(vm_memory_mib=4096))
        self.assertFalse(self.result()[0])

    def test_initial_cold_role_result_must_survive_restage(self):
        self.rewrite_source("cold_role_result", lambda value: value["trial"].update(
            cold_trial=False))
        self.assertFalse(self.result()[0])

    def test_native_result_can_be_imported_without_restarting_the_vm(self):
        spec = importlib.util.spec_from_file_location("m25_repoctl_import_test", ROOT / "scripts/repoctl.py")
        assert spec and spec.loader
        repoctl = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(repoctl)
        campaign = "20260929T163821Z-9da62296f3d5"
        laboratory = self.root / "laboratory"
        stage = laboratory / "network-smoke" / campaign
        stage.mkdir(parents=True)
        (stage / "prepared.json").write_text(json.dumps({
            "campaign_id": campaign, "box_sha256": BOX_SHA, "source_sha": ORIGINAL,
        }), encoding="utf-8")
        source_vagrantfile = self.root / "platform/vagrant/rocky-image-smoke/Vagrantfile"
        for relative in ("platform/vagrant/rocky-image-smoke/Vagrantfile", "smoke-run/Vagrantfile"):
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_vagrantfile, destination)
        native = laboratory / "evidence/network-smoke" / campaign / "result.json"
        native.parent.mkdir(parents=True)
        retained = self.root / m25.NETWORK_SMOKE
        native.write_bytes(retained.read_bytes())
        retained.unlink()

        def clean_git(*args, check=True):
            if args == ("status", "--porcelain", "--untracked-files=all"):
                return ""
            if args == ("rev-parse", "HEAD"):
                return HEAD + "\n"
            if args == ("rev-parse", "HEAD^{tree}"):
                return TREE + "\n"
            raise AssertionError(args)

        with (mock.patch.object(repoctl, "ROOT", self.root),
              mock.patch.object(repoctl, "git", side_effect=clean_git),
              mock.patch.object(m25.rocky_box_catalog, "source_file",
                                return_value=source_vagrantfile.read_bytes())):
            self.assertEqual(0, repoctl.lab_network_import(campaign, laboratory_root=laboratory))
            self.assertEqual(native.read_bytes(), retained.read_bytes())
            self.assertEqual(0, repoctl.lab_network_native_prepare(
                campaign, laboratory_root=laboratory))
            runner_root = laboratory / "network-smoke" / f"runner-{HEAD}"
            staged = json.loads((runner_root / "runner.json").read_text(encoding="utf-8"))
            self.assertEqual(HEAD, staged["source_sha"])
            self.assertEqual(TREE, staged["source_tree_sha"])
            for name in m25.NETWORK_RUNNER_FILES:
                self.assertEqual(m25._digest(self.root / "scripts/windows" / name),
                                 m25._digest(runner_root / "scripts/windows" / name))
            staged_vagrantfile = stage / "smoke-run/Vagrantfile"
            staged_vagrantfile.write_text("stale VM definition\n", encoding="utf-8")
            self.assertEqual(2, repoctl.lab_network_native_prepare(
                campaign, laboratory_root=laboratory))
            shutil.copyfile(source_vagrantfile, staged_vagrantfile)
            original = retained.read_bytes()
            payload = json.loads(native.read_text(encoding="utf-8"))
            payload["guest_security"] = "NOT_EXECUTED"
            native.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(2, repoctl.lab_network_import(campaign, laboratory_root=laboratory))
            self.assertEqual(original, retained.read_bytes())

    def test_native_qualification_may_reuse_original_packer_bytes_honestly(self):
        self.rewrite_source("image_build", lambda value: value.update(
            source_sha=QUALIFIED, source_tree=QUALIFIED_TREE,
            packer_build="REUSED", reuse_source_sha=ORIGINAL,
            packer_inputs_digest=INPUTS))
        for name in ("image_qualification", "image_release"):
            self.rewrite_source(name, lambda value: value.update(source_sha=QUALIFIED))
        self.rewrite_source("native_import", lambda value: value.update(
            source_git_sha=QUALIFIED, source_tree_sha=QUALIFIED_TREE,
            staging_manifest_sha256="8" * 64))
        self.rewrite_source("native_result", lambda value: value.update(
            source_git_sha=QUALIFIED, source_tree_sha=QUALIFIED_TREE,
            staging_manifest_sha256="8" * 64,
            packer={"build": "REUSED", "reuse_source_sha": ORIGINAL,
                    "inputs_digest": INPUTS}))
        self.assertTrue(self.result()[0])
        self.rewrite_source("native_result", lambda value: value["packer"].update(
            reuse_source_sha="f" * 40))
        self.assertFalse(self.result()[0])

    def test_changed_qualification_logic_and_malformed_native_observations_fail(self):
        with mock.patch.object(m25, "_qualification_sources_match", return_value=False):
            self.assertFalse(self.result()[0])
        self.rewrite_source("native_result", lambda value: value.update(vagrant_smoke=[]))
        self.assertFalse(self.result()[0])

    def test_qualification_source_comparison_detects_changed_runner_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            runner = repository / m25.IMAGE_QUALIFICATION_FILES[0]
            runner.parent.mkdir(parents=True)
            runner.write_text("original\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repository), "-c", "commit.gpgsign=false", "-c", "user.name=Test",
                            "-c", "user.email=test@example.invalid", "commit", "-qm", "original"], check=True)
            first = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True).strip()
            runner.write_text("changed\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repository), "-c", "commit.gpgsign=false", "-c", "user.name=Test",
                            "-c", "user.email=test@example.invalid", "commit", "-qm", "changed"], check=True)
            second = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True).strip()
            self.assertTrue(self.real_source_match(repository, first, first))
            self.assertFalse(self.real_source_match(repository, first, second))


if __name__ == "__main__":
    unittest.main()
