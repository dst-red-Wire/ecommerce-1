"""M2.5 proof must remain tied to observed Rocky, VM, and RKE2 results."""

from __future__ import annotations

import importlib.util
import json
import shutil
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
                         *m25.RKE2_SERVER_SOURCE_FILES,
                         "config/artifacts/rocky-10.2-base-packages.lock.json",
                         "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json"):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        lock = json.loads((self.root / "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json").read_text())
        self.manifest_sha = lock["approved_manifest_sha256"]
        server_hashes = [
            f"{m25._digest(self.root / relative)}  {(self.root / relative).resolve()}"
            for relative in m25.RKE2_SERVER_SOURCE_FILES
        ]
        self.manifest = {
            "box_sha256": BOX_SHA, "inputs_digest": INPUTS,
            "packer_template_digest": TEMPLATE, "staging_manifest_sha256": STAGING,
            "source_sha": ORIGINAL, "source_tree_sha": ORIGINAL_TREE,
            "rocky_version": "10.2", "virtualbox_version": "7.2.18",
            "native_vtx": "PASS", "nem_detected": False,
            "packer_build": "PASS", "packer_log_sha256": "8" * 64,
        }
        self.campaign_epoch = int(datetime.now(timezone.utc).timestamp())
        transfer = {
            "mode": "delta", "source_digest": self.manifest_sha,
            "prior_target_digest": None, "manifest_digest": self.manifest_sha,
            "final_digest": self.manifest_sha, "target_valid_before": False,
            "copy_changed": True,
            "started_at": datetime.fromtimestamp(self.campaign_epoch - 10, timezone.utc).isoformat(),
            "finished_at": datetime.fromtimestamp(self.campaign_epoch - 9, timezone.utc).isoformat(),
        }
        source_payloads = {
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
                "box_digest": BOX_SHA,
                "packer": {"status": "REUSED", "build": "NOT_EXECUTED",
                           "inputs_digest": INPUTS},
                "guest_security": "PASS", "vm_recreate": "NOT_REQUIRED",
                "vm_restart": "NOT_REQUIRED",
                "resume_from": "downstream-qualification",
                "resume_seed_server": "NOT_REQUIRED",
                "cleanup": {"status": "PASS", "seed_server": "PASS", "lock": "PASS",
                            "vm_preserved": True,
                            "vm_name": "ecommerce-rocky-10-2-smoke-4e935faff986", "vm_id": UUID},
                "checkpoints": {name: "PASS" for name in (
                    "03-vm-smoke", "04-network-ssh", "05-rocky-runtime",
                    "06-image-qualification")},
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
            "server_source": {"git_sha": HEAD, "source_sha256": server_hashes},
            "rke2_result": {"node_ready": True, "cilium_ready": 1, "selinux": "Enforcing",
                            "pending_pods": [],
                            "rke2_service": "active",
                            "nft_policies": {"output": "drop", "forward": "drop"},
                            "public_connect_error": 101, "rke2_version": "rke2 version v1.37.0+rke2r1"},
            "role_result": {"exit_code": 0, "vm_uuid": UUID,
                            "bundle_manifest_sha256": self.manifest_sha,
                            "transfer": transfer},
            "cold_role_result": {"exit_code": 0, "vm_uuid": UUID,
                                 "bundle_manifest_sha256": self.manifest_sha,
                                 "transfer": transfer,
                                 "trial": {"vm_uuid": UUID,
                                           "boot_id": "87654321-4321-4321-4321-abcdef123456",
                                           "cold_trial": True, "previous_attempt": False}},
            "tamper_result": {"blocked_task": "Revalidate every staged byte immediately before privileged installation",
                              "rke2_service": "inactive", "mutation": {
                                  "before_sha256": lock["release_artifacts"]["binary"]["sha256"],
                                  "after_sha256": "f" * 64}},
            "campaign_result": {
                "schema_version": 1, "status": "PASS", "head_sha": HEAD,
                "head_tree_sha": TREE, "vm_uuid": UUID, "box_sha256": BOX_SHA,
                "virtualbox_backend": "NATIVE_VTX",
                "vm_memory_mib": 4096, "created_at_epoch": self.campaign_epoch,
                "manifest_sha256": self.manifest_sha,
                "actions": [
                    {"action": action, "status": "PASS", "duration_seconds": 1.0,
                     **({"transfer": transfer} if action in {"test", "restage"} else {}),
                     **({"vm_uuid": UUID, "install_required": install} if action == "server" else {})}
                    for action, install in zip(
                        ["validate", "create", "test", "diagnostics", "server", "server", "restage",
                         "tamper", "restage", "server", "destroy"],
                        [None, None, None, None, True, False, None, None, None, True, None],
                    )
                ],
            },
        }
        package_lock_path = self.root / "config/artifacts/rocky-10.2-base-packages.lock.json"
        package_lock = json.loads(package_lock_path.read_text(encoding="utf-8"))
        roots = package_lock["profiles"]["base"]["roots"] + package_lock["profiles"]["rke2"]["roots"]
        names = sorted(set(roots) | {f"fixture-pkg-{index:02d}" for index in range(60)})
        packages = [f"{name}|0:1.0-1.x86_64" for name in names]
        log_relative = "logs/ssh-resume-20260929T170000Z/VBox.log"
        source_payloads["current_network_smoke"]["image_qualification"] = {
            "status": "PASS", "source_sha": HEAD, "source_tree_sha": TREE,
            "box_sha256": BOX_SHA, "vm_id": UUID, "virtualbox_backend": "NATIVE_VTX",
            "virtualbox_log_relative": log_relative,
            "virtualbox_log_sha256": m25.hashlib.sha256(
                b"HM: Using VT-x implementation 3.0\n").hexdigest(),
            "package_lock_sha256": m25._digest(package_lock_path),
            "checks": {name: "PASS" for name in m25.IMAGE_CHECKS},
            "observations": {name: {"status": "PASS", "exit_code": 0,
                                     "stdout": f"{name}-observed", "stderr": "",
                                     "stdout_truncated": False}
                             for name in m25.IMAGE_CHECKS},
            "supply_chain": {
                "artifact_sha256": BOX_SHA,
                "package_manifest": {"format": "rpm-nevra-v1", "packages": packages},
                "profile_inventory": {"profile": "rke2", "required_packages": sorted(roots)},
                "sbom": {
                    "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                    "metadata": {"component": {"type": "file",
                               "name": "rocky-10.2-rke2-virtualbox.box",
                               "hashes": [{"alg": "SHA-256", "content": BOX_SHA}]}},
                    "components": [{"type": "library", "name": name, "version": "0:1.0-1.x86_64"}
                                   for name in names],
                },
            },
        }
        self.backend_log = self.root / ".context/mgmt-offline-vm" / VM / "backend-VBox.log"
        self.backend_log.parent.mkdir(parents=True, exist_ok=True)
        self.backend_log.write_text("HM: HMR3Init: VT-x w/ nested paging\n", encoding="utf-8")
        source_payloads["backend_probe"]["virtualbox_log_sha256"] = m25._digest(self.backend_log)
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
            "original_image_execution": {
                "source_sha": ORIGINAL, "source_tree_sha": ORIGINAL_TREE,
                "packer_build": "PASS", "packer_log_sha256": "8" * 64,
            },
            "ready_for_real_provisioning": True, "deployment_state": "NOT_DEPLOYED",
            "paid_resources_created": 0,
            "six_node_rocky_rke2": "pending-real-target-and-service-inputs",
        }
        destination = self.root / m25.OUTPUT
        destination.parent.mkdir(parents=True)
        destination.write_text(json.dumps(self.evidence), encoding="utf-8")
        self.destination = destination
        self.shadow_root = self.root / "protected-native-smoke"
        shadow = self.shadow_root / f"{source_payloads['current_network_smoke']['campaign_id']}-{HEAD}"
        protected_result = shadow / "evidence/network-smoke" / source_payloads["current_network_smoke"]["campaign_id"] / "result.json"
        protected_result.parent.mkdir(parents=True)
        protected_result.write_bytes((self.root / m25.NETWORK_SMOKE).read_bytes())
        protected_runner = shadow / f"runner-{HEAD}" / "runner.json"
        protected_runner.parent.mkdir(parents=True)
        protected_runner.write_text('{"status":"PASS"}\n', encoding="utf-8")
        protected_log = shadow / source_payloads["current_network_smoke"]["campaign_id"] / log_relative
        protected_log.parent.mkdir(parents=True)
        protected_log.write_text("HM: Using VT-x implementation 3.0\n", encoding="utf-8")
        (shadow / "native-boot.json").write_text(json.dumps({
            "mode": "NETWORK_SMOKE_NATIVE", "phase": "RECOVERED", "run_status": "PASS",
            "campaign_id": source_payloads["current_network_smoke"]["campaign_id"],
            "source_sha": HEAD, "source_tree_sha": TREE,
            "vm_name": source_payloads["current_network_smoke"]["vm_name"],
            "vm_id": UUID, "box_sha256": BOX_SHA,
            "shadow_root": str(m25.SHADOW_WINDOWS_ROOT / shadow.name),
            "result_sha256": m25._digest(protected_result),
            "runner_manifest_sha256": m25._digest(protected_runner),
        }), encoding="utf-8")
        patcher = mock.patch.object(m25, "SHADOW_ROOT", self.shadow_root)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name, value in (("find_matching_box", Path("/unused/box")),
                            ("verify", self.manifest),
                            ("semantic_build_inputs", {"inputs_digest": INPUTS,
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

    def rewrite_protected_smoke(self, mutation):
        self.rewrite_source("current_network_smoke", mutation)
        smoke = self.root / m25.NETWORK_SMOKE
        campaign = "20260929T163821Z-9da62296f3d5"
        shadow = self.shadow_root / f"{campaign}-{HEAD}"
        protected = shadow / "evidence/network-smoke" / campaign / "result.json"
        protected.write_bytes(smoke.read_bytes())
        boot = shadow / "native-boot.json"
        state = json.loads(boot.read_text(encoding="utf-8"))
        state["result_sha256"] = m25._digest(protected)
        boot.write_text(json.dumps(state), encoding="utf-8")

    def test_valid_sources_pass_and_missing_source_fails(self):
        self.assertTrue(self.result()[0])
        self.assertFalse(self.roadmap_result()[0])
        self.assertIn("does not prove persistent MGMT deployment", self.roadmap_result()[1])
        (self.root / m25._paths(VM)["rke2_result"]).unlink()
        self.assertFalse(self.result()[0])

    def test_wrong_head_tree_expiry_blocked_and_rocky9_fail(self):
        for change in ({"head_sha": "f" * 40}, {"head_tree_sha": "f" * 40},
                       {"status": "BLOCKED_RUNTIME"}, {"rocky_version": "9.8"},
                       {"native_vtx": "NOT_MEASURED"},
                       {"schema_version": True}, {"paid_resources_created": False}):
            with self.subTest(change=change):
                original = dict(self.evidence)
                self.evidence.update(change)
                self.write()
                self.assertFalse(self.result()[0])
                self.evidence = original
        self.write()
        self.assertFalse(self.result(now=datetime.now(timezone.utc) + timedelta(days=2))[0])

    def test_source_digest_and_runtime_failures_are_rejected(self):
        self.evidence["source_evidence"]["image_reuse"]["sha256"] = "f" * 64
        self.write()
        self.assertFalse(self.result()[0])
        self.evidence["source_evidence"]["image_reuse"]["sha256"] = m25._digest(
            self.root / m25._paths(VM)["image_reuse"])
        self.write()
        runtime = self.root / m25._paths(VM)["rke2_result"]
        data = json.loads(runtime.read_text())
        data["node_ready"] = False
        runtime.write_text(json.dumps(data))
        self.evidence["source_evidence"]["rke2_result"]["sha256"] = m25._digest(runtime)
        self.write()
        self.assertFalse(self.result()[0])

    def test_changed_input_digest_and_box_digest_are_rejected(self):
        with mock.patch.object(m25.rocky_box_catalog, "semantic_build_inputs",
                               side_effect=lambda sha: {
                                   "inputs_digest": "f" * 64 if sha == HEAD else INPUTS,
                                   "packer_template_digest": TEMPLATE,
                               }):
            self.assertFalse(self.result()[0])
        self.manifest["box_sha256"] = "f" * 64
        self.assertFalse(self.result()[0])

    def test_server_source_pending_pod_and_unapproved_tamper_are_rejected(self):
        self.rewrite_source("server_source", lambda value: value["source_sha256"].__setitem__(
            0, "0" * 64 + value["source_sha256"][0][64:]))
        self.assertFalse(self.result()[0])
        expected = [
            f"{m25._digest(self.root / relative)}  {(self.root / relative).resolve()}"
            for relative in m25.RKE2_SERVER_SOURCE_FILES
        ]
        self.rewrite_source("server_source", lambda value: value.update(source_sha256=expected))
        self.rewrite_source("rke2_result", lambda value: value.update(pending_pods=["kube-system/coredns"]))
        self.assertFalse(self.result()[0])
        self.rewrite_source("rke2_result", lambda value: value.update(pending_pods=[]))
        self.rewrite_source("tamper_result", lambda value: value["mutation"].update(before_sha256="e" * 64))
        self.assertFalse(self.result()[0])

    def test_public_egress_observation_must_indicate_denial(self):
        for value in ({}, "", "ConnectionRefusedError", 0, True):
            with self.subTest(value=value):
                self.rewrite_source("rke2_result", lambda result: result.update(
                    public_connect_error=value))
                with self.assertRaisesRegex(ValueError, "RKE2/Cilium runtime proof"):
                    m25.validate(self.root, self.evidence, HEAD, TREE)

    def test_runtime_counts_and_exit_codes_reject_booleans(self):
        self.rewrite_source("role_result", lambda value: value.update(exit_code=False))
        with self.assertRaisesRegex(ValueError, "offline role or VM identity"):
            m25.validate(self.root, self.evidence, HEAD, TREE)
        self.rewrite_source("role_result", lambda value: value.update(exit_code=0))
        self.rewrite_source("rke2_result", lambda value: value.update(cilium_ready=True))
        with self.assertRaisesRegex(ValueError, "RKE2/Cilium runtime proof"):
            m25.validate(self.root, self.evidence, HEAD, TREE)

    def test_unknown_provenance_and_fake_execution_rebinding_are_rejected(self):
        self.rewrite_source("image_reuse", lambda value: value["reused_from"].update(source_sha="f" * 40))
        self.assertFalse(self.result()[0])
        self.rewrite_source("image_reuse", lambda value: value["reused_from"].update(source_sha=ORIGINAL))
        self.evidence["original_image_execution"]["source_sha"] = HEAD
        self.write()
        self.assertFalse(self.result()[0])

    def test_original_packer_provenance_missing_or_nem_is_rejected(self):
        original = self.evidence.pop("original_image_execution")
        self.write()
        self.assertFalse(self.result()[0])
        self.evidence["original_image_execution"] = original
        self.write()
        self.manifest["nem_detected"] = True
        self.assertFalse(self.result()[0])

    def test_functional_rke2_nem_is_recorded_separately_from_native_image(self):
        self.backend_log.write_text("NEM: Hyper-V active\n", encoding="utf-8")
        self.rewrite_source("backend_probe", lambda value: value.update(
            virtualbox_backend="NEM", hypervisor_present=True,
            virtualbox_log_sha256=m25._digest(self.backend_log)))
        self.rewrite_source("campaign_result", lambda value: value.update(virtualbox_backend="NEM"))
        self.assertTrue(self.result()[0])

    def test_rke2_backend_log_snapshot_is_content_bound(self):
        self.backend_log.write_text("NEM: Hyper-V active\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "backend log digest differs"):
            m25.validate(self.root, self.evidence, HEAD, TREE)
        self.rewrite_source("backend_probe", lambda value: value.update(
            virtualbox_log_sha256=m25._digest(self.backend_log)))
        with self.assertRaisesRegex(ValueError, "backend log classification differs"):
            m25.validate(self.root, self.evidence, HEAD, TREE)

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

    def test_image_qualification_checkpoint_and_observations_are_required(self):
        self.rewrite_protected_smoke(lambda value: value["checkpoints"].update(
            {"06-image-qualification": "FAIL"}))
        with self.assertRaisesRegex(ValueError, "network and guest-security smoke"):
            m25.validate(self.root, self.evidence, HEAD, TREE)
        self.rewrite_protected_smoke(lambda value: value["checkpoints"].update(
            {"06-image-qualification": "PASS"}))
        self.rewrite_protected_smoke(lambda value: value.update(resume_from="image-qualification"))
        with self.assertRaisesRegex(ValueError, "network and guest-security smoke"):
            m25.validate(self.root, self.evidence, HEAD, TREE)
        self.rewrite_protected_smoke(lambda value: value.update(resume_from="downstream-qualification"))
        self.rewrite_protected_smoke(lambda value: value["image_qualification"]["observations"].update(
            {"security": {"status": "PASS", "exit_code": [], "stdout": "ok", "stderr": "",
                          "stdout_truncated": False}}))
        with self.assertRaisesRegex(ValueError, "observation is invalid: security"):
            m25.validate(self.root, self.evidence, HEAD, TREE)

    def test_smoke_reuse_and_cleanup_cannot_contradict_pass(self):
        self.rewrite_protected_smoke(lambda value: value["packer"].update(
            status="REBUILT", build="PASS"))
        with self.assertRaisesRegex(ValueError, "network and guest-security smoke"):
            m25.validate(self.root, self.evidence, HEAD, TREE)
        self.rewrite_protected_smoke(lambda value: value["packer"].update(
            status="REUSED", build="NOT_EXECUTED"))
        self.rewrite_protected_smoke(lambda value: value["cleanup"].update(seed_server="FAIL"))
        with self.assertRaisesRegex(ValueError, "network and guest-security smoke"):
            m25.validate(self.root, self.evidence, HEAD, TREE)
        self.rewrite_protected_smoke(lambda value: value["cleanup"].update(seed_server="PASS"))
        self.rewrite_protected_smoke(lambda value: value.update(
            vm_restart="EXECUTED_EXISTING_VM", resume_seed_server="NOT_REQUIRED"))
        with self.assertRaisesRegex(ValueError, "network and guest-security smoke"):
            m25.validate(self.root, self.evidence, HEAD, TREE)

    def test_campaign_duration_must_be_measured_finite_number(self):
        self.rewrite_source("campaign_result", lambda value: value["actions"][0].update(
            duration_seconds=True))
        with self.assertRaisesRegex(ValueError, "campaign sequence is incomplete"):
            m25.validate(self.root, self.evidence, HEAD, TREE)
        self.rewrite_source("campaign_result", lambda value: value["actions"][0].update(
            duration_seconds=float("inf")))
        with self.assertRaisesRegex(ValueError, "campaign sequence is incomplete"):
            m25.validate(self.root, self.evidence, HEAD, TREE)

    def test_malformed_image_supply_chain_fails_with_validation_error(self):
        self.rewrite_protected_smoke(lambda value: value["image_qualification"]["supply_chain"]
                                     ["profile_inventory"].update(required_packages=[{}]))
        with self.assertRaisesRegex(ValueError, "RPM inventory is invalid"):
            m25.validate(self.root, self.evidence, HEAD, TREE)

    def test_native_vtx_log_is_content_bound(self):
        campaign = "20260929T163821Z-9da62296f3d5"
        log = self.shadow_root / f"{campaign}-{HEAD}" / campaign / (
            "logs/ssh-resume-20260929T170000Z/VBox.log")
        log.write_text("NEM: Hyper-V is active\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "VirtualBox log digest is invalid"):
            m25.validate(self.root, self.evidence, HEAD, TREE)
        self.rewrite_protected_smoke(lambda value: value["image_qualification"].update(
            virtualbox_log_sha256=m25._digest(log)))
        with self.assertRaisesRegex(ValueError, "does not prove VT-x"):
            m25.validate(self.root, self.evidence, HEAD, TREE)

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

    def test_transfer_decision_must_match_approved_bytes_and_recovery(self):
        self.rewrite_source("cold_role_result", lambda value: value["transfer"].update(
            source_digest="0" * 64))
        self.assertFalse(self.result()[0])
        self.rewrite_source("cold_role_result", lambda value: value["transfer"].update(
            source_digest=self.manifest_sha))
        self.rewrite_source("campaign_result", lambda value: value["actions"][8]["transfer"].update(
            copy_changed=False))
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
        package_relative = "config/artifacts/rocky-10.2-base-packages.lock.json"
        package_stage = stage / package_relative
        package_stage.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.root / package_relative, package_stage)
        (stage / "SHA256SUMS").write_text(
            f"{m25._digest(package_stage)}  {package_relative}\n", encoding="utf-8"
        )
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
            boot_state = laboratory / "network-smoke/native-boot.json"
            recovered = {
                "mode": "NETWORK_SMOKE_NATIVE", "campaign_id": campaign,
                "phase": "RECOVERED", "run_status": "FAIL",
                "source_sha": HEAD, "source_tree_sha": TREE,
                "vm_id": json.loads(native.read_text(encoding="utf-8"))["cleanup"]["vm_id"],
                "box_sha256": BOX_SHA,
                "result_sha256": m25._digest(native),
            }
            boot_state.write_text(json.dumps(recovered), encoding="utf-8")
            self.assertEqual(2, repoctl.lab_network_import(campaign, laboratory_root=laboratory))
            recovered["run_status"] = "PASS"
            recovered["result_sha256"] = "0" * 64
            boot_state.write_text(json.dumps(recovered), encoding="utf-8")
            self.assertEqual(2, repoctl.lab_network_import(campaign, laboratory_root=laboratory))
            recovered["result_sha256"] = m25._digest(native)
            boot_state.write_text(json.dumps(recovered), encoding="utf-8")
            self.assertEqual(0, repoctl.lab_network_import(campaign, laboratory_root=laboratory))
            original_native = native.read_bytes()
            original_read_bytes = Path.read_bytes
            changed_source = False

            def replace_result_after_read(path):
                nonlocal changed_source
                data = original_read_bytes(path)
                if path == native and not changed_source:
                    changed_source = True
                    native.write_bytes(b'{"status":"FAIL"}')
                return data

            with mock.patch.object(Path, "read_bytes", replace_result_after_read):
                self.assertEqual(0, repoctl.lab_network_import(campaign, laboratory_root=laboratory))
            self.assertTrue(changed_source)
            self.assertEqual(original_native, retained.read_bytes())
            self.assertNotEqual(original_native, native.read_bytes())
            native.write_bytes(original_native)
            boot_state.unlink()
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

    def test_current_qualification_reuses_original_packer_bytes_honestly(self):
        self.assertNotEqual(ORIGINAL, HEAD)
        self.assertEqual(ORIGINAL, self.evidence["original_image_execution"]["source_sha"])
        self.assertEqual(HEAD, json.loads((self.root / m25.NETWORK_SMOKE).read_text())[
            "resume_runner_source_sha"])
        self.assertTrue(self.result()[0])
        self.manifest["packer_log_sha256"] = "f" * 64
        self.assertFalse(self.result()[0])

    def test_protected_result_and_recovered_boot_must_match_import(self):
        campaign = "20260929T163821Z-9da62296f3d5"
        shadow = self.shadow_root / f"{campaign}-{HEAD}"
        protected_result = shadow / "evidence/network-smoke" / campaign / "result.json"
        original = protected_result.read_bytes()
        protected_result.write_bytes(b'{"status":"FAKE"}')
        self.assertFalse(self.result()[0])
        protected_result.write_bytes(original)
        boot_path = shadow / "native-boot.json"
        boot = json.loads(boot_path.read_text())
        boot["run_status"] = "FAIL"
        boot_path.write_text(json.dumps(boot))
        self.assertFalse(self.result()[0])


if __name__ == "__main__":
    unittest.main()
