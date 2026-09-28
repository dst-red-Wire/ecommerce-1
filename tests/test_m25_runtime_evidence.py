"""M2.5 proof must remain tied to observed Rocky, VM, and RKE2 results."""

from __future__ import annotations

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
import roadmap_sync


HEAD = "a" * 40
TREE = "b" * 40
UUID = "12345678-1234-1234-1234-123456789abc"
BOX_SHA = "c" * 64
INPUTS = "d" * 64
VM = "ecommerce-mgmt-test-proof"


class M25RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for relative in ("config/contracts/machine-image-lock.yaml",
                         "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json"):
            destination = self.root / relative
            destination.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / relative, destination)
        lock = json.loads((self.root / "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json").read_text())
        self.manifest_sha = lock["approved_manifest_sha256"]
        self.manifest = {
            "box_sha256": BOX_SHA, "inputs_digest": INPUTS,
            "rocky_version": "10.2", "virtualbox_version": "7.2.18",
            "native_vtx": "PASS", "nem_detected": False,
        }
        source_payloads = {
            "image_build": {"status": "PASS", "source_sha": HEAD, "source_tree": TREE,
                            "sha256": BOX_SHA, "artifact": "rocky-10.2-rke2-virtualbox.box",
                            "virtualbox_backend": "NATIVE_VTX", "virtualbox_version": "7.2.18",
                            "packer_build": "PASS"},
            "image_qualification": {"status": "PASS", "source_sha": HEAD,
                                    "artifact_sha256": BOX_SHA, "artifact": "rocky-10.2-rke2-virtualbox.box",
                                    "qualification": {key: "PASS" for key in (
                                        "boot", "ssh", "rocky_release", "kernel", "systemd",
                                        "rke2_prerequisites", "security", "cleanup", "key_cleanup",
                                        "swap_absent", "rpm_profile")}},
            "image_release": {"status": "PASS", "source_sha": HEAD,
                              "artifact_sha256": BOX_SHA, "artifact": "rocky-10.2-rke2-virtualbox.box",
                              "checks": {key: "PASS" for key in (
                                  "exact_source_sha", "build_evidence", "checksum",
                                  "qualification_evidence", "cleanup", "ephemeral_key_absent",
                                  "sbom", "package_manifest", "profile_inventory")}},
            "native_import": {"status": "PASS", "source_git_sha": HEAD,
                              "source_tree_sha": TREE, "artifact_sha256": BOX_SHA,
                              "virtualbox_backend": "NATIVE_VTX", "wsl2_restored": "PASS",
                              "bcd_restored": "PASS"},
            "server_source": {"git_sha": HEAD},
            "rke2_result": {"node_ready": True, "cilium_ready": 1, "selinux": "Enforcing",
                            "nft_policies": {"output": "drop", "forward": "drop"},
                            "public_connect_error": 101, "rke2_version": "rke2 version v1.37.0+rke2r1"},
            "role_result": {"exit_code": 0, "vm_uuid": UUID,
                            "bundle_manifest_sha256": self.manifest_sha},
            "tamper_result": {"blocked_task": "Revalidate every staged byte immediately before privileged installation",
                              "rke2_service": "inactive", "mutation": {
                                  "before_sha256": "e" * 64, "after_sha256": "f" * 64}},
            "campaign_result": {
                "schema_version": 1, "status": "PASS", "head_sha": HEAD,
                "head_tree_sha": TREE, "vm_uuid": UUID, "box_sha256": BOX_SHA,
                "manifest_sha256": self.manifest_sha,
                "actions": [
                    {"action": action, "status": "PASS", "duration_seconds": 1.0,
                     **({"vm_uuid": UUID, "install_required": install} if action == "server" else {})}
                    for action, install in zip(
                        ["validate", "create", "test", "server", "server", "restage",
                         "tamper", "restage", "server", "destroy"],
                        [None, None, None, True, False, None, None, None, True, None],
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
            "created_at_epoch": int(datetime.now(timezone.utc).timestamp()),
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
                            ("verify", self.manifest)):
            patcher = mock.patch.object(m25.rocky_box_catalog, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def result(self, *, now=None):
        contract = roadmap_sync.policy()["status_derivation"]["runtime_evidence_contract"]
        return roadmap_sync._runtime_evidence_result(
            self.root, {"path": m25.OUTPUT.as_posix(), "environments": ["lab"]},
            "M2.5", HEAD, TREE, contract, 86400, now or datetime.now(timezone.utc),
        )

    def write(self):
        self.destination.write_text(json.dumps(self.evidence), encoding="utf-8")

    def test_valid_sources_pass_and_missing_source_fails(self):
        self.assertTrue(self.result()[0])
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


if __name__ == "__main__":
    unittest.main()
