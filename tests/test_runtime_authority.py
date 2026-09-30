"""Producer-bound runtime proof dispatch; generic PASS is insufficient."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import yaml

from scripts import runtime_authority


ROOT = Path(__file__).resolve().parents[1]
LAB_PATH = runtime_authority._LAB_PATH


class RuntimeAuthorityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        policy = self.root / "config/contracts/roadmap-policy.yaml"
        policy.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "config/contracts/roadmap-policy.yaml", policy)
        (self.root / "architecture.lock.yaml").write_text(
            yaml.safe_dump({
                "machine_contracts": {
                    "roadmap_policy": "config/contracts/roadmap-policy.yaml"
                }
            }),
            encoding="utf-8",
        )
        (self.root / ".gitignore").write_text(".context/\n", encoding="utf-8")
        (self.root / "source.txt").write_text("source\n", encoding="utf-8")
        self.git("init", "-q")
        self.git("add", ".")
        self.git(
            "-c", "user.name=Fixture", "-c",
            "user.email=fixture@example.invalid", "-c",
            "commit.gpgsign=false", "commit", "-q", "-m", "fixture",
        )
        self.head = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        self.path = self.root / LAB_PATH
        self.path.parent.mkdir(parents=True)
        self.proof = {
            "schema_version": 1,
            "status": "PASS",
            "exact_commit_evidence": True,
            "runtime_execution": True,
            "head_sha": self.head,
            "head_tree_sha": self.tree,
            "created_at_epoch": time.time(),
            "milestone": "M2.5",
            "environment": "lab",
            "runtime_identity": {
                "kind": "virtualbox-vm",
                "id": "11111111-1111-1111-1111-111111111111",
            },
            "outcome": "PASS",
            "deployment_state": "NOT_DEPLOYED",
        }
        self.write_proof()

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.root, text=True, capture_output=True, check=True
        ).stdout.strip()

    def write_proof(self):
        self.path.write_text(
            json.dumps(self.proof, sort_keys=True) + "\n", encoding="utf-8"
        )

    def verify(self, **kwargs):
        inputs = {
            "root": self.root,
            "milestone": "M2.5",
            "head_sha": self.head,
            "evidence_path": LAB_PATH,
        }
        inputs.update(kwargs)
        return runtime_authority.verify_runtime_proof(**inputs)

    def test_registered_lab_producer_is_required_and_receives_exact_identity(self):
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
        ) as producer:
            result = self.verify()
        self.assertEqual("PASS", result["status"])
        self.assertEqual("", result["reason"])
        self.assertEqual(self.head, result["head_sha"])
        self.assertEqual(self.tree, result["head_tree_sha"])
        self.assertRegex(result["evidence_digest"], r"^sha256:[0-9a-f]{64}$")
        producer.assert_called_once()
        args = producer.call_args.args
        self.assertEqual((self.root, self.head, self.tree), (args[0], args[2], args[3]))
        self.assertEqual(self.proof, args[1])

    def test_self_declared_pass_cannot_replace_real_producer_validation(self):
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence,
            "validate",
            side_effect=ValueError("observed VM sources missing"),
        ):
            result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertIn("observed VM sources missing", result["reason"])

    def test_unregistered_milestone_and_path_fail_before_producer(self):
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
        ) as producer:
            self.assertEqual("FAIL", self.verify(milestone="M3")["status"])
            self.assertEqual(
                "FAIL",
                self.verify(evidence_path=".context/evidence/roadmap/M3.json")["status"],
            )
        producer.assert_not_called()

    def test_recovery_required_fails_without_producer_verified_recovery(self):
        self.proof["recovery"] = {
            "capture": "PASS", "restore": "PASS",
            "restore_verification": "PASS",
        }
        self.write_proof()
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
        ) as producer:
            result = self.verify(recovery_required=True)
        self.assertEqual("FAIL", result["status"])
        self.assertIn("producer-verified capture", result["reason"])
        producer.assert_not_called()

    def test_stale_or_dirty_source_fails_before_producer(self):
        self.proof["created_at_epoch"] = time.time() - 86401
        self.write_proof()
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
        ) as producer:
            self.assertEqual("FAIL", self.verify()["status"])
        producer.assert_not_called()
        self.proof["created_at_epoch"] = time.time()
        self.write_proof()
        (self.root / "source.txt").write_text("dirty\n", encoding="utf-8")
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
        ) as producer:
            self.assertEqual("FAIL", self.verify()["status"])
        producer.assert_not_called()

    def test_policy_declaration_cannot_be_weakened(self):
        policy = self.root / "config/contracts/roadmap-policy.yaml"
        value = yaml.safe_load(policy.read_text(encoding="utf-8"))
        milestone = next(item for item in value["milestones"] if item["id"] == "M2.5")
        milestone["requirements"]["runtime_evidence"][0]["proof_type"] = "runtime"
        policy.write_text(yaml.safe_dump(value), encoding="utf-8")
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
        ) as producer:
            result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertIn("canonical M2.5 lab", result["reason"])
        producer.assert_not_called()

    def test_malformed_architecture_registration_fails_closed(self):
        (self.root / "architecture.lock.yaml").write_text(
            "machine_contracts: []\n", encoding="utf-8"
        )
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
        ) as producer:
            result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertIn("RoadmapPolicy is not registered", result["reason"])
        producer.assert_not_called()

    def test_symlink_duplicate_json_and_mutation_during_validation_fail(self):
        target = self.path.parent / "target.json"
        target.write_bytes(self.path.read_bytes())
        self.path.unlink()
        self.path.symlink_to(target)
        self.assertIn("symlink", self.verify()["reason"])
        self.path.unlink()
        self.path.write_text('{"status":"PASS","status":"PASS"}\n', encoding="utf-8")
        self.assertIn("duplicate runtime evidence key", self.verify()["reason"])
        self.write_proof()

        def mutate(*_args):
            self.path.write_bytes(self.path.read_bytes() + b" ")

        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence,
            "validate",
            side_effect=mutate,
        ):
            result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertIn("changed during producer validation", result["reason"])


if __name__ == "__main__":
    unittest.main()
