"""Producer-bound runtime proof dispatch; generic PASS is insufficient."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
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
            yaml.safe_dump(
                {
                    "machine_contracts": {
                        "roadmap_policy": "config/contracts/roadmap-policy.yaml"
                    }
                }
            ),
            encoding="utf-8",
        )
        for relative in runtime_authority._HISTORICAL_PRODUCER_INPUTS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        (self.root / ".gitignore").write_text(".context/\n", encoding="utf-8")
        (self.root / "source.txt").write_text("source\n", encoding="utf-8")
        self.git("init", "-q")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
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

    def historical(self, **changes):
        arguments = {
            "base_sha": self.head,
            "head_tree_sha": self.tree,
            "evidence_digest": "sha256:"
            + hashlib.sha256(self.path.read_bytes()).hexdigest(),
        }
        arguments.update(changes)
        return runtime_authority.verify_historical_runtime_proof(
            self.root, "M2.5", self.head, LAB_PATH, **arguments
        )

    def test_historical_exact_producer_proof_survives_new_head_and_elapsed_time(self):
        self.proof["created_at_epoch"] = time.time() - 172800
        self.write_proof()
        (self.root / "source.txt").write_text("merged source\n", encoding="utf-8")
        self.git("add", "source.txt")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "later commit",
        )
        self.assertNotEqual(self.head, self.git("rev-parse", "HEAD"))
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
        ) as producer:
            result = self.historical()
        self.assertEqual("PASS", result["status"], result["reason"])
        self.assertEqual(self.proof["runtime_identity"], result["runtime_identity"])
        producer.assert_called_once_with(self.root, self.proof, self.head, self.tree)

    def test_historical_wrong_digest_tree_identity_or_recovery_never_authorizes(self):
        for changes in (
            {"evidence_digest": "sha256:" + "0" * 64},
            {"head_tree_sha": "0" * 40},
            {"recovery_required": True},
        ):
            with (
                self.subTest(changes=changes),
                mock.patch.object(
                    runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
                ) as producer,
            ):
                self.assertEqual("FAIL", self.historical(**changes)["status"])
                producer.assert_not_called()
        self.proof["head_sha"] = "0" * 40
        self.write_proof()
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
        ) as producer:
            self.assertEqual("FAIL", self.historical()["status"])
            producer.assert_not_called()

    def test_historical_self_declared_pass_fails_the_actual_producer(self):
        result = self.historical()
        self.assertEqual("FAIL", result["status"])
        self.assertIn("M2.5", result["reason"])

    def test_historical_runtime_still_requires_real_producer_observations(self):
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence,
            "validate",
            side_effect=ValueError("protected VM identity does not match"),
        ):
            result = self.historical()
        self.assertEqual("FAIL", result["status"])
        self.assertIn("protected VM identity", result["reason"])

    def test_historical_runtime_uses_base_policy_and_exact_head_producer_data(self):
        policy = self.root / "config/contracts/roadmap-policy.yaml"
        policy.write_text("status_derivation: forged\n", encoding="utf-8")
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
        ):
            self.assertEqual("PASS", self.historical()["status"])
        contract = self.root / runtime_authority._HISTORICAL_PRODUCER_INPUTS[0]
        contract.write_bytes(contract.read_bytes() + b" ")
        with mock.patch.object(
            runtime_authority.roadmap_sync.m25_runtime_evidence, "validate"
        ) as producer:
            result = self.historical()
        self.assertEqual("FAIL", result["status"])
        self.assertIn("exact HEAD", result["reason"])
        producer.assert_not_called()

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
                self.verify(evidence_path=".context/evidence/roadmap/M3.json")[
                    "status"
                ],
            )
        producer.assert_not_called()

    def test_recovery_required_fails_without_producer_verified_recovery(self):
        self.proof["recovery"] = {
            "capture": "PASS",
            "restore": "PASS",
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


class NativeRecoveryDispatchTests(unittest.TestCase):
    """Dispatch tests mock the producer; actual observation tests are separate."""

    git = RuntimeAuthorityTests.git
    write_proof = RuntimeAuthorityTests.write_proof

    def setUp(self):
        RuntimeAuthorityTests.setUp(self)
        for relative in runtime_authority._NATIVE_HISTORICAL_PRODUCER_INPUTS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        self.policy_path = self.root / runtime_authority._EXECUTION_POLICY_PATH
        shutil.copyfile(ROOT / runtime_authority._EXECUTION_POLICY_PATH, self.policy_path)
        (self.root / "architecture.lock.yaml").write_text(yaml.safe_dump({
            "machine_contracts": {
                "roadmap_policy": "config/contracts/roadmap-policy.yaml",
                "execution_properties_policy": runtime_authority._EXECUTION_POLICY_PATH,
            },
        }), encoding="utf-8")
        self.path = self.root / runtime_authority._NATIVE_RECOVERY_PATH
        self.path.parent.mkdir(parents=True)
        self.proof.update(
            environment="host", proof_type="native-host-recovery",
            paid_resources_created=0,
        )
        self.commit_source()
        self.verdict = {
            "status": "PASS", "environment": "host",
            "runtime_identity": self.proof["runtime_identity"],
            "recovery": {phase: "PASS" for phase in runtime_authority._RECOVERY_PHASES},
        }

    def commit_source(self):
        self.git("add", ".")
        self.git(
            "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-qm", "native fixture",
        )
        self.head = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        self.proof.update(head_sha=self.head, head_tree_sha=self.tree)
        self.write_proof()

    def verify(self, **changes):
        inputs = {
            "root": self.root, "milestone": "M2.5", "head_sha": self.head,
            "evidence_path": runtime_authority._NATIVE_RECOVERY_PATH,
            "recovery_required": True,
        }
        inputs.update(changes)
        return runtime_authority.verify_runtime_proof(**inputs)

    def historical(self, **changes):
        inputs = {
            "root": self.root, "milestone": "M2.5", "head_sha": self.head,
            "evidence_path": runtime_authority._NATIVE_RECOVERY_PATH,
            "base_sha": self.head, "head_tree_sha": self.tree,
            "evidence_digest": "sha256:" + hashlib.sha256(self.path.read_bytes()).hexdigest(),
            "recovery_required": True,
        }
        inputs.update(changes)
        return runtime_authority.verify_historical_runtime_proof(**inputs)

    def producer(self, **kwargs):
        return mock.patch.object(
            runtime_authority.native_recovery_evidence, "validate",
            **({"return_value": self.verdict} | kwargs),
        )

    def test_registered_host_producer_receives_exact_identity_and_returns_bound_verdict(self):
        with self.producer() as producer:
            result = self.verify()
        self.assertEqual("PASS", result["status"], result)
        self.assertEqual(runtime_authority._NATIVE_PRODUCER, result["producer"])
        self.assertEqual("native-host-recovery", result["proof_type"])
        self.assertEqual("host", result["environment"])
        self.assertEqual(self.verdict["recovery"], result["recovery"])
        self.assertEqual(self.head, result["head_sha"])
        self.assertEqual(self.tree, result["head_tree_sha"])
        self.assertEqual(runtime_authority._NATIVE_RECOVERY_PATH, result["evidence_path"])
        self.assertEqual(
            "sha256:" + hashlib.sha256(self.path.read_bytes()).hexdigest(),
            result["evidence_digest"],
        )
        producer.assert_called_once_with(
            self.root, self.proof, self.head, self.tree, historical=False,
        )

    def test_consumer_recovery_pass_never_authorizes(self):
        self.proof["recovery"] = self.verdict["recovery"]
        self.write_proof()
        with self.producer() as producer:
            self.assertEqual("FAIL", self.verify()["status"])
        producer.assert_not_called()

    def test_failed_missing_or_inconsistent_producer_verdict_never_authorizes(self):
        variants = [
            None, {}, self.verdict | {"status": "FAIL"},
            self.verdict | {"environment": "production"},
            self.verdict | {"runtime_identity": {"kind": "virtualbox-vm", "id": "other"}},
            self.verdict | {"recovery": {"capture": "PASS", "restore": "PASS"}},
            self.verdict | {"recovery": self.verdict["recovery"] | {"restore": "FAIL"}},
        ]
        for verdict in variants:
            with self.subTest(verdict=verdict), self.producer(return_value=verdict):
                self.assertEqual("FAIL", self.verify()["status"])
        with self.producer(side_effect=ValueError("protected recovery receipt absent")):
            result = self.verify()
        self.assertIn("protected recovery receipt absent", result["reason"])

    def test_host_metadata_cannot_claim_other_scope_or_identity(self):
        original = dict(self.proof)
        for changes in (
            {"environment": "lab"}, {"environment": "production"},
            {"deployment_state": "DEPLOYED"}, {"paid_resources_created": 1},
            {"paid_resources_created": False}, {"schema_version": True},
            {"head_sha": "0" * 40}, {"head_tree_sha": "0" * 40},
            {"proof_type": "lab-readiness"}, {"runtime_execution": False},
            {"exact_commit_evidence": False}, {"runtime_identity": {"kind": "host"}},
            {"created_at_epoch": time.time() - 86401},
            {"created_at_epoch": time.time() + 300},
            {"created_at_epoch": True}, {"created_at_epoch": float("nan")},
        ):
            self.proof = original | changes
            self.write_proof()
            with self.subTest(changes=changes), self.producer() as producer:
                self.assertEqual("FAIL", self.verify()["status"])
            producer.assert_not_called()

    def test_wrong_dispatch_and_dirty_checkout_fail_before_producer(self):
        with self.producer() as producer:
            for changes in (
                {"milestone": "M3"}, {"head_sha": "short"},
                {"evidence_path": ".context/evidence/native-recovery/other.json"},
                {"recovery_required": "true"},
            ):
                with self.subTest(changes=changes):
                    self.assertEqual("FAIL", self.verify(**changes)["status"])
            (self.root / "source.txt").write_text("changed", encoding="utf-8")
            self.assertEqual("FAIL", self.verify()["status"])
        producer.assert_not_called()

    def test_execution_policy_registration_and_semantics_cannot_be_weakened(self):
        original = yaml.safe_load(self.policy_path.read_text(encoding="utf-8"))
        variants = [
            original | {"status": "disabled"},
            original | {"properties": original["properties"] | {
                "recovery": original["properties"]["recovery"] | {
                    "capture_before_mutation": "optional",
                },
            }},
            original | {"properties": original["properties"] | {
                "verification": {"runtime_evidence": "required", "declaration_only_proof": "allowed"},
            }},
        ]
        for value in variants:
            self.policy_path.write_text(yaml.safe_dump(value), encoding="utf-8")
            self.commit_source()
            with self.producer() as producer:
                self.assertEqual("FAIL", self.verify()["status"])
            producer.assert_not_called()
        self.policy_path.write_text(yaml.safe_dump(original), encoding="utf-8")
        (self.root / "architecture.lock.yaml").write_text(
            "machine_contracts: {}\n", encoding="utf-8",
        )
        self.commit_source()
        with self.producer() as producer:
            result = self.verify()
        self.assertIn("ExecutionPropertiesPolicy is not registered", result["reason"])
        producer.assert_not_called()

    def test_unsafe_evidence_and_duplicate_fields_are_rejected(self):
        target = self.path.parent / "target.json"
        target.write_bytes(self.path.read_bytes())
        self.path.unlink()
        self.path.symlink_to(target)
        with self.producer() as producer:
            self.assertIn("symlink", self.verify()["reason"])
        producer.assert_not_called()
        self.path.unlink()
        self.path.hardlink_to(target)
        with self.producer() as producer:
            self.assertIn("hardlinked", self.verify()["reason"])
        producer.assert_not_called()
        self.path.unlink()
        self.path.write_text('{"status":"PASS","status":"PASS"}', encoding="utf-8")
        with self.producer() as producer:
            self.assertIn("duplicate runtime evidence key", self.verify()["reason"])
        producer.assert_not_called()

    def test_evidence_or_checkout_change_during_validation_is_rejected(self):
        def mutate_evidence(*_args, **_kwargs):
            self.path.write_bytes(self.path.read_bytes() + b" ")
            return self.verdict

        with self.producer(side_effect=mutate_evidence):
            self.assertIn("changed during producer validation", self.verify()["reason"])
        self.write_proof()

        def mutate_source(*_args, **_kwargs):
            (self.root / "source.txt").write_text("changed", encoding="utf-8")
            return self.verdict

        with self.producer(side_effect=mutate_source):
            self.assertIn("source changed during producer validation", self.verify()["reason"])

    def test_historical_keeps_original_identity_and_digest_without_reexpiring(self):
        self.proof["created_at_epoch"] = time.time() - 172800
        self.write_proof()
        head, tree, proof = self.head, self.tree, dict(self.proof)
        digest = "sha256:" + hashlib.sha256(self.path.read_bytes()).hexdigest()
        (self.root / "source.txt").write_text("later", encoding="utf-8")
        self.git("add", "source.txt")
        self.git(
            "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-qm", "later",
        )
        with self.producer() as producer:
            result = self.historical()
        self.assertEqual("PASS", result["status"], result)
        self.assertEqual(digest, result["evidence_digest"])
        producer.assert_called_once_with(self.root, proof, head, tree, historical=True)

    def test_historical_uses_base_policy_and_original_head_input_bytes(self):
        self.policy_path.write_text("status: forged\n", encoding="utf-8")
        with self.producer():
            self.assertEqual("PASS", self.historical()["status"])
        runner = self.root / "scripts/windows/LabNativeBoot.ps1"
        runner.write_bytes(runner.read_bytes() + b" ")
        with self.producer() as producer:
            result = self.historical()
        self.assertEqual("FAIL", result["status"])
        self.assertIn("exact HEAD", result["reason"])
        producer.assert_not_called()

    def test_historical_rejects_wrong_digest_tree_base_or_source_mutation(self):
        for changes in (
            {"base_sha": None}, {"base_sha": "not-a-sha"},
            {"head_tree_sha": None}, {"head_tree_sha": "0" * 40},
            {"evidence_digest": None}, {"evidence_digest": "sha256:" + "0" * 64},
            {"recovery_required": 1},
        ):
            with self.subTest(changes=changes), self.producer() as producer:
                self.assertEqual("FAIL", self.historical(**changes)["status"])
            producer.assert_not_called()

        def mutate_input(*_args, **_kwargs):
            runner = self.root / "scripts/windows/LabNativeBoot.ps1"
            runner.write_bytes(runner.read_bytes() + b" ")
            return self.verdict

        with self.producer(side_effect=mutate_input):
            result = self.historical()
        self.assertIn("exact HEAD", result["reason"])


if __name__ == "__main__":
    unittest.main()
