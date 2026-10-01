"""Deterministic four-level merge-risk policy tests."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("merge_risk", ROOT / "scripts/merge_risk.py")
MERGE_RISK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MERGE_RISK)
BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40


class MergeRiskPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        contract = yaml.safe_load(
            (ROOT / "config/contracts/review-policy.yaml").read_text(encoding="utf-8")
        )
        cls.policy = contract["repository_delivery"]["pr_loop"]["risk_classification"]
        cls.owner_boundary = contract["repository_delivery"]["pr_loop"]["owner_boundary"]

    def classify(self, changes):
        paths = sorted(changes)
        return MERGE_RISK.evaluate_merge_risk(
            self.policy,
            base_sha=BASE_SHA,
            head_sha=HEAD_SHA,
            pr_number=171,
            changed_files=paths,
            file_changes=changes,
        )

    def test_policy_is_closed_world_and_has_four_classes(self):
        self.assertTrue(
            MERGE_RISK.merge_risk_policy_is_valid(self.policy, self.owner_boundary)
        )
        self.assertEqual(
            ["LOW_RISK", "SENSITIVE", "PRIVILEGED", "PRODUCTION"],
            self.policy["classifications"],
        )
        mutated = copy.deepcopy(self.policy)
        mutated["production"]["capabilities"]["production-inventory"]["paths"].remove(
            "config/infrastructure/prod-inventory.yaml"
        )
        self.assertFalse(
            MERGE_RISK.merge_risk_policy_is_valid(mutated, self.owner_boundary)
        )

    def test_paths_derive_each_level_and_requirements(self):
        cases = (
            ("docs/README.md", "LOW_RISK", "not-required-by-policy"),
            (
                "config/contracts/security-scan-policy.yaml",
                "SENSITIVE",
                "explicit-repository-owner",
            ),
            ("scripts/windows/LabNativeBoot.ps1", "PRIVILEGED", "explicit-repository-owner"),
            (
                "config/infrastructure/prod-inventory.yaml",
                "PRODUCTION",
                "explicit-repository-owner",
            ),
        )
        for path, level, owner in cases:
            with self.subTest(path=path):
                result = self.classify({path: "changed"})
                self.assertEqual(level, result["classification"])
                self.assertEqual(owner, result["requirements"]["owner_authorization"])
                self.assertEqual(
                    self.policy["class_requirements"][level], result["requirements"]
                )
                self.assertTrue(result["analysis_complete"])

    def test_content_signals_and_highest_class_win(self):
        privileged = self.classify(
            {"scripts/host_control.py": "subprocess.run(['bcdedit'])"}
        )
        self.assertEqual("PRIVILEGED", privileged["classification"])
        self.assertEqual("capture-restore-verify", privileged["requirements"]["recovery"])
        credentials = self.classify({"scripts/identity.py": "rotate credentials"})
        self.assertEqual("PRIVILEGED", credentials["classification"])
        production = self.classify(
            {"scripts/deploy.py": "perform production rollout"}
        )
        self.assertEqual("PRODUCTION", production["classification"])
        self.assertEqual(
            "production-runtime-before-mutation",
            production["requirements"]["runtime_evidence"],
        )
        mixed = self.classify(
            {
                "scripts/windows/LabNativeBoot.ps1": "changed",
                "config/infrastructure/prod-inventory.yaml": "changed",
            }
        )
        self.assertEqual("PRODUCTION", mixed["classification"])

    def test_ambiguous_input_remains_sensitive_and_owner_gated(self):
        result = MERGE_RISK.evaluate_merge_risk(
            self.policy,
            base_sha="invalid",
            head_sha=HEAD_SHA,
            pr_number=171,
            changed_files=["docs/README.md"],
            file_changes={"docs/README.md": "changed"},
        )
        self.assertEqual("SENSITIVE", result["classification"])
        self.assertFalse(result["analysis_complete"])
        self.assertEqual(
            "explicit-repository-owner",
            result["requirements"]["owner_authorization"],
        )


if __name__ == "__main__":
    unittest.main()
