#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("validate_governance", ROOT / "scripts/validate-governance.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class GovernanceValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controls = MODULE.load_yaml(ROOT / "governance/controls.yaml")
        cls.frameworks = MODULE.load_yaml(ROOT / "governance/frameworks.yaml")
        cls.environments = MODULE.load_yaml(ROOT / "governance/environments.yaml")
        cls.exceptions = MODULE.load_yaml(ROOT / "governance/exceptions.yaml")
        cls.data_policy = MODULE.load_yaml(ROOT / "governance/data-policy.yaml")
        cls.schema = MODULE.load_json(ROOT / "governance/controls.schema.json")

    def validate(self, controls=None, exceptions=None, frameworks=None):
        return MODULE.validate_model(
            ROOT,
            controls or copy.deepcopy(self.controls),
            frameworks or copy.deepcopy(self.frameworks),
            copy.deepcopy(self.environments),
            exceptions or copy.deepcopy(self.exceptions),
            copy.deepcopy(self.data_policy),
            copy.deepcopy(self.schema),
            today=date(2026, 8, 21),
        )

    def assert_has(self, errors, fragment):
        self.assertTrue(any(fragment in item for item in errors), errors)

    def test_canonical_registry_passes(self):
        self.assertEqual([], self.validate())

    def test_duplicate_control_id_fails(self):
        controls = copy.deepcopy(self.controls)
        controls["controls"].append(copy.deepcopy(controls["controls"][0]))
        self.assert_has(self.validate(controls=controls), "duplicate control IDs")

    def test_invalid_status_fails(self):
        controls = copy.deepcopy(self.controls)
        controls["controls"][0]["enforcement_status"] = "PROVEN"
        self.assert_has(self.validate(controls=controls), "PROVEN")

    def test_unknown_framework_fails(self):
        controls = copy.deepcopy(self.controls)
        controls["controls"][0]["framework_mappings"][0]["framework"] = "UNKNOWN_FRAMEWORK"
        self.assert_has(self.validate(controls=controls), "unknown framework")

    def test_nonexistent_project_control_mapping_fails(self):
        controls = copy.deepcopy(self.controls)
        controls["controls"][0]["framework_mappings"][0]["project_control_id"] = "SEC-999"
        self.assert_has(self.validate(controls=controls), "nonexistent project control mapping")

    def test_malformed_framework_mapping_fails(self):
        controls = copy.deepcopy(self.controls)
        controls["controls"][0]["framework_mappings"][0]["control"] = "???"
        self.assert_has(self.validate(controls=controls), "malformed framework control reference")

    def test_proven_runtime_without_evidence_fails(self):
        controls = copy.deepcopy(self.controls)
        controls["controls"][0]["runtime_status"] = "PROVEN_RUNTIME"
        self.assert_has(self.validate(controls=controls), "PROVEN_RUNTIME requires runtime probe evidence")

    def valid_exception(self):
        return {
            "id": "EXC-0001",
            "control_id": "NET-001",
            "reason": "Contrainte temporaire de migration documentée.",
            "risk": "Exposition réseau résiduelle bornée.",
            "compensating_controls": ["Firewall cloud limité à un CIDR approuvé."],
            "scope": {"kind": "Deployment", "namespace": "integration", "name": "migration"},
            "environments": ["integration"],
            "approver_role": "security",
            "reference": "RISK-0001",
            "created_at": "2026-08-01",
            "expires_at": "2026-09-01",
        }

    def test_exception_without_expiry_fails(self):
        exceptions = copy.deepcopy(self.exceptions)
        exception = self.valid_exception()
        exception.pop("expires_at")
        exceptions["exceptions"] = [exception]
        self.assert_has(self.validate(exceptions=exceptions), "expires_at")

    def test_expired_exception_fails(self):
        exceptions = copy.deepcopy(self.exceptions)
        exception = self.valid_exception()
        exception["created_at"] = "2025-01-01"
        exception["expires_at"] = "2025-02-01"
        exceptions["exceptions"] = [exception]
        self.assert_has(self.validate(exceptions=exceptions), "exception expired")

    def test_wildcard_exception_scope_fails(self):
        exceptions = copy.deepcopy(self.exceptions)
        exception = self.valid_exception()
        exception["scope"] = {"namespace": "*"}
        exceptions["exceptions"] = [exception]
        self.assert_has(self.validate(exceptions=exceptions), "wildcard scope is forbidden")


if __name__ == "__main__":
    unittest.main()
