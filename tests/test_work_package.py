from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from scripts import work_package


ROOT = Path(__file__).resolve().parents[1]


def valid_package() -> dict:
    return {
        "id": "m25-governance-chain",
        "milestone": "M2.5",
        "tracker_issue": 32,
        "work_item_issue": 170,
        "objective": "Validate the bounded governance chain for one work item.",
        "scope": {
            "allowed_paths": [
                "config/contracts/work-package-policy.yaml",
                "scripts/work_package.py",
                "tests/test_work_package.py",
            ],
            "forbidden_paths": ["scripts/repoctl.py"],
        },
        "dependencies": [],
        "acceptance": {
            "contracts": [
                "config/contracts/roadmap-policy.yaml",
                "config/contracts/qualification-execution-policy.yaml",
            ],
            "qualification_gates": ["governance", "contracts"],
            "runtime_evidence": [],
            "tests": ["tests/test_work_package.py"],
            "qce_capabilities": [],
        },
        "execution": {
            "preflight_required": True,
            "runtime_required": False,
            "recovery_required": False,
        },
        "review": {"code": "required", "security": "required"},
        "completion": {"post_merge_verification": True},
        "exit_criteria": [
            "The exact package declaration and all changed paths validate."
        ],
    }


class WorkPackageTests(unittest.TestCase):
    def test_valid_declaration_never_claims_execution_or_acceptance(self):
        package = valid_package()
        result = work_package.work_package_status(
            package,
            root=ROOT,
            changed_paths=["scripts/work_package.py", "tests/test_work_package.py"],
            expected_issue=170,
            expected_milestone="M2.5",
        )
        self.assertEqual("VALID", result["status"])
        self.assertEqual("VALID", result["scope_status"])
        self.assertEqual("NOT_EVALUATED", result["acceptance_status"])
        self.assertEqual("NOT_EVALUATED", result["runtime_status"])
        self.assertEqual([], result["errors"])
        self.assertNotIn("PASS", str(result))

    def test_scope_not_checked_when_changed_paths_are_omitted(self):
        result = work_package.work_package_status(valid_package(), root=ROOT)
        self.assertEqual("VALID", result["status"])
        self.assertEqual("NOT_CHECKED", result["scope_status"])

    def test_changed_path_outside_scope_fails(self):
        errors = work_package.validate_work_package(
            valid_package(), root=ROOT, changed_paths=["scripts/roadmap_sync.py"]
        )
        self.assertTrue(any("outside allowed_paths" in error for error in errors))

    def test_forbidden_path_wins_even_when_allowed_by_subtree(self):
        package = valid_package()
        package["scope"]["allowed_paths"].append("scripts/governance/**")
        package["scope"]["forbidden_paths"].append("scripts/governance/private.py")
        errors = work_package.validate_work_package(
            package, root=ROOT, changed_paths=["scripts/governance/private.py"]
        )
        self.assertTrue(any("is forbidden" in error for error in errors))

    def test_exact_allowed_forbidden_conflict_fails(self):
        package = valid_package()
        package["scope"]["forbidden_paths"].append("scripts/work_package.py")
        errors = work_package.validate_work_package(package, root=ROOT)
        self.assertTrue(any("both allowed and forbidden" in error for error in errors))

    def test_absolute_traversal_and_unbounded_patterns_fail(self):
        for unsafe in ("/tmp/escape.py", "../escape.py", "scripts/../escape.py", "**"):
            with self.subTest(path=unsafe):
                package = valid_package()
                package["scope"]["allowed_paths"] = [unsafe]
                errors = work_package.validate_work_package(package, root=ROOT)
                self.assertTrue(any("scope.allowed_paths" in error for error in errors))

    def test_changed_path_traversal_fails(self):
        errors = work_package.validate_work_package(
            valid_package(), root=ROOT, changed_paths=["scripts/../secrets.txt"]
        )
        self.assertTrue(any("scope.changed_paths" in error for error in errors))

    def test_tracker_must_match_roadmap_and_issue_context(self):
        package = valid_package()
        package["tracker_issue"] = 13
        errors = work_package.validate_work_package(
            package, root=ROOT, expected_issue=171
        )
        self.assertTrue(any("tracker_issue does not match" in error for error in errors))
        self.assertTrue(any("work_item_issue does not match" in error for error in errors))

    def test_missing_contract_or_acceptance_fails(self):
        package = valid_package()
        package["acceptance"]["contracts"] = ["config/contracts/absent-policy.yaml"]
        package["acceptance"]["tests"] = []
        errors = work_package.validate_work_package(package, root=ROOT)
        self.assertTrue(any("does not exist" in error for error in errors))
        self.assertTrue(any("acceptance.tests must be a nonempty list" in error for error in errors))

    def test_unknown_qualification_gate_fails(self):
        package = valid_package()
        package["acceptance"]["qualification_gates"] = ["fabricated-pass-gate"]
        errors = work_package.validate_work_package(package, root=ROOT)
        self.assertTrue(any("unknown gate" in error for error in errors))

    def test_required_capabilities_use_qualification_registry(self):
        package = valid_package()
        package["execution"]["required_capabilities"] = ["cpu-capacity"]
        package["execution"]["capability_parameters"] = {
            "cpu-capacity": {"minimum_count": 4}
        }
        result = work_package.work_package_status(package, root=ROOT)
        self.assertEqual("VALID", result["status"])
        self.assertEqual("NOT_EVALUATED", result["preflight_status"])

        package["execution"]["required_capabilities"] = ["unknown-probe"]
        errors = work_package.validate_work_package(package, root=ROOT)
        self.assertTrue(any("unknown capability unknown-probe" in error for error in errors))
        self.assertTrue(
            any("cpu-capacity is not a required capability" in error for error in errors)
        )

    def test_capability_parameters_reject_unknown_keys_and_unbounded_values(self):
        package = valid_package()
        package["execution"]["required_capabilities"] = ["cpu-capacity"]
        package["execution"]["capability_parameters"] = {
            "cpu-capacity": {"minimum_count": [4]}
        }
        errors = work_package.validate_work_package(package, root=ROOT)
        self.assertTrue(any("must match positive-integer" in error for error in errors))
        package["execution"]["capability_parameters"] = {
            "other": {"minimum_count": 4}
        }
        errors = work_package.validate_work_package(package, root=ROOT)
        self.assertTrue(any("is not a required capability" in error for error in errors))

    def test_required_resource_parameters_and_unknown_extra_are_rejected(self):
        package = valid_package()
        package["execution"]["required_capabilities"] = [
            "cpu-capacity", "memory-capacity", "disk-capacity"
        ]
        package["execution"]["capability_parameters"] = {
            "cpu-capacity": {"minimum_count": 4, "forged": True},
            "memory-capacity": {"minimum_mib": 8192},
            "disk-capacity": {"path": "/home/dev"},
        }
        errors = work_package.validate_work_package(package, root=ROOT)
        self.assertTrue(any("cpu-capacity.forged is not declared" in error for error in errors))
        self.assertTrue(any("disk-capacity.minimum_mib is required" in error for error in errors))
        package["execution"]["capability_parameters"] = {
            "cpu-capacity": {"minimum_count": 4},
            "memory-capacity": {"minimum_mib": 8192},
            "disk-capacity": {"path": "/home/dev", "minimum_mib": 4096},
        }
        self.assertEqual([], work_package.validate_work_package(package, root=ROOT))

    def test_additional_capability_types_are_validated(self):
        package = valid_package()
        package["execution"]["required_capabilities"] = [
            "packer-runtime", "ssh-identity", "network", "toolchain-pinned",
            "artifact-available", "windows-admin", "virtualbox-backend",
        ]
        digest = "sha256:" + "a" * 64
        parameters = {
            "packer-runtime": {"version": "1.14.2"},
            "ssh-identity": {"path": "/home/dev/.ssh/id_ed25519"},
            "network": {"host": "127.0.0.1", "port": 443},
            "toolchain-pinned": {"sha256": digest},
            "artifact-available": {
                "path": ".context/cache/rocky.box", "sha256": digest,
            },
            "virtualbox-backend": {
                "evidence_path": ".context/evidence/backend.json",
                "sha256": digest,
                "backend": "NATIVE_VTX",
            },
        }
        package["execution"]["capability_parameters"] = parameters
        self.assertEqual([], work_package.validate_work_package(package, root=ROOT))
        invalid = [
            ("packer-runtime", "version", "latest", "pinned-version"),
            ("ssh-identity", "path", "", "nonempty-string"),
            ("network", "port", 65536, "tcp-port"),
            ("toolchain-pinned", "sha256", "unverified", "sha256-digest"),
            ("artifact-available", "path", "../escape", "repository-relative-path"),
            ("virtualbox-backend", "backend", "UNKNOWN", "virtualbox-backend"),
        ]
        for capability, name, value, kind in invalid:
            with self.subTest(capability=capability, parameter=name):
                changed = copy.deepcopy(package)
                changed["execution"]["capability_parameters"][capability][name] = value
                errors = work_package.validate_work_package(changed, root=ROOT)
                self.assertTrue(
                    any(kind in error or "unsafe path" in error for error in errors),
                    errors,
                )

    def test_runtime_requires_named_evidence_without_claiming_it_passed(self):
        package = valid_package()
        package["execution"]["runtime_required"] = True
        errors = work_package.validate_work_package(package, root=ROOT)
        self.assertTrue(any("runtime_evidence required" in error for error in errors))
        package["acceptance"]["runtime_evidence"] = [
            ".context/evidence/m25-runtime.json"
        ]
        result = work_package.work_package_status(package, root=ROOT)
        self.assertEqual("VALID", result["status"])
        self.assertEqual("NOT_EVALUATED", result["runtime_status"])

    def test_review_preflight_and_post_merge_are_mandatory(self):
        package = valid_package()
        package["execution"]["preflight_required"] = False
        package["review"]["security"] = "optional"
        package["completion"]["post_merge_verification"] = False
        errors = work_package.validate_work_package(package, root=ROOT)
        self.assertTrue(any("preflight_required must be true" in error for error in errors))
        self.assertTrue(any("review.security must be required" in error for error in errors))
        self.assertTrue(any("post_merge_verification must be true" in error for error in errors))

    def test_duplicate_yaml_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "work-package.yaml"
            path.write_text("id: a\nid: b\n", encoding="utf-8")
            with self.assertRaisesRegex(work_package.WorkPackageError, "duplicate YAML key"):
                work_package._read_yaml(path)

    def test_policy_cannot_drop_required_work_item(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_file = root / work_package.POLICY_PATH
            policy_file.parent.mkdir(parents=True)
            content = (ROOT / work_package.POLICY_PATH).read_text(encoding="utf-8")
            policy_file.write_text(
                content.replace("    - work_item_issue\n", ""),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                work_package.WorkPackageError, "required_fields"
            ):
                work_package.load_policy(root)

    def test_dependencies_and_exit_criteria_are_bounded(self):
        package = copy.deepcopy(valid_package())
        package["dependencies"] = [package["id"]]
        package["exit_criteria"] = []
        errors = work_package.validate_work_package(package, root=ROOT)
        self.assertTrue(any("self-referential" in error for error in errors))
        self.assertTrue(any("exit_criteria must be a nonempty list" in error for error in errors))


if __name__ == "__main__":
    unittest.main()

