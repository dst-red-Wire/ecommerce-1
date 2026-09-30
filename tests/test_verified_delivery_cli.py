"""CLI boundaries for work packages, preflight and exact-SHA bundles."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

from tests.test_work_package import valid_package


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_delivery_cli", ROOT / "scripts/repoctl.py")
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class VerifiedDeliveryCliTests(unittest.TestCase):
    def setUp(self):
        context = ROOT / ".context"
        context.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=context)
        self.addCleanup(self.temporary.cleanup)
        self.package_path = Path(self.temporary.name) / "package.yaml"

    def write_package(self, package):
        self.package_path.write_text(yaml.safe_dump(package), encoding="utf-8")
        return str(self.package_path)

    def call_json(self, function, *args, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            return_code = function(*args, **kwargs)
        return return_code, json.loads(output.getvalue())

    def test_command_allowlist_registers_scoped_entrypoints(self):
        lock = yaml.safe_load((ROOT / "architecture.lock.yaml").read_text(encoding="utf-8"))
        local = lock["repository_governance"]["canonical_workspace"]["command_allowlist"]["local"]
        for command in ("work-package", "preflight", "evidence-bundle"):
            self.assertIn(command, local)

    def test_work_package_binds_issue_and_milestone(self):
        path = self.write_package(valid_package())
        code, result = self.call_json(REPOCTL.work_package_command, path, 170, "M2.5")
        self.assertEqual(0, code)
        self.assertEqual("VALID", result["status"])
        code, result = self.call_json(REPOCTL.work_package_command, path, 171, "M2.5")
        self.assertEqual(2, code)
        self.assertEqual("INVALID", result["status"])

    def test_invalid_package_blocks_preflight_probes(self):
        import delivery_preflight

        package = copy.deepcopy(valid_package())
        package["acceptance"]["tests"] = []
        path = self.write_package(package)
        with mock.patch.object(delivery_preflight, "run_preflight") as probe:
            code, result = self.call_json(
                REPOCTL.preflight_command, path, "a" * 40
            )
        self.assertEqual(1, code)
        self.assertEqual("FAIL", result["status"])
        self.assertFalse(result["mutation_performed"])
        probe.assert_not_called()

    def test_blocked_runtime_remains_distinct_from_failure(self):
        import delivery_preflight

        path = self.write_package(valid_package())

        def fake_git(*args):
            if args[:2] == ("rev-parse", "HEAD"):
                return "b" * 40
            if args[:2] == ("branch", "--show-current"):
                return "feat/verified-delivery-chain"
            if args[:2] == ("rev-parse", "origin/main"):
                return "a" * 40
            if args[:2] == ("status", "--porcelain"):
                return ""
            if args[0] == "diff":
                return "scripts/work_package.py" + chr(0)
            raise AssertionError(args)

        probe_result = {
            "status": "BLOCKED_RUNTIME",
            "source_sha": "b" * 40,
            "capacity": "BLOCKED_RUNTIME",
            "environment": "PASS",
            "required_capabilities": [],
            "mutation_performed": False,
        }
        with (
            mock.patch.object(REPOCTL, "git", side_effect=fake_git),
            mock.patch.object(REPOCTL, "run") as lineage,
            mock.patch.object(REPOCTL, "ruby_yaml", return_value={}),
            mock.patch.object(delivery_preflight, "run_preflight", return_value=probe_result),
            mock.patch.object(delivery_preflight, "write_preflight") as write,
        ):
            lineage.return_value.returncode = 0
            code, result = self.call_json(
                REPOCTL.preflight_command, path, "a" * 40
            )
        self.assertEqual(3, code)
        self.assertEqual("BLOCKED_RUNTIME", result["status"])
        self.assertEqual("PASS", result["environment"])
        self.assertFalse(result["mutation_performed"])
        write.assert_called_once()

    def test_dirty_head_blocks_bundle_before_creation(self):
        import evidence_bundle

        with (
            mock.patch.object(REPOCTL, "git", return_value=" M tracked.py"),
            mock.patch.object(evidence_bundle, "create_bundle") as create,
        ):
            code, result = self.call_json(
                REPOCTL.evidence_bundle_command,
                "a" * 40,
                artifacts=[],
                runtime_evidence=[],
                gate_evidence=[],
                review_evidence=[],
            )
        self.assertEqual(1, code)
        self.assertEqual("FAIL", result["status"])
        create.assert_not_called()

    def test_pr_body_marker_selects_one_scoped_work_item(self):
        import issue_lifecycle

        marker = REPOCTL._delivery_pr_work_item_marker(
            ["scripts/repoctl.py", "tests/test_verified_delivery_cli.py"]
        )
        parsed = issue_lifecycle.parse_pr_work_item_marker(marker)
        self.assertEqual(170, parsed["work_item_issue"])
        self.assertEqual("M7", parsed["milestone"])
        with self.assertRaisesRegex(RuntimeError, "exactly one scoped work package"):
            REPOCTL._delivery_pr_work_item_marker(["services/product/main.go"])

    def test_acceptance_failure_stops_bundle_before_runtime_and_creation(self):
        import delivery_preflight
        import evidence_bundle
        import issue_lifecycle
        import runtime_authority

        package = valid_package()
        package["acceptance"]["runtime_evidence"] = [".context/evidence/roadmap/arbitrary.json"]
        package["execution"]["runtime_required"] = True
        path = self.write_package(package)
        qualification = Path(self.temporary.name) / "qualification.json"
        qualification.write_text(json.dumps({"status": "PASS"}), encoding="utf-8")
        with (
            mock.patch.object(REPOCTL, "_delivery_package_input",
                              return_value=(package, {"status": "VALID"}, Path(path))),
            mock.patch.object(delivery_preflight, "verify_preflight",
                              return_value={"evidence_digest": "sha256:" + "1" * 64}),
            mock.patch.object(REPOCTL, "_valid_exact_evidence", return_value=qualification),
            mock.patch.object(issue_lifecycle, "read_qualified_head_snapshot",
                              return_value={}),
            mock.patch.object(issue_lifecycle, "derive_premerge_acceptance",
                              return_value={"status": "FAIL", "errors": ["required gate not PASS"]}),
            mock.patch.object(runtime_authority, "verify_runtime_proof") as runtime,
            mock.patch.object(evidence_bundle, "create_bundle") as create,
        ):
            with self.assertRaisesRegex(RuntimeError, "acceptance is not PASS"):
                REPOCTL._delivery_exact_bundle_gate(
                    "a" * 40, "b" * 40,
                    {"work_package": path, "work_item_issue": 170, "milestone": "M2.5"},
                )
        runtime.assert_not_called()
        create.assert_not_called()

    def test_runtime_self_declared_pass_cannot_enter_bundle(self):
        import delivery_preflight
        import evidence_bundle
        import issue_lifecycle
        import runtime_authority

        package = valid_package()
        package["acceptance"]["runtime_evidence"] = [".context/evidence/roadmap/arbitrary.json"]
        package["execution"]["runtime_required"] = True
        path = self.write_package(package)
        qualification = Path(self.temporary.name) / "qualification.json"
        qualification.write_text(json.dumps({"status": "PASS"}), encoding="utf-8")
        with (
            mock.patch.object(REPOCTL, "_delivery_package_input",
                              return_value=(package, {"status": "VALID"}, Path(path))),
            mock.patch.object(delivery_preflight, "verify_preflight",
                              return_value={"evidence_digest": "sha256:" + "1" * 64}),
            mock.patch.object(REPOCTL, "_valid_exact_evidence", return_value=qualification),
            mock.patch.object(issue_lifecycle, "read_qualified_head_snapshot",
                              return_value={}),
            mock.patch.object(issue_lifecycle, "derive_premerge_acceptance",
                              return_value={"status": "PASS", "errors": []}),
            mock.patch.object(REPOCTL, "qualification_workflow",
                              return_value={"performance_audit_runs": 0}),
            mock.patch.object(runtime_authority, "verify_runtime_proof",
                              return_value={"status": "FAIL",
                                            "reason": "no registered producer validator"}),
            mock.patch.object(evidence_bundle, "create_bundle") as create,
        ):
            with self.assertRaisesRegex(RuntimeError, "runtime producer validation failed"):
                REPOCTL._delivery_exact_bundle_gate(
                    "a" * 40, "b" * 40,
                    {"work_package": path, "work_item_issue": 170, "milestone": "M2.5"},
                )
        create.assert_not_called()

    def test_outdated_thread_does_not_block_requalified_head(self):
        payload = {
            "data": {"repository": {"pullRequest": {"reviewThreads": {
                "nodes": [
                    {"id": "old", "isResolved": False, "isOutdated": True},
                    {"id": "current", "isResolved": False, "isOutdated": False},
                    {"id": "resolved", "isResolved": True, "isOutdated": False},
                ],
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            }}}}
        }
        response = mock.Mock(
            returncode=0, stdout=json.dumps(payload), stderr=""
        )
        with mock.patch.object(REPOCTL, "run", return_value=response) as query:
            remaining = REPOCTL._github_unresolved_review_threads(
                "gh", "dst-red-Wire/ecommerce-1", 171
            )
        self.assertEqual(1, remaining)
        self.assertIn("isOutdated", query.call_args.args[0][4])

    def test_post_merge_policy_validation_rejects_missing_verification(self):
        policy = REPOCTL.repository_delivery_policy()
        policy = copy.deepcopy(policy)
        policy["post_merge"].pop("verification")
        with self.assertRaisesRegex(RuntimeError, "post-merge verification"):
            REPOCTL._validate_repository_delivery_policy(policy)


if __name__ == "__main__":
    unittest.main()
