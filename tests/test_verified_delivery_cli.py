"""CLI boundaries for work packages, preflight and exact-SHA bundles."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

from tests.test_work_package import valid_package


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "repoctl_delivery_cli", ROOT / "scripts/repoctl.py"
)
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class VerifiedDeliveryCliTests(unittest.TestCase):
    def setUp(self):
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("REPOCTL_TRUSTED_", "GIT_"))
        }
        patcher = mock.patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
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

    @contextlib.contextmanager
    def preflight_fixture(self, package=None):
        """Real Git/BASE producer; isolate the CLI's outer work-item boundary."""
        import evidence_bundle
        from tests.test_delivery_preflight import DeliveryPreflightTests

        fixture = DeliveryPreflightTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        package = copy.deepcopy(package or valid_package())
        relative = "config/work-packages/M2.5/cli-fixture.yaml"
        path = fixture.root / relative
        path.parent.mkdir(parents=True)
        content = yaml.safe_dump(package).encode()
        path.write_bytes(content)
        fixture.git("add", relative)
        fixture.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "CLI package fixture",
        )
        fixture.head = fixture.git("rev-parse", "HEAD")
        fixture.tree = fixture.git("rev-parse", "HEAD^{tree}")
        original_arguments = fixture.verification_arguments

        def arguments(capabilities=None, parameters=None):
            return {
                **original_arguments(capabilities, parameters),
                "expected_package_id": package["id"],
                "expected_package_digest": evidence_bundle.digest_bytes(content),
                "expected_issue": package["work_item_issue"],
                "expected_milestone": package["milestone"],
            }

        fixture.verification_arguments = arguments

        def run_in_fixture(command, *, check=True, capture=False, **kwargs):
            return subprocess.run(
                command,
                cwd=fixture.root,
                check=check,
                capture_output=capture,
                text=True,
                **kwargs,
            )

        with (
            mock.patch.object(REPOCTL, "ROOT", fixture.root),
            mock.patch.object(REPOCTL, "CONTEXT", fixture.root / ".context"),
            mock.patch.object(REPOCTL, "git", side_effect=fixture.git),
            mock.patch.object(REPOCTL, "run", side_effect=run_in_fixture),
            mock.patch.object(
                REPOCTL,
                "_delivery_package_input",
                return_value=(
                    package,
                    {"status": "VALID", "scope_status": "VALID"},
                    path,
                ),
            ),
            mock.patch.object(
                REPOCTL,
                "_require_trusted_pr_execution",
                return_value={
                    "base_sha": fixture.base,
                    "head_sha": fixture.head,
                    "pr_number": 171,
                },
            ),
        ):
            yield fixture, package, path

    @staticmethod
    def producer_arguments(fixture):
        arguments = fixture.verification_arguments()
        arguments["required_capabilities"] = arguments.pop("expected_capabilities")
        arguments["capability_parameters"] = arguments.pop(
            "expected_capability_parameters"
        )
        return arguments

    def fresh_work_item(self, fixture, package, package_path):
        import delivery_preflight

        result = fixture.bound_result()
        path = delivery_preflight.write_preflight(fixture.root, result)
        receipt = delivery_preflight.verify_preflight(
            fixture.root, **fixture.verification_arguments(), expected_result=result
        )
        return {
            "status": "PASS",
            "pr": 171,
            "work_package": str(package_path.relative_to(fixture.root)),
            "work_package_id": package["id"],
            "work_item_issue": package["work_item_issue"],
            "milestone": package["milestone"],
            "preflight": result,
            "preflight_verification": receipt,
            "preflight_path": str(path.relative_to(fixture.root)),
            "preflight_digest": receipt["evidence_digest"],
        }

    @contextlib.contextmanager
    def bundle_context(self, fixture, *, acceptance=None):
        import issue_lifecycle

        qualification = fixture.root / f".context/evidence/{fixture.head}.json"
        qualification.parent.mkdir(parents=True, exist_ok=True)
        qualification.write_text(
            json.dumps(
                {
                    "status": "PASS",
                    "exact_commit_evidence": True,
                    "base_sha": fixture.base,
                    "head_sha": fixture.head,
                    "head_tree_sha": fixture.tree,
                    "qualification_identity": "fixture-qualification",
                }
            ),
            encoding="utf-8",
        )
        with (
            mock.patch.object(
                REPOCTL, "_valid_exact_evidence", return_value=qualification
            ),
            mock.patch.object(
                REPOCTL,
                "qualification_workflow",
                return_value={"performance_audit_runs": 0},
            ),
            mock.patch.object(
                issue_lifecycle, "read_qualified_head_snapshot", return_value={}
            ),
            mock.patch.object(
                issue_lifecycle,
                "derive_premerge_acceptance",
                return_value=acceptance or {"status": "PASS", "errors": []},
            ),
        ):
            yield qualification

    @staticmethod
    def exact_reviews(fixture):
        return {
            kind: {
                "status": "PASS",
                "blocking_findings": 0,
                "head_sha": fixture.head,
                "comment_id": index,
            }
            for index, kind in enumerate(("code", "security"), start=10)
        }

    def test_command_allowlist_registers_scoped_entrypoints(self):
        lock = yaml.safe_load(
            (ROOT / "architecture.lock.yaml").read_text(encoding="utf-8")
        )
        local = lock["repository_governance"]["canonical_workspace"][
            "command_allowlist"
        ]["local"]
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
            code, result = self.call_json(REPOCTL.preflight_command, path, "a" * 40)
        self.assertEqual(1, code)
        self.assertEqual("FAIL", result["status"])
        self.assertFalse(result["mutation_performed"])
        probe.assert_not_called()

    def test_blocked_runtime_remains_distinct_from_failure(self):
        import delivery_preflight

        with self.preflight_fixture() as (fixture, package, path):
            result = delivery_preflight.run_preflight(
                fixture.root, **self.producer_arguments(fixture)
            )
            result.update(status="BLOCKED_RUNTIME", capacity="BLOCKED_RUNTIME")
            with (
                mock.patch.object(
                    delivery_preflight, "run_preflight", return_value=result
                ),
                mock.patch.object(
                    delivery_preflight,
                    "write_preflight",
                    wraps=delivery_preflight.write_preflight,
                ) as write,
                mock.patch.object(delivery_preflight, "verify_preflight") as verify,
            ):
                code, rendered = self.call_json(
                    REPOCTL.preflight_command, str(path), fixture.base
                )
            self.assertEqual(3, code)
            self.assertEqual("BLOCKED_RUNTIME", rendered["status"])
            self.assertEqual("PASS", rendered["environment"])
            self.assertFalse(rendered["mutation_performed"])
            self.assertEqual("diagnostic-only", rendered["authority"])
            write.assert_called_once_with(fixture.root, result)
            verify.assert_not_called()

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

    def test_pr_body_records_owner_contracts_tests_and_rollback(self):
        changed = "scripts/repoctl.py\ntests/test_verified_delivery_cli.py\n"

        def fake_git(*args):
            if args[:2] == ("diff", "--name-only"):
                return changed
            if args[:2] == ("diff", "--stat"):
                return "2 files changed"
            raise AssertionError(args)

        evidence = {
            "base_sha": "a" * 40,
            "gates": [{"gate": "governance", "status": "PASS"}],
        }
        with (
            mock.patch.object(REPOCTL, "git", side_effect=fake_git),
            mock.patch.object(REPOCTL, "CONTEXT", Path(self.temporary.name)),
            mock.patch.object(
                REPOCTL,
                "_github_repository_identity",
                return_value=("dst-red-Wire", "dst-red-Wire/ecommerce-1"),
            ),
            mock.patch.object(REPOCTL, "github_exact_ci_status", return_value="PASS"),
        ):
            body = REPOCTL._delivery_pr_body(
                "gh",
                "main",
                "feat/verified-delivery-chain",
                "b" * 40,
                "Verified delivery chain",
                evidence,
            ).read_text(encoding="utf-8")
        self.assertIn("Owner: @dst-red-Wire", body)
        self.assertIn("Work item: #170", body)
        self.assertIn("## Relevant contracts", body)
        self.assertIn("config/contracts/work-package-policy.yaml", body)
        self.assertIn("## Required tests", body)
        self.assertIn("tests/test_verified_delivery_cli.py", body)
        self.assertIn("## Rollback", body)
        self.assertIn("signed revert PR", body)

    def test_acceptance_failure_stops_bundle_before_runtime_and_creation(self):
        import evidence_bundle
        import runtime_authority

        package = valid_package()
        package["acceptance"]["runtime_evidence"] = [
            ".context/evidence/roadmap/arbitrary.json"
        ]
        package["execution"]["runtime_required"] = True
        with self.preflight_fixture(package) as (fixture, package, path):
            item = self.fresh_work_item(fixture, package, path)
            with (
                self.bundle_context(
                    fixture,
                    acceptance={"status": "FAIL", "errors": ["required gate not PASS"]},
                ),
                mock.patch.object(runtime_authority, "verify_runtime_proof") as runtime,
                mock.patch.object(evidence_bundle, "create_bundle") as create,
            ):
                with self.assertRaisesRegex(RuntimeError, "acceptance is not PASS"):
                    REPOCTL._delivery_exact_bundle_gate(
                        fixture.base, fixture.head, item
                    )
            runtime.assert_not_called()
            create.assert_not_called()

    def test_runtime_self_declared_pass_cannot_enter_bundle(self):
        import evidence_bundle
        import runtime_authority

        package = valid_package()
        package["acceptance"]["runtime_evidence"] = [
            ".context/evidence/roadmap/arbitrary.json"
        ]
        package["execution"]["runtime_required"] = True
        with self.preflight_fixture(package) as (fixture, package, path):
            item = self.fresh_work_item(fixture, package, path)
            with (
                self.bundle_context(fixture),
                mock.patch.object(
                    runtime_authority,
                    "verify_runtime_proof",
                    return_value={
                        "status": "FAIL",
                        "reason": "no registered producer validator",
                    },
                ) as runtime,
                mock.patch.object(evidence_bundle, "create_bundle") as create,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "runtime producer validation failed"
                ):
                    REPOCTL._delivery_exact_bundle_gate(
                        fixture.base, fixture.head, item
                    )
            runtime.assert_called_once()
            create.assert_not_called()

    def test_head_diagnostic_allows_publication_but_cannot_authorize_merge(self):
        import delivery_preflight

        with self.preflight_fixture() as (fixture, package, path):
            with mock.patch.object(
                delivery_preflight,
                "verify_preflight",
                wraps=delivery_preflight.verify_preflight,
            ) as verify:
                code, result = self.call_json(
                    REPOCTL.preflight_command, str(path), fixture.base
                )
            self.assertEqual(0, code, result)
            self.assertEqual("PASS", result["status"])
            self.assertEqual("diagnostic", result["execution_authority"])
            self.assertEqual("diagnostic-only", result["authority"])
            self.assertEqual({}, result["preflight_verification"])
            self.assertEqual("", result["preflight_digest"])
            verify.assert_not_called()
            with self.assertRaisesRegex(ValueError, "execution_authority"):
                delivery_preflight.verify_preflight(
                    fixture.root,
                    **fixture.verification_arguments(),
                    expected_result=result,
                )
            with self.bundle_context(fixture):
                code, bundle = self.call_json(
                    REPOCTL.evidence_bundle_command,
                    fixture.base,
                    artifacts=[],
                    runtime_evidence=[],
                    review_evidence=[],
                    gate_evidence=[result["preflight_path"]],
                )
            self.assertEqual(0, code, bundle)
            self.assertEqual("bundle-integrity-only", bundle["authority"])
            self.assertEqual("PASS", bundle["integrity_status"])
            work_item = {
                "status": "PASS",
                "pr": 171,
                "work_package": str(path),
                "work_item_issue": package["work_item_issue"],
                "milestone": package["milestone"],
                "preflight": result,
            }
            with self.assertRaisesRegex(RuntimeError, "fresh BASE preflight"):
                REPOCTL._delivery_exact_bundle_gate(
                    fixture.base, fixture.head, work_item
                )

    def test_cli_trusted_receipt_binds_original_producer_result_and_serialized_bytes(
        self,
    ):
        import delivery_preflight
        import evidence_bundle

        with self.preflight_fixture() as (fixture, package, path):
            produced = fixture.bound_result()
            original = copy.deepcopy(produced)
            with (
                mock.patch.object(
                    delivery_preflight, "run_preflight", return_value=produced
                ) as run,
                mock.patch.object(
                    delivery_preflight,
                    "verify_preflight",
                    wraps=delivery_preflight.verify_preflight,
                ) as verify,
            ):
                code, rendered = self.call_json(
                    REPOCTL.preflight_command, str(path), fixture.base
                )
            self.assertEqual(0, code, rendered)
            self.assertEqual(original, produced)
            self.assertIs(produced, verify.call_args.kwargs["expected_result"])
            expected = fixture.verification_arguments()
            for key, value in expected.items():
                self.assertEqual(value, verify.call_args.kwargs[key], key)
            for key in (
                "expected_head_tree_sha",
                "expected_package_id",
                "expected_package_digest",
                "expected_issue",
                "expected_milestone",
            ):
                self.assertEqual(expected[key], run.call_args.kwargs[key], key)
            receipt = rendered["preflight_verification"]
            self.assertTrue(receipt["fresh_execution_verified"])
            self.assertEqual("current-preflight-verification", rendered["authority"])
            content = (fixture.root / rendered["preflight_path"]).read_bytes()
            self.assertEqual(
                evidence_bundle.digest_bytes(content), rendered["preflight_digest"]
            )
            self.assertNotEqual(
                json.loads(content)["evidence_digest"], rendered["preflight_digest"]
            )

    def test_fresh_bundle_keeps_preflight_and_both_external_review_snapshots(self):
        import delivery_preflight

        with self.preflight_fixture() as (fixture, package, path):
            item = self.fresh_work_item(fixture, package, path)
            with (
                self.bundle_context(fixture),
                mock.patch.object(
                    delivery_preflight,
                    "verify_preflight",
                    wraps=delivery_preflight.verify_preflight,
                ) as verify,
            ):
                bundle = REPOCTL._delivery_exact_bundle_gate(
                    fixture.base,
                    fixture.head,
                    item,
                    reviews=self.exact_reviews(fixture),
                )
            self.assertIs(item["preflight"], verify.call_args.kwargs["expected_result"])
            self.assertEqual("bundle-integrity-only", bundle["authority"])
            self.assertTrue(
                bundle["preflight_verification"]["fresh_execution_verified"]
            )
            manifest = json.loads((fixture.root / bundle["manifest"]).read_bytes())
            gates = {
                entry["path"]: entry["sha256"] for entry in manifest["gate_evidence"]
            }
            self.assertEqual(item["preflight_digest"], gates[item["preflight_path"]])
            self.assertEqual(
                item["preflight_digest"], bundle["preflight_evidence_digest"]
            )
            self.assertIn(f".context/evidence/{fixture.head}.json", gates)
            self.assertEqual(2, len(manifest["review_evidence"]))
            self.assertEqual([], manifest["runtime_evidence"])
            self.assertFalse(manifest["verdict_authority"])

    def test_bundle_rejects_unbound_result_or_receipt_before_creation(self):
        import evidence_bundle

        with self.preflight_fixture() as (fixture, package, path):
            item = self.fresh_work_item(fixture, package, path)
            for change in ("result", "producer", "receipt", "missing"):
                with self.subTest(change=change):
                    modified = copy.deepcopy(item)
                    if change == "result":
                        modified["preflight"]["generated_at_epoch"] -= 1
                    elif change == "producer":
                        modified["preflight"]["producer"]["sha256"] = (
                            "sha256:" + "0" * 64
                        )
                    elif change == "receipt":
                        modified["preflight_digest"] = "sha256:" + "0" * 64
                        modified["preflight_verification"]["evidence_digest"] = (
                            modified["preflight_digest"]
                        )
                    else:
                        modified.pop("preflight")
                    with mock.patch.object(evidence_bundle, "create_bundle") as create:
                        with self.assertRaisesRegex(
                            (RuntimeError, ValueError), "preflight|producer"
                        ):
                            REPOCTL._delivery_exact_bundle_gate(
                                fixture.base, fixture.head, modified
                            )
                    create.assert_not_called()

    def test_dry_run_checks_existing_bundle_without_claiming_fresh_execution(self):
        import delivery_preflight
        import evidence_bundle

        with self.preflight_fixture() as (fixture, package, path):
            item = self.fresh_work_item(fixture, package, path)
            reviews = self.exact_reviews(fixture)
            with self.bundle_context(fixture):
                REPOCTL._delivery_exact_bundle_gate(
                    fixture.base, fixture.head, item, reviews=reviews
                )
                diagnostic = {
                    key: value
                    for key, value in item.items()
                    if key
                    not in {
                        "preflight_verification",
                        "preflight_path",
                        "preflight_digest",
                    }
                }
                diagnostic["preflight"] = {**item["preflight"], "generated_at_epoch": 1}
                evidence = fixture.root / ".context/evidence"
                before = {
                    str(p.relative_to(evidence)): p.read_bytes()
                    for p in evidence.rglob("*")
                    if p.is_file()
                }
                with (
                    mock.patch.object(evidence_bundle, "create_bundle") as create,
                    mock.patch.object(
                        delivery_preflight,
                        "verify_preflight",
                        wraps=delivery_preflight.verify_preflight,
                    ) as verify,
                ):
                    result = REPOCTL._delivery_exact_bundle_gate(
                        fixture.base,
                        fixture.head,
                        diagnostic,
                        reviews=reviews,
                        create=False,
                    )
                after = {
                    str(p.relative_to(evidence)): p.read_bytes()
                    for p in evidence.rglob("*")
                    if p.is_file()
                }
            create.assert_not_called()
            self.assertIsNone(verify.call_args.kwargs["expected_result"])
            self.assertFalse(
                result["preflight_verification"]["fresh_execution_verified"]
            )
            self.assertEqual("bundle-integrity-only", result["authority"])
            self.assertEqual(before, after)

    def test_rebuilt_bundle_cannot_substitute_preflight_bytes_after_receipt(self):
        import delivery_preflight
        import evidence_bundle

        with self.preflight_fixture() as (fixture, package, path):
            item = self.fresh_work_item(fixture, package, path)
            original_create = evidence_bundle.create_bundle
            substituted = []

            def replace_then_bundle(*args, **kwargs):
                replacement = {
                    **item["preflight"],
                    "generated_at_epoch": item["preflight"]["generated_at_epoch"] - 1,
                }
                delivery_preflight.write_preflight(fixture.root, replacement)
                result = original_create(*args, **kwargs)
                self.assertEqual(
                    "PASS",
                    evidence_bundle.verify_bundle(fixture.root, fixture.head)["status"],
                )
                substituted.append(True)
                return result

            with (
                self.bundle_context(fixture),
                mock.patch.object(
                    evidence_bundle, "create_bundle", side_effect=replace_then_bundle
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "bundle preflight differs from captured verified bytes",
                ):
                    REPOCTL._delivery_exact_bundle_gate(
                        fixture.base, fixture.head, item
                    )
            self.assertEqual([True], substituted)

    def test_outdated_thread_does_not_block_requalified_head(self):
        payload = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [
                                {"id": "old", "isResolved": False, "isOutdated": True},
                                {
                                    "id": "current",
                                    "isResolved": False,
                                    "isOutdated": False,
                                },
                                {
                                    "id": "resolved",
                                    "isResolved": True,
                                    "isOutdated": False,
                                },
                            ],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            }
        }
        response = mock.Mock(returncode=0, stdout=json.dumps(payload), stderr="")
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
