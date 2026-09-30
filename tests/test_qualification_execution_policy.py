from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import types
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_execution_policy_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

PERF_SPEC = importlib.util.spec_from_file_location(
    "qualification_performance_campaign_test",
    ROOT / "scripts/qualification_performance_campaign.py",
)
assert PERF_SPEC and PERF_SPEC.loader
PERF_MOD = importlib.util.module_from_spec(PERF_SPEC)
PERF_SPEC.loader.exec_module(PERF_MOD)


def _transfer_fixture(manifest: str) -> dict:
    return {
        "mode": "delta", "source_digest": manifest, "prior_target_digest": None,
        "manifest_digest": manifest, "final_digest": manifest,
        "target_valid_before": False, "copy_changed": True,
        "started_at": "2026-09-29T20:00:00+00:00",
        "finished_at": "2026-09-29T20:00:01+00:00",
    }


class QualificationExecutionPolicyTests(unittest.TestCase):
    def setUp(self):
        box = {
            "vm_box_name": "rocky-10.2-rke2-virtualbox",
            "vm_box_url": "file:///C:/ecommerce-lab/artifacts/verified/rocky-10.2-rke2-virtualbox.box",
            "vm_box_sha256": "a" * 64,
            "vm_vagrant_version": "2.4.9",
        }
        patcher = mock.patch.object(MOD, "_rke2_verified_box", return_value=box)
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_unit_subprocess_does_not_inherit_trusted_delivery_identity(self):
        env = dict(os.environ, REPOCTL_TRUSTED_CONTROLLER="/invalid/controller.py")
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "tests.test_commit_provenance.CommitProvenanceTests.test_placeholder_author_email_is_rejected",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_workstation_aggregate_tag_is_blocked_outside_wsl_before_mutation(self):
        detected = types.SimpleNamespace(name="linux_container")
        with (
            mock.patch.object(MOD, "toolchain_closure", return_value=0),
            mock.patch.object(
                MOD,
                "qualification_execution_policy",
                return_value={
                    "execution_context": {
                        "wsl2_only_reconcile_tags": ["docker", "workstation"]
                    }
                },
            ),
            mock.patch.object(
                MOD,
                "_runtime_api",
                return_value=types.SimpleNamespace(
                    detect_execution_environment=lambda: detected
                ),
            ),
            mock.patch.object(
                MOD, "require", side_effect=AssertionError("Ansible must not start")
            ),
            redirect_stderr(io.StringIO()) as output,
        ):
            self.assertEqual(2, MOD.reconcile("workstation,bootstrap"))
        self.assertIn("BLOCKED_RUNTIME", output.getvalue())
        self.assertIn("no mutation performed", output.getvalue())

    def test_static_profile_excludes_runtime_without_constructing_executor(self):
        requests = [types.SimpleNamespace(name="testcontainers")]
        api = types.SimpleNamespace(
            detect_execution_environment=lambda **_kwargs: types.SimpleNamespace(name="linux_container"),
            RuntimeExecutor=mock.Mock(side_effect=AssertionError("runtime executor must not run")),
        )
        contract = {
            "runtime_orchestration": {},
            "qualification_profiles": {
                "static": {
                    "allowed_environments": ["linux_container"],
                    "runtime_capabilities": {"testcontainers": "out_of_scope"},
                }
            },
        }
        decisions = []
        callback = mock.Mock(return_value=0)
        with (
            mock.patch.object(MOD, "_runtime_api", return_value=api),
            mock.patch.object(MOD, "_runtime_requests", return_value=requests),
            mock.patch.object(MOD, "_runtime_source", return_value=("worktree", "a" * 40)),
            mock.patch.object(MOD, "qualification_execution_policy", return_value=contract),
        ):
            for _ in range(2):
                self.assertEqual(0, MOD._execute_with_runtime(
                    [{"gate": "service:product"}], callback, workflow="verify-change",
                    head="WORKTREE", environment={}, execution_profile="static",
                    scope_decisions=decisions,
                ))
        self.assertEqual(2, callback.call_count)
        self.assertTrue(all(item["status"] == "OUT_OF_SCOPE" and item["executed"] is False for item in decisions))

    def test_required_runtime_in_container_is_blocked_without_executor(self):
        requests = [types.SimpleNamespace(name="docker-runtime")]
        api = types.SimpleNamespace(
            detect_execution_environment=lambda **_kwargs: types.SimpleNamespace(name="linux_container"),
            RuntimeExecutor=mock.Mock(side_effect=AssertionError("mutation must not run")),
        )
        contract = {"runtime_orchestration": {}, "qualification_profiles": {"full": {
            "allowed_environments": ["wsl2_developer"],
            "runtime_capabilities": {"docker-runtime": "required_when_affected"},
        }}}
        records = []
        with (
            mock.patch.object(MOD, "_runtime_api", return_value=api),
            mock.patch.object(MOD, "_runtime_requests", return_value=requests),
            mock.patch.object(MOD, "_runtime_source", return_value=("worktree", "a" * 40)),
            mock.patch.object(MOD, "qualification_execution_policy", return_value=contract),
        ):
            self.assertEqual(2, MOD._execute_with_runtime(
                [{"gate": "service:product"}], mock.Mock(), workflow="verify-change",
                head="WORKTREE", environment={}, records=records, execution_profile="full",
            ))
        self.assertEqual("BLOCKED_RUNTIME", records[0]["runtime_status"])
        self.assertIn("no mutation performed", records[0]["reason"])

    def test_tekton_container_executes_read_only_runtime_capability(self):
        runtime = MOD._runtime_api()
        policy = MOD.qualification_execution_policy()
        callback = mock.Mock(return_value=0)
        requests = [runtime.CapabilityRequest("ansible-runtime")]

        class FakeExecutor:
            def __init__(self, *_args, **_kwargs):
                pass

            def execute(self, _requests, execute, **kwargs):
                environment = dict(kwargs["base_environment"])
                environment["ECOMMERCE_RUNTIME_ORCHESTRATED"] = "1"
                return types.SimpleNamespace(
                    status="PASS", exit_code=execute(environment), evidence_path=None
                )

        api = types.SimpleNamespace(
            detect_execution_environment=lambda **_kwargs: types.SimpleNamespace(name="linux_container"),
            RuntimePlanner=runtime.RuntimePlanner,
            RuntimeExecutor=FakeExecutor,
            BuiltinCapabilityDriver=lambda _environment: object(),
        )
        with (
            mock.patch.object(MOD, "_runtime_api", return_value=api),
            mock.patch.object(MOD, "_runtime_requests", return_value=requests),
            mock.patch.object(MOD, "_runtime_source", return_value=("exact-sha", "a" * 40)),
            mock.patch.object(MOD, "qualification_execution_policy", return_value=policy),
        ):
            self.assertEqual(0, MOD._execute_with_runtime(
                [{"gate": "platform:ansible"}], callback, workflow="gate:platform:ansible",
                head="a" * 40, environment={}, execution_profile="tekton", authoritative=True,
            ))
        callback.assert_called_once()
        self.assertEqual("tekton", callback.call_args.args[0]["ECOMMERCE_EXECUTION_PROFILE"])

    def test_tekton_container_blocks_mutable_capability_closure(self):
        runtime = MOD._runtime_api()
        policy = MOD.qualification_execution_policy()
        requests = [runtime.CapabilityRequest("docker-runtime")]
        api = types.SimpleNamespace(
            detect_execution_environment=lambda **_kwargs: types.SimpleNamespace(name="linux_container"),
            RuntimePlanner=runtime.RuntimePlanner,
            RuntimeExecutor=mock.Mock(side_effect=AssertionError("host mutation must not start")),
        )
        records = []
        callback = mock.Mock()
        with (
            mock.patch.object(MOD, "_runtime_api", return_value=api),
            mock.patch.object(MOD, "_runtime_requests", return_value=requests),
            mock.patch.object(MOD, "_runtime_source", return_value=("exact-sha", "a" * 40)),
            mock.patch.object(MOD, "qualification_execution_policy", return_value=policy),
        ):
            self.assertEqual(2, MOD._execute_with_runtime(
                [{"gate": "service:product"}], callback, workflow="gate:service:product",
                head="a" * 40, environment={}, execution_profile="tekton", records=records,
            ))
        callback.assert_not_called()
        self.assertEqual("BLOCKED_RUNTIME", records[0]["runtime_status"])
        self.assertIn("docker-runtime", records[0]["reason"])

    def test_tekton_gate_entrypoints_select_container_profile(self):
        for action, selector in (("ci-global", "--gate"), ("ci-component", "--component")):
            with self.subTest(action=action):
                with (
                    mock.patch.dict(os.environ, {"ECOMMERCE_RUNTIME_ORCHESTRATED": ""}),
                    mock.patch.object(
                        sys, "argv",
                        ["repoctl.py", action, selector, "platform:ansible", "--base", "origin/main",
                         "--head", "a" * 40, "--record-dir", ".context/tekton/test"],
                    ),
                    mock.patch(
                        "canonical_workspace.check",
                        return_value={
                            "status": "PASS",
                            "execution_scope": "ci",
                            "publication_allowed": False,
                        },
                    ),
                    mock.patch("native_workspace.workspace_error", return_value=None),
                    mock.patch.object(MOD, "_execute_direct_gate_with_runtime", return_value=0) as execute,
                ):
                    self.assertEqual(0, MOD.main())
                    self.assertEqual("tekton", execute.call_args.kwargs["execution_profile"])

    def test_static_only_full_plan_runs_outside_wsl_without_runtime_executor(self):
        callback = mock.Mock(return_value=0)
        api = types.SimpleNamespace(
            detect_execution_environment=lambda **_kwargs: types.SimpleNamespace(
                name="linux_container"
            ),
            RuntimeExecutor=mock.Mock(
                side_effect=AssertionError("runtime executor must not run")
            ),
        )
        contract = {
            "runtime_orchestration": {},
            "qualification_profiles": {
                "full": {
                    "allowed_environments": ["wsl2_developer"],
                    "runtime_capabilities": {},
                }
            },
        }
        with (
            mock.patch.object(MOD, "_runtime_api", return_value=api),
            mock.patch.object(MOD, "_runtime_requests", return_value=[]),
            mock.patch.object(MOD, "_runtime_source", return_value=("worktree", "a" * 40)),
            mock.patch.object(MOD, "qualification_execution_policy", return_value=contract),
        ):
            self.assertEqual(
                0,
                MOD._execute_with_runtime(
                    [{"gate": "frontend:storefront"}],
                    callback,
                    workflow="verify-change",
                    head="WORKTREE",
                    environment={},
                    execution_profile="full",
                ),
            )
        callback.assert_called_once()
        self.assertEqual(
            "1", callback.call_args.args[0]["ECOMMERCE_RUNTIME_ORCHESTRATED"]
        )

    def test_workspace_check_requires_native_filesystem_before_success(self):
        with (
            mock.patch.object(sys, "argv", ["repoctl.py", "workspace-check"]),
            mock.patch(
                "canonical_workspace.check",
                return_value={
                    "status": "PASS",
                    "execution_scope": "local",
                    "publication_allowed": True,
                },
            ),
            mock.patch(
                "native_workspace.workspace_error",
                return_value="WSL2 checkout must use a native Linux filesystem",
            ),
        ):
            self.assertNotEqual(0, MOD.main())

    def test_ci_scope_cannot_run_publication_commands(self):
        with (
            mock.patch.object(
                sys, "argv", ["repoctl.py", "deliver", "--title", "proof"]
            ),
            mock.patch(
                "canonical_workspace.check",
                return_value={
                    "status": "PASS",
                    "execution_scope": "ci",
                    "publication_allowed": False,
                },
            ),
            mock.patch.object(MOD, "deliver") as deliver,
        ):
            self.assertEqual(1, MOD.main())
        deliver.assert_not_called()

    def test_ci_scope_rejects_frontend_generation_before_dispatch(self):
        with (
            mock.patch.object(sys, "argv", ["repoctl.py", "frontend", "generate", "all"]),
            mock.patch(
                "canonical_workspace.check",
                return_value={"status": "PASS", "execution_scope": "ci"},
            ),
            mock.patch.object(MOD, "frontend") as frontend,
        ):
            self.assertEqual(1, MOD.main())
        frontend.assert_not_called()

    def test_runtime_restore_failures_always_add_a_failed_evidence_record(self):
        class FakeExecutor:
            def __init__(self, *_args, **_kwargs):
                pass

            def execute(self, *_args, **_kwargs):
                return types.SimpleNamespace(
                    status=runtime_status,
                    exit_code=1,
                    evidence_path=None,
                )

        for runtime_status in ("FAIL_RESTORE", "FAIL_VERIFY_RESTORE"):
            with self.subTest(runtime_status=runtime_status):
                records = [{"gate": "governance", "status": "PASS", "exit_code": 0}]
                api = types.SimpleNamespace(
                    RuntimeExecutor=FakeExecutor,
                    BuiltinCapabilityDriver=lambda _environment: object(),
                    detect_execution_environment=lambda **_kwargs: types.SimpleNamespace(name="unknown"),
                )
                with (
                    mock.patch.object(MOD, "_runtime_api", return_value=api),
                    mock.patch.object(
                        MOD,
                        "_runtime_requests",
                        return_value=[types.SimpleNamespace(name="docker-runtime")],
                    ),
                    mock.patch.object(
                        MOD, "_runtime_source", return_value=("worktree", "a" * 40)
                    ),
                    mock.patch.object(
                        MOD,
                        "qualification_execution_policy",
                        return_value={
                            "runtime_orchestration": {},
                            "qualification_profiles": {
                                "full": {
                                    "allowed_environments": ["unknown"],
                                    "runtime_capabilities": {},
                                }
                            },
                        },
                    ),
                ):
                    rc = MOD._execute_with_runtime(
                        [{"gate": "governance"}],
                        lambda _environment: 0,
                        workflow="verify-change",
                        head="WORKTREE",
                        environment={},
                        records=records,
                    )
                self.assertEqual(1, rc)
                self.assertEqual("PASS", records[0]["status"])
                self.assertEqual("FAIL", records[-1]["status"])
                self.assertEqual(runtime_status, records[-1]["runtime_status"])

    def test_failed_runtime_evidence_cannot_be_reused_as_exact_pass(self):
        head = "a" * 40
        base = "b" * 40
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory)
            evidence_dir = context / "evidence"
            evidence_dir.mkdir()
            evidence = evidence_dir / f"{head}.json"
            evidence.write_text(
                json.dumps(
                    {
                        "schema_version": 5,
                        "status": "FAIL",
                        "exact_commit_evidence": True,
                        "head_sha": head,
                        "base_sha": base,
                    }
                ),
                encoding="utf-8",
            )

            def fake_git(*args, check=True):
                if args[:2] == ("rev-parse", "HEAD"):
                    return head + "\n"
                if args[:2] == ("rev-parse", head):
                    return head + "\n"
                if args[0] == "status":
                    return ""
                raise AssertionError(args)

            with (
                mock.patch.object(MOD, "CONTEXT", context),
                mock.patch.object(MOD, "git", side_effect=fake_git),
                mock.patch.object(MOD, "_supported_evidence_schema", return_value=True),
            ):
                self.assertIsNone(MOD._valid_exact_evidence("origin/main", head))

    def test_final_evidence_is_not_pass_when_gates_pass_but_restore_fails(self):
        head = "a" * 40
        base = "b" * 40
        records = [
            {"gate": "governance", "status": "PASS", "exit_code": 0},
            {
                "gate": "runtime-orchestration",
                "status": "FAIL",
                "runtime_status": "FAIL_RESTORE",
                "exit_code": 1,
            },
        ]

        def fake_git(*args, check=True):
            if args == ("rev-parse", "origin/main"):
                return base + "\n"
            if args == ("rev-parse", "HEAD"):
                return head + "\n"
            if args[0] == "status":
                return " M scripts/repoctl.py\n"
            raise AssertionError(args)

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(MOD, "ROOT", Path(directory)),
            mock.patch.object(MOD, "CONTEXT", Path(directory)),
            mock.patch.object(MOD, "git", side_effect=fake_git),
            mock.patch.object(MOD, "worktree_tree_sha", return_value="c" * 40),
            mock.patch.object(MOD, "qualification_identity", return_value="identity"),
        ):
            evidence = MOD.write_evidence(
                "origin/main", "WORKTREE", [], [], records
            )
            payload = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual("FAIL", payload["status"])

    def test_ci_component_none_skips_before_runtime_policy_resolution(self):
        head = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            argv = [
                "repoctl.py",
                "ci-component",
                "--component",
                "none",
                "--base",
                "origin/main",
                "--head",
                head,
                "--record-dir",
                directory,
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch(
                    "canonical_workspace.check",
                    return_value={
                        "status": "PASS",
                        "execution_scope": "ci",
                        "publication_allowed": False,
                    },
                ),
                mock.patch.object(
                    MOD, "_require_clean_exact_checkout", return_value=(head, head)
                ),
                mock.patch.object(MOD, "_execute_direct_gate_with_runtime") as runtime,
            ):
                self.assertEqual(0, MOD.main())
            runtime.assert_not_called()
            record = json.loads(
                (Path(directory) / "component-none.json").read_text(encoding="utf-8")
            )
            self.assertEqual("SKIP", record["records"][0]["status"])

    def test_empty_opentofu_area_skips_before_runtime_requirement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "platform" / "terraform").mkdir(parents=True)
            with (
                mock.patch.object(sys, "argv", ["repoctl.py", "opentofu"]),
                mock.patch(
                    "canonical_workspace.check",
                    return_value={
                        "status": "PASS",
                        "execution_scope": "local",
                        "publication_allowed": True,
                    },
                ),
                mock.patch.object(MOD, "ROOT", root),
                mock.patch("native_workspace.workspace_error", return_value=None),
                mock.patch.object(MOD, "_execute_direct_gate_with_runtime") as runtime,
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(0, MOD.main())
            runtime.assert_not_called()
            self.assertIn("SKIP OpenTofu: no compatible .tf sources found", output.getvalue())

    def test_qualification_identity_handles_stopped_docker_deterministically(self):
        unavailable = subprocess.CompletedProcess(
            ["docker", "info"], 1, "", "daemon stopped\n"
        )
        probes = {(('docker', 'info'), True)}
        with (
            mock.patch.object(MOD, "_qualification_toolchain", return_value=({}, probes)),
            mock.patch.object(MOD.shutil, "which", return_value=sys.executable),
            mock.patch.object(MOD, "run", return_value=unavailable),
        ):
            first = MOD.qualification_identity()
            second = MOD.qualification_identity()
        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{64}$")

    def test_policy_is_registered_under_architecture_root(self):
        lock = MOD.ruby_yaml("architecture.lock.yaml")
        self.assertEqual(
            "config/contracts/qualification-execution-policy.yaml",
            lock["machine_contracts"]["qualification_execution_policy"],
        )
        policy = MOD.qualification_execution_policy()
        self.assertEqual("QualificationExecutionPolicy", policy["kind"])
        self.assertEqual("architecture.lock.yaml", policy["architecture_authority"])
        self.assertEqual("entire-repository", policy["scope"])
        self.assertEqual("enforced", policy["status"])
        self.assertGreaterEqual(policy["execution"]["local_max_workers"], 1)
        self.assertLessEqual(policy["execution"]["local_max_workers"], 16)
        self.assertEqual(
            "ECOMMERCE_QUALIFICATION_MAX_WORKERS",
            policy["execution"]["ci_max_workers_env"],
        )
        self.assertIs(True, policy["execution"]["ci_max_workers_required"])
        self.assertEqual(
            ["docker", "workstation"],
            policy["execution_context"]["wsl2_only_reconcile_tags"],
        )
        self.assertEqual(
            ["linux_container"],
            policy["qualification_profiles"]["tekton"]["allowed_environments"],
        )
        self.assertEqual(
            {"full"},
            {
                name
                for name, profile in policy["qualification_profiles"].items()
                if profile["merge_authoritative"]
            },
        )

    def test_qualification_workflows_are_centralized(self):
        policy = MOD.qualification_execution_policy()
        lifecycle = policy["qualification_lifecycle"]
        defaults = lifecycle["workflow_defaults"]
        proof = policy["workflows"]["qualification_proof"]
        rke2 = policy["workflows"]["rke2_local_virtualbox"]
        tekton = policy["workflows"]["tekton_proof"]
        campaign = policy["workflows"]["performance_campaign"]

        self.assertEqual("every-qualification-workflow", lifecycle["applies_to"])
        self.assertEqual(
            "config/contracts/qualification-execution-policy.yaml",
            lifecycle["single_authority"],
        )
        self.assertEqual("forbidden", lifecycle["per_workflow_policy_duplication"])
        self.assertEqual("workflows", lifecycle["registration"]["registry"])
        self.assertEqual(
            "forbidden",
            lifecycle["registration"]["unregistered_authoritative_qualification"],
        )
        self.assertEqual("forbidden", lifecycle["registration"]["local_lifecycle_override"])
        completed_registration = lifecycle["completed_proof_registration"]
        self.assertIs(False, completed_registration["registration_is_execution"])
        self.assertEqual(
            "forbidden",
            completed_registration["execute_entrypoint_on_registration"],
        )
        self.assertEqual(
            "qualified-source-sha-and-invalidation-inputs",
            completed_registration["proof_binding"],
        )
        self.assertIs(
            False,
            completed_registration["metadata_only_registry_change_invalidates_runtime_proof"],
        )
        self.assertIs(True, completed_registration["reuse_until_invalidation_input_changes"])
        self.assertIs(True, defaults["stop_when_exit_criteria_pass"])
        self.assertEqual("forbidden", defaults["post_pass_scope_expansion"])
        self.assertEqual("follow-up-work-item", defaults["non_blocking_findings"])
        self.assertEqual("return-to-development", defaults["blocking_findings"])
        authoritative = lifecycle["authoritative_completion"]
        self.assertEqual("merge_authoritative=true", authoritative["applies_when"])
        self.assertEqual("reuse-valid-evidence", authoritative["same_sha_pass_replay"])
        self.assertEqual("requires-explicit-blocking-reason", authoritative["same_sha_failed_replay"])
        self.assertEqual(1, authoritative["final_candidate_runs"])
        self.assertIs(True, lifecycle["waits"]["every_wait_must_be_bounded"])
        self.assertEqual("forbidden", lifecycle["waits"]["indefinite_wait"])
        self.assertIs(True, lifecycle["reruns"]["non_blocking_improvement_creates_follow_up"])
        self.assertEqual(
            "forbidden",
            lifecycle["duplication"]["merge_authoritative_duplicate_full_gate_run_same_sha"],
        )
        self.assertEqual(
            "allowed-when-centrally-declared",
            lifecycle["duplication"]["non_merge_authoritative_measurement_repetitions"],
        )

        for name, workflow in policy["workflows"].items():
            with self.subTest(workflow=name):
                self.assertFalse(set(defaults).intersection(workflow))
                self.assertTrue(workflow["owner"])
                self.assertTrue(workflow["purpose"])
                self.assertTrue(workflow["entrypoint"])
                self.assertTrue(workflow["exit_criteria"])
                self.assertTrue(workflow["evidence"])
                self.assertTrue(
                    all(path.startswith(".context/") for path in workflow["evidence"].values())
                )

        resolved_proof = MOD.qualification_workflow("qualification_proof")
        resolved_rke2 = MOD.qualification_workflow("rke2_local_virtualbox")
        resolved_tekton = MOD.qualification_workflow("tekton_proof")
        resolved_campaign = MOD.qualification_workflow("performance_campaign")
        self.assertIs(True, resolved_proof["exact_sha_required"])
        self.assertIs(True, resolved_proof["clean_worktree_required"])
        self.assertIs(True, resolved_proof["stop_when_exit_criteria_pass"])
        self.assertIs(True, resolved_rke2["exact_sha_required"])
        self.assertIs(True, resolved_rke2["clean_worktree_required"])
        self.assertIs(True, resolved_rke2["stop_when_exit_criteria_pass"])
        self.assertEqual(
            "scripts/repoctl.py rke2-local-virtualbox-qualification --inputs .context/mgmt-vm-inputs.json",
            resolved_rke2["entrypoint"],
        )
        self.assertIs(True, resolved_tekton["exact_sha_required"])
        self.assertIs(False, resolved_tekton["merge_authoritative"])
        self.assertIs(True, resolved_tekton["state_changing"])
        self.assertIs(True, resolved_tekton["completion_requires_remote_readback"])
        self.assertEqual(
            ".context/runtime/tekton-proof/<sha>.json",
            tekton["evidence"]["runtime"],
        )
        self.assertIs(True, resolved_campaign["exact_sha_required"])
        self.assertIs(True, resolved_campaign["clean_worktree_required"])

        self.assertNotIn("completion", rke2)
        self.assertNotIn("superseded_completion", rke2)
        superseded = rke2["historical_completion"]
        self.assertEqual("rocky-10.2-packer-image-migration", superseded["superseded_by"])
        self.assertEqual("84cf01601aa336f0cdd2d1899d764437294fbfe6", superseded["qualified_source_sha"])
        self.assertEqual("complete", superseded["status"])
        self.assertEqual("PASS", superseded["criteria_status"])
        self.assertEqual(
            ".context/mgmt-offline-vm/<name>/rke2-result.json",
            rke2["evidence"]["runtime"],
        )
        self.assertIn("exact-sha-code-review-pass", rke2["exit_criteria"])
        self.assertIn("exact-sha-security-review-pass", rke2["exit_criteria"])

        self.assertEqual(1, proof["verify_change_runs"])
        self.assertEqual(1, proof["performance_audit_runs"])
        self.assertEqual(".context/performance/<sha>.json", proof["performance_audit_output"])
        self.assertIs(False, proof["performance_campaign_required"])
        self.assertIs(True, proof["merge_authoritative"])

        self.assertEqual(3, campaign["repetitions"])
        self.assertIs(False, campaign["merge_authoritative"])
        self.assertNotIn("repetitions", policy["performance"]["campaign"])

    def test_qualification_proof_runs_missing_exact_steps_once(self):
        head = "a" * 40
        evidence = ROOT / ".context" / "evidence" / f"{head}.json"

        def fake_git(*args, check=True):
            if args == ("rev-parse", "HEAD"):
                return head + "\n"
            if args == ("status", "--porcelain", "--untracked-files=all"):
                return ""
            raise AssertionError(args)

        completed = MOD.subprocess.CompletedProcess([], 0, "", "")
        audit_path = ROOT / ".context" / "performance" / f"{head}.json"
        with (
            mock.patch.object(MOD, "git", side_effect=fake_git),
            mock.patch.object(MOD, "verify_change", return_value=0) as verify,
            mock.patch.object(MOD, "_valid_exact_evidence", side_effect=[None, evidence]) as valid_evidence,
            mock.patch.object(MOD, "_qualification_audit_path", return_value=audit_path),
            mock.patch.object(MOD, "_valid_performance_audit", return_value=audit_path) as valid_audit,
            mock.patch.object(MOD, "_completed_proof_inputs_unchanged", return_value=True),
            mock.patch.object(MOD, "run", return_value=completed) as run,
        ):
            self.assertEqual(0, MOD.qualification_proof("origin/main"))

        verify.assert_called_once_with("origin/main", head)
        self.assertEqual(2, valid_evidence.call_count)
        self.assertEqual(1, valid_audit.call_count)
        run.assert_called_once()
        command = run.call_args.args[0]
        self.assertIn("scripts/performance_audit.py", command)
        self.assertEqual(1, command.count("--evidence"))
        self.assertEqual(1, command.count("--output"))
        self.assertEqual(str(audit_path), command[command.index("--output") + 1])

    def test_performance_audit_validator_rejects_malformed_json_shapes(self):
        head = "a" * 40
        base = "b" * 40
        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "audit.json"
            payload = {
                "schema_version": 1,
                "head_sha": head,
                "base_sha": base,
                "evidence_status": "PASS",
                "inventory": {"failed_gates": 0},
                "safety": {
                    "content_cache_authorizes_pass_reuse": False,
                    "verdict_reuse_policy": "exact-direct-parent-only",
                },
            }

            def fake_git(*args, check=True):
                if args == ("rev-parse", "origin/main"):
                    return base + "\n"
                raise AssertionError(args)

            with (
                mock.patch.object(MOD, "_qualification_audit_path", return_value=audit_path),
                mock.patch.object(MOD, "git", side_effect=fake_git),
            ):
                audit_path.write_text(json.dumps(payload), encoding="utf-8")
                self.assertEqual(audit_path, MOD._valid_performance_audit("origin/main", head))
                for malformed in ([], dict(payload, safety=None), dict(payload, safety=[])):
                    with self.subTest(malformed=malformed):
                        audit_path.write_text(json.dumps(malformed), encoding="utf-8")
                        self.assertIsNone(MOD._valid_performance_audit("origin/main", head))
                audit_path.write_text("{", encoding="utf-8")
                self.assertIsNone(MOD._valid_performance_audit("origin/main", head))

    def test_chatgpt_review_readiness_uses_latest_exact_sha_verdict_per_kind(self):
        head = "a" * 40
        policy = {
            "ai_reviewer": {
                "evidence": {
                    "required_kinds": ["code", "security"],
                    "required_status": "PASS",
                }
            }
        }

        def proof(kind, status, blockers):
            return (
                '<!-- chatgpt-exact-sha-review:v1 '
                + __import__("json").dumps(
                    {
                        "provider": "ChatGPT",
                        "kind": kind,
                        "head_sha": head,
                        "status": status,
                        "blocking_findings": blockers,
                    },
                    separators=(",", ":"),
                )
                + " -->"
            )

        cases = (
            (
                "blocked-then-pass",
                [
                    {"user": {"login": "owner"}, "body": proof("code", "BLOCKED", 1)},
                    {"user": {"login": "owner"}, "body": proof("code", "PASS", 0)},
                    {"user": {"login": "owner"}, "body": proof("security", "PASS", 0)},
                ],
                True,
            ),
            (
                "pass-then-blocked",
                [
                    {"user": {"login": "owner"}, "body": proof("code", "PASS", 0)},
                    {"user": {"login": "owner"}, "body": proof("code", "BLOCKED", 1)},
                    {"user": {"login": "owner"}, "body": proof("security", "PASS", 0)},
                ],
                False,
            ),
        )

        for name, comments, expected_ready in cases:
            with self.subTest(case=name):
                authoritative_comments = [
                    {
                        **comment,
                        "id": index,
                        "created_at": f"2026-09-27T10:{index:02d}:00Z",
                    }
                    for index, comment in enumerate(comments, start=1)
                ]
                owner = MOD.subprocess.CompletedProcess(
                    [],
                    0,
                    __import__("json").dumps(
                        {"owner": {"login": "owner"}, "nameWithOwner": "owner/repo"}
                    ),
                    "",
                )
                history = MOD.subprocess.CompletedProcess(
                    [], 0, __import__("json").dumps([authoritative_comments]), ""
                )

                def fake_run(command, **kwargs):
                    if command[1:3] == ["repo", "view"]:
                        return owner
                    if command[1:3] == ["api", "--paginate"]:
                        return history
                    raise AssertionError(command)

                with (
                    mock.patch.object(MOD, "pull_request_review_policy", return_value=policy),
                    mock.patch.object(MOD, "run", side_effect=fake_run),
                ):
                    ready, reason = MOD.chatgpt_review_readiness("gh", 129, head)
                self.assertIs(expected_ready, ready)
                if expected_ready:
                    self.assertIn("PASS", reason)
                else:
                    self.assertIn("not PASS", reason)

    def test_qualification_proof_reuses_fresh_exact_sha_pass_without_replay(self):
        head = "a" * 40
        evidence = ROOT / ".context" / "evidence" / f"{head}.json"
        audit_path = ROOT / ".context" / "performance" / f"{head}.json"

        def fake_git(*args, check=True):
            if args == ("rev-parse", "HEAD"):
                return head + "\n"
            if args == ("status", "--porcelain", "--untracked-files=all"):
                return ""
            raise AssertionError(args)

        with (
            mock.patch.object(MOD, "git", side_effect=fake_git),
            mock.patch.object(MOD, "verify_change") as verify,
            mock.patch.object(MOD, "_valid_exact_evidence", return_value=evidence),
            mock.patch.object(MOD, "_valid_performance_audit", return_value=audit_path),
            mock.patch.object(MOD, "_qualification_audit_path") as requested_audit,
            mock.patch.object(MOD, "_completed_proof_inputs_unchanged", return_value=True),
            mock.patch.object(MOD, "run") as run,
        ):
            self.assertEqual(0, MOD.qualification_proof("origin/main"))

        verify.assert_not_called()
        requested_audit.assert_not_called()
        run.assert_not_called()

    def test_qualification_proof_rechecks_frozen_source_after_audit(self):
        head = "a" * 40
        evidence = ROOT / ".context" / "evidence" / f"{head}.json"
        audit_path = ROOT / ".context" / "performance" / f"{head}.json"
        workflow = {
            "verify_change_runs": 1,
            "performance_audit_runs": 1,
            "clean_worktree_required": True,
            "exact_sha_required": True,
        }

        for mutation in ("dirty", "head-moved"):
            with self.subTest(mutation=mutation):
                calls = {"status": 0, "head": 0}

                def fake_git(*args, check=True):
                    if args == ("rev-parse", "HEAD"):
                        calls["head"] += 1
                        if mutation == "head-moved" and calls["head"] >= 2:
                            return "b" * 40 + "\n"
                        return head + "\n"
                    if args == ("status", "--porcelain", "--untracked-files=all"):
                        calls["status"] += 1
                        if mutation == "dirty" and calls["status"] >= 2:
                            return " M scripts/repoctl.py\n"
                        return ""
                    raise AssertionError(args)

                with (
                    mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                    mock.patch.object(MOD, "git", side_effect=fake_git),
                    mock.patch.object(MOD, "_valid_exact_evidence", return_value=evidence),
                    mock.patch.object(MOD, "_valid_performance_audit", return_value=audit_path),
                    mock.patch.object(MOD, "_qualification_audit_path"),
                    mock.patch.object(MOD, "verify_change") as verify,
                    mock.patch.object(MOD, "run") as run,
                ):
                    self.assertEqual(2, MOD.qualification_proof("origin/main"))
                verify.assert_not_called()
                run.assert_not_called()

    def test_completed_proof_inputs_use_stored_object_ids_without_historical_commit(self):
        source = "a" * 40
        expected = {
            "config/a.yaml": "1" * 40,
            "platform/runtime": "2" * 40,
        }
        unchanged_a = MOD.subprocess.CompletedProcess([], 0, "1" * 40 + "\n", "")
        changed_b = MOD.subprocess.CompletedProcess([], 0, "f" * 40 + "\n", "")
        with mock.patch.object(MOD, "run", side_effect=[unchanged_a, changed_b]) as run:
            self.assertFalse(
                MOD._completed_proof_inputs_unchanged(
                    source,
                    ["config/a.yaml", "platform/runtime"],
                    expected,
                )
            )
        self.assertEqual(2, run.call_count)
        for call in run.call_args_list:
            self.assertEqual(["git", "rev-parse"], call.args[0][:2])
            self.assertNotIn(source, call.args[0])
        with mock.patch.object(
            MOD,
            "run",
            return_value=MOD.subprocess.CompletedProcess([], 0, "1" * 40 + "\n", ""),
        ):
            self.assertTrue(
                MOD._completed_proof_inputs_unchanged(
                    source,
                    ["config/a.yaml"],
                    {"config/a.yaml": "1" * 40},
                )
            )

    def test_gate_written_bytes_color_thresholds_and_grouping(self):
        self.assertEqual("0", MOD._format_written_bytes(0))
        self.assertEqual("1 652 089", MOD._format_written_bytes(1_652_089))
        self.assertEqual("56 262 884", MOD._format_written_bytes(56_262_884))
        self.assertEqual("36", MOD._write_bytes_color(0))
        self.assertEqual("32", MOD._write_bytes_color(56_262_884))
        self.assertEqual("33", MOD._write_bytes_color(128 * 1024 * 1024))
        self.assertEqual("35", MOD._write_bytes_color(1024 * 1024 * 1024))
        with mock.patch.object(MOD, "_supports_color", return_value=True):
            self.assertIn(
                "\033[32m56 262 884\033[0m",
                MOD._paint(MOD._format_written_bytes(56_262_884), "32"),
            )

    def test_gate_progress_keeps_prefix_fixed_and_updates_stopwatch_and_odometer_fields(self):
        import io

        stream = io.StringIO()
        with (
            mock.patch.object(MOD, "_supports_color", return_value=True),
            mock.patch("sys.stdout", stream),
        ):
            progress = MOD._GateProgress("governance", enabled=True)
            progress.update(45.376, 1_652_089)
            progress.update(45.627, 1_652_190)
            self.assertTrue(progress.finish("PASS"))

        rendered = stream.getvalue()
        prefix = "RUN   governance |"
        self.assertEqual(1, rendered.count(prefix))
        self.assertIn("\033[36m  45.376s\033[0m", rendered)
        self.assertIn("\033[32m1 652 089\033[0m", rendered)
        self.assertEqual(1, rendered.count("1 652 "))
        self.assertIn("\033[36m627s\033[0m", rendered)

        duration = progress._duration(45.627)
        bytes_column = len(prefix) + len(duration) + len(" | ") + len("1 652 ")
        self.assertIn(
            f"\r\033[{bytes_column}C\033[32m190\033[0m",
            rendered,
        )
        self.assertIn("\r\033[32mPASS  \033[0m", rendered)
        self.assertEqual(1, rendered.count("\n"))

    def test_live_gate_record_is_not_printed_twice_after_status_transition(self):
        import io

        stream = io.StringIO()
        record = {
            "gate": "system",
            "duration_seconds": 33.046,
            "written_bytes": 19_556,
            "live_status_rendered": True,
            "log": ".context/logs/system.log",
        }
        with redirect_stdout(stream):
            MOD._emit_gate_record(True, record)
        self.assertEqual("", stream.getvalue())

    def test_compact_static_gate_status_supports_skip_and_reuse(self):
        import io

        stream = io.StringIO()
        with (
            mock.patch.object(MOD, "_supports_color", return_value=False),
            redirect_stdout(stream),
        ):
            MOD._emit_compact_gate_status("SKIP", "frontend:none", 0.0, 0)
            MOD._emit_compact_gate_status("REUSE", "security", 0.0, 19_556)
        self.assertEqual(
            [
                "SKIP  frontend:none | 0.000s | 0",
                "REUSE security | 0.000s | 19 556",
            ],
            stream.getvalue().splitlines(),
        )

    def test_semantic_region_snapshot_detects_module_binding_mutation(self):
        source = "BINDING = 'one'\n\nclass Stop:\n    pass\n"
        projection = "BINDING = 'one'\n"
        digest = MOD.hashlib.sha256(projection.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "scripts" / "helper.py"
            script.parent.mkdir(parents=True)
            script.write_text(source, encoding="utf-8")
            snapshot = {
                "scripts/helper.py": {
                    "end_marker": "class Stop",
                    "sha256": digest,
                }
            }
            with mock.patch.object(MOD, "ROOT", root):
                self.assertTrue(MOD._semantic_region_snapshot_unchanged(snapshot))
                script.write_text(
                    "BINDING = 'two'\n\nclass Stop:\n    pass\n",
                    encoding="utf-8",
                )
                self.assertFalse(MOD._semantic_region_snapshot_unchanged(snapshot))

    def test_semantic_function_snapshot_detects_consumed_helper_mutation(self):
        source = "def helper():\n    return 1\n"
        digest = MOD.hashlib.sha256(source.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "scripts" / "helper.py"
            script.parent.mkdir(parents=True)
            script.write_text(source, encoding="utf-8")
            snapshot = {"scripts/helper.py": {"helper": digest}}
            with mock.patch.object(MOD, "ROOT", root):
                self.assertTrue(MOD._semantic_function_snapshot_unchanged(snapshot))
                script.write_text("def helper():\n    return 2\n", encoding="utf-8")
                self.assertFalse(MOD._semantic_function_snapshot_unchanged(snapshot))

    def test_rke2_entrypoint_rejects_non_object_inputs_before_capability_planning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "mgmt-vm-inputs.json"
            inputs.write_text("[]\n", encoding="utf-8")
            with (mock.patch.object(MOD, "ROOT", root),
                  mock.patch.object(sys, "argv", [
                      "repoctl.py", "rke2-local-virtualbox-qualification",
                      "--inputs", str(inputs),
                  ]),
                  mock.patch.dict(os.environ, {"ECOMMERCE_RUNTIME_ORCHESTRATED": "0"}),
                  mock.patch("canonical_workspace.check", return_value={
                      "status": "PASS", "execution_scope": "local",
                  }),
                  mock.patch("native_workspace.workspace_error", return_value=None)):
                self.assertEqual(2, MOD.main())

    def test_rke2_registered_entrypoint_executes_complete_existing_fixture_sequence(self):
        completed = MOD.subprocess.CompletedProcess([], 0, "", "")
        execution_policy = MOD.qualification_execution_policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / ".context" / "mgmt-vm-inputs.json"
            toolchain = root / "config/contracts/toolchain-lock.json"
            toolchain.parent.mkdir(parents=True)
            toolchain.write_text(json.dumps({"versions": {"VIRTUALBOX_VERSION": "7.2.18"}}))
            inputs.parent.mkdir(parents=True)
            vm_name = "ecommerce-mgmt-test-policy"
            input_values = {
                "vm_name": vm_name,
                "vm_cpus": 4,
                "vm_memory": 4096,
                "mgmt_offline_manifest_sha256": "738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad",
            }
            inputs.write_text(
                __import__("json").dumps(input_values) + "\n",
                encoding="utf-8",
            )
            frozen_inputs = __import__("json").dumps(
                {**input_values, **MOD._rke2_verified_box("c" * 40)},
                sort_keys=True,
                separators=(",", ":"),
            )
            state = root / ".context" / "mgmt-offline-vm" / vm_name
            head = "c" * 40
            workflow = {
                "entrypoint": (
                    "scripts/repoctl.py rke2-local-virtualbox-qualification "
                    "--inputs .context/mgmt-vm-inputs.json"
                ),
                "exact_sha_required": True,
                "clean_worktree_required": True,
                "resumable": False,
            }

            def fake_git(*args, check=True):
                if args == ("status", "--porcelain", "--untracked-files=all"):
                    return ""
                if args == ("rev-parse", "HEAD"):
                    return head + "\n"
                if args == ("rev-parse", "HEAD^{tree}"):
                    return "b" * 40 + "\n"
                raise AssertionError(args)

            server_attempts = []
            def fake_run(command, **kwargs):
                if command[-1] == "vm_action=create":
                    state.mkdir(parents=True, exist_ok=True)
                    (state / "preflight.json").write_text(json.dumps({
                        "rocky_release": "Rocky Linux release 10.2 (Red Quartz)",
                        "selinux": "Enforcing", "kernel": "6.12.0-test", "systemd": "running",
                        "boot_id": "12345678-1234-1234-1234-123456789abc",
                        "online_cpus": 4, "memory_kib": 4 * 1024 * 1024,
                        "ssh_access": {
                            "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
                            "permitrootlogin": "no", "authenticationmethods": "publickey",
                        },
                        "public_connect_errno": 101,
                        "nft_policies": {"output": "drop", "forward": "drop"},
                        "ipv4_routes": [], "ipv6_routes": [],
                    }) + "\n", encoding="utf-8")
                    inputs.write_text(
                        __import__("json").dumps(
                            {
                                **input_values,
                                "vm_python": "/tmp/untrusted-python",
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                if command[-1] == "vm_action=test":
                    (state / "role-result.json").write_text(json.dumps({
                        "exit_code": 0, "trial": {"cold_trial": True,
                                                  "previous_attempt": False},
                        "transfer": _transfer_fixture(input_values["mgmt_offline_manifest_sha256"]),
                    }) + "\n", encoding="utf-8")
                if command[-1] == "vm_action=server":
                    server_attempts.append(True)
                    state.mkdir(parents=True, exist_ok=True)
                    (state / "server-source.json").write_text(
                        __import__("json").dumps({"git_sha": head}) + "\n",
                        encoding="utf-8",
                    )
                    (state / "server-invocation.json").write_text(json.dumps({
                        "vm_uuid": "12345678-1234-1234-1234-123456789abc",
                        "install_required": len(server_attempts) != 2,
                    }))
                    (state / "role-result.json").write_text(json.dumps({
                        "exit_code": 0, "vm_uuid": "12345678-1234-1234-1234-123456789abc",
                        "transfer": _transfer_fixture(input_values["mgmt_offline_manifest_sha256"]),
                    }))
                    (state / "rke2-result.json").write_text(json.dumps({
                        "node_ready": True, "cilium_ready": 1,
                    }))
                    (state / "tamper-result.json").write_text(json.dumps({
                        "blocked_task": "Revalidate every staged byte immediately before privileged installation",
                    }))
                return completed

            with (
                mock.patch.object(MOD, "ROOT", root),
                mock.patch.object(MOD, "qualification_execution_policy", return_value=execution_policy),
                mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                mock.patch.object(MOD, "_approved_rke2_manifest_sha256", return_value="738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad"),
                mock.patch.object(MOD, "_canonical_rke2_vagrant_ready", return_value=True),
                mock.patch.object(MOD, "git", side_effect=fake_git),
                mock.patch.object(MOD, "require"),
                mock.patch.dict(sys.modules, {"rke2_virtualbox_backend": types.SimpleNamespace(
                    probe=lambda *args, **kwargs: {
                        "vm_uuid": "12345678-1234-1234-1234-123456789abc",
                        "virtualbox_backend": "NEM",
                    }
                )}),
                mock.patch.object(MOD, "run", side_effect=fake_run) as run,
            ):
                self.assertEqual(
                    0,
                    MOD.rke2_local_virtualbox_qualification(".context/mgmt-vm-inputs.json"),
                )
                for index, step in ((11, "evidence"), (12, "final")):
                    checkpoint_path = state / "step-checkpoints" / f"{index:02d}-{step}.json"
                    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
                    self.assertEqual("PASS", checkpoint["status"])
                    self.assertEqual(step, checkpoint["step"])

        actions = [
            call.args[0][-1]
            for call in run.call_args_list
            if call.args and call.args[0][-2] == "-e" and call.args[0][-1].startswith("vm_action=")
        ]
        self.assertEqual(
            [
                "vm_action=validate",
                "vm_action=create",
                "vm_action=test",
                "vm_action=diagnostics",
                "vm_action=server",
                "vm_action=server",
                "vm_action=restage",
                "vm_action=tamper",
                "vm_action=restage",
                "vm_action=server",
                "vm_action=destroy",
            ],
            actions,
        )
        ansible_calls = [
            call
            for call in run.call_args_list
            if call.args and call.args[0] and call.args[0][0] == "ansible-playbook"
        ]
        self.assertEqual(11, len(ansible_calls))
        for call in ansible_calls:
            command = call.args[0]
            self.assertIn(f"vm_repo={root}", command)
            self.assertIn(f"vm_state={state}", command)
            self.assertIn(frozen_inputs, command)
            self.assertFalse(any(str(part).startswith("@") for part in command))

    def test_rke2_launcher_rejects_dirty_worktree_and_vm_repo_override(self):
        completed = MOD.subprocess.CompletedProcess([], 0, "", "")
        workflow = {
            "entrypoint": (
                "scripts/repoctl.py rke2-local-virtualbox-qualification "
                "--inputs .context/mgmt-vm-inputs.json"
            ),
            "exact_sha_required": True,
            "clean_worktree_required": True,
            "resumable": False,
        }
        head = "d" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / ".context" / "mgmt-vm-inputs.json"
            inputs.parent.mkdir(parents=True)
            inputs.write_text(
                __import__("json").dumps({"vm_name": "ecommerce-mgmt-test-policy"}) + "\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(MOD, "ROOT", root),
                mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                mock.patch.object(
                    MOD,
                    "git",
                    side_effect=lambda *args, **kwargs: (
                        " M scripts/repoctl.py\n"
                        if args == ("status", "--porcelain", "--untracked-files=all")
                        else head + "\n"
                    ),
                ),
                mock.patch.object(MOD, "run", return_value=completed) as run,
            ):
                self.assertEqual(
                    2,
                    MOD.rke2_local_virtualbox_qualification(".context/mgmt-vm-inputs.json"),
                )
                run.assert_not_called()

            inputs.write_text(
                __import__("json").dumps(
                    {
                        "vm_name": "ecommerce-mgmt-test-policy",
                        "vm_repo": "/tmp/alternate-source",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            def clean_git(*args, check=True):
                if args == ("status", "--porcelain", "--untracked-files=all"):
                    return ""
                if args == ("rev-parse", "HEAD"):
                    return head + "\n"
                raise AssertionError(args)

            with (
                mock.patch.object(MOD, "ROOT", root),
                mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                mock.patch.object(MOD, "git", side_effect=clean_git),
                mock.patch.object(MOD, "run", return_value=completed) as run,
            ):
                self.assertEqual(
                    2,
                    MOD.rke2_local_virtualbox_qualification(".context/mgmt-vm-inputs.json"),
                )
                run.assert_not_called()

    def test_rke2_vagrant_runtime_must_match_canonical_version(self):
        good = MOD.subprocess.CompletedProcess(
            [], 0, "Vagrant 2.4.9\n", ""
        )
        wrong = MOD.subprocess.CompletedProcess(
            [], 0, "Vagrant 2.5.0\n", ""
        )
        missing = MOD.subprocess.CompletedProcess([], 1, "", "missing")

        with (
            mock.patch.object(MOD, "_canonical_rke2_vagrant_version", return_value="2.4.9"),
            mock.patch.object(MOD, "run", return_value=good) as run,
        ):
            self.assertTrue(MOD._canonical_rke2_vagrant_ready())
            run.assert_called_once_with(
                ["/mnt/c/Program Files/Vagrant/bin/vagrant.exe", "--version"],
                check=False,
                capture=True,
            )

        with (
            mock.patch.object(MOD, "_canonical_rke2_vagrant_version", return_value="2.4.9"),
            mock.patch.object(MOD, "run", return_value=wrong),
        ):
            self.assertFalse(MOD._canonical_rke2_vagrant_ready())

        with (
            mock.patch.object(MOD, "_canonical_rke2_vagrant_version", return_value="2.4.9"),
            mock.patch.object(MOD, "run", return_value=missing),
        ):
            self.assertFalse(MOD._canonical_rke2_vagrant_ready())

    def test_rke2_create_failure_preserves_virtualbox_registration(self):
        workflow = {
            "entrypoint": (
                "scripts/repoctl.py rke2-local-virtualbox-qualification "
                "--inputs .context/mgmt-vm-inputs.json"
            ),
            "exact_sha_required": True,
            "clean_worktree_required": True,
            "resumable": False,
        }
        head = "d" * 40
        approved = "738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad"
        cases = [
            ("preexisting-vm", "old-uuid", "old-uuid"),
            ("no-vm-created", None, None),
            ("fresh-vm-with-stale-key", None, "new-uuid"),
        ]

        for name, before, after in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                vm_name = "ecommerce-mgmt-test-policy"
                state = root / ".context" / "mgmt-offline-vm" / vm_name
                inputs = root / ".context" / "mgmt-vm-inputs.json"
                inputs.parent.mkdir(parents=True)
                inputs.write_text(
                    __import__("json").dumps(
                        {
                            "vm_name": vm_name,
                            "vm_cpus": 4, "vm_memory": 4096,
                            "mgmt_offline_manifest_sha256": approved,
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                if name == "fresh-vm-with-stale-key":
                    state.mkdir(parents=True, exist_ok=True)
                    (state / "identity").write_text("stale-key\n", encoding="utf-8")

                def clean_git(*args, check=True):
                    if args == ("status", "--porcelain", "--untracked-files=all"):
                        return ""
                    if args == ("rev-parse", "HEAD"):
                        return head + "\n"
                    raise AssertionError(args)

                completed = MOD.subprocess.CompletedProcess([], 0, "", "")
                failed = MOD.subprocess.CompletedProcess([], 1, "", "")

                def fake_run(command, **kwargs):
                    if command[-1] == "vm_action=create":
                        return failed
                    return completed

                with (
                    mock.patch.object(MOD, "ROOT", root),
                    mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                    mock.patch.object(MOD, "_approved_rke2_manifest_sha256", return_value=approved),
                    mock.patch.object(MOD, "_canonical_rke2_vagrant_ready", return_value=True),
                    mock.patch.object(
                        MOD,
                        "_rke2_registered_vm_identity",
                        side_effect=[before, after],
                    ),
                    mock.patch.object(MOD, "git", side_effect=clean_git),
                    mock.patch.object(MOD, "require"),
                    mock.patch.object(MOD, "run", side_effect=fake_run) as run,
                ):
                    self.assertEqual(
                        1,
                        MOD.rke2_local_virtualbox_qualification(
                            ".context/mgmt-vm-inputs.json"
                        ),
                    )

                actions = [
                    call.args[0][-1]
                    for call in run.call_args_list
                    if call.args and call.args[0][-1].startswith("vm_action=")
                ]
                self.assertEqual(
                    ["vm_action=validate", "vm_action=create"],
                    actions,
                )

    def test_rke2_launcher_rejects_undocumented_input_overrides(self):
        completed = MOD.subprocess.CompletedProcess([], 0, "", "")
        workflow = {
            "entrypoint": (
                "scripts/repoctl.py rke2-local-virtualbox-qualification "
                "--inputs .context/mgmt-vm-inputs.json"
            ),
            "exact_sha_required": True,
            "clean_worktree_required": True,
            "resumable": False,
        }
        head = "d" * 40
        forbidden = [
            "vm_python",
            "vm_bridge",
            "vm_box_url",
            "vm_box_sha256",
            "vm_vagrant_windows",
            "vm_state",
            "vm_action",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / ".context" / "mgmt-vm-inputs.json"
            inputs.parent.mkdir(parents=True)

            def clean_git(*args, check=True):
                if args == ("status", "--porcelain", "--untracked-files=all"):
                    return ""
                if args == ("rev-parse", "HEAD"):
                    return head + "\n"
                raise AssertionError(args)

            for field in forbidden:
                with self.subTest(field=field):
                    inputs.write_text(
                        __import__("json").dumps(
                            {
                                "vm_name": "ecommerce-mgmt-test-policy",
                                field: "untrusted-override",
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    with (
                        mock.patch.object(MOD, "ROOT", root),
                        mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                        mock.patch.object(MOD, "git", side_effect=clean_git),
                        mock.patch.object(MOD, "run", return_value=completed) as run,
                    ):
                        self.assertEqual(
                            2,
                            MOD.rke2_local_virtualbox_qualification(
                                ".context/mgmt-vm-inputs.json"
                            ),
                        )
                        run.assert_not_called()

    def test_rke2_launcher_requires_supported_sizing_before_vm_creation(self):
        workflow = {
            "entrypoint": "scripts/repoctl.py rke2-local-virtualbox-qualification --inputs .context/mgmt-vm-inputs.json",
            "exact_sha_required": True, "clean_worktree_required": True, "resumable": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / ".context/mgmt-vm-inputs.json"
            inputs.parent.mkdir(parents=True)
            for sizing in ({}, {"vm_cpus": 2, "vm_memory": 4096},
                           {"vm_cpus": 4, "vm_memory": 2048},
                           {"vm_cpus": 4, "vm_memory": 32768}):
                with self.subTest(sizing=sizing):
                    inputs.write_text(json.dumps({"vm_name": "ecommerce-mgmt-test-policy", **sizing}),
                                      encoding="utf-8")
                    with (mock.patch.object(MOD, "ROOT", root),
                          mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                          mock.patch.object(MOD, "git", side_effect=lambda *args, **kwargs: "" if args[0] == "status" else "e" * 40),
                          mock.patch.object(MOD, "run") as run):
                        self.assertEqual(2, MOD.rke2_local_virtualbox_qualification(
                            ".context/mgmt-vm-inputs.json"))
                        run.assert_not_called()

    def test_rke2_launcher_rejects_noncanonical_manifest_digest(self):
        completed = MOD.subprocess.CompletedProcess([], 0, "", "")
        workflow = {
            "entrypoint": (
                "scripts/repoctl.py rke2-local-virtualbox-qualification "
                "--inputs .context/mgmt-vm-inputs.json"
            ),
            "exact_sha_required": True,
            "clean_worktree_required": True,
            "resumable": False,
        }
        head = "e" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / ".context" / "mgmt-vm-inputs.json"
            inputs.parent.mkdir(parents=True)
            inputs.write_text(
                __import__("json").dumps(
                    {
                        "vm_name": "ecommerce-mgmt-test-policy",
                        "vm_cpus": 4, "vm_memory": 4096,
                        "mgmt_offline_manifest_sha256": "f" * 64,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            def clean_git(*args, check=True):
                if args == ("status", "--porcelain", "--untracked-files=all"):
                    return ""
                if args == ("rev-parse", "HEAD"):
                    return head + "\n"
                raise AssertionError(args)

            with (
                mock.patch.object(MOD, "ROOT", root),
                mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                mock.patch.object(MOD, "_approved_rke2_manifest_sha256", return_value="738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad"),
                mock.patch.object(MOD, "_canonical_rke2_vagrant_ready", return_value=True),
                mock.patch.object(MOD, "git", side_effect=clean_git),
                mock.patch.object(MOD, "run", return_value=completed) as run,
            ):
                self.assertEqual(
                    2,
                    MOD.rke2_local_virtualbox_qualification(".context/mgmt-vm-inputs.json"),
                )
                run.assert_not_called()

    def test_rke2_launcher_rejects_source_evidence_from_another_sha(self):
        completed = MOD.subprocess.CompletedProcess([], 0, "", "")
        approved_manifest = "738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad"
        workflow = {
            "entrypoint": (
                "scripts/repoctl.py rke2-local-virtualbox-qualification "
                "--inputs .context/mgmt-vm-inputs.json"
            ),
            "exact_sha_required": True,
            "clean_worktree_required": True,
            "resumable": False,
        }
        head = "e" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vm_name = "ecommerce-mgmt-test-policy"
            toolchain = root / "config/contracts/toolchain-lock.json"
            toolchain.parent.mkdir(parents=True)
            toolchain.write_text(json.dumps({"versions": {"VIRTUALBOX_VERSION": "7.2.18"}}))
            inputs = root / ".context" / "mgmt-vm-inputs.json"
            inputs.parent.mkdir(parents=True)
            inputs.write_text(
                __import__("json").dumps(
                    {
                        "vm_name": vm_name,
                        "vm_cpus": 4,
                        "vm_memory": 4096,
                        "mgmt_offline_manifest_sha256": "738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            state = root / ".context" / "mgmt-offline-vm" / vm_name

            def clean_git(*args, check=True):
                if args == ("status", "--porcelain", "--untracked-files=all"):
                    return ""
                if args == ("rev-parse", "HEAD"):
                    return head + "\n"
                if args == ("rev-parse", "HEAD^{tree}"):
                    return "b" * 40 + "\n"
                raise AssertionError(args)

            def fake_run(command, **kwargs):
                if command[-1] == "vm_action=create":
                    state.mkdir(parents=True, exist_ok=True)
                    (state / "preflight.json").write_text(json.dumps({
                        "rocky_release": "Rocky Linux release 10.2 (Red Quartz)",
                        "selinux": "Enforcing", "kernel": "6.12.0-test", "systemd": "running",
                        "boot_id": "12345678-1234-1234-1234-123456789abc",
                        "online_cpus": 4, "memory_kib": 4 * 1024 * 1024,
                        "ssh_access": {
                            "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
                            "permitrootlogin": "no", "authenticationmethods": "publickey",
                        },
                        "public_connect_errno": 101,
                        "nft_policies": {"output": "drop", "forward": "drop"},
                        "ipv4_routes": [], "ipv6_routes": [],
                    }) + "\n", encoding="utf-8")
                if command[-1] == "vm_action=test":
                    (state / "role-result.json").write_text(json.dumps({
                        "exit_code": 0, "trial": {"cold_trial": True,
                                                  "previous_attempt": False},
                        "transfer": _transfer_fixture(approved_manifest),
                    }) + "\n", encoding="utf-8")
                if command[-1] == "vm_action=server":
                    state.mkdir(parents=True, exist_ok=True)
                    (state / "server-source.json").write_text(
                        __import__("json").dumps({"git_sha": "f" * 40}) + "\n",
                        encoding="utf-8",
                    )
                return completed

            with (
                mock.patch.object(MOD, "ROOT", root),
                mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                mock.patch.object(MOD, "_approved_rke2_manifest_sha256", return_value="738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad"),
                mock.patch.object(MOD, "_canonical_rke2_vagrant_ready", return_value=True),
                mock.patch.object(MOD, "git", side_effect=clean_git),
                mock.patch.object(MOD, "require"),
                mock.patch.dict(sys.modules, {"rke2_virtualbox_backend": types.SimpleNamespace(
                    probe=lambda *args, **kwargs: {
                        "vm_uuid": "12345678-1234-1234-1234-123456789abc",
                        "virtualbox_backend": "NEM",
                    }
                )}),
                mock.patch.object(MOD, "run", side_effect=fake_run) as run,
            ):
                self.assertEqual(
                    2,
                    MOD.rke2_local_virtualbox_qualification(".context/mgmt-vm-inputs.json"),
                )
        self.assertEqual("vm_action=server", run.call_args_list[-1].args[0][-1])

    def test_tekton_proof_launcher_consumes_registry_and_records_remote_readback(self):
        completed = MOD.subprocess.CompletedProcess([], 0, "", "")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = {
                "exact_sha_required": True,
                "clean_worktree_required": True,
                "merge_authoritative": False,
                "state_changing": True,
                "completion_requires_remote_readback": True,
                "evidence": {"runtime": ".context/runtime/tekton-proof/<sha>.json"},
            }
            head = "c" * 40

            def fake_git(*args, check=True):
                if args == ("status", "--porcelain", "--untracked-files=all"):
                    return ""
                if args == ("rev-parse", "HEAD"):
                    return head + "\n"
                raise AssertionError(args)

            with (
                mock.patch.object(MOD, "ROOT", root),
                mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                mock.patch.object(MOD, "git", side_effect=fake_git),
                mock.patch.object(MOD, "require"),
                mock.patch.object(MOD, "run", return_value=completed) as run,
            ):
                self.assertEqual(
                    0,
                    MOD.tekton_proof("runtime.yaml", "a" * 40, "b" * 40, head),
                )
            payload = __import__("json").loads(
                (root / ".context" / "runtime" / "tekton-proof" / f"{head}.json").read_text()
            )
            self.assertEqual("PASS", payload["status"])
            self.assertEqual("signed-harbor-evidence-authenticated", payload["remote_readback"])
            run.assert_called_once()

    def test_tekton_proof_rechecks_frozen_checkout_before_pass_evidence(self):
        completed = MOD.subprocess.CompletedProcess([], 0, "", "")
        workflow = {
            "exact_sha_required": True,
            "clean_worktree_required": True,
            "merge_authoritative": False,
            "state_changing": True,
            "completion_requires_remote_readback": True,
            "evidence": {"runtime": ".context/runtime/tekton-proof/<sha>.json"},
        }
        head = "c" * 40

        for mutation in ("dirty-worktree", "head-moved"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                calls = {"status": 0, "head": 0}

                def fake_git(*args, check=True):
                    if args == ("status", "--porcelain", "--untracked-files=all"):
                        calls["status"] += 1
                        if mutation == "dirty-worktree" and calls["status"] >= 2:
                            return " M platform/tekton/pipeline.yaml\n"
                        return ""
                    if args == ("rev-parse", "HEAD"):
                        calls["head"] += 1
                        if mutation == "head-moved" and calls["head"] >= 2:
                            return "d" * 40 + "\n"
                        return head + "\n"
                    raise AssertionError(args)

                with (
                    mock.patch.object(MOD, "ROOT", root),
                    mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                    mock.patch.object(MOD, "git", side_effect=fake_git),
                    mock.patch.object(MOD, "require"),
                    mock.patch.object(MOD, "run", return_value=completed) as run,
                ):
                    self.assertEqual(
                        2,
                        MOD.tekton_proof("runtime.yaml", "a" * 40, "b" * 40, head),
                    )

                self.assertFalse(
                    (root / ".context" / "runtime" / "tekton-proof" / f"{head}.json").exists()
                )
                run.assert_called_once()

    def test_performance_campaign_freeze_helper_rejects_source_drift(self):
        head = "a" * 40
        with mock.patch.object(
            PERF_MOD.subprocess,
            "check_output",
            side_effect=["\n", head + "\n"],
        ):
            self.assertEqual(head, PERF_MOD._assert_frozen_checkout())

        with mock.patch.object(
            PERF_MOD.subprocess,
            "check_output",
            return_value=" M scripts/repoctl.py\n",
        ):
            with self.assertRaisesRegex(RuntimeError, "worktree changed"):
                PERF_MOD._assert_frozen_checkout(head)

        with mock.patch.object(
            PERF_MOD.subprocess,
            "check_output",
            side_effect=["\n", "b" * 40 + "\n"],
        ):
            with self.assertRaisesRegex(RuntimeError, "HEAD changed"):
                PERF_MOD._assert_frozen_checkout(head)

    def test_performance_campaign_uses_central_workflow_repetition_count(self):
        completed = MOD.subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(MOD, "qualification_workflow", return_value={"repetitions": 7}),
            mock.patch.object(MOD, "run", return_value=completed) as run,
        ):
            self.assertEqual(0, MOD.performance_campaign("origin/main"))

        command = run.call_args.args[0]
        self.assertEqual("7", command[command.index("--repetitions") + 1])

    def test_ci_worker_budget_is_required_from_runtime(self):
        execution = MOD.qualification_execution_policy()["execution"]
        env_name = execution["ci_max_workers_env"]
        with mock.patch.dict(
            MOD.os.environ,
            {"ECOMMERCE_EXECUTION_SCOPE": "ci", env_name: ""},
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "runtime-provided"):
                MOD._execution_workers()
        with mock.patch.dict(
            MOD.os.environ,
            {"ECOMMERCE_EXECUTION_SCOPE": "ci", env_name: "3"},
            clear=False,
        ):
            self.assertEqual(3, MOD._execution_workers())

    def test_cross_cutting_execution_domain_is_centralized(self):
        model = MOD.repository_authority_model()
        self.assertEqual(
            "qualification_execution_policy",
            model["domains"]["qualification_execution"]["machine_contract"],
        )
        cache = MOD.qualification_cache.contract()
        self.assertEqual(
            "architecture.lock.yaml#machine_contracts.qualification_execution_policy",
            cache["consumers"]["qualification_execution"]["authority"],
        )
        self.assertEqual("delegated", cache["consumers"]["qualification_execution"]["gate_inventory"])

    def test_required_gate_classes_have_explicit_safety_modes(self):
        expectations = {
            "governance": ("composed", False),
            "runtime-efficiency": ("content-pass", True),
            "contracts": ("content-pass", True),
            "automation": ("content-pass", True),
            "security": ("fresh", True),
            "system": ("composed", False),
            "platform:ansible": ("content-pass", True),
            "platform:terraform": ("content-pass", True),
            "frontend:storefront": ("native-only", True),
            "service:product": ("native-only", True),
        }
        for gate, (cache_mode, parallel_safe) in expectations.items():
            with self.subTest(gate=gate):
                policy = MOD._resolved_gate_policy(gate)
                self.assertEqual(cache_mode, policy["cache_mode"])
                self.assertIs(parallel_safe, policy["parallel_safe"])

    def test_system_tests_are_owned_once_and_dynamic_cache_targets_exact_file(self):
        owners = MOD._dedicated_test_owners()
        self.assertEqual(16, len(owners))
        self.assertEqual("governance", owners["tests/test_architecture_authority.py"])
        self.assertEqual("governance", owners["tests/test_commit_provenance.py"])
        self.assertEqual("governance", owners["tests/test_runtime_orchestration.py"])
        self.assertEqual("governance", owners["tests/test_modern_engineering.py"])
        self.assertEqual("governance", owners["tests/test_security_policy.py"])
        self.assertEqual("governance", owners["tests/test_kratix_platform.py"])
        self.assertEqual("contracts", owners["tests/openapi_validator_test.rb"])
        self.assertEqual("runtime-efficiency", owners["tests/runtime_efficiency_test.rb"])

        gate = MOD._resolved_gate_policy("system:test:tests/test_m1_qualification_runner.py")
        self.assertEqual("system:test:*", gate["_policy_name"])
        self.assertIn("tests/test_m1_qualification_runner.py", gate["inputs"])
        self.assertIn("tests/test_m1_qualification_runner.py", gate["validators"])
        self.assertNotIn("<target>", gate["inputs"])

    def test_system_plan_excludes_dedicated_owned_tests(self):
        captured = {}

        def capture(regular, internal):
            captured["regular"] = list(regular)
            captured["internal"] = list(internal)
            return 0

        with (
            mock.patch.object(MOD, "_git_neutral_test_env", return_value={}),
            mock.patch.object(MOD, "_run_regular_then_internal_parallel", side_effect=capture),
        ):
            self.assertEqual(0, MOD.system_check())
        names = [name for name, _producer in captured["regular"] + captured["internal"]]
        self.assertNotIn("system:test:tests/test_architecture_authority.py", names)
        self.assertNotIn("system:test:tests/openapi_validator_test.rb", names)
        self.assertIn("system:test:tests/test_m1_qualification_runner.py", names)
        self.assertIn("system:test:tests/delivery/test_performance_audit.py", names)
        self.assertIn("system:test:tests/test_developer_git_defaults.py", [name for name, _ in captured["internal"]])

    def test_governance_plan_shards_validators_and_owned_tests(self):
        captured = {}

        def capture(regular, internal):
            captured["regular"] = list(regular)
            captured["internal"] = list(internal)
            return 0

        with mock.patch.object(MOD, "_run_regular_then_internal_parallel", side_effect=capture):
            self.assertEqual(0, MOD.governance())
        names = [name for name, _producer in captured["regular"] + captured["internal"]]
        self.assertIn("governance:authority", names)
        self.assertIn("governance:commit-provenance", names)
        self.assertIn("governance:documentation", names)
        self.assertIn("governance:validator:scripts/validate-architecture.rb", names)
        self.assertIn("governance:test:tests/test_architecture_authority.py", names)
        self.assertIn("governance:test:tests/test_commit_provenance.py", names)
        self.assertIn("governance:test:tests/test_qualification_execution_policy.py", names)
        self.assertIn("governance:test:tests/test_runtime_orchestration.py", names)
        self.assertEqual(21, len(names))
        self.assertIn(
            "governance:test:tests/test_architecture_authority.py",
            [name for name, _producer in captured["internal"]],
        )

    def test_python_unittest_method_sharding_is_central_and_deterministic(self):
        identifiers = MOD._python_unittest_ids("tests/test_architecture_authority.py")
        self.assertGreaterEqual(len(identifiers), 60)
        self.assertTrue(
            all(identifier.startswith("tests.test_architecture_authority.ArchitectureAuthorityTest.test_") for identifier in identifiers)
        )
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual(
            4,
            MOD.qualification_execution_policy()["execution"]["python_unittest_method_shard_min_tests"],
        )
        shards = MOD._python_unittest_shards("tests/test_architecture_authority.py")
        self.assertEqual(MOD._execution_workers(), len(shards))
        flattened = [identifier for shard in shards for identifier in shard]
        self.assertEqual(set(identifiers), set(flattened))
        self.assertEqual(len(identifiers), len(flattened))
        self.assertLessEqual(max(map(len, shards)) - min(map(len, shards)), 1)

    def test_dynamic_service_inputs_are_resolved_without_product_special_case(self):
        product = MOD._resolved_gate_policy("service:product")
        catalog = MOD._resolved_gate_policy("service:catalog")
        self.assertIn("services/product/**/*", product["inputs"])
        self.assertIn("services/catalog/**/*", catalog["inputs"])
        self.assertNotEqual(product["inputs"], catalog["inputs"])
        self.assertEqual("service:*", product["_policy_name"])

    def test_top_level_commands_and_ci_fanout_are_contract_driven(self):
        globals_ = MOD._policy_gate_names("global")
        self.assertEqual(
            ["governance", "runtime-efficiency", "contracts", "automation", "security", "qualification-tools"],
            globals_,
        )
        self.assertEqual(globals_, MOD._policy_gate_names("global", ci_fanout_only=True))
        contracts, reason = MOD._gate_command("contracts", "origin/main", "HEAD")
        self.assertIsNone(reason)
        self.assertEqual(
            ["contracts", "--base", "origin/main", "--head", "HEAD"],
            contracts[-5:],
        )
        product, reason = MOD._gate_command("service:product")
        self.assertIsNone(reason)
        self.assertEqual(["service", "product"], product[-2:])

    def test_global_gate_order_is_stable_when_cached_mapping_keys_are_sorted(self):
        expected = ["governance", "runtime-efficiency", "contracts", "automation", "security", "qualification-tools"]
        policy = MOD.qualification_execution_policy()
        policy["gates"] = dict(sorted(policy["gates"].items()))
        with mock.patch.object(MOD, "qualification_execution_policy", return_value=policy):
            self.assertEqual(expected, MOD._policy_gate_names("global"))
            self.assertEqual(expected, MOD._policy_gate_names("global", ci_fanout_only=True))

    def test_execution_plan_emits_run_fresh_reuse_and_is_policy_complete(self):
        parent = {
            "gates": [
                {"gate": "service:product", "status": "PASS"},
                {"gate": "system", "status": "PASS"},
            ]
        }
        plan = MOD.build_execution_plan(
            "origin/main",
            "HEAD",
            ["global", "service:product", "system"],
            parent_sha="a" * 40,
            parent_evidence=parent,
            delta_components={"global"},
        )
        by_gate = {entry["gate"]: entry for entry in plan}
        self.assertEqual("fresh", by_gate["security"]["action"])
        self.assertEqual("run", by_gate["governance"]["action"])
        self.assertEqual("reuse", by_gate["service:product"]["action"])
        self.assertEqual("reuse", by_gate["system"]["action"])
        self.assertEqual(
            set(MOD._policy_gate_names("global")) | {"service:product", "system"},
            set(by_gate),
        )

    def test_dependency_cycle_and_unknown_dependency_fail_closed(self):
        cycle = [
            {
                "gate": "a",
                "scope": "global",
                "action": "run",
                "command": ["a"],
                "dependencies": ["b"],
            },
            {
                "gate": "b",
                "scope": "global",
                "action": "run",
                "command": ["b"],
                "dependencies": ["a"],
            },
        ]
        with self.assertRaisesRegex(RuntimeError, "cycle or unsatisfied"):
            MOD._execute_plan_scope(cycle, "global", [], {}, None, None)

        unknown = [
            {
                "gate": "a",
                "scope": "global",
                "action": "run",
                "command": ["a"],
                "dependencies": ["missing"],
            }
        ]
        with self.assertRaisesRegex(RuntimeError, "unknown gate"):
            MOD._execute_plan_scope(unknown, "global", [], {}, None, None)

    def test_performance_campaign_and_budgets_are_central_contract(self):
        policy = MOD.qualification_execution_policy()
        performance = policy["performance"]
        campaign = policy["workflows"]["performance_campaign"]
        self.assertEqual(3, campaign["repetitions"])
        self.assertNotIn("repetitions", performance["campaign"])
        self.assertEqual(110.054, performance["baselines_seconds"]["system"])
        self.assertEqual(86.060, performance["baselines_seconds"]["governance"])
        self.assertLessEqual(performance["budgets_seconds"]["warm_verify_change_wall_max"], 30)
        self.assertLessEqual(performance["budgets_seconds"]["service_product_warm_wall_max"], 15)
        self.assertIs(True, performance["regression"]["fail_on_budget_regression"])

    def test_performance_campaign_validator_accepts_only_exact_pass_budget_proof(self):
        import json
        import tempfile
        import time

        head = "a" * 40
        tree = "b" * 40
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory)
            proof_dir = context / "performance"
            proof_dir.mkdir()
            proof = proof_dir / f"campaign-{head}.json"
            repetitions = MOD.qualification_workflow("performance_campaign")["repetitions"]
            payload = {
                "schema_version": 1,
                "status": "PASS",
                "head_sha": head,
                "head_tree_sha": tree,
                "qualification_identity": "identity",
                "created_at_epoch": time.time(),
                "repetitions": repetitions,
                "budgets": {"warm": {"status": "PASS"}},
                "safety": {
                    "native_dependency_caches_preserved": True,
                    "product_runtime_tests_remain_fresh": True,
                },
            }
            proof.write_text(json.dumps(payload), encoding="utf-8")

            def fake_git(*args, check=True):
                if args == ("rev-parse", f"{head}^{{tree}}"):
                    return tree + "\n"
                raise AssertionError(args)

            with (
                mock.patch.object(MOD, "CONTEXT", context),
                mock.patch.object(MOD, "git", side_effect=fake_git),
                mock.patch.object(MOD, "qualification_identity", return_value="identity"),
            ):
                self.assertEqual(proof, MOD._valid_performance_campaign(head))
                for malformed in (
                    [], dict(payload, budgets={"warm": None}),
                    dict(payload, safety=None), dict(payload, safety=[]),
                ):
                    with self.subTest(malformed=malformed):
                        proof.write_text(json.dumps(malformed), encoding="utf-8")
                        self.assertIsNone(MOD._valid_performance_campaign(head))
                payload["budgets"]["warm"]["status"] = "FAIL"
                proof.write_text(json.dumps(payload), encoding="utf-8")
                self.assertIsNone(MOD._valid_performance_campaign(head))

    def test_unknown_gate_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "does not declare gate"):
            MOD._resolved_gate_policy("unknown:gate")

    def test_platform_parallel_safety_keeps_unique_mutation_domains(self):
        ansible = MOD._resolved_gate_policy("platform:ansible")
        terraform = MOD._resolved_gate_policy("platform:terraform")
        self.assertIs(True, ansible["parallel_safe"])
        self.assertIs(True, terraform["parallel_safe"])
        self.assertEqual(
            ["project-owned-collection-version-reconciliation"],
            ansible["fresh_prechecks"],
        )
        self.assertEqual(
            ["approved-opentofu-executable-availability", "canonical-provider-lock-contract"],
            terraform["fresh_prechecks"],
        )
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn('TemporaryDirectory(prefix="ecommerce-opentofu-validation-")', source)
        self.assertIn('collections_install_root', (ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8"))

    def test_tekton_finalizer_rejects_skip_for_planned_fresh_gate(self):
        head = "a" * 40
        base_sha = "b" * 40
        with tempfile.TemporaryDirectory() as directory:
            record_dir = Path(directory)
            (record_dir / "plan.json").write_text(
                __import__("json").dumps(
                    {
                        "schema_version": 2,
                        "head_sha": head,
                        "base_sha": base_sha,
                        "gates": ["security"],
                        "execution_plan": [
                            {
                                "gate": "security",
                                "scope": "global",
                                "action": "fresh",
                                "cache_mode": "fresh",
                                "parallel_safe": True,
                                "ci_fanout": True,
                            }
                        ],
                        "precomputed_records": [],
                    }
                ),
                encoding="utf-8",
            )
            (record_dir / "global-security.json").write_text(
                __import__("json").dumps(
                    {
                        "head_sha": head,
                        "records": [
                            {
                                "gate": "security",
                                "status": "SKIP",
                                "duration_seconds": 0.0,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            def fake_git(*args, check=True):
                if args == ("rev-parse", "origin/main"):
                    return base_sha + "\n"
                raise AssertionError(args)

            with (
                mock.patch.object(MOD, "_require_clean_exact_checkout", return_value=(head, head)),
                mock.patch.object(MOD, "git", side_effect=fake_git),
                mock.patch.object(MOD, "publish_remote_status") as publish,
                mock.patch.object(MOD, "write_evidence") as write,
            ):
                self.assertEqual(1, MOD.ci_finalize("origin/main", head, str(record_dir)))

            write.assert_not_called()
            self.assertTrue(
                any(
                    call.args[1] == "failure"
                    for call in publish.call_args_list
                    if len(call.args) > 1
                )
            )

    def test_security_and_dynamic_runtime_state_cannot_be_content_cached(self):
        policy = MOD.qualification_execution_policy()
        self.assertEqual("fresh", MOD._resolved_gate_policy("security")["cache_mode"])
        dynamic = set(policy["dynamic_state"]["always_fresh"])
        self.assertTrue(
            {
                "docker-runtime-state",
                "kubernetes-runtime-state",
                "network-state",
                "secrets-and-authentication",
            }.issubset(dynamic)
        )
        with self.assertRaisesRegex(RuntimeError, "not approved"):
            MOD._gate_cache_key("security", {})

    def test_execute_gate_keeps_child_output_out_of_terminal_and_in_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = root / ".context"
            terminal = io.StringIO()
            policy = {
                "cache_mode": "fresh",
                "scope": "global",
                "parallel_safe": True,
                "ci_fanout": True,
            }
            with (
                mock.patch.object(MOD, "ROOT", root),
                mock.patch.object(MOD, "CONTEXT", context),
                mock.patch.object(MOD, "_resolved_gate_policy", return_value=policy),
                redirect_stdout(terminal),
            ):
                ok, record = MOD._execute_gate(
                    "security",
                    [MOD.sys.executable, "-c", "print('GATE-LOG-ONLY')"],
                    {},
                )

            self.assertTrue(ok)
            self.assertEqual("", terminal.getvalue())
            log_text = (root / record["log"]).read_text(encoding="utf-8")
            self.assertEqual("GATE-LOG-ONLY\n", log_text)
            self.assertEqual(len(log_text.encode("utf-8")), record["written_bytes"])

            emitted = io.StringIO()
            with (
                mock.patch.object(MOD, "_supports_color", return_value=False),
                redirect_stdout(emitted),
            ):
                MOD._emit_gate_record(ok, record)
            self.assertIn(
                (
                    f"PASS  security | {record['duration_seconds']:.3f}s | "
                    f"{MOD._format_written_bytes(record['written_bytes'])}"
                ),
                emitted.getvalue(),
            )

    def test_parallel_batch_preserves_declared_order_and_serial_barrier(self):
        records = []

        def fake_execute(name, command, env=None):
            return True, {
                "gate": name,
                "status": "PASS",
                "exit_code": 0,
                "duration_seconds": 0.001,
                "written_bytes": 0,
                "command": command,
                "log": ".context/logs/test.log",
                "execution": "fresh",
            }

        with (
            mock.patch.object(MOD, "_execution_workers", return_value=2),
            mock.patch.object(MOD, "_gate_parallel_safe", side_effect=lambda name: name != "serial"),
            mock.patch.object(MOD, "_execute_gate", side_effect=fake_execute),
            mock.patch.object(MOD, "_emit_gate_record"),
        ):
            self.assertTrue(
                MOD._run_gate_batch(
                    [
                        ("a", ["a"]),
                        ("b", ["b"]),
                        ("serial", ["serial"]),
                        ("c", ["c"]),
                    ],
                    records,
                )
            )
        self.assertEqual(["a", "b", "serial", "c"], [record["gate"] for record in records])


class QualificationStepGuardTests(unittest.TestCase):
    def setUp(self):
        from datetime import datetime, timezone

        self.steps = MOD.qualification_steps
        self.started = datetime.now(timezone.utc)
        self.sha = "a" * 40
        self.digest = "b" * 64
        self.artifact_digest = "c" * 64
        self.workflow = MOD.qualification_execution_policy()["workflows"]["rke2_local_virtualbox"]
        self.graph = self.steps.validate_graph(self.workflow)
        self.preflight = self.steps.checkpoint(
            qualification="m2.5", step="preflight", source_sha=self.sha,
            input_digest=self.digest, status="PASS", started_at=self.started,
            preflight=True,
        )

    def test_policy_schema_rejects_missing_version_unknown_rule_and_status(self):
        policy = MOD.qualification_execution_policy()
        self.assertTrue(policy["step_qualification"]["resumable"])
        self.assertFalse(policy["workflows"]["rke2_local_virtualbox"]["resumable"])
        for mutation in (
            lambda value: value.pop("version"),
            lambda value: value.update(kind="WrongKind"),
            lambda value: value.update(status="draft"),
            lambda value: value["step_qualification"].pop("checkpointed"),
            lambda value: value["step_qualification"].update(unknown_rule=True),
        ):
            altered = json.loads(json.dumps(policy))
            mutation(altered)
            with self.subTest(altered=altered.get("kind")), self.assertRaises(ValueError):
                self.steps.validate_policy(altered, ROOT)

    def test_failed_preflight_checkpoint_matches_the_schema(self):
        schema = json.loads((ROOT / "config/contracts/qualification-step-evidence.schema.json").read_text())
        failed = self.steps.checkpoint(
            qualification="m2.5", step="preflight", source_sha=self.sha,
            input_digest=self.digest, status="FAIL", started_at=self.started,
        )
        self.assertNotIn("preflight", schema["required"])
        self.assertNotIn("preflight", failed)
        matching_rules = [rule for rule in schema["allOf"] if rule.get("if", {}).get(
            "properties", {}).get("step", {}).get("const") == "preflight"]
        self.assertEqual(1, len(matching_rules))
        self.assertEqual("PASS", matching_rules[0]["if"]["properties"]["status"]["const"])
        self.assertEqual(["preflight"], matching_rules[0]["then"]["required"])
        self.steps.validate_checkpoint(failed)
        passed_without_proof = dict(failed, status="PASS")
        with self.assertRaisesRegex(ValueError, "preflight lacks"):
            self.steps.validate_checkpoint(passed_without_proof)

    def test_preflight_blocks_expensive_work_and_full_requires_smoke(self):
        with self.assertRaisesRegex(ValueError, "preflight"):
            self.steps.guard_start(qualification="m2.5", step="vm-smoke", graph=self.graph, source_sha=self.sha,
                                   input_digest=self.digest, checkpoints={})
        with self.assertRaisesRegex(ValueError, "predecessor checkpoint"):
            self.steps.guard_start(qualification="m2.5", step="rke2-single", graph=self.graph, source_sha=self.sha,
                                   input_digest=self.digest, checkpoints={"preflight": self.preflight})

    def test_compatible_smoke_allows_full_and_other_sha_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            proof = Path(temporary) / "runtime.json"
            proof.write_text('{"observed":true}\n', encoding="utf-8")
            records = {"preflight": self.preflight}
            for name in ("input-lock", "image"):
                records[name] = self.steps.checkpoint(
                    qualification="m2.5", step=name, source_sha=self.sha,
                    input_digest=self.digest, status="PASS", started_at=self.started,
                    artifact_digest=self.artifact_digest,
                )
            for name in ("vm-smoke", "network-ssh", "rocky-runtime", "offline-bundle"):
                records[name] = self.steps.checkpoint(
                    qualification="m2.5", step=name, source_sha=self.sha,
                    input_digest=self.digest, status="PASS", started_at=self.started,
                    artifact_digest=self.artifact_digest, runtime_path=proof,
                )
            self.steps.guard_start(qualification="m2.5", step="rke2-single", graph=self.graph, source_sha=self.sha,
                                   input_digest=self.digest, checkpoints=records)
            for missing in ("input-lock", "image", "vm-smoke", "network-ssh", "rocky-runtime", "offline-bundle"):
                incomplete = {name: record for name, record in records.items() if name != missing}
                with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "predecessor checkpoint"):
                    self.steps.guard_start(qualification="m2.5", step="rke2-single", graph=self.graph,
                                           source_sha=self.sha, input_digest=self.digest, checkpoints=incomplete)
            with self.assertRaisesRegex(ValueError, "image predecessor checkpoint"):
                self.steps.guard_start(qualification="m2.5", step="vm-smoke", graph=self.graph,
                                       source_sha=self.sha, input_digest=self.digest,
                                       checkpoints={"preflight": self.preflight,
                                                    "input-lock": records["input-lock"]})
            wrong_step = dict(records["network-ssh"], step="vm-smoke")
            with self.assertRaisesRegex(ValueError, "identity differs"):
                self.steps.guard_start(qualification="m2.5", step="rke2-single", graph=self.graph,
                                       source_sha=self.sha, input_digest=self.digest,
                                       checkpoints=dict(records, **{"network-ssh": wrong_step}))
            failed = dict(records["rocky-runtime"], status="FAIL")
            with self.assertRaisesRegex(ValueError, "predecessor PASS"):
                self.steps.guard_start(qualification="m2.5", step="rke2-single", graph=self.graph,
                                       source_sha=self.sha, input_digest=self.digest,
                                       checkpoints=dict(records, **{"rocky-runtime": failed}))
            with self.assertRaisesRegex(ValueError, "another source SHA"):
                self.steps.guard_start(qualification="m2.5", step="rke2-single", graph=self.graph, source_sha="d" * 40,
                                       input_digest=self.digest, checkpoints=records)
            proof.write_text('{"observed":false}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "changed"):
                self.steps.guard_start(qualification="m2.5", step="rke2-single", graph=self.graph, source_sha=self.sha,
                                       input_digest=self.digest, checkpoints=records)

    def test_checkpoint_requires_source_runtime_proof_and_reuse_provenance(self):
        for duration in (True, float("inf"), float("nan")):
            with self.subTest(duration=duration), self.assertRaisesRegex(ValueError, "duration"):
                self.steps.validate_checkpoint(dict(self.preflight, duration_seconds=duration))
        record = dict(self.preflight)
        del record["source_sha"]
        with self.assertRaisesRegex(ValueError, "fields"):
            self.steps.validate_checkpoint(record)
        record = dict(self.preflight, step="vm-smoke")
        with self.assertRaisesRegex(ValueError, "runtime evidence"):
            self.steps.validate_checkpoint(record, runtime_required=True)
        record = dict(self.preflight, status="SKIPPED_REUSED_VERIFIED", executed=False,
                      reused=True, cache_hit=True, artifact_digest=self.artifact_digest)
        with self.assertRaisesRegex(ValueError, "provenance"):
            self.steps.validate_checkpoint(record)
        record["reused_from"] = {"source_sha": self.sha, "input_digest": "d" * 64,
                                 "artifact_digest": self.artifact_digest}
        with self.assertRaisesRegex(ValueError, "provenance"):
            self.steps.validate_checkpoint(record)
        record["reused_from"]["input_digest"] = self.digest
        self.steps.validate_checkpoint(record)

    def test_reused_runtime_smoke_cannot_omit_or_change_immutable_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            proof = Path(temporary) / "smoke.json"
            proof.write_text('{"observed":true}\n', encoding="utf-8")
            reused = self.steps.checkpoint(
                qualification="m2.5", step="vm-smoke", source_sha=self.sha,
                input_digest=self.digest, artifact_digest=self.artifact_digest,
                status="SKIPPED_REUSED_VERIFIED", started_at=self.started,
                reused_from={"source_sha": "e" * 40, "input_digest": self.digest,
                             "artifact_digest": self.artifact_digest},
            )
            with self.assertRaisesRegex(ValueError, "runtime evidence"):
                self.steps.validate_checkpoint(reused, runtime_required=True)
            import hashlib

            reused["runtime_evidence"] = {
                "path": str(proof), "sha256": hashlib.sha256(proof.read_bytes()).hexdigest(),
            }
            self.steps.validate_checkpoint(reused, runtime_required=True)
            proof.write_text('{"observed":false}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "changed"):
                self.steps.validate_checkpoint(reused, runtime_required=True)

    def test_verified_artifact_reuse_forbids_rebuild(self):
        import hashlib

        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "box"
            artifact.write_bytes(b"verified box")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self.assertEqual("SKIPPED_REUSED_VERIFIED", self.steps.verified_reuse(
                path=artifact, source_sha=self.sha, recorded_source_sha="e" * 40,
                expected_digest=digest, input_digest=self.digest,
                recorded_input_digest=self.digest, operation="reuse"))
            with self.assertRaisesRegex(ValueError, "must be reused"):
                self.steps.verified_reuse(path=artifact, source_sha=self.sha,
                                          recorded_source_sha="e" * 40, expected_digest=digest,
                                          input_digest=self.digest, recorded_input_digest=self.digest,
                                          operation="build")
            self.assertEqual("REBUILD_REQUIRED", self.steps.verified_reuse(
                path=artifact, source_sha=self.sha, recorded_source_sha="e" * 40,
                expected_digest=digest, input_digest=self.digest,
                recorded_input_digest="e" * 64, operation="reuse"))

    def test_transfer_cleanup_network_and_review_guards(self):
        with self.assertRaisesRegex(ValueError, "retransferred"):
            self.steps.guard_transfer(source_digest=self.digest, target_digest=self.digest,
                                      mode="full", manifest_digest=self.artifact_digest,
                                      final_digest=self.digest)
        self.steps.guard_transfer(source_digest=self.digest, target_digest=self.digest,
                                  mode="skip", manifest_digest=self.artifact_digest)
        transfer = {
            "mode": "skip", "source_digest": self.digest,
            "prior_target_digest": self.digest, "manifest_digest": self.digest,
            "final_digest": self.digest, "target_valid_before": True,
            "copy_changed": False, "started_at": "2026-09-29T20:00:00+00:00",
            "finished_at": "2026-09-29T20:00:01+00:00",
        }
        self.steps.validate_transfer_record(transfer, approved_manifest=self.digest)
        with self.assertRaisesRegex(ValueError, "copy decision"):
            self.steps.validate_transfer_record(dict(transfer, copy_changed=True),
                                                approved_manifest=self.digest)
        with self.assertRaisesRegex(ValueError, "approved manifest"):
            self.steps.validate_transfer_record(dict(transfer, source_digest=self.artifact_digest),
                                                approved_manifest=self.digest)
        with self.assertRaisesRegex(ValueError, "retained"):
            self.steps.guard_cleanup(final_evidence_captured=False, explicitly_authorized=False)
        self.steps.guard_cleanup(final_evidence_captured=False, explicitly_authorized=True)
        with self.assertRaisesRegex(ValueError, "exact SHA"):
            self.steps.guard_review(source_sha=self.sha, code_sha=self.sha,
                                    security_sha="e" * 40)
        self.steps.guard_review(source_sha=self.sha, code_sha=self.sha, security_sha=self.sha)
        with self.assertRaisesRegex(ValueError, "staged probes"):
            self.steps.guard_network(probes=["tcp_port"], elapsed_seconds=120,
                                     budget_seconds=120, bounded_backoff=False)

    def test_selective_invalidation_and_unknown_impact(self):
        impacts = self.workflow["impact_inputs"]
        docs = self.steps.invalidate(self.graph, impacts, ["docs_only"])
        self.assertEqual([], docs["invalidated_steps"])
        ansible = self.steps.invalidate(self.graph, impacts, ["ansible"])
        self.assertIn("image", ansible["reusable_steps"])
        self.assertIn("rke2-single", ansible["invalidated_steps"])
        self.assertIn("final", ansible["invalidated_steps"])
        unknown = self.steps.invalidate(self.graph, impacts, ["unclassified"])
        self.assertEqual(set(self.graph), set(unknown["invalidated_steps"]))

    def test_qualification_impact_reuses_canonical_affected_classifier(self):
        rules = self.workflow["impact_path_rules"]
        self.assertEqual(["docs_only"], self.steps.classify_impact(
            ["docs/engineering/example.md"], ["global"], rules))
        self.assertEqual(["ansible"], self.steps.classify_impact(
            ["platform/ansible/roles/rke2_server/tasks/main.yml"],
            ["global", "platform:ansible"], rules))
        self.assertEqual(["unknown"], self.steps.classify_impact(
            ["platform/ansible/roles/rke2_server/tasks/main.yml"],
            ["global", "platform:ansible", "system"], rules))
        with (
            mock.patch.object(MOD, "changed_paths", return_value=["docs/engineering/example.md"]),
            mock.patch.object(MOD, "affected", return_value=["global"]) as canonical,
        ):
            result = MOD.qualification_impact("base", "head", "rke2_local_virtualbox")
        canonical.assert_called_once_with("base", "head", strict_unknown=True)
        self.assertEqual([], result["invalidated_steps"])

    def test_rke2_bundle_transfer_is_skipped_only_after_target_digest_probe(self):
        import yaml

        tasks = yaml.safe_load((ROOT / "platform/ansible/roles/mgmt_offline_artifacts/tasks/main.yml").read_text(encoding="utf-8"))
        names = [task["name"] for task in tasks]
        probe_name = "Check whether the content-addressed target already matches the approved bundle"
        transfer_name = "Transfer approved bundle only when target content is absent or invalid"
        verify_name = "Verify transferred bytes before package installation"
        self.assertLess(names.index(probe_name), names.index(transfer_name))
        self.assertLess(names.index(transfer_name), names.index(verify_name))
        probe = tasks[names.index(probe_name)]
        transfer = tasks[names.index(transfer_name)]
        self.assertIn("--manifest-sha256", probe["ansible.builtin.command"]["argv"])
        self.assertEqual("mgmt_offline_existing.rc != 0", transfer["when"])
        self.assertEqual("mgmt_offline_existing", probe["register"])


if __name__ == "__main__":
    unittest.main()
