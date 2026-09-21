from __future__ import annotations

import importlib.util
import io
import tempfile
from contextlib import redirect_stdout
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


class QualificationExecutionPolicyTests(unittest.TestCase):
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

        completion = rke2["completion"]
        self.assertEqual("complete", completion["status"])
        self.assertEqual("PASS", completion["criteria_status"])
        self.assertEqual("existing-proof-no-rerun", completion["proof_registration"])
        self.assertEqual(
            "84cf01601aa336f0cdd2d1899d764437294fbfe6",
            completion["qualified_source_sha"],
        )
        self.assertEqual(128, completion["merged_by_pr"])
        self.assertEqual(
            "088b576dac43cb17e304967e3e58433499760fa9",
            completion["merge_commit_sha"],
        )
        self.assertEqual(
            "https://github.com/dst-red-Wire/ecommerce-1/pull/128#issuecomment-5754280746",
            completion["provenance"]["code_review"],
        )
        self.assertEqual(
            "https://github.com/dst-red-Wire/ecommerce-1/pull/128#issuecomment-5754280831",
            completion["provenance"]["security_review"],
        )
        self.assertEqual(
            "738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad",
            completion["provenance"]["approved_manifest_sha256"],
        )
        self.assertIn(
            "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json",
            completion["invalidation_inputs"],
        )
        runtime_fixture_inputs = [
            "platform/ansible/tests/mgmt_offline_vm/Vagrantfile",
            "platform/ansible/tests/mgmt_offline_vm/contract.yml",
            "platform/ansible/tests/mgmt_offline_vm/create.yml",
            "platform/ansible/tests/mgmt_offline_vm/destroy.yml",
            "platform/ansible/tests/mgmt_offline_vm/main.yml",
            "platform/ansible/tests/mgmt_offline_vm/server.yml",
            "platform/ansible/tests/mgmt_offline_vm/test.yml",
            "platform/ansible/tests/mgmt_offline_vm/transport.py",
        ]
        for path in runtime_fixture_inputs:
            self.assertIn(path, completion["invalidation_inputs"])
        self.assertNotIn(
            "platform/ansible/tests/mgmt_offline_vm/README.md",
            completion["invalidation_inputs"],
        )
        self.assertEqual(
            set(completion["invalidation_inputs"]),
            set(completion["invalidation_object_ids"]),
        )
        self.assertTrue(
            all(
                __import__("re").fullmatch(r"[0-9a-f]{40}", object_id)
                for object_id in completion["invalidation_object_ids"].values()
            )
        )
        toolchain_inputs = [
            "config/contracts/toolchain-lock.json",
            "config/toolchain/versions.env",
            "platform/ansible/requirements.yml",
        ]
        for path in toolchain_inputs:
            self.assertIn(path, completion["invalidation_inputs"])
            with self.subTest(invalidation_input=path):
                expected = completion["invalidation_object_ids"][path]
                changed = MOD.subprocess.CompletedProcess([], 0, "f" * 40 + "\n", "")
                with mock.patch.object(MOD, "run", return_value=changed):
                    self.assertFalse(
                        MOD._completed_proof_inputs_unchanged(
                            completion["qualified_source_sha"],
                            [path],
                            {path: expected},
                        )
                    )
        semantic = completion["invalidation_semantic_functions"]
        self.assertIn("scripts/repoctl.py", semantic)
        self.assertIn("scripts/capability_bootstrap.py", semantic)
        self.assertIn("ansible_collections_ready", semantic["scripts/repoctl.py"])
        self.assertIn(
            "validate_toolchain_projections",
            semantic["scripts/capability_bootstrap.py"],
        )
        self.assertTrue(MOD._semantic_function_snapshot_unchanged(semantic))
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
                owner = MOD.subprocess.CompletedProcess(
                    [],
                    0,
                    __import__("json").dumps(
                        {"owner": {"login": "owner"}, "nameWithOwner": "owner/repo"}
                    ),
                    "",
                )
                history = MOD.subprocess.CompletedProcess(
                    [], 0, __import__("json").dumps([comments]), ""
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

    def test_rke2_registered_entrypoint_executes_complete_existing_fixture_sequence(self):
        completed = MOD.subprocess.CompletedProcess([], 0, "", "")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / ".context" / "mgmt-vm-inputs.json"
            inputs.parent.mkdir(parents=True)
            vm_name = "ecommerce-mgmt-test-policy"
            input_values = {
                "vm_name": vm_name,
                "mgmt_offline_manifest_sha256": "738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad",
            }
            inputs.write_text(
                __import__("json").dumps(input_values) + "\n",
                encoding="utf-8",
            )
            frozen_inputs = __import__("json").dumps(
                input_values,
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
            }

            def fake_git(*args, check=True):
                if args == ("status", "--porcelain", "--untracked-files=all"):
                    return ""
                if args == ("rev-parse", "HEAD"):
                    return head + "\n"
                raise AssertionError(args)

            def fake_run(command, **kwargs):
                if command[-1] == "vm_action=create":
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
                if command[-1] == "vm_action=server":
                    state.mkdir(parents=True, exist_ok=True)
                    (state / "server-source.json").write_text(
                        __import__("json").dumps({"git_sha": head}) + "\n",
                        encoding="utf-8",
                    )
                return completed

            with (
                mock.patch.object(MOD, "ROOT", root),
                mock.patch.object(MOD, "qualification_workflow", return_value=workflow),
                mock.patch.object(MOD, "_approved_rke2_manifest_sha256", return_value="738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad"),
                mock.patch.object(MOD, "_canonical_rke2_vagrant_ready", return_value=True),
                mock.patch.object(MOD, "git", side_effect=fake_git),
                mock.patch.object(MOD, "require"),
                mock.patch.object(MOD, "run", side_effect=fake_run) as run,
            ):
                self.assertEqual(
                    0,
                    MOD.rke2_local_virtualbox_qualification(".context/mgmt-vm-inputs.json"),
                )

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
        self.assertEqual(10, len(ansible_calls))
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

    def test_rke2_create_failure_cleans_only_new_virtualbox_registration(self):
        workflow = {
            "entrypoint": (
                "scripts/repoctl.py rke2-local-virtualbox-qualification "
                "--inputs .context/mgmt-vm-inputs.json"
            ),
            "exact_sha_required": True,
            "clean_worktree_required": True,
        }
        head = "d" * 40
        approved = "738a5cd2aa1be1eb93b08247193c1585574ad1668650993226eafe3f3cfa0bad"
        cases = [
            ("preexisting-vm", "old-uuid", "old-uuid", False),
            ("no-vm-created", None, None, False),
            ("fresh-vm-with-stale-key", None, "new-uuid", True),
        ]

        for name, before, after, cleanup_expected in cases:
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
                    ["vm_action=validate", "vm_action=create"]
                    + (["vm_action=destroy"] if cleanup_expected else []),
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

    def test_rke2_launcher_rejects_noncanonical_manifest_digest(self):
        completed = MOD.subprocess.CompletedProcess([], 0, "", "")
        workflow = {
            "entrypoint": (
                "scripts/repoctl.py rke2-local-virtualbox-qualification "
                "--inputs .context/mgmt-vm-inputs.json"
            ),
            "exact_sha_required": True,
            "clean_worktree_required": True,
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
        workflow = {
            "entrypoint": (
                "scripts/repoctl.py rke2-local-virtualbox-qualification "
                "--inputs .context/mgmt-vm-inputs.json"
            ),
            "exact_sha_required": True,
            "clean_worktree_required": True,
        }
        head = "e" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vm_name = "ecommerce-mgmt-test-policy"
            inputs = root / ".context" / "mgmt-vm-inputs.json"
            inputs.parent.mkdir(parents=True)
            inputs.write_text(
                __import__("json").dumps(
                    {
                        "vm_name": vm_name,
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
                raise AssertionError(args)

            def fake_run(command, **kwargs):
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
                mock.patch.object(MOD, "run", side_effect=fake_run) as run,
            ):
                self.assertEqual(
                    2,
                    MOD.rke2_local_virtualbox_qualification(".context/mgmt-vm-inputs.json"),
                )
        self.assertEqual("vm_action=destroy", run.call_args_list[-1].args[0][-1])

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
        self.assertEqual(11, len(owners))
        self.assertEqual("governance", owners["tests/test_architecture_authority.py"])
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
        self.assertIn("governance:documentation", names)
        self.assertIn("governance:validator:scripts/validate-architecture.rb", names)
        self.assertIn("governance:test:tests/test_architecture_authority.py", names)
        self.assertIn("governance:test:tests/test_qualification_execution_policy.py", names)
        self.assertEqual(15, len(names))
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
            ["governance", "runtime-efficiency", "contracts", "automation", "security"],
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
        expected = ["governance", "runtime-efficiency", "contracts", "automation", "security"]
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
            ["approved-terraform-executable-availability", "canonical-provider-lock-contract"],
            terraform["fresh_prechecks"],
        )
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn('TemporaryDirectory(prefix="ecommerce-terraform-validation-")', source)
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
            self.assertEqual("GATE-LOG-ONLY\n", (root / record["log"]).read_text(encoding="utf-8"))

    def test_parallel_batch_preserves_declared_order_and_serial_barrier(self):
        records = []

        def fake_execute(name, command, env=None):
            return True, {
                "gate": name,
                "status": "PASS",
                "exit_code": 0,
                "duration_seconds": 0.001,
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


if __name__ == "__main__":
    unittest.main()
