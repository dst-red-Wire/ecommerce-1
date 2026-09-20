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
        proof = policy["workflows"]["qualification_proof"]
        campaign = policy["workflows"]["performance_campaign"]

        self.assertEqual(1, proof["verify_change_runs"])
        self.assertEqual(1, proof["performance_audit_runs"])
        self.assertEqual(".context/performance/<sha>.json", proof["performance_audit_output"])
        self.assertIs(False, proof["performance_campaign_required"])
        self.assertIs(True, proof["merge_authoritative"])

        self.assertEqual(3, campaign["repetitions"])
        self.assertIs(False, campaign["merge_authoritative"])
        self.assertNotIn("repetitions", policy["performance"]["campaign"])

    def test_qualification_proof_runs_exact_verify_once_then_audit_once(self):
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
            mock.patch.object(MOD, "_valid_exact_evidence", return_value=evidence),
            mock.patch.object(MOD, "_qualification_audit_path", return_value=audit_path),
            mock.patch.object(MOD, "_valid_performance_audit", return_value=audit_path) as valid_audit,
            mock.patch.object(MOD, "run", return_value=completed) as run,
        ):
            self.assertEqual(0, MOD.qualification_proof("origin/main"))

        verify.assert_called_once_with("origin/main", head)
        valid_audit.assert_called_once_with("origin/main", head)
        run.assert_called_once()
        command = run.call_args.args[0]
        self.assertIn("scripts/performance_audit.py", command)
        self.assertEqual(1, command.count("--evidence"))
        self.assertEqual(1, command.count("--output"))
        self.assertEqual(str(audit_path), command[command.index("--output") + 1])

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
