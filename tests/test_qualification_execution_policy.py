from __future__ import annotations

import importlib.util
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
            "governance": ("composed", True),
            "runtime-efficiency": ("content-pass", True),
            "contracts": ("content-pass", True),
            "automation": ("content-pass", True),
            "security": ("fresh", True),
            "system": ("composed", True),
            "platform:ansible": ("content-pass", False),
            "platform:terraform": ("content-pass", False),
            "frontend:storefront": ("native-only", True),
            "service:product": ("native-only", True),
        }
        for gate, (cache_mode, parallel_safe) in expectations.items():
            with self.subTest(gate=gate):
                policy = MOD._resolved_gate_policy(gate)
                self.assertEqual(cache_mode, policy["cache_mode"])
                self.assertIs(parallel_safe, policy["parallel_safe"])

    def test_dynamic_service_inputs_are_resolved_without_product_special_case(self):
        product = MOD._resolved_gate_policy("service:product")
        catalog = MOD._resolved_gate_policy("service:catalog")
        self.assertIn("services/product/**/*", product["inputs"])
        self.assertIn("services/catalog/**/*", catalog["inputs"])
        self.assertNotEqual(product["inputs"], catalog["inputs"])
        self.assertEqual("service:*", product["_policy_name"])

    def test_unknown_gate_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "does not declare gate"):
            MOD._resolved_gate_policy("unknown:gate")

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
