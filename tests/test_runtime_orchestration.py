from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from scripts.runtime_orchestration import (
    BuiltinCapabilityDriver,
    CapabilityRequest,
    CapabilitySpec,
    PlannedCapability,
    RuntimeBlocked,
    RuntimeExecutor,
    RuntimePlanner,
    RuntimePolicyError,
    RuntimeVerificationError,
    validate_runtime_policy,
)

ROOT = Path(__file__).resolve().parents[1]


def capability(
    *,
    requires: list[str] | None = None,
    mutation_class: str = "none",
    handler: str = "dependency",
    prepare: str = "none",
) -> dict:
    mutable = mutation_class in {"local-ephemeral", "local-virtualization"}
    return {
        "handler": handler,
        "requires": requires or [],
        "mutation_class": mutation_class,
        "timeout_seconds": 2,
        "privilege": "none",
        "global_lock": mutable,
        "operations": {
            "detector": "fake",
            "preflight": "fake",
            "prepare": prepare,
            "verify": "fake",
            "restore": "fake" if mutable else "none",
            "verify_restore": "fake" if mutable else "none",
        },
        "evidence_fields": ["satisfied", "value", "api_token"],
    }


def policy(capabilities: dict[str, dict]) -> dict:
    return {
        "enabled": True,
        "single_authority": True,
        "lifecycle": [
            "resolve",
            "capture",
            "preflight",
            "prepare",
            "verify",
            "execute",
            "restore",
            "verify_restore",
            "evidence",
        ],
        "rules": {
            "preflight_before_mutation": "required",
            "capture_initial_state": "required",
            "bounded_mutations": "required",
            "restore_on_success": "required",
            "restore_on_failure": "required",
            "restore_on_interrupt": "required",
            "restore_verification": "required",
            "fail_on_restore_failure": "required",
            "tracked_source_mutation_for_evidence": "forbidden",
            "evidence_root": ".context",
            "secrets_in_evidence": "forbidden",
            "dynamic_state_cache": "forbidden",
        },
        "mutation_classes": [
            "none",
            "local-ephemeral",
            "local-virtualization",
            "external-governed",
            "production-governed",
        ],
        "external_paid_resources": {"implicit_creation": "forbidden"},
        "production": {"implicit_mutation": "forbidden"},
        "lock": {
            "path": ".context/runtime/orchestration.lock",
            "timeout_seconds": 1,
        },
        "capabilities": capabilities,
    }


class FakeDriver:
    def __init__(self, initial: dict[str, dict] | None = None) -> None:
        self.initial = initial or {}
        self.current = {name: dict(value) for name, value in self.initial.items()}
        self.events: list[str] = []
        self.block_preflight: set[str] = set()
        self.fail_prepare: set[str] = set()
        self.fail_restore: set[str] = set()
        self.fail_verify_restore: set[str] = set()

    def capture(self, item):
        self.events.append(f"capture:{item.spec.name}")
        return dict(self.current.get(item.spec.name, {"satisfied": False, "value": 0}))

    def preflight(self, item, state):
        self.events.append(f"preflight:{item.spec.name}")
        if item.spec.name in self.block_preflight:
            raise RuntimeBlocked(f"blocked {item.spec.name}")
        return {
            "status": "PASS",
            "mutation_required": item.spec.mutation_class
            in {"local-ephemeral", "local-virtualization"}
            and state.get("satisfied") is not True,
        }

    def prepare(self, item, state):
        if state.get("satisfied") is True or item.spec.mutation_class == "none":
            self.events.append(f"noop:{item.spec.name}")
            return dict(state), {}
        self.events.append(f"prepare:{item.spec.name}")
        self.current[item.spec.name] = {"satisfied": True, "value": 1}
        if item.spec.name in self.fail_prepare:
            raise RuntimeVerificationError(f"prepare failed {item.spec.name}")
        return dict(self.current[item.spec.name]), {}

    def verify(self, item, _state):
        self.events.append(f"verify:{item.spec.name}")
        return {"status": "PASS"}

    def restore(self, item, state):
        self.events.append(f"restore:{item.spec.name}")
        if item.spec.name in self.fail_restore:
            raise RuntimeVerificationError(f"restore failed {item.spec.name}")
        self.current[item.spec.name] = dict(state)
        return {"action": "restore"}

    def verify_restore(self, item, state):
        self.events.append(f"verify_restore:{item.spec.name}")
        if item.spec.name in self.fail_verify_restore:
            raise RuntimeVerificationError(f"verify restore failed {item.spec.name}")
        if item.spec.mutation_class in {
            "local-ephemeral",
            "local-virtualization",
        } and self.current.get(item.spec.name) != dict(state):
            raise RuntimeVerificationError(f"state mismatch {item.spec.name}")
        return dict(self.current.get(item.spec.name, {"satisfied": True}))


class RuntimeOrchestrationTests(unittest.TestCase):
    def run_transaction(
        self,
        capabilities: dict[str, dict],
        requests: list[CapabilityRequest],
        driver: FakeDriver,
        gate=None,
        *,
        source_kind: str = "worktree",
        authoritative: bool = False,
    ):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        executor = RuntimeExecutor(root, policy(capabilities), driver=driver)
        result = executor.execute(
            requests,
            gate or (lambda _env: 0),
            workflow="test",
            source_kind=source_kind,
            source_sha="a" * 40,
            selected_gates=["gate:a", "gate:b"],
            authoritative=authoritative,
        )
        evidence = (
            json.loads(result.evidence_path.read_text(encoding="utf-8"))
            if result.evidence_path
            else None
        )
        return result, evidence

    def test_no_capability_is_a_true_noop(self):
        called = []
        result, evidence = self.run_transaction(
            {"unused": capability()},
            [],
            FakeDriver(),
            lambda env: called.append(env) or 0,
        )
        self.assertEqual("PASS", result.status)
        self.assertEqual(1, len(called))
        self.assertEqual("1", called[0]["ECOMMERCE_RUNTIME_ORCHESTRATED"])
        self.assertIsNone(evidence)

    def test_satisfied_capability_does_not_mutate(self):
        caps = {"docker": capability(mutation_class="local-ephemeral", prepare="start")}
        driver = FakeDriver({"docker": {"satisfied": True, "value": 1}})
        result, _ = self.run_transaction(caps, [CapabilityRequest("docker")], driver)
        self.assertEqual("PASS", result.status)
        self.assertNotIn("prepare:docker", driver.events)
        self.assertNotIn("restore:docker", driver.events)

    def test_temporary_capability_wraps_gate_and_restores(self):
        caps = {"docker": capability(mutation_class="local-ephemeral", prepare="start")}
        driver = FakeDriver({"docker": {"satisfied": False, "value": 0}})
        result, evidence = self.run_transaction(
            caps, [CapabilityRequest("docker")], driver
        )
        self.assertEqual("PASS", result.status)
        self.assertLess(
            driver.events.index("prepare:docker"), driver.events.index("restore:docker")
        )
        self.assertTrue(evidence["restore_verified"])

    def test_duplicate_requests_prepare_once(self):
        caps = {"docker": capability(mutation_class="local-ephemeral", prepare="start")}
        driver = FakeDriver({"docker": {"satisfied": False}})
        self.run_transaction(
            caps, [CapabilityRequest("docker"), CapabilityRequest("docker")], driver
        )
        self.assertEqual(1, driver.events.count("prepare:docker"))

    def test_dependency_order_is_topological(self):
        caps = {
            "docker": capability(mutation_class="local-ephemeral", prepare="start"),
            "tests": capability(requires=["docker"]),
        }
        plan = RuntimePlanner(policy(caps)).resolve([CapabilityRequest("tests")])
        self.assertEqual(["docker", "tests"], [item.spec.name for item in plan])

    def test_command_probe_uses_first_available_approved_alternative(self):
        item = PlannedCapability(
            CapabilitySpec(
                name="terraform-runtime",
                handler="command",
                requires=(),
                mutation_class="none",
                timeout_seconds=2,
                privilege="none",
                global_lock=False,
                operations={},
                evidence_fields=("satisfied", "command", "exit_code"),
                default_parameters={},
            ),
            {"commands": [["tofu", "version"], ["terraform", "version"]]},
        )
        driver = BuiltinCapabilityDriver()
        unavailable = subprocess.CompletedProcess(["tofu", "version"], 127, "", "")
        available = subprocess.CompletedProcess(
            ["terraform", "version"], 0, "Terraform v1.9.8\n", ""
        )
        with mock.patch.object(driver, "_run", side_effect=[unavailable, available]):
            state = driver.capture(item)
        self.assertTrue(state["satisfied"])
        self.assertEqual("terraform", state["command"])

    def test_global_preflight_failure_causes_zero_mutation(self):
        caps = {
            "docker": capability(mutation_class="local-ephemeral", prepare="start"),
            "memory": capability(),
        }
        driver = FakeDriver(
            {"docker": {"satisfied": False}, "memory": {"satisfied": True}}
        )
        driver.block_preflight.add("memory")
        result, _ = self.run_transaction(
            caps, [CapabilityRequest("docker"), CapabilityRequest("memory")], driver
        )
        self.assertEqual("BLOCKED_RUNTIME", result.status)
        self.assertFalse(any(event.startswith("prepare:") for event in driver.events))

    def test_partial_prepare_failure_rolls_back_owned_changes(self):
        caps = {
            "a": capability(mutation_class="local-ephemeral", prepare="start"),
            "b": capability(
                requires=["a"], mutation_class="local-ephemeral", prepare="start"
            ),
        }
        driver = FakeDriver({"a": {"satisfied": False}, "b": {"satisfied": False}})
        driver.fail_prepare.add("b")
        result, _ = self.run_transaction(caps, [CapabilityRequest("b")], driver)
        self.assertEqual("FAIL", result.status)
        self.assertIn("restore:a", driver.events)
        self.assertEqual({"satisfied": False}, driver.current["a"])

    def test_gate_failure_restores(self):
        caps = {"docker": capability(mutation_class="local-ephemeral", prepare="start")}
        driver = FakeDriver({"docker": {"satisfied": False}})
        result, _ = self.run_transaction(
            caps, [CapabilityRequest("docker")], driver, lambda _env: 7
        )
        self.assertEqual("FAIL", result.status)
        self.assertEqual(7, result.exit_code)
        self.assertIn("restore:docker", driver.events)

    def test_exception_restores(self):
        caps = {"docker": capability(mutation_class="local-ephemeral", prepare="start")}
        driver = FakeDriver({"docker": {"satisfied": False}})

        def explode(_env):
            raise ValueError("gate exploded")

        result, _ = self.run_transaction(
            caps, [CapabilityRequest("docker")], driver, explode
        )
        self.assertEqual("FAIL", result.status)
        self.assertIn("restore:docker", driver.events)

    def test_interrupt_restores(self):
        caps = {"docker": capability(mutation_class="local-ephemeral", prepare="start")}
        driver = FakeDriver({"docker": {"satisfied": False}})

        def interrupt(_env):
            raise KeyboardInterrupt()

        result, _ = self.run_transaction(
            caps, [CapabilityRequest("docker")], driver, interrupt
        )
        self.assertEqual("INTERRUPTED", result.status)
        self.assertIn("restore:docker", driver.events)

    def test_restore_failure_is_blocking(self):
        caps = {"docker": capability(mutation_class="local-ephemeral", prepare="start")}
        driver = FakeDriver({"docker": {"satisfied": False}})
        driver.fail_restore.add("docker")
        result, evidence = self.run_transaction(
            caps, [CapabilityRequest("docker")], driver
        )
        self.assertEqual("FAIL_RESTORE", result.status)
        self.assertEqual(1, result.exit_code)
        self.assertFalse(evidence["restore_verified"])

    def test_verify_restore_failure_is_blocking(self):
        caps = {"docker": capability(mutation_class="local-ephemeral", prepare="start")}
        driver = FakeDriver({"docker": {"satisfied": False}})
        driver.fail_verify_restore.add("docker")
        result, _ = self.run_transaction(caps, [CapabilityRequest("docker")], driver)
        self.assertEqual("FAIL_RESTORE", result.status)

    def test_initial_running_state_remains_running(self):
        caps = {"docker": capability(mutation_class="local-ephemeral", prepare="start")}
        initial = {"satisfied": True, "value": 1}
        driver = FakeDriver({"docker": initial})
        self.run_transaction(caps, [CapabilityRequest("docker")], driver)
        self.assertEqual(initial, driver.current["docker"])

    def test_initial_stopped_state_returns_to_stopped(self):
        caps = {"docker": capability(mutation_class="local-ephemeral", prepare="start")}
        initial = {"satisfied": False, "value": 0}
        driver = FakeDriver({"docker": initial})
        self.run_transaction(caps, [CapabilityRequest("docker")], driver)
        self.assertEqual(initial, driver.current["docker"])

    def test_ip_forward_exact_initial_values_are_restored(self):
        caps = {"ip": capability(mutation_class="local-ephemeral", prepare="set-one")}
        for value in (0, 1):
            with self.subTest(value=value):
                initial = {"satisfied": value == 1, "value": value}
                driver = FakeDriver({"ip": initial})
                self.run_transaction(caps, [CapabilityRequest("ip")], driver)
                self.assertEqual(initial, driver.current["ip"])

    def test_external_and_production_capabilities_are_readonly(self):
        for mutation_class in ("external-governed", "production-governed"):
            with self.subTest(mutation_class=mutation_class):
                caps = {
                    "remote": capability(
                        mutation_class=mutation_class,
                        prepare="create-resource",
                    )
                }
                with self.assertRaisesRegex(RuntimePolicyError, "prepare-readonly"):
                    RuntimePlanner(policy(caps))

    def test_secret_state_is_redacted_from_evidence(self):
        caps = {"auth": capability()}
        driver = FakeDriver({"auth": {"satisfied": True, "api_token": "do-not-write"}})
        _, evidence = self.run_transaction(caps, [CapabilityRequest("auth")], driver)
        self.assertEqual("[REDACTED]", evidence["initial_state"]["auth"]["api_token"])
        self.assertNotIn("do-not-write", json.dumps(evidence))

    def test_worktree_evidence_is_non_authoritative(self):
        caps = {"check": capability()}
        _, evidence = self.run_transaction(
            caps,
            [CapabilityRequest("check")],
            FakeDriver({"check": {"satisfied": True}}),
            authoritative=True,
        )
        self.assertEqual("worktree", evidence["source_kind"])
        self.assertFalse(evidence["authoritative"])

    def test_exact_sha_evidence_is_sha_bound(self):
        caps = {"check": capability()}
        _, evidence = self.run_transaction(
            caps,
            [CapabilityRequest("check")],
            FakeDriver({"check": {"satisfied": True}}),
            source_kind="exact-sha",
            authoritative=True,
        )
        self.assertEqual("a" * 40, evidence["source_sha"])
        self.assertTrue(evidence["authoritative"])

    def test_unknown_capability_and_cycle_fail_closed(self):
        planner = RuntimePlanner(policy({"a": capability()}))
        with self.assertRaisesRegex(RuntimePolicyError, "unknown runtime capability"):
            planner.resolve([CapabilityRequest("missing")])
        with self.assertRaisesRegex(RuntimePolicyError, "cycle"):
            RuntimePlanner(
                policy(
                    {
                        "a": capability(requires=["b"]),
                        "b": capability(requires=["a"]),
                    }
                )
            )

    def test_central_policy_safety_contract_validates(self):
        validate_runtime_policy(policy({"check": capability()}))


class RuntimeOrchestrationGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = yaml.safe_load(
            (ROOT / "architecture.lock.yaml").read_text(encoding="utf-8")
        )
        cls.contract_path = (
            ROOT / cls.lock["machine_contracts"]["qualification_execution_policy"]
        )
        cls.contract = yaml.safe_load(cls.contract_path.read_text(encoding="utf-8"))

    def test_single_runtime_authority_is_the_registered_execution_policy(self):
        self.assertEqual(
            "config/contracts/qualification-execution-policy.yaml",
            self.lock["machine_contracts"]["qualification_execution_policy"],
        )
        runtime = self.contract["runtime_orchestration"]
        self.assertIs(True, runtime["single_authority"])
        parallel_contracts = [
            path
            for path in (ROOT / "config" / "contracts").glob(
                "*runtime*orchestration*.yaml"
            )
            if path != self.contract_path
        ]
        self.assertEqual([], parallel_contracts)

    def test_capability_references_and_mutation_compensation_are_governed(self):
        runtime = self.contract["runtime_orchestration"]
        names = set(runtime["capabilities"])
        for gate_name, gate in self.contract["gates"].items():
            for item in gate.get("runtime_capabilities", []):
                name = item if isinstance(item, str) else item["name"]
                self.assertIn(name, names, gate_name)
        for name, spec in runtime["capabilities"].items():
            if spec["mutation_class"] in {"local-ephemeral", "local-virtualization"}:
                self.assertNotEqual("none", spec["operations"]["restore"], name)
                self.assertNotEqual("none", spec["operations"]["verify_restore"], name)

    def test_requirements_are_gate_driven_not_milestone_profiles(self):
        source = (ROOT / "scripts" / "repoctl.py").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"if\s+milestone\s*==")
        runtime_files = [
            path.name.lower()
            for path in (ROOT / "config").rglob("*.yaml")
            if "runtime" in path.name.lower() and "orchestration" in path.name.lower()
        ]
        self.assertEqual([], runtime_files)
        self.assertEqual(
            {"inherit_from_selected_gates": True},
            self.contract["workflows"]["qualification_proof"]["runtime_capabilities"],
        )

    def test_dynamic_runtime_state_is_always_fresh_and_evidence_is_ignored(self):
        dynamic = set(self.contract["dynamic_state"]["always_fresh"])
        self.assertTrue(
            {
                "docker-runtime-state",
                "kubernetes-runtime-state",
                "network-state",
                "secrets-and-authentication",
            }.issubset(dynamic)
        )
        runtime = self.contract["runtime_orchestration"]
        self.assertEqual("forbidden", runtime["rules"]["dynamic_state_cache"])
        self.assertEqual(".context", runtime["rules"]["evidence_root"])
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(".context", ignore)

    def test_product_gate_declares_runtime_and_service_does_not_reconcile_it(self):
        product = self.contract["gates"]["service:*"]["runtime_capabilities"]
        self.assertEqual("testcontainers", product[0]["name"])
        source = (ROOT / "scripts" / "repoctl.py").read_text(encoding="utf-8")
        start = source.index("def service_check(")
        end = source.index("\ndef security(", start)
        service_source = source[start:end]
        self.assertNotIn('run(["docker", "info"]', service_source)
        self.assertNotIn("net.ipv4.ip_forward", service_source)


if __name__ == "__main__":
    unittest.main()
