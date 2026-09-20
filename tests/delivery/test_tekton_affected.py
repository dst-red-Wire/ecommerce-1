from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TektonAffectedContractTests(unittest.TestCase):
    def read(self, path: str) -> str:
        return (ROOT / path).read_text(encoding="utf-8")

    def test_top_level_pipeline_fans_out_only_classifier_results(self):
        pipeline = self.read("platform/tekton/pipelines/affected.yaml")
        self.assertIn("name: ecommerce-affected", pipeline)
        self.assertIn("$(tasks.classify.results.components[*])", pipeline)
        self.assertIn("$(tasks.classify.results.global-gates[*])", pipeline)
        self.assertIn("name: global-gates", pipeline)
        self.assertIn("name: max-workers", pipeline)
        self.assertIn("value: $(params.max-workers)", pipeline)
        self.assertIn("finally:", pipeline)
        self.assertIn("name: finalize-evidence", pipeline)

    def test_tekton_uses_repository_controller_not_shell_wrappers(self):
        paths = [
            "platform/tekton/tasks/affected-components.yaml",
            "platform/tekton/tasks/global-gates.yaml",
            "platform/tekton/tasks/component-gates.yaml",
            "platform/tekton/tasks/finalize-evidence.yaml",
        ]
        for path in paths:
            content = self.read(path)
            self.assertIn("scripts/repoctl.py", content, path)
            self.assertNotIn(".sh", content, path)

    def test_ci_topology_delegates_execution_to_central_policy(self):
        topology = self.read("config/contracts/ci-topology.yaml")
        self.assertIn(
            "execution_policy: config/contracts/qualification-execution-policy.yaml",
            topology,
        )

    def test_ci_evidence_contract_fails_closed(self):
        contract = self.read("config/contracts/ci-evidence.yaml")
        self.assertIn("signature_required: true", contract)
        self.assertIn("verification_failure_behavior: full-reexecution", contract)
        self.assertIn("missing_remote_evidence_behavior: full-reexecution", contract)
        self.assertIn("forge_status_binds_exact_commit_sha: true", contract)

    def test_finalizer_assembles_fanned_out_global_records_from_plan_v2(self):
        repoctl = self.read("scripts/repoctl.py")
        self.assertIn('for pattern in ("global-*.json", "component-*.json")', repoctl)
        self.assertIn('"schema_version": 2', repoctl)
        self.assertIn('"precomputed_records"', repoctl)
        self.assertIn("unexpected = set(by_gate) - expected", repoctl)
        self.assertNotIn('_record_path(directory, "global")', repoctl)

    def test_gate_evidence_contract_requires_execution_metadata(self):
        contract = self.read("config/contracts/ci-evidence.yaml")
        for field in (
            "execution",
            "cache_mode",
            "scope",
            "parallel_safe",
            "parallel_group",
            "started_at_monotonic_offset",
        ):
            self.assertIn(f"- {field}", contract)
        self.assertIn("- cache_key", contract)
        self.assertIn("- input_digest", contract)

    def test_runtime_requires_measured_bounded_parallelism(self):
        contract = self.read("config/contracts/tekton-trigger-runtime.yaml")
        self.assertIn("bounded_parallelism_required: true", contract)
        self.assertIn("enforcement: kubernetes-resourcequota-and-runner-pod-resources", contract)
        self.assertIn("hardcoded_concurrency_without_measurement_forbidden: true", contract)
        self.assertIn("performance_evidence_required_before_tuning: true", contract)
        self.assertIn("qualification_max_workers_parameter: max-workers", contract)
        self.assertIn("qualification_max_workers_env: ECOMMERCE_QUALIFICATION_MAX_WORKERS", contract)
        self.assertIn("bounded-execution-budget-proven", contract)

    def test_classifier_publishes_both_policy_driven_matrices(self):
        classifier = self.read("platform/tekton/tasks/affected-components.yaml")
        self.assertIn("name: global-gates", classifier)
        self.assertIn("$(results.global-gates.path)", classifier)
        global_task = self.read("platform/tekton/tasks/global-gates.yaml")
        self.assertIn("name: gate", global_task)
        self.assertIn("--gate", global_task)
        self.assertIn("$(params.gate)", global_task)

    def test_parallel_gate_taskruns_use_ephemeral_isolated_checkouts(self):
        for path in (
            "platform/tekton/tasks/global-gates.yaml",
            "platform/tekton/tasks/component-gates.yaml",
        ):
            content = self.read(path)
            self.assertIn("name: isolated-checkout", content, path)
            self.assertIn("emptyDir: {}", content, path)
            self.assertIn("--shared", content, path)
            self.assertIn("--no-checkout", content, path)
            self.assertIn("workingDir: /var/ecommerce-run/repository", content, path)
            self.assertIn("checkout, --quiet, --detach, $(params.head)", content, path)
            self.assertIn("$(workspaces.source.path)/$(params.record-dir)", content, path)
            self.assertNotIn(".sh", content, path)
        component = self.read("platform/tekton/tasks/component-gates.yaml")
        global_task = self.read("platform/tekton/tasks/global-gates.yaml")
        self.assertIn("name: ECOMMERCE_TOOL_HOME", global_task)
        self.assertIn(".context/cache/tool-home", global_task)
        self.assertIn("name: ECOMMERCE_EXECUTION_SCOPE", global_task)
        self.assertIn("name: ECOMMERCE_QUALIFICATION_MAX_WORKERS", global_task)
        self.assertIn("value: $(params.max-workers)", global_task)
        self.assertIn("name: ECOMMERCE_TOOL_HOME", component)
        self.assertIn(".context/cache/tool-home", component)
        self.assertIn("name: ECOMMERCE_EXECUTION_SCOPE", component)
        self.assertIn("name: ECOMMERCE_QUALIFICATION_MAX_WORKERS", component)
        self.assertIn("value: $(params.max-workers)", component)
        self.assertIn("name: GOCACHE", component)
        self.assertIn(".context/cache/go-build", component)
        self.assertIn("name: GOMODCACHE", component)
        self.assertIn(".context/cache/go-mod", component)


if __name__ == "__main__":
    unittest.main()
