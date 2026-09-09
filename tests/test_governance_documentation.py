import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class GovernanceDocumentationTest(unittest.TestCase):
    def test_agent_policy_has_one_shell_authority_model(self):
        text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("Repeatable or stateful workstation and host changes belong to Ansible.", text)
        self.assertIn("Stateless repository orchestration belongs to `scripts/repoctl.py`.", text)
        self.assertNotIn("Write portable POSIX `sh`", text)
        self.assertNotIn("repository shell helpers", text)

    def test_active_docs_do_not_restore_legacy_automation(self):
        checks = {
            "README.md": r"scripts/ci-\*\.sh",
            "docs/project/CODEX_HANDOFFS.md": r"shared POSIX `sh` helpers|shared repository scripts factored",
            "docs/api/README.md": r"bootstrap CI Woodpecker",
        }
        for relative, forbidden in checks.items():
            with self.subTest(relative=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIsNone(re.search(forbidden, text, flags=re.IGNORECASE))

    def test_execution_authorities_do_not_restore_superseded_targets(self):
        checks = {
            "docs/architecture/BASELINE_V2.md": [
                r"DVC \+ Git/Gitea",
                r"Fluent Bit \+ Data Prepper \+ OpenSearch Logs",
            ],
            "docs/architecture/EXACT_TOPOLOGY_V2.md": [
                r"Exactly 17 Go services",
                r"No checkout service",
                r"Storefront Next\.js|Admin Next\.js",
                r"DVC/Git/SeaweedFS",
            ],
            "docs/project/CODEX_HANDOFFS.md": [
                r"exactly 17 backend",
                r"no checkout service",
                r"Cart -> Order -> Tax -> Fraud/Risk -> Payment",
                r"C\. `Shipping -> Tracking -> Returns -> Billing -> Notification`",
            ],
            "docs/architecture/DEPLOYMENT_DAG.md": [
                r"OTel Collector, Prometheus, Alertmanager, Grafana",
                r"Fluent Bit -> Data Prepper -> OpenSearch Logs",
            ],
            "config/infrastructure/deployment-waves.yaml": [
                r"fluent-bit|opensearch-logs|prometheus-server-tsdb",
            ],
        }
        for relative, forbidden_terms in checks.items():
            text = (ROOT / relative).read_text(encoding="utf-8")
            for forbidden in forbidden_terms:
                with self.subTest(relative=relative, forbidden=forbidden):
                    self.assertIsNone(re.search(forbidden, text, flags=re.IGNORECASE))

    def test_milestone_security_and_promotion_contracts_stay_aligned(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("M2.5 persistent MGMT bootstrap", agents)
        self.assertIn("M2.5 PROVEN -> M3 PREPROD infra", agents)
        self.assertIn("M2 + M4 -> M5 vertical slice", agents)

        master = (ROOT / "docs/project/MASTER_EXECUTION_PLAN.md").read_text(encoding="utf-8")
        self.assertIn("M1 PROVEN; M2.5 PROVEN for real PREPROD CREATE", master)
        self.assertIn("M1 -> M2", master)
        self.assertIn("M1 -> M2.5 -> M3 -> M4", master)
        self.assertIn("M2 + M4 -> M5 -> M6 -> M7 -> M8 -> M9", master)
        self.assertNotIn("M0 -> M1 -> { M2, M2.5 } -> M3", master)

        security = (ROOT / "docs/architecture/SECURITY_TRUST_ZONES.md").read_text(encoding="utf-8")
        self.assertIn("Exactly 19 Go backend services", security)
        self.assertNotIn("17 Go services + Storefront/Admin workloads", security)
        for component in [
            "VictoriaMetrics",
            "VictoriaLogs",
            "ClickHouse",
            "MongoDB (HyperDX metadata only)",
            "OpenSearch Security",
            "lakeFS/MLflow metadata",
        ]:
            self.assertIn(component, security)

        mlops = (ROOT / "docs/architecture/MLOPS_TOPOLOGY_V1.md").read_text(encoding="utf-8")
        self.assertIn("no automatic model promotion", mlops.lower())
        self.assertIn("a human approval is required", mlops.lower())

    def test_deployment_dag_requires_machine_graph_and_runtime_binding(self):
        text = (ROOT / "docs/architecture/DEPLOYMENT_DAG.md").read_text(encoding="utf-8")
        self.assertIn("is the machine authority for graph topology", text)
        self.assertIn("duplicate wave IDs", text)
        self.assertIn("unknown `requires` targets", text)
        self.assertIn("cycles", text)
        self.assertIn("unreachable waves", text)
        self.assertIn("must not be invented", text.lower())

    def test_m4_handoff_preserves_storage_first_dependency_order(self):
        text = (ROOT / "docs/project/CODEX_HANDOFFS.md").read_text(encoding="utf-8")
        m4 = text.split("## M4 prompt — Platform Baseline", 1)[1].split("## M5 prompt — Commerce Vertical Slice", 1)[0]
        seaweed = m4.index("SeaweedFS S3")
        observability_branch = [
            m4.index("observability operators"),
            m4.index("observability stateful stores"),
            m4.index("observability/security services"),
        ]
        stateful_branch = [
            m4.index("CloudNativePG"),
            m4.index("remaining stateful platform"),
            m4.index("IAM/edge"),
        ]
        self.assertTrue(all(position > seaweed for position in observability_branch + stateful_branch))
        self.assertEqual(observability_branch, sorted(observability_branch))
        self.assertEqual(stateful_branch, sorted(stateful_branch))
        self.assertIn("independent branches may proceed in parallel", m4)
        self.assertIn("`requires` graph", m4)

    def test_executable_handoffs_read_lock_before_baseline(self):
        for relative in [
            "docs/project/CODEX_HANDOFFS.md",
            "instruction/dev/PROMPT_IA_00_BOOTSTRAP_MONOREPO.md",
        ]:
            text = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(relative=relative):
                self.assertLess(text.index("architecture.lock.yaml"), text.index("BASELINE_V2.md"))


if __name__ == "__main__":
    unittest.main()
