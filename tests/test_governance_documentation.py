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
                r"fluent-bit|opensearch-logs|\bprometheus\b",
            ],
        }
        for relative, forbidden_terms in checks.items():
            text = (ROOT / relative).read_text(encoding="utf-8")
            for forbidden in forbidden_terms:
                with self.subTest(relative=relative, forbidden=forbidden):
                    self.assertIsNone(re.search(forbidden, text, flags=re.IGNORECASE))


if __name__ == "__main__":
    unittest.main()
