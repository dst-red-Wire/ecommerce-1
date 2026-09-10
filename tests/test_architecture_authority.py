"""Mutation tests for root authority and active-document regression prevention."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("authority", ROOT / "scripts/architecture_authority.py")
authority = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(authority)


class ArchitectureAuthorityTest(unittest.TestCase):
    def test_repository(self):
        self.assertEqual([], authority.validate(ROOT))

    def test_active_superseded_statements(self):
        for statement in (
            "Exactly 17 services.", "17 Go services + Storefront/Admin workloads.",
            "exactly 17 backend service directories", "No checkout service.",
            "PROD frontend target: Next.js.", "ATS -> Storefront Next.js",
            "Dataset versioning: DVC + Git + SeaweedFS S3.",
            "BASELINE_V2.md is the canonical architecture authority.",
            "Active exact index: EXACT_TOPOLOGY_V2.md.",
            "Next.js is the target PROD frontend runtime after migration.",
            "DVC is the active dataset versioner; lakeFS was rejected.",
            "Exactly 17 services; the historical diagram is attached.",
            "BASELINE_V2.md is canonical; the prior plan is superseded.",
        ):
            with self.subTest(statement=statement):
                self.assertTrue(authority.documentation_errors(statement))

    def test_historical_context_does_not_exempt_later_active_claim(self):
        self.assertEqual([], authority.documentation_errors(
            "DVC is superseded by lakeFS.\nNext.js is the migration source.\n"
            "Historical: exactly 17 services."
        ))
        self.assertTrue(authority.documentation_errors(
            "Historical: DVC was used.\nDataset versioning: DVC."
        ))
        self.assertEqual([], authority.documentation_errors("DVC has been superseded by lakeFS."))

    def test_active_superseded_platform_defaults_are_rejected(self):
        for statement in ("GitOps CD: FluxCD.", "Progressive delivery: Flagger.",
                          "Object storage default: MinIO Community Edition.",
                          "Logging baseline: Loki.", "SIEM: Splunk.",
                          "General logging pipeline: Fluent Bit."):
            with self.subTest(statement=statement):
                self.assertTrue(authority.documentation_errors(statement))

    def test_operational_service_counts_are_not_topology_claims(self):
        self.assertEqual([], authority.documentation_errors("Incident impact: 17 services were unavailable."))
        self.assertEqual([], authority.documentation_errors("17 backend services are complete; two remain."))

    def copy_repository(self, directory):
        root = Path(directory)
        for relative in ("architecture.lock.yaml", "AGENTS.md", "README.md"):
            shutil.copy2(ROOT / relative, root / relative)
        shutil.copytree(ROOT / "config", root / "config")
        shutil.copytree(ROOT / "docs", root / "docs")
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        return root

    def test_mutated_lock_is_rejected(self):
        mutations = {
            "version": ("version: 5", "version: 2"),
            "index": ("docs/architecture/EXACT_TOPOLOGY_V5.md", "docs/architecture/EXACT_TOPOLOGY_V2.md"),
            "dataset": ("dataset_versioner: lakefs", "dataset_versioner: dvc"),
            "dag": ("M3-preprod-infrastructure: [M2-5-persistent-mgmt-bootstrap]",
                    "M3-preprod-infrastructure: [M2-golden-service-product]"),
            "contract": ("resilience_governance: config/contracts/resilience-governance.yaml",
                         "removed_resilience: config/contracts/resilience-governance.yaml"),
            "dns_ttl": ("critical_ttl_seconds: 60", "critical_ttl_seconds: 120"),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            original = (root / "architecture.lock.yaml").read_text()
            for name, (before, after) in mutations.items():
                with self.subTest(name=name):
                    self.assertIn(before, original)
                    (root / "architecture.lock.yaml").write_text(original.replace(before, after, 1))
                    self.assertTrue(authority.validate(root))

    def test_delivery_guidance_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.assertEqual([], authority.validate(root))
            agents = root / "AGENTS.md"
            original = agents.read_text()
            agents.write_text(original.replace("M2.5 -> M3 PREPROD infra", "M1 -> M3 PREPROD infra"))
            self.assertTrue(any("build sequence" in error for error in authority.validate(root)))
            agents.write_text(original)
            plan = root / "docs/project/MASTER_EXECUTION_PLAN.md"
            original_plan = plan.read_text()
            plan.write_text(original_plan.replace("M2.5 PROVEN; exact infrastructure", "M1 PROVEN; exact infrastructure"))
            self.assertTrue(any("gate M3" in error for error in authority.validate(root)))

    def test_exact_contract_mutations_are_rejected(self):
        mutations = (
            ("config/contracts/security-trust-zones.yaml", "  Z6: backup-evidence-dfir\n", ""),
            ("config/contracts/security-trust-zones.yaml", "  default: deny", "  default: allow"),
            ("config/contracts/security-trust-zones.yaml", "image-layers, ci-logs", "image-layers, ci-output"),
            ("config/contracts/resilience-governance.yaml", "  destroy_required_forensic_evidence: forbidden",
             "  destroy_required_forensic_evidence: allowed"),
            ("config/contracts/resilience-governance.yaml", "    - dns-gslb-change", ""),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            for relative, before, after in mutations:
                with self.subTest(relative=relative, invariant=before.strip()):
                    path = root / relative
                    original = path.read_text()
                    self.assertIn(before, original)
                    path.write_text(original.replace(before, after, 1))
                    self.assertTrue(any(relative in error for error in authority.validate(root)))
                    path.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_observability_guidance_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            agents = root / "AGENTS.md"
            original = agents.read_text()
            agents.write_text(original.replace("- Infrastructure/application logs: VictoriaLogs.",
                                               "- General logging pipeline: Fluent Bit + Data Prepper + OpenSearch."))
            self.assertTrue(any("general logging" in error for error in authority.validate(root)))
            agents.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_l2_context_contract_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            router = root / "config/context/router.yaml"
            original = router.read_text()
            router.write_text(original.replace("      - config/contracts/resilience-governance.yaml\n", "", 1))
            self.assertTrue(any("L2 context" in error for error in authority.validate(root)))
            router.write_text(original)
            self.assertEqual([], authority.validate(root))

    def test_new_documents_and_missing_authority_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            self.assertEqual([], authority.validate(root))
            new = root / "new-guide.md"
            new.write_text("Exactly 17 services.")
            self.assertTrue(any("new-guide.md" in e for e in authority.validate(root)))
            new.unlink()
            (root / "architecture.lock.yaml").unlink()
            self.assertTrue(authority.validate(root))


if __name__ == "__main__":
    unittest.main()
