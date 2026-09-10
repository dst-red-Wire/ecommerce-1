"""Mutation tests for root authority and active-document regression prevention."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

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
            "version": lambda lock: lock.update(version=2),
            "index": lambda lock: lock["topology_contracts"].update(exact_index="docs/architecture/EXACT_TOPOLOGY_V2.md"),
            "dataset": lambda lock: lock["mlops"].update(dataset_versioner="dvc"),
            "dag": lambda lock: lock["milestone_dependencies"]["M3-preprod-infrastructure"].append("M2-golden-service-product"),
            "contract": lambda lock: lock["machine_contracts"].pop("resilience_governance"),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_repository(directory)
            original = (root / "architecture.lock.yaml").read_text()
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    lock = yaml.safe_load(original)
                    mutate(lock)
                    (root / "architecture.lock.yaml").write_text(yaml.safe_dump(lock))
                    self.assertTrue(authority.validate(root))

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
