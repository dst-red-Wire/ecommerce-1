from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


class DeliverContractTests(unittest.TestCase):
    def test_make_target_uses_native_controller(self):
        self.assertIn("deliver:", MAKEFILE)
        self.assertIn("scripts/repoctl.py deliver", MAKEFILE)
        self.assertNotIn("git-deliver.sh", MAKEFILE)

    def test_never_merges_or_force_pushes(self):
        self.assertNotIn("pr merge", CONTROLLER)
        self.assertNotIn("push -f", CONTROLLER)
        self.assertNotIn("--force-with-lease", CONTROLLER)

    def test_delivery_binds_exact_evidence_and_verifies_pr_head(self):
        self.assertIn("exact_commit_evidence", CONTROLLER)
        self.assertIn(".context", CONTROLLER)
        self.assertIn("PR head mismatch", CONTROLLER)
        self.assertIn("pr\",\"list", CONTROLLER.replace(" ", ""))


if __name__ == "__main__":
    unittest.main()
