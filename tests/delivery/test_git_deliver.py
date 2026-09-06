from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / 'scripts/git-deliver.sh').read_text()
MAKEFILE = (ROOT / 'Makefile').read_text()
WINGET = (ROOT / '.config/configuration.winget').read_text()

class DeliverContractTests(unittest.TestCase):
    def test_make_target_exists(self):
        self.assertIn('deliver:', MAKEFILE)
        self.assertIn('./scripts/git-deliver.sh', MAKEFILE)

    def test_never_merges_or_force_pushes(self):
        self.assertNotIn('gh pr merge', SCRIPT)
        self.assertNotIn('--force', SCRIPT)
        self.assertNotIn('push -f', SCRIPT)

    def test_avoids_duplicate_pull_requests(self):
        self.assertIn('pr list --head', SCRIPT)

    def test_pr_is_created_with_explicit_base_and_head(self):
        self.assertIn('pr create --base', SCRIPT)
        self.assertIn('--head "$branch"', SCRIPT)

    def test_github_cli_is_reconciled(self):
        self.assertIn('id: GitHub.cli', WINGET)

if __name__ == '__main__':
    unittest.main()
