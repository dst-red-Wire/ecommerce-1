import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class FrontendGoPolicyTest(unittest.TestCase):
    def test_node_application_artifacts_absent_from_frontend(self):
        tracked = subprocess.check_output(["git", "ls-files", "frontend"], cwd=ROOT, text=True).splitlines()
        untracked = subprocess.check_output(
            ["git", "ls-files", "--others", "--exclude-standard", "frontend"], cwd=ROOT, text=True
        ).splitlines()
        names = {
            "package.json",
            "pnpm-lock.yaml",
            "package-lock.json",
            "yarn.lock",
            ".node-version",
            ".nvmrc",
            "turbo.json",
            "pnpm-workspace.yaml",
        }
        bad = [path for path in tracked + untracked if Path(path).name in names or Path(path).suffix in {".ts", ".tsx"}]
        self.assertEqual([], bad)

    def test_templ_and_vendored_htmx_are_present(self):
        module = (ROOT / "frontend/go.mod").read_text(encoding="utf-8")
        template = (ROOT / "frontend/internal/web/layout.templ").read_text(encoding="utf-8")
        htmx = (ROOT / "frontend/internal/web/assets/htmx.min.js").read_text(encoding="utf-8")
        self.assertIn("github.com/a-h/templ", module)
        self.assertIn("templ layout", template)
        self.assertIn('version:"2.0.4"', htmx)
