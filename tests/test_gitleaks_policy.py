import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class GitleaksPolicyTests(unittest.TestCase):
    def test_no_commit_wide_allowlist_exists(self):
        config = tomllib.loads((ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))
        for allowlist in config.get("allowlists", []):
            self.assertNotIn("commits", allowlist)

    def test_real_secret_in_same_source_path_remains_detectable(self):
        executable = shutil.which("gitleaks")
        self.assertIsNotNone(executable, "managed gitleaks capability is required for the security gate")
        value = "".join(("aB3dE5fG7hJ9kLmN", "2pQrS4tUvW6xYzA8", "bC0dE2fG4hJ6kL8m", "N0pQ2rS4tU6vW8x"))
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp, "scripts", "validate-architecture.rb")
            source.parent.mkdir()
            source.write_text(f'api_key = "{value}"\n', encoding="utf-8")
            proc = subprocess.run(
                [executable, "dir", "--config", str(ROOT / ".gitleaks.toml"), "--redact", "--no-banner", tmp],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(1, proc.returncode)
        self.assertNotIn(value, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
