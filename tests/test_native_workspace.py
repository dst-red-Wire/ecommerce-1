from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_workspace_test", ROOT / "scripts/native_workspace.py")
assert SPEC and SPEC.loader
WORKSPACE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKSPACE)


class NativeWorkspaceTests(unittest.TestCase):
    def test_wsl_requires_native_linux_filesystem(self):
        self.assertIsNone(
            WORKSPACE.workspace_error(ROOT, platform="linux", kernel_release="microsoft-WSL2", filesystem="ext4")
        )
        error = WORKSPACE.workspace_error(ROOT, platform="linux", kernel_release="microsoft-WSL2", filesystem="9p")
        self.assertIn("native Linux filesystem", error)

    def test_native_windows_execution_is_rejected(self):
        self.assertIn("WSL2", WORKSPACE.workspace_error(ROOT, platform="win32"))

    def test_regular_linux_runner_is_accepted(self):
        self.assertIsNone(WORKSPACE.workspace_error(ROOT, platform="linux", kernel_release="generic-linux"))

    def test_weakened_policy_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "architecture.lock.yaml").write_text(
                "repository_governance:\n  windows_workspace:\n    status: advisory\n",
                encoding="utf-8",
            )
            self.assertIn("policy drift", WORKSPACE.workspace_error(root, platform="linux"))


if __name__ == "__main__":
    unittest.main()
