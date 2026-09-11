from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_node_policy", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class GlobalNodePolicyTest(unittest.TestCase):
    def repository(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        return temporary, root

    def assert_rejected(self, root: Path):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, REPOCTL.node_policy(root))

    def test_tracked_node_file_is_rejected(self):
        temporary, root = self.repository()
        with temporary:
            (root / "package.json").write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "add", "package.json"], cwd=root, check=True)
            self.assert_rejected(root)

    def test_untracked_node_file_is_rejected(self):
        temporary, root = self.repository()
        with temporary:
            (root / "component.tsx").write_text("export default 1\n", encoding="utf-8")
            self.assert_rejected(root)

    def test_ansible_node_install_is_rejected(self):
        temporary, root = self.repository()
        with temporary:
            path = root / "platform/ansible/roles/tool/tasks/main.yml"
            path.parent.mkdir(parents=True)
            path.write_text("- name: Install runtime\n  ansible.builtin.command: node --version\n", encoding="utf-8")
            self.assert_rejected(root)

    def test_repoctl_pnpm_command_is_rejected(self):
        temporary, root = self.repository()
        with temporary:
            path = root / "scripts/repoctl.py"
            path.parent.mkdir(parents=True)
            path.write_text('run(["pnpm", "install"])\n', encoding="utf-8")
            self.assert_rejected(root)

    def test_makefile_nx_target_is_rejected(self):
        temporary, root = self.repository()
        with temporary:
            (root / "Makefile").write_text("nx:\n\t@echo graph\n", encoding="utf-8")
            self.assert_rejected(root)

    def test_repository_is_native_only(self):
        self.assertEqual(0, REPOCTL.node_policy(ROOT))


if __name__ == "__main__":
    unittest.main()
