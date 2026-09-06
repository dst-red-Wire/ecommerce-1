import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl", ROOT / "scripts/repoctl.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class DeveloperStateFastPathTest(unittest.TestCase):
    def test_exact_state_skips_ansible_startup(self):
        with mock.patch.object(MOD, "developer_state_ready", return_value=True), \
             mock.patch.object(MOD, "require", side_effect=AssertionError("Ansible must not start")):
            MOD.ensure_developer("go,cgo,sqlc,docker")

    def test_shell_policy_uses_effective_worktree_not_stale_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)

            legacy = repo / "legacy.sh"
            legacy.write_text("#!/bin/sh\n", encoding="utf-8")
            subprocess.run(["git", "add", "legacy.sh"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repo, check=True)
            self.assertEqual(["legacy.sh"], MOD.repository_shell_paths(repo))

            # Migration deletes tracked Shell files before staging/commit. The gate
            # must evaluate WORKTREE and therefore accept this deletion immediately.
            legacy.unlink()
            self.assertEqual([], MOD.repository_shell_paths(repo))

            # A new untracked Shell helper must still fail closed.
            new_shell = repo / "new-helper.sh"
            new_shell.write_text("#!/bin/sh\n", encoding="utf-8")
            self.assertEqual(["new-helper.sh"], MOD.repository_shell_paths(repo))

            # Ignored dependency/cache content is outside repository policy scope.
            (repo / ".gitignore").write_text("ignored.sh\n", encoding="utf-8")
            (repo / "ignored.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            self.assertEqual(["new-helper.sh"], MOD.repository_shell_paths(repo))

    def test_exact_versions_are_detected_without_ansible(self):
        pins = {"GO_VERSION": "1.26.6", "SQLC_VERSION": "1.31.1"}
        commands = {"node": "/bin/node", "corepack": "/bin/corepack", "go": "/bin/go", "gofmt": "/bin/gofmt", "cc": "/bin/cc", "sqlc": "/bin/sqlc", "docker": "/bin/docker"}

        def fake_which(name):
            return commands.get(name)

        def fake_run(cmd, **kwargs):
            if cmd[0] == "/bin/node":
                return subprocess.CompletedProcess(cmd, 0, "v24.20.0\n", "")
            if cmd[0] == "/bin/go":
                return subprocess.CompletedProcess(cmd, 0, "go version go1.26.6 linux/amd64\n", "")
            if cmd[0] == "/bin/sqlc":
                return subprocess.CompletedProcess(cmd, 0, "v1.31.1\n", "")
            if cmd[0] == "/bin/docker":
                return subprocess.CompletedProcess(cmd, 0, "", "")
            raise AssertionError(cmd)

        with mock.patch.object(MOD, "pinned_versions", return_value=pins), \
             mock.patch.object(MOD.shutil, "which", side_effect=fake_which), \
             mock.patch.object(MOD, "run", side_effect=fake_run):
            self.assertTrue(MOD.developer_state_ready("node,go,cgo,sqlc,docker"))


if __name__ == "__main__":
    unittest.main()
