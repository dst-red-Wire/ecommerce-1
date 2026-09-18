import os
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl", ROOT / "scripts/repoctl.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class DeveloperStateFastPathTest(unittest.TestCase):
    def setUp(self):
        # Git exports worktree-local variables to commit hooks. Temporary repositories
        # must not inherit those paths or mutate the caller's index/configuration.
        isolated = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        isolated.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        environment = mock.patch.dict(os.environ, isolated, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def test_ruby_runner_prerequisite_present_is_returned(self):
        with mock.patch.object(MOD.shutil, "which", return_value="/usr/bin/ruby"):
            self.assertEqual("/usr/bin/ruby", MOD.require("ruby"))

    def test_missing_ruby_raises_blocked_runner_prerequisite(self):
        with mock.patch.object(MOD.shutil, "which", return_value=None):
            with self.assertRaisesRegex(MOD.MissingRunnerPrerequisite, "runner prerequisite missing: ruby"):
                MOD.require("ruby")

    def test_terraform_check_prefers_tofu_when_both_providers_exist(self):
        calls = []

        def fake_which(command):
            return {"tofu": "/opt/bin/tofu", "terraform": "/opt/bin/terraform"}.get(command)

        with (
            mock.patch.object(pathlib.Path, "rglob", return_value=[MOD.ROOT / "platform/example.tf"]),
            mock.patch.object(MOD.shutil, "which", side_effect=fake_which),
            mock.patch.object(MOD, "run", side_effect=lambda argv, **kwargs: calls.append(argv)),
        ):
            self.assertEqual(0, MOD.terraform_check())

        self.assertTrue(calls)
        self.assertTrue(all(call[0] == "/opt/bin/tofu" for call in calls))

    def test_exact_state_skips_ansible_startup(self):
        with (
            mock.patch.object(MOD, "developer_state_ready", return_value=True),
            mock.patch.object(MOD, "require", side_effect=AssertionError("Ansible must not start")),
        ):
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

    def test_exact_managed_go_pair_is_detected_without_ansible(self):
        pins = {"NODE_VERSION": "24.20.0", "GO_VERSION": "1.26.6", "SQLC_VERSION": "1.31.1"}
        commands = {
            "node": "/bin/node",
            "corepack": "/bin/corepack",
            "cc": "/bin/cc",
            "sqlc": "/bin/sqlc",
            "docker": "/bin/docker",
        }

        def fake_which(name):
            return commands.get(name)

        def fake_run(cmd, **kwargs):
            if cmd[0] == "/bin/node":
                return subprocess.CompletedProcess(cmd, 0, "v24.20.0\n", "")
            if cmd[0].endswith("/.local/bin/go"):
                return subprocess.CompletedProcess(cmd, 0, "go version go1.26.6 linux/amd64\n", "")
            if cmd[0] == "/bin/sqlc":
                return subprocess.CompletedProcess(cmd, 0, "v1.31.1\n", "")
            if cmd[0] == "/bin/docker":
                return subprocess.CompletedProcess(cmd, 0, "", "")
            raise AssertionError(cmd)

        with tempfile.TemporaryDirectory() as home:
            managed = Path(home) / ".local" / "bin"
            managed.mkdir(parents=True)
            for name in ("go", "gofmt"):
                (managed / name).touch(mode=0o755)
            with (
                mock.patch.object(MOD.Path, "home", return_value=Path(home)),
                mock.patch.object(MOD, "pinned_versions", return_value=pins),
                mock.patch.object(MOD.shutil, "which", side_effect=fake_which),
                mock.patch.object(MOD, "run", side_effect=fake_run),
            ):
                self.assertTrue(MOD.developer_state_ready("node,go,cgo,sqlc,docker"))

    def test_stale_managed_go_is_rejected_even_when_system_go_is_correct(self):
        with tempfile.TemporaryDirectory() as home:
            managed = Path(home) / ".local" / "bin"
            managed.mkdir(parents=True)
            for name in ("go", "gofmt"):
                (managed / name).touch(mode=0o755)

            def fake_run(command, **_kwargs):
                self.assertEqual(str(managed / "go"), command[0])
                return subprocess.CompletedProcess(command, 0, "go version go1.25.0 linux/amd64\n", "")

            with (
                mock.patch.object(MOD.Path, "home", return_value=Path(home)),
                mock.patch.object(MOD, "pinned_versions", return_value={"GO_VERSION": "1.26.6"}),
                mock.patch.object(MOD.shutil, "which", return_value="/usr/bin/go"),
                mock.patch.object(MOD, "run", side_effect=fake_run),
            ):
                self.assertFalse(MOD.developer_state_ready("go"))


if __name__ == "__main__":
    unittest.main()
