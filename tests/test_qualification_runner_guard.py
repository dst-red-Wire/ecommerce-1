"""Exercise trusted admission against real, isolated candidate repositories."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TrustedRunnerGuardTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.repo = self.directory / "candidate"
        self.repo.mkdir()
        self.guard = self.directory / "trusted-guard.py"
        shutil.copyfile(ROOT / "scripts/qualification_runner_guard.py", self.guard)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.write("platform/ansible/qualification-egress.yml", "---\n[]\n")
        self.write("platform/ansible/roles/qualification_proxy_client/tasks/main.yml", "---\n[]\n")
        self.write("scripts/qualification_runner_guard.py", "raise SystemExit(0)\n")
        self.commit()
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(
            ["git", *args], cwd=self.repo, env=self.env, text=True, stderr=subprocess.DEVNULL
        )

    def write(self, relative, content):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def admit(self):
        return subprocess.run(
            [
                sys.executable,
                "-I",
                str(self.guard),
                "--repo",
                str(self.repo),
                "--base",
                self.base,
                "--head",
                self.git("rev-parse", "HEAD").strip(),
            ],
            env=self.env,
            text=True,
            capture_output=True,
        )

    def test_trusted_guard_ignores_candidate_validator_and_rejects_controller_change(self):
        self.assertEqual(0, self.admit().returncode)
        self.write("platform/ansible/qualification-egress.yml", "---\n- hosts: localhost\n  tasks: []\n")
        self.commit()
        result = self.admit()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("unapproved base-relative runner change", result.stdout)

    def test_proxy_role_change_is_in_controller_execution_closure(self):
        self.write("platform/ansible/roles/qualification_proxy_client/tasks/main.yml", "---\n- shell: unapproved\n")
        self.commit()
        self.assertNotEqual(0, self.admit().returncode)

    def test_replacement_refs_cannot_hide_real_object_changes(self):
        self.write("platform/ansible/qualification-egress.yml", "---\n- hosts: localhost\n  tasks: []\n")
        self.commit()
        self.git("replace", self.base, "HEAD")
        self.assertEqual("", self.git("diff", "--name-only", self.base, "HEAD"))
        result = self.admit()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("replacement refs are forbidden", result.stdout)

    def test_ansible_clone_fetches_head_reachable_only_through_pr_ref(self):
        import shlex
        from ansible.modules import git as ansible_git
        import yaml

        tasks = yaml.safe_load((ROOT / "platform/ansible/qualification-runner.yml").read_text())[0]["post_tasks"]
        parameters = next(task["ansible.builtin.git"] for task in tasks if "ansible.builtin.git" in task)
        self.assertEqual("{{ qualification_pr_head }}", parameters["refspec"])
        remote = self.directory / "remote.git"
        subprocess.run(["git", "init", "--bare", str(remote)], env=self.env, capture_output=True, check=True)
        self.git("remote", "add", "origin", remote.as_uri())
        self.git("push", "origin", "HEAD:refs/heads/main")
        subprocess.run(["git", "symbolic-ref", "HEAD", "refs/heads/main"], cwd=remote, env=self.env, check=True)
        self.write("private-head.txt", "PR-only content\n")
        self.commit()
        head = self.git("rev-parse", "HEAD").strip()
        self.git("push", "origin", "HEAD:refs/pull/1/head")
        env = self.env
        commands = []

        class LocalGitModule:
            def run_command(module, command, check_rc=False, cwd=None):
                argv = shlex.split(command) if isinstance(command, str) else command
                commands.append(argv)
                result = subprocess.run(
                    argv,
                    cwd=cwd if cwd and Path(cwd).exists() else remote.parent,
                    env=env,
                    text=True,
                    capture_output=True,
                )
                if check_rc and result.returncode:
                    raise AssertionError(result.stderr)
                return result.returncode, result.stdout, result.stderr

            def fail_json(module, **kwargs):
                raise AssertionError(kwargs)

        destination = self.directory / "module-clone"
        module = LocalGitModule()
        ansible_git.clone(
            shutil.which("git"),
            module,
            remote.as_uri(),
            str(destination),
            "origin",
            None,
            head,
            False,
            None,
            head,
            None,
            False,
            None,
            {},
            [],
            False,
        )
        self.assertTrue(any(command[1:4] == ["fetch", "origin", head] for command in commands))
        subprocess.run(["git", "checkout", "--detach", head], cwd=destination, env=env, capture_output=True, check=True)
        self.assertEqual("PR-only content\n", (destination / "private-head.txt").read_text())
