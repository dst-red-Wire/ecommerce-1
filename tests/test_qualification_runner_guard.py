"""Exercise trusted admission against real, isolated candidate repositories."""

import os
import importlib.util
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
            [shutil.which("git", path=os.defpath), *args],
            cwd=self.repo,
            env=self.env,
            text=True,
            stderr=subprocess.DEVNULL,
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

    def test_candidate_git_on_path_never_executes_in_trusted_guard(self):
        marker = self.directory / "candidate-git-executed"
        self.write("git", f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n")
        (self.repo / "git").chmod(0o755)
        self.commit()
        alias = self.directory / "alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        for entry in (".", str(self.repo), str(alias)):
            with self.subTest(entry=entry):
                self.env["PATH"] = entry + os.pathsep + os.defpath
                result = self.admit()
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertFalse(marker.exists())

    def test_canonical_collection_pin_admission_rejects_any_additional_mutation(self):
        spec = importlib.util.spec_from_file_location("trusted_runner_guard", self.guard)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        path = "platform/ansible/requirements.yml"
        before = subprocess.check_output(
            [shutil.which("git", path=os.defpath), "show", "91c636997a3d62595c65f815319c1342c93ea956:" + path],
            cwd=ROOT,
            env=self.env,
        )
        after = (ROOT / path).read_bytes()
        guard.validate_runner_changes({path: before}, {path: after})
        with self.assertRaisesRegex(AssertionError, "unapproved base-relative"):
            guard.validate_runner_changes({path: before}, {path: after + b"# extra candidate mutation\n"})

    def test_replacement_refs_cannot_hide_real_object_changes(self):
        self.write("platform/ansible/qualification-egress.yml", "---\n- hosts: localhost\n  tasks: []\n")
        self.commit()
        self.git("replace", self.base, "HEAD")
        self.assertEqual("", self.git("diff", "--name-only", self.base, "HEAD"))
        result = self.admit()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("replacement refs are forbidden", result.stdout)
