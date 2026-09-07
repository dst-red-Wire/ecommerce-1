from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "platform/ansible/roles/developer_workstation/tasks/main.yml"
ANSIBLE_PLAYBOOK = shutil.which("ansible-playbook")


class DeveloperGitDefaultsTest(unittest.TestCase):
    def run_playbook(self, repo_root: Path) -> subprocess.CompletedProcess[str]:
        playbook = repo_root / "git-defaults-test.yml"
        playbook.write_text(
            textwrap.dedent(
                f"""\
                ---
                - hosts: localhost
                  connection: local
                  gather_facts: false
                  vars:
                    repo_root: {repo_root}
                  tasks:
                    - name: Reconcile only repository Git defaults
                      ansible.builtin.include_tasks: {TASKS}
                      loop: [outer-git-defaults-task]
                      tags: [git]
                """
            ),
            encoding="utf-8",
        )
        return subprocess.run(
            [ANSIBLE_PLAYBOOK, "-i", "localhost,", "-c", "local", str(playbook), "--tags", "git"],
            text=True,
            capture_output=True,
            check=False,
        )

    def create_repo(self, root: Path, defaults: str) -> Path:
        repo = root / "repo"
        (repo / "config/workstation").mkdir(parents=True)
        (repo / "config/workstation/git-local.conf").write_text(defaults, encoding="utf-8")
        for command in (
            ["git", "init", str(repo)],
            ["git", "-C", str(repo), "config", "user.name", "Regression Test"],
            ["git", "-C", str(repo), "config", "user.email", "regression@example.invalid"],
            ["git", "-C", str(repo), "remote", "add", "origin", "https://example.invalid/ecommerce-1.git"],
        ):
            subprocess.run(command, check=True, capture_output=True, text=True)
        return repo

    @unittest.skipUnless(ANSIBLE_PLAYBOOK, "ansible-playbook is required")
    def test_comments_are_filtered_before_validation_and_defaults_are_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.create_repo(
                Path(directory),
                "# Repository-owned Git defaults\n   # Indented comment\n\ncore.autocrlf=input\npull.ff=only\n",
            )

            first = self.run_playbook(repo)
            self.assertEqual(0, first.returncode, first.stdout + first.stderr)
            self.assertIn(
                "changed: [localhost] => (item=core.autocrlf=input)",
                first.stdout,
            )
            self.assertIn(
                "changed: [localhost] => (item=pull.ff=only)",
                first.stdout,
            )
            # The recap counts changed tasks, not changed loop items.
            self.assertIn("changed=1", first.stdout)

            second = self.run_playbook(repo)
            self.assertEqual(0, second.returncode, second.stdout + second.stderr)
            self.assertIn("changed=0", second.stdout)
            self.assertNotIn(
                "changed: [localhost] => (item=core.autocrlf=input)",
                second.stdout,
            )
            self.assertNotIn(
                "changed: [localhost] => (item=pull.ff=only)",
                second.stdout,
            )

    @unittest.skipUnless(ANSIBLE_PLAYBOOK, "ansible-playbook is required")
    def test_core_bare_true_is_repaired_before_normal_git_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.create_repo(Path(directory), "core.autocrlf=input\npull.ff=only\n")
            subprocess.run(["git", "-C", str(repo), "config", "core.bare", "true"], check=True)

            result = self.run_playbook(repo)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            repaired = subprocess.check_output(
                ["git", "-C", str(repo), "config", "--local", "--get", "core.bare"], text=True
            ).strip()
            self.assertEqual("false", repaired)
            self.assertEqual(
                "true",
                subprocess.check_output(["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"], text=True).strip(),
            )

    @unittest.skipUnless(ANSIBLE_PLAYBOOK, "ansible-playbook is required")
    def test_malformed_default_fails_with_its_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.create_repo(Path(directory), "valid.key=value\nmalformed-entry\n")

            result = self.run_playbook(repo)
            output = " ".join((result.stdout + result.stderr).split())

            self.assertNotEqual(0, result.returncode)
            self.assertIn("malformed-entry", output)
            self.assertIn("expected a non-empty key", output)
            self.assertIn("key=value form", output)

    def test_git_default_workflow_uses_explicit_loop_variables(self):
        tasks = TASKS.read_text(encoding="utf-8")
        workflow = tasks.split("- name: Read repository Git default lines", 1)[1].split(
            "- name: Validate Git identity fields without inventing identity", 1
        )[0]

        self.assertIn("developer_git_default_lines", workflow)
        self.assertIn("git_default_line | trim | length > 0", workflow)
        self.assertIn("not (git_default_line | trim).startswith('#')", workflow)
        self.assertNotIn("reject('match'", workflow)
        self.assertIn('loop_var: git_default_line', workflow)
        self.assertIn('loop_var: git_default_entry', workflow)
        self.assertIn('loop_var: git_default_result', workflow)
        self.assertIn("git_default_result.git_default_entry", workflow)
        self.assertNotIn("item.item", workflow)
        self.assertNotIn("{{ item", workflow)


if __name__ == "__main__":
    unittest.main()
