from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "platform/ansible/roles/developer_workstation/tasks/main.yml"
ANSIBLE_PLAYBOOK = shutil.which("ansible-playbook")


@unittest.skipUnless(ANSIBLE_PLAYBOOK, "ansible-playbook is required")
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

    def test_comments_are_filtered_before_validation_and_defaults_are_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.create_repo(
                Path(directory),
                "# Repository-owned Git defaults\n   # Indented comment\n\ncore.autocrlf=input\npull.ff=only\n",
            )

            first = self.run_playbook(repo)
            self.assertEqual(0, first.returncode, first.stdout + first.stderr)
            self.assertIn("changed=2", first.stdout)

            second = self.run_playbook(repo)
            self.assertEqual(0, second.returncode, second.stdout + second.stderr)
            self.assertIn("changed=0", second.stdout)

    def test_malformed_default_fails_with_its_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self.create_repo(Path(directory), "valid.key=value\nmalformed-entry\n")

            result = self.run_playbook(repo)

            self.assertNotEqual(0, result.returncode)
            self.assertIn("malformed-entry", result.stdout + result.stderr)
            self.assertIn("expected a non-empty key", result.stdout + result.stderr)

    def test_validation_uses_only_explicitly_selected_active_defaults(self):
        tasks = TASKS.read_text(encoding="utf-8")
        selection = tasks.split("- name: Select active repository Git defaults", 1)[1].split(
            "- name: Validate repository Git defaults", 1
        )[0]
        validation = tasks.split("- name: Validate repository Git defaults", 1)[1].split(
            "- name: Read current repository-local Git defaults", 1
        )[0]

        self.assertIn("developer_git_default_lines", selection)
        self.assertIn("item | trim | length > 0", selection)
        self.assertIn("not (item | trim).startswith('#')", selection)
        self.assertNotIn("reject('match'", selection)
        self.assertIn('loop: "{{ developer_git_defaults }}"', validation)


if __name__ == "__main__":
    unittest.main()
