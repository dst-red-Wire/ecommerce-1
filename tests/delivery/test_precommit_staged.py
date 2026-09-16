import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
from unittest import mock
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("staged_behavior", ROOT / "scripts/repoctl.py")
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class PrecommitStagedContractTest(unittest.TestCase):
    def test_hooks_declare_explicit_stages(self):
        config = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        self.assertIn("stages: [pre-commit]", config)
        self.assertIn("stages: [pre-push]", config)

    def test_fast_hook_materializes_only_the_index(self):
        controller = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        function = controller.split("def precommit()", 1)[1].split("\ndef prepush()", 1)[0]
        self.assertIn('"--cached"', function)
        self.assertIn("_materialize_staged_tree(snapshot)", function)
        self.assertNotIn("verify_change", function)
        self.assertIn('"gitleaks"', function)

    @contextlib.contextmanager
    def fixture(self):
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, env, clear=True):
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(
                    ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", *args],
                    cwd=root,
                    stderr=subprocess.DEVNULL,
                    text=True,
                ).strip()

            git("init")
            (root / ".gitleaks.toml").write_bytes((ROOT / ".gitleaks.toml").read_bytes())
            git("add", ".gitleaks.toml")
            git("commit", "-m", "Initialize fixture")
            with mock.patch.object(REPOCTL, "ROOT", root):
                yield root, git

    def test_partial_commit_preserves_index_and_unstaged_content(self):
        with self.fixture() as (root, git):
            path = root / "example.py"
            path.write_text("value = 1\n")
            git("add", "--", path.name)
            index = git("write-tree")
            path.write_text("def invalid(\n")
            self.assertEqual(0, REPOCTL.precommit())
            self.assertEqual(index, git("write-tree"))
            self.assertEqual("def invalid(\n", path.read_text())

    def test_replacement_head_cannot_hide_invalid_staged_change(self):
        with self.fixture() as (root, git):
            (root / "invalid.py").write_text("undefined_name()\n")
            git("add", "invalid.py")
            original = git("rev-parse", "HEAD")
            replacement = git("commit-tree", git("write-tree"), "-m", "Replacement fixture")
            git("replace", original, replacement)
            self.assertEqual("", git("diff", "--cached", "--name-only"))
            with self.assertRaises(RuntimeError):
                REPOCTL.precommit()

    def test_replacement_blob_cannot_change_indexed_bytes(self):
        with self.fixture() as (root, git):
            path = root / "invalid.py"
            path.write_text("undefined_name()\n")
            git("add", path.name)
            indexed = git("rev-parse", ":invalid.py")
            path.write_text("value = 1\n")
            replacement = git("hash-object", "-w", path.name)
            git("replace", indexed, replacement)
            with tempfile.TemporaryDirectory() as directory:
                REPOCTL._materialize_staged_tree(Path(directory))
                self.assertEqual("undefined_name()\n", (Path(directory) / path.name).read_text())
            with self.assertRaises(RuntimeError):
                REPOCTL.precommit()

    def test_filesystem_equivalent_index_paths_cannot_overwrite_a_blob(self):
        with self.fixture() as (root, git), tempfile.TemporaryDirectory() as directory:
            (root / "first").write_text("first indexed content")
            (root / "second").write_text("second indexed content")
            first = git("hash-object", "-w", "first")
            second = git("hash-object", "-w", "second")
            git("update-index", "--add", "--cacheinfo", f"100644,{first},CASE.txt")
            git("update-index", "--add", "--cacheinfo", f"100644,{second},case.txt")
            snapshot = Path(directory)
            original_open = Path.open
            original_chmod = Path.chmod

            def case_insensitive_chmod(path, *args, **kwargs):
                if path.parent == snapshot:
                    path = path.with_name(path.name.lower())
                return original_chmod(path, *args, **kwargs)

            def case_insensitive_open(path, mode="r", *args, **kwargs):
                if path.parent == snapshot:
                    path = path.with_name(path.name.lower())
                return original_open(path, mode, *args, **kwargs)

            with (
                mock.patch.object(Path, "open", case_insensitive_open),
                mock.patch.object(Path, "chmod", case_insensitive_chmod),
            ):
                with self.assertRaisesRegex(RuntimeError, "indexed paths collide"):
                    REPOCTL._materialize_staged_tree(snapshot)
            self.assertEqual("first indexed content", (snapshot / "case.txt").read_text())
            self.assertEqual(first, git("rev-parse", ":CASE.txt"))
            self.assertEqual(second, git("rev-parse", ":case.txt"))

    def test_directory_aliases_cannot_redirect_staged_linter_configuration(self):
        with self.fixture() as (root, git), tempfile.TemporaryDirectory() as directory:
            (root / "config").write_text('[tool.ruff.lint]\nignore = ["F821"]\n')
            (root / "bad").write_text("undefined_name()\n")
            config = git("hash-object", "-w", "config")
            bad = git("hash-object", "-w", "bad")
            git("update-index", "--add", "--cacheinfo", f"100644,{config},CASE/pyproject.toml")
            git("update-index", "--add", "--cacheinfo", f"100644,{bad},case/bad.py")
            snapshot = Path(directory)
            original_mkdir, original_stat = Path.mkdir, Path.stat

            def folded(path):
                if path.is_relative_to(snapshot):
                    return snapshot.joinpath(*(part.lower() for part in path.relative_to(snapshot).parts))
                return path

            def mkdir(path, *args, **kwargs):
                return original_mkdir(folded(path), *args, **kwargs)

            def stat(path, *args, **kwargs):
                return original_stat(folded(path), *args, **kwargs)

            with mock.patch.object(Path, "mkdir", mkdir), mock.patch.object(Path, "stat", stat):
                with self.assertRaisesRegex(RuntimeError, "directory aliases collide"):
                    REPOCTL._materialize_staged_tree(snapshot)
            self.assertEqual([], list(snapshot.rglob("*.py")))
            self.assertEqual([], list(snapshot.rglob("*.toml")))

    def test_non_utf8_staged_path_is_scanned_without_decoding_failure(self):
        with self.fixture() as (root, git):
            name = os.fsdecode(b"bad\xff.txt")
            (root / name).write_text("value = 1\n")
            git("add", "--", name)
            index = git("write-tree")
            self.assertEqual(0, REPOCTL.precommit())
            self.assertEqual(index, git("write-tree"))

    def test_staged_terraform_format_drift_is_rejected(self):
        with self.fixture() as (root, git):
            path = root / "main.tf"
            path.write_text('locals {\nvalue= "example"\n}\n')
            git("add", "main.tf")
            path.write_text('locals {\n  value = "example"\n}\n')
            with self.assertRaises(RuntimeError):
                REPOCTL.precommit()

    def test_staged_ansible_configuration_cannot_execute_inventory_or_custom_rules(self):
        with self.fixture() as (root, git):
            marker = root / "inventory-executed"
            rule_marker = root / "rule-executed"
            inventory = root / "inventories/mgmt/inventory.rb"
            inventory.parent.mkdir(parents=True)
            inventory.write_text(f"#!/usr/bin/ruby\nFile.write('{marker}', 'executed')\nputs '{{}}'\n")
            inventory.chmod(0o755)
            config = root / "platform/ansible/ansible.cfg"
            config.parent.mkdir(parents=True)
            config.write_text(f"[defaults]\ninventory = {inventory}\n")
            rules = root / "candidate_rules"
            rules.mkdir()
            (rules / "execute.py").write_text(f'from pathlib import Path\n\nPath("{rule_marker}").touch()\n')
            (root / ".ansible-lint").write_text(f"---\nrulesdir: [{rules}]\n")
            (root / "playbook.yml").write_text("---\n- name: Valid indexed playbook\n  hosts: localhost\n  tasks: []\n")
            git("add", ".")
            index = git("write-tree")
            self.assertEqual(0, REPOCTL.precommit())
            self.assertFalse(marker.exists())
            self.assertFalse(rule_marker.exists())
            self.assertEqual(index, git("write-tree"))

    def test_staged_ansible_syntax_is_rejected_despite_valid_worktree(self):
        with self.fixture() as (root, git):
            path = root / "playbook.yml"
            path.write_text("---\n- hosts: localhost\n  tasks: [\n")
            git("add", "playbook.yml")
            path.write_text("---\n- name: Valid unstaged playbook\n  hosts: localhost\n  tasks: []\n")
            with self.assertRaises(RuntimeError):
                REPOCTL.precommit()

    def test_valid_staged_terraform_and_ansible_ignore_unstaged_invalid_content(self):
        with self.fixture() as (root, git):
            terraform = root / "main.tf"
            playbook = root / "playbook.yml"
            terraform.write_text('locals {\n  value = "example"\n}\n')
            playbook.write_text("---\n- name: Valid staged playbook\n  hosts: localhost\n  tasks: []\n")
            git("add", "main.tf", "playbook.yml")
            index = git("write-tree")
            terraform.write_text("invalid Terraform\n")
            playbook.write_text("[invalid YAML\n")
            self.assertEqual(0, REPOCTL.precommit())
            self.assertEqual(index, git("write-tree"))
            self.assertEqual("[invalid YAML\n", playbook.read_text())

    def test_staged_go_vet_failure_is_not_hidden_by_valid_worktree(self):
        with self.fixture() as (root, git):
            (root / "go.mod").write_text("module fixture\n\ngo 1.23.0\n")
            source = root / "example.go"
            invalid = 'package fixture\n\nimport "fmt"\n\nfunc message() {\n\tfmt.Printf("%d", "text")\n}\n'
            source.write_text(invalid)
            git("add", "go.mod", "example.go")
            source.write_text(invalid.replace('"%d"', '"%s"'))
            with self.assertRaisesRegex(RuntimeError, "vet"):
                REPOCTL.precommit()

    def test_option_like_and_quoted_paths_are_checked(self):
        for name in ("--stdin-filename=x.py", "line\nbreak.py"):
            with self.subTest(name=name), self.fixture() as (root, git):
                (root / name).write_text("undefined_name()\n")
                git("add", "--", name)
                with self.assertRaises(RuntimeError):
                    REPOCTL.precommit()

    def test_external_symlink_is_rejected_before_any_scanner(self):
        with self.fixture() as (root, git), tempfile.TemporaryDirectory() as external:
            target = Path(external) / "private.py"
            target.write_text("untracked_private_fixture\n")
            (root / "link.py").symlink_to(target)
            git("add", "--", "link.py")
            diagnostics = io.StringIO()
            with mock.patch.object(REPOCTL, "require") as require, contextlib.redirect_stderr(diagnostics):
                self.assertNotEqual(0, REPOCTL.precommit())
            require.assert_not_called()
            self.assertNotIn("untracked_private_fixture", diagnostics.getvalue())
            self.assertNotIn(str(target), diagnostics.getvalue())

    def test_publish_rejects_dirty_symlink_before_commit_even_without_hooks(self):
        with self.fixture() as (root, git), tempfile.TemporaryDirectory() as external:
            git("checkout", "-b", "fixture-publish")
            head = git("rev-parse", "HEAD")
            git("update-ref", "refs/remotes/origin/main", head)
            target = Path(external) / "private.py"
            target.write_text("untracked_private_fixture\n")
            (root / "link.py").symlink_to(target)
            original_run = REPOCTL.run
            commands = []

            def run(command, **kwargs):
                commands.append(command)
                if command[:2] == ["git", "fetch"]:
                    return subprocess.CompletedProcess(command, 0)
                return original_run(command, **kwargs)

            with (
                mock.patch.object(REPOCTL, "run", side_effect=run),
                mock.patch.object(REPOCTL, "_load_promotable_worktree_evidence", return_value=None),
                mock.patch.object(REPOCTL, "verify_change") as verify,
            ):
                self.assertEqual(1, REPOCTL.publish("main", "Must reject symlink"))
            self.assertEqual(head, git("rev-parse", "HEAD"))
            self.assertFalse(any(command[:2] in (["git", "commit"], ["git", "push"]) for command in commands))
            verify.assert_not_called()

    def test_publish_rejects_clean_committed_gitlink_before_verification(self):
        with self.fixture() as (root, git):
            git("checkout", "-b", "fixture-publish")
            head = git("rev-parse", "HEAD")
            git("update-ref", "refs/remotes/origin/main", head)
            git("update-index", "--add", "--cacheinfo", f"160000,{head},external")
            (root / "external").mkdir()
            git("commit", "-m", "Add gitlink fixture")
            original_run = REPOCTL.run
            commands = []

            def run(command, **kwargs):
                commands.append(command)
                if command[:2] == ["git", "fetch"]:
                    return subprocess.CompletedProcess(command, 0)
                return original_run(command, **kwargs)

            with (
                mock.patch.object(REPOCTL, "run", side_effect=run),
                mock.patch.object(REPOCTL, "verify_change") as verify,
            ):
                self.assertEqual(1, REPOCTL.publish("main", "Refuse committed gitlink"))
            verify.assert_not_called()
            self.assertFalse(any(command[:2] == ["git", "push"] for command in commands))

    def test_guard_rejects_unresolved_regular_index_entries(self):
        with mock.patch.object(REPOCTL, "git", return_value=f"100644 {'a' * 40} 2\tconflicted.py\0"):
            self.assertNotEqual(0, REPOCTL._reject_staged_symlinks())

    def test_unstaged_attributes_cannot_convert_indexed_blobs(self):
        for tracked in (False, True):
            with self.subTest(tracked=tracked), self.fixture() as (root, git):
                folder = root / "nested"
                folder.mkdir()
                path = folder / "fixture.go"
                content = b"package fixture\n\nvar value = 1\n"
                path.write_bytes(content)
                attributes = folder / ".gitattributes"
                if tracked:
                    attributes.write_text("*.go text\n")
                    git("add", "--", "nested/.gitattributes")
                git("add", "--", "nested/fixture.go")
                index = git("write-tree")
                attributes.write_text("*.go working-tree-encoding=UTF-16\n")
                with tempfile.TemporaryDirectory() as destination:
                    snapshot = Path(destination)
                    REPOCTL._materialize_staged_tree(snapshot)
                    self.assertEqual(content, (snapshot / "nested/fixture.go").read_bytes())
                self.assertEqual(0, REPOCTL.precommit())
                self.assertEqual(index, git("write-tree"))
                self.assertEqual("*.go working-tree-encoding=UTF-16\n", attributes.read_text())


if __name__ == "__main__":
    unittest.main()
