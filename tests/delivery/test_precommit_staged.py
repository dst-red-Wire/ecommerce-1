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

    def test_non_utf8_staged_path_is_scanned_without_decoding_failure(self):
        with self.fixture() as (root, git):
            name = os.fsdecode(b"bad\xff.txt")
            (root / name).write_text("value = 1\n")
            git("add", "--", name)
            index = git("write-tree")
            self.assertEqual(0, REPOCTL.precommit())
            self.assertEqual(index, git("write-tree"))

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
