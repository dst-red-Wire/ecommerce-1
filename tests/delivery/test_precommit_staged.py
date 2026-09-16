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
        self.assertIn('"checkout-index"', function)
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


if __name__ == "__main__":
    unittest.main()
