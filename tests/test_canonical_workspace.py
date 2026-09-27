"""Canonical workspace policy failure modes."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import canonical_workspace as workspace

ROOT = Path("/home/dev/ecommerce-1")
HEAD = "a" * 40


class CanonicalWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.values = {
            ("rev-parse", "--show-toplevel"): str(ROOT),
            ("rev-parse", "--absolute-git-dir"): str(ROOT / ".git"),
            (
                "remote",
                "get-url",
                "origin",
            ): "https://github.com/dst-red-Wire/ecommerce-1.git",
            ("worktree", "list", "--porcelain"): f"worktree {ROOT}\nHEAD {HEAD}\n",
            ("rev-parse", "HEAD"): HEAD,
            ("branch", "--show-current"): "main",
        }

    def run_check(self, cwd=ROOT):
        with (
            patch.object(
                workspace, "_git", side_effect=lambda _cwd, *args: self.values[args]
            ),
            patch.dict(os.environ, {"PWD": str(cwd)}),
        ):
            return workspace.check(cwd=cwd)

    def test_canonical_single_worktree(self):
        result = self.run_check()
        self.assertEqual((result["status"], result["worktree_count"]), ("PASS", 1))

    def test_wrong_path(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / ".git").mkdir()
            self.values[("rev-parse", "--show-toplevel")] = directory
            self.values[("rev-parse", "--absolute-git-dir")] = str(
                Path(directory) / ".git"
            )
            self.assertEqual(
                self.run_check(Path(directory))["reason"], "NON_CANONICAL_WORKSPACE"
            )

    def test_second_worktree(self):
        self.values[("worktree", "list", "--porcelain")] += (
            "worktree /tmp/extra\nHEAD deadbeef\n"
        )
        self.assertEqual(self.run_check()["reason"], "MULTIPLE_WORKTREES")

    def test_windows_mount(self):
        self.values[("rev-parse", "--show-toplevel")] = "/mnt/c/dev/ecommerce-1"
        self.values[("rev-parse", "--absolute-git-dir")] = "/mnt/c/dev/ecommerce-1/.git"
        with patch.object(
            Path, "resolve", autospec=True, side_effect=lambda p, **kw: p
        ):
            self.assertEqual(
                self.run_check(Path("/mnt/c/dev/ecommerce-1"))["reason"],
                "NON_CANONICAL_WORKSPACE",
            )

    def test_wrong_repository(self):
        self.values[("remote", "get-url", "origin")] = (
            "https://github.com/other/ecommerce-1.git"
        )
        self.assertEqual(self.run_check()["reason"], "WRONG_REPOSITORY")

    def test_symlink_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "link"
            link.symlink_to(ROOT)
            with (
                patch.object(
                    workspace, "_git", side_effect=lambda _cwd, *args: self.values[args]
                ),
                patch.dict(os.environ, {"PWD": str(link)}),
            ):
                self.assertEqual(
                    workspace.check(cwd=link)["reason"],
                    "WORKSPACE_SYMLINK_MISMATCH",
                )

    def test_missing_git(self):
        with patch.object(
            workspace, "_git", side_effect=subprocess.CalledProcessError(128, "git")
        ):
            self.assertEqual(
                workspace.check(cwd=ROOT)["reason"], "GIT_ROOT_UNAVAILABLE"
            )

    def test_stable_json(self):
        result = self.run_check()
        decoded = json.loads(json.dumps(result, sort_keys=True))
        self.assertEqual(decoded["repository"], "dst-red-Wire/ecommerce-1")
        self.assertEqual(decoded["head"], HEAD)
        self.assertEqual(decoded["canonical_workspace"], str(ROOT))


if __name__ == "__main__":
    unittest.main()
