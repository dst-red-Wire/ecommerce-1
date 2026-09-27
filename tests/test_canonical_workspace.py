"""Canonical workspace policy failure modes."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

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
                "--all",
                "origin",
            ): "https://github.com/dst-red-Wire/ecommerce-1.git",
            (
                "remote",
                "get-url",
                "--push",
                "--all",
                "origin",
            ): "https://github.com/dst-red-Wire/ecommerce-1.git",
            ("worktree", "list", "--porcelain"): f"worktree {ROOT}\nHEAD {HEAD}\n",
            ("rev-parse", "HEAD"): HEAD,
            ("branch", "--show-current"): "main",
        }

    def run_check(self, cwd=ROOT, execution_scope="local"):
        with (
            patch.object(
                workspace, "_git", side_effect=lambda _cwd, *args: self.values[args]
            ),
            patch.dict(os.environ, {"PWD": str(cwd)}),
        ):
            return workspace.check(cwd=cwd, execution_scope=execution_scope)

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
        self.values[("remote", "get-url", "--all", "origin")] = (
            "https://github.com/other/ecommerce-1.git"
        )
        self.assertEqual(self.run_check()["reason"], "WRONG_REPOSITORY")

    def test_unapproved_push_url_is_rejected_without_disclosure(self):
        secret = "push-token"
        self.values[("remote", "get-url", "--push", "--all", "origin")] = (
            f"https://user:{secret}@github.com/other/ecommerce-1.git"
        )
        result = self.run_check()
        self.assertEqual(result["reason"], "WRONG_REPOSITORY")
        self.assertNotIn(secret, json.dumps(result, sort_keys=True))

    def test_every_push_url_is_checked(self):
        self.values[("remote", "get-url", "--push", "--all", "origin")] = (
            "https://github.com/dst-red-Wire/ecommerce-1.git\n"
            "https://github.com/other/ecommerce-1.git"
        )
        self.assertEqual(self.run_check()["reason"], "WRONG_REPOSITORY")

    def test_credentials_are_redacted_from_fetch_and_push_evidence(self):
        secret = "token-value"
        authenticated = f"https://user:{secret}@github.com/dst-red-Wire/ecommerce-1.git"
        self.values[("remote", "get-url", "--all", "origin")] = authenticated
        self.values[("remote", "get-url", "--push", "--all", "origin")] = authenticated
        result = self.run_check()
        encoded = json.dumps(result, sort_keys=True)
        self.assertEqual(result["status"], "PASS")
        self.assertNotIn(secret, encoded)
        self.assertEqual(
            result["repository_remotes"],
            {
                "fetch": ["https://github.com/dst-red-Wire/ecommerce-1.git"],
                "push": ["https://github.com/dst-red-Wire/ecommerce-1.git"],
            },
        )

    def test_ci_scope_admits_one_isolated_local_clone(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / ".git").mkdir()
            self.values[("rev-parse", "--show-toplevel")] = str(root)
            self.values[("rev-parse", "--absolute-git-dir")] = str(root / ".git")
            self.values[("remote", "get-url", "--all", "origin")] = "/workspace/source"
            self.values[("remote", "get-url", "--push", "--all", "origin")] = (
                "/workspace/source"
            )
            self.values[("worktree", "list", "--porcelain")] = (
                f"worktree {root}\nHEAD {HEAD}\n"
            )
            self.values[("branch", "--show-current")] = ""
            result = self.run_check(root, execution_scope="ci")
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["publication_allowed"])
        self.assertEqual(result["repository_remotes"]["fetch"], ["local-checkout"])

    def test_isolated_delivery_rejects_local_push_destination(self):
        self.values[("remote", "get-url", "--push", "--all", "origin")] = (
            "/tmp/unapproved.git"
        )
        result = self.run_check(execution_scope="isolated-delivery")
        self.assertEqual(result["reason"], "WRONG_REPOSITORY")

    def test_unknown_execution_scope_fails_closed(self):
        self.assertEqual(
            self.run_check(execution_scope="developer-bypass")["reason"],
            "UNSUPPORTED_EXECUTION_SCOPE",
        )

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
        self.assertEqual(decoded["git_head"], HEAD)
        self.assertEqual(decoded["git_branch"], "main")
        self.assertEqual(decoded["canonical_root"], str(ROOT))
        self.assertEqual(decoded["worktree_count"], 1)
        self.assertNotIn("head", decoded)
        self.assertNotIn("branch", decoded)
        self.assertNotIn("canonical_workspace", decoded)

    def test_lock_declares_only_ci_as_nonpublishing_isolated_scope(self):
        policy = yaml.safe_load(
            (ROOT / "architecture.lock.yaml").read_text(encoding="utf-8")
        )["repository_governance"]["canonical_workspace"]
        self.assertEqual(
            policy["execution_scope_environment"], "ECOMMERCE_EXECUTION_SCOPE"
        )
        self.assertEqual(
            policy["noncanonical_execution_scopes"], ["ci", "isolated-delivery"]
        )
        self.assertEqual(policy["publication_scopes"], ["local", "isolated-delivery"])


if __name__ == "__main__":
    unittest.main()
