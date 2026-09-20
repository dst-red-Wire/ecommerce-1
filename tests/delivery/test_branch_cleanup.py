from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repoctl_branch_cleanup_test", ROOT / "scripts" / "repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class BranchCleanupTests(unittest.TestCase):
    def git(self, root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            check=check,
            text=True,
            capture_output=True,
        )

    def init_repo(self, directory: str) -> tuple[Path, Path]:
        base = Path(directory)
        remote = base / "remote.git"
        root = base / "repo"
        self.git(base, "init", "--bare", str(remote))
        self.git(base, "init", "-b", "main", str(root))
        self.git(root, "config", "user.name", "Branch Cleanup Test")
        self.git(root, "config", "user.email", "branch-cleanup@example.invalid")
        (root / "README.md").write_text("base\n", encoding="utf-8")
        self.git(root, "add", "README.md")
        self.git(root, "commit", "-m", "base")
        self.git(root, "remote", "add", "origin", str(remote))
        self.git(root, "push", "-u", "origin", "main")
        return root, remote

    def cleanup_policy(self) -> dict:
        return {
            "default_branch": "main",
            "cleanup": {
                "automatic_branch_cleanup": {
                    "enabled": True,
                    "triggers": ["git-sync", "finish-pr"],
                    "default_branch_ref": "origin/<default-branch>",
                    "delete_when": [
                        "head-is-ancestor-of-default-branch",
                        "merged-pr-head-matches-current-branch-head",
                    ],
                    "merged_pr_base_must_match_default": True,
                    "github_merge_proof": "exact-head-sha",
                    "preserve": [
                        "default-branch",
                        "master",
                        "current-branch",
                        "active-worktree",
                        "branch-with-unabsorbed-head",
                        "branch-advanced-after-merged-pr",
                    ],
                    "github_cli_optional_for_ancestor_cleanup": True,
                    "remote_delete_requires_exact_lease": True,
                    "local_delete_requires_compare_and_delete": True,
                }
            },
        }

    def branch_exists(self, root: Path, branch: str) -> bool:
        return self.git(root, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}", check=False).returncode == 0

    def remote_branch_exists(self, root: Path, branch: str) -> bool:
        return bool(self.git(root, "ls-remote", "--heads", "origin", f"refs/heads/{branch}").stdout.strip())

    def test_repository_delivery_policy_rejects_incomplete_cleanup_contract(self):
        policy = REPOCTL.repository_delivery_policy()
        broken = {
            **policy,
            "cleanup": {
                **policy["cleanup"],
                "automatic_branch_cleanup": {
                    "enabled": True,
                },
            },
        }
        with self.assertRaisesRegex(RuntimeError, "automatic branch cleanup policy drift"):
            REPOCTL._validate_repository_delivery_policy(broken)

    def test_central_contract_enables_safe_automatic_cleanup(self):
        cleanup = REPOCTL.repository_delivery_policy()["cleanup"]["automatic_branch_cleanup"]
        self.assertIs(True, cleanup["enabled"])
        self.assertEqual(["git-sync", "finish-pr"], cleanup["triggers"])
        self.assertEqual(
            [
                "head-is-ancestor-of-default-branch",
                "merged-pr-head-matches-current-branch-head",
            ],
            cleanup["delete_when"],
        )
        self.assertEqual("exact-head-sha", cleanup["github_merge_proof"])
        self.assertIs(True, cleanup["remote_delete_requires_exact_lease"])
        self.assertIs(True, cleanup["local_delete_requires_compare_and_delete"])
        self.assertIn("active-worktree", cleanup["preserve"])
        self.assertIn("branch-advanced-after-merged-pr", cleanup["preserve"])

    def test_planner_preserves_current_worktree_and_advanced_branch(self):
        plan = REPOCTL._plan_branch_cleanup(
            {
                "main": "a" * 40,
                "absorbed": "b" * 40,
                "advanced": "c" * 40,
                "worktree": "d" * 40,
            },
            {
                "main": "a" * 40,
                "absorbed": "b" * 40,
                "advanced": "c" * 40,
                "worktree": "d" * 40,
            },
            current_branch="main",
            default_branch="main",
            active_worktrees={"main", "worktree"},
            ancestor_heads={
                "a" * 40: True,
                "b" * 40: True,
                "c" * 40: False,
                "d" * 40: True,
            },
            merged_pr_heads={"advanced": {"e" * 40}},
        )
        by_key = {(item["scope"], item["branch"]): item for item in plan}
        self.assertEqual("delete", by_key[("local", "absorbed")]["action"])
        self.assertEqual("head-is-ancestor-of-default-branch", by_key[("local", "absorbed")]["reason"])
        self.assertEqual("keep", by_key[("remote", "advanced")]["action"])
        self.assertEqual("branch-advanced-after-merged-pr", by_key[("remote", "advanced")]["reason"])
        self.assertEqual("keep", by_key[("local", "worktree")]["action"])
        self.assertEqual("active-worktree", by_key[("local", "worktree")]["reason"])
        self.assertEqual("keep", by_key[("local", "main")]["action"])
        self.assertEqual("protected-branch", by_key[("local", "main")]["reason"])

    def test_planner_preserves_all_refs_when_one_side_has_unabsorbed_work(self):
        absorbed = "b" * 40
        unique = "c" * 40
        plan = REPOCTL._plan_branch_cleanup(
            {"diverged": unique},
            {"diverged": absorbed},
            current_branch="main",
            default_branch="main",
            active_worktrees={"main"},
            ancestor_heads={absorbed: True, unique: False},
            merged_pr_heads={},
        )
        by_scope = {item["scope"]: item for item in plan}
        self.assertEqual("keep", by_scope["remote"]["action"])
        self.assertEqual("branch-with-unabsorbed-head", by_scope["remote"]["reason"])
        self.assertEqual("keep", by_scope["local"]["action"])
        self.assertEqual("branch-with-unabsorbed-head", by_scope["local"]["reason"])

    def test_remote_delete_uses_exact_sha_lease(self):
        sha = "a" * 40
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(REPOCTL, "run", return_value=completed) as run:
            ok, detail = REPOCTL._delete_branch_ref("remote", "feature", sha)
        self.assertTrue(ok)
        self.assertEqual("", detail)
        command = run.call_args.args[0]
        self.assertEqual(
            [
                "git",
                "push",
                f"--force-with-lease=refs/heads/feature:{sha}",
                "origin",
                ":refs/heads/feature",
            ],
            command,
        )

    def test_local_delete_uses_compare_and_delete_old_sha(self):
        sha = "b" * 40
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(REPOCTL, "run", return_value=completed) as run:
            ok, detail = REPOCTL._delete_branch_ref("local", "feature", sha)
        self.assertTrue(ok)
        self.assertEqual("", detail)
        self.assertEqual(
            ["git", "update-ref", "-d", "refs/heads/feature", sha],
            run.call_args.args[0],
        )

    def test_delete_rejects_non_exact_sha_before_git(self):
        with mock.patch.object(REPOCTL, "run") as run:
            ok, detail = REPOCTL._delete_branch_ref("remote", "feature", "abc")
        self.assertFalse(ok)
        self.assertIn("not exact", detail)
        run.assert_not_called()

    def test_cleanup_deletes_branch_whose_head_is_already_in_main(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _remote = self.init_repo(directory)
            self.git(root, "switch", "-c", "absorbed")
            (root / "absorbed.txt").write_text("absorbed\n", encoding="utf-8")
            self.git(root, "add", "absorbed.txt")
            self.git(root, "commit", "-m", "absorbed")
            self.git(root, "push", "-u", "origin", "absorbed")
            self.git(root, "switch", "main")
            self.git(root, "merge", "--ff-only", "absorbed")
            self.git(root, "push", "origin", "main")

            with (
                mock.patch.object(REPOCTL, "ROOT", root),
                mock.patch.object(REPOCTL, "repository_delivery_policy", return_value=self.cleanup_policy()),
                mock.patch.object(REPOCTL, "_merged_pr_exact_heads", return_value={}),
            ):
                self.assertEqual(0, REPOCTL.branch_cleanup())

            self.assertFalse(self.branch_exists(root, "absorbed"))
            self.assertFalse(self.remote_branch_exists(root, "absorbed"))

    def test_cleanup_deletes_exact_head_of_merged_pr_even_when_not_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _remote = self.init_repo(directory)
            self.git(root, "switch", "-c", "squash-merged")
            (root / "feature.txt").write_text("feature\n", encoding="utf-8")
            self.git(root, "add", "feature.txt")
            self.git(root, "commit", "-m", "feature")
            head = self.git(root, "rev-parse", "HEAD").stdout.strip()
            self.git(root, "push", "-u", "origin", "squash-merged")
            self.git(root, "switch", "main")

            with (
                mock.patch.object(REPOCTL, "ROOT", root),
                mock.patch.object(REPOCTL, "repository_delivery_policy", return_value=self.cleanup_policy()),
                mock.patch.object(
                    REPOCTL,
                    "_merged_pr_exact_heads",
                    return_value={"squash-merged": {head}},
                ),
            ):
                self.assertEqual(0, REPOCTL.branch_cleanup())

            self.assertFalse(self.branch_exists(root, "squash-merged"))
            self.assertFalse(self.remote_branch_exists(root, "squash-merged"))

    def test_cleanup_preserves_branch_advanced_after_merged_pr(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _remote = self.init_repo(directory)
            self.git(root, "switch", "-c", "advanced")
            (root / "feature.txt").write_text("first\n", encoding="utf-8")
            self.git(root, "add", "feature.txt")
            self.git(root, "commit", "-m", "first")
            merged_head = self.git(root, "rev-parse", "HEAD").stdout.strip()
            (root / "feature.txt").write_text("second\n", encoding="utf-8")
            self.git(root, "commit", "-am", "second")
            self.git(root, "push", "-u", "origin", "advanced")
            self.git(root, "switch", "main")

            with (
                mock.patch.object(REPOCTL, "ROOT", root),
                mock.patch.object(REPOCTL, "repository_delivery_policy", return_value=self.cleanup_policy()),
                mock.patch.object(
                    REPOCTL,
                    "_merged_pr_exact_heads",
                    return_value={"advanced": {merged_head}},
                ),
            ):
                self.assertEqual(0, REPOCTL.branch_cleanup())

            self.assertTrue(self.branch_exists(root, "advanced"))
            self.assertTrue(self.remote_branch_exists(root, "advanced"))

    def test_git_sync_automatically_runs_cleanup(self):
        with (
            mock.patch.object(REPOCTL, "git", side_effect=["feature\n", ""]),
            mock.patch.object(REPOCTL, "run"),
            mock.patch.object(REPOCTL, "branch_cleanup", return_value=0) as cleanup,
        ):
            self.assertEqual(0, REPOCTL.git_sync())
        cleanup.assert_called_once_with(dry_run=False, fetch_remote=False)


if __name__ == "__main__":
    unittest.main()
