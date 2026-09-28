"""Contract tests for the one bounded, exact-SHA PR base transition."""

import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_pr_sync_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class SyncPRBaseTests(unittest.TestCase):
    OLD = "a" * 40
    MAIN = "b" * 40
    NEW = "c" * 40

    def setUp(self):
        self.head = self.OLD
        self.commands = []
        self.remote = self.OLD
        self.pr = {
            "number": 161, "state": "OPEN", "draft": False,
            "head_sha": self.OLD, "head_branch": "feature/pr-loop",
            "head_repository": "owner/repo", "base": "main", "base_sha": self.MAIN,
        }
        self.patches = [
            mock.patch.object(REPOCTL, "_require_trusted_pr_execution", return_value={}),
            mock.patch.object(REPOCTL, "_pr_loop_open_pr_errors", return_value=[]),
            mock.patch.object(REPOCTL, "_pr_loop_checkout_errors", return_value=[]),
            mock.patch.object(REPOCTL, "_github_pr_snapshot", side_effect=self.snapshot),
            mock.patch.object(REPOCTL, "_remote_ref_sha", side_effect=self.ref),
            mock.patch.object(REPOCTL, "_remote_branch_head", side_effect=lambda _: self.remote),
            mock.patch.object(REPOCTL, "git", side_effect=self.git),
            mock.patch.object(REPOCTL, "run", side_effect=self.fake_run),
            mock.patch.object(REPOCTL, "_controller_command", side_effect=lambda *args: ["repoctl", *args]),
            mock.patch.object(REPOCTL, "_pr_loop_qualification", side_effect=self.proof),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()

    def snapshot(self, *_):
        return {**self.pr, "head_sha": self.remote}

    def ref(self, name):
        return self.MAIN if name == "origin/main" else self.remote

    def git(self, *args):
        if args == ("rev-parse", "HEAD"):
            return self.head + "\n"
        if args[0] == "status":
            return ""
        raise AssertionError(args)

    def proof(self, base, head):
        return {"status": "PASS", "head_sha": head, "base_sha": base}

    def fake_run(self, command, **_kwargs):
        self.commands.append(command)
        if command[:3] == ["git", "merge-base", "--is-ancestor"]:
            return subprocess.CompletedProcess(command, 0 if self.main_is_ancestor or command[-1] == self.NEW else 1, "", "")
        if command[:2] == ["git", "merge"] and "--abort" not in command:
            if getattr(self, "conflict", False):
                return subprocess.CompletedProcess(command, 1, "", "conflict")
            self.head = self.NEW
        if command[:3] == ["git", "merge", "--abort"]:
            self.head = self.OLD
        if command[:2] == ["git", "push"]:
            self.remote = self.NEW
        return subprocess.CompletedProcess(command, 0, "", "")

    def test_already_descended_creates_no_commit_or_push(self):
        self.main_is_ancestor = True
        first = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        second = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        self.assertEqual("NOT_REQUIRED", first["status"])
        self.assertEqual("NOT_REQUIRED", second["status"])
        self.assertEqual("", first["new_head_sha"])
        self.assertFalse(any(c[:2] in (["git", "merge"], ["git", "push"]) for c in self.commands))

    def test_signed_merge_is_qualified_before_normal_push(self):
        self.main_is_ancestor = False
        result = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        self.assertEqual("PASS", result["status"])
        self.assertEqual(self.NEW, result["new_head_sha"])
        self.assertEqual({"status": "PASS", "head_sha": self.NEW, "base_sha": self.MAIN, "source": "executed"}, result["qualification"])
        merge = next(i for i, c in enumerate(self.commands) if c[:2] == ["git", "merge"])
        qualify = next(i for i, c in enumerate(self.commands) if c[:2] == ["repoctl", "qualification-proof"])
        push = next(i for i, c in enumerate(self.commands) if c[:2] == ["git", "push"])
        self.assertLess(merge, qualify)
        self.assertLess(qualify, push)
        self.assertIn("-S", self.commands[merge])
        self.assertEqual(["git", "push", "origin", "HEAD:refs/heads/feature/pr-loop"], self.commands[push])
        self.assertFalse(result["force_push_used"] or result["rebase_used"])

    def test_conflict_aborts_and_restores_without_push(self):
        self.main_is_ancestor = False
        self.conflict = True
        result = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        self.assertEqual("SYNC_CONFLICT", result["error"])
        self.assertEqual("PASS", result["restore_on_failure"])
        self.assertEqual("PASS", result["worktree_clean"])
        self.assertEqual(self.OLD, self.head)
        self.assertIn(["git", "merge", "--abort"], self.commands)
        self.assertFalse(any(c[:2] == ["git", "push"] for c in self.commands))

    def test_remote_head_change_blocks_push(self):
        self.main_is_ancestor = False
        with mock.patch.object(REPOCTL, "_remote_branch_head", return_value="d" * 40):
            result = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        self.assertEqual("REMOTE_HEAD_CHANGED", result["error"])
        self.assertFalse(any(c[:2] == ["git", "push"] for c in self.commands))

    def test_qualification_failure_blocks_push(self):
        self.main_is_ancestor = False
        with mock.patch.object(REPOCTL, "_pr_loop_qualification", return_value={"status": "MISSING"}):
            result = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        self.assertEqual("QUALIFICATION_FAILED", result["error"])
        self.assertFalse(any(c[:2] == ["git", "push"] for c in self.commands))


if __name__ == "__main__":
    unittest.main()
