"""Contract tests for the one bounded, exact-SHA PR base transition."""

import importlib.util
import subprocess
import tempfile
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
    TREE = "d" * 40

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
        if args == ("branch", "--show-current"):
            return "feature/pr-loop\n"
        if args == ("rev-parse", "HEAD"):
            return self.head + "\n"
        if args == ("rev-parse", "HEAD^{tree}"):
            return self.TREE + "\n"
        if args[0] == "status":
            return ""
        raise AssertionError(args)

    def proof(self, base, head):
        return {"status": "PASS", "head_sha": head, "base_sha": base}

    def fake_run(self, command, **_kwargs):
        self.commands.append(command)
        if command[:4] == ["git", "rev-parse", "--verify", "MERGE_HEAD"]:
            in_progress = getattr(self, "merge_in_progress", False)
            return subprocess.CompletedProcess(command, 0 if in_progress else 1, self.MAIN + "\n" if in_progress else "", "")
        if command[:4] == ["git", "rev-list", "--parents", "-n"]:
            return subprocess.CompletedProcess(command, 0, f"{self.NEW} {self.OLD} {self.MAIN}\n", "")
        if command[:2] == ["git", "update-ref"]:
            if getattr(self, "restore_fails", False):
                return subprocess.CompletedProcess(command, 1, "", "ref changed")
            self.head = self.OLD
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:3] == ["git", "merge-base", "--is-ancestor"]:
            return subprocess.CompletedProcess(command, 0 if self.main_is_ancestor or command[-1] == self.NEW else 1, "", "")
        if command[:2] == ["git", "merge"] and "--abort" not in command:
            if getattr(self, "conflict", False):
                self.merge_in_progress = True
                return subprocess.CompletedProcess(command, 1, "", "conflict")
            self.head = self.NEW
        if command[:3] == ["git", "merge", "--abort"]:
            self.head = self.OLD
            self.merge_in_progress = False
        if command[:2] == ["git", "push"]:
            if getattr(self, "push_fails", False):
                return subprocess.CompletedProcess(command, 1, "", "rejected")
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
        self.assertEqual("PASS", result["restore_verification"])
        self.assertEqual(self.OLD, self.head)
        self.assertFalse(any(c[:2] == ["git", "push"] for c in self.commands))

    def test_base_change_after_merge_abandons_old_controller_before_qualification(self):
        self.main_is_ancestor = False
        changed = REPOCTL.PRBaseChanged(self.MAIN, "d" * 40, "d" * 40)
        with mock.patch.object(
            REPOCTL, "_pr_loop_current_base", side_effect=[self.pr, self.pr, changed]
        ):
            result = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        self.assertEqual("BASE_CHANGED", result["error"])
        self.assertEqual("PASS", result["restore_verification"])
        self.assertEqual(self.OLD, self.head)
        self.assertEqual(self.OLD, self.remote)
        self.assertFalse(any(c[:2] == ["repoctl", "qualification-proof"] for c in self.commands))
        self.assertFalse(any(c[:2] == ["git", "push"] for c in self.commands))

    def test_base_change_after_qualification_blocks_publication(self):
        self.main_is_ancestor = False
        changed = REPOCTL.PRBaseChanged(self.MAIN, "d" * 40, "d" * 40)
        with mock.patch.object(
            REPOCTL, "_pr_loop_current_base",
            side_effect=[self.pr, self.pr, self.pr, changed],
        ):
            result = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        self.assertEqual("BASE_CHANGED", result["error"])
        self.assertEqual("PASS", result["restore_verification"])
        self.assertEqual(self.OLD, self.head)
        self.assertTrue(any(c[:2] == ["repoctl", "qualification-proof"] for c in self.commands))
        self.assertFalse(any(c[:2] == ["git", "push"] for c in self.commands))

    def test_qualification_failure_blocks_push(self):
        self.main_is_ancestor = False
        with mock.patch.object(REPOCTL, "_pr_loop_qualification", return_value={"status": "MISSING"}):
            result = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        self.assertEqual("QUALIFICATION_FAILED", result["error"])
        self.assertEqual("PASS", result["restore_verification"])
        self.assertEqual(self.OLD, self.head)
        self.assertFalse(any(c[:2] == ["git", "push"] for c in self.commands))

    def test_signed_merge_verification_failure_restores_head(self):
        self.main_is_ancestor = False
        original_run = self.fake_run

        def fail_signature(command, **kwargs):
            if command[:3] == ["git", "verify-commit", "--raw"]:
                self.commands.append(command)
                return subprocess.CompletedProcess(command, 1, "", "bad signature")
            return original_run(command, **kwargs)

        with mock.patch.object(REPOCTL, "run", side_effect=fail_signature):
            result = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        self.assertEqual("SIGNED_MERGE_VERIFICATION_FAILED", result["error"])
        self.assertEqual("PASS", result["restore_verification"])
        self.assertEqual(self.OLD, self.head)

    def test_failed_push_restores_if_remote_remains_old(self):
        self.main_is_ancestor = False
        self.push_fails = True
        result = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        self.assertEqual("PUSH_FAILED", result["error"])
        self.assertEqual("PASS", result["restore_verification"])
        self.assertEqual(self.OLD, self.head)
        self.assertEqual(self.OLD, self.remote)

    def test_recovery_failure_is_reported_without_false_verification(self):
        self.main_is_ancestor = False
        self.restore_fails = True
        with mock.patch.object(REPOCTL, "_pr_loop_qualification", return_value={"status": "MISSING"}):
            result = REPOCTL.sync_pr_base("gh", "owner/repo", self.pr)
        self.assertEqual("SYNC_RECOVERY_FAILED", result["error"])
        self.assertEqual("QUALIFICATION_FAILED", result["failure_reason"])
        self.assertEqual("FAIL", result["restore_verification"])


class SyncRecoveryGitTests(unittest.TestCase):
    def test_unpublished_merge_restores_exact_branch_head_tree_and_cleanliness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.run(
                    ["git", *args], cwd=root, text=True, capture_output=True, check=True,
                ).stdout.strip()

            git("init", "-q", "-b", "main")
            git("config", "user.name", "Sync Recovery Test")
            git("config", "user.email", "sync-recovery@example.invalid")
            git("config", "commit.gpgsign", "false")
            (root / "shared.txt").write_text("base\n", encoding="utf-8")
            git("add", "shared.txt")
            git("commit", "-q", "-m", "base")
            git("switch", "-q", "-c", "feature/pr-loop")
            (root / "feature.txt").write_text("feature\n", encoding="utf-8")
            git("add", "feature.txt")
            git("commit", "-q", "-m", "feature")
            old_head = git("rev-parse", "HEAD")
            git("switch", "-q", "main")
            (root / "main.txt").write_text("main\n", encoding="utf-8")
            git("add", "main.txt")
            git("commit", "-q", "-m", "main advances")
            main_sha = git("rev-parse", "HEAD")
            git("switch", "-q", "feature/pr-loop")

            with mock.patch.object(REPOCTL, "ROOT", root):
                captured = REPOCTL._capture_pr_sync_state("feature/pr-loop", old_head, main_sha)
                git("merge", "--no-ff", "-m", "sync main", main_sha)
                self.assertNotEqual(old_head, git("rev-parse", "HEAD"))
                restored, reason = REPOCTL._restore_pr_sync_state(captured)

            self.assertTrue(restored, reason)
            self.assertEqual("feature/pr-loop", git("branch", "--show-current"))
            self.assertEqual(old_head, git("rev-parse", "HEAD"))
            self.assertEqual(captured["tree_sha"], git("rev-parse", "HEAD^{tree}"))
            self.assertEqual("", git("status", "--porcelain", "--untracked-files=all"))


if __name__ == "__main__":
    unittest.main()
