from __future__ import annotations

import copy
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "repoctl_commit_provenance_test",
    ROOT / "scripts" / "repoctl.py",
)
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class CommitProvenanceTests(unittest.TestCase):
    def identity_policy(self) -> dict:
        return REPOCTL.commit_provenance_policy()["identity"]

    def test_placeholder_author_email_is_rejected(self):
        error = REPOCTL._identity_provenance_error(
            "author", "Test", "test@example.invalid", self.identity_policy()
        )
        self.assertEqual("placeholder author email test@example.invalid", error)

    def test_placeholder_committer_email_is_rejected(self):
        error = REPOCTL._identity_provenance_error(
            "committer", "Release Bot", "test@example.com", self.identity_policy()
        )
        self.assertEqual("placeholder committer email test@example.com", error)

    def test_reserved_invalid_domain_is_rejected(self):
        error = REPOCTL._identity_provenance_error(
            "author", "Contributor", "contributor@internal.invalid", self.identity_policy()
        )
        self.assertEqual("placeholder author email contributor@internal.invalid", error)

    def test_real_noreply_github_identity_is_allowed(self):
        error = REPOCTL._identity_provenance_error(
            "author",
            "PIERMATH BOUYA",
            "141283735+dst-red-Wire@users.noreply.github.com",
            self.identity_policy(),
        )
        self.assertIsNone(error)

    def test_delivery_checks_exact_commit_provenance(self):
        publish_source = inspect.getsource(REPOCTL.publish)
        deliver_source = inspect.getsource(REPOCTL.deliver)
        self.assertIn(
            'commit_provenance_check(base_ref, "WORKTREE", include_local_identity=True)',
            publish_source,
        )
        self.assertIn(
            'remote_commit_provenance_check(gh, f"origin/{base_name}", head)',
            deliver_source,
        )
        self.assertLess(
            deliver_source.index("remote_commit_provenance_check"),
            deliver_source.index('"pr",\n            "list"'),
        )

    def test_finish_pr_blocks_unverified_required_commit(self):
        source = inspect.getsource(REPOCTL.finish_pr)
        self.assertIn("commit_provenance_check(base_ref, head)", source)
        self.assertIn("remote_commit_provenance_check(gh, base_ref, head)", source)
        self.assertLess(
            source.index("remote_commit_provenance_check"),
            source.index("chatgpt_review_readiness"),
        )

    def test_provenance_check_is_exact_sha_bound(self):
        base_sha = "b" * 40
        head_sha = "a" * 40
        calls: list[tuple[str, ...]] = []

        def fake_git(*args: str, **_kwargs) -> str:
            calls.append(args)
            if args[:2] == ("rev-parse", "--verify"):
                return (base_sha if args[2].startswith("base") else head_sha) + "\n"
            if args[0] == "log":
                return (
                    "\x1e"
                    + head_sha
                    + "\x00PIERMATH BOUYA"
                    + "\x00141283735+dst-red-Wire@users.noreply.github.com"
                    + "\x00PIERMATH BOUYA"
                    + "\x00141283735+dst-red-Wire@users.noreply.github.com\n"
                )
            raise AssertionError(args)

        with mock.patch.object(REPOCTL, "git", side_effect=fake_git):
            resolved_base, resolved_head, records = REPOCTL._commit_identity_records("base", "feature")

        self.assertEqual(base_sha, resolved_base)
        self.assertEqual(head_sha, resolved_head)
        self.assertEqual(head_sha, records[0]["sha"])
        self.assertIn(("rev-parse", "--verify", "base^{commit}"), calls)
        self.assertIn(("rev-parse", "--verify", "feature^{commit}"), calls)
        self.assertTrue(any(call[-1] == f"{base_sha}..{head_sha}" for call in calls if call[0] == "log"))

    def test_provenance_policy_has_single_authority(self):
        governed_files = [ROOT / "architecture.lock.yaml", *sorted((ROOT / "config" / "contracts").glob("*.yaml"))]
        declarations = sum(
            path.read_text(encoding="utf-8").count("  commit_provenance:\n")
            for path in governed_files
        )
        self.assertEqual(1, declarations)
        model = (ROOT / "config/contracts/repository-authority-model.yaml").read_text(encoding="utf-8")
        self.assertIn("  git_delivery:\n    machine_contract: review_policy\n", model)
        lock = (ROOT / "architecture.lock.yaml").read_text(encoding="utf-8")
        self.assertIn("  review_policy: config/contracts/review-policy.yaml\n", lock)

        mutated = REPOCTL.repository_delivery_policy()
        mutated = copy.deepcopy(mutated)
        mutated["commit_provenance"]["failure_mode"] = "advisory"
        with self.assertRaisesRegex(RuntimeError, "commit provenance policy drift"):
            REPOCTL._validate_repository_delivery_policy(mutated)

    def test_mutation_test_identity_must_fail(self):
        identity_policy = self.identity_policy()
        with tempfile.TemporaryDirectory(prefix="commit-provenance-") as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Real Contributor"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "real@example.net"], cwd=root, check=True)
            tracked = root / "tracked.txt"
            tracked.write_text("base\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run(
                ["git", "-c", "commit.gpgsign=false", "commit", "-m", "base"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            tracked.write_text("mutation\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            invalid_env = os.environ.copy()
            invalid_env.update(
                {
                    "GIT_AUTHOR_NAME": "Test",
                    "GIT_AUTHOR_EMAIL": "test@example.invalid",
                    "GIT_COMMITTER_NAME": "Test",
                    "GIT_COMMITTER_EMAIL": "test@example.invalid",
                }
            )
            subprocess.run(
                ["git", "-c", "commit.gpgsign=false", "commit", "-m", "mutation"],
                cwd=root,
                env=invalid_env,
                check=True,
                capture_output=True,
            )
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()

            stderr = io.StringIO()
            with (
                mock.patch.object(REPOCTL, "ROOT", root),
                mock.patch.object(REPOCTL, "commit_provenance_policy", return_value={
                    "identity": identity_policy
                }),
                mock.patch("sys.stderr", stderr),
            ):
                result = REPOCTL.commit_provenance_check(base, head)

        self.assertEqual(1, result)
        self.assertIn(
            f"FAIL commit provenance {head}: placeholder author email test@example.invalid",
            stderr.getvalue(),
        )

    def test_remote_provenance_reports_github_reason(self):
        sha = "a" * 40
        response = subprocess.CompletedProcess(
            [],
            0,
            json.dumps(
                {
                    "sha": sha,
                    "commit": {"verification": {"verified": False, "reason": "unknown_key"}},
                }
            ),
            "",
        )
        stderr = io.StringIO()
        with (
            mock.patch.object(REPOCTL, "_commit_identity_records", return_value=("b" * 40, sha, [{"sha": sha}])),
            mock.patch.object(REPOCTL, "run", return_value=response),
            mock.patch("sys.stderr", stderr),
        ):
            result = REPOCTL.remote_commit_provenance_check("gh", "base", sha)
        self.assertEqual(2, result)
        self.assertIn(f"{sha} is not verified reason=unknown_key", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
