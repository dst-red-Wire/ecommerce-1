"""Historical exact-SHA evidence cannot authorize a newer PR head."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "repoctl_delivery_supersession", ROOT / "scripts/repoctl.py"
)
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class DeliverySupersessionTests(unittest.TestCase):
    SHA_A = "a" * 40
    SHA_B = "b" * 40
    BASE = "c" * 40

    def setUp(self):
        # These unit fixtures model local HEAD history, not an executing base
        # wrapper. The enclosing qualification context must not grant them one.
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("REPOCTL_TRUSTED_", "GIT_"))
        }
        self.enterContext(mock.patch.dict(os.environ, environment, clear=True))
        self.enterContext(
            mock.patch.object(REPOCTL, "_TRUSTED_PR_EXECUTION_CONTEXT", None)
        )

    @staticmethod
    def comment(body: str, identifier: int) -> dict:
        timestamp = f"2026-09-30T10:{identifier:02d}:00Z"
        return {
            "id": identifier,
            "body": body,
            "created_at": timestamp,
            "updated_at": timestamp,
            "user": {"login": "owner"},
            "author_association": "OWNER",
        }

    @classmethod
    def review_comment(cls, kind: str, sha: str, identifier: int) -> dict:
        proof = {
            "provider": "ChatGPT",
            "kind": kind,
            "head_sha": sha,
            "status": "PASS",
            "blocking_findings": 0,
        }
        marker = "<!-- chatgpt-exact-sha-review:v1 " + json.dumps(proof) + " -->"
        return cls.comment(marker, identifier)

    @classmethod
    def owner_comment(cls, sha: str, identifier: int) -> dict:
        return cls.comment(
            f"/owner-authorization approve scope=pr-161 sha={sha}", identifier
        )

    @classmethod
    def pr(cls, head: str) -> dict:
        return {
            "number": 161,
            "state": "OPEN",
            "draft": False,
            "base": "main",
            "base_sha": cls.BASE,
            "head_sha": head,
            "merged": False,
        }

    @classmethod
    def risk(cls, head: str) -> dict:
        return {
            "classification": "SENSITIVE",
            "authority": "repository-policy",
            "pr": 161,
            "base_sha": cls.BASE,
            "head_sha": head,
            "changed_files": ["scripts/repoctl.py"],
            "reasons": ["governance"],
            "matched_capabilities": ["governance"],
            "analysis_complete": True,
        }

    def authorities(self, comments: list[dict], head: str) -> tuple[dict, dict]:
        reviews = REPOCTL._chatgpt_review_evidence(comments, "owner", head)
        owner = REPOCTL._owner_authorization_evidence(comments, "owner", 161, head)
        return reviews, owner

    def state(self, reviews: dict, owner: dict, qualification: dict) -> tuple[str, str]:
        return REPOCTL.derive_pr_loop_state(
            self.pr(self.SHA_B),
            qualification,
            reviews["code"],
            reviews["security"],
            owner,
            risk=self.risk(self.SHA_B),
        )

    def test_prior_comments_superseded_then_code_and_security_requested_in_order(self):
        comments = [
            self.review_comment("code", self.SHA_A, 1),
            self.review_comment("security", self.SHA_A, 2),
            self.owner_comment(self.SHA_A, 3),
        ]
        old_reviews, old_owner = self.authorities(comments, self.SHA_A)
        self.assertEqual("PASS", old_reviews["code"]["status"])
        self.assertEqual("PASS", old_reviews["security"]["status"])
        self.assertEqual("PASS", old_owner["status"])

        reviews, owner = self.authorities(comments, self.SHA_B)
        for kind, comment_id in (("code", 1), ("security", 2)):
            with self.subTest(kind=kind):
                self.assertEqual("SUPERSEDED", reviews[kind]["status"])
                self.assertEqual(self.SHA_A, reviews[kind]["superseded_head_sha"])
                self.assertEqual(comment_id, reviews[kind]["superseded_comment_id"])
        self.assertEqual("SUPERSEDED", owner["status"])
        self.assertEqual(3, owner["superseded_comment_id"])
        qualified_head_b = {"status": "PASS", "head_sha": self.SHA_B}
        self.assertEqual(
            ("CHATGPT_REVIEW_REQUIRED", "CHATGPT_CODE_REVIEW"),
            self.state(reviews, owner, qualified_head_b),
        )

        comments.append(self.review_comment("code", self.SHA_B, 4))
        reviews, owner = self.authorities(comments, self.SHA_B)
        self.assertEqual("PASS", reviews["code"]["status"])
        self.assertEqual("SUPERSEDED", reviews["security"]["status"])
        self.assertEqual(
            ("CHATGPT_REVIEW_REQUIRED", "CHATGPT_SECURITY_REVIEW"),
            self.state(reviews, owner, qualified_head_b),
        )

        comments.append(self.review_comment("security", self.SHA_B, 5))
        reviews, owner = self.authorities(comments, self.SHA_B)
        self.assertEqual("PASS", reviews["security"]["status"])
        self.assertEqual(
            ("OWNER_AUTH_REQUIRED", "OWNER_AUTHORIZATION"),
            self.state(reviews, owner, qualified_head_b),
        )

    def test_historical_qualification_is_superseded_for_new_git_head(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / ".gitignore").write_text(".context/\n", encoding="utf-8")
            (repo / "source.txt").write_text("A\n", encoding="utf-8")
            self.git(repo, "init", "-q")
            self.git(repo, "add", ".")
            self.git(
                repo,
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "A",
            )
            head_a = self.git(repo, "rev-parse", "HEAD")
            (repo / "source.txt").write_text("B\n", encoding="utf-8")
            self.git(repo, "add", "source.txt")
            self.git(
                repo,
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "B",
            )
            head_b = self.git(repo, "rev-parse", "HEAD")
            evidence_dir = repo / ".context" / "evidence"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / f"{head_a}.json").write_text(
                json.dumps(
                    {
                        "status": "PASS",
                        "exact_commit_evidence": True,
                        "head_sha": head_a,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(REPOCTL, "ROOT", repo),
                mock.patch.object(REPOCTL, "CONTEXT", repo / ".context"),
            ):
                qualification = REPOCTL._pr_loop_qualification(head_a, head_b)
        self.assertEqual("SUPERSEDED", qualification["status"])
        self.assertEqual(head_a, qualification["superseded_head_sha"])
        self.assertEqual(head_b, qualification["head_sha"])
        self.assertEqual(
            ("QUALIFICATION_REQUIRED", "QUALIFICATION"),
            REPOCTL.derive_pr_loop_state(
                self.pr(head_b),
                qualification,
                {"status": "MISSING", "head_sha": head_b},
                {"status": "MISSING", "head_sha": head_b},
                {"status": "SUPERSEDED", "head_sha": head_b},
                risk=self.risk(head_b),
            ),
        )

    @staticmethod
    def git(repo: Path, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=repo, text=True, capture_output=True, check=True
        ).stdout.strip()


if __name__ == "__main__":
    unittest.main()
