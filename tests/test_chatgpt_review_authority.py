from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "repoctl_chatgpt_review_authority_test",
    ROOT / "scripts" / "repoctl.py",
)
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class ChatGPTReviewAuthorityTests(unittest.TestCase):
    HEAD = "a" * 40

    def policy(self):
        return {
            "ai_reviewer": {
                "provider": "ChatGPT",
                "evidence": {
                    "required_kinds": ["code", "security"],
                    "required_status": "PASS",
                    "comment_author": "repository-owner",
                },
            }
        }

    def marker(self, kind: str, *, sha: str | None = None, status: str = "PASS", blockers: int = 0):
        payload = {
            "provider": "ChatGPT",
            "kind": kind,
            "head_sha": sha or self.HEAD,
            "status": status,
            "blocking_findings": blockers,
        }
        return "<!-- chatgpt-exact-sha-review:v1 " + json.dumps(payload, separators=(",", ":")) + " -->"

    def run_with_comments(self, comments, *, author="dst-red-Wire"):
        owner = subprocess.CompletedProcess(
            [],
            0,
            json.dumps({"owner": {"login": "dst-red-Wire"}, "nameWithOwner": "dst-red-Wire/ecommerce-1"}),
            "",
        )
        comment_response = subprocess.CompletedProcess(
            [],
            0,
            json.dumps(
                [
                    [
                        {"body": body, "user": {"login": author}}
                        for body in comments
                    ]
                ]
            ),
            "",
        )

        def fake_run(command, **_kwargs):
            if command[1:4] == ["repo", "view", "--json"]:
                return owner
            if command[1:4] == ["api", "--paginate", "--slurp"]:
                return comment_response
            raise AssertionError(command)

        with (
            mock.patch.object(REPOCTL, "pull_request_review_policy", return_value=self.policy()),
            mock.patch.object(REPOCTL, "run", side_effect=fake_run),
        ):
            return REPOCTL.chatgpt_review_readiness("gh", 126, self.HEAD)

    def test_accepts_exact_chatgpt_code_and_security_pass(self):
        ready, reason = self.run_with_comments(
            [
                self.marker("code"),
                self.marker("security"),
            ]
        )
        self.assertTrue(ready)
        self.assertIn("ChatGPT CODE and SECURITY reviews PASS", reason)

    def test_ignores_codex_and_wrong_sha_comments(self):
        codex = "<!-- codex-security-review:v1 {\"status\":\"completed\"} -->"
        ready, reason = self.run_with_comments(
            [
                codex,
                self.marker("code", sha="b" * 40),
                self.marker("security"),
            ]
        )
        self.assertFalse(ready)
        self.assertIn("missing ChatGPT exact-SHA review proof: code", reason)

    def test_rejects_blocking_chatgpt_finding(self):
        ready, reason = self.run_with_comments(
            [
                self.marker("code", status="BLOCKED", blockers=1),
                self.marker("security"),
            ]
        )
        self.assertFalse(ready)
        self.assertIn("ChatGPT code review is not PASS", reason)

    def test_conflicting_exact_sha_markers_fail_closed_regardless_of_order(self):
        pass_code = self.marker("code")
        blocked_code = self.marker("code", status="BLOCKED", blockers=1)
        security = self.marker("security")
        for comments in (
            [pass_code, blocked_code, security],
            [blocked_code, pass_code, security],
        ):
            with self.subTest(order=[comments.index(pass_code), comments.index(blocked_code)]):
                ready, reason = self.run_with_comments(comments)
                self.assertFalse(ready)
                self.assertIn("ChatGPT code review is not PASS", reason)

    def test_reads_all_paginated_comment_pages(self):
        owner = subprocess.CompletedProcess(
            [],
            0,
            json.dumps({"owner": {"login": "dst-red-Wire"}}),
            "",
        )
        pages = subprocess.CompletedProcess(
            [],
            0,
            json.dumps(
                [
                    [{"body": self.marker("code"), "user": {"login": "dst-red-Wire"}}],
                    [
                        {
                            "body": self.marker("code", status="BLOCKED", blockers=1),
                            "user": {"login": "dst-red-Wire"},
                        },
                        {"body": self.marker("security"), "user": {"login": "dst-red-Wire"}},
                    ],
                ]
            ),
            "",
        )

        def fake_run(command, **_kwargs):
            if command[1:4] == ["repo", "view", "--json"]:
                return owner
            if command[1:4] == ["api", "--paginate", "--slurp"]:
                return pages
            raise AssertionError(command)

        with (
            mock.patch.object(REPOCTL, "pull_request_review_policy", return_value=self.policy()),
            mock.patch.object(REPOCTL, "run", side_effect=fake_run),
        ):
            ready, reason = REPOCTL.chatgpt_review_readiness("gh", 126, self.HEAD)
        self.assertFalse(ready)
        self.assertIn("ChatGPT code review is not PASS", reason)

    def test_rejects_markers_from_non_owner_comment_author(self):
        ready, reason = self.run_with_comments(
            [self.marker("code"), self.marker("security")],
            author="external-contributor",
        )
        self.assertFalse(ready)
        self.assertIn("missing ChatGPT exact-SHA review proof", reason)

    def test_rejects_boolean_blocking_findings(self):
        payloads = []
        for kind in ("code", "security"):
            payload = {
                "provider": "ChatGPT",
                "kind": kind,
                "head_sha": self.HEAD,
                "status": "PASS",
                "blocking_findings": False,
            }
            payloads.append(
                "<!-- chatgpt-exact-sha-review:v1 "
                + json.dumps(payload, separators=(",", ":"))
                + " -->"
            )
        ready, reason = self.run_with_comments(payloads)
        self.assertFalse(ready)
        self.assertIn("blocking_findings=False", reason)

    def test_finish_pr_source_enforces_chatgpt_review_gate(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        finish = source[source.index("def finish_pr(") : source.index("def precommit(")]
        self.assertIn("chatgpt_review_readiness(gh, number, head)", finish)
        self.assertIn("finish-pr ChatGPT CODE/SECURITY review gate not satisfied", finish)
        self.assertNotIn("@codex review", finish)
        self.assertNotIn("@codex security review", finish)


if __name__ == "__main__":
    unittest.main()
