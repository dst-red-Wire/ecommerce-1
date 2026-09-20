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

    def run_with_comments(self, comments):
        completed = subprocess.CompletedProcess(
            [],
            0,
            json.dumps({"comments": [{"body": body} for body in comments]}),
            "",
        )
        with (
            mock.patch.object(REPOCTL, "pull_request_review_policy", return_value=self.policy()),
            mock.patch.object(REPOCTL, "run", return_value=completed),
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

    def test_finish_pr_source_enforces_chatgpt_review_gate(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        finish = source[source.index("def finish_pr(") : source.index("def precommit(")]
        self.assertIn("chatgpt_review_readiness(gh, number, head)", finish)
        self.assertIn("finish-pr ChatGPT CODE/SECURITY review gate not satisfied", finish)
        self.assertNotIn("@codex review", finish)
        self.assertNotIn("@codex security review", finish)


if __name__ == "__main__":
    unittest.main()
