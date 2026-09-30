"""Exact-SHA ChatGPT owner reviews must precede the native UAC bootstrap."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import repoctl


CAMPAIGN = "20260929T163821Z-9da62296f3d5"
SHA = "a" * 40
VM_ID = "e80d60f3-a12e-4734-a654-0cd24dce0fa1"
OWNER = "dst-red-Wire"


def marker(kind: str, *, sha: str = SHA, status: str = "PASS",
           findings: int = 0) -> str:
    payload = {
        "provider": "ChatGPT", "kind": kind, "head_sha": sha,
        "status": status, "blocking_findings": findings,
    }
    return "<!-- chatgpt-exact-sha-review:v1 " + json.dumps(
        payload, separators=(",", ":")) + " -->"


def issue_comment(identifier: int, author: str, body: str, minute: int,
                  association: str = "OWNER") -> dict:
    timestamp = f"2026-09-30T02:{minute:02d}:00Z"
    return {
        "id": identifier, "user": {"login": author}, "author_association": association,
        "body": body, "created_at": timestamp, "updated_at": timestamp,
    }


class NativeUacReviewGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pr = {
            "number": 169, "state": "OPEN", "draft": False, "base": "main",
            "head_sha": SHA, "head_repository": "dst-red-Wire/ecommerce-1",
        }
        self.code = issue_comment(101, OWNER, "CODE: PASS\n" + marker("code"), 1)
        self.security = issue_comment(102, OWNER, "SECURITY: PASS\n" + marker("security"), 2)
        self.owner = issue_comment(
            103, OWNER,
            f"NATIVE-UAC-V1 PR=169 SHA={SHA} CAMPAIGN={CAMPAIGN} VM={VM_ID} "
            "CODE=101 SECURITY=102 APPROVED", 3,
        )
        self.comments = [self.code, self.security, self.owner]

    def gate(self) -> tuple[bool, str]:
        def issue_comments_only(_gh: str, endpoint: str) -> list[dict]:
            self.assertIn("/issues/169/comments?per_page=100", endpoint)
            return self.comments

        with (mock.patch.object(repoctl, "_github_pr_snapshot", return_value=self.pr),
              mock.patch.object(repoctl, "_native_uac_paginated_comments",
                                side_effect=issue_comments_only)):
            return repoctl._native_uac_review_gate("/usr/bin/gh", CAMPAIGN, SHA, VM_ID)

    def test_exact_chatgpt_reviews_and_later_owner_authorization_pass(self) -> None:
        self.assertTrue(self.gate()[0])
        self.comments.append(issue_comment(
            104, "chatgpt-codex-connector[bot]", "Codex adverse historical finding", 4,
            association="NONE"))
        self.assertTrue(self.gate()[0])

    def test_wrong_pr_identity_or_unavailable_api_fails_closed(self) -> None:
        for key, value in (("state", "CLOSED"), ("base", "other"),
                           ("head_sha", "b" * 40), ("head_repository", "attacker/repo"),
                           ("draft", True)):
            with self.subTest(key=key):
                original = self.pr[key]
                self.pr[key] = value
                self.assertFalse(self.gate()[0])
                self.pr[key] = original
        with mock.patch.object(repoctl, "_github_pr_snapshot", side_effect=RuntimeError("offline")):
            self.assertFalse(repoctl._native_uac_review_gate("gh", CAMPAIGN, SHA, VM_ID)[0])

    def test_missing_blocked_wrong_sha_or_ambiguous_marker_fails_closed(self) -> None:
        for body in (
            marker("security", status="BLOCKED", findings=1),
            marker("security", status="PASS", findings=1),
            marker("security", sha="b" * 40),
            "<!-- chatgpt-exact-sha-review:v1 {bad JSON} -->",
            marker("security") + "\n" + marker("security"),
        ):
            with self.subTest(body=body[:48]):
                self.security["body"] = body
                self.assertFalse(self.gate()[0])
        self.security["body"] = marker("security")
        self.comments = [self.code, self.owner]
        self.assertFalse(self.gate()[0])

    def test_latest_blocked_review_revokes_prior_pass_until_new_owner_approval(self) -> None:
        self.comments.append(issue_comment(
            104, OWNER, "SECURITY: BLOCKED\n" +
            marker("security", status="BLOCKED", findings=1), 4))
        self.assertIn("not clean", self.gate()[1])
        self.comments.append(issue_comment(105, OWNER, marker("security"), 5))
        self.assertFalse(self.gate()[0])  # Prior authorization names security comment 102.
        self.comments.append(issue_comment(
            106, OWNER,
            f"NATIVE-UAC-V1 PR=169 SHA={SHA} CAMPAIGN={CAMPAIGN} VM={VM_ID} "
            "CODE=101 SECURITY=105 APPROVED", 6))
        self.assertTrue(self.gate()[0])

    def test_only_repository_owner_comments_have_review_and_approval_authority(self) -> None:
        self.code["user"]["login"] = "other-user"
        self.assertFalse(self.gate()[0])
        self.code["user"]["login"] = OWNER
        self.code["author_association"] = "CONTRIBUTOR"
        self.assertFalse(self.gate()[0])
        self.code["author_association"] = "OWNER"
        self.owner["author_association"] = "CONTRIBUTOR"
        self.assertFalse(self.gate()[0])

    def test_edited_review_or_approval_cannot_reuse_creation_order(self) -> None:
        self.code["updated_at"] = "2026-09-30T02:04:00Z"
        self.assertFalse(self.gate()[0])
        self.code["updated_at"] = self.code["created_at"]
        self.owner["updated_at"] = "2026-09-30T02:04:00Z"
        self.assertFalse(self.gate()[0])

    def test_owner_approval_must_be_exact_later_and_reference_both_review_ids(self) -> None:
        self.owner["created_at"] = "2026-09-30T02:01:30Z"
        self.owner["updated_at"] = self.owner["created_at"]
        self.assertFalse(self.gate()[0])
        self.owner["created_at"] = "2026-09-30T02:03:00Z"
        self.owner["updated_at"] = self.owner["created_at"]
        self.owner["body"] = self.owner["body"].replace("CODE=101", "CODE=999")
        self.assertFalse(self.gate()[0])
        self.owner["body"] = self.owner["body"].replace("CODE=999", "CODE=101")
        self.owner["user"]["login"] = "other-user"
        self.assertFalse(self.gate()[0])
        self.owner["user"]["login"] = OWNER
        self.comments.append(issue_comment(
            104, OWNER, f"NATIVE-UAC-V1 PR=169 SHA={SHA} REVOKED", 4))
        self.assertFalse(self.gate()[0])

    def test_paginated_owner_issue_comments_reject_malformed_payload(self) -> None:
        one = issue_comment(1, OWNER, "old", 1)
        two = issue_comment(2, OWNER, "new", 2)
        response = subprocess.CompletedProcess([], 0, json.dumps([one]) + "\n" + json.dumps([two]), "")
        endpoint = "repos/dst-red-Wire/ecommerce-1/issues/169/comments?per_page=100"
        with mock.patch.object(repoctl, "run", return_value=response) as run:
            self.assertEqual(repoctl._native_uac_paginated_comments("/usr/bin/gh", endpoint),
                             [one, two])
        self.assertEqual(run.call_args.args[0], ["/usr/bin/gh", "api", "--paginate", endpoint])
        with mock.patch.object(repoctl, "run", return_value=subprocess.CompletedProcess([], 0, "{}", "")):
            with self.assertRaises(RuntimeError):
                repoctl._native_uac_paginated_comments("gh", endpoint)

    def test_prepare_and_elevated_selftest_refuse_before_staging_or_bootstrap(self) -> None:
        def git_value(*args):
            return "" if args[0] == "status" else SHA

        for action in ("Prepare", "SelfTest"):
            with (self.subTest(action=action),
                  mock.patch.object(repoctl, "git", side_effect=git_value),
                  mock.patch.object(repoctl.os.path, "isfile", return_value=True),
                  mock.patch.object(repoctl.os, "access", return_value=True),
                  mock.patch.object(repoctl, "_native_uac_review_gate", return_value=(False, "denied")),
                  mock.patch.object(repoctl, "lab_network_native_prepare") as prepare,
                  mock.patch.object(repoctl, "_native_bootstrap_script") as bootstrap,
                  contextlib.redirect_stderr(io.StringIO())):
                self.assertNotEqual(repoctl.lab_network_native_boot(action, CAMPAIGN, VM_ID), 0)
                prepare.assert_not_called()
                bootstrap.assert_not_called()

    def test_selftest_cli_requires_vm_id_before_any_uac(self) -> None:
        result = subprocess.run(
            [sys.executable, str(repoctl.ROOT / "scripts/repoctl.py"),
             "lab-network-native-boot-self-test", "--campaign-id", CAMPAIGN],
            text=True, capture_output=True, timeout=20,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--expected-vm-id", result.stderr)


if __name__ == "__main__":
    unittest.main()
