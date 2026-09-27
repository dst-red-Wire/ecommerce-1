from __future__ import annotations

import importlib.util
import hashlib
import hmac
from pathlib import Path
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/trusted_pr_event_consumer.py"
SPEC = importlib.util.spec_from_file_location("trusted_pr_event_consumer", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EventConsumerTests(unittest.TestCase):
    def setUp(self):
        self.payload = {"repository": {"full_name": MODULE.REPOSITORY}, "action": "opened", "pull_request": {"number": 163}}

    def test_pull_request_routes_only_supported_actions(self):
        self.assertEqual(MODULE.event_pr("pull_request", self.payload), 163)
        self.payload["action"] = "closed"
        self.assertIsNone(MODULE.event_pr("pull_request", self.payload))

    def test_wrong_repository_blocks(self):
        self.payload["repository"]["full_name"] = "attacker/repo"
        with self.assertRaises(MODULE.Blocked):
            MODULE.event_pr("pull_request", self.payload)

    def test_webhook_signature_is_required(self):
        raw, secret = b'{"action":"opened"}', "a" * 32
        signature = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        MODULE.verify_webhook(raw, signature, secret)
        for bad_signature, bad_secret in (("", secret), (signature, ""), (signature, "b" * 32)):
            with self.assertRaises(MODULE.Blocked):
                MODULE.verify_webhook(raw, bad_signature, bad_secret)

    def test_owner_comment_only(self):
        self.payload.update({"action": "created", "issue": {"number": 163, "pull_request": {}}, "comment": {"user": {"login": "dst-red-Wire"}, "body": "/owner-authorization approve scope=pr-163 sha=" + "a" * 40}})
        self.assertIsNone(MODULE.event_pr("issue_comment", self.payload))
        self.payload["issue"]["pull_request"] = {"url": "https://api.github.com/pulls/163"}
        self.assertEqual(MODULE.event_pr("issue_comment", self.payload), 163)
        self.payload["comment"]["user"]["login"] = "attacker"
        self.assertIsNone(MODULE.event_pr("issue_comment", self.payload))
        self.payload["comment"]["user"]["login"] = "dst-red-Wire"
        self.payload["comment"]["body"] = "example /owner-authorization approve scope=pr-163 sha=" + "a" * 40
        self.assertIsNone(MODULE.event_pr("issue_comment", self.payload))

    def test_credentials_removed_before_any_evidence_audit(self):
        with mock.patch.dict(MODULE.os.environ, {"GH_TOKEN": "secret", "GITHUB_TOKEN": "secret", "CI_EVIDENCE_COSIGN_KEY": "key", "UNRELATED_TOKEN": "secret", "PATH": "/usr/bin"}):
            env = MODULE.no_credentials_env()
        self.assertEqual(env["PATH"], "/usr/bin")
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "CI_EVIDENCE_COSIGN_KEY", "UNRELATED_TOKEN"):
            self.assertNotIn(name, env)

    def test_live_binding_ignores_event_sha(self):
        repo = {"full_name": MODULE.REPOSITORY, "default_branch": "main"}
        pr = {"number": 163, "state": "open", "draft": False, "base": {"ref": "main", "repo": {"full_name": MODULE.REPOSITORY}, "sha": "a" * 40}, "head": {"sha": "b" * 40}}
        with mock.patch.object(MODULE, "github", side_effect=[repo, pr]):
            self.assertEqual(MODULE.live_binding(163), ("a" * 40, "b" * 40))

    def test_draft_pr_is_blocked_before_mutation(self):
        repo = {"full_name": MODULE.REPOSITORY, "default_branch": "main"}
        pr = {"number": 163, "state": "open", "draft": True, "base": {"ref": "main", "repo": {"full_name": MODULE.REPOSITORY}, "sha": "a" * 40}, "head": {"sha": "b" * 40}}
        with mock.patch.object(MODULE, "github", side_effect=[repo, pr]):
            with self.assertRaises(MODULE.Blocked):
                MODULE.live_binding(163)

    def test_missing_qualification_never_invokes_mutating_transition(self):
        probe = mock.Mock(returncode=0, stdout='{"head_sha":"' + "b" * 40 + '","qualification":{"status":"MISSING"}}')
        with mock.patch.dict(MODULE.os.environ, {"GH_TOKEN": "test-token", "GITHUB_REPOSITORY": MODULE.REPOSITORY}), mock.patch.object(MODULE.subprocess, "run", return_value=probe) as subprocess_run:
            with self.assertRaises(MODULE.Blocked):
                MODULE.transition(Path("/base"), Path("/head"), 163)
        self.assertEqual(subprocess_run.call_count, 1)
        self.assertIn("--dry-run", subprocess_run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
