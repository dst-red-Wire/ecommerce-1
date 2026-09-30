from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import chatgpt_review_dispatcher as dispatcher
from scripts import pr_monitor
from scripts.exact_pr_binding import ExactPRBinding, ExactPRBindingChanged

REPOSITORY = "dst-red-Wire/ecommerce-1"
BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
NEXT_HEAD_SHA = "c" * 40
PR = 169


class FakeTransport:
    def __init__(self):
        self.submissions = []
        self.polls = []
        self.results = []
        self.state = "RUNNING"
        self.bad_result = False

    def submit(self, request, *, idempotency_key):
        self.submissions.append((request, idempotency_key))
        return {"submission_id": "job-one"}

    def status(self, submission_id):
        self.polls.append(submission_id)
        return {"submission_id": submission_id, "state": self.state}

    def fetch_result(self, submission_id):
        self.results.append(submission_id)
        identity = self.submissions[0][1]
        result = {
            "submission_id": submission_id,
            "identity": identity,
            "provider": "ChatGPT",
            "kind": self.submissions[0][0]["review_kind"].lower(),
            "pr": PR,
            "head_sha": self.submissions[0][0]["head_sha"],
            "status": "PASS",
            "blocking_findings": 0,
            "output": "Review text is evidence only.",
        }
        if self.bad_result:
            result["head_sha"] = NEXT_HEAD_SHA
        return result


class ReviewDispatcherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.outbox = Path(self.temporary.name) / "review-dispatch"
        self.binding = ExactPRBinding(
            REPOSITORY, PR, "main", BASE_SHA, "feature/reviews", HEAD_SHA
        )

    def request(self, kind="CODE", *, binding=None):
        binding = binding or self.binding
        previous = {
            "head_sha": BASE_SHA if kind == "CODE" else binding.head_sha,
            "validated_verdict": "" if kind == "CODE" else "CODE_PASS",
        }
        current = {"head_sha": binding.head_sha, "exact_head_verified": True}
        handoff = pr_monitor.chatgpt_review_handoff(
            binding.pr_number,
            previous,
            current,
            {"status": {"modified": {"state": "review"}}},
            ["scripts/repoctl.py"],
            review_kind=kind,
        )
        return {
            "schema_version": 1,
            "event": "CHATGPT_REVIEW_REQUIRED",
            "state": "CHATGPT_REVIEW_REQUIRED",
            "provider": "ChatGPT",
            "review_kind": kind,
            "repository": binding.repository,
            "pr": binding.pr_number,
            "base": binding.base,
            "base_sha": binding.base_sha,
            "head_sha": binding.head_sha,
            "head_branch": binding.head_branch,
            "handoff": handoff,
            "handoff_bytes": len(handoff.encode()),
            "handoff_sha256": hashlib.sha256(handoff.encode()).hexdigest(),
            "expected_marker": {
                "provider": "ChatGPT",
                "kind": kind.lower(),
                "head_sha": binding.head_sha,
                "status": "PASS",
                "blocking_findings": 0,
            },
            "verdict_authority": False,
            "rerun": {
                "argv": [
                    "python3",
                    "scripts/repository_delivery.py",
                    "trusted-pr-transition",
                ],
                "command": "python3 scripts/repository_delivery.py trusted-pr-transition",
                "controller_source": "exact-pr-base-sha",
                "after_valid_marker": True,
            },
        }

    def proof(self, kind, *, binding=None):
        binding = binding or self.binding
        return {
            "provider": "ChatGPT",
            "kind": kind.lower(),
            "head_sha": binding.head_sha,
            "status": "PASS",
            "blocking_findings": 0,
            "pr": binding.pr_number,
            "repository": binding.repository,
            "owner_login": "dst-red-Wire",
            "author_login": "dst-red-Wire",
            "comment_id": 100 if kind == "CODE" else 101,
            "created_at": "2026-09-30T12:00:00Z",
            "updated_at": "2026-09-30T12:00:00Z",
            "is_latest_for_kind": True,
        }

    def dispatch(self, request, *, binding=None, **overrides):
        arguments = {
            "binding": binding or self.binding,
            "outbox_root": self.outbox,
            "binding_revalidator": lambda value: value,
        }
        arguments.update(overrides)
        return dispatcher.dispatch_review_request(request, **arguments)

    def test_no_transport_creates_non_authoritative_blocked_outbox(self):
        request = self.request()
        result = self.dispatch(request)
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("BLOCKED_EXTERNAL_REVIEW_TRANSPORT", result["reason"])
        self.assertIs(result["verdict_authority"], False)
        self.assertEqual("", result["submission_id"])
        self.assertEqual(request["handoff_sha256"], result["handoff_sha256"])
        self.assertTrue(Path(result["outbox_path"]).is_file())
        self.assertEqual(result["identity"], Path(result["outbox_path"]).stem)
        artifact = json.loads(Path(result["outbox_path"]).read_text(encoding="utf-8"))
        self.assertEqual(request, artifact["request"])
        self.assertEqual(result["identity"], self.dispatch(request)["identity"])

    def test_tampered_request_artifact_cannot_be_reused_or_reported(self):
        request = self.request()
        record = self.dispatch(request)
        path = Path(record["outbox_path"])
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["request"]["expected_marker"] = ["malformed"]
        path.write_text(json.dumps(artifact), encoding="utf-8")
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(request)
        with self.assertRaises(dispatcher.ReviewDispatchError):
            dispatcher.dispatch_status(
                self.binding,
                "CODE",
                outbox_root=self.outbox,
                binding_revalidator=lambda value: value,
            )

    def test_code_then_security_requires_exact_owner_marker(self):
        transport = FakeTransport()
        code = self.dispatch(self.request(), transport=transport)
        self.assertEqual("REQUESTED", code["state"])
        self.assertEqual(1, len(transport.submissions))
        security = self.dispatch(self.request("SECURITY"), transport=transport)
        self.assertEqual("BLOCKED", security["state"])
        self.assertEqual("WAITING_CODE_REVIEW", security["reason"])
        self.assertEqual(1, len(transport.submissions))
        code_proof = lambda binding, kind: (
            self.proof("CODE") if kind == "code" else None
        )
        security = self.dispatch(
            self.request("SECURITY"),
            transport=transport,
            owner_marker_lookup=code_proof,
        )
        self.assertEqual("REQUESTED", security["state"])
        self.assertEqual(2, len(transport.submissions))
        both = lambda binding, kind: self.proof(kind.upper())
        verified = self.dispatch(
            self.request("SECURITY"),
            owner_marker_lookup=both,
        )
        self.assertEqual("PASS", verified["state"])
        self.assertEqual("OWNER_MARKER_VERIFIED", verified["reason"])
        self.assertEqual(101, verified["owner_comment_id"])
        self.assertIs(verified["verdict_authority"], False)

    def test_duplicate_submission_uses_same_identity_and_does_not_submit_again(self):
        request = self.request()
        transport = FakeTransport()
        first = self.dispatch(request, transport=transport)
        second = self.dispatch(request, transport=transport)
        self.assertEqual(first["identity"], second["identity"])
        self.assertEqual("RUNNING", second["state"])
        self.assertEqual(1, len(transport.submissions))
        self.assertEqual(["job-one"], transport.polls)

    def test_transport_completion_never_becomes_review_authority(self):
        request = self.request()
        transport = FakeTransport()
        self.dispatch(request, transport=transport)
        transport.state = "COMPLETED"
        result = self.dispatch(request, transport=transport)
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("AWAITING_OWNER_MARKER", result["reason"])
        self.assertTrue(result["result_sha256"])
        self.assertIs(result["verdict_authority"], False)
        self.assertEqual("AWAITING_OWNER_MARKER", self.dispatch(request)["reason"])

    def test_malformed_transport_result_blocks_and_keeps_no_result_digest(self):
        request = self.request()
        transport = FakeTransport()
        self.dispatch(request, transport=transport)
        transport.state = "COMPLETED"
        transport.bad_result = True
        result = self.dispatch(request, transport=transport)
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("BLOCKED_EXTERNAL_REVIEW_RESULT", result["reason"])
        self.assertEqual("", result["result_sha256"])

    def test_transport_result_requires_bound_kind_and_consistent_verdict(self):
        record = {
            "submission_id": "job-one",
            "identity": "d" * 64,
            "review_kind": "CODE",
            "pr": PR,
            "head_sha": HEAD_SHA,
        }
        response = {
            "submission_id": "job-one",
            "identity": "d" * 64,
            "provider": "ChatGPT",
            "kind": "code",
            "pr": PR,
            "head_sha": HEAD_SHA,
            "status": "PASS",
            "blocking_findings": 0,
            "output": "reviewed exact SHA",
        }
        self.assertEqual(64, len(dispatcher._transport_result(response, record)))
        for changes in (
            {"kind": "security"},
            {"status": "PASS", "blocking_findings": 1},
            {"status": "FAIL", "blocking_findings": 0},
            {"provider": "Codex"},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaises(dispatcher.ReviewResultError),
            ):
                dispatcher._transport_result({**response, **changes}, record)

    def test_invalid_owner_proof_never_verifies_review(self):
        forged = self.proof("CODE")
        forged["updated_at"] = "2026-09-30T12:01:00Z"
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(self.request(), owner_marker_lookup=lambda *_: forged)

    def test_wrong_provider_pr_head_base_and_digest_fail_before_outbox(self):
        changes = {
            "provider": "Codex",
            "pr": PR + 1,
            "head_sha": NEXT_HEAD_SHA,
            "base_sha": NEXT_HEAD_SHA,
            "handoff_sha256": "0" * 64,
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                request = self.request()
                request[key] = value
                with self.assertRaises(dispatcher.ReviewDispatchError):
                    self.dispatch(request)
        self.assertFalse(self.outbox.exists())

    def test_handoff_content_and_size_are_checked_not_only_sha(self):
        changes = [
            lambda r: r.update(handoff_bytes=r["handoff_bytes"] + 1),
            lambda r: r.update(
                handoff="forged",
                handoff_bytes=6,
                handoff_sha256=hashlib.sha256(b"forged").hexdigest(),
            ),
            lambda r: r.update(
                handoff=r["handoff"].replace(
                    '"current_head":"' + HEAD_SHA + '"',
                    '"current_head":"' + NEXT_HEAD_SHA + '"',
                ),
                handoff_sha256=hashlib.sha256(
                    r["handoff"]
                    .replace(
                        '"current_head":"' + HEAD_SHA + '"',
                        '"current_head":"' + NEXT_HEAD_SHA + '"',
                    )
                    .encode()
                ).hexdigest(),
            ),
        ]
        for mutate in changes:
            request = self.request()
            mutate(request)
            with self.assertRaises(dispatcher.ReviewDispatchError):
                self.dispatch(request)

    def test_new_head_supersedes_old_outbox_and_stale_binding_cannot_submit(self):
        old = self.dispatch(self.request())
        new_binding = ExactPRBinding(
            REPOSITORY, PR, "main", BASE_SHA, "feature/reviews", NEXT_HEAD_SHA
        )
        new = self.dispatch(self.request(binding=new_binding), binding=new_binding)
        self.assertEqual("BLOCKED", new["state"])
        self.assertEqual("BLOCKED_EXTERNAL_REVIEW_TRANSPORT", new["reason"])
        self.assertEqual(
            "SUPERSEDED", json.loads(Path(old["outbox_path"]).read_text())["state"]
        )
        stale = self.dispatch(
            self.request(),
            binding_revalidator=lambda _: (_ for _ in ()).throw(
                ExactPRBindingChanged("HEAD_CHANGED", current_head_sha=NEXT_HEAD_SHA)
            ),
        )
        self.assertEqual("SUPERSEDED", stale["state"])

    def test_unknown_schema_field_and_rerun_execution_metadata_rejected(self):
        request = self.request()
        request["marker_is_pass"] = True
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(request)
        request = self.request()
        request["rerun"]["after_valid_marker"] = False
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(request)

    def github_comment(
        self,
        comment_id,
        status,
        blockers,
        *,
        author="dst-red-Wire",
        head=HEAD_SHA,
        kind="code",
        edited=False,
    ):
        marker = json.dumps(
            {
                "provider": "ChatGPT",
                "kind": kind,
                "head_sha": head,
                "status": status,
                "blocking_findings": blockers,
            },
            separators=(",", ":"),
        )
        return {
            "id": comment_id,
            "created_at": f"2026-09-30T12:{comment_id:02d}:00Z",
            "updated_at": f"2026-09-30T12:{comment_id + int(edited):02d}:00Z",
            "user": {"login": author},
            "body": f"CODE review\n<!-- chatgpt-exact-sha-review:v1 {marker} -->",
        }

    def github_lookup(self, comments):
        response = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps([comments]),
            stderr="",
        )
        with mock.patch.object(
            dispatcher.subprocess, "run", return_value=response
        ) as run:
            proof = dispatcher.github_owner_marker_lookup(self.binding, "code")
        self.assertEqual(
            [
                "gh",
                "api",
                "--paginate",
                "--slurp",
                f"repos/{REPOSITORY}/issues/{PR}/comments?per_page=100",
            ],
            run.call_args.args[0],
        )
        return proof

    def test_github_owner_lookup_uses_latest_unedited_exact_marker(self):
        proof = self.github_lookup(
            [
                self.github_comment(1, "PASS", 0),
                self.github_comment(2, "PASS", 0, author="other-user"),
                self.github_comment(3, "PASS", 0, head=NEXT_HEAD_SHA),
                self.github_comment(4, "BLOCKED", 2),
            ]
        )
        self.assertEqual(4, proof["comment_id"])
        self.assertEqual("BLOCKED", proof["status"])
        result = self.dispatch(self.request(), owner_marker_lookup=lambda *_: proof)
        self.assertEqual("FAIL", result["state"])
        self.assertIs(result["verdict_authority"], False)

    def test_edited_latest_owner_marker_blocks_older_pass(self):
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.github_lookup(
                [
                    self.github_comment(1, "PASS", 0),
                    self.github_comment(2, "PASS", 0, edited=True),
                ]
            )

    def test_multiple_markers_in_owner_comment_are_rejected(self):
        comment = self.github_comment(1, "PASS", 0)
        comment["body"] += "\n" + comment["body"].splitlines()[-1]
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.github_lookup([comment])

    def test_security_does_not_start_after_failed_code_marker(self):
        transport = FakeTransport()
        failed_code = self.proof("CODE")
        failed_code.update(status="BLOCKED", blocking_findings=1)
        result = self.dispatch(
            self.request("SECURITY"),
            transport=transport,
            owner_marker_lookup=lambda _, kind: failed_code if kind == "code" else None,
        )
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("CODE_REVIEW_FAILED", result["reason"])
        self.assertEqual([], transport.submissions)

    def test_policy_change_fails_closed_before_creating_outbox(self):
        policy = Path(self.temporary.name) / "policy.yaml"
        policy.write_text(
            dispatcher.POLICY_PATH.read_text(encoding="utf-8").replace(
                "verdict_authority: false", "verdict_authority: true"
            ),
            encoding="utf-8",
        )
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(self.request(), policy_path=policy)
        self.assertFalse(self.outbox.exists())

    def test_nonowner_marker_does_not_supply_proof(self):
        self.assertIsNone(
            self.github_lookup(
                [
                    self.github_comment(1, "PASS", 0, author="codex-bot"),
                ]
            )
        )

    def test_duplicate_json_key_in_owner_marker_is_rejected(self):
        comment = self.github_comment(1, "PASS", 0)
        comment["body"] = comment["body"].replace(
            '"status":"PASS"',
            '"status":"BLOCKED","status":"PASS"',
        )
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.github_lookup([comment])

    def test_read_only_status_reports_outbox_without_granting_authority(self):
        empty = dispatcher.dispatch_status(
            self.binding,
            "CODE",
            outbox_root=self.outbox,
            binding_revalidator=lambda value: value,
        )
        self.assertEqual("NOT_REQUESTED", empty["state"])
        self.assertFalse(self.outbox.exists())
        dispatched = self.dispatch(self.request())
        current = dispatcher.dispatch_status(
            self.binding,
            "CODE",
            outbox_root=self.outbox,
            binding_revalidator=lambda value: value,
        )
        self.assertEqual("BLOCKED", current["state"])
        self.assertEqual("BLOCKED_EXTERNAL_REVIEW_TRANSPORT", current["reason"])
        self.assertEqual(dispatched["identity"], current["records"][0]["identity"])
        self.assertIs(current["verdict_authority"], False)

    def test_read_only_status_detects_head_supersession(self):
        state = dispatcher.dispatch_status(
            self.binding,
            "CODE",
            outbox_root=self.outbox,
            binding_revalidator=lambda _: (_ for _ in ()).throw(
                ExactPRBindingChanged("HEAD_CHANGED", current_head_sha=NEXT_HEAD_SHA)
            ),
        )
        self.assertEqual("SUPERSEDED", state["state"])
        self.assertEqual(NEXT_HEAD_SHA, state["current_head_sha"])
        self.assertFalse(self.outbox.exists())

    def test_symlinked_outbox_parent_is_rejected(self):
        target = Path(self.temporary.name) / "target"
        target.mkdir()
        link = Path(self.temporary.name) / "link"
        link.symlink_to(target, target_is_directory=True)
        self.outbox = link / "review-dispatch"
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(self.request())
        self.assertEqual([], list(target.iterdir()))


if __name__ == "__main__":
    unittest.main()
