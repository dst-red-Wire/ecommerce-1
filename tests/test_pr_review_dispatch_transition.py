"""The PR-head adapter can request review but cannot create review authority."""

import hashlib
from pathlib import Path
from unittest import TestCase, mock

from scripts import pr_review_dispatch_transition as transition
from scripts.exact_pr_binding import ExactPRBinding

HEAD = "a" * 40
BASE = "b" * 40
BRANCH = "feature/exact-review"
REPOSITORY = "dst-red-Wire/ecommerce-1"


def controller(kind="CODE", *, pr=169, head=HEAD, base=BASE):
    handoff = "exact-handoff"
    review = {
        "event": "CHATGPT_REVIEW_REQUIRED",
        "state": "CHATGPT_REVIEW_REQUIRED",
        "provider": "ChatGPT",
        "review_kind": kind,
        "pr": pr,
        "head_sha": head,
        "handoff": handoff,
        "handoff_bytes": len(handoff),
        "handoff_sha256": hashlib.sha256(handoff.encode()).hexdigest(),
        "expected_marker": {
            "provider": "ChatGPT",
            "kind": kind.lower(),
            "head_sha": head,
            "status": "PASS",
            "blocking_findings": 0,
        },
        "rerun": {
            "argv": ["python3", "trusted.py"],
            "command": "python3 trusted.py",
            "controller_source": "exact-pr-base-sha",
            "after_valid_marker": True,
        },
        "verdict_authority": False,
    }
    return {
        "schema_version": 2,
        "pr": pr,
        "head_sha": head,
        "head_branch": BRANCH,
        "base": "main",
        "state": "CHATGPT_REVIEW_REQUIRED",
        "qualification": {"status": "PASS", "head_sha": head, "base_sha": base},
        "code_review": {"status": "MISSING", "head_sha": head},
        "security_review": {"status": "MISSING", "head_sha": head},
        "review_request": review,
        "blockers": [],
    }


class PRReviewDispatchTransitionTest(TestCase):
    def setUp(self):
        self.binding = ExactPRBinding(REPOSITORY, 169, "main", BASE, BRANCH, HEAD)

    def local_git(self):
        return mock.patch.object(transition, "_git", side_effect=["", HEAD, BRANCH])

    def test_code_dispatch_uses_exact_binding_and_reports_absent_transport(self):
        record = {
            "state": "BLOCKED",
            "reason": "BLOCKED_EXTERNAL_REVIEW_TRANSPORT",
            "identity": "c" * 64,
            "outbox_path": "/tmp/request.json",
            "verdict_authority": False,
        }
        dispatch = mock.Mock(return_value=record)
        with self.local_git():
            result = transition.dispatch_controller_result(
                controller(),
                pr_number=169,
                target_root=Path("/repo"),
                resolver=lambda *args, **kwargs: self.binding,
                dispatcher=dispatch,
                marker_lookup=lambda *_: None,
            )
        self.assertEqual("BLOCKED_EXTERNAL_REVIEW_TRANSPORT", result["state"])
        self.assertEqual("BLOCKED", result["review_dispatch"]["status"])
        self.assertFalse(result["review_dispatch"]["verdict_authority"])
        request = dispatch.call_args.args[0]
        self.assertEqual(self.binding.base_sha, request["base_sha"])
        self.assertEqual(self.binding.repository, request["repository"])
        self.assertEqual(self.binding.head_branch, request["head_branch"])

    def test_security_cannot_dispatch_without_exact_code_pass(self):
        with (
            self.local_git(),
            self.assertRaisesRegex(transition.ReviewTransitionError, "CODE PASS"),
        ):
            transition.dispatch_controller_result(
                controller("SECURITY"),
                pr_number=169,
                target_root=Path("/repo"),
                resolver=lambda *args, **kwargs: self.binding,
            )

    def test_wrong_pr_and_changed_handoff_are_rejected(self):
        wrong = ExactPRBinding(REPOSITORY, 170, "main", BASE, BRANCH, HEAD)
        with (
            self.local_git(),
            self.assertRaisesRegex(transition.ReviewTransitionError, "number differs"),
        ):
            transition.dispatch_controller_result(
                controller(),
                pr_number=169,
                target_root=Path("/repo"),
                resolver=lambda *args, **kwargs: wrong,
            )
        tampered = controller()
        tampered["review_request"]["handoff"] = "changed-handoff"
        with self.assertRaisesRegex(transition.ReviewTransitionError, "malformed"):
            transition._request_from_controller(tampered, self.binding)

    def test_dry_run_prepares_no_outbox_or_transport(self):
        dispatch = mock.Mock()
        with self.local_git():
            result = transition.dispatch_controller_result(
                controller(),
                pr_number=169,
                target_root=Path("/repo"),
                dry_run=True,
                resolver=lambda *args, **kwargs: self.binding,
                dispatcher=dispatch,
            )
        dispatch.assert_not_called()
        self.assertEqual("NOT_REQUESTED", result["review_dispatch"]["status"])

    def test_verified_marker_reruns_trusted_controller_once(self):
        review = controller()
        owner = {"state": "OWNER_AUTH_REQUIRED", "pr": 169, "head_sha": HEAD}
        with (
            mock.patch.object(
                transition, "_trusted_transition", side_effect=[(0, review), (0, owner)]
            ) as trusted,
            mock.patch.object(
                transition,
                "dispatch_controller_result",
                return_value={
                    **review,
                    "review_dispatch": {"status": "PASS", "kind": "CODE"},
                },
            ),
        ):
            code, result = transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
            )
        self.assertEqual(0, code)
        self.assertEqual("OWNER_AUTH_REQUIRED", result["state"])
        self.assertEqual(2, trusted.call_count)

    def test_new_qualification_settles_handoff_before_dispatch(self):
        first = controller()
        first["qualification"]["source"] = "executed"
        settled = controller()
        settled["qualification"]["source"] = "reused"
        blocked = {
            **settled,
            "state": "BLOCKED_EXTERNAL_REVIEW_TRANSPORT",
            "review_dispatch": {"status": "BLOCKED", "kind": "CODE"},
        }
        with (
            mock.patch.object(
                transition,
                "_trusted_transition",
                side_effect=[(0, first), (0, settled)],
            ) as trusted,
            mock.patch.object(
                transition, "dispatch_controller_result", return_value=blocked
            ) as dispatch,
        ):
            rc, result = transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
            )
        self.assertEqual(1, rc)
        self.assertEqual("BLOCKED_EXTERNAL_REVIEW_TRANSPORT", result["state"])
        self.assertEqual(2, trusted.call_count)
        self.assertIs(settled, dispatch.call_args.args[0])

    def test_unstable_qualification_handoff_blocks_before_dispatch(self):
        first = controller()
        first["qualification"]["source"] = "executed"
        again = controller()
        again["qualification"]["source"] = "executed"
        with (
            mock.patch.object(
                transition, "_trusted_transition", side_effect=[(0, first), (0, again)]
            ),
            mock.patch.object(transition, "dispatch_controller_result") as dispatch,
            self.assertRaisesRegex(
                transition.ReviewTransitionError, "did not stabilize"
            ),
        ):
            transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
            )
        dispatch.assert_not_called()

    def test_failed_code_stops_without_dispatch(self):
        failed = {"state": "CODE_FAILED", "pr": 169, "head_sha": HEAD}
        with mock.patch.object(
            transition, "_trusted_transition", return_value=(1, failed)
        ):
            code, result = transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
            )
        self.assertEqual(1, code)
        self.assertEqual("CODE_FAILED", result["state"])

    def test_owner_fail_marker_stops_before_security(self):
        review = controller()
        with (
            mock.patch.object(
                transition, "_trusted_transition", return_value=(0, review)
            ) as trusted,
            mock.patch.object(
                transition,
                "dispatch_controller_result",
                return_value={
                    **review,
                    "review_dispatch": {"status": "FAIL", "kind": "CODE"},
                },
            ),
        ):
            code, result = transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
            )
        self.assertEqual(1, code)
        self.assertEqual("CODE_FAILED", result["state"])
        trusted.assert_called_once()

    def test_status_reads_only_the_current_exact_pr_outbox(self):
        status = {"state": "REQUESTED", "verdict_authority": False}
        with (
            mock.patch.object(transition, "_git", side_effect=[HEAD, BRANCH]),
            mock.patch.object(transition.shutil, "which", return_value="/gh"),
            mock.patch.object(
                transition, "resolve_exact_open_pr", return_value=self.binding
            ) as resolver,
            mock.patch.object(
                transition, "dispatch_status", return_value=status
            ) as reader,
        ):
            result = transition.review_dispatch_status(Path("/repo"), 169, "CODE")
        self.assertEqual(status, result)
        resolver.assert_called_once_with(REPOSITORY, HEAD, BRANCH, "main", gh="/gh")
        reader.assert_called_once_with(self.binding, "CODE", gh="/gh")

    def test_status_rejects_a_different_pr(self):
        with (
            mock.patch.object(transition, "_git", side_effect=[HEAD, BRANCH]),
            mock.patch.object(transition.shutil, "which", return_value="/gh"),
            mock.patch.object(
                transition, "resolve_exact_open_pr", return_value=self.binding
            ),
            mock.patch.object(transition, "dispatch_status") as reader,
            self.assertRaisesRegex(transition.ReviewTransitionError, "number differs"),
        ):
            transition.review_dispatch_status(Path("/repo"), 170, "CODE")
        reader.assert_not_called()

    def test_edited_owner_marker_blocks_before_trusted_transition(self):
        with (
            mock.patch.object(transition, "_git", side_effect=["", HEAD, BRANCH]),
            mock.patch.object(transition.shutil, "which", return_value="/gh"),
            mock.patch.object(
                transition, "resolve_exact_open_pr", return_value=self.binding
            ),
            mock.patch.object(
                transition,
                "github_owner_marker_lookup",
                side_effect=transition.ReviewDispatchError("latest marker was edited"),
            ),
            mock.patch.object(transition, "_trusted_transition") as trusted,
            self.assertRaises(transition.ReviewDispatchError),
        ):
            transition.transition(Path("/trusted"), Path("/target"), 169)
        trusted.assert_not_called()
