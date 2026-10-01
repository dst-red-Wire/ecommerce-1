from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from scripts import pr_review_convergence as convergence
from scripts.exact_pr_binding import ExactPRBinding

HEAD = "b" * 40
BASE = "a" * 40
MERGE = "c" * 40
BINDING = ExactPRBinding(
    "dst-red-Wire/ecommerce-1", 169, "main", BASE, "feature/review", HEAD
)


def proof(kind: str, comment_id: int, created: str) -> dict:
    return {
        "provider": "ChatGPT",
        "kind": kind,
        "head_sha": HEAD,
        "repository": BINDING.repository,
        "pr": BINDING.pr_number,
        "status": "PASS",
        "blocking_findings": 0,
        "author_login": "dst-red-Wire",
        "owner_login": "dst-red-Wire",
        "created_at": created,
        "updated_at": created,
        "comment_id": comment_id,
        "is_latest_for_kind": True,
    }


CODE = proof("code", 10, "2026-10-01T12:00:00Z")
SECURITY = proof("security", 11, "2026-10-01T12:01:00Z")


def revalidate(binding: ExactPRBinding, *, gh: str) -> ExactPRBinding:
    return binding


def marker_lookup(binding: ExactPRBinding, kind: str, *, gh: str) -> dict:
    return CODE if kind == "code" else SECURITY


def review_controller(trusted: Path, target: Path, kind: str = "CODE") -> dict:
    return {
        "state": "CHATGPT_REVIEW_REQUIRED",
        "pr": BINDING.pr_number,
        "head_sha": HEAD,
        "review_request": {
            **BINDING.as_dict(),
            "pr": BINDING.pr_number,
            "review_kind": kind,
            "verdict_authority": False,
            "rerun": {
                "argv": [
                    sys.executable,
                    str(trusted.resolve() / "scripts/repository_delivery.py"),
                    "trusted-pr-transition",
                    "--target-root",
                    str(target.resolve()),
                    "--pr",
                    str(BINDING.pr_number),
                ],
                "controller_source": "exact-pr-base-sha",
                "after_valid_marker": True,
            },
        },
        "review_dispatch": {
            "status": "PASS",
            "reason": "OWNER_MARKER_VERIFIED",
            "verdict_authority": False,
            "head_sha": HEAD,
            "pr": BINDING.pr_number,
            "kind": kind,
        },
    }


def uac_controller() -> dict:
    return {
        "state": "OWNER_AUTH_REQUIRED",
        "pr": 169,
        "head_sha": HEAD,
        "owner_authorization_required": True,
        "owner_authorization": {
            "status": "MISSING",
            "command": f"/owner-authorization approve scope=pr-169 sha={HEAD}",
        },
        "code_review": {
            "status": "PASS",
            "head_sha": HEAD,
            "blocking_findings": 0,
            "comment_id": 10,
        },
        "security_review": {
            "status": "PASS",
            "head_sha": HEAD,
            "blocking_findings": 0,
            "comment_id": 11,
        },
    }


def uac_comment(comment_id: int = 42, *, updated: str | None = None) -> dict:
    created = "2026-10-01T12:02:00Z"
    return {
        "id": comment_id,
        "body": f"/owner-authorization approve scope=pr-169 sha={HEAD}",
        "user": {"login": "dst-red-Wire"},
        "author_association": "OWNER",
        "created_at": created,
        "updated_at": updated or created,
    }


class ConvergenceTest(unittest.TestCase):
    def test_exact_rerun_argv_after_owner_marker(self):
        trusted = Path("/trusted")
        target = Path("/target")
        controller = review_controller(trusted, target)
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0))
        rc = convergence.rerun_after_review_marker(
            controller,
            BINDING,
            trusted_root=trusted,
            target_root=target,
            gh="gh",
            marker_lookup=marker_lookup,
            revalidator=revalidate,
            runner=runner,
        )
        self.assertEqual(0, rc)
        self.assertEqual(
            controller["review_request"]["rerun"]["argv"],
            runner.call_args.args[0],
        )
        self.assertGreaterEqual(runner.call_args.kwargs["cwd"], target)

    def test_rerun_rejects_edited_marker_and_wrong_argv(self):
        trusted = Path("/trusted")
        target = Path("/target")
        controller = review_controller(trusted, target)
        runner = mock.Mock()
        edited = dict(CODE, updated_at="2026-10-01T12:00:01Z")
        with self.assertRaisesRegex(convergence.ReviewConvergenceError, "marker"):
            convergence.rerun_after_review_marker(
                controller,
                BINDING,
                trusted_root=trusted,
                target_root=target,
                gh="gh",
                marker_lookup=lambda *_args, **_kwargs: edited,
                revalidator=revalidate,
                runner=runner,
            )
        runner.assert_not_called()
        controller["review_request"]["rerun"]["argv"].append("--json")
        with self.assertRaisesRegex(convergence.ReviewConvergenceError, "argv"):
            convergence.rerun_after_review_marker(
                controller,
                BINDING,
                trusted_root=trusted,
                target_root=target,
                gh="gh",
                marker_lookup=marker_lookup,
                revalidator=revalidate,
                runner=runner,
            )
        runner.assert_not_called()

    def test_security_rerun_requires_chronological_code(self):
        controller = review_controller(Path("/trusted"), Path("/target"), "SECURITY")
        early = dict(
            SECURITY,
            created_at="2026-09-30T12:00:00Z",
            updated_at="2026-09-30T12:00:00Z",
        )
        with self.assertRaisesRegex(convergence.ReviewConvergenceError, "predates"):
            convergence.rerun_after_review_marker(
                controller,
                BINDING,
                trusted_root=Path("/trusted"),
                target_root=Path("/target"),
                gh="gh",
                marker_lookup=lambda _binding, kind, **_: (
                    CODE if kind == "code" else early
                ),
                revalidator=revalidate,
                runner=mock.Mock(),
            )

    def test_uac_requires_campaign_opt_in_and_never_posts_as_bot(self):
        api = mock.Mock(return_value={"login": "automation-bot"})
        comments = mock.Mock(return_value=[])
        result = convergence.publish_owner_authorization(
            uac_controller(),
            BINDING,
            gh="gh",
            marker_lookup=marker_lookup,
            revalidator=revalidate,
            github_api=api,
            comments_reader=comments,
        )
        self.assertEqual("AWAITING_OWNER_MARKER", result["status"])
        api.assert_not_called()
        result = convergence.publish_owner_authorization(
            uac_controller(),
            BINDING,
            gh="gh",
            marker_lookup=marker_lookup,
            revalidator=revalidate,
            github_api=api,
            comments_reader=comments,
            authorization_binding=f"169:{HEAD}",
        )
        self.assertEqual("AWAITING_OWNER_MARKER", result["status"])
        api.assert_called_once_with("gh", ["user"])

    def test_uac_reuses_existing_immutable_owner_comment(self):
        api = mock.Mock()
        result = convergence.publish_owner_authorization(
            uac_controller(),
            BINDING,
            gh="gh",
            marker_lookup=marker_lookup,
            revalidator=revalidate,
            github_api=api,
            comments_reader=lambda *_: [uac_comment()],
            authorization_binding=f"169:{HEAD}",
        )
        self.assertEqual(
            {"status": "PASS", "published": False, "comment_id": 42}, result
        )
        api.assert_not_called()

    def test_uac_publishes_exact_command_and_verifies_github(self):
        comments: list[dict] = []

        def api(_gh: str, args: list[str], **kwargs):
            if args == ["user"]:
                return {"login": "dst-red-Wire"}
            self.assertEqual("--method", args[0])
            self.assertIn(f"sha={HEAD}", kwargs["input_text"])
            comment = uac_comment()
            comments.append(comment)
            return comment

        result = convergence.publish_owner_authorization(
            uac_controller(),
            BINDING,
            gh="gh",
            marker_lookup=marker_lookup,
            revalidator=revalidate,
            github_api=api,
            comments_reader=lambda *_: comments,
            authorization_binding=f"169:{HEAD}",
        )
        self.assertEqual(
            {"status": "PASS", "published": True, "comment_id": 42}, result
        )

    def test_edited_uac_refused(self):
        with self.assertRaisesRegex(convergence.ReviewConvergenceError, "edited"):
            convergence.publish_owner_authorization(
                uac_controller(),
                BINDING,
                gh="gh",
                marker_lookup=marker_lookup,
                revalidator=revalidate,
                github_api=mock.Mock(),
                comments_reader=lambda *_: [
                    uac_comment(updated="2026-10-01T12:03:00Z")
                ],
                authorization_binding=f"169:{HEAD}",
            )

    def test_reconcile_merged_exact_sha_and_unknown(self):
        payload = {
            "number": 169,
            "state": "closed",
            "merged": True,
            "merged_at": "2026-10-01T12:10:00Z",
            "merge_commit_sha": MERGE,
            "head": {
                "ref": BINDING.head_branch,
                "sha": HEAD,
                "repo": {"full_name": BINDING.repository},
            },
            "base": {
                "ref": "main",
                "sha": BASE,
                "repo": {"full_name": BINDING.repository},
            },
        }
        result = convergence.reconcile_post_rerun(
            BINDING, gh="gh", github_api=lambda *_: payload
        )
        self.assertEqual({"status": "MERGED", "merge_sha": MERGE}, result)
        changed = dict(payload, head={**payload["head"], "sha": "d" * 40})
        self.assertEqual(
            "SUPERSEDED",
            convergence.reconcile_post_rerun(
                BINDING, gh="gh", github_api=lambda *_: changed
            )["status"],
        )
        self.assertEqual(
            "UNKNOWN",
            convergence.reconcile_post_rerun(
                BINDING,
                gh="gh",
                github_api=mock.Mock(
                    side_effect=convergence.ReviewConvergenceError("offline")
                ),
            )["status"],
        )


if __name__ == "__main__":
    unittest.main()
