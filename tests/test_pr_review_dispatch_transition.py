"""The PR-head adapter can request review but cannot create review authority."""

import hashlib
import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from scripts import chatgpt_review_transport as review_transport
from scripts import pr_monitor
from scripts import pr_review_dispatch_transition as transition
from scripts.exact_pr_binding import (
    ExactPRBinding,
    ExactPRBindingChanged,
    ExactPRBindingError,
)

HEAD = "a" * 40
BASE = "b" * 40
BRANCH = "feature/exact-review"
REPOSITORY = "dst-red-Wire/ecommerce-1"
TREE = "c" * 40
EVIDENCE_DIGEST = "sha256:" + "d" * 64
BOOTSTRAP_BASE = "ced96d663c1dca1c885d450104f344c10431738d"
BOOTSTRAP_BRANCH = "feat/controller-compat-bootstrap"


def controller(
    kind="CODE",
    *,
    pr=169,
    head=HEAD,
    base=BASE,
    branch=BRANCH,
    tree=TREE,
    structured=True,
):
    handoff = pr_monitor.chatgpt_review_handoff(
        pr,
        {
            "head_sha": base if kind == "CODE" else head,
            "validated_verdict": "" if kind == "CODE" else "CODE_PASS",
        },
        {"head_sha": head, "exact_head_verified": True},
        {"status": {"modified": {"state": "review"}}},
        ["scripts/repoctl.py"],
        review_kind=kind,
    )
    review = {
        "event": "CHATGPT_REVIEW_REQUIRED",
        "state": "CHATGPT_REVIEW_REQUIRED",
        "provider": "ChatGPT",
        "review_kind": kind,
        "pr": pr,
        "head_sha": head,
        "handoff": handoff,
        "handoff_bytes": len(handoff.encode()),
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
    result = {
        "schema_version": 2,
        "pr": pr,
        "head_sha": head,
        "head_branch": branch,
        "base": "main",
        "state": "CHATGPT_REVIEW_REQUIRED",
        "next_action": f"CHATGPT_{kind}_REVIEW",
        "qualification": {"status": "PASS", "head_sha": head, "base_sha": base},
        "code_review": {"status": "MISSING", "head_sha": head},
        "security_review": {"status": "MISSING", "head_sha": head},
        "review_request": review,
        "blockers": [],
    }
    if structured:
        result["review_kind"] = kind
        result["qualification"]["compatibility_digest"] = EVIDENCE_DIGEST
        result["handoff"] = pr_monitor.build_handoff(
            repository=REPOSITORY,
            pr=pr,
            review_kind=kind,
            base_sha=base,
            head_sha=head,
            tree_sha=tree,
            changed_files=["scripts/repoctl.py"],
            qualification_status="PASS",
            qualification_evidence_digest=EVIDENCE_DIGEST,
            previous_validated_verdict="CODE_PASS" if kind == "SECURITY" else None,
            previous_head=head if kind == "SECURITY" else None,
        )
    return result


def structured_controller(kind="CODE", *, tree=TREE):
    result = controller(kind, tree=tree)
    if kind == "SECURITY":
        result["code_review"] = {
            "status": "PASS",
            "head_sha": HEAD,
            "blocking_findings": 0,
        }
    return result


class PRReviewDispatchTransitionTest(TestCase):
    def setUp(self):
        self.binding = ExactPRBinding(REPOSITORY, 169, "main", BASE, BRANCH, HEAD)
        self.bootstrap_binding = ExactPRBinding(
            REPOSITORY, 172, "main", BOOTSTRAP_BASE, BOOTSTRAP_BRANCH, HEAD
        )
        self.legacy_binding_arg = f"{BOOTSTRAP_BASE}:{HEAD}"
        self.gh_path = "/managed/gh"
        gh_patch = mock.patch.object(
            transition,
            "resolve_managed_gh",
            return_value=(self.gh_path, "2.101.0", "c" * 64),
        )
        self.managed_gh = gh_patch.start()
        self.addCleanup(gh_patch.stop)
        fetch_patch = mock.patch.object(transition, "_ensure_trusted_head_object")
        self.fetch_head = fetch_patch.start()
        self.addCleanup(fetch_patch.stop)

    def test_local_git_status_does_not_run_checkout_fsmonitor_or_inherited_git(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            subprocess.run(["/usr/bin/git", "init", "-q", str(checkout)], check=True)
            (checkout / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            subprocess.run(["/usr/bin/git", "-C", str(checkout), "add", "tracked.txt"], check=True)
            subprocess.run(
                ["/usr/bin/git", "-C", str(checkout), "-c", "user.name=Test",
                 "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                 "commit", "-qm", "base"],
                check=True,
            )
            fsmonitor_marker = checkout / ".git/fsmonitor-ran"
            fsmonitor = checkout / ".git/fsmonitor-canary"
            fsmonitor.write_text(
                f"#!/bin/sh\nprintf ran > {fsmonitor_marker}\necho token\n",
                encoding="utf-8",
            )
            fsmonitor.chmod(0o700)
            subprocess.run(
                ["/usr/bin/git", "-C", str(checkout), "config", "core.fsmonitor", str(fsmonitor)],
                check=True,
            )
            subprocess.run(
                ["/usr/bin/git", "-C", str(checkout), "status", "--porcelain"],
                check=True, capture_output=True, text=True,
            )
            self.assertTrue(fsmonitor_marker.exists(), "fixture must execute under bare Git")
            fsmonitor_marker.unlink()
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            fake_git_marker = root / "fake-git-ran"
            fake_git = fake_bin / "git"
            fake_git.write_text(
                f"#!/bin/sh\nprintf ran > {fake_git_marker}\nexit 91\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o700)
            real_run = subprocess.run
            seen_status = []

            def capture_run(command, **kwargs):
                if command[0] == "/usr/bin/git" and "status" in command:
                    seen_status.append(kwargs["env"])
                return real_run(command, **kwargs)

            with (
                mock.patch.dict(transition.os.environ, {
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "GH_TOKEN": "fixture-secret",
                    "GITHUB_TOKEN": "fixture-secret-2",
                }),
                mock.patch.object(transition.subprocess, "run", side_effect=capture_run),
            ):
                self.assertEqual("", transition._git(checkout, "status", "--porcelain"))
            self.assertEqual(1, len(seen_status))
            self.assertEqual("/usr/bin:/bin", seen_status[0]["PATH"])
            self.assertEqual("/nonexistent", seen_status[0]["HOME"])
            self.assertNotIn("GH_TOKEN", seen_status[0])
            self.assertNotIn("GITHUB_TOKEN", seen_status[0])
            self.assertFalse(fsmonitor_marker.exists())
            self.assertFalse(fake_git_marker.exists())

    def local_git(self):
        return mock.patch.object(
            transition, "_git", side_effect=["", HEAD, BRANCH, TREE]
        )

    def test_code_dispatch_uses_exact_binding_and_reports_absent_transport(self):
        record = {
            "state": "BLOCKED",
            "reason": "BLOCKED_EXTERNAL_REVIEW_TRANSPORT",
            "identity": "c" * 64,
            "outbox_path": "/tmp/request.json",
            "verdict_authority": False,
        }
        dispatch = mock.Mock(return_value=record)
        resolver = mock.Mock(return_value=self.binding)
        with self.local_git():
            result = transition.dispatch_controller_result(
                controller(),
                pr_number=169,
                target_root=Path("/repo"),
                resolver=resolver,
                dispatcher=dispatch,
                marker_lookup=lambda *_: None,
            )
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", result["state"])
        self.assertEqual("BLOCKED", result["review_dispatch"]["status"])
        self.assertEqual("CHATGPT_CODE_REVIEW", result["next_action"])
        self.assertEqual("PASS", result["qualification"]["status"])
        self.assertEqual("MISSING", result["code_review"]["status"])
        self.assertEqual("MISSING", result["security_review"]["status"])
        self.assertFalse(result["review_request"]["verdict_authority"])
        self.assertFalse(result["review_dispatch"]["verdict_authority"])
        request = dispatch.call_args.args[0]
        self.assertEqual(self.binding.base_sha, request["base_sha"])
        self.assertEqual(self.binding.repository, request["repository"])
        self.assertEqual(self.binding.head_branch, request["head_branch"])
        self.managed_gh.assert_called_once_with(transition.ROOT)
        resolver.assert_called_once_with(
            REPOSITORY, HEAD, BRANCH, "main", BASE, gh=self.gh_path
        )

    def test_poll_existing_only_forbids_new_transport_submission(self):
        dispatch = mock.Mock(
            return_value={
                "state": "BLOCKED",
                "reason": "SUBMIT_NOT_ALLOWED",
                "identity": "c" * 64,
                "submission_id": "",
                "verdict_authority": False,
            }
        )
        with self.local_git():
            result = transition.dispatch_controller_result(
                structured_controller(),
                pr_number=169,
                target_root=Path("/repo"),
                allow_submit=False,
                resolver=lambda *args, **kwargs: self.binding,
                dispatcher=dispatch,
                marker_lookup=lambda *_: None,
            )
        self.assertFalse(dispatch.call_args.kwargs["allow_submit"])
        self.assertEqual("SUBMIT_NOT_ALLOWED", result["review_dispatch"]["reason"])
        self.assertEqual("", result["review_dispatch"]["submission_id"])

    def test_structured_handoff_is_the_actual_dispatched_text(self):
        source = structured_controller()
        record = {
            "state": "BLOCKED",
            "reason": "BLOCKED_EXTERNAL_REVIEW_TRANSPORT",
            "identity": "c" * 64,
            "outbox_path": "/tmp/request.json",
            "verdict_authority": False,
        }
        dispatch = mock.Mock(return_value=record)
        with mock.patch.object(
            transition, "_git", side_effect=["", HEAD, BRANCH, TREE]
        ):
            result = transition.dispatch_controller_result(
                source,
                pr_number=169,
                target_root=Path("/repo"),
                resolver=lambda *args, **kwargs: self.binding,
                dispatcher=dispatch,
                marker_lookup=lambda *_: None,
            )
        request = dispatch.call_args.args[0]
        text = json.dumps(
            source["handoff"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        self.assertEqual(text, request["handoff"])
        self.assertEqual(len(text.encode()), request["handoff_bytes"])
        self.assertEqual(
            hashlib.sha256(text.encode()).hexdigest(), request["handoff_sha256"]
        )
        self.assertNotEqual(
            source["handoff"]["handoff_sha256"], request["handoff_sha256"]
        )
        self.assertEqual(request, result["review_request"])
        self.assertEqual(
            request["handoff_sha256"], result["review_dispatch"]["handoff_sha256"]
        )

    def test_structured_handoff_rejects_wrong_tree_and_malformed_present_v1(self):
        wrong_tree = structured_controller(tree="e" * 40)
        with (
            mock.patch.object(transition, "_git", side_effect=["", HEAD, BRANCH, TREE]),
            self.assertRaisesRegex(transition.ReviewTransitionError, "tree differs"),
        ):
            transition.dispatch_controller_result(
                wrong_tree,
                pr_number=169,
                target_root=Path("/repo"),
                resolver=lambda *args, **kwargs: self.binding,
                dispatcher=mock.Mock(),
            )
        for field, value in (
            ("handoff_sha256", "0" * 64),
            ("head_sha", "e" * 40),
            (
                "qualification",
                {"status": "PASS", "evidence_digest": "sha256:" + "f" * 64},
            ),
            ("changed_files", ["../unsafe.py"]),
        ):
            with self.subTest(field=field):
                source = structured_controller()
                source["handoff"][field] = value
                with self.assertRaisesRegex(
                    transition.ReviewTransitionError, "structured handoff is malformed"
                ):
                    transition._request_from_controller(source, self.binding)

    def test_compatibility_controller_cannot_fall_back_to_legacy_handoff(self):
        source = structured_controller()
        del source["handoff"]
        with self.assertRaisesRegex(
            transition.ReviewTransitionError, "omitted structured handoff"
        ):
            transition._request_from_controller(source, self.binding)

    def test_structured_security_requires_controller_code_pass(self):
        source = structured_controller("SECURITY")
        source["code_review"]["status"] = "MISSING"
        with self.assertRaisesRegex(transition.ReviewTransitionError, "CODE PASS"):
            transition._request_from_controller(source, self.binding)

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

    def test_binding_change_before_dispatch_has_no_dispatch_or_marker(self):
        changed = ExactPRBinding(REPOSITORY, 169, "main", BASE, BRANCH, "e" * 40)
        for outcome, expected in (
            (changed, transition.ReviewTransitionSuperseded),
            (
                ExactPRBindingChanged("HEAD_CHANGED"),
                transition.ReviewTransitionSuperseded,
            ),
            (
                ExactPRBindingError("GitHub API request failed: PR detail"),
                transition.ReviewTransitionTransientGitHub,
            ),
        ):
            with (
                self.subTest(outcome=outcome),
                self.local_git(),
                mock.patch.object(
                    transition,
                    "revalidate_exact_open_pr",
                    side_effect=outcome if isinstance(outcome, Exception) else None,
                    return_value=outcome
                    if isinstance(outcome, ExactPRBinding)
                    else None,
                ),
                self.assertRaises(expected),
            ):
                dispatch = mock.Mock()
                marker = mock.Mock()
                transition.dispatch_controller_result(
                    controller(),
                    pr_number=169,
                    target_root=Path("/repo"),
                    binding=self.binding,
                    dispatcher=dispatch,
                    marker_lookup=marker,
                )
            dispatch.assert_not_called()
            marker.assert_not_called()

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
            mock.patch.object(
                transition, "rerun_after_review_marker", return_value=0
            ) as rerun,
            mock.patch.object(
                transition, "reconcile_post_rerun", return_value={"status": "OPEN"}
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
        rerun.assert_called_once()

    def test_binding_change_before_second_controller_pass_is_superseded(self):
        review = controller()
        changed = ExactPRBinding(REPOSITORY, 169, "main", BASE, BRANCH, "e" * 40)
        preflight = mock.Mock(side_effect=[self.binding, changed])
        with (
            mock.patch.object(
                transition, "_trusted_transition", return_value=(0, review)
            ) as trusted,
            mock.patch.object(
                transition,
                "dispatch_controller_result",
                return_value={
                    **review,
                    "review_dispatch": {"status": "PASS", "kind": "CODE"},
                },
            ) as dispatch,
            mock.patch.object(transition, "rerun_after_review_marker", return_value=0),
            mock.patch.object(
                transition, "reconcile_post_rerun", return_value={"status": "OPEN"}
            ),
            mock.patch.object(transition, "publish_owner_authorization") as marker,
            self.assertRaises(transition.ReviewTransitionSuperseded),
        ):
            transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=preflight,
            )
        trusted.assert_called_once()
        dispatch.assert_called_once()
        marker.assert_not_called()
        self.assertEqual(2, preflight.call_count)

    def test_new_qualification_settles_handoff_before_dispatch(self):
        first = controller(
            pr=172, base=BOOTSTRAP_BASE, branch=BOOTSTRAP_BRANCH, structured=False
        )
        first["qualification"]["source"] = "executed"
        settled = controller(
            pr=172, base=BOOTSTRAP_BASE, branch=BOOTSTRAP_BRANCH, structured=False
        )
        settled["qualification"]["source"] = "reused"
        blocked = {
            **settled,
            "state": "CHATGPT_REVIEW_REQUIRED",
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
                172,
                legacy_bootstrap_binding=self.legacy_binding_arg,
                preflight=lambda *_: self.bootstrap_binding,
            )
        self.assertEqual(0, rc)
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", result["state"])
        self.assertEqual(2, trusted.call_count)
        self.assertIs(settled, dispatch.call_args.args[0])

    def test_binding_change_while_stabilizing_blocks_second_pass_and_dispatch(self):
        first = controller(
            pr=172, base=BOOTSTRAP_BASE, branch=BOOTSTRAP_BRANCH, structured=False
        )
        first["qualification"]["source"] = "executed"
        changed = ExactPRBinding(
            REPOSITORY,
            172,
            "main",
            BOOTSTRAP_BASE,
            BOOTSTRAP_BRANCH,
            "e" * 40,
        )
        preflight = mock.Mock(side_effect=[self.bootstrap_binding, changed])
        with (
            mock.patch.object(
                transition, "_trusted_transition", return_value=(0, first)
            ) as trusted,
            mock.patch.object(transition, "dispatch_controller_result") as dispatch,
            mock.patch.object(transition, "publish_owner_authorization") as marker,
            self.assertRaises(transition.ReviewTransitionSuperseded),
        ):
            transition.transition(
                Path("/trusted"),
                Path("/target"),
                172,
                legacy_bootstrap_binding=self.legacy_binding_arg,
                preflight=preflight,
            )
        trusted.assert_called_once()
        dispatch.assert_not_called()
        marker.assert_not_called()
        self.assertEqual(2, preflight.call_count)

    def test_unstable_qualification_handoff_blocks_before_dispatch(self):
        first = controller(
            pr=172, base=BOOTSTRAP_BASE, branch=BOOTSTRAP_BRANCH, structured=False
        )
        first["qualification"]["source"] = "executed"
        again = controller(
            pr=172, base=BOOTSTRAP_BASE, branch=BOOTSTRAP_BRANCH, structured=False
        )
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
                172,
                legacy_bootstrap_binding=self.legacy_binding_arg,
                preflight=lambda *_: self.bootstrap_binding,
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
        self.fetch_head.assert_called_once_with(
            Path("/trusted"), self.binding, allow_fetch=True
        )

    def test_dry_run_never_allows_a_trusted_object_fetch(self):
        with mock.patch.object(
            transition,
            "_trusted_transition",
            return_value=(0, {"state": "DRY_RUN", "pr": 169}),
        ) as trusted:
            transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                dry_run=True,
                preflight=lambda *_: self.binding,
            )
        self.fetch_head.assert_called_once_with(
            Path("/trusted"), self.binding, allow_fetch=False
        )
        trusted.assert_called_once()

    def test_changed_binding_returns_explicit_superseded_state(self):
        with (
            mock.patch.object(
                transition,
                "transition",
                side_effect=transition.ReviewTransitionSuperseded(
                    "trusted exact PR binding changed: HEAD_CHANGED"
                ),
            ),
            mock.patch.object(transition, "_print_result") as printer,
        ):
            rc = transition.main(
                [
                    "--trusted-root",
                    "/trusted",
                    "--target-root",
                    "/target",
                    "--pr",
                    "169",
                    "--json",
                ]
            )
        self.assertEqual(1, rc)
        result = printer.call_args.args[0]
        self.assertEqual("SUPERSEDED", result["state"])
        self.assertEqual("SUPERSEDED", result["review_dispatch"]["status"])
        self.assertEqual("REVALIDATE_EXACT_PR", result["next_action"])

    def test_fetch_failure_blocks_before_controller_or_review_dispatch(self):
        self.fetch_head.side_effect = transition.ReviewTransitionTransientFetch(
            "trusted exact HEAD fetch failed"
        )
        with (
            mock.patch.object(transition, "_trusted_transition") as trusted,
            mock.patch.object(transition, "dispatch_controller_result") as dispatch,
            self.assertRaises(transition.ReviewTransitionTransientFetch),
        ):
            transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
            )
        trusted.assert_not_called()
        dispatch.assert_not_called()

    def test_github_preflight_unavailable_blocks_before_controller(self):
        with (
            mock.patch.object(transition, "_trusted_transition") as trusted,
            mock.patch.object(transition, "dispatch_controller_result") as dispatch,
            self.assertRaises(transition.ReviewTransitionTransientGitHub),
        ):
            transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=mock.Mock(
                    side_effect=ExactPRBindingError("GitHub API request failed")
                ),
            )
        trusted.assert_not_called()
        dispatch.assert_not_called()

    def test_non_api_binding_contradiction_is_not_retryable(self):
        with (
            mock.patch.object(transition, "_trusted_transition") as trusted,
            self.assertRaises(transition.ReviewTransitionError) as raised,
        ):
            transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=mock.Mock(
                    side_effect=ExactPRBindingError(
                        "expected exactly one open PR for the exact source; found 0"
                    )
                ),
            )
        self.assertNotIsInstance(
            raised.exception, transition.ReviewTransitionTransientGitHub
        )
        trusted.assert_not_called()

    def test_transient_github_revalidation_returns_machine_readable_blocker(self):
        with (
            mock.patch.object(
                transition,
                "transition",
                side_effect=transition.ReviewTransitionTransientGitHub(
                    "trusted exact PR revalidation is unavailable"
                ),
            ),
            mock.patch.object(transition, "_print_result") as printer,
        ):
            rc = transition.main(
                [
                    "--trusted-root",
                    "/trusted",
                    "--target-root",
                    "/target",
                    "--pr",
                    "169",
                    "--json",
                ]
            )
        self.assertEqual(1, rc)
        result = printer.call_args.args[0]
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual(
            "TRUSTED_GITHUB_REVALIDATION_UNAVAILABLE", result["error_code"]
        )
        self.assertIs(True, result["retryable"])
        self.assertEqual("RETRY_GITHUB_REVALIDATION", result["next_action"])

    def test_transient_fetch_returns_machine_readable_blocker(self):
        with (
            mock.patch.object(
                transition,
                "transition",
                side_effect=transition.ReviewTransitionTransientFetch(
                    "trusted exact HEAD fetch failed"
                ),
            ),
            mock.patch.object(transition, "_print_result") as printer,
        ):
            rc = transition.main(
                [
                    "--trusted-root",
                    "/trusted",
                    "--target-root",
                    "/target",
                    "--pr",
                    "169",
                    "--json",
                ]
            )
        self.assertEqual(1, rc)
        result = printer.call_args.args[0]
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("TRUSTED_HEAD_FETCH_FAILED", result["error_code"])
        self.assertIs(True, result["retryable"])

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
            mock.patch.object(
                transition, "resolve_exact_open_pr", return_value=self.binding
            ) as resolver,
            mock.patch.object(
                transition, "dispatch_status", return_value=status
            ) as reader,
        ):
            result = transition.review_dispatch_status(Path("/repo"), 169, "CODE")
        self.assertEqual(status, result)
        resolver.assert_called_once_with(
            REPOSITORY, HEAD, BRANCH, "main", gh=self.gh_path
        )
        reader.assert_called_once_with(self.binding, "CODE", gh=self.gh_path)
        self.managed_gh.assert_called_once_with(transition.ROOT)

    def test_status_rejects_a_different_pr(self):
        with (
            mock.patch.object(transition, "_git", side_effect=[HEAD, BRANCH]),
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
            mock.patch.object(
                transition, "resolve_exact_open_pr", return_value=self.binding
            ) as resolver,
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
        resolver.assert_called_once_with(
            REPOSITORY, HEAD, BRANCH, "main", gh=self.gh_path
        )
        self.managed_gh.assert_called_once_with(transition.ROOT)

    def test_missing_or_mismatched_managed_gh_blocks_despite_path_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_gh = Path(directory) / "gh"
            fake_gh.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_gh.chmod(0o755)
            for failure in (
                "managed gh executable is absent",
                "managed gh binary differs from pinned archive",
            ):
                with (
                    self.subTest(failure=failure),
                    mock.patch.dict(os.environ, {"PATH": directory}),
                    mock.patch.object(transition, "_git", side_effect=[HEAD, BRANCH]),
                    mock.patch.object(
                        transition,
                        "resolve_exact_open_pr",
                    ) as resolver,
                    self.assertRaisesRegex(transition.ReviewTransitionError, failure),
                ):
                    self.managed_gh.side_effect = ValueError(failure)
                    transition.review_dispatch_status(Path("/repo"), 169, "CODE")
                resolver.assert_not_called()

    def test_executed_structured_handoff_dispatches_from_same_controller_response(self):
        review = structured_controller()
        review["qualification"]["source"] = "executed"
        dispatch = mock.Mock(
            return_value={
                "state": "BLOCKED",
                "reason": "BLOCKED_EXTERNAL_REVIEW_TRANSPORT",
                "verdict_authority": False,
            }
        )
        adapter = transition.dispatch_controller_result
        with (
            mock.patch.object(
                transition,
                "_trusted_transition",
                side_effect=[
                    (0, review),
                    AssertionError("a fresh witness cannot survive a subprocess rerun"),
                ],
            ) as trusted,
            mock.patch.object(transition, "_git", side_effect=["", HEAD, BRANCH, TREE]),
            mock.patch.object(
                transition, "revalidate_exact_open_pr", return_value=self.binding
            ),
            mock.patch.object(
                transition,
                "dispatch_controller_result",
                side_effect=lambda value, **kwargs: adapter(
                    value, **kwargs, dispatcher=dispatch
                ),
            ) as dispatch_adapter,
        ):
            rc, result = transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
            )
        self.assertEqual(0, rc)
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", result["state"])
        trusted.assert_called_once()
        dispatch_adapter.assert_called_once()
        self.assertIs(review, dispatch_adapter.call_args.args[0])
        dispatch.assert_called_once()
        self.assertEqual(
            review["handoff"], json.loads(dispatch.call_args.args[0]["handoff"])
        )
        self.assertEqual("executed", result["qualification"]["source"])

    def test_invalid_structured_handoff_never_retries_or_falls_back(self):
        for malformed in ("digest", "tree", "missing", "null"):
            with self.subTest(malformed=malformed):
                review = structured_controller()
                review["qualification"]["source"] = "executed"
                if malformed == "digest":
                    review["handoff"]["handoff_sha256"] = "0" * 64
                elif malformed == "tree":
                    review = structured_controller(tree="e" * 40)
                    review["qualification"]["source"] = "executed"
                elif malformed == "missing":
                    del review["handoff"]
                else:
                    review["handoff"] = None
                dispatch = mock.Mock()
                adapter = transition.dispatch_controller_result

                def dispatch_validated(
                    value, adapter=adapter, dispatcher=dispatch, **kwargs
                ):
                    return adapter(value, **kwargs, dispatcher=dispatcher)

                with (
                    mock.patch.object(
                        transition, "_trusted_transition", return_value=(0, review)
                    ) as trusted,
                    mock.patch.object(
                        transition, "_git", side_effect=["", HEAD, BRANCH, TREE]
                    ),
                    mock.patch.object(
                        transition,
                        "revalidate_exact_open_pr",
                        return_value=self.binding,
                    ),
                    mock.patch.object(
                        transition,
                        "dispatch_controller_result",
                        side_effect=dispatch_validated,
                    ) as dispatch_adapter,
                    self.assertRaises(transition.ReviewTransitionError),
                ):
                    transition.transition(
                        Path("/trusted"),
                        Path("/target"),
                        169,
                        preflight=lambda *_: self.binding,
                    )
                trusted.assert_called_once()
                dispatch_adapter.assert_called_once()
                dispatch.assert_not_called()

    def test_structured_valid_marker_reruns_controller_for_security_stage(self):
        code = structured_controller()
        security = structured_controller("SECURITY")
        for review in (code, security):
            review["qualification"]["source"] = "executed"
        dispatch = mock.Mock(
            side_effect=[
                {"state": "PASS", "verdict_authority": False},
                {
                    "state": "BLOCKED",
                    "reason": "BLOCKED_EXTERNAL_REVIEW_TRANSPORT",
                    "verdict_authority": False,
                },
            ]
        )
        adapter = transition.dispatch_controller_result
        with (
            mock.patch.object(
                transition,
                "_trusted_transition",
                side_effect=[(0, code), (0, security)],
            ) as trusted,
            mock.patch.object(
                transition, "_git", side_effect=["", HEAD, BRANCH, TREE] * 2
            ),
            mock.patch.object(
                transition, "revalidate_exact_open_pr", return_value=self.binding
            ),
            mock.patch.object(
                transition,
                "dispatch_controller_result",
                side_effect=lambda value, **kwargs: adapter(
                    value, **kwargs, dispatcher=dispatch
                ),
            ),
            mock.patch.object(
                transition, "rerun_after_review_marker", return_value=0
            ) as rerun,
            mock.patch.object(
                transition, "reconcile_post_rerun", return_value={"status": "OPEN"}
            ),
        ):
            rc, result = transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
            )
        self.assertEqual(0, rc)
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", result["state"])
        self.assertEqual(2, trusted.call_count)
        self.assertEqual(
            ["CODE", "SECURITY"],
            [call.args[0]["review_kind"] for call in dispatch.call_args_list],
        )
        self.assertEqual("SECURITY", result["review_dispatch"]["kind"])
        rerun.assert_called_once()

    def test_legacy_bootstrap_is_rejected_without_explicit_exact_binding(self):
        source = controller(
            pr=172, base=BOOTSTRAP_BASE, branch=BOOTSTRAP_BRANCH, structured=False
        )
        legacy_handoff = source["review_request"]["handoff"]
        dispatch = mock.Mock()
        for argument in (None, f"{BOOTSTRAP_BASE}:{'e' * 40}"):
            with (
                self.subTest(argument=argument),
                mock.patch.object(
                    transition, "_git", side_effect=["", HEAD, BOOTSTRAP_BRANCH]
                ),
                self.assertRaises(transition.ReviewTransitionError),
            ):
                transition.dispatch_controller_result(
                    source,
                    pr_number=172,
                    target_root=Path("/repo"),
                    resolver=lambda *args, **kwargs: self.bootstrap_binding,
                    dispatcher=dispatch,
                    legacy_bootstrap_binding=argument,
                )
        dispatch.assert_not_called()
        with mock.patch.object(
            transition, "_git", side_effect=["", HEAD, BOOTSTRAP_BRANCH]
        ):
            result = transition.dispatch_controller_result(
                source,
                pr_number=172,
                target_root=Path("/repo"),
                dry_run=True,
                resolver=lambda *args, **kwargs: self.bootstrap_binding,
                dispatcher=dispatch,
                legacy_bootstrap_binding=self.legacy_binding_arg,
            )
        dispatch.assert_not_called()
        self.assertEqual(
            "legacy-bootstrap", result["review_dispatch"]["handoff_protocol"]
        )
        self.assertEqual(
            self.legacy_binding_arg,
            result["review_dispatch"]["legacy_bootstrap_binding"],
        )
        self.assertEqual(legacy_handoff, result["review_request"]["handoff"])

    def test_stale_bootstrap_opt_in_stops_before_controller_execution(self):
        with (
            mock.patch.object(transition, "_trusted_transition") as trusted,
            self.assertRaises(transition.ReviewTransitionError),
        ):
            transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                legacy_bootstrap_binding=self.legacy_binding_arg,
                preflight=lambda *_: self.binding,
            )
        trusted.assert_not_called()

    def test_explicit_bootstrap_transition_reaches_real_outbox(self):
        from scripts import chatgpt_review_dispatcher as dispatcher

        source = controller(
            pr=172, base=BOOTSTRAP_BASE, branch=BOOTSTRAP_BRANCH, structured=False
        )
        legacy_handoff = source["review_request"]["handoff"]
        source["qualification"]["source"] = "reused"
        adapter = transition.dispatch_controller_result
        with tempfile.TemporaryDirectory() as directory:
            outbox = Path(directory) / "outbox"

            def dispatch(request, **kwargs):
                return dispatcher.dispatch_review_request(
                    request, outbox_root=outbox, **kwargs
                )

            with (
                mock.patch.object(
                    transition, "_trusted_transition", return_value=(0, source)
                ) as trusted,
                mock.patch.object(
                    transition, "_git", side_effect=["", HEAD, BOOTSTRAP_BRANCH]
                ),
                mock.patch.object(
                    transition,
                    "revalidate_exact_open_pr",
                    return_value=self.bootstrap_binding,
                ),
                mock.patch.object(
                    transition,
                    "dispatch_controller_result",
                    side_effect=lambda value, **kwargs: adapter(
                        value,
                        dispatcher=dispatch,
                        marker_lookup=lambda *_: None,
                        **kwargs,
                    ),
                ),
            ):
                rc, result = transition.transition(
                    Path("/trusted"),
                    Path("/target"),
                    172,
                    legacy_bootstrap_binding=self.legacy_binding_arg,
                    preflight=lambda *_: self.bootstrap_binding,
                )
            trusted.assert_called_once()
            self.assertEqual(0, rc)
            self.assertEqual("PASS", result["qualification"]["status"])
            self.assertEqual("CHATGPT_REVIEW_REQUIRED", result["state"])
            record = json.loads(
                Path(result["review_dispatch"]["outbox_path"]).read_text()
            )
            self.assertEqual("legacy-bootstrap", record["handoff_protocol"])
            self.assertEqual(
                self.legacy_binding_arg, record["legacy_bootstrap_binding"]
            )
            self.assertEqual(legacy_handoff, record["request"]["handoff"])
            self.assertFalse(record["request"]["handoff"].startswith("{"))

    def test_resolved_transport_states_are_explicit_and_passed_to_dispatcher(self):
        for state in ("DISABLED", "UNAVAILABLE", "CONFIGURED"):
            with self.subTest(state=state):
                backend = object() if state == "CONFIGURED" else None
                resolution = review_transport.TransportResolution(
                    state, "command-v1" if backend else "none", backend, state
                )
                dispatch = mock.Mock(
                    return_value={
                        "state": "BLOCKED",
                        "reason": "BLOCKED_EXTERNAL_REVIEW_TRANSPORT",
                        "verdict_authority": False,
                    }
                )
                with (
                    self.local_git(),
                    mock.patch.object(
                        transition, "resolve_review_transport", return_value=resolution
                    ) as resolve,
                ):
                    result = transition.dispatch_controller_result(
                        structured_controller(),
                        pr_number=169,
                        target_root=Path("/repo"),
                        resolver=lambda *args, **kwargs: self.binding,
                        dispatcher=dispatch,
                        marker_lookup=lambda *_: None,
                    )
                resolve.assert_called_once_with()
                self.assertIs(backend, dispatch.call_args.kwargs["transport"])
                self.assertEqual(state, result["review_dispatch"]["transport_state"])
                self.assertEqual(
                    resolution.backend, result["review_dispatch"]["transport_backend"]
                )

    def test_dry_run_never_resolves_transport(self):
        with (
            self.local_git(),
            mock.patch.object(transition, "resolve_review_transport") as resolve,
        ):
            result = transition.dispatch_controller_result(
                structured_controller(),
                pr_number=169,
                target_root=Path("/repo"),
                dry_run=True,
                resolver=lambda *args, **kwargs: self.binding,
            )
        resolve.assert_not_called()
        self.assertEqual("NOT_REQUESTED", result["review_dispatch"]["status"])
        self.assertEqual("DRY_RUN", result["review_dispatch"]["transport"])

    def test_owner_authorization_requires_exact_opt_in(self):
        owner = {"state": "OWNER_AUTH_REQUIRED", "pr": 169, "head_sha": HEAD}
        with (
            mock.patch.object(
                transition, "_trusted_transition", return_value=(0, owner)
            ),
            mock.patch.object(transition, "publish_owner_authorization") as publish,
        ):
            rc, result = transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
            )
        self.assertEqual(0, rc)
        self.assertEqual("OWNER_AUTH_REQUIRED", result["state"])
        publish.assert_not_called()
        with (
            mock.patch.object(transition, "_trusted_transition") as trusted,
            self.assertRaisesRegex(transition.ReviewTransitionError, "binding differs"),
        ):
            transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
                owner_authorization_binding="169:" + "c" * 40,
            )
        trusted.assert_not_called()

    def test_exact_owner_authorization_opt_in_restarts_controller(self):
        owner = {"state": "OWNER_AUTH_REQUIRED", "pr": 169, "head_sha": HEAD}
        ready = {"state": "MERGE_READY", "pr": 169, "head_sha": HEAD}
        with (
            mock.patch.object(
                transition, "_trusted_transition", side_effect=[(0, owner), (0, ready)]
            ) as trusted,
            mock.patch.object(
                transition,
                "publish_owner_authorization",
                return_value={"status": "PASS", "published": True},
            ) as publish,
        ):
            rc, result = transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
                owner_authorization_binding=f"169:{HEAD}",
            )
        self.assertEqual(0, rc)
        self.assertEqual("MERGE_READY", result["state"])
        self.assertEqual(2, trusted.call_count)
        self.assertEqual(
            f"169:{HEAD}", publish.call_args.kwargs["authorization_binding"]
        )

    def test_nonzero_rerun_is_reconciled_against_exact_github_merge(self):
        review = controller()
        merged = {"status": "MERGED", "merge_sha": "f" * 40}
        with (
            mock.patch.object(
                transition, "_trusted_transition", return_value=(0, review)
            ) as trusted,
            mock.patch.object(
                transition,
                "dispatch_controller_result",
                return_value={
                    **review,
                    "review_dispatch": {"status": "PASS", "kind": "CODE"},
                },
            ),
            mock.patch.object(
                transition, "rerun_after_review_marker", return_value=1
            ) as rerun,
            mock.patch.object(
                transition, "reconcile_post_rerun", return_value=merged
            ) as reconcile,
        ):
            rc, result = transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
            )
        self.assertEqual(0, rc)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("f" * 40, result["merge_sha"])
        trusted.assert_called_once()
        rerun.assert_called_once()
        reconcile.assert_called_once_with(self.binding, gh=self.gh_path)

    def test_nonzero_after_uac_accepts_only_exact_github_merge(self):
        owner = {"state": "OWNER_AUTH_REQUIRED", "pr": 169, "head_sha": HEAD}
        uncertain = {"state": "BLOCKED", "pr": 169, "head_sha": HEAD}
        with (
            mock.patch.object(
                transition,
                "_trusted_transition",
                side_effect=[(0, owner), (1, uncertain)],
            ),
            mock.patch.object(
                transition,
                "publish_owner_authorization",
                return_value={"status": "PASS", "published": True},
            ),
            mock.patch.object(
                transition,
                "reconcile_post_rerun",
                return_value={"status": "MERGED", "merge_sha": "f" * 40},
            ) as reconcile,
        ):
            rc, result = transition.transition(
                Path("/trusted"),
                Path("/target"),
                169,
                preflight=lambda *_: self.binding,
                owner_authorization_binding=f"169:{HEAD}",
            )
        self.assertEqual(0, rc)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("f" * 40, result["merge_sha"])
        reconcile.assert_called_once_with(self.binding, gh=self.gh_path)


class TrustedHeadObjectTest(TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.origin = root / "origin.git"
        self.writer = root / "writer"
        self.trusted = root / "trusted"
        for command in (
            ["git", "init", "--bare", str(self.origin)],
            ["git", "init", "-b", "main", str(self.writer)],
        ):
            subprocess.run(command, capture_output=True, text=True, check=True)
        self.git(self.writer, "config", "user.email", "transition-test@example.invalid")
        self.git(self.writer, "config", "user.name", "Transition Test")
        self.git(self.writer, "remote", "add", "origin", str(self.origin))
        (self.writer / "base.txt").write_text("base", encoding="utf-8")
        self.git(self.writer, "add", "base.txt")
        self.git(self.writer, "-c", "commit.gpgsign=false", "commit", "-m", "base")
        self.base_sha = self.git(self.writer, "rev-parse", "HEAD")
        self.git(self.writer, "push", "origin", "main")
        subprocess.run(
            ["git", "clone", "--branch", "main", str(self.origin), str(self.trusted)],
            capture_output=True,
            text=True,
            check=True,
        )
        self.git(self.writer, "checkout", "-b", "feature")
        (self.writer / "feature.txt").write_text("new", encoding="utf-8")
        self.git(self.writer, "add", "feature.txt")
        self.git(self.writer, "-c", "commit.gpgsign=false", "commit", "-m", "feature")
        self.head_sha = self.git(self.writer, "rev-parse", "HEAD")
        self.git(self.writer, "push", "origin", "feature")
        self.binding = ExactPRBinding(
            REPOSITORY, 169, "main", self.base_sha, "feature", self.head_sha
        )

    @staticmethod
    def git(root, *args):
        return subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    def local_authority(self, binding=None):
        return (
            mock.patch.object(
                transition, "_trusted_origin_url", return_value=str(self.origin)
            ),
            mock.patch.object(transition, "_managed_gh", return_value="/managed/gh"),
            mock.patch.object(
                transition,
                "revalidate_exact_open_pr",
                return_value=binding or self.binding,
            ),
        )

    def test_missing_exact_head_is_fetched_once_without_moving_trusted_base(self):
        self.assertNotEqual(
            0,
            subprocess.run(
                ["git", "cat-file", "-e", self.head_sha],
                cwd=self.trusted,
                capture_output=True,
                check=False,
            ).returncode,
        )
        before = (
            self.git(self.trusted, "rev-parse", "HEAD"),
            self.git(self.trusted, "status", "--porcelain", "--untracked-files=all"),
            self.git(
                self.trusted,
                "for-each-ref",
                "--format=%(refname) %(objectname)",
            ),
        )
        origin, gh, revalidate = self.local_authority()
        with origin, gh, revalidate as checked_binding:
            transition._ensure_trusted_head_object(
                self.trusted, self.binding, allow_fetch=True
            )
            real_run = subprocess.run
            with mock.patch.object(
                transition.subprocess, "run", wraps=real_run
            ) as runner:
                transition._ensure_trusted_head_object(
                    self.trusted, self.binding, allow_fetch=True
                )
            self.assertFalse(
                any("fetch" in call.args[0] for call in runner.call_args_list)
            )
        self.assertEqual(
            "commit", self.git(self.trusted, "cat-file", "-t", self.head_sha)
        )
        self.assertEqual(
            before,
            (
                self.git(self.trusted, "rev-parse", "HEAD"),
                self.git(
                    self.trusted, "status", "--porcelain", "--untracked-files=all"
                ),
                self.git(
                    self.trusted,
                    "for-each-ref",
                    "--format=%(refname) %(objectname)",
                ),
            ),
        )
        self.assertEqual(4, checked_binding.call_count)

    def test_canonical_fetch_uses_pinned_helper_and_fixed_auth_environment(self):
        gh_path = "/managed/gh;untrusted-command"
        actual_run = subprocess.run
        captured = {}

        def capture_fetch(command, **kwargs):
            if "fetch" in command and transition._CANONICAL_ORIGIN in command:
                captured["command"] = list(command)
                captured["env"] = dict(kwargs["env"])
                command = [
                    str(self.origin) if item == transition._CANONICAL_ORIGIN else item
                    for item in command
                ]
            return actual_run(command, **kwargs)

        with (
            mock.patch.object(
                transition, "_trusted_origin_url",
                return_value=transition._CANONICAL_ORIGIN,
            ),
            mock.patch.object(transition, "_managed_gh", return_value=gh_path),
            mock.patch.object(
                transition, "revalidate_exact_open_pr", return_value=self.binding
            ),
            mock.patch.dict(transition.os.environ, {
                "GH_TOKEN": "fixture-only",
                "PATH": "/untrusted:/usr/bin:/bin",
            }),
            mock.patch.object(transition.subprocess, "run", side_effect=capture_fetch),
        ):
            transition._ensure_trusted_head_object(
                self.trusted, self.binding, allow_fetch=True
            )
        self.assertEqual("/usr/bin/git", captured["command"][0])
        self.assertIn(
            f"credential.helper=!{shlex.quote(gh_path)} auth git-credential",
            captured["command"],
        )
        self.assertEqual("/usr/bin:/bin", captured["env"]["PATH"])
        self.assertEqual("/nonexistent", captured["env"]["HOME"])
        self.assertEqual("fixture-only", captured["env"]["GH_TOKEN"])
        self.assertNotIn("GIT_SSH_COMMAND", captured["env"])

    def test_dry_run_with_missing_object_never_fetches(self):
        origin, gh, revalidate = self.local_authority()
        real_run = subprocess.run
        with (
            origin,
            gh,
            revalidate,
            mock.patch.object(transition.subprocess, "run", wraps=real_run) as runner,
            self.assertRaisesRegex(
                transition.ReviewTransitionError, "dry-run requires"
            ),
        ):
            transition._ensure_trusted_head_object(
                self.trusted, self.binding, allow_fetch=False
            )
        self.assertFalse(any("fetch" in call.args[0] for call in runner.call_args_list))
        self.assertEqual(self.base_sha, self.git(self.trusted, "rev-parse", "HEAD"))

    def test_invalid_origin_or_sha_blocks_before_fetch(self):
        with self.assertRaisesRegex(
            transition.ReviewTransitionError, "binding is invalid"
        ):
            transition._ensure_trusted_head_object(
                self.trusted,
                ExactPRBinding(
                    REPOSITORY, 169, "main", self.base_sha, "feature", "bad"
                ),
                allow_fetch=True,
            )
        with (
            mock.patch.object(transition, "_managed_gh", return_value="/managed/gh"),
            self.assertRaisesRegex(transition.ReviewTransitionError, "origin differs"),
        ):
            transition._ensure_trusted_head_object(
                self.trusted, self.binding, allow_fetch=True
            )
        self.assertEqual(self.base_sha, self.git(self.trusted, "rev-parse", "HEAD"))

    def test_missing_remote_sha_fails_closed_and_preserves_trusted_base(self):
        absent = ExactPRBinding(
            REPOSITORY, 169, "main", self.base_sha, "feature", "f" * 40
        )
        origin, gh, revalidate = self.local_authority(absent)
        with (
            origin,
            gh,
            revalidate,
            self.assertRaisesRegex(
                transition.ReviewTransitionError, "trusted exact HEAD fetch failed"
            ),
        ):
            transition._ensure_trusted_head_object(
                self.trusted, absent, allow_fetch=True
            )
        self.assertEqual(self.base_sha, self.git(self.trusted, "rev-parse", "HEAD"))
        self.assertEqual(
            "", self.git(self.trusted, "status", "--porcelain", "--untracked-files=all")
        )

    def test_github_revalidation_failure_after_fetch_stops_before_controller(self):
        with (
            mock.patch.object(
                transition, "_trusted_origin_url", return_value=str(self.origin)
            ),
            mock.patch.object(transition, "_managed_gh", return_value="/managed/gh"),
            mock.patch.object(
                transition,
                "revalidate_exact_open_pr",
                side_effect=[
                    self.binding,
                    ExactPRBindingError("GitHub API request failed"),
                ],
            ) as revalidate,
            mock.patch.object(transition, "_trusted_transition") as trusted,
            self.assertRaises(transition.ReviewTransitionTransientGitHub),
        ):
            transition.transition(
                self.trusted,
                self.writer,
                169,
                preflight=lambda *_: self.binding,
            )
        self.assertEqual(2, revalidate.call_count)
        trusted.assert_not_called()
        self.assertEqual(
            "commit", self.git(self.trusted, "cat-file", "-t", self.head_sha)
        )
        self.assertEqual(self.base_sha, self.git(self.trusted, "rev-parse", "HEAD"))

    def test_ref_change_during_fetch_blocks_before_controller(self):
        original_snapshot = transition._trusted_checkout_snapshot(self.trusted)
        changed_snapshot = (
            original_snapshot[0],
            original_snapshot[1],
            original_snapshot[2],
            original_snapshot[3] + "\nrefs/heads/unexpected " + "e" * 40,
        )
        origin, gh, revalidate = self.local_authority()
        with (
            origin,
            gh,
            revalidate,
            mock.patch.object(
                transition,
                "_trusted_checkout_snapshot",
                side_effect=[original_snapshot, changed_snapshot],
            ),
            mock.patch.object(transition, "_trusted_transition") as trusted,
            self.assertRaisesRegex(
                transition.ReviewTransitionError, "checkout changed during fetch"
            ),
        ):
            transition.transition(
                self.trusted,
                self.writer,
                169,
                preflight=lambda *_: self.binding,
            )
        trusted.assert_not_called()
        self.assertEqual(self.base_sha, self.git(self.trusted, "rev-parse", "HEAD"))

    def test_github_head_change_after_fetch_is_superseded(self):
        with (
            mock.patch.object(
                transition, "_trusted_origin_url", return_value=str(self.origin)
            ),
            mock.patch.object(transition, "_managed_gh", return_value="/managed/gh"),
            mock.patch.object(
                transition,
                "revalidate_exact_open_pr",
                side_effect=[
                    self.binding,
                    ExactPRBindingChanged("HEAD_CHANGED"),
                ],
            ) as revalidate,
            self.assertRaisesRegex(
                transition.ReviewTransitionSuperseded, "HEAD_CHANGED"
            ),
        ):
            transition._ensure_trusted_head_object(
                self.trusted, self.binding, allow_fetch=True
            )
        self.assertEqual(2, revalidate.call_count)
        self.assertEqual(self.base_sha, self.git(self.trusted, "rev-parse", "HEAD"))
        self.assertEqual(
            "", self.git(self.trusted, "status", "--porcelain", "--untracked-files=all")
        )

    def test_commit_outside_base_ancestry_is_rejected(self):
        self.git(self.writer, "checkout", "--orphan", "unrelated")
        self.git(self.writer, "rm", "-r", "--force", ".")
        (self.writer / "other.txt").write_text("other", encoding="utf-8")
        self.git(self.writer, "add", "other.txt")
        self.git(self.writer, "-c", "commit.gpgsign=false", "commit", "-m", "unrelated")
        other_sha = self.git(self.writer, "rev-parse", "HEAD")
        self.git(self.writer, "push", "origin", "unrelated")
        unrelated = ExactPRBinding(
            REPOSITORY, 169, "main", self.base_sha, "unrelated", other_sha
        )
        origin, gh, revalidate = self.local_authority(unrelated)
        with (
            origin,
            gh,
            revalidate,
            self.assertRaisesRegex(
                transition.ReviewTransitionError, "not a commit descending"
            ),
        ):
            transition._ensure_trusted_head_object(
                self.trusted, unrelated, allow_fetch=True
            )
        self.assertEqual(self.base_sha, self.git(self.trusted, "rev-parse", "HEAD"))
        self.assertEqual(
            "", self.git(self.trusted, "status", "--porcelain", "--untracked-files=all")
        )
