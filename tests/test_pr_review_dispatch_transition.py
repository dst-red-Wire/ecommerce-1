"""The PR-head adapter can request review but cannot create review authority."""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from scripts import chatgpt_review_transport as review_transport
from scripts import pr_monitor
from scripts import pr_review_dispatch_transition as transition
from scripts.exact_pr_binding import ExactPRBinding

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
