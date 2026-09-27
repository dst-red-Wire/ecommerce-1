import contextlib
import importlib.util
import io
import json
import subprocess
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_pr_loop_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class PRLoopStateTests(unittest.TestCase):
    SHA = "a" * 40

    def pr(self, **overrides):
        value = {
            "number": 161,
            "state": "OPEN",
            "draft": False,
            "head_sha": self.SHA,
            "head_branch": "feature/pr-loop",
            "head_repository": "owner/repo",
            "base": "main",
            "base_sha": "b" * 40,
            "merged": False,
            "merge_commit_sha": "",
        }
        value.update(overrides)
        return value

    @staticmethod
    def qualification(status="PASS"):
        return {"status": status, "source": "reused"}

    def review(self, status="PASS", blockers=0, sha=None):
        return {
            "provider": "ChatGPT",
            "status": status,
            "blocking_findings": blockers,
            "head_sha": sha or self.SHA,
        }

    @staticmethod
    def owner(status="PASS"):
        return {"status": status}

    def state(self, *, qualification="PASS", code="PASS", security="PASS", owner="PASS", merge=None):
        code_result = {"status": "MISSING"} if code == "MISSING" else self.review(code, 0 if code == "PASS" else 1)
        security_result = (
            {"status": "MISSING"}
            if security == "MISSING"
            else self.review(security, 0 if security == "PASS" else 1)
        )
        return REPOCTL.derive_pr_loop_state(
            self.pr(),
            self.qualification(qualification),
            code_result,
            security_result,
            self.owner(owner),
            merge,
        )

    def test_transition_order_and_failure_states(self):
        cases = (
            ({"qualification": "MISSING"}, ("QUALIFICATION_REQUIRED", "QUALIFICATION")),
            ({"qualification": "FAIL"}, ("QUALIFICATION_FAILED", "FIX_QUALIFICATION")),
            (
                {"code": "MISSING"},
                ("CHATGPT_REVIEW_REQUIRED", "CHATGPT_CODE_REVIEW"),
            ),
            ({"code": "BLOCKED"}, ("CODE_FAILED", "FIX_CODE_FINDINGS")),
            (
                {"security": "MISSING"},
                ("CHATGPT_REVIEW_REQUIRED", "CHATGPT_SECURITY_REVIEW"),
            ),
            ({"security": "BLOCKED"}, ("SECURITY_FAILED", "FIX_SECURITY_FINDINGS")),
            ({"owner": "MISSING"}, ("OWNER_AUTH_REQUIRED", "OWNER_AUTHORIZATION")),
        )
        for values, expected in cases:
            with self.subTest(values=values):
                self.assertEqual(expected, self.state(**values))

    def test_security_and_owner_cannot_replace_code(self):
        self.assertEqual(
            ("CHATGPT_REVIEW_REQUIRED", "CHATGPT_CODE_REVIEW"),
            self.state(code="MISSING", security="PASS", owner="PASS"),
        )
        self.assertEqual(
            ("CHATGPT_REVIEW_REQUIRED", "CHATGPT_SECURITY_REVIEW"),
            self.state(code="PASS", security="MISSING", owner="PASS"),
        )

    def test_merge_ready_requires_every_merge_requirement(self):
        complete = {
            "current_main_lineage": True,
            "unresolved_blocking_findings": True,
            "required_conversations": True,
            "branch_protection": True,
            "required_checks": True,
            "commit_provenance": True,
        }
        self.assertEqual(("MERGE_READY", "FINISH_PR"), self.state(merge=complete))
        for name in complete:
            with self.subTest(name=name):
                incomplete = dict(complete)
                incomplete[name] = False
                state, _next = self.state(merge=incomplete)
                self.assertEqual("BLOCKED", state)

    def test_merged_pr_routes_only_to_post_merge_cleanup(self):
        state = REPOCTL.derive_pr_loop_state(
            self.pr(state="MERGED", merged=True),
            self.qualification("MISSING"),
            {"status": "MISSING"},
            {"status": "MISSING"},
            self.owner("MISSING"),
        )
        self.assertEqual(("MERGED", "POST_MERGE_CLEANUP"), state)

    def test_draft_closed_and_wrong_base_fail_closed(self):
        inputs = (
            self.pr(draft=True),
            self.pr(state="CLOSED"),
            self.pr(base="develop"),
        )
        for pr in inputs:
            with self.subTest(pr=pr):
                state, _next = REPOCTL.derive_pr_loop_state(
                    pr,
                    self.qualification(),
                    self.review(),
                    self.review(),
                    self.owner(),
                )
                self.assertEqual("BLOCKED", state)


class PRLoopAuthorityEvidenceTests(unittest.TestCase):
    SHA_A = "a" * 40
    SHA_B = "b" * 40

    @staticmethod
    def comment(
        body,
        *,
        author="owner",
        identifier=1,
        timestamp="2026-09-27T10:00:00Z",
        updated_at=None,
    ):
        return {
            "id": identifier,
            "body": body,
            "created_at": timestamp,
            "updated_at": updated_at or timestamp,
            "user": {"login": author},
        }

    @staticmethod
    def marker(kind, sha, status="PASS", blockers=0, **extra):
        payload = {
            "provider": "ChatGPT",
            "kind": kind,
            "head_sha": sha,
            "status": status,
            "blocking_findings": blockers,
            **extra,
        }
        return "<!-- chatgpt-exact-sha-review:v1 " + json.dumps(payload, separators=(",", ":")) + " -->"

    def policy(self):
        return {
            "ai_reviewer": {
                "evidence": {
                    "required_kinds": ["code", "security"],
                    "required_status": "PASS",
                }
            }
        }

    def test_old_sha_reviews_are_historical_only(self):
        comments = [
            self.comment(self.marker("code", self.SHA_A)),
            self.comment(self.marker("security", self.SHA_A), identifier=2),
        ]
        with mock.patch.object(REPOCTL, "pull_request_review_policy", return_value=self.policy()):
            evidence = REPOCTL._chatgpt_review_evidence(comments, "owner", self.SHA_B)
        self.assertEqual("MISSING", evidence["code"]["status"])
        self.assertEqual("MISSING", evidence["security"]["status"])

    def test_latest_exact_sha_marker_wins_and_wrong_owner_or_shape_is_ignored(self):
        comments = [
            self.comment(self.marker("code", self.SHA_A, "BLOCKED", 1), identifier=1),
            self.comment(self.marker("code", self.SHA_A), author="attacker", identifier=2),
            self.comment(self.marker("code", self.SHA_A, unexpected=True), identifier=3),
            self.comment(self.marker("code", self.SHA_A), identifier=4),
        ]
        with mock.patch.object(REPOCTL, "pull_request_review_policy", return_value=self.policy()):
            evidence = REPOCTL._chatgpt_review_evidence(comments, "owner", self.SHA_A)
        self.assertEqual("PASS", evidence["code"]["status"])
        self.assertEqual(4, evidence["code"]["comment_id"])

    def test_code_and_security_fail_markers_remain_blocking(self):
        comments = [
            self.comment(self.marker("code", self.SHA_A, "BLOCKED", 2)),
            self.comment(self.marker("security", self.SHA_A, "FAIL", 1), identifier=2),
        ]
        with mock.patch.object(REPOCTL, "pull_request_review_policy", return_value=self.policy()):
            evidence = REPOCTL._chatgpt_review_evidence(comments, "owner", self.SHA_A)
        self.assertFalse(REPOCTL._review_result_is_pass(evidence["code"]))
        self.assertFalse(REPOCTL._review_result_is_pass(evidence["security"]))

    def test_editing_old_comment_cannot_reorder_chatgpt_verdicts(self):
        comments = [
            self.comment(
                self.marker("code", self.SHA_A, "BLOCKED", 1),
                identifier=2,
                timestamp="2026-09-27T10:01:00Z",
            ),
            self.comment(
                self.marker("code", self.SHA_A),
                identifier=1,
                timestamp="2026-09-27T10:00:00Z",
                updated_at="2026-09-27T10:02:00Z",
            ),
        ]
        with mock.patch.object(REPOCTL, "pull_request_review_policy", return_value=self.policy()):
            evidence = REPOCTL._chatgpt_review_evidence(comments, "owner", self.SHA_A)
        self.assertEqual("BLOCKED", evidence["code"]["status"])
        self.assertEqual(2, evidence["code"]["comment_id"])

    def test_owner_authorization_requires_owner_exact_scope_and_exact_sha(self):
        command = f"/owner-authorization approve scope=pr-161 sha={self.SHA_A}"
        cases = (
            ([self.comment(command, author="attacker")], "MISSING"),
            ([self.comment(f"/owner-authorization approve scope=pr-999 sha={self.SHA_A}")], "MISSING"),
            ([self.comment(f"/owner-authorization approve scope=pr-161 sha={self.SHA_B}")], "MISSING"),
            ([self.comment(command)], "PASS"),
        )
        for comments, expected in cases:
            with self.subTest(expected=expected, comments=comments):
                evidence = REPOCTL._owner_authorization_evidence(
                    comments, "owner", 161, self.SHA_A
                )
                self.assertEqual(expected, evidence["status"])

    def test_owner_authorization_must_be_the_entire_comment(self):
        command = f"/owner-authorization approve scope=pr-161 sha={self.SHA_A}"
        embedded = (
            f"Example:\n{command}",
            f"```text\n{command}\n```",
            f"{command}\nApproved as described above.",
        )
        for body in embedded:
            with self.subTest(body=body):
                evidence = REPOCTL._owner_authorization_evidence(
                    [self.comment(body)], "owner", 161, self.SHA_A
                )
                self.assertEqual("MISSING", evidence["status"])
        exact = REPOCTL._owner_authorization_evidence(
            [self.comment(f"  {command}\n")], "owner", 161, self.SHA_A
        )
        self.assertEqual("PASS", exact["status"])

    def test_later_scope_authorization_supersedes_prior_sha(self):
        comments = [
            self.comment(
                f"/owner-authorization approve scope=pr-161 sha={self.SHA_A}",
                identifier=1,
            ),
            self.comment(
                f"/owner-authorization approve scope=pr-161 sha={self.SHA_B}",
                identifier=2,
                timestamp="2026-09-27T10:01:00Z",
            ),
        ]
        evidence = REPOCTL._owner_authorization_evidence(comments, "owner", 161, self.SHA_A)
        self.assertEqual("MISSING", evidence["status"])
        self.assertIn("another SHA", evidence["reason"])

    def test_later_explicit_revocation_invalidates_authorization(self):
        comments = [
            self.comment(
                f"/owner-authorization approve scope=pr-161 sha={self.SHA_A}",
                identifier=1,
            ),
            self.comment(
                f"/owner-authorization revoke scope=pr-161 sha={self.SHA_A}",
                identifier=2,
                timestamp="2026-09-27T10:01:00Z",
            ),
        ]
        evidence = REPOCTL._owner_authorization_evidence(comments, "owner", 161, self.SHA_A)
        self.assertEqual("MISSING", evidence["status"])
        self.assertIn("revoked", evidence["reason"])

    def test_editing_old_approval_cannot_supersede_newer_revocation(self):
        comments = [
            self.comment(
                f"/owner-authorization revoke scope=pr-161 sha={self.SHA_A}",
                identifier=2,
                timestamp="2026-09-27T10:01:00Z",
            ),
            self.comment(
                f"/owner-authorization approve scope=pr-161 sha={self.SHA_A}",
                identifier=1,
                timestamp="2026-09-27T10:00:00Z",
                updated_at="2026-09-27T10:02:00Z",
            ),
        ]
        evidence = REPOCTL._owner_authorization_evidence(
            comments, "owner", 161, self.SHA_A
        )
        self.assertEqual("MISSING", evidence["status"])
        self.assertIn("revoked", evidence["reason"])

    def test_open_pr_validation_rejects_foreign_repo_and_malformed_sha(self):
        pr = {
            "state": "OPEN",
            "draft": False,
            "base": "main",
            "head_repository": "foreign/repo",
            "head_sha": "abc",
            "base_sha": self.SHA_B,
            "head_branch": "feature",
        }
        errors = REPOCTL._pr_loop_open_pr_errors(pr, "owner/repo")
        self.assertTrue(any("head repository" in error for error in errors))
        self.assertTrue(any("40-character" in error for error in errors))

    def test_empty_branch_ruleset_does_not_satisfy_protection(self):
        responses = [
            subprocess.CompletedProcess([], 1, "", "not protected"),
            subprocess.CompletedProcess([], 0, "[]", ""),
        ]
        with mock.patch.object(REPOCTL, "run", side_effect=responses):
            protected, _reason = REPOCTL._github_branch_protection_status("gh", "main")
        self.assertFalse(protected)


class PRLoopOrchestrationTests(unittest.TestCase):
    SHA_A = "a" * 40
    SHA_B = "b" * 40

    def snapshot(self, sha=None, **overrides):
        value = {
            "number": 161,
            "state": "OPEN",
            "draft": False,
            "head_sha": sha or self.SHA_A,
            "head_branch": "feature/pr-loop",
            "head_repository": "owner/repo",
            "base": "main",
            "base_sha": "c" * 40,
            "merged": False,
            "merge_commit_sha": "",
        }
        value.update(overrides)
        return value

    @staticmethod
    def completed(returncode=0):
        return subprocess.CompletedProcess([], returncode, "", "")

    @staticmethod
    def missing_authorities(_gh, pr, sha):
        del pr
        return (
            {
                "code": {"status": "MISSING", "head_sha": sha},
                "security": {"status": "MISSING", "head_sha": sha},
            },
            {
                "status": "MISSING",
                "command": f"/owner-authorization approve scope=pr-161 sha={sha}",
            },
        )

    def run_json(self, **kwargs):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            rc = REPOCTL.pr_loop(161, json_output=True, **kwargs)
        return rc, json.loads(stream.getvalue().strip().splitlines()[-1])

    def common(self):
        return (
            mock.patch.object(REPOCTL.shutil, "which", return_value="gh"),
            mock.patch.object(
                REPOCTL,
                "repository_delivery_policy",
                return_value={"pr_loop": {"state_persistence": "forbidden"}},
            ),
            mock.patch.object(
                REPOCTL,
                "_github_repository_identity",
                return_value=("owner", "owner/repo"),
            ),
            mock.patch.object(REPOCTL, "_pr_loop_checkout_errors", return_value=[]),
        )

    def test_dry_run_is_read_only_and_emits_exact_code_handoff(self):
        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL, "_github_pr_snapshot", return_value=self.snapshot()
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "PASS", "source": "reused"},
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", side_effect=self.missing_authorities
        ), mock.patch.object(REPOCTL, "run") as run:
            rc, payload = self.run_json(dry_run=True)
        self.assertEqual(0, rc)
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", payload["state"])
        self.assertEqual("CODE", payload["review_kind"])
        self.assertEqual("CHATGPT_CODE_REVIEW", payload["next_action"])
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", payload["review_request"]["event"])
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", payload["review_request"]["state"])
        self.assertEqual("CODE", payload["review_request"]["review_kind"])
        self.assertEqual(161, payload["review_request"]["pr"])
        self.assertEqual(self.SHA_A, payload["review_request"]["head_sha"])
        self.assertEqual(
            {
                "provider": "ChatGPT",
                "kind": "code",
                "head_sha": self.SHA_A,
                "status": "PASS",
                "blocking_findings": 0,
            },
            payload["review_request"]["expected_marker"],
        )
        run.assert_not_called()

    def test_security_handoff_is_emitted_only_after_exact_sha_code_pass(self):
        patches = self.common()
        authorities = (
            {
                "code": {
                    "provider": "ChatGPT",
                    "status": "PASS",
                    "blocking_findings": 0,
                    "head_sha": self.SHA_A,
                },
                "security": {"status": "MISSING", "head_sha": self.SHA_A},
            },
            {
                "status": "MISSING",
                "command": (
                    "/owner-authorization approve scope=pr-161 "
                    f"sha={self.SHA_A}"
                ),
            },
        )
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL, "_github_pr_snapshot", return_value=self.snapshot()
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "PASS", "source": "reused"},
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", return_value=authorities
        ), mock.patch.object(REPOCTL, "run") as run:
            rc, payload = self.run_json(dry_run=True)
        self.assertEqual(0, rc)
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", payload["state"])
        self.assertEqual("SECURITY", payload["review_kind"])
        self.assertEqual("CHATGPT_SECURITY_REVIEW", payload["next_action"])
        self.assertEqual("security", payload["review_request"]["expected_marker"]["kind"])
        self.assertEqual(self.SHA_A, payload["review_request"]["head_sha"])
        run.assert_not_called()

    def test_valid_exact_sha_qualification_is_reused_without_rerun(self):
        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL, "_github_pr_snapshot", return_value=self.snapshot()
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "PASS", "source": "reused"},
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", side_effect=self.missing_authorities
        ), mock.patch.object(REPOCTL, "run", return_value=self.completed()) as run:
            rc, payload = self.run_json(dry_run=False)
        self.assertEqual(0, rc)
        self.assertEqual("reused", payload["qualification"]["source"])
        commands = [call.args[0] for call in run.call_args_list]
        self.assertFalse(any("qualification-proof" in command for command in commands))

    def test_head_change_before_qualification_stops_without_running_gates(self):
        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL,
            "_github_pr_snapshot",
            side_effect=[self.snapshot(self.SHA_A), self.snapshot(self.SHA_B)],
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "MISSING", "source": "none"},
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", side_effect=self.missing_authorities
        ), mock.patch.object(REPOCTL, "run", return_value=self.completed()) as run:
            rc, payload = self.run_json(dry_run=False)
        self.assertEqual(1, rc)
        self.assertEqual("HEAD_CHANGED", payload["state"])
        commands = [call.args[0] for call in run.call_args_list]
        self.assertFalse(any("qualification-proof" in command for command in commands))

    def test_missing_qualification_is_generated_once_then_code_is_requested(self):
        patches = self.common()
        qualification_results = [
            {"status": "MISSING", "source": "none"},
            {"status": "PASS", "source": "reused"},
        ]
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL, "_github_pr_snapshot", return_value=self.snapshot()
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            side_effect=qualification_results,
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", side_effect=self.missing_authorities
        ), mock.patch.object(REPOCTL, "run", return_value=self.completed()) as run:
            rc, payload = self.run_json(dry_run=False)
        self.assertEqual(0, rc)
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", payload["state"])
        self.assertEqual("CODE", payload["review_kind"])
        self.assertEqual("executed", payload["qualification"]["source"])
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            1,
            sum("qualification-proof" in command for command in commands),
        )

    def test_github_unavailable_fails_closed(self):
        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL, "_github_pr_snapshot", side_effect=RuntimeError("GitHub unavailable")
        ), mock.patch.object(REPOCTL, "run", return_value=self.completed()):
            rc, payload = self.run_json(dry_run=False)
        self.assertEqual(1, rc)
        self.assertEqual("GITHUB_UNAVAILABLE", payload["state"])

    def test_finish_pr_failure_is_not_reported_as_merge_success(self):
        pass_authorities = (
            {
                "code": {"status": "PASS", "blocking_findings": 0, "head_sha": self.SHA_A},
                "security": {"status": "PASS", "blocking_findings": 0, "head_sha": self.SHA_A},
            },
            {"status": "PASS", "head_sha": self.SHA_A},
        )
        calls = []

        def run(command, **_kwargs):
            calls.append(command)
            if "finish-pr" in command:
                return self.completed(1)
            return self.completed(0)

        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL, "_github_pr_snapshot", return_value=self.snapshot()
        ) as snapshot, mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "PASS", "source": "reused"},
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", return_value=pass_authorities
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_merge_requirements",
            return_value=(
                {
                    "current_main_lineage": True,
                    "unresolved_blocking_findings": True,
                    "required_conversations": True,
                    "branch_protection": True,
                    "required_checks": True,
                    "commit_provenance": True,
                },
                [],
            ),
        ), mock.patch.object(REPOCTL, "run", side_effect=run):
            rc, payload = self.run_json(dry_run=False)
        self.assertEqual(1, rc)
        self.assertEqual("FAIL", payload["merge_result"])
        self.assertEqual("BLOCKED", payload["state"])
        self.assertTrue(any("finish-pr" in command for command in calls))
        self.assertEqual(3, snapshot.call_count)
        self.assertIn("GitHub confirms", payload["blockers"][0])

    def test_finish_pr_nonzero_rechecks_github_and_accepts_exact_merge(self):
        pass_authorities = (
            {
                "code": {"status": "PASS", "blocking_findings": 0, "head_sha": self.SHA_A},
                "security": {"status": "PASS", "blocking_findings": 0, "head_sha": self.SHA_A},
            },
            {"status": "PASS", "head_sha": self.SHA_A},
        )
        merged = self.snapshot(
            state="MERGED",
            merged=True,
            merge_commit_sha="d" * 40,
        )

        def run(command, **_kwargs):
            if "finish-pr" in command:
                return self.completed(1)
            return self.completed(0)

        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL,
            "_github_pr_snapshot",
            side_effect=[self.snapshot(), self.snapshot(), merged],
        ) as snapshot, mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "PASS", "source": "reused"},
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", return_value=pass_authorities
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_merge_requirements",
            return_value=(
                {name: True for name in REPOCTL._PR_LOOP_MERGE_REQUIREMENTS},
                [],
            ),
        ), mock.patch.object(REPOCTL, "run", side_effect=run), mock.patch.object(
            REPOCTL, "_pr_loop_post_merge", return_value=0
        ) as post_merge:
            rc = REPOCTL.pr_loop(161, json_output=False)
        self.assertEqual(0, rc)
        self.assertEqual(3, snapshot.call_count)
        post_merge.assert_called_once()
        self.assertEqual("PASS", post_merge.call_args.args[3]["merge_result"])

    def test_finish_pr_nonzero_and_github_unavailable_reports_unknown_merge(self):
        pass_authorities = (
            {
                "code": {"status": "PASS", "blocking_findings": 0, "head_sha": self.SHA_A},
                "security": {"status": "PASS", "blocking_findings": 0, "head_sha": self.SHA_A},
            },
            {"status": "PASS", "head_sha": self.SHA_A},
        )

        def run(command, **_kwargs):
            if "finish-pr" in command:
                return self.completed(1)
            return self.completed(0)

        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL,
            "_github_pr_snapshot",
            side_effect=[
                self.snapshot(),
                self.snapshot(),
                RuntimeError("GitHub unavailable after finish-pr"),
            ],
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "PASS", "source": "reused"},
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", return_value=pass_authorities
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_merge_requirements",
            return_value=(
                {name: True for name in REPOCTL._PR_LOOP_MERGE_REQUIREMENTS},
                [],
            ),
        ), mock.patch.object(REPOCTL, "run", side_effect=run):
            rc, payload = self.run_json(dry_run=False)
        self.assertEqual(1, rc)
        self.assertEqual("UNKNOWN", payload["merge_result"])
        self.assertEqual("GITHUB_UNAVAILABLE", payload["state"])
        self.assertEqual("VERIFY_MERGE_STATE", payload["next_action"])

    def test_cleanup_failure_remains_post_merge_cleanup(self):
        result = REPOCTL._pr_loop_empty_result(161)
        result.update({"head_sha": self.SHA_A, "merge_result": "PASS"})
        merged = self.snapshot(
            state="MERGED",
            merged=True,
            merge_commit_sha="d" * 40,
        )

        def git(*args, **_kwargs):
            if args[:2] == ("status", "--porcelain"):
                return ""
            if args == ("branch", "--show-current"):
                return "main\n"
            return ""

        def run(command, **_kwargs):
            if "branch-cleanup" in command:
                return self.completed(1)
            return self.completed(0)

        with mock.patch.object(REPOCTL, "git", side_effect=git), mock.patch.object(
            REPOCTL, "run", side_effect=run
        ):
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                rc = REPOCTL._pr_loop_post_merge(
                    "gh", "owner/repo", merged, result, dry_run=False, json_output=True
                )
        payload = json.loads(stream.getvalue().strip().splitlines()[-1])
        self.assertEqual(1, rc)
        self.assertEqual("POST_MERGE_CLEANUP", payload["state"])
        self.assertEqual("PASS", payload["merge_result"])
        self.assertEqual("FAIL", payload["cleanup_result"])

    def test_cleanup_success_reaches_done(self):
        result = REPOCTL._pr_loop_empty_result(161)
        result.update({"head_sha": self.SHA_A, "merge_result": "PASS"})
        merged = self.snapshot(
            state="MERGED",
            merged=True,
            merge_commit_sha="d" * 40,
        )

        def git(*args, **_kwargs):
            if args[:2] == ("status", "--porcelain"):
                return ""
            if args == ("branch", "--show-current"):
                return "main\n"
            return ""

        with mock.patch.object(REPOCTL, "git", side_effect=git), mock.patch.object(
            REPOCTL, "run", return_value=self.completed(0)
        ):
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                rc = REPOCTL._pr_loop_post_merge(
                    "gh", "owner/repo", merged, result, dry_run=False, json_output=True
                )
        payload = json.loads(stream.getvalue().strip().splitlines()[-1])
        self.assertEqual(0, rc)
        self.assertEqual("DONE", payload["state"])
        self.assertEqual("PASS", payload["merge_result"])
        self.assertEqual("PASS", payload["cleanup_result"])

    def test_head_change_during_finish_pr_is_never_reported_as_merged(self):
        pass_authorities = (
            {
                "code": {"status": "PASS", "blocking_findings": 0, "head_sha": self.SHA_A},
                "security": {"status": "PASS", "blocking_findings": 0, "head_sha": self.SHA_A},
            },
            {"status": "PASS", "head_sha": self.SHA_A},
        )
        snapshots = [
            self.snapshot(self.SHA_A),
            self.snapshot(self.SHA_A),
            self.snapshot(self.SHA_B, state="MERGED", merged=True, merge_commit_sha="d" * 40),
        ]
        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL, "_github_pr_snapshot", side_effect=snapshots
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "PASS", "source": "reused"},
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", return_value=pass_authorities
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_merge_requirements",
            return_value=(
                {name: True for name in REPOCTL._PR_LOOP_MERGE_REQUIREMENTS},
                [],
            ),
        ), mock.patch.object(REPOCTL, "run", return_value=self.completed(0)):
            rc, payload = self.run_json(dry_run=False)
        self.assertEqual(1, rc)
        self.assertEqual("BLOCKED", payload["state"])
        self.assertEqual("FAIL", payload["merge_result"])
        self.assertIn("initial exact head", payload["blockers"][0])


class PRLoopSourceContractTests(unittest.TestCase):
    def test_finish_pr_enforces_owner_boundary_and_resolved_conversations(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        finish = source[source.index("def finish_pr(") : source.index("def _pr_loop_empty_result(")]
        self.assertIn("owner_authorization", finish)
        self.assertIn("_github_unresolved_review_threads", finish)
        self.assertIn("--match-head-commit", finish)

    def test_make_adapter_and_json_cli_are_exposed(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn("pr-loop:", makefile)
        self.assertIn('sub.add_parser("pr-loop")', source)
        self.assertIn('loop.add_argument("--json"', source)
        self.assertIn('loop.add_argument("--dry-run"', source)

    def test_pr_loop_delegates_merge_and_never_calls_github_merge_directly(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        loop = source[source.index("def pr_loop(") : source.index("def precommit(")]
        self.assertIn('_controller_command("finish-pr"', loop)
        self.assertNotIn('"pr", "merge"', loop)


if __name__ == "__main__":
    unittest.main()
