import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_pr_loop_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)
RISK_SPEC = importlib.util.spec_from_file_location(
    "merge_risk_pr_loop_test", ROOT / "scripts/merge_risk.py"
)
assert RISK_SPEC and RISK_SPEC.loader
MERGE_RISK = importlib.util.module_from_spec(RISK_SPEC)
RISK_SPEC.loader.exec_module(MERGE_RISK)


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

    def qualification(self, status="PASS"):
        return {"status": status, "source": "reused", "head_sha": self.SHA}

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

    def risk(self, classification="SENSITIVE", sha=None, base_sha=None):
        return {
            "classification": classification,
            "authority": "repository-policy",
            "pr": 161,
            "base_sha": base_sha or "b" * 40,
            "head_sha": sha or self.SHA,
            "changed_files": ["services/product/query.go"],
            "reasons": [] if classification == "LOW_RISK" else ["governance"],
            "matched_capabilities": [] if classification == "LOW_RISK" else ["governance"],
            "analysis_complete": True,
        }

    def state(
        self,
        *,
        qualification="PASS",
        code="PASS",
        security="PASS",
        owner="PASS",
        risk="SENSITIVE",
        merge=None,
    ):
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
            risk=self.risk(risk),
        )

    def test_prior_sha_fail_and_deferred_require_new_qualification_and_reviews(self):
        previous, current = "a" * 40, "b" * 40
        pr = self.pr(head_sha=current)
        old_qualification = {"status": "PASS", "head_sha": previous}
        current_qualification = {"status": "PASS", "head_sha": current}
        old_code = self.review("FAIL", 1, previous)
        old_security = self.review("DEFERRED", 0, previous)
        self.assertEqual(
            ("QUALIFICATION_REQUIRED", "QUALIFICATION"),
            REPOCTL.derive_pr_loop_state(
                pr, old_qualification, old_code, old_security, self.owner()
            ),
        )
        self.assertEqual(
            ("CHATGPT_REVIEW_REQUIRED", "CHATGPT_CODE_REVIEW"),
            REPOCTL.derive_pr_loop_state(
                pr, current_qualification, old_code, old_security, self.owner()
            ),
        )
        self.assertEqual(
            ("CHATGPT_REVIEW_REQUIRED", "CHATGPT_SECURITY_REVIEW"),
            REPOCTL.derive_pr_loop_state(
                pr, current_qualification, self.review(sha=current), old_security,
                self.owner(),
            ),
        )
        self.assertEqual(
            ("CHATGPT_REVIEW_REQUIRED", "CHATGPT_CODE_REVIEW"),
            REPOCTL.derive_pr_loop_state(
                pr, current_qualification, self.review(sha=previous),
                self.review(sha=previous), self.owner(),
            ),
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

    def test_low_risk_requires_policy_absence_not_synthetic_authorization(self):
        complete = {name: True for name in REPOCTL._PR_LOOP_MERGE_REQUIREMENTS}
        self.assertEqual(
            ("MERGE_READY", "FINISH_PR"),
            self.state(
                risk="LOW_RISK",
                owner="NOT_REQUIRED_BY_POLICY",
                merge=complete,
            ),
        )
        self.assertEqual(
            ("BLOCKED", "RECLASSIFY_RISK"),
            self.state(risk="LOW_RISK", owner="PASS", merge=complete),
        )

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


class PRLoopRiskClassificationTests(unittest.TestCase):
    BASE = "b" * 40
    HEAD_A = "a" * 40
    HEAD_B = "c" * 40

    @classmethod
    def setUpClass(cls):
        cls.policy = REPOCTL.repository_delivery_policy()["pr_loop"]["risk_classification"]

    def classify(self, paths, changes=None, head=None, policy=None):
        ordered = sorted(paths)
        payload = {path: "" for path in ordered}
        payload.update(changes or {})
        return MERGE_RISK.evaluate_merge_risk(
            policy or self.policy,
            base_sha=self.BASE,
            head_sha=head or self.HEAD_A,
            pr_number=162,
            changed_files=ordered,
            file_changes=payload,
        )

    def test_ordinary_application_change_is_low_risk(self):
        result = self.classify(
            ["services/product/internal/application/query.go", "tests/test_product_query.py"]
        )
        self.assertEqual("LOW_RISK", result["classification"])
        self.assertEqual([], result["reasons"])
        self.assertEqual([], result["matched_capabilities"])
        self.assertEqual(self.HEAD_A, result["head_sha"])

    def test_each_sensitive_capability_is_owner_gated(self):
        cases = {
            "governance": ("architecture.lock.yaml", ""),
            "delivery-authority": ("scripts/repoctl.py", ""),
            "branch-protection": (".github/CODEOWNERS", ""),
            "infrastructure-apply": ("platform/terraform/main.tf", ""),
            "destructive-operation": ("scripts/cleanup.py", "rm -rf /tmp/scoped"),
            "state-migration": ("services/order/migrations/002_drop.sql", "DROP TABLE old"),
            "iam": ("config/contracts/identity-boundary-policy.yaml", ""),
            "secrets": ("config/contracts/secret-delivery-policy.yaml", ""),
            "network": ("config/infrastructure/network-plan.yaml", ""),
            "dns": ("config/contracts/dns-authority-policy.yaml", ""),
            "signing-or-provenance-policy": ("scripts/check_automation_signing.py", ""),
            "security-policy": ("config/contracts/security-scan-policy.yaml", ""),
            "artifact-publication-authority": ("platform/tekton/publish.yaml", ""),
        }
        for capability, (path, content) in cases.items():
            with self.subTest(capability=capability):
                result = self.classify([path], {path: content})
                self.assertEqual("SENSITIVE", result["classification"])
                self.assertIn(capability, result["matched_capabilities"])

    def test_application_auth_paths_are_sensitive_without_keyword_content(self):
        paths = (
            "services/order/internal/auth/guard.go",
            "services/order/internal/authentication/login.go",
            "services/order/internal/authorization/check.go",
            "services/order/internal/security/policy.go",
            "services/order/internal/oidc/client.go",
            "services/order/internal/oauth/callback.go",
            "services/order/internal/jwt/parser.go",
            "services/order/internal/session/store.go",
            "services/order/internal/http/middleware/authenticate.go",
            "services/order/internal/http/session_manager.go",
        )
        for path in paths:
            with self.subTest(path=path):
                result = self.classify([path], {path: "return nil\n"})
                self.assertEqual("SENSITIVE", result["classification"])
                self.assertIn("iam", result["matched_capabilities"])

    def test_unknown_capability_path_and_partial_inputs_never_become_low_risk(self):
        unknown_policy = copy.deepcopy(self.policy)
        unknown_policy["sensitive"]["capabilities"]["unknown-capability"] = {
            "paths": ["services/**"]
        }
        cases = (
            self.classify(["unknown/new.surface"]),
            self.classify(["services/product/query.go"], policy=unknown_policy),
            MERGE_RISK.evaluate_merge_risk(
                self.policy,
                base_sha=self.BASE,
                head_sha=self.HEAD_A,
                pr_number=162,
                changed_files=["services/product/query.go"],
                file_changes={},
            ),
        )
        for result in cases:
            with self.subTest(result=result):
                self.assertEqual("SENSITIVE", result["classification"])

    def test_git_or_policy_failure_is_sensitive(self):
        with mock.patch.object(
            REPOCTL,
            "_run_exact_base_merge_risk_controller",
            side_effect=RuntimeError("Git unavailable"),
        ):
            result = REPOCTL.classify_merge_risk(self.BASE, self.HEAD_A, 162)
        self.assertEqual("SENSITIVE", result["classification"])
        self.assertFalse(result["analysis_complete"])
        self.assertIn("trusted-base-classification-error", result["reasons"][0])

        with mock.patch.object(
            REPOCTL,
            "_run_exact_base_merge_risk_controller",
            side_effect=RuntimeError("partial exact-base result"),
        ):
            partial = REPOCTL.classify_merge_risk(self.BASE, self.HEAD_A, 162)
        self.assertEqual("SENSITIVE", partial["classification"])
        self.assertIn("partial exact-base result", partial["reasons"][0])

    def test_tampered_head_classifier_still_requires_owner_authorization(self):
        def git(repository, *args):
            completed = subprocess.run(
                ["git", *args],
                cwd=repository,
                text=True,
                capture_output=True,
                check=False,
            )
            if completed.returncode:
                self.fail(completed.stderr or completed.stdout)
            return (completed.stdout or "").strip()

        with tempfile.TemporaryDirectory(prefix="merge-risk-tamper-") as directory:
            repository = Path(directory)
            (repository / "scripts").mkdir()
            (repository / "config/contracts").mkdir(parents=True)
            (repository / "scripts/merge_risk.py").write_bytes(
                (ROOT / "scripts/merge_risk.py").read_bytes()
            )
            (repository / "config/contracts/review-policy.yaml").write_bytes(
                (ROOT / "config/contracts/review-policy.yaml").read_bytes()
            )
            git(repository, "init", "-q")
            git(repository, "add", ".")
            git(
                repository,
                "-c",
                "user.name=Test User",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "trusted base",
            )
            base_sha = git(repository, "rev-parse", "HEAD")

            (repository / "scripts/merge_risk.py").write_text(
                """#!/usr/bin/env python3
import argparse, json
p = argparse.ArgumentParser()
p.add_argument('--base-sha', required=True)
p.add_argument('--head-sha', required=True)
p.add_argument('--pr', type=int)
a = p.parse_args()
print(json.dumps({'classification': 'LOW_RISK', 'authority': 'repository-policy',
    'controller_source': 'exact-pr-base-sha', 'controller_path': 'scripts/merge_risk.py',
    'policy_source': 'exact-pr-base-sha', 'pr': a.pr, 'base_sha': a.base_sha,
    'head_sha': a.head_sha, 'changed_files': ['services/fake.go'], 'reasons': [],
    'matched_capabilities': [], 'analysis_complete': True}))
""",
                encoding="utf-8",
            )
            (repository / "scripts/repoctl.py").write_text(
                "def classify_merge_risk(*_args): return {'classification': 'LOW_RISK'}\n",
                encoding="utf-8",
            )
            git(repository, "add", ".")
            git(
                repository,
                "-c",
                "user.name=Test User",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "tamper with head classifier",
            )
            head_sha = git(repository, "rev-parse", "HEAD")

            with mock.patch.object(REPOCTL, "ROOT", repository):
                result = REPOCTL.classify_merge_risk(base_sha, head_sha, 161)

        self.assertEqual("SENSITIVE", result["classification"])
        self.assertEqual("exact-pr-base-sha", result["controller_source"])
        self.assertIn("delivery-authority", result["matched_capabilities"], result)
        state = REPOCTL.derive_pr_loop_state(
            PRLoopStateTests().pr(base_sha=base_sha, head_sha=head_sha),
            {"status": "PASS", "head_sha": head_sha},
            {"status": "PASS", "blocking_findings": 0, "head_sha": head_sha},
            {"status": "PASS", "blocking_findings": 0, "head_sha": head_sha},
            {"status": "MISSING"},
            risk=result,
        )
        self.assertEqual(("OWNER_AUTH_REQUIRED", "OWNER_AUTHORIZATION"), state)

    def test_sha_change_invalidates_prior_classification_and_reviews(self):
        prior = self.classify(["services/product/query.go"], head=self.HEAD_A)
        prior["pr"] = 161
        pr = PRLoopStateTests().pr(head_sha=self.HEAD_B)
        state = REPOCTL.derive_pr_loop_state(
            pr,
            {"status": "PASS", "head_sha": self.HEAD_B},
            {"status": "PASS", "blocking_findings": 0, "head_sha": self.HEAD_B},
            {"status": "PASS", "blocking_findings": 0, "head_sha": self.HEAD_B},
            {"status": "NOT_REQUIRED_BY_POLICY"},
            {name: True for name in REPOCTL._PR_LOOP_MERGE_REQUIREMENTS},
            risk=prior,
        )
        self.assertEqual(("BLOCKED", "RECLASSIFY_RISK"), state)
        current = self.classify(["architecture.lock.yaml"], head=self.HEAD_B)
        self.assertEqual("SENSITIVE", current["classification"])

    def test_policy_and_controller_cannot_self_declare_low_risk(self):
        for path in ("config/contracts/review-policy.yaml", "scripts/repoctl.py"):
            with self.subTest(path=path):
                result = self.classify([path])
                self.assertEqual("SENSITIVE", result["classification"])
                self.assertTrue(result["matched_capabilities"])
                state = REPOCTL.derive_pr_loop_state(
                    {
                        "number": 162,
                        "state": "OPEN",
                        "draft": False,
                        "base": "main",
                        "base_sha": self.BASE,
                        "head_sha": self.HEAD_A,
                    },
                    {"status": "PASS", "head_sha": self.HEAD_A},
                    {"status": "PASS", "blocking_findings": 0, "head_sha": self.HEAD_A},
                    {"status": "PASS", "blocking_findings": 0, "head_sha": self.HEAD_A},
                    {"status": "MISSING"},
                    risk=result,
                )
                self.assertEqual(("OWNER_AUTH_REQUIRED", "OWNER_AUTHORIZATION"), state)


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


class PRLoopHandoffTests(unittest.TestCase):
    BASE = "b" * 40
    HEAD = "a" * 40

    def test_canonical_handoff_contains_bounded_exact_sha_delta_and_files(self):
        snapshot = {
            "number": 161,
            "base_sha": self.BASE,
            "head_sha": self.HEAD,
            "draft": False,
            "state": "OPEN",
            "merged": False,
        }
        completed = subprocess.CompletedProcess(
            [],
            0,
            "z.py\0a.py\0a.py\0",
            "",
        )
        with mock.patch.object(REPOCTL, "run", return_value=completed) as run:
            handoff = REPOCTL._pr_loop_chatgpt_handoff(
                snapshot,
                {"status": "PASS", "source": "reused", "head_sha": self.HEAD},
                {"status": "MISSING", "head_sha": self.HEAD},
                {"status": "MISSING", "head_sha": self.HEAD},
                "CODE",
            )
        self.assertIn("ChatGPT incremental exact-SHA PR review handoff", handoff)
        self.assertIn(f'"current_head":"{self.HEAD}"', handoff)
        self.assertIn('"review_kind":"CODE"', handoff)
        self.assertIn('"changed_files":["a.py","z.py"]', handoff)
        self.assertLessEqual(len(handoff.encode()), 16 * 1024)
        self.assertEqual(
            ["git", "diff", "--name-only", "-z", f"{self.BASE}..{self.HEAD}"],
            run.call_args.args[0],
        )

    def test_security_handoff_carries_code_pass_without_reasking_code(self):
        snapshot = {
            "number": 161,
            "base_sha": self.BASE,
            "head_sha": self.HEAD,
            "draft": False,
            "state": "OPEN",
            "merged": False,
        }
        completed = subprocess.CompletedProcess([], 0, "a.py\0", "")
        with mock.patch.object(REPOCTL, "run", return_value=completed):
            handoff = REPOCTL._pr_loop_chatgpt_handoff(
                snapshot,
                {"status": "PASS", "source": "reused", "head_sha": self.HEAD},
                {
                    "provider": "ChatGPT",
                    "kind": "code",
                    "status": "PASS",
                    "blocking_findings": 0,
                    "head_sha": self.HEAD,
                },
                {"status": "MISSING", "head_sha": self.HEAD},
                "SECURITY",
            )
        self.assertIn('"review_kind":"SECURITY"', handoff)
        self.assertIn('"previous_validated_verdict":"CODE_PASS"', handoff)
        self.assertIn("exact-SHA CODE is already PASS", handoff)


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
        return rc, json.loads(stream.getvalue())

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
            mock.patch.multiple(
                REPOCTL,
                _pr_loop_checkout_errors=mock.Mock(return_value=[]),
                _require_trusted_pr_execution=mock.Mock(
                    return_value={"trusted_root": Path("/trusted/base"), "target_root": ROOT}
                ),
            ),
        )

    def test_dry_run_is_read_only_and_emits_exact_code_handoff(self):
        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL, "_github_pr_snapshot", return_value=self.snapshot()
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "PASS", "source": "reused", "head_sha": self.SHA_A},
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", side_effect=self.missing_authorities
        ), mock.patch.object(
            REPOCTL, "_pr_loop_chatgpt_handoff", return_value="bounded-code-handoff"
        ) as handoff, mock.patch.object(REPOCTL, "run") as run:
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
        self.assertEqual("bounded-code-handoff", payload["review_request"]["handoff"])
        self.assertEqual(
            "exact-pr-base-sha",
            payload["review_request"]["rerun"]["controller_source"],
        )
        self.assertIn(
            "/trusted/base/scripts/repository_delivery.py",
            payload["review_request"]["rerun"]["argv"],
        )
        self.assertNotIn("make pr-loop", payload["review_request"]["rerun"]["command"])
        self.assertEqual(len("bounded-code-handoff"), payload["review_request"]["handoff_bytes"])
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
        handoff.assert_called_once()
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
            return_value={"status": "PASS", "source": "reused", "head_sha": self.SHA_A},
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", return_value=authorities
        ), mock.patch.object(
            REPOCTL, "_pr_loop_chatgpt_handoff", return_value="bounded-security-handoff"
        ) as handoff, mock.patch.object(REPOCTL, "run") as run:
            rc, payload = self.run_json(dry_run=True)
        self.assertEqual(0, rc)
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", payload["state"])
        self.assertEqual("SECURITY", payload["review_kind"])
        self.assertEqual("CHATGPT_SECURITY_REVIEW", payload["next_action"])
        self.assertEqual("security", payload["review_request"]["expected_marker"]["kind"])
        self.assertEqual(self.SHA_A, payload["review_request"]["head_sha"])
        self.assertEqual("bounded-security-handoff", payload["review_request"]["handoff"])
        self.assertEqual("SECURITY", handoff.call_args.args[-1])
        run.assert_not_called()

    def test_missing_canonical_handoff_blocks_instead_of_emitting_minimal_event(self):
        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL, "_github_pr_snapshot", return_value=self.snapshot()
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "PASS", "source": "reused", "head_sha": self.SHA_A},
        ), mock.patch.object(
            REPOCTL, "pull_request_authority_evidence", side_effect=self.missing_authorities
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_chatgpt_handoff",
            side_effect=RuntimeError("bounded handoff unavailable"),
        ), mock.patch.object(REPOCTL, "run") as run:
            rc, payload = self.run_json(dry_run=True)
        self.assertEqual(1, rc)
        self.assertEqual("BLOCKED", payload["state"])
        self.assertEqual("FIX_CHATGPT_REVIEW_HANDOFF", payload["next_action"])
        self.assertNotIn("review_request", payload)
        run.assert_not_called()

    def test_valid_exact_sha_qualification_is_reused_without_rerun(self):
        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL, "_github_pr_snapshot", return_value=self.snapshot()
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "PASS", "source": "reused", "head_sha": self.SHA_A},
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
            {"status": "PASS", "source": "reused", "head_sha": self.SHA_A},
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

    def test_low_risk_calls_finish_pr_without_owner_authorization(self):
        reviews = {
            "code": {"status": "PASS", "blocking_findings": 0, "head_sha": self.SHA_A},
            "security": {"status": "PASS", "blocking_findings": 0, "head_sha": self.SHA_A},
        }
        missing_owner = {
            "status": "MISSING",
            "command": f"/owner-authorization approve scope=pr-161 sha={self.SHA_A}",
        }
        low_risk = {
            "classification": "LOW_RISK",
            "authority": "repository-policy",
            "policy_source": "exact-pr-base-sha",
            "pr": 161,
            "base_sha": "c" * 40,
            "head_sha": self.SHA_A,
            "changed_files": ["services/product/query.go"],
            "reasons": [],
            "matched_capabilities": [],
            "analysis_complete": True,
        }
        merged = self.snapshot(state="MERGED", merged=True, merge_commit_sha="d" * 40)
        calls = []

        def run(command, **_kwargs):
            calls.append(command)
            return self.completed(0)

        patches = self.common()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL,
            "_github_pr_snapshot",
            side_effect=[self.snapshot(), self.snapshot(), merged],
        ), mock.patch.object(
            REPOCTL,
            "_pr_loop_qualification",
            return_value={"status": "PASS", "source": "reused", "head_sha": self.SHA_A},
        ), mock.patch.object(
            REPOCTL,
            "pull_request_authority_evidence",
            return_value=(reviews, missing_owner),
        ), mock.patch.object(
            REPOCTL, "classify_merge_risk", return_value=low_risk
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
        payload = post_merge.call_args.args[3]
        self.assertEqual(0, rc)
        self.assertEqual("LOW_RISK", payload["risk_classification"])
        self.assertFalse(payload["owner_authorization_required"])
        self.assertEqual("NOT_REQUIRED_BY_POLICY", payload["owner_authorization"]["status"])
        self.assertEqual("AUTO", payload["merge_mode"])
        self.assertTrue(any("finish-pr" in command for command in calls))

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
            return_value={"status": "PASS", "source": "reused", "head_sha": self.SHA_A},
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
            return_value={"status": "PASS", "source": "reused", "head_sha": self.SHA_A},
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
            return_value={"status": "PASS", "source": "reused", "head_sha": self.SHA_A},
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

        with mock.patch.object(REPOCTL, "git", side_effect=git), mock.patch.object(
            REPOCTL, "run", return_value=self.completed(0)
        ), mock.patch.object(
            REPOCTL, "branch_cleanup", return_value=1
        ):
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                rc = REPOCTL._pr_loop_post_merge(
                    "gh", "owner/repo", merged, result, dry_run=False, json_output=True
                )
        payload = json.loads(stream.getvalue().strip().splitlines()[-1])
        self.assertEqual(1, rc)
        self.assertEqual("MERGED", payload["state"])
        self.assertEqual("PASS", payload["merge_result"])
        self.assertEqual("FAIL", payload["cleanup_result"])

    def test_already_merged_noisy_cleanup_emits_only_one_json_document(self):
        merged = self.snapshot(state="MERGED", merged=True, merge_commit_sha="d" * 40)

        def git(*args, **_kwargs):
            if args[:2] == ("status", "--porcelain"):
                return ""
            if args == ("branch", "--show-current"):
                return "main\n"
            return ""

        def noisy_cleanup(**_kwargs):
            print("PRESERVE local protected | current-branch")
            print("DELETE remote stale | merged")
            print("PASS branch-cleanup candidates=1 deleted=1 kept=1 failures=0")
            raise RuntimeError("cleanup reporting failed")

        patches = self.common()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patches[0], patches[1], patches[2], patches[3], mock.patch.object(
            REPOCTL, "_github_pr_snapshot", return_value=merged
        ), mock.patch.object(REPOCTL, "git", side_effect=git), mock.patch.object(
            REPOCTL, "run", return_value=self.completed(0)
        ), mock.patch.object(REPOCTL, "branch_cleanup", side_effect=noisy_cleanup):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = REPOCTL.pr_loop(161, json_output=True)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(1, rc)
        self.assertEqual(1, stdout.getvalue().count("\n"))
        self.assertEqual("MERGED", payload["state"])
        self.assertEqual("PASS", payload["merge_result"])
        self.assertEqual("FAIL", payload["cleanup_result"])
        self.assertEqual("PASS", payload["output_contract"])
        self.assertIn("PRESERVE", stderr.getvalue())
        self.assertIn("DELETE", stderr.getvalue())
        self.assertIn("PASS branch-cleanup", stderr.getvalue())

    def test_finish_pr_json_preserves_confirmed_merge_after_reporting_failure(self):
        before = {"number": 161, "headRefOid": self.SHA_A}
        after = {
            "state": "MERGED",
            "mergedAt": "2026-09-27T10:00:00Z",
            "headRefOid": self.SHA_A,
            "mergeCommit": {"oid": "d" * 40},
        }

        def noisy_finish(_base):
            cleanup_rc, roadmap_rc = REPOCTL._finish_pr_post_merge_tasks()
            return 1 if cleanup_rc or roadmap_rc else 0

        def noisy_cleanup(**_kwargs):
            print("DELETE remote stale | merged")
            print("FAIL branch-cleanup candidates=1 deleted=0 kept=0 failures=1")
            return 1

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(REPOCTL.shutil, "which", return_value="gh"), mock.patch.object(
            REPOCTL, "git", return_value=self.SHA_A + "\n"
        ), mock.patch.object(
            REPOCTL, "output", side_effect=[json.dumps(before), json.dumps(after)]
        ), mock.patch.object(REPOCTL, "finish_pr", side_effect=noisy_finish), mock.patch.object(
            REPOCTL, "branch_cleanup", side_effect=noisy_cleanup
        ), mock.patch.object(REPOCTL, "_roadmap_followup_after_merge", return_value=0):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = REPOCTL._finish_pr_json("main")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(1, rc)
        self.assertEqual(1, stdout.getvalue().count("\n"))
        self.assertEqual("MERGED", payload["state"])
        self.assertEqual("PASS", payload["merge_result"])
        self.assertEqual("FAIL", payload["cleanup_result"])
        self.assertEqual("PASS", payload["roadmap_result"])
        self.assertEqual("POST_MERGE_CLEANUP", payload["next_action"])
        self.assertEqual("PASS", payload["output_contract"])
        self.assertIn("DELETE", stderr.getvalue())
        self.assertIn("FAIL branch-cleanup", stderr.getvalue())

    def test_finish_pr_json_keeps_cleanup_pass_when_roadmap_fails(self):
        before = {"number": 161, "headRefOid": self.SHA_A}
        after = {
            "state": "MERGED",
            "mergedAt": "2026-09-27T10:00:00Z",
            "headRefOid": self.SHA_A,
            "mergeCommit": {"oid": "d" * 40},
        }

        def finish_with_roadmap_failure(_base):
            cleanup_rc, roadmap_rc = REPOCTL._finish_pr_post_merge_tasks()
            return 1 if cleanup_rc or roadmap_rc else 0

        stdout = io.StringIO()
        with mock.patch.object(REPOCTL.shutil, "which", return_value="gh"), mock.patch.object(
            REPOCTL, "git", return_value=self.SHA_A + "\n"
        ), mock.patch.object(
            REPOCTL, "output", side_effect=[json.dumps(before), json.dumps(after)]
        ), mock.patch.object(
            REPOCTL, "finish_pr", side_effect=finish_with_roadmap_failure
        ), mock.patch.object(
            REPOCTL, "branch_cleanup", return_value=0
        ) as cleanup, mock.patch.object(
            REPOCTL, "_roadmap_followup_after_merge", return_value=1
        ) as roadmap:
            with contextlib.redirect_stdout(stdout):
                rc = REPOCTL._finish_pr_json("main")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(1, rc)
        cleanup.assert_called_once_with(dry_run=False, fetch_remote=False)
        roadmap.assert_called_once_with()
        self.assertEqual("MERGED", payload["state"])
        self.assertEqual("PASS", payload["merge_result"])
        self.assertEqual("PASS", payload["cleanup_result"])
        self.assertEqual("FAIL", payload["roadmap_result"])
        self.assertEqual("FIX_ROADMAP_SYNC", payload["next_action"])
        self.assertEqual("PASS", payload["output_contract"])
        self.assertNotIn("POST_MERGE_CLEANUP", stdout.getvalue())

    def test_json_serialization_fallback_keeps_merge_verdict(self):
        result = REPOCTL._pr_loop_empty_result(161)
        result.update({"state": "MERGED", "merge_result": "PASS", "cleanup_result": "FAIL"})
        result["unexpected"] = object()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            REPOCTL._emit_pr_loop_result(result, json_output=True)
        payload = json.loads(stdout.getvalue())
        self.assertEqual("MERGED", payload["state"])
        self.assertEqual("PASS", payload["merge_result"])
        self.assertEqual("FAIL", payload["cleanup_result"])
        self.assertEqual("FAIL", payload["output_contract"])

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
        ), mock.patch.object(
            REPOCTL, "branch_cleanup", return_value=0
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

    def test_pr_loop_cleanup_pass_does_not_hide_roadmap_failure(self):
        result = REPOCTL._pr_loop_empty_result(161)
        result.update({
            "head_sha": self.SHA_A,
            "merge_result": "PASS",
            "roadmap_result": "FAIL",
        })
        merged = self.snapshot(state="MERGED", merged=True, merge_commit_sha="d" * 40)

        def git(*args, **_kwargs):
            if args[:2] == ("status", "--porcelain"):
                return ""
            if args == ("branch", "--show-current"):
                return "main\n"
            return ""

        with mock.patch.object(REPOCTL, "git", side_effect=git), mock.patch.object(
            REPOCTL, "run", return_value=self.completed(0)
        ), mock.patch.object(REPOCTL, "branch_cleanup", return_value=0):
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                rc = REPOCTL._pr_loop_post_merge(
                    "gh", "owner/repo", merged, result, dry_run=False, json_output=True
                )
        payload = json.loads(stream.getvalue())
        self.assertEqual(1, rc)
        self.assertEqual("MERGED", payload["state"])
        self.assertEqual("PASS", payload["merge_result"])
        self.assertEqual("PASS", payload["cleanup_result"])
        self.assertEqual("FAIL", payload["roadmap_result"])
        self.assertEqual("FIX_ROADMAP_SYNC", payload["next_action"])

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
            return_value={"status": "PASS", "source": "reused", "head_sha": self.SHA_A},
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
    def test_json_head_change_rejects_old_sha_conclusions(self):
        old_sha, current_sha = "a" * 40, "b" * 40
        result = REPOCTL._pr_loop_empty_result(164)
        result.update({
            "head_sha": old_sha,
            "current_head_sha": current_sha,
            "state": "HEAD_CHANGED",
            "qualification": {"status": "PASS", "head_sha": old_sha},
            "code_review": {"status": "FAIL", "head_sha": old_sha},
            "security_review": {"status": "DEFERRED", "head_sha": old_sha},
            "risk": {"classification": "LOW_RISK", "head_sha": old_sha},
            "risk_classification": "LOW_RISK",
            "owner_authorization": {"status": "PASS", "head_sha": old_sha},
            "merge_requirements": {"required_checks": True},
        })
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            REPOCTL._emit_pr_loop_result(result, json_output=True)
        payload = json.loads(output.getvalue())
        self.assertEqual(current_sha, payload["head_sha"])
        for kind in ("qualification", "code_review", "security_review"):
            self.assertEqual(current_sha, payload[kind]["head_sha"])
            self.assertEqual("MISSING", payload[kind]["status"])
        self.assertEqual("HEAD_CHANGED", payload["state"])
        self.assertEqual("UNKNOWN", payload["risk_classification"])
        self.assertEqual(current_sha, payload["risk"]["head_sha"])
        self.assertEqual("MISSING", payload["owner_authorization"]["status"])
        self.assertNotIn("merge_requirements", payload)

    def test_json_cannot_report_old_review_as_current_fail_or_pass(self):
        current_sha, old_sha = "b" * 40, "a" * 40
        for old_status in ("PASS", "FAIL"):
            with self.subTest(old_status=old_status):
                result = REPOCTL._pr_loop_empty_result(164)
                result.update({
                    "head_sha": current_sha,
                    "state": "CODE_FAILED" if old_status == "FAIL" else "MERGE_READY",
                    "qualification": {"status": "PASS", "head_sha": current_sha},
                    "code_review": {"status": old_status, "head_sha": old_sha},
                    "security_review": {"status": "MISSING", "head_sha": current_sha},
                })
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    REPOCTL._emit_pr_loop_result(result, json_output=True)
                payload = json.loads(output.getvalue())
                self.assertEqual("MISSING", payload["code_review"]["status"])
                self.assertEqual(current_sha, payload["code_review"]["head_sha"])
                self.assertEqual("BLOCKED", payload["state"])
                self.assertFalse(payload["merge_ready"])

    def test_json_cli_preflight_failure_still_emits_one_document(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            REPOCTL.sys, "argv", ["repoctl.py", "pr-loop", "--pr", "162", "--json"]
        ), mock.patch(
            "canonical_workspace.check", return_value={"status": "FAIL", "reason": "test workspace"}
        ):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = REPOCTL.main()
        payload = json.loads(stdout.getvalue())
        self.assertEqual(1, rc)
        self.assertEqual(1, stdout.getvalue().count("\n"))
        self.assertEqual("BLOCKED", payload["state"])
        self.assertEqual("PASS", payload["output_contract"])
        self.assertIn("test workspace", payload["blockers"][0])

    def test_direct_pr_loop_requires_the_exact_base_wrapper(self):
        with (
            mock.patch.dict(REPOCTL.os.environ, {}, clear=True),
            mock.patch.object(REPOCTL, "_TRUSTED_PR_EXECUTION_CONTEXT", None),
        ):
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                rc = REPOCTL.pr_loop(162, json_output=True)
        result = json.loads(stream.getvalue().strip().splitlines()[-1])
        self.assertEqual(1, rc)
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("USE_EXACT_BASE_CONTROLLER", result["next_action"])
        self.assertIn("trusted-pr-transition", result["blockers"][0])

    def test_risk_decision_executes_only_the_exact_base_controller(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        runner = source[
            source.index("def _run_exact_base_merge_risk_controller(") : source.index(
                "def classify_merge_risk("
            )
        ]
        self.assertNotIn("import merge_risk", source)
        self.assertNotIn("def _evaluate_merge_risk(", source)
        self.assertIn('f"{base_sha}:{MERGE_RISK_CONTROLLER_PATH}"', runner)
        self.assertIn('"-I"', runner)

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
        self.assertIn("trusted-pr-transition", makefile)
        self.assertIn("TRUSTED_ROOT", makefile)
        self.assertIn('sub.add_parser("pr-loop")', source)
        self.assertIn('loop.add_argument("--json"', source)
        self.assertIn('loop.add_argument("--dry-run"', source)
        self.assertIn('fin.add_argument("--json"', source)

    def test_pr_loop_delegates_merge_and_never_calls_github_merge_directly(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        post_merge = source[
            source.index("def _pr_loop_post_merge(") : source.index("def pr_loop(")
        ]
        loop = source[source.index("def pr_loop(") : source.index("def precommit(")]
        self.assertIn('finish_args = ["finish-pr", "--base", "main"]', loop)
        self.assertIn('_controller_command(*finish_args)', loop)
        self.assertIn("branch_cleanup(dry_run=False, fetch_remote=False)", post_merge)
        self.assertNotIn('_controller_command("branch-cleanup"', post_merge)
        self.assertNotIn('"pr", "merge"', loop)


if __name__ == "__main__":
    unittest.main()
