"""Exact-comment and owner-order checks for controlled risk content assessment."""

from __future__ import annotations

import contextlib
import io
import subprocess
import tempfile
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import repoctl


BASE = "b" * 40
HEAD = "a" * 40
REPOSITORY = "dst-red-Wire/ecommerce-1"
PR = 183
MARKER = "chatgpt-risk-content-assessment:v1"
FINDING = {
    "id": "sha256:" + "c" * 64,
    "tier": "PRODUCTION",
    "capability": "production-operations",
    "path": "scripts/runtime_authority.py",
    "side": "+",
    "line": 182,
    "rule_index": 0,
    "line_sha256": "sha256:" + "d" * 64,
}
FINDINGS = [FINDING]
DIGEST = "sha256:" + hashlib.sha256(json.dumps(
    FINDINGS, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
).encode("ascii")).hexdigest()
POLICY = {
    "marker": MARKER,
    "required_kinds": ["code", "security"],
    "accepted_kinds": ["comment", "read-only-validation", "metadata"],
    "max_findings": 128,
    "max_attestation_bytes": 8192,
}


def regular_marker(kind: str) -> str:
    payload = {
        "provider": "ChatGPT", "kind": kind, "head_sha": HEAD,
        "status": "PASS", "blocking_findings": 0,
    }
    return "<!-- chatgpt-exact-sha-review:v1 " + json.dumps(
        payload, separators=(",", ":")) + " -->"


def assessment_marker(kind: str, *, override: dict | None = None) -> str:
    payload = {
        "schema_version": 1,
        "pr": PR,
        "base_sha": BASE,
        "head_sha": HEAD,
        "findings_sha256": DIGEST,
        "dispositions": [{
            "finding_id": FINDING["id"], "kind": "read-only-validation",
            "rationale": "The changed line names a validation category.",
            "effect_trace": "No production execution path is called.",
        }],
        "review_kind": kind,
    }
    if override:
        payload.update(override)
    return "<!-- " + MARKER + " " + json.dumps(
        payload, separators=(",", ":")) + " -->"


def comment(identifier: int, minute: int, body: str) -> dict:
    instant = f"2026-10-01T12:{minute:02d}:00Z"
    return {
        "id": identifier, "user": {"login": "dst-red-Wire"},
        "author_association": "OWNER", "created_at": instant,
        "updated_at": instant, "body": body,
    }


class RiskAssessmentCommentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.comments = [
            comment(101, 1, regular_marker("code") + "\n" + assessment_marker("code")),
            comment(102, 2, regular_marker("security") + "\n" + assessment_marker("security")),
            comment(103, 3, f"/owner-authorization approve scope=pr-{PR} sha={HEAD}"),
        ]
        self.reviews = {
            "code": {"status": "PASS", "head_sha": HEAD, "blocking_findings": 0,
                     "comment_id": 101},
            "security": {"status": "PASS", "head_sha": HEAD, "blocking_findings": 0,
                         "comment_id": 102},
        }
        self.owner = {
            "status": "PASS", "scope": f"pr-{PR}", "head_sha": HEAD,
            "comment_id": 103, "command": self.comments[2]["body"],
            "source": "github-pr-comment",
        }
        self.baseline = {"content_findings": FINDINGS,
                         "content_findings_sha256": DIGEST}
        self.snapshot = {
            "number": PR, "state": "OPEN", "draft": False,
            "base": "main", "base_sha": BASE, "head_sha": HEAD,
            "head_repository": REPOSITORY,
        }

    def select(self):
        with (
            mock.patch.object(repoctl, "_risk_content_assessment_policy", return_value=POLICY),
            mock.patch.object(repoctl, "_github_pr_snapshot", return_value=self.snapshot),
            mock.patch.object(repoctl, "_github_pr_comments", return_value=self.comments),
        ):
            return repoctl._risk_content_assessment_from_reviews(
                "gh", REPOSITORY, PR, BASE, HEAD,
                self.baseline, self.reviews, self.owner,
            )

    def test_two_independent_review_comments_and_later_owner_are_bound(self):
        selected = self.select()
        self.assertIsNotNone(selected)
        assessment, receipt = selected
        self.assertNotIn("review_kind", assessment)
        self.assertEqual(DIGEST, assessment["findings_sha256"])
        self.assertEqual((101, 102, 103), (
            receipt["code_comment_id"], receipt["security_comment_id"],
            receipt["owner_comment_id"],
        ))
        self.assertTrue(receipt["owner_after_security"])
        self.assertEqual("PASS", repoctl._risk_content_assessment_owner_gate(
            {"content_assessment": receipt}, self.owner)["status"])

    def test_marker_in_another_comment_never_substitutes_for_review_comment(self):
        self.comments[0]["body"] = regular_marker("code")
        self.comments.append(comment(104, 4, assessment_marker("code")))
        self.assertIsNone(self.select())

    def test_wrong_binding_or_disagreement_preserves_baseline(self):
        for change in (
            {"base_sha": "f" * 40}, {"head_sha": "f" * 40},
            {"pr": PR + 1}, {"findings_sha256": "sha256:" + "0" * 64},
            {"dispositions": []},
        ):
            with self.subTest(change=change):
                original = self.comments[1]["body"]
                self.comments[1]["body"] = (
                    regular_marker("security") + "\n"
                    + assessment_marker("security", override=change)
                )
                self.assertIsNone(self.select())
                self.comments[1]["body"] = original

    def test_duplicate_marker_or_edited_comment_is_rejected(self):
        original = self.comments[0]["body"]
        self.comments[0]["body"] += "\n" + assessment_marker("code")
        self.assertIsNone(self.select())
        self.comments[0]["body"] = original
        self.comments[0]["updated_at"] = "2026-10-01T12:05:00Z"
        self.assertIsNone(self.select())
        baseline = {
            "classification": "PRODUCTION", "changed_files": [FINDING["path"]],
            "analysis_complete": True, **self.baseline,
        }
        with (
            mock.patch.object(repoctl, "_run_exact_base_merge_risk_controller",
                              return_value=baseline) as controller,
            mock.patch.object(repoctl, "_risk_content_assessment_policy",
                              return_value=POLICY),
            mock.patch.object(repoctl, "_github_pr_snapshot",
                              return_value=self.snapshot),
            mock.patch.object(repoctl, "_github_pr_comments",
                              return_value=self.comments),
        ):
            result = repoctl.classify_merge_risk(
                BASE, HEAD, PR, gh="gh", repository=REPOSITORY,
                reviews=self.reviews, authorization=self.owner,
            )
        self.assertIs(result, baseline)
        controller.assert_called_once_with(BASE, HEAD, PR)

    def test_owner_predating_security_does_not_authorize_lower_tier(self):
        self.comments[2]["created_at"] = "2026-10-01T12:01:30Z"
        self.comments[2]["updated_at"] = self.comments[2]["created_at"]
        self.assertIsNone(self.select())
        baseline = {
            "classification": "PRODUCTION", "changed_files": [FINDING["path"]],
            "analysis_complete": True, **self.baseline,
        }
        with (
            mock.patch.object(repoctl, "_run_exact_base_merge_risk_controller",
                              return_value=baseline) as controller,
            mock.patch.object(repoctl, "_risk_content_assessment_policy",
                              return_value=POLICY),
            mock.patch.object(repoctl, "_github_pr_snapshot",
                              return_value=self.snapshot),
            mock.patch.object(repoctl, "_github_pr_comments",
                              return_value=self.comments),
        ):
            result = repoctl.classify_merge_risk(
                BASE, HEAD, PR, gh="gh", repository=REPOSITORY,
                reviews=self.reviews, authorization=self.owner,
            )
        self.assertIs(result, baseline)
        controller.assert_called_once_with(BASE, HEAD, PR)
        gated = repoctl._risk_content_assessment_owner_gate(
            {"content_assessment": {
                "owner_after_security": False, "owner_comment_id": 103,
            }}, self.owner)
        self.assertEqual("MISSING", gated["status"])

    def test_newer_review_fail_or_owner_revoke_retains_baseline(self):
        baseline = {
            "classification": "PRODUCTION", "changed_files": [FINDING["path"]],
            "analysis_complete": True, **self.baseline,
        }
        failing_review = {
            "provider": "ChatGPT", "kind": "security", "head_sha": HEAD,
            "status": "FAIL", "blocking_findings": 1,
        }
        fail_body = "<!-- chatgpt-exact-sha-review:v1 " + json.dumps(
            failing_review, separators=(",", ":")) + " -->"
        for body in (
            fail_body,
            f"/owner-authorization revoke scope=pr-{PR} sha={HEAD}",
        ):
            with self.subTest(body=body):
                self.comments.append(comment(104, 4, body))
                self.assertIsNone(self.select())
                with (
                    mock.patch.object(repoctl, "_run_exact_base_merge_risk_controller",
                                      return_value=baseline) as controller,
                    mock.patch.object(repoctl, "_risk_content_assessment_policy",
                                      return_value=POLICY),
                    mock.patch.object(repoctl, "_github_pr_snapshot",
                                      return_value=self.snapshot),
                    mock.patch.object(repoctl, "_github_pr_comments",
                                      return_value=self.comments),
                ):
                    result = repoctl.classify_merge_risk(
                        BASE, HEAD, PR, gh="gh", repository=REPOSITORY,
                        reviews=self.reviews, authorization=self.owner,
                    )
                self.assertIs(result, baseline)
                controller.assert_called_once_with(BASE, HEAD, PR)
                self.comments.pop()

    def test_pr_change_during_comment_read_rejects_assessment(self):
        changed = dict(self.snapshot, head_sha="e" * 40)
        with (
            mock.patch.object(repoctl, "_risk_content_assessment_policy", return_value=POLICY),
            mock.patch.object(repoctl, "_github_pr_snapshot",
                              side_effect=[self.snapshot, changed]),
            mock.patch.object(repoctl, "_github_pr_comments", return_value=self.comments),
        ):
            self.assertIsNone(repoctl._risk_content_assessment_from_reviews(
                "gh", REPOSITORY, PR, BASE, HEAD,
                self.baseline, self.reviews, self.owner,
            ))

    def test_controller_downgrade_requires_stable_second_comment_read(self):
        baseline = {
            "classification": "PRODUCTION", "changed_files": [FINDING["path"]],
            "analysis_complete": True, **self.baseline,
        }
        final = dict(baseline, classification="SENSITIVE")
        selected = self.select()
        with (
            mock.patch.object(repoctl, "_run_exact_base_merge_risk_controller",
                              side_effect=[baseline, final]) as controller,
            mock.patch.object(repoctl, "_risk_content_assessment_from_reviews",
                              side_effect=[selected, selected]),
        ):
            result = repoctl.classify_merge_risk(
                BASE, HEAD, PR, gh="gh", repository=REPOSITORY,
                reviews=self.reviews, authorization=self.owner,
            )
        self.assertEqual("SENSITIVE", result["classification"])
        self.assertEqual(selected[1], result["content_assessment"])
        self.assertEqual(selected[0], controller.call_args.kwargs["assessment"])
        with (
            mock.patch.object(repoctl, "_run_exact_base_merge_risk_controller",
                              side_effect=[baseline, final]),
            mock.patch.object(repoctl, "_risk_content_assessment_from_reviews",
                              side_effect=[selected, None]),
        ):
            result = repoctl.classify_merge_risk(
                BASE, HEAD, PR, gh="gh", repository=REPOSITORY,
                reviews=self.reviews, authorization=self.owner,
            )
        self.assertIs(result, baseline)

    def test_no_assessment_file_pass_without_later_owner_receipt(self):
        baseline = {
            "classification": "PRODUCTION", "changed_files": [FINDING["path"]],
            "analysis_complete": True, **self.baseline,
        }
        valid = self.select()
        self.assertIsNotNone(valid)
        assessment, receipt = valid
        invalid = {**receipt, "owner_after_security": False,
                   "owner_comment_id": None}
        with (
            mock.patch.object(repoctl, "_run_exact_base_merge_risk_controller",
                              return_value=baseline) as controller,
            mock.patch.object(repoctl, "_risk_content_assessment_from_reviews",
                              return_value=(assessment, invalid)),
        ):
            result = repoctl.classify_merge_risk(
                BASE, HEAD, PR, gh="gh", repository=REPOSITORY,
                reviews=self.reviews, authorization=self.owner,
            )
        self.assertIs(result, baseline)
        controller.assert_called_once_with(BASE, HEAD, PR)

    def test_incomplete_base_or_final_analysis_cannot_lower_risk(self):
        selected = self.select()
        baseline = {
            "classification": "PRODUCTION", "changed_files": [FINDING["path"]],
            "analysis_complete": True, **self.baseline,
        }
        final = dict(baseline, classification="SENSITIVE")
        for stage in ("baseline", "final"):
            with self.subTest(stage=stage):
                first = dict(baseline)
                second = dict(final)
                (first if stage == "baseline" else second)["analysis_complete"] = False
                with (
                    mock.patch.object(repoctl, "_run_exact_base_merge_risk_controller",
                                      side_effect=[first, second]) as controller,
                    mock.patch.object(repoctl, "_risk_content_assessment_from_reviews",
                                      return_value=selected),
                ):
                    result = repoctl.classify_merge_risk(
                        BASE, HEAD, PR, gh="gh", repository=REPOSITORY,
                        reviews=self.reviews, authorization=self.owner,
                    )
                self.assertIs(result, first)
                self.assertNotIn("content_assessment", result)
                self.assertEqual(1 if stage == "baseline" else 2,
                                 controller.call_count)

    def test_pr_loop_requests_owner_then_enforces_risk_proof(self):
        snapshot = {
            **self.snapshot, "head_branch": "fix/assessment-fixture",
            "merged": False, "merge_commit_sha": "",
        }
        qualification = {"status": "PASS", "head_sha": HEAD}

        def transition(risk: dict, *, risk_failure: bool) -> tuple[int, dict, int, object]:
            output = io.StringIO()
            gate_effect = (RuntimeError("producer proof required")
                           if risk_failure else None)
            with (
                mock.patch.object(repoctl, "_pr_sync_lock",
                                  return_value=contextlib.nullcontext(True)),
                mock.patch.object(repoctl, "_require_trusted_pr_execution",
                                  return_value={"trusted_root": Path("/trusted/base"),
                                                "target_root": Path("/target/head"),
                                                "base_sha": BASE}),
                mock.patch.object(repoctl.shutil, "which", return_value="gh"),
                mock.patch.object(repoctl, "repository_delivery_policy",
                                  return_value={"pr_loop": {"state_persistence": "forbidden"}}),
                mock.patch.object(repoctl, "_github_repository_identity",
                                  return_value=("dst-red-Wire", REPOSITORY)),
                mock.patch.object(repoctl, "_pr_loop_current_base", return_value=snapshot),
                mock.patch.object(repoctl, "_pr_loop_checkout_errors", return_value=[]),
                mock.patch.object(repoctl, "_delivery_pr_work_item_preflight",
                                  return_value={"status": "PASS", "reason": "",
                                                "milestone": "M2.5", "work_item_issue": 182,
                                                "work_package": "fixture.yaml",
                                                "preflight": {"status": "PASS"}}),
                mock.patch.object(repoctl, "_pr_loop_qualification",
                                  return_value=qualification),
                mock.patch.object(repoctl, "pull_request_authority_evidence",
                                  return_value=(self.reviews, self.owner)),
                mock.patch.object(repoctl, "classify_merge_risk", return_value=risk),
                mock.patch.object(repoctl, "_delivery_exact_bundle_gate",
                                  return_value={"status": "PASS"}),
                mock.patch.object(repoctl, "_delivery_risk_evidence_gate",
                                  side_effect=gate_effect,
                                  return_value={"status": "PASS"}) as risk_gate,
                mock.patch.object(repoctl, "run",
                                  return_value=subprocess.CompletedProcess([], 0, "", "")),
                mock.patch.object(repoctl, "finish_pr") as finish,
                contextlib.redirect_stdout(output),
            ):
                rc = repoctl.pr_loop(PR, dry_run=True, json_output=True)
            return rc, json.loads(output.getvalue()), risk_gate.call_count, finish

        self.comments[2]["created_at"] = "2026-10-01T12:01:30Z"
        self.comments[2]["updated_at"] = self.comments[2]["created_at"]
        self.assertIsNone(self.select())
        risk = repoctl._merge_risk_result(
            "SENSITIVE", base_sha=BASE, head_sha=HEAD, pr_number=PR,
            changed_files=[FINDING["path"]], reasons=["content-assessed"],
            matched_capabilities=["delivery-authority"], analysis_complete=True,
        )
        risk["content_assessment"] = {
            "owner_after_security": False, "owner_comment_id": 103,
        }
        rc, payload, risk_calls, finish = transition(risk, risk_failure=True)
        self.assertEqual(0, rc)
        self.assertEqual("OWNER_AUTH_REQUIRED", payload["state"])
        self.assertFalse(payload["merge_ready"])
        self.assertEqual("MISSING", payload["owner_authorization"]["status"])
        self.assertEqual(0, risk_calls)
        finish.assert_not_called()

        self.comments[2]["created_at"] = "2026-10-01T12:03:00Z"
        self.comments[2]["updated_at"] = self.comments[2]["created_at"]
        selected = self.select()
        self.assertIsNotNone(selected)
        risk["content_assessment"] = selected[1]
        rc, payload, risk_calls, finish = transition(risk, risk_failure=True)
        self.assertEqual(1, rc)
        self.assertEqual("BLOCKED", payload["state"])
        self.assertEqual("FIX_EVIDENCE_BUNDLE", payload["next_action"])
        self.assertEqual(1, risk_calls)
        finish.assert_not_called()

    def test_invalid_inventory_digest_is_rejected(self):
        result = {
            "classification": "PRODUCTION", "authority": "repository-policy",
            "controller_source": "exact-pr-base-sha",
            "controller_path": repoctl.MERGE_RISK_CONTROLLER_PATH,
            "policy_source": "exact-pr-base-sha", "pr": PR,
            "base_sha": BASE, "head_sha": HEAD,
            "changed_files": [FINDING["path"]],
            "reasons": ["production-operations"],
            "matched_capabilities": ["production-operations"],
            "analysis_complete": True,
            "requirements": repoctl._RISK_CLASS_REQUIREMENTS["PRODUCTION"],
            "content_findings": FINDINGS,
            "content_findings_sha256": "sha256:" + "0" * 64,
        }
        with self.assertRaisesRegex(RuntimeError, "finding digest"):
            repoctl._validated_trusted_merge_risk_result(
                result, base_sha=BASE, head_sha=HEAD, pr_number=PR,
            )


class RiskAssessmentAdoptionSimulationTests(unittest.TestCase):
    """Local Git history exercises old-base then adopted-base authority."""

    def test_old_base_governance_then_new_base_content_only_arbitration(self):
        source_root = Path(__file__).resolve().parents[1]
        def command(cwd: Path, *args: str) -> str:
            result = subprocess.run(
                ["git", *args], cwd=cwd, capture_output=True, text=True,
                check=False,
            )
            if result.returncode:
                self.fail(result.stderr or result.stdout or f"git {args} failed")
            return (result.stdout or "").strip()

        def commit(cwd: Path, title: str) -> str:
            command(cwd, "add", ".")
            command(cwd, "-c", "user.name=Fixture Owner",
                    "-c", "user.email=fixture@example.invalid",
                    "-c", "commit.gpgsign=false", "commit", "-qm", title)
            return command(cwd, "rev-parse", "HEAD")

        with tempfile.TemporaryDirectory(prefix="risk-adoption-simulation-") as temporary:
            repository = Path(temporary)
            (repository / "scripts/windows").mkdir(parents=True)
            (repository / "config/contracts").mkdir(parents=True)
            command(repository, "init", "-q")
            # The old controller fixture is intentionally self-contained, so
            # shallow CI checkouts exercise this exact-base transition too.
            old_controller = r'''#!/usr/bin/env python3
import argparse
import json
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--base-sha", required=True)
parser.add_argument("--head-sha", required=True)
parser.add_argument("--pr", type=int)
args = parser.parse_args()
paths = sorted(subprocess.check_output(
    ["git", "diff", "--name-only", args.base_sha, args.head_sha], text=True,
).splitlines())
governance = any(path in {
    "config/contracts/review-policy.yaml", "scripts/merge_risk.py",
} for path in paths)
print(json.dumps({
    "classification": "SENSITIVE" if governance else "LOW_RISK",
    "authority": "repository-policy", "controller_source": "exact-pr-base-sha",
    "controller_path": "scripts/merge_risk.py",
    "policy_source": "exact-pr-base-sha", "pr": args.pr,
    "base_sha": args.base_sha, "head_sha": args.head_sha,
    "changed_files": paths,
    "reasons": ["legacy-governance-change"] if governance else [],
    "matched_capabilities": ["governance"] if governance else [],
    "analysis_complete": True,
}, sort_keys=True))
'''
            (repository / "config/contracts/review-policy.yaml").write_text(
                "legacy_policy: true\n", encoding="utf-8"
            )
            (repository / "scripts/merge_risk.py").write_text(
                old_controller, encoding="utf-8"
            )
            (repository / "scripts/runtime_authority.py").write_text(
                'PRODUCTION_CREDENTIAL_LABEL = "none"\n', encoding="utf-8"
            )
            (repository / "scripts/windows/LabNativeBoot.ps1").write_text(
                "Write-Output 'ready'\n", encoding="utf-8"
            )
            old_base = commit(repository, "old exact base")

            for relative in (
                "config/contracts/review-policy.yaml", "scripts/merge_risk.py",
            ):
                (repository / relative).write_bytes((source_root / relative).read_bytes())
            adopted_base = commit(repository, "adopt controlled risk arbitration")
            with mock.patch.object(repoctl, "ROOT", repository):
                governance = repoctl._run_exact_base_merge_risk_controller(
                    old_base, adopted_base, 184
                )
            self.assertEqual("SENSITIVE", governance["classification"])
            self.assertEqual(["legacy-governance-change"], governance["reasons"])
            self.assertEqual("exact-pr-base-sha", governance["controller_source"])

            (repository / "scripts/runtime_authority.py").write_text(
                'PRODUCTION_CREDENTIAL_LABEL = "production credential"\n',
                encoding="utf-8",
            )
            content_head = commit(repository, "reader-only content fixture")
            with mock.patch.object(repoctl, "ROOT", repository):
                baseline = repoctl._run_exact_base_merge_risk_controller(
                    adopted_base, content_head, PR
                )
            self.assertEqual("PRODUCTION", baseline["classification"])
            self.assertTrue(baseline["content_findings"])
            payload = {
                "schema_version": 1, "pr": PR,
                "base_sha": adopted_base, "head_sha": content_head,
                "findings_sha256": baseline["content_findings_sha256"],
                "dispositions": [
                    {"finding_id": finding["id"], "kind": "metadata",
                     "rationale": "This source line names a fixture label only.",
                     "effect_trace": "No production or credential operation consumes it."}
                    for finding in baseline["content_findings"]
                ],
            }
            comments = []
            reviews = {}
            for index, kind in enumerate(("code", "security"), start=1):
                regular = {
                    "provider": "ChatGPT", "kind": kind, "head_sha": content_head,
                    "status": "PASS", "blocking_findings": 0,
                }
                attestation = {**payload, "review_kind": kind}
                body = (
                    "<!-- chatgpt-exact-sha-review:v1 "
                    + json.dumps(regular, separators=(",", ":")) + " -->\n"
                    + "<!-- " + MARKER + " "
                    + json.dumps(attestation, separators=(",", ":")) + " -->"
                )
                comments.append(comment(300 + index, index, body))
                reviews[kind] = {
                    "status": "PASS", "head_sha": content_head,
                    "blocking_findings": 0, "comment_id": 300 + index,
                }
            owner_command = (
                f"/owner-authorization approve scope=pr-{PR} sha={content_head}"
            )
            comments.append(comment(303, 3, owner_command))
            owner = {"status": "PASS", "scope": f"pr-{PR}",
                     "head_sha": content_head, "comment_id": 303,
                     "command": owner_command, "source": "github-pr-comment"}
            snapshot = {
                "number": PR, "state": "OPEN", "draft": False,
                "base": "main", "base_sha": adopted_base,
                "head_sha": content_head, "head_repository": REPOSITORY,
            }
            with (
                mock.patch.object(repoctl, "ROOT", repository),
                mock.patch.object(repoctl, "_risk_content_assessment_policy",
                                  return_value=POLICY),
                mock.patch.object(repoctl, "_github_pr_snapshot",
                                  return_value=snapshot),
                mock.patch.object(repoctl, "_github_pr_comments",
                                  return_value=comments),
            ):
                assessed = repoctl.classify_merge_risk(
                    adopted_base, content_head, PR, gh="gh",
                    repository=REPOSITORY, reviews=reviews, authorization=owner,
                )
            self.assertEqual("SENSITIVE", assessed["classification"])
            self.assertTrue(assessed["content_assessment"]["owner_after_security"])

            command(repository, "checkout", "-q", adopted_base)
            (repository / "scripts/windows/LabNativeBoot.ps1").write_text(
                "Write-Output 'read-only validation'\n", encoding="utf-8"
            )
            windows_head = commit(repository, "native path fixture")
            with mock.patch.object(repoctl, "ROOT", repository):
                native = repoctl._run_exact_base_merge_risk_controller(
                    adopted_base, windows_head, 181
                )
            self.assertEqual("PRIVILEGED", native["classification"])
            self.assertIn("host-mutation", native["matched_capabilities"])


if __name__ == "__main__":
    unittest.main()
