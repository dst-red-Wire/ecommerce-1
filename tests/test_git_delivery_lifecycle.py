import copy
import importlib.util
import inspect
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_delivery", ROOT / "scripts/repoctl.py")
repoctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repoctl)


class GitDeliveryLifecycleContractTest(unittest.TestCase):
    def test_canonical_policy_is_fail_closed(self):
        policy = repoctl.repository_delivery_policy()
        self.assertEqual("github", policy["forge"])
        self.assertEqual("main", policy["default_branch"])
        self.assertEqual("exact-sha", policy["publish"]["qualification"])
        self.assertTrue(policy["publish"]["exact_evidence_required"])
        self.assertEqual("forbidden", policy["publish"]["force_push"])
        self.assertEqual("exact", policy["pull_request"]["head_sha_binding"])
        self.assertEqual(
            {
                "provider": "github",
                "transport": "gh-api-rest",
                "endpoint": "repos/{owner}/{repo}/pulls/{number}",
                "base_sha_selector": ".base.sha",
                "head_sha_selector": ".head.sha",
                "subcommand_json_sha_fields": "non-authoritative",
            },
            policy["pull_request"]["metadata_authority"],
        )
        self.assertEqual("retained-by-forge", policy["pull_request"]["record_after_merge"])
        self.assertEqual("forbidden", policy["pr_loop"]["state_persistence"])
        self.assertEqual(
            "repository-policy-with-sensitive-owner-boundary",
            repoctl.pull_request_review_policy()["agent_execution_fallback"][
                "merge_decision_authority"
            ],
        )
        self.assertEqual(2, policy["pr_loop"]["schema_version"])
        self.assertEqual("scripts/repository_delivery.py", policy["pr_loop"]["controller"])
        self.assertEqual("exact-pr-base-sha", policy["pr_loop"]["controller_source"])
        self.assertEqual("trusted-pr-transition", policy["pr_loop"]["command"])
        self.assertEqual("forbidden", policy["pr_loop"]["direct_head_controller"])
        self.assertEqual(
            ["exact-pr-head", "sync-pr-base-if-required", "qualification"],
            policy["pr_loop"]["transition_order"][:3],
        )
        self.assertEqual(
            "abandon-and-restart-from-current-exact-base",
            policy["pr_loop"]["exact_sha"]["in_flight_transition_on_base_change"],
        )
        self.assertEqual("BASE_CHANGED", policy["pr_loop"]["base_change"]["state"])
        self.assertEqual(
            ["sync-pr-base", "qualification", "git-push", "finish-pr"],
            policy["pr_loop"]["base_change"]["stop_before"],
        )
        handoff = policy["pr_loop"]["chatgpt_handoff"]
        self.assertEqual("ChatGPT-only", handoff["verdict_authority"])
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", handoff["state"])
        self.assertEqual(["CODE", "SECURITY"], handoff["review_kinds"])
        self.assertEqual("canonical-bounded-handoff", handoff["trigger"])
        self.assertEqual(
            "scripts/pr_monitor.py#chatgpt_review_handoff",
            handoff["helper"],
        )
        self.assertEqual("required", handoff["payload"])
        self.assertEqual(16 * 1024, handoff["payload_budget_bytes"])
        self.assertEqual("sha256", handoff["payload_digest"])
        self.assertTrue(handoff["fail_if_payload_unavailable"])
        self.assertEqual("exact-pr-and-head-sha", handoff["invocation_binding"])
        self.assertEqual("required", handoff["rerun_after_valid_marker"])
        self.assertEqual(
            {
                "ordering": "immutable-created-at-then-id",
                "updated_at_authority": "forbidden",
                "owner_authorization_match": "whole-trimmed-comment",
            },
            policy["pr_loop"]["comment_evidence"],
        )
        self.assertEqual("forbidden", policy["pr_loop"]["owner_boundary"]["automatic_generation"])
        self.assertEqual("risk-based", policy["pr_loop"]["owner_boundary"]["mode"])
        self.assertTrue(policy["pr_loop"]["owner_boundary"]["unique_human_interruption"])
        self.assertEqual(
            "required",
            policy["pr_loop"]["owner_boundary"]["automatic_rerun_after_authorization"],
        )
        risk = policy["pr_loop"]["risk_classification"]
        self.assertEqual("repository-policy", risk["authority"])
        self.assertEqual("scripts/merge_risk.py#classify_merge_risk", risk["implementation"])
        self.assertEqual("exact-pr-base-sha", risk["controller_source"])
        self.assertEqual("sensitive", risk["bootstrap_without_controller"])
        self.assertEqual("forbidden", risk["head_controller_execution"])
        self.assertEqual("exact-pr-base-sha", risk["policy_source"])
        self.assertEqual("forbidden", risk["llm_decision"])
        self.assertEqual("sensitive", risk["unknown_or_ambiguous"])
        self.assertEqual("sensitive", risk["partial_analysis"])
        self.assertEqual("sensitive", risk["git_error"])
        self.assertEqual("MERGE_READY", policy["pr_loop"]["merge_delegation"]["state"])
        self.assertEqual("finish-pr", policy["pr_loop"]["merge_delegation"]["command"])
        self.assertEqual(
            "reread-github-before-result",
            policy["pr_loop"]["merge_delegation"]["nonzero_exit"],
        )
        self.assertEqual("branch-cleanup", policy["pr_loop"]["post_merge_cleanup"]["command"])
        self.assertEqual("merge", policy["merge"]["method"])
        self.assertEqual("required", policy["merge"]["match_head_commit"])
        self.assertEqual("required", policy["merge"]["branch_protection"])
        self.assertEqual("when-configured", policy["merge"]["required_checks"])
        self.assertEqual("forbidden", policy["merge"]["bypass_branch_protection"])
        self.assertEqual("delete", policy["cleanup"]["remote_branch"])
        self.assertEqual("delete", policy["cleanup"]["local_branch"])
        automatic_cleanup = policy["cleanup"]["automatic_branch_cleanup"]
        self.assertIs(True, automatic_cleanup["remote_delete_requires_exact_lease"])
        self.assertIs(True, automatic_cleanup["local_delete_requires_compare_and_delete"])

    def test_unsafe_policy_mutations_are_rejected(self):
        policy = repoctl.repository_delivery_policy()
        mutations = (
            ("publish", "force_push", "allowed"),
            ("publish", "direct_default_branch_write", "allowed"),
            ("pull_request", "head_sha_binding", "floating"),
            ("pull_request", "metadata_authority", {}),
            ("merge", "method", "squash"),
            ("merge", "match_head_commit", "optional"),
            ("merge", "branch_protection", "optional"),
            ("merge", "required_checks", "optional"),
            ("merge", "bypass_branch_protection", "allowed"),
            ("cleanup", "remote_branch", "keep"),
            ("cleanup", "local_branch", "keep"),
        )
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                mutated = copy.deepcopy(policy)
                mutated[section][key] = value
                with self.assertRaises(RuntimeError):
                    repoctl._validate_repository_delivery_policy(mutated)

    def test_finish_pr_uses_exact_head_and_no_protection_bypass(self):
        source = inspect.getsource(repoctl.finish_pr)
        for marker in (
            "--match-head-commit",
            "--required",
            "/protection",
            "/rules/branches/",
            "merge-base",
            "_valid_exact_evidence",
            "origin/{branch}",
            '_delete_branch_ref("remote", branch, head)',
            '_delete_branch_ref("local", branch, head)',
            "remote_branch.returncode not in {0, 2}",
            "cannot prove remote branch state",
            "github_pull_request_metadata(gh, number)",
        ):
            self.assertIn(marker, source)
        for marker in (
            "--admin",
            "git push origin --delete",
            'git", "push", "origin", "--delete',
            "git branch -d",
            'git", "branch", "-d',
            "--delete-branch",
        ):
            self.assertNotIn(marker, source)
        self.assertIn("no checks reported", source)
        self.assertIn("owner_authorization", source)
        self.assertIn("_github_unresolved_review_threads", source)

    def test_pr_loop_policy_drift_is_rejected(self):
        policy = repoctl.repository_delivery_policy()
        mutations = (
            lambda value: value["pr_loop"]["merge_delegation"].__setitem__("direct_merge", "allowed"),
            lambda value: value["pr_loop"].__setitem__("controller_source", "pull-request-head"),
            lambda value: value["pr_loop"]["transition_order"].remove("sync-pr-base-if-required"),
            lambda value: value["pr_loop"]["base_change"].__setitem__(
                "next_action", "SYNC_PR_BASE"
            ),
            lambda value: value["pr_loop"].__setitem__("direct_head_controller", "allowed"),
            lambda value: value["pr_loop"]["risk_classification"].__setitem__("llm_decision", "allowed"),
            lambda value: value["pr_loop"]["risk_classification"].__setitem__(
                "controller_source", "pull-request-head"
            ),
            lambda value: value["pr_loop"]["risk_classification"].__setitem__(
                "head_controller_execution", "allowed"
            ),
            lambda value: value["pr_loop"]["risk_classification"]["low_risk"].__setitem__(
                "eligible_paths", ["**"]
            ),
            lambda value: value["pr_loop"]["risk_classification"]["sensitive"][
                "capabilities"
            ]["iam"]["paths"].remove("services/**/oauth/**"),
            lambda value: value["pr_loop"]["risk_classification"]["sensitive"][
                "capabilities"
            ].pop("governance"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                mutated = copy.deepcopy(policy)
                mutate(mutated)
                with self.assertRaisesRegex(RuntimeError, "pr-loop"):
                    repoctl._validate_repository_delivery_policy(mutated)

    def test_makefile_exposes_centralized_commands(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("deliver: signing-rotation-check", makefile)
        self.assertIn("scripts/repoctl.py deliver", makefile)
        self.assertNotIn("publish-change:", makefile)
        self.assertNotIn("scripts/repoctl.py publish", makefile)
        self.assertIn("trusted-pr-transition", makefile)
        self.assertIn("TRUSTED_ROOT", makefile)
        self.assertIn("finish-pr:", makefile)
        self.assertIn("finish-pr is internal", makefile)


if __name__ == "__main__":
    unittest.main()
