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
        self.assertNotIn("headRefOid", source)

    def test_makefile_exposes_centralized_commands(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("publish-change:", makefile)
        self.assertIn("scripts/repoctl.py publish-change", makefile)
        self.assertIn("finish-pr:", makefile)
        self.assertIn("scripts/repoctl.py finish-pr", makefile)


if __name__ == "__main__":
    unittest.main()
