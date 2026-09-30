from __future__ import annotations

import json
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import exact_pr_binding as PR

REPOSITORY = "dst-red-Wire/ecommerce-1"
HEAD = "a" * 40
BASE = "b" * 40
BRANCH = "feature/dynamic-pr"


def pr_payload(number: int = 169) -> dict:
    return {
        "number": number,
        "state": "open",
        "draft": False,
        "merged": False,
        "merged_at": None,
        "base": {
            "ref": "main",
            "sha": BASE,
            "repo": {"full_name": REPOSITORY},
        },
        "head": {
            "ref": BRANCH,
            "sha": HEAD,
            "repo": {"full_name": REPOSITORY},
        },
    }


class ExactPRBindingTests(unittest.TestCase):
    def setUp(self):
        self.list_items = [pr_payload()]
        self.details = {169: pr_payload()}
        self.current_base = BASE
        self.calls = []

    def fake_api(self, gh, endpoint):
        self.assertEqual(gh, "gh")
        self.calls.append(endpoint)
        if endpoint == f"repos/{REPOSITORY}/branches/main":
            return {"name": "main", "commit": {"sha": self.current_base}}
        if endpoint.startswith(f"repos/{REPOSITORY}/pulls?"):
            page = int(endpoint.rsplit("page=", 1)[1])
            start = (page - 1) * 100
            return self.list_items[start : start + 100]
        if endpoint.startswith(f"repos/{REPOSITORY}/pulls/"):
            number = int(endpoint.rsplit("/", 1)[1])
            return self.details[number]
        raise AssertionError(endpoint)

    def resolve(self, **kwargs):
        with mock.patch.object(PR, "_api", side_effect=self.fake_api):
            return PR.resolve_exact_open_pr(REPOSITORY, HEAD, BRANCH, "main", **kwargs)

    def test_resolves_169_then_new_170_dynamically(self):
        old = self.resolve()
        self.assertEqual(169, old.pr_number)
        self.assertEqual(BASE, old.base_sha)
        self.assertEqual(
            {
                "repository": REPOSITORY,
                "pr_number": 169,
                "base": "main",
                "base_sha": BASE,
                "head_branch": BRANCH,
                "head_sha": HEAD,
            },
            old.as_dict(),
        )
        self.assertEqual(
            [
                f"repos/{REPOSITORY}/branches/main",
                f"repos/{REPOSITORY}/pulls?state=open&per_page=100&page=1",
                f"repos/{REPOSITORY}/pulls/169",
                f"repos/{REPOSITORY}/branches/main",
            ],
            self.calls,
        )

        self.list_items = [pr_payload(170)]
        self.details[170] = pr_payload(170)
        self.details[169]["state"] = "closed"
        fresh = self.resolve()
        self.assertEqual(170, fresh.pr_number)
        with (
            mock.patch.object(PR, "_api", side_effect=self.fake_api),
            self.assertRaises(PR.ExactPRBindingChanged) as error,
        ):
            PR.revalidate_exact_open_pr(old)
        self.assertEqual("PR_CHANGED", error.exception.reason)

    def test_binding_is_immutable_and_json_projection_is_a_copy(self):
        binding = self.resolve()
        with self.assertRaises(FrozenInstanceError):
            binding.pr_number = 170
        projected = binding.as_dict()
        projected["pr_number"] = 170
        self.assertEqual(169, binding.pr_number)
        self.assertEqual(
            binding,
            PR.ExactPRBinding.from_dict(json.loads(json.dumps(binding.as_dict()))),
        )
        with mock.patch.object(PR, "_api", side_effect=self.fake_api):
            self.assertEqual(binding, PR.revalidate_exact_open_pr(binding.as_dict()))
        with self.assertRaises(PR.ExactPRBindingError):
            PR.ExactPRBinding.from_dict({**binding.as_dict(), "unknown": True})

    def test_rejects_zero_or_two_exact_open_pull_requests(self):
        for items, count in (([], 0), ([pr_payload(), pr_payload(170)], 2)):
            with self.subTest(count=count):
                self.list_items = items
                with self.assertRaisesRegex(PR.ExactPRBindingError, f"found {count}"):
                    self.resolve()

    def test_checks_all_pages_before_deciding_uniqueness(self):
        unrelated = pr_payload(200)
        unrelated["head"]["sha"] = "c" * 40
        self.list_items = [unrelated for _ in range(100)] + [pr_payload()]
        binding = self.resolve()
        self.assertEqual(169, binding.pr_number)
        self.assertIn(
            f"repos/{REPOSITORY}/pulls?state=open&per_page=100&page=2",
            self.calls,
        )

    def test_rejects_draft_closed_merged_fork_and_detail_mismatches(self):
        mutations = {
            "draft": lambda item: item.update(draft=True),
            "closed": lambda item: item.update(state="closed"),
            "merged": lambda item: item.update(merged_at="2026-01-01T00:00:00Z"),
            "merged_flag": lambda item: item.update(merged=True),
            "invalid_merged_flag": lambda item: item.update(merged=0),
            "missing_merged_at": lambda item: item.pop("merged_at"),
            "wrong_number": lambda item: item.update(number=170),
            "fork": lambda item: item["head"]["repo"].update(full_name="other/fork"),
            "wrong_base_repo": lambda item: item["base"]["repo"].update(
                full_name="other/repo"
            ),
            "wrong_base_sha": lambda item: item["base"].update(sha="c" * 40),
            "wrong_head_sha": lambda item: item["head"].update(sha="c" * 40),
            "wrong_branch": lambda item: item["head"].update(ref="other-branch"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                self.details[169] = pr_payload()
                mutate(self.details[169])
                with self.assertRaises(PR.ExactPRBindingError):
                    self.resolve()

    def test_list_head_or_branch_mismatch_has_no_exact_candidate(self):
        for field, value in (("sha", "c" * 40), ("ref", "other-branch")):
            with self.subTest(field=field):
                self.list_items = [pr_payload()]
                self.list_items[0]["head"][field] = value
                with self.assertRaisesRegex(PR.ExactPRBindingError, "found 0"):
                    self.resolve()

    def test_rejects_wrong_inputs_and_current_main(self):
        with mock.patch.object(PR, "_api", side_effect=self.fake_api):
            for repository, source_sha, branch, base, base_sha in (
                ("other/repo", HEAD, BRANCH, "main", None),
                (REPOSITORY, "short", BRANCH, "main", None),
                (REPOSITORY, HEAD, "", "main", None),
                (REPOSITORY, HEAD, BRANCH, "develop", None),
                (REPOSITORY, HEAD, BRANCH, "main", "bad-sha"),
                (REPOSITORY, HEAD, BRANCH, "main", "c" * 40),
            ):
                with (
                    self.subTest(
                        repository=repository,
                        source_sha=source_sha,
                        branch=branch,
                        base=base,
                        base_sha=base_sha,
                    ),
                    self.assertRaises(PR.ExactPRBindingError),
                ):
                    PR.resolve_exact_open_pr(
                        repository, source_sha, branch, base, base_sha
                    )

    def test_rejects_malformed_api_objects_and_base_race(self):
        scenarios = [
            ("branch-sha", {"name": "main", "commit": {"sha": "bad"}}),
            ("branch-shape", {"name": "main", "commit": []}),
            ("list-shape", {"not": "a list"}),
            ("list-nested", [{"number": 1, "head": None, "base": {}}]),
            ("detail-nested", {"number": 169, "head": [], "base": {}}),
        ]
        for label, bad in scenarios:
            with self.subTest(label=label):

                def api(_gh, endpoint, *, label=label, bad=bad):
                    if label.startswith("branch") and "/branches/" in endpoint:
                        return bad
                    if label.startswith("list") and "pulls?" in endpoint:
                        return bad
                    if label.startswith("detail") and endpoint.endswith("/pulls/169"):
                        return bad
                    return self.fake_api(_gh, endpoint)

                with (
                    mock.patch.object(PR, "_api", side_effect=api),
                    self.assertRaises(PR.ExactPRBindingError),
                ):
                    PR.resolve_exact_open_pr(REPOSITORY, HEAD, BRANCH, "main")

        reads = iter([BASE, "c" * 40])
        with (
            mock.patch.object(
                PR, "_current_base_sha", side_effect=lambda *_: next(reads)
            ),
            mock.patch.object(PR, "_api", side_effect=self.fake_api),
            self.assertRaisesRegex(PR.ExactPRBindingError, "changed while"),
        ):
            PR.resolve_exact_open_pr(REPOSITORY, HEAD, BRANCH, "main")

    def test_revalidation_rejects_forged_binding_before_api_call(self):
        forged = PR.ExactPRBinding("other/repo", 169, "main", BASE, BRANCH, HEAD)
        with (
            mock.patch.object(PR, "_api") as api,
            self.assertRaises(PR.ExactPRBindingError),
        ):
            PR.revalidate_exact_open_pr(forged)
        api.assert_not_called()

    def test_revalidation_reports_head_supersession(self):
        binding = self.resolve()
        self.details[169]["head"]["sha"] = "c" * 40
        with (
            mock.patch.object(PR, "_api", side_effect=self.fake_api),
            self.assertRaises(PR.ExactPRBindingChanged) as error,
        ):
            PR.revalidate_exact_open_pr(binding)
        self.assertEqual("HEAD_CHANGED", error.exception.reason)
        self.assertEqual("c" * 40, error.exception.current_head_sha)

    def test_api_command_and_json_errors_fail_closed(self):
        endpoint = f"repos/{REPOSITORY}/branches/main"
        for result in (
            subprocess.CompletedProcess(["gh"], 1, "", "unauthorized"),
            subprocess.CompletedProcess(["gh"], 0, "{broken", ""),
        ):
            with (
                mock.patch.object(PR.subprocess, "run", return_value=result),
                self.assertRaises(PR.ExactPRBindingError),
            ):
                PR._api("gh", endpoint)
        with (
            mock.patch.object(
                PR.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["gh"], 30),
            ),
            self.assertRaises(PR.ExactPRBindingError),
        ):
            PR._api("gh", endpoint)


if __name__ == "__main__":
    unittest.main()
