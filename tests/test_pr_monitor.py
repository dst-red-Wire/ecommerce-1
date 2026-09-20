import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error

from scripts import pr_monitor


def args(**overrides):
    values = {
        "owner": "o",
        "repo": "r",
        "pr": 7,
        "codex_command": [],
        "abandoned": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class PRMonitorTest(unittest.TestCase):
    def test_adaptive_interval_respects_minimum(self):
        self.assertEqual(pr_monitor.next_interval(0, 900, 3600), 900)
        self.assertEqual(pr_monitor.next_interval(4, 900, 3600), 1800)
        self.assertEqual(pr_monitor.next_interval(8, 900, 3600), 3600)
        self.assertEqual(pr_monitor.next_interval(4, 2700, 3600), 2700)
        self.assertEqual(pr_monitor.next_interval(8, 3500, 3600), 3600)

    def test_delta_ignores_poll_metadata_and_diffs_collections(self):
        previous = {
            "head_sha": "a",
            "checks": {"one": "SUCCESS", "two": "PENDING"},
            "reviews": {},
            "open_findings": {},
            "polled_at": 1,
            "etag": "one",
        }
        current = {
            "head_sha": "a",
            "checks": {"one": "FAILURE", "three": "SUCCESS"},
            "reviews": {},
            "open_findings": {},
            "polled_at": 2,
            "etag": "two",
        }
        result = pr_monitor.delta(previous, current)
        self.assertEqual(set(result), {"checks"})
        self.assertEqual(result["checks"]["added"], {"three": "SUCCESS"})
        self.assertEqual(result["checks"]["removed"], {"two": "PENDING"})
        self.assertEqual(result["checks"]["modified"]["one"]["after"], "FAILURE")

    def test_snapshot_tracks_finding_body_position_and_readiness_fields(self):
        pr = {
            "headRefOid": "abc",
            "reviews": {"nodes": []},
            "commits": {"nodes": []},
            "reviewThreads": {
                "nodes": [
                    {
                        "id": "open",
                        "isResolved": False,
                        "comments": {
                            "nodes": [
                                {
                                    "id": "c1",
                                    "path": "x.py",
                                    "line": 8,
                                    "originalLine": 7,
                                    "body": "fix this",
                                    "author": {"login": "reviewer"},
                                }
                            ]
                        },
                    },
                    {"id": "done", "isResolved": True, "comments": {"nodes": [{"id": "c2"}]}},
                ]
            },
            "mergeStateStatus": "BEHIND",
            "isDraft": True,
            "state": "OPEN",
            "merged": False,
        }
        result = pr_monitor.snapshot(pr, etag="tag", timestamp=1)
        finding = result["open_findings"]["open"]
        self.assertEqual(finding["body"], "fix this")
        self.assertEqual(finding["line"], 8)
        self.assertEqual(finding["original_line"], 7)
        self.assertEqual(result["merge_state_status"], "BEHIND")
        self.assertTrue(result["is_draft"])

    def test_paginate_review_threads_fetches_all_pages(self):
        pr = {
            "reviewThreads": {
                "nodes": [{"id": "a"}],
                "pageInfo": {"hasNextPage": True, "endCursor": "one"},
            }
        }
        payload = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [{"id": "b"}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            }
        }
        with mock.patch.object(pr_monitor, "github_request", return_value=(200, payload, "")) as request:
            result = pr_monitor.paginate_review_threads(pr, owner="o", repo="r", number=7, token="t")
        self.assertEqual([item["id"] for item in result["reviewThreads"]["nodes"]], ["a", "b"])
        request.assert_called_once()

    def test_default_state_path_is_namespaced_by_repository(self):
        first = pr_monitor.default_state_path("one", "repo", 7)
        second = pr_monitor.default_state_path("two", "repo", 7)
        self.assertNotEqual(first, second)
        self.assertIn("one-repo-pr-7", str(first))

    def test_304_honors_terminal_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps({"etag": "same", "state": "CLOSED", "merged": False, "unchanged_polls": 3}))
            with mock.patch.object(pr_monitor, "github_request", return_value=(304, None, "same")):
                terminal, unchanged = pr_monitor.poll_once(args(), state, "token")
            self.assertTrue(terminal)
            self.assertEqual(unchanged, 4)

    def test_changed_state_is_persisted_only_after_successful_processing(self):
        previous = {
            "etag": "old",
            "head_sha": "old",
            "checks": {},
            "reviews": {},
            "open_findings": {},
            "open_findings_count": 0,
            "state": "OPEN",
            "merged": False,
        }
        pr = {
            "headRefOid": "new",
            "reviews": {"nodes": []},
            "commits": {"nodes": []},
            "reviewThreads": {"nodes": [], "pageInfo": {"hasNextPage": False}},
            "state": "OPEN",
            "merged": False,
        }
        payload = {"data": {"repository": {"pullRequest": pr}}}
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps(previous))
            with (
                mock.patch.object(pr_monitor, "github_request", return_value=(200, payload, "newtag")),
                mock.patch.object(pr_monitor, "changed_files", return_value=["x.py"]),
                mock.patch.object(pr_monitor, "invoke_codex", side_effect=RuntimeError("review failed")),
            ):
                with self.assertRaises(RuntimeError):
                    pr_monitor.poll_once(args(codex_command=["codex"]), state, "token")
            self.assertEqual(json.loads(state.read_text())["head_sha"], "old")

    def test_validated_verdict_is_stored_and_reused_in_prompt(self):
        previous = {
            "etag": "old",
            "head_sha": "old",
            "checks": {},
            "reviews": {},
            "open_findings": {},
            "open_findings_count": 0,
            "state": "OPEN",
            "merged": False,
            "validated_verdict": "VERDICT : READY",
        }
        current = dict(previous, head_sha="new")
        prompt = pr_monitor.codex_prompt(7, previous, current, {"head_sha": {"before": "old", "after": "new"}}, ["x.py"])
        self.assertIn("VERDICT : READY", prompt)
        self.assertLessEqual(len(prompt.encode()), pr_monitor.PROMPT_BUDGET_BYTES)

    def test_bounded_prompt_stays_within_budget(self):
        findings = {
            str(index): {
                "body": "x" * 5000,
                "path": f"file-{index}.py",
                "line": index,
            }
            for index in range(100)
        }
        payload = {
            "pr": 7,
            "previous_validated_verdict": "v" * 10000,
            "current_head": "abc",
            "changed_files": [f"f-{i}" for i in range(200)],
            "delta": {"open_findings": {"added": findings}},
        }
        encoded = pr_monitor.bounded_payload(payload, budget=4096)
        self.assertLessEqual(len(encoded.encode()), 4096)
        json.loads(encoded)

    def test_invoke_codex_uses_exact_head_worktree(self):
        with (
            mock.patch.object(pr_monitor, "exact_head_worktree") as checkout,
            mock.patch.object(pr_monitor, "_run") as run,
        ):
            checkout.return_value.__enter__.return_value = Path("/exact")
            checkout.return_value.__exit__.return_value = False
            run.return_value = mock.Mock(stdout="VERDICT : READY\n")
            result = pr_monitor.invoke_codex(["codex"], "prompt", head_sha="abc")
        self.assertEqual(result, "VERDICT : READY")
        run.assert_called_once_with(["codex"], cwd=Path("/exact"), input_text="prompt")

    def test_transient_http_failures_are_classified_for_retry(self):
        error = urllib.error.HTTPError(
            "https://api.github.com", 503, "unavailable", {}, None
        )
        error.read = mock.Mock(return_value=b"down")
        with mock.patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(pr_monitor.TransientGitHubError):
                pr_monitor.github_request("https://api.github.com", "token")


if __name__ == "__main__":
    unittest.main()
