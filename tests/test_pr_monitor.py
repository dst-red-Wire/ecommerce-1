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

    def test_changed_state_emits_and_persists_chatgpt_review_handoff(self):
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
                mock.patch.object(pr_monitor, "exact_head_worktree") as checkout,
                mock.patch("builtins.print") as output,
            ):
                checkout.return_value.__enter__.return_value = Path("/exact")
                checkout.return_value.__exit__.return_value = False
                terminal, unchanged = pr_monitor.poll_once(args(), state, "token")
            self.assertFalse(terminal)
            self.assertEqual(unchanged, 0)
            stored = json.loads(state.read_text())
            self.assertEqual("new", stored["head_sha"])
            self.assertIn("chatgpt_review_handoff", stored)
            self.assertIn("current_head", stored["chatgpt_review_handoff"])
            self.assertTrue(stored["exact_head_verified"])
            checkout.assert_called_once_with("new")
            output.assert_any_call("CHATGPT_REVIEW_REQUIRED", flush=True)

    def test_chatgpt_review_handoff_is_bounded_and_exact_sha_oriented(self):
        previous = {
            "head_sha": "old",
            "checks": {},
            "reviews": {},
            "open_findings": {},
            "validated_verdict": "READY",
        }
        current = dict(previous, head_sha="new")
        handoff = pr_monitor.chatgpt_review_handoff(
            7,
            previous,
            current,
            {"head_sha": {"before": "old", "after": "new"}},
            ["x.py"],
        )
        self.assertIn("ChatGPT incremental exact-SHA PR review handoff", handoff)
        self.assertIn("Return the compact UX summary as five lines", handoff)
        self.assertIn('"current_head":"new"', handoff)
        self.assertIn('"previous_validated_verdict":"READY"', handoff)
        self.assertLessEqual(len(handoff.encode()), pr_monitor.PROMPT_BUDGET_BYTES)

        with mock.patch.object(pr_monitor, "_supports_color", return_value=False):
            lines = pr_monitor.compact_status_lines(
                7,
                previous,
                {**current, "validated_verdict": "WAITING"},
                {"head_sha": {"before": "old", "after": "new"}},
            )
        self.assertEqual(5, len(lines))
        self.assertTrue(lines[0].startswith("PR #7"))
        self.assertTrue(lines[1].startswith("HEAD :"))
        self.assertTrue(lines[2].startswith("CHANGEMENT :"))
        self.assertTrue(lines[3].startswith("VERDICT :"))
        self.assertTrue(lines[4].startswith("ACTION :"))

        with mock.patch.object(pr_monitor, "_supports_color", return_value=True):
            colored = pr_monitor.compact_status_lines(
                7,
                previous,
                {**current, "validated_verdict": "READY"},
                {"head_sha": {"before": "old", "after": "new"}},
            )
        self.assertEqual(5, len(colored))
        self.assertTrue(all("\033[" in line and line.endswith("\033[0m") for line in colored))

    def test_snapshot_reuses_latest_chatgpt_exact_sha_verdict(self):
        head = "a" * 40
        def marker(kind, status, blockers):
            return (
                '<!-- chatgpt-exact-sha-review:v1 '
                + json.dumps(
                    {
                        "provider": "ChatGPT",
                        "kind": kind,
                        "head_sha": head,
                        "status": status,
                        "blocking_findings": blockers,
                    },
                    separators=(",", ":"),
                )
                + " -->"
            )

        pr = {
            "headRefOid": head,
            "_repository_owner_login": "owner",
            "comments": {
                "nodes": [
                    {
                        "id": "1",
                        "createdAt": "2026-09-21T08:00:00Z",
                        "body": marker("code", "BLOCKED", 1),
                        "author": {"login": "owner"},
                    },
                    {
                        "id": "2",
                        "createdAt": "2026-09-21T08:01:00Z",
                        "body": marker("code", "PASS", 0),
                        "author": {"login": "owner"},
                    },
                    {
                        "id": "3",
                        "createdAt": "2026-09-21T08:02:00Z",
                        "body": marker("security", "PASS", 0),
                        "author": {"login": "owner"},
                    },
                ]
            },
            "reviews": {"nodes": []},
            "commits": {"nodes": []},
            "reviewThreads": {"nodes": []},
            "state": "OPEN",
            "merged": False,
        }
        result = pr_monitor.snapshot(pr, etag="tag", timestamp=1)
        self.assertEqual("READY", result["validated_verdict"])
        self.assertEqual("PASS", result["chatgpt_review"]["code"]["status"])
        self.assertEqual("PASS", result["chatgpt_review"]["security"]["status"])

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

    def test_pr_monitor_has_no_codex_control_or_external_ai_execution_hook(self):
        source = (Path(pr_monitor.__file__)).read_text(encoding="utf-8").lower()
        for forbidden in (
            "codex",
            "--codex-command",
            "pr_monitor_codex_command",
            "invoke_codex",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

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
