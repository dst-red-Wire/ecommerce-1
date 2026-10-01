import argparse
import json
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from scripts import pr_monitor
from scripts.exact_pr_binding import ExactPRBinding


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
                    {
                        "id": "done",
                        "isResolved": True,
                        "comments": {"nodes": [{"id": "c2"}]},
                    },
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
        with mock.patch.object(
            pr_monitor, "github_request", return_value=(200, payload, "")
        ) as request:
            result = pr_monitor.paginate_review_threads(
                pr, owner="o", repo="r", number=7, token="t"
            )
        self.assertEqual(
            [item["id"] for item in result["reviewThreads"]["nodes"]], ["a", "b"]
        )
        request.assert_called_once()

    def test_default_state_path_is_namespaced_by_repository(self):
        first = pr_monitor.default_state_path("one", "repo", 7)
        second = pr_monitor.default_state_path("two", "repo", 7)
        self.assertNotEqual(first, second)
        self.assertIn("one-repo-pr-7", str(first))

    def test_304_honors_terminal_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "etag": "same",
                        "state": "CLOSED",
                        "merged": False,
                        "unchanged_polls": 3,
                    }
                )
            )
            with mock.patch.object(
                pr_monitor, "github_request", return_value=(304, None, "same")
            ):
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
                mock.patch.object(
                    pr_monitor, "github_request", return_value=(200, payload, "newtag")
                ),
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
            checkout.assert_called_once_with("new", repo_root=pr_monitor.ROOT)
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
        self.assertIn('"review_kind":"COMBINED"', handoff)
        self.assertIn('"previous_validated_verdict":"READY"', handoff)
        self.assertLessEqual(len(handoff.encode()), pr_monitor.PROMPT_BUDGET_BYTES)

        code_handoff = pr_monitor.chatgpt_review_handoff(
            7,
            previous,
            current,
            {"head_sha": {"before": "old", "after": "new"}},
            ["x.py"],
            review_kind="CODE",
        )
        self.assertIn('"review_kind":"CODE"', code_handoff)
        self.assertIn("Perform only the requested CODE review", code_handoff)

        minimal = pr_monitor.bounded_payload(
            {
                "pr": 7,
                "review_kind": "CODE",
                "previous_validated_verdict": "READY",
                "delta": {
                    "checks": {
                        "modified": {
                            f"check-{index}": {"before": "x" * 400, "after": "y" * 400}
                            for index in range(100)
                        }
                    }
                },
                "previous_head": "old",
                "current_head": "new",
                "changed_files": [f"path/{index}.py" for index in range(100)],
                "exact_head_verified": True,
            },
            budget=1024,
        )
        decoded = json.loads(minimal)
        self.assertEqual("old", decoded["previous_head"])
        self.assertEqual("new", decoded["current_head"])
        self.assertEqual("CODE", decoded["review_kind"])
        self.assertIn("delta", decoded)
        self.assertTrue(decoded["exact_head_verified"])
        self.assertTrue(decoded["truncated"])

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
        self.assertTrue(
            all("\033[" in line and line.endswith("\033[0m") for line in colored)
        )

    def test_snapshot_reuses_latest_chatgpt_exact_sha_verdict(self):
        head = "a" * 40

        def marker(kind, status, blockers):
            return (
                "<!-- chatgpt-exact-sha-review:v1 "
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
                        "updatedAt": "2026-09-21T08:00:00Z",
                        "authorAssociation": "OWNER",
                        "body": marker("code", "BLOCKED", 1),
                        "author": {"login": "owner"},
                    },
                    {
                        "id": "2",
                        "createdAt": "2026-09-21T08:01:00Z",
                        "updatedAt": "2026-09-21T08:01:00Z",
                        "authorAssociation": "OWNER",
                        "body": marker("code", "PASS", 0),
                        "author": {"login": "owner"},
                    },
                    {
                        "id": "3",
                        "createdAt": "2026-09-21T08:02:00Z",
                        "updatedAt": "2026-09-21T08:02:00Z",
                        "authorAssociation": "OWNER",
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

    def test_bounded_prompt_trims_long_paths_until_the_summary_fits(self):
        payload = {
            "pr": 7,
            "review_kind": "CODE",
            "previous_validated_verdict": "READY",
            "previous_head": "old",
            "current_head": "new",
            "changed_files": [f"path/{index}/{'x' * 390}.py" for index in range(20)],
            "delta": {},
            "exact_head_verified": True,
        }
        encoded = pr_monitor.bounded_payload(payload, budget=4096)
        decoded = json.loads(encoded)
        self.assertLessEqual(len(encoded.encode()), 4096)
        self.assertLess(len(decoded["changed_files"]), 20)

    def test_pr_monitor_has_no_codex_control_or_external_ai_execution_hook(self):
        source = (Path(pr_monitor.__file__)).read_text(encoding="utf-8").lower()
        for forbidden in (
            '["codex",',
            '("codex",',
            "--codex-command",
            "pr_monitor_codex_command",
            "invoke_codex",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_edited_and_nonowner_markers_never_look_ready(self):
        head = "a" * 40
        marker = (
            "<!-- chatgpt-exact-sha-review:v1 "
            + json.dumps(
                {
                    "provider": "ChatGPT",
                    "kind": "code",
                    "head_sha": head,
                    "status": "PASS",
                    "blocking_findings": 0,
                }
            )
            + " -->"
        )
        comment = {
            "id": "one",
            "createdAt": "2026-10-01T12:00:00Z",
            "updatedAt": "2026-10-01T12:00:01Z",
            "authorAssociation": "OWNER",
            "body": marker,
            "author": {"login": "owner"},
        }
        pr = {
            "headRefOid": head,
            "_repository_owner_login": "owner",
            "comments": {"nodes": [comment]},
        }
        self.assertEqual("BLOCKED", pr_monitor._latest_chatgpt_review(pr)["verdict"])
        comment["updatedAt"] = comment["createdAt"]
        comment["authorAssociation"] = "CONTRIBUTOR"
        self.assertEqual("BLOCKED", pr_monitor._latest_chatgpt_review(pr)["verdict"])
        comment["author"] = {"login": "bot"}
        self.assertEqual({}, pr_monitor._latest_chatgpt_review(pr))

    def test_pending_transport_polls_on_304_but_idle_timer_does_not_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "etag": "same",
                        "state": "OPEN",
                        "merged": False,
                        "resume_pending": True,
                        "unchanged_polls": 1,
                    }
                )
            )
            monitor_args = args(trusted_root=Path("/trusted"))
            with (
                mock.patch.object(
                    pr_monitor, "github_request", return_value=(304, None, "same")
                ),
                mock.patch.object(
                    pr_monitor,
                    "resume_trusted_transition",
                    return_value=pr_monitor.ResumeOutcome(False),
                ) as resume,
            ):
                pr_monitor.poll_once(monitor_args, state, "token")
                resume.assert_called_once_with(monitor_args, poll_existing_only=True)
                resume.reset_mock()
                pr_monitor.poll_once(monitor_args, state, "token")
                resume.assert_not_called()

    def test_marker_event_resumes_trusted_controller_without_user_notification(self):
        head = "a" * 40
        previous = {
            "etag": "before",
            "state": "OPEN",
            "merged": False,
            "head_sha": head,
            "chatgpt_review": {},
            "owner_authorization": {},
            "exact_head_verified": True,
        }
        current = {
            **previous,
            "etag": "after",
            "chatgpt_review": {"code": {"status": "PASS", "comment_id": "new-marker"}},
        }
        payload = {
            "data": {
                "repository": {
                    "owner": {"login": "dst-red-Wire"},
                    "pullRequest": {"state": "OPEN", "headRefOid": head},
                }
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps(previous))
            monitor_args = args(
                owner="dst-red-Wire",
                repo="ecommerce-1",
                pr=169,
                trusted_root=Path("/trusted"),
            )
            with (
                mock.patch.object(
                    pr_monitor, "github_request", return_value=(200, payload, "after")
                ),
                mock.patch.object(pr_monitor, "snapshot", return_value=current),
                mock.patch.object(
                    pr_monitor,
                    "resume_trusted_transition",
                    return_value=pr_monitor.ResumeOutcome(False),
                ) as resume,
                mock.patch.object(pr_monitor, "exact_head_worktree") as checkout,
            ):
                pr_monitor.poll_once(monitor_args, state, "token")
            resume.assert_called_once_with(monitor_args, poll_existing_only=False)
            checkout.assert_not_called()

    def test_resume_passes_exact_campaign_consent_and_polls_existing_submission(self):
        monitor_args = args(
            owner="dst-red-Wire",
            repo="ecommerce-1",
            pr=169,
            trusted_root=Path("/trusted"),
            target_root=Path("/target"),
            owner_authorization_binding="169:" + "a" * 40,
        )
        completed = mock.Mock(
            stdout=json.dumps(
                {
                    "pr": 169,
                    "state": "CHATGPT_REVIEW_REQUIRED",
                    "head_sha": "a" * 40,
                    "review_dispatch": {
                        "status": "RUNNING",
                        "submission_id": "submission-1",
                        "head_sha": "a" * 40,
                        "pr": 169,
                    },
                }
            ),
            returncode=0,
        )
        with (
            mock.patch.object(
                pr_monitor,
                "_verified_resume_context",
                return_value=(
                    Path("/trusted"),
                    Path("/target"),
                    Path("/trusted/scripts/pr_review_dispatch_transition.py"),
                ),
            ),
            mock.patch.object(
                pr_monitor.subprocess, "run", return_value=completed
            ) as runner,
        ):
            pending = pr_monitor.resume_trusted_transition(monitor_args)
        self.assertTrue(pending.pending)
        self.assertFalse(pending.transient_error)
        command = runner.call_args.args[0]
        self.assertIn("--owner-authorization-binding", command)
        self.assertEqual("169:" + "a" * 40, command[-1])
        self.assertEqual(["-I", "-c"], command[1:3])
        self.assertEqual(
            "/trusted/scripts/pr_review_dispatch_transition.py", command[4]
        )
        self.assertEqual(Path("/trusted"), runner.call_args.kwargs["cwd"])

    def test_transient_transport_retry_is_bounded_and_timer_polls_only_existing(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "etag": "same",
                        "state": "OPEN",
                        "merged": False,
                        "resume_pending": True,
                        "resume_retry_count": 0,
                    }
                )
            )
            monitor_args = args(trusted_root=Path("/trusted"))
            with (
                mock.patch.object(
                    pr_monitor, "github_request", return_value=(304, None, "same")
                ),
                mock.patch.object(
                    pr_monitor,
                    "resume_trusted_transition",
                    return_value=pr_monitor.ResumeOutcome(True, transient_error=True),
                ) as resume,
            ):
                for count in range(1, 4):
                    pr_monitor.poll_once(monitor_args, state, "token")
                    saved = json.loads(state.read_text())
                    self.assertEqual(count, saved["resume_retry_count"])
                    self.assertEqual(
                        count < pr_monitor.MAX_TRANSIENT_RESUME_RETRIES,
                        saved["resume_pending"],
                    )
                pr_monitor.poll_once(monitor_args, state, "token")
            self.assertEqual(3, resume.call_count)
            for call in resume.call_args_list:
                self.assertTrue(call.kwargs["poll_existing_only"])

    def test_transient_retry_requires_exact_existing_submission(self):
        monitor_args = args(
            owner="dst-red-Wire",
            repo="ecommerce-1",
            pr=169,
            trusted_root=Path("/trusted"),
            target_root=Path("/target"),
        )
        dispatch = {
            "status": "BLOCKED",
            "reason": "BLOCKED_EXTERNAL_REVIEW_TRANSPORT",
            "submission_id": "submission-1",
            "head_sha": "a" * 40,
            "pr": 169,
        }
        result = {
            "pr": 169,
            "head_sha": "a" * 40,
            "state": "CHATGPT_REVIEW_REQUIRED",
            "review_dispatch": dispatch,
        }
        with (
            mock.patch.object(
                pr_monitor,
                "_verified_resume_context",
                return_value=(
                    Path("/trusted"),
                    Path("/target"),
                    Path("/trusted/scripts/pr_review_dispatch_transition.py"),
                ),
            ),
            mock.patch.object(
                pr_monitor.subprocess,
                "run",
                return_value=mock.Mock(stdout=json.dumps(result), returncode=0),
            ) as runner,
        ):
            outcome = pr_monitor.resume_trusted_transition(
                monitor_args, poll_existing_only=True
            )
            self.assertEqual(pr_monitor.ResumeOutcome(True, True), outcome)
            self.assertIn("--poll-existing-only", runner.call_args.args[0])
            dispatch["submission_id"] = None
            runner.return_value.stdout = json.dumps(result)
            outcome = pr_monitor.resume_trusted_transition(
                monitor_args, poll_existing_only=True
            )
            self.assertEqual(pr_monitor.ResumeOutcome(False), outcome)

    def test_head_change_syncs_before_trusted_resume(self):
        old_head = "a" * 40
        new_head = "b" * 40
        previous = {
            "etag": "old",
            "head_sha": old_head,
            "state": "OPEN",
            "merged": False,
            "checks": {},
            "reviews": {},
            "open_findings": {},
        }
        current = {**previous, "head_sha": new_head, "etag": "new"}
        payload = {
            "data": {
                "repository": {"pullRequest": {"state": "OPEN", "headRefOid": new_head}}
            }
        }
        order = []
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps(previous))
            monitor_args = args(
                owner="dst-red-Wire",
                repo="ecommerce-1",
                pr=169,
                trusted_root=Path("/trusted"),
                target_root=Path("/target"),
            )
            with (
                mock.patch.object(pr_monitor, "ROOT", Path("/trusted")),
                mock.patch.object(
                    pr_monitor, "github_request", return_value=(200, payload, "new")
                ),
                mock.patch.object(pr_monitor, "snapshot", return_value=current),
                mock.patch.object(pr_monitor, "changed_files", return_value=["x.py"]),
                mock.patch.object(pr_monitor, "exact_head_worktree") as checkout,
                mock.patch.object(
                    pr_monitor,
                    "sync_exact_pr_head",
                    side_effect=lambda *_: order.append("sync"),
                ) as sync,
                mock.patch.object(
                    pr_monitor,
                    "resume_trusted_transition",
                    side_effect=lambda *_args, **_kwargs: (
                        order.append("resume"),
                        pr_monitor.ResumeOutcome(False),
                    )[1],
                ) as resume,
            ):
                checkout.return_value.__enter__.return_value = Path("/exact")
                checkout.return_value.__exit__.return_value = False
                pr_monitor.poll_once(monitor_args, state, "token")
            self.assertEqual(["sync", "resume"], order)
            sync.assert_called_once_with(monitor_args, new_head)
            resume.assert_called_once_with(monitor_args, poll_existing_only=False)

    def test_exact_head_sync_fast_forwards_only_clean_descendant(self):
        def git(root: Path, *arguments: str) -> str:
            result = subprocess.run(
                ["git", *arguments],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            return result.stdout.strip()

        with tempfile.TemporaryDirectory() as directory:
            origin = Path(directory) / "origin.git"
            checkout = Path(directory) / "checkout"
            trusted = Path(directory) / "trusted"
            subprocess.run(
                ["git", "init", "--bare", str(origin)],
                text=True,
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ["git", "init", "-b", "main", str(checkout)],
                text=True,
                capture_output=True,
                check=True,
            )
            git(checkout, "config", "user.email", "monitor-test@example.invalid")
            git(checkout, "config", "user.name", "Monitor Test")
            git(checkout, "remote", "add", "origin", str(origin))
            (checkout / "base.txt").write_text("base")
            git(checkout, "add", "base.txt")
            git(checkout, "-c", "commit.gpgsign=false", "commit", "-m", "base")
            base_sha = git(checkout, "rev-parse", "HEAD")
            git(checkout, "push", "origin", "main")
            subprocess.run(
                ["git", "clone", "--branch", "main", str(origin), str(trusted)],
                text=True,
                capture_output=True,
                check=True,
            )
            git(checkout, "checkout", "-b", "feature")
            (checkout / "feature.txt").write_text("old")
            git(checkout, "add", "feature.txt")
            git(checkout, "-c", "commit.gpgsign=false", "commit", "-m", "old")
            old_sha = git(checkout, "rev-parse", "HEAD")
            (checkout / "feature.txt").write_text("new")
            git(checkout, "add", "feature.txt")
            git(checkout, "-c", "commit.gpgsign=false", "commit", "-m", "new")
            new_sha = git(checkout, "rev-parse", "HEAD")
            git(checkout, "push", "origin", "feature")
            git(checkout, "reset", "--hard", old_sha)
            binding = ExactPRBinding(
                "dst-red-Wire/ecommerce-1", 169, "main", base_sha, "feature", new_sha
            )
            monitor_args = args(
                owner="dst-red-Wire",
                repo="ecommerce-1",
                pr=169,
                trusted_root=trusted,
                target_root=checkout,
            )
            with (
                mock.patch.object(pr_monitor, "ROOT", trusted),
                mock.patch.object(
                    pr_monitor,
                    "_trusted_adapter",
                    return_value=trusted / "scripts/pr_review_dispatch_transition.py",
                ),
                mock.patch.object(
                    pr_monitor,
                    "resolve_managed_gh",
                    return_value=("gh", "1.0.0", "digest"),
                ),
                mock.patch.object(
                    pr_monitor, "resolve_exact_open_pr", return_value=binding
                ),
                mock.patch.object(
                    pr_monitor, "revalidate_exact_open_pr", return_value=binding
                ) as revalidate,
            ):
                pr_monitor.sync_exact_pr_head(monitor_args, new_sha)
                self.assertEqual(new_sha, git(checkout, "rev-parse", "HEAD"))
                self.assertEqual(base_sha, git(trusted, "rev-parse", "HEAD"))
                self.assertEqual("", git(checkout, "status", "--porcelain"))
                self.assertGreaterEqual(revalidate.call_count, 3)
                git(checkout, "reset", "--hard", old_sha)
                (checkout / "feature.txt").write_text("diverged")
                git(checkout, "add", "feature.txt")
                git(checkout, "-c", "commit.gpgsign=false", "commit", "-m", "diverged")
                divergent_sha = git(checkout, "rev-parse", "HEAD")
                with self.assertRaisesRegex(
                    pr_monitor.SupersededHeadError, "SUPERSEDED"
                ):
                    pr_monitor.sync_exact_pr_head(monitor_args, new_sha)
                self.assertEqual(divergent_sha, git(checkout, "rev-parse", "HEAD"))

    def test_transient_http_failures_are_classified_for_retry(self):
        error = urllib.error.HTTPError(
            "https://api.github.com", 503, "unavailable", {}, None
        )
        error.read = mock.Mock(return_value=b"down")
        with (
            mock.patch("urllib.request.urlopen", side_effect=error),
            self.assertRaises(pr_monitor.TransientGitHubError),
        ):
            pr_monitor.github_request("https://api.github.com", "token")

    def test_malicious_target_adapter_is_never_selected_for_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted = root / "trusted"
            target = root / "target"
            (trusted / "scripts").mkdir(parents=True)
            (target / "scripts").mkdir(parents=True)
            safe_adapter = trusted / "scripts/pr_review_dispatch_transition.py"
            malicious_adapter = target / "scripts/pr_review_dispatch_transition.py"
            safe_adapter.write_text("raise SystemExit(0)\n")
            malicious_adapter.write_text('raise RuntimeError("stolen token")\n')
            monitor_args = args(
                owner="dst-red-Wire",
                repo="ecommerce-1",
                pr=169,
                trusted_root=trusted,
                target_root=target,
            )
            completed = mock.Mock(
                stdout=json.dumps({"pr": 169, "state": "MERGE_READY"}),
                returncode=0,
            )
            with (
                mock.patch.object(
                    pr_monitor,
                    "_verified_resume_context",
                    return_value=(trusted, target, safe_adapter),
                ),
                mock.patch.object(
                    pr_monitor.subprocess, "run", return_value=completed
                ) as runner,
            ):
                pr_monitor.resume_trusted_transition(monitor_args)
            command = runner.call_args.args[0]
            self.assertEqual(str(safe_adapter), command[4])
            self.assertNotIn(str(malicious_adapter), command)
            self.assertEqual(trusted, runner.call_args.kwargs["cwd"])
            self.assertEqual(["-I", "-c"], command[1:3])
            self.assertEqual(str(target), command[command.index("--target-root") + 1])

    def test_missing_base_adapter_blocks_without_target_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted = root / "trusted"
            target = root / "target"
            (trusted / "scripts").mkdir(parents=True)
            (target / "scripts").mkdir(parents=True)
            (trusted / "scripts/pr_monitor.py").write_bytes(
                Path(pr_monitor.__file__).read_bytes()
            )
            (target / "scripts/pr_review_dispatch_transition.py").write_text(
                'raise RuntimeError("malicious PR HEAD")\n'
            )
            subprocess.run(
                ["git", "init", "-b", "main", str(trusted)],
                capture_output=True,
                text=True,
                check=True,
            )
            for command in (
                ["git", "config", "user.email", "monitor-test@example.invalid"],
                ["git", "config", "user.name", "Monitor Test"],
                ["git", "add", "scripts/pr_monitor.py"],
                ["git", "-c", "commit.gpgsign=false", "commit", "-m", "trusted base"],
            ):
                subprocess.run(
                    command, cwd=trusted, capture_output=True, text=True, check=True
                )
            base_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=trusted,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            binding = ExactPRBinding(
                "dst-red-Wire/ecommerce-1",
                169,
                "main",
                base_sha,
                "feature",
                "a" * 40,
            )
            monitor_args = args(
                owner="dst-red-Wire",
                repo="ecommerce-1",
                pr=169,
                trusted_root=trusted,
                target_root=target,
            )
            with (
                mock.patch.object(pr_monitor, "ROOT", trusted),
                self.assertRaisesRegex(
                    RuntimeError, "trusted exact-base source is unavailable"
                ),
            ):
                pr_monitor._trusted_adapter(monitor_args, binding)
            with (
                mock.patch.object(
                    pr_monitor,
                    "_verified_resume_context",
                    side_effect=RuntimeError(
                        "trusted exact-base source is unavailable"
                    ),
                ),
                mock.patch.object(pr_monitor.subprocess, "run") as runner,
                self.assertRaises(RuntimeError),
            ):
                pr_monitor.resume_trusted_transition(monitor_args)
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
