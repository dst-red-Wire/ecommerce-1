import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import socket


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_wait_reviews", ROOT / "scripts/repoctl.py")
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)
SHA = "a" * 40
STALE = "b" * 40


def review(kind="code", sha=SHA, event_id=20, timestamp="2026-01-01T00:02:00Z"):
    marker = "Codex Review" if kind == "code" else "Codex Security Review"
    return {
        "id": event_id,
        "submitted_at": timestamp,
        "commit_id": sha if kind == "code" else None,
        "user": {"login": "chatgpt-codex-connector[bot]"},
        "body": f"### {marker}\n\n**Reviewed commit:** `{sha[:10]}`",
    }


def request(kind="code", event_id=10, timestamp="2026-01-01T00:01:00Z"):
    command = "@codex review" if kind == "code" else "@codex security review"
    return {"id": event_id, "created_at": timestamp, "user": {"login": "owner"}, "body": command}


class FakeReader:
    def __init__(self, head=SHA, reviews=None, comments=None, error=None, heads=None):
        self.head, self.reviews, self.comments, self.error = head, reviews or [], comments or [], error
        self.heads = iter(heads) if heads is not None else None
        self.calls = []

    def get(self, path):
        self.calls.append(("GET", path))
        if self.error:
            raise self.error
        return {"head": {"sha": next(self.heads) if self.heads is not None else self.head}}

    def pages(self, path):
        self.calls.append(("GET", path))
        return self.reviews if path.endswith("/reviews") else self.comments


class Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return io.BytesIO(json.dumps(self.payload).encode())

    def __exit__(self, *_args):
        return False


class WaitReviewsTests(unittest.TestCase):
    def invoke(self, reader, **overrides):
        args = dict(
            repo="dst-red-Wire/ecommerce-1",
            pr=77,
            expected_sha=SHA,
            interval=1,
            max_attempts=1,
            json_mode=False,
            reader=reader,
            sleeper=lambda _seconds: None,
        )
        args.update(overrides)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            code = REPOCTL.wait_reviews_command(**args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_invalid_inputs_exit_four(self):
        cases = [
            {"expected_sha": "abc"},
            {"expected_sha": "z" * 40},
            {"repo": "owner"},
            {"pr": 0},
            {"interval": 0},
            {"max_attempts": 0},
        ]
        for values in cases:
            with self.subTest(values=values):
                self.assertEqual(4, self.invoke(FakeReader(), **values)[0])

    def test_json_invalid_inputs_emit_one_document(self):
        for values in ({"repo": "owner"}, {"expected_sha": "abc"}, {"interval": 0}, {"max_attempts": 0}):
            with self.subTest(values=values):
                code, out, err = self.invoke(FakeReader(), json_mode=True, **values)
                self.assertEqual(4, code)
                document = json.loads(out)
                self.assertEqual("INVALID_INPUT", document["result"])
                self.assertEqual(0, document["attempt"])
                self.assertIn("INVALID_INPUT", err)

    def test_head_movement_exits_two_before_collections(self):
        reader = FakeReader(head=STALE)
        code, out, _ = self.invoke(reader)
        self.assertEqual(2, code)
        self.assertIn("HEAD_MOVED", out)
        self.assertEqual(1, len(reader.calls))

    def test_individual_states(self):
        cases = [
            ([], [], ("NOT_REQUESTED", "NOT_REQUESTED")),
            ([], [request("code")], ("REQUESTED_OR_RUNNING", "NOT_REQUESTED")),
            ([], [request("security")], ("NOT_REQUESTED", "REQUESTED_OR_RUNNING")),
            ([review("code", STALE)], [], ("STALE_SHA", "NOT_REQUESTED")),
            ([], [review("security", STALE)], ("NOT_REQUESTED", "STALE_SHA")),
            ([review("code")], [], ("COMPLETED", "NOT_REQUESTED")),
            ([], [review("security")], ("NOT_REQUESTED", "COMPLETED")),
            ([review("code", STALE)], [review("security")], ("STALE_SHA", "COMPLETED")),
        ]
        for reviews, comments, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(expected, REPOCTL.codex_review_states(reviews, comments, SHA))

    def test_both_reviews_on_expected_sha_succeed(self):
        reader = FakeReader(reviews=[review("code")], comments=[review("security")])
        code, out, _ = self.invoke(reader)
        self.assertEqual(0, code)
        self.assertIn("same_sha=YES", out)
        self.assertEqual(4, len(reader.calls))

    def test_final_head_movement_rejects_collected_reviews(self):
        reader = FakeReader(heads=[SHA, STALE], reviews=[review("code")], comments=[review("security")])
        code, out, _ = self.invoke(reader)
        self.assertEqual(2, code)
        self.assertIn("HEAD_MOVED", out)
        self.assertNotIn("REVIEWS_COMPLETE", out)

    def test_final_head_confirmation_allows_success(self):
        reader = FakeReader(heads=[SHA, SHA], reviews=[review("code")], comments=[review("security")])
        self.assertEqual(0, self.invoke(reader)[0])

    def test_reviews_on_different_shas_never_succeed(self):
        reader = FakeReader(reviews=[review("code")], comments=[review("security", STALE)])
        code, out, _ = self.invoke(reader)
        self.assertEqual(3, code)
        self.assertIn("security=STALE_SHA", out)

    def test_new_request_after_stale_review_is_running(self):
        stale = review("code", STALE, 10, "2026-01-01T00:01:00Z")
        newer = request("code", 20, "2026-01-01T00:02:00Z")
        self.assertEqual("REQUESTED_OR_RUNNING", REPOCTL.codex_review_states([stale], [newer], SHA)[0])

    def test_old_request_before_stale_review_remains_stale(self):
        stale = review("code", STALE, 20, "2026-01-01T00:02:00Z")
        older = request("code", 10, "2026-01-01T00:01:00Z")
        self.assertEqual("STALE_SHA", REPOCTL.codex_review_states([stale], [older], SHA)[0])

    def test_exact_completion_precedes_newer_other_sha_completion(self):
        exact = review("code", SHA, 10, "2026-01-01T00:01:00Z")
        newer_stale = review("code", STALE, 20, "2026-01-01T00:02:00Z")
        self.assertEqual("COMPLETED", REPOCTL.codex_review_states([exact, newer_stale], [], SHA)[0])

    def test_exact_completion_is_not_downgraded_by_later_request(self):
        exact = review("code", SHA, 10, "2026-01-01T00:01:00Z")
        newer = request("code", 20, "2026-01-01T00:02:00Z")
        self.assertEqual("COMPLETED", REPOCTL.codex_review_states([exact], [newer], SHA)[0])

    def test_malformed_users_are_ignored_without_hiding_valid_history(self):
        malformed = []
        for user in (None, {}, "deleted-user", {"login": None}):
            item = review("code", SHA)
            item["user"] = user
            malformed.append(item)
        valid = review("code", SHA, 30)
        comment = review("security", SHA)
        comment["user"] = None
        self.assertEqual(("COMPLETED", "NOT_REQUESTED"), REPOCTL.codex_review_states(malformed + [valid], [comment], SHA))

    def test_command_matching_is_bounded(self):
        self.assertEqual("code", REPOCTL._request_kind("  @codex review please  "))
        self.assertEqual("security", REPOCTL._request_kind("@codex security review"))
        self.assertIsNone(REPOCTL._request_kind("> @codex review"))
        self.assertIsNone(REPOCTL._request_kind("documentation says @codex review"))

    def test_timeout_exits_three_and_does_not_sleep_after_last_attempt(self):
        sleeps = []
        reader = FakeReader()
        code, out, _ = self.invoke(reader, max_attempts=2, sleeper=sleeps.append)
        self.assertEqual(3, code)
        self.assertIn("Automatic retrigger: FORBIDDEN", out)
        self.assertEqual([1], sleeps)

    def test_interruption_is_clean_and_does_not_retrigger(self):
        reader = FakeReader()
        code, out, _ = self.invoke(
            reader,
            max_attempts=2,
            sleeper=lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
        self.assertEqual(130, code)
        self.assertTrue(out.endswith("INTERRUPTED\nAutomatic retrigger: FORBIDDEN\n"))
        self.assertTrue(all(method == "GET" for method, _ in reader.calls))

    def test_sigterm_uses_interruption_path_and_restores_handler(self):
        handlers = []

        def fake_signal(signum, handler):
            handlers.append((signum, handler))

        with (
            mock.patch.object(REPOCTL.signal, "getsignal", return_value="previous"),
            mock.patch.object(REPOCTL.signal, "signal", side_effect=fake_signal),
            mock.patch.object(REPOCTL, "wait_reviews_command", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            REPOCTL.wait_reviews_with_signals("repo", 1, SHA, 1, 1, False)
        self.assertEqual(REPOCTL.signal.SIGTERM, handlers[0][0])
        self.assertEqual((REPOCTL.signal.SIGTERM, "previous"), handlers[-1])

    def test_api_error_exits_five(self):
        code, out, _ = self.invoke(FakeReader(error=REPOCTL.GitHubAPIError("safe failure")))
        self.assertEqual(5, code)
        self.assertIn("API_FAILURE", out)

    def test_socket_and_url_timeouts_are_sanitized_api_failures(self):
        for error in (socket.timeout("secret timeout"), urllib.error.URLError(socket.timeout("secret timeout"))):
            with self.subTest(error=type(error).__name__):
                reader = REPOCTL.GitHubReader("token", lambda _req, timeout: (_ for _ in ()).throw(error))
                code, out, _ = self.invoke(reader)
                self.assertEqual(5, code)
                self.assertIn("API_FAILURE", out)
                self.assertNotIn("secret", out)

    def test_json_timeout_error_is_one_api_failure_document(self):
        reader = REPOCTL.GitHubReader("token", lambda _req, timeout: (_ for _ in ()).throw(socket.timeout()))
        code, out, err = self.invoke(reader, json_mode=True)
        self.assertEqual(5, code)
        self.assertEqual("API_FAILURE", json.loads(out)["result"])
        self.assertIn("GitHub API request failed", err)

    def test_json_success_is_one_document_and_progress_is_stderr(self):
        reader = FakeReader(reviews=[review("code")], comments=[review("security")])
        code, out, err = self.invoke(reader, json_mode=True)
        self.assertEqual(0, code)
        self.assertEqual("REVIEWS_COMPLETE", json.loads(out)["result"])
        self.assertIn("attempt=1", err)

    def test_json_timeout_is_one_document(self):
        code, out, err = self.invoke(FakeReader(), json_mode=True)
        self.assertEqual(3, code)
        self.assertEqual("TIMEOUT", json.loads(out)["result"])
        self.assertNotIn("TIMEOUT", err)

    def test_unpaginated_iteration_fetches_each_endpoint_once_and_get_only(self):
        reader = FakeReader()
        self.invoke(reader)
        self.assertEqual(3, len(reader.calls))
        self.assertTrue(all(method == "GET" for method, _ in reader.calls))
        self.assertEqual(3, len({path for _, path in reader.calls}))

    def test_reviews_and_comments_paginate(self):
        for collection in ("reviews", "comments"):
            calls = []

            def opener(req, timeout):
                calls.append(req)
                self.assertEqual(REPOCTL.GITHUB_HTTP_TIMEOUT_SECONDS, timeout)
                page = urllib.parse.parse_qs(urllib.parse.urlsplit(req.full_url).query)["page"][0]
                return Response([{}] * 100 if page == "1" else [{}])

            reader = REPOCTL.GitHubReader(opener=opener)
            items = reader.pages(f"/repos/o/r/{collection}")
            self.assertEqual(101, len(items))
            self.assertEqual(2, len(calls))
            self.assertTrue(all(req.get_method() == "GET" for req in calls))

    def test_auth_headers_and_token_redaction(self):
        captured = []
        for token in (None, "highly-secret-token"):

            def opener(req, timeout):
                captured.append(req)
                self.assertEqual(REPOCTL.GITHUB_HTTP_TIMEOUT_SECONDS, timeout)
                return Response({})

            REPOCTL.GitHubReader(token, opener).get("/repos/o/r")
        self.assertIsNone(captured[0].get_header("Authorization"))
        self.assertEqual("Bearer highly-secret-token", captured[1].get_header("Authorization"))
        error = urllib.error.HTTPError("https://api.github.com/x", 403, "forbidden", {}, None)
        with self.assertRaisesRegex(REPOCTL.GitHubAPIError, "authentication/authorization") as raised:
            REPOCTL.GitHubReader("highly-secret-token", lambda _req, timeout: (_ for _ in ()).throw(error)).get("/x")
        self.assertNotIn("highly-secret-token", str(raised.exception))

    def test_unauthenticated_attempt_policy_rejects_unsafe_before_api_call(self):
        reader = FakeReader()
        with mock.patch.dict(REPOCTL.os.environ, {}, clear=True):
            code, _, err = self.invoke(reader, max_attempts=40)
        self.assertEqual(4, code)
        self.assertIn("provide GH_TOKEN/GITHUB_TOKEN", err)
        self.assertEqual([], reader.calls)

    def test_unauthenticated_safe_limit_and_authenticated_defaults(self):
        with mock.patch.dict(REPOCTL.os.environ, {}, clear=True):
            self.assertEqual(3, self.invoke(FakeReader(), max_attempts=REPOCTL.GITHUB_UNAUTHENTICATED_MAX_ATTEMPTS)[0])
        with mock.patch.dict(REPOCTL.os.environ, {"GH_TOKEN": "token"}, clear=True):
            self.assertEqual(3, self.invoke(FakeReader(), max_attempts=40)[0])

    def test_unauthenticated_reader_budget_is_bounded_with_margin(self):
        calls = []
        reader = REPOCTL.GitHubReader(opener=lambda req, timeout: calls.append(req) or Response({}))
        for _ in range(REPOCTL.GITHUB_UNAUTHENTICATED_REQUEST_BUDGET):
            reader.get("/x")
        with self.assertRaisesRegex(REPOCTL.GitHubAPIError, "budget exhausted"):
            reader.get("/x")
        self.assertEqual(REPOCTL.GITHUB_UNAUTHENTICATED_REQUEST_BUDGET, len(calls))

    def test_reader_has_no_mutating_interface_or_retrigger_payload(self):
        for method in ("post", "put", "patch", "delete"):
            self.assertFalse(hasattr(REPOCTL.GitHubReader, method))
        source = (ROOT / "scripts/repoctl.py").read_text()
        self.assertNotIn('method="POST"', source)
        self.assertNotIn('method="PATCH"', source)
        self.assertNotIn('method="PUT"', source)
        self.assertNotIn('method="DELETE"', source)


if __name__ == "__main__":
    unittest.main()
