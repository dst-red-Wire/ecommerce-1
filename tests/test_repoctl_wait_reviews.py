import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest import mock
import urllib.error
import urllib.parse


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
    def __init__(self, head=SHA, reviews=None, comments=None, error=None):
        self.head, self.reviews, self.comments, self.error = head, reviews or [], comments or [], error
        self.calls = []

    def get(self, path):
        self.calls.append(("GET", path))
        if self.error:
            raise self.error
        return {"head": {"sha": self.head}}

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

    def test_api_error_exits_five(self):
        code, out, _ = self.invoke(FakeReader(error=REPOCTL.GitHubAPIError("safe failure")))
        self.assertEqual(5, code)
        self.assertIn("API_FAILURE", out)

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

            def opener(req):
                calls.append(req)
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

            def opener(req):
                captured.append(req)
                return Response({})

            REPOCTL.GitHubReader(token, opener).get("/repos/o/r")
        self.assertIsNone(captured[0].get_header("Authorization"))
        self.assertEqual("Bearer highly-secret-token", captured[1].get_header("Authorization"))
        error = urllib.error.HTTPError("https://api.github.com/x", 403, "forbidden", {}, None)
        with self.assertRaisesRegex(REPOCTL.GitHubAPIError, "authentication/authorization") as raised:
            REPOCTL.GitHubReader("highly-secret-token", lambda _req: (_ for _ in ()).throw(error)).get("/x")
        self.assertNotIn("highly-secret-token", str(raised.exception))

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
