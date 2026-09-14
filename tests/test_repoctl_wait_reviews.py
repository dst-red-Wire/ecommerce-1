import importlib.util
import http.client
import io
import json
from pathlib import Path
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import socket
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_wait_reviews", ROOT / "scripts/repoctl.py")
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)
SHA = "a" * 40
STALE = "b" * 40


def review(kind="code", sha=SHA, event_id=20, timestamp="2026-01-01T00:02:00Z", body_sha=None):
    marker = "💡 Codex Review" if kind == "code" else "🛡️ Codex Security Review"
    identity = body_sha if body_sha is not None else sha
    metadata = (
        ""
        if kind == "code"
        else '<!-- codex-security-review:v1 {"headSha":"' + identity + '","status":"completed"} -->\n'
    )
    return {
        "id": event_id,
        "submitted_at": timestamp,
        "commit_id": sha if kind == "code" else None,
        "user": {"login": "chatgpt-codex-connector[bot]"},
        "body": f"{metadata}### {marker}\n\n**Reviewed commit:** `{identity}`",
    }


def request(kind="code", event_id=10, timestamp="2026-01-01T00:01:00Z"):
    command = "@codex review" if kind == "code" else "@codex security review"
    return {"id": event_id, "created_at": timestamp, "user": {"login": "owner"}, "body": command}


def summary(sha=SHA, repo="dst-red-Wire/ecommerce-1", pr=77, code_status="Completed", short_sha=None):
    short_sha = short_sha if short_sha is not None else sha[:7]
    body = (
        '<!-- codex-pull-request-review-summary -->\n'
        '<!-- codex-security-review:v1 {"headSha":"' + sha + '","repository":"' + repo
        + '","pullRequestNumber":' + str(pr) + ',"status":"completed"} -->\n'
        "## Codex Review Summary\n\n"
        "| Review | Status | Commit | Review trigger |\n"
        "| --- | --- | --- | --- |\n"
        f"| 📝 **Code Review** | ✅ **{code_status}** | `{short_sha}` | Manual request |\n"
        f"| 🔒 **Security Review** | ✅ **Completed** | `{sha[:7]}` | Manual request |\n"
    )
    return {"id": 30, "created_at": "2026-01-01T00:03:00Z", "user": {"login": "chatgpt-codex-connector"}, "body": body}


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


class TruncatedResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, *_args):
        raise http.client.IncompleteRead(b"partial", 100)


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

    def invoke_cli(self, *arguments, env=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["repoctl.py", "wait-reviews", *arguments]
        with (
            mock.patch.object(REPOCTL.sys, "argv", argv),
            mock.patch.dict(REPOCTL.os.environ, env or {}, clear=True),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            code = REPOCTL.main()
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

    def test_parser_level_invalid_inputs_use_wait_reviews_contract(self):
        base = ["--repo", "dst-red-Wire/ecommerce-1", "--pr", "77", "--sha", SHA, "--max-attempts", "1"]
        for option, value in (("--pr", "nope"), ("--interval", "nope"), ("--max-attempts", "nope")):
            arguments = base.copy()
            if option in arguments:
                arguments[arguments.index(option) + 1] = value
            else:
                arguments.extend((option, value))
            with self.subTest(option=option, json_mode=True):
                code, out, err = self.invoke_cli(*arguments, "--json")
                self.assertEqual(4, code)
                self.assertEqual("INVALID_INPUT", json.loads(out)["result"])
                self.assertNotIn("usage:", err)
            with self.subTest(option=option, json_mode=False):
                code, out, err = self.invoke_cli(*arguments)
                self.assertEqual(4, code)
                self.assertEqual("", out)
                self.assertIn("INVALID_INPUT", err)
                self.assertNotIn("usage:", err)

    def test_missing_required_options_use_wait_reviews_contract(self):
        values = {"--repo": "dst-red-Wire/ecommerce-1", "--pr": "77", "--sha": SHA}
        for missing in (("--repo",), ("--pr",), ("--sha",), tuple(values)):
            arguments = [part for option, value in values.items() if option not in missing for part in (option, value)]
            with self.subTest(missing=missing, json_mode=True):
                code, out, err = self.invoke_cli(*arguments, "--max-attempts", "1", "--json")
                self.assertEqual(4, code)
                self.assertEqual("INVALID_INPUT", json.loads(out)["result"])
                self.assertNotIn("usage:", err)
            if len(missing) == 1:
                with self.subTest(missing=missing, json_mode=False):
                    code, out, err = self.invoke_cli(*arguments, "--max-attempts", "1")
                    self.assertEqual(4, code)
                    self.assertEqual("", out)
                    self.assertIn("INVALID_INPUT", err)
                    self.assertNotIn("usage:", err)

    def test_complete_json_invalid_input_parser_matrix(self):
        valid = ["--repo", "dst-red-Wire/ecommerce-1", "--pr", "77", "--sha", SHA, "--max-attempts", "1"]
        cases = {
            "missing_repo": ["--pr", "77", "--sha", SHA, "--max-attempts", "1"],
            "missing_pr": ["--repo", "dst-red-Wire/ecommerce-1", "--sha", SHA, "--max-attempts", "1"],
            "missing_sha": ["--repo", "dst-red-Wire/ecommerce-1", "--pr", "77", "--max-attempts", "1"],
            "repo_without_value": ["--repo"],
            "pr_without_value": ["--pr"],
            "sha_without_value": ["--sha"],
            "interval_without_value": [*valid, "--interval"],
            "attempts_without_value": [*valid, "--max-attempts"],
            "malformed_pr": [*valid[:3], "nope", *valid[4:]],
            "malformed_interval": [*valid, "--interval", "nope"],
            "malformed_attempts": [*valid[:-1], "nope"],
            "nan_interval": [*valid, "--interval", "nan"],
            "inf_interval": [*valid, "--interval", "inf"],
            "negative_inf_interval": [*valid, "--interval", "-inf"],
            "bad_repo": ["--repo", "bad repo", *valid[2:]],
            "short_sha": [*valid[:5], "abc", *valid[6:]],
            "non_hex_sha": [*valid[:5], "z" * 40, *valid[6:]],
            "unknown_option": [*valid, "--does-not-exist", "value"],
            "positional": [*valid, "unexpected"],
            "duplicate_repo": [*valid, "--repo", "other/repo"],
            "duplicate_pr": [*valid, "--pr", "78"],
            "duplicate_sha": [*valid, "--sha", STALE],
            "duplicate_interval": [*valid, "--interval", "1", "--interval", "2"],
            "duplicate_attempts": [*valid, "--max-attempts", "2"],
            "empty_repo": ["--repo=", *valid[2:]],
            "empty_pr": [valid[0], valid[1], "--pr=", *valid[4:]],
            "empty_sha": [*valid[:4], "--sha=", *valid[6:]],
        }
        for name, arguments in cases.items():
            with self.subTest(name=name):
                code, out, err = self.invoke_cli(*arguments, "--json")
                self.assertEqual(4, code)
                self.assertEqual(1, len(out.strip().splitlines()))
                self.assertEqual("INVALID_INPUT", json.loads(out)["result"])
                self.assertNotIn("usage:", err.lower())
                self.assertNotIn("Traceback", out + err)

    def test_real_subprocess_parser_errors_use_json_contract(self):
        cases = (["--repo"], ["--pr"], ["--sha"], ["--unknown", "foo"], ["unexpected"])
        for arguments in cases:
            with self.subTest(arguments=arguments):
                completed = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/repoctl.py"), "wait-reviews", "--json", *arguments],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(4, completed.returncode)
                self.assertEqual(1, len(completed.stdout.strip().splitlines()))
                self.assertEqual("INVALID_INPUT", json.loads(completed.stdout)["result"])
                self.assertNotIn("usage:", completed.stderr.lower())

    def test_long_option_abbreviations_are_rejected(self):
        json_cases = (("--r", "bad"), ("--sh", "bad"), ("--int", "1"), ("--max-a", "2"))
        for arguments in json_cases:
            with self.subTest(arguments=arguments):
                code, out, err = self.invoke_cli("--json", *arguments)
                self.assertEqual(4, code)
                self.assertEqual(1, len(out.strip().splitlines()))
                self.assertEqual("INVALID_INPUT", json.loads(out)["result"])
                self.assertIn("unrecognized arguments:", err)
                self.assertNotIn("usage:", err.lower())
                self.assertNotIn("Traceback", out + err)

        code, out, err = self.invoke_cli("--j", "--repo", "bad")
        self.assertEqual(4, code)
        self.assertEqual("", out)
        self.assertIn("INVALID_INPUT", err)
        self.assertIn("unrecognized arguments:", err)
        self.assertNotIn("usage:", err.lower())
        self.assertNotIn("Traceback", err)

    def test_exact_long_options_continue_to_parse(self):
        arguments = (
            "--json", "--repo", "dst-red-Wire/ecommerce-1", "--pr", "77", "--sha", SHA,
            "--interval", "1", "--max-attempts", "1",
        )
        with mock.patch.object(REPOCTL, "wait_reviews_with_signals", return_value=0) as wait_reviews:
            code, out, err = self.invoke_cli(*arguments)
        self.assertEqual(0, code)
        self.assertEqual("", out)
        self.assertEqual("", err)
        wait_reviews.assert_called_once_with("dst-red-Wire/ecommerce-1", "77", SHA, "1", "1", True)

    def test_non_finite_intervals_are_invalid(self):
        for interval in ("nan", "+nan", "-nan", "inf", "+inf", "-inf", "Infinity"):
            with self.subTest(interval=interval):
                code, out, _ = self.invoke(FakeReader(), interval=interval, json_mode=True)
                self.assertEqual(4, code)
                self.assertEqual("INVALID_INPUT", json.loads(out)["result"])
        self.assertEqual(3, self.invoke(FakeReader(), interval="0.25")[0])

    def test_polling_interval_bound_accepts_operational_values(self):
        for interval in ("0.25", "75", str(REPOCTL.MAX_WAIT_REVIEWS_INTERVAL_SECONDS)):
            with self.subTest(interval=interval):
                self.assertEqual(3, self.invoke(FakeReader(), interval=interval)[0])

    def test_polling_interval_bound_rejects_before_api_or_sleep(self):
        for interval in (0, -1, REPOCTL.MAX_WAIT_REVIEWS_INTERVAL_SECONDS + 0.01, "1e100"):
            reader = FakeReader()
            sleeps = []
            with self.subTest(interval=interval):
                code, out, err = self.invoke(reader, interval=interval, json_mode=True, sleeper=sleeps.append)
                self.assertEqual(4, code)
                self.assertEqual(1, len(out.strip().splitlines()))
                self.assertEqual("INVALID_INPUT", json.loads(out)["result"])
                self.assertNotIn("Traceback", out + err)
                self.assertEqual([], reader.calls)
                self.assertEqual([], sleeps)
        code, out, err = self.invoke(FakeReader(), interval="1e100")
        self.assertEqual(4, code)
        self.assertEqual("", out)
        self.assertIn("INVALID_INPUT", err)
        self.assertNotIn("usage:", err.lower())

    def test_sleep_domain_errors_use_invalid_input_contract(self):
        for error in (OverflowError(), ValueError()):
            with self.subTest(error=type(error).__name__):
                code, out, err = self.invoke(
                    FakeReader(), max_attempts=2, json_mode=True,
                    sleeper=lambda _seconds, error=error: (_ for _ in ()).throw(error),
                )
                self.assertEqual(4, code)
                self.assertEqual("INVALID_INPUT", json.loads(out)["result"])
                self.assertNotIn("Traceback", out + err)

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
        self.assertEqual(
            [
                ("GET", "/repos/dst-red-Wire/ecommerce-1/pulls/77"),
                ("GET", "/repos/dst-red-Wire/ecommerce-1/pulls/77/reviews"),
                ("GET", "/repos/dst-red-Wire/ecommerce-1/issues/77/comments"),
                ("GET", "/repos/dst-red-Wire/ecommerce-1/pulls/77"),
            ],
            reader.calls,
        )

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

    def test_only_full_sha_identity_can_complete_a_review(self):
        for length in (7, 10, 12, 39):
            with self.subTest(kind="code", length=length):
                item = review("code", SHA, body_sha=SHA[:length])
                item["commit_id"] = None
                self.assertNotEqual("COMPLETED", REPOCTL.codex_review_states([item], [], SHA)[0])
            with self.subTest(kind="security", length=length):
                item = review("security", SHA, body_sha=SHA[:length])
                self.assertNotEqual("COMPLETED", REPOCTL.codex_review_states([], [item], SHA)[1])

    def test_shared_prefix_abbreviation_never_validates_another_sha(self):
        old_sha = "aaaaaaaaaa" + "b" * 30
        new_sha = "aaaaaaaaaa" + "c" * 30
        stale = review("security", old_sha, body_sha=old_sha[:10])
        self.assertNotEqual("COMPLETED", REPOCTL.codex_review_states([], [stale], new_sha)[1])

    def test_authoritative_commit_id_wins_over_abbreviated_body(self):
        item = review("code", SHA, body_sha=SHA[:10])
        self.assertEqual("COMPLETED", REPOCTL.codex_review_states([item], [], SHA)[0])

    def test_completed_security_metadata_supplies_full_sha_identity(self):
        body = (
            '<!-- codex-security-review:v1 {"headSha":"' + SHA + '","status":"completed"} -->\n'
            "### Codex Security Review"
        )
        item = {"id": 20, "created_at": "2026-01-01T00:02:00Z", "user": {"login": "chatgpt-codex-connector[bot]"}, "body": body}
        self.assertEqual("COMPLETED", REPOCTL.codex_review_states([], [item], SHA)[1])

    def test_review_types_are_structurally_distinct_and_mutually_exclusive(self):
        code = review("code")
        code["body"] += "\nDiscussion: Codex Security Review and ### 🛡️ Codex Security Review are not evidence."
        self.assertEqual(("COMPLETED", "NOT_REQUESTED"), REPOCTL.codex_review_states([code], [], SHA))

        security = review("security")
        self.assertEqual(("NOT_REQUESTED", "COMPLETED"), REPOCTL.codex_review_states([], [security], SHA))
        evidence = REPOCTL._classify_review_event(code, "review", "dst-red-Wire/ecommerce-1", 77)
        self.assertEqual("CODE", evidence[0])
        self.assertNotEqual("SECURITY", evidence[0])

    def test_real_codex_review_body_shape_is_code_only(self):
        bodies = (
            "\n### 💡 Codex Review\n\nHere are some automated review suggestions...",
            "\r\n### 💡 Codex Review\r\nHere are some automated review suggestions...",
            "\n\n\n### 💡 Codex Review\nHere are some automated review suggestions...",
            "   \n\t\n### 💡 Codex Review\nHere are some automated review suggestions...",
        )
        for body in bodies:
            item = review("code")
            item["body"] = body
            with self.subTest(body=repr(body)):
                self.assertEqual("CODE", REPOCTL._classify_review_event(item, "review", "dst-red-Wire/ecommerce-1", 77)[0])
                self.assertEqual(("COMPLETED", "NOT_REQUESTED"), REPOCTL.codex_review_states([item], [], SHA))

    def test_first_meaningful_line_remains_an_exact_identity(self):
        rejected = (
            "Some prose\n### 💡 Codex Review",
            "> ### 💡 Codex Review",
            "discussion of ### 💡 Codex Review",
            "### 💡 Codex Review extra",
            "prefix ### 💡 Codex Review",
        )
        for body in rejected:
            item = review("code")
            item["body"] = body
            with self.subTest(body=body):
                self.assertEqual("OTHER", REPOCTL._classify_review_event(item, "review", "", None)[0])
        for body in (None, 123, {}, "", " \t\n\r\n"):
            item = review("code")
            item["body"] = body
            with self.subTest(body=body):
                self.assertEqual("OTHER", REPOCTL._classify_review_event(item, "review", "", None)[0])

    def test_real_shaped_code_and_structured_security_complete_together(self):
        code = review("code")
        code["body"] = "\n### 💡 Codex Review\n\nHere are some automated review suggestions..."
        security = review("security")
        self.assertEqual(("COMPLETED", "COMPLETED"), REPOCTL.codex_review_states([code], [security], SHA))

    def test_no_submission_canonical_summary_completes_both_reviews(self):
        item = summary()
        self.assertEqual(
            ("COMPLETED", "COMPLETED"),
            REPOCTL.codex_review_states([], [item], SHA, "dst-red-Wire/ecommerce-1", 77),
        )
        reader = FakeReader(comments=[item])
        code, out, _ = self.invoke(reader)
        self.assertEqual(0, code)
        self.assertIn("REVIEWS_COMPLETE", out)

    def test_summary_code_completion_fails_closed_for_spoofing_and_structure(self):
        mutations = []
        wrong_author = summary()
        wrong_author["user"] = {"login": "pull-request-author"}
        mutations.append(wrong_author)
        missing_marker = summary()
        missing_marker["body"] = missing_marker["body"].replace(REPOCTL.REVIEW_SUMMARY_MARKER + "\n", "")
        mutations.append(missing_marker)
        prose = summary()
        prose["body"] = prose["body"].replace(REPOCTL.REVIEW_SUMMARY_MARKER, "Codex Review Summary")
        mutations.append(prose)
        duplicate_marker = summary()
        duplicate_marker["body"] += REPOCTL.REVIEW_SUMMARY_MARKER + "\n"
        mutations.append(duplicate_marker)
        missing_row = summary()
        missing_row["body"] = "\n".join(line for line in missing_row["body"].splitlines() if "Code Review**" not in line)
        mutations.append(missing_row)
        duplicate_row = summary()
        duplicate_row["body"] = duplicate_row["body"].replace(
            "| 🔒 **Security Review**", "| 📝 **Code Review**"
        )
        mutations.append(duplicate_row)
        ambiguous_table = summary()
        ambiguous_table["body"] += "\n| Review | Status | Commit | Review trigger |\n| --- | --- | --- | --- |\n"
        mutations.append(ambiguous_table)
        for item in mutations:
            with self.subTest(body=item["body"]):
                states = REPOCTL.codex_review_states([], [item], SHA, "dst-red-Wire/ecommerce-1", 77)
                self.assertNotEqual("COMPLETED", states[0])

    def test_summary_code_completion_requires_exact_structured_anchor(self):
        items = [
            summary(STALE),
            summary(repo="other/repo"),
            summary(pr=78),
            summary(short_sha="bbbbbbb"),
            summary(code_status="Running"),
            summary(code_status="Unknown"),
        ]
        for length in (7, 10, 12, 39):
            items.append(summary(SHA[:length]))
        items.append(summary("z" * 40))
        malformed = summary()
        malformed["body"] = malformed["body"].replace('"headSha":"' + SHA + '"', '"headSha":')
        items.append(malformed)
        missing_sha = summary()
        missing_sha["body"] = missing_sha["body"].replace('"headSha":"' + SHA + '",', "")
        items.append(missing_sha)
        missing_repo = summary()
        missing_repo["body"] = missing_repo["body"].replace('"repository":"dst-red-Wire/ecommerce-1",', "")
        items.append(missing_repo)
        missing_pr = summary()
        missing_pr["body"] = missing_pr["body"].replace('"pullRequestNumber":77,', "")
        items.append(missing_pr)
        duplicate_metadata = summary()
        duplicate_metadata["body"] += '<!-- codex-security-review:v1 {"headSha":"' + STALE + '","status":"completed"} -->\n'
        items.append(duplicate_metadata)
        for item in items:
            with self.subTest(body=item["body"]):
                self.assertNotEqual(
                    "COMPLETED",
                    REPOCTL.codex_review_states([], [item], SHA, "dst-red-Wire/ecommerce-1", 77)[0],
                )

    def test_running_summary_preserves_request_state(self):
        self.assertEqual(
            "REQUESTED_OR_RUNNING",
            REPOCTL.codex_review_states(
                [], [request("code"), summary(code_status="Running")], SHA, "dst-red-Wire/ecommerce-1", 77
            )[0],
        )

    def test_ambiguous_event_fails_closed(self):
        ambiguous = review("code")
        ambiguous["body"] += '\n<!-- codex-security-review:v1 {"headSha":"' + SHA + '","status":"completed"} -->'
        self.assertEqual(("NOT_REQUESTED", "NOT_REQUESTED"), REPOCTL.codex_review_states([ambiguous], [], SHA))

    def test_security_metadata_rejects_untrusted_or_wrong_identity(self):
        payloads = (
            "not-json",
            '{"headSha":"' + SHA[:39] + '","status":"completed"}',
            '{"headSha":"' + STALE + '","status":"completed"}',
            '{"headSha":"' + SHA + '","status":"unknown"}',
            '{"headSha":"' + SHA + '","status":"completed","repository":"other/repo"}',
            '{"headSha":"' + SHA + '","status":"completed","pullRequestNumber":78}',
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                item = review("security")
                item["body"] = f"<!-- codex-security-review:v1 {payload} -->\n### 🛡️ Codex Security Review"
                states = REPOCTL.codex_review_states([], [item], SHA, "dst-red-Wire/ecommerce-1", 77)
                self.assertNotEqual("COMPLETED", states[1])
        duplicate = review("security")
        duplicate["body"] += '\n<!-- codex-security-review:v1 {"headSha":"' + SHA + '","status":"completed"} -->'
        self.assertNotEqual("COMPLETED", REPOCTL.codex_review_states([], [duplicate], SHA)[1])

    def test_exact_completion_is_not_downgraded_by_later_request(self):
        exact = review("code", SHA, 10, "2026-01-01T00:01:00Z")
        newer = request("code", 20, "2026-01-01T00:02:00Z")
        self.assertEqual("COMPLETED", REPOCTL.codex_review_states([exact], [newer], SHA)[0])

    def test_malformed_users_are_ignored_without_hiding_valid_history(self):
        malformed = []
        for user in (None, {}, "deleted-user", {"login": None}, {"login": 123}):
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

    def test_truncated_response_is_sanitized_api_failure(self):
        reader = REPOCTL.GitHubReader("token", lambda _req, timeout: TruncatedResponse())
        code, out, err = self.invoke(reader, json_mode=True)
        self.assertEqual(5, code)
        self.assertEqual("API_FAILURE", json.loads(out)["result"])
        self.assertIn("IncompleteRead", err)
        self.assertNotIn("partial", out + err)
        self.assertNotIn("Traceback", out + err)

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

    def test_malformed_environment_tokens_never_leak(self):
        sentinel = "super-secret-token\nINJECTED"
        args = ["--repo", "dst-red-Wire/ecommerce-1", "--pr", "77", "--sha", SHA, "--max-attempts", "1", "--json"]
        for variable in ("GH_TOKEN", "GITHUB_TOKEN"):
            with self.subTest(variable=variable):
                code, out, err = self.invoke_cli(*args, env={variable: sentinel})
                self.assertEqual(5, code)
                self.assertEqual("API_FAILURE", json.loads(out)["result"])
                self.assertIn("invalid GitHub authentication token format", err)
                self.assertNotIn(sentinel, out + err)
                self.assertNotIn("super-secret-token", out + err)

    def test_gh_token_precedes_github_token(self):
        captured = []
        fake = FakeReader(head=STALE)

        def reader_factory(token):
            captured.append(token)
            return fake

        with mock.patch.object(REPOCTL, "GitHubReader", side_effect=reader_factory):
            # Default arguments are accepted with authentication; the first GET
            # exits on head movement without persisting or printing either token.
            code, out, err = self.invoke_cli(
                "--repo", "dst-red-Wire/ecommerce-1", "--pr", "77", "--sha", SHA,
                env={"GH_TOKEN": "preferred", "GITHUB_TOKEN": "fallback"},
            )
        self.assertEqual(2, code)
        self.assertEqual(["preferred"], captured)
        self.assertNotIn("preferred", out + err)
        self.assertNotIn("fallback", out + err)

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
