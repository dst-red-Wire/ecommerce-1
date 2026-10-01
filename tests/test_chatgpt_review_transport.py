"""Contract tests for the explicitly configured command review transport."""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from scripts import chatgpt_review_transport as transport


class CommandReviewTransportTest(TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.command = self.root / "review-worker"
        self.calls = self.root / "calls.jsonl"
        self.script = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

message = json.loads(sys.stdin.readline())
with Path(os.environ["FAKE_REVIEW_CALLS"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(message, sort_keys=True) + "\\n")
operation = message["operation"]
if operation == "submit":
    print(json.dumps({"submission_id": "job-one"}))
elif operation == "status":
    print(json.dumps({"submission_id": message["submission_id"], "state": "RUNNING"}))
elif operation == "fetch_result":
    print(json.dumps({
        "submission_id": message["submission_id"],
        "identity": "a" * 64,
        "provider": "ChatGPT",
        "repository": "dst-red-Wire/ecommerce-1",
        "kind": "code",
        "pr": 169,
        "head_sha": "b" * 40,
        "status": "PASS",
        "blocking_findings": 0,
        "output": "Bounded review",
    }))
else:
    sys.exit(2)
"""
        self._write_worker(self.script)

    def _write_worker(self, source):
        self.command.write_text(source, encoding="utf-8")
        self.command.chmod(0o700)
        return hashlib.sha256(self.command.read_bytes()).hexdigest()

    def _config(self, digest=None):
        return {
            "CHATGPT_REVIEW_TRANSPORT": "command-v1",
            "CHATGPT_REVIEW_TRANSPORT_COMMAND": str(self.command),
            "CHATGPT_REVIEW_TRANSPORT_SHA256": digest
            or hashlib.sha256(self.command.read_bytes()).hexdigest(),
        }

    def test_resolution_has_explicit_configured_disabled_unavailable_states(self):
        self.assertEqual("UNAVAILABLE", transport.resolve_review_transport({}).state)
        self.assertEqual(
            "DISABLED",
            transport.resolve_review_transport(
                {"CHATGPT_REVIEW_TRANSPORT": "disabled"}
            ).state,
        )
        self.assertEqual(
            "UNAVAILABLE",
            transport.resolve_review_transport(
                {"CHATGPT_REVIEW_TRANSPORT": "unknown-v1"}
            ).state,
        )
        resolved = transport.resolve_review_transport(self._config())
        self.assertEqual("CONFIGURED", resolved.state)
        self.assertEqual("command-v1", resolved.backend)
        self.assertIsInstance(resolved.transport, transport.CommandReviewTransport)
        self.assertEqual(
            "UNAVAILABLE",
            transport.resolve_review_transport(self._config("0" * 64)).state,
        )

    def test_command_roundtrip_sends_canonical_request_and_identity(self):
        resolved = transport.resolve_review_transport(self._config())
        worker = resolved.transport
        self.assertIsNotNone(worker)
        request = {"handoff": "bounded exact review", "head_sha": "b" * 40}
        with mock.patch.dict(os.environ, {"FAKE_REVIEW_CALLS": str(self.calls)}):
            first = worker.submit(request, idempotency_key="a" * 64)
            second = worker.submit(request, idempotency_key="a" * 64)
            status = worker.status(first["submission_id"])
            result = worker.fetch_result(first["submission_id"])
        self.assertEqual(first, second)
        self.assertEqual({"submission_id": "job-one", "state": "RUNNING"}, status)
        self.assertEqual("dst-red-Wire/ecommerce-1", result["repository"])
        self.assertEqual("PASS", result["status"])
        calls = [
            json.loads(line)
            for line in self.calls.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(
            ["submit", "submit", "status", "fetch_result"],
            [call["operation"] for call in calls],
        )
        self.assertTrue(all(call["schema_version"] == 1 for call in calls))
        self.assertEqual("a" * 64, calls[0]["idempotency_key"])
        self.assertEqual(request, calls[0]["request"])
        self.assertEqual("job-one", calls[2]["submission_id"])
        self.assertEqual("job-one", calls[3]["submission_id"])

    def test_digest_and_symlink_components_fail_closed(self):
        digest = hashlib.sha256(self.command.read_bytes()).hexdigest()
        alias = self.root / "alias"
        alias.symlink_to(self.command)
        with self.assertRaises(transport.ReviewTransportError):
            transport.CommandReviewTransport(alias, digest)
        folder = self.root / "folder"
        folder.mkdir()
        nested = folder / "review-worker"
        nested.write_bytes(self.command.read_bytes())
        nested.chmod(0o700)
        folder_alias = self.root / "folder-alias"
        folder_alias.symlink_to(folder)
        with self.assertRaises(transport.ReviewTransportError):
            transport.CommandReviewTransport(folder_alias / nested.name, digest)
        worker = transport.CommandReviewTransport(self.command, digest)
        self._write_worker(self.script + "\n# changed\n")
        with self.assertRaisesRegex(transport.ReviewTransportError, "digest differs"):
            worker.submit({"handoff": "bounded"}, idempotency_key="a" * 64)

    def test_malformed_oversized_and_failed_worker_never_expose_stderr(self):
        digest = self._write_worker(
            "#!/usr/bin/env python3\nimport sys\n"
            'print("SENSITIVE_VALUE", file=sys.stderr)\nsys.exit(1)\n'
        )
        worker = transport.CommandReviewTransport(self.command, digest)
        with self.assertRaises(transport.ReviewTransportError) as failure:
            worker.status("job-one")
        self.assertNotIn("SENSITIVE_VALUE", str(failure.exception))
        digest = self._write_worker('#!/usr/bin/env python3\nprint("x" * 20000)\n')
        worker = transport.CommandReviewTransport(self.command, digest)
        with self.assertRaisesRegex(
            transport.ReviewTransportError, "exceeds byte limit"
        ):
            worker.status("job-one")
        digest = self._write_worker(
            '#!/usr/bin/env python3\nprint("{\\"state\\":1,\\"state\\":2}")\n'
        )
        worker = transport.CommandReviewTransport(self.command, digest)
        with self.assertRaisesRegex(transport.ReviewTransportError, "malformed"):
            worker.status("job-one")

    def test_handoff_budget_is_enforced_before_worker_submit(self):
        worker = transport.CommandReviewTransport(
            self.command, hashlib.sha256(self.command.read_bytes()).hexdigest()
        )
        with (
            mock.patch.dict(os.environ, {"FAKE_REVIEW_CALLS": str(self.calls)}),
            self.assertRaisesRegex(
                transport.ReviewTransportError, "handoff exceeds byte limit"
            ),
        ):
            worker.submit({"handoff": "x" * 8193}, idempotency_key="a" * 64)
        self.assertFalse(self.calls.exists())

    def test_timeout_is_bounded_and_kills_worker(self):
        digest = self._write_worker(
            "#!/usr/bin/env python3\nimport time\ntime.sleep(3)\n"
        )
        worker = transport.CommandReviewTransport(self.command, digest)
        with (
            mock.patch.object(transport, "_TIMEOUT_SECONDS", 0.1),
            self.assertRaisesRegex(transport.ReviewTransportError, "timed out"),
        ):
            worker.status("job-one")
