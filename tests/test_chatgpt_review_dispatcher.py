from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import chatgpt_review_dispatcher as dispatcher
from scripts import pr_monitor
from scripts.exact_pr_binding import ExactPRBinding, ExactPRBindingChanged

REPOSITORY = "dst-red-Wire/ecommerce-1"
BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
NEXT_HEAD_SHA = "c" * 40
PR = 169
TREE_SHA = "d" * 40
EVIDENCE_DIGEST = "sha256:" + "e" * 64


class FakeTransport:
    def __init__(self):
        self.submissions = []
        self.polls = []
        self.results = []
        self.state = "RUNNING"
        self.bad_result = False
        self.review_status = "PASS"
        self.blocking_findings = 0

    def submit(self, request, *, idempotency_key):
        self.submissions.append((request, idempotency_key))
        return {"submission_id": "job-one"}

    def status(self, submission_id):
        self.polls.append(submission_id)
        return {"submission_id": submission_id, "state": self.state}

    def fetch_result(self, submission_id):
        self.results.append(submission_id)
        identity = self.submissions[0][1]
        result = {
            "submission_id": submission_id,
            "identity": identity,
            "provider": "ChatGPT",
            "repository": self.submissions[0][0]["repository"],
            "kind": self.submissions[0][0]["review_kind"].lower(),
            "pr": self.submissions[0][0]["pr"],
            "head_sha": self.submissions[0][0]["head_sha"],
            "status": self.review_status,
            "blocking_findings": self.blocking_findings,
            "output": "Review text is evidence only.",
        }
        if self.bad_result:
            result["head_sha"] = NEXT_HEAD_SHA
        return result


class ReviewDispatcherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.outbox = Path(self.temporary.name) / "review-dispatch"
        self.binding = ExactPRBinding(
            REPOSITORY, PR, "main", BASE_SHA, "feature/reviews", HEAD_SHA
        )

    def legacy_request(self, kind="CODE", *, binding=None):
        binding = binding or self.binding
        previous = {
            "head_sha": binding.base_sha if kind == "CODE" else binding.head_sha,
            "validated_verdict": "" if kind == "CODE" else "CODE_PASS",
        }
        current = {"head_sha": binding.head_sha, "exact_head_verified": True}
        handoff = pr_monitor.chatgpt_review_handoff(
            binding.pr_number,
            previous,
            current,
            {"status": {"modified": {"state": "review"}}},
            ["scripts/repoctl.py"],
            review_kind=kind,
        )
        return {
            "schema_version": 1,
            "event": "CHATGPT_REVIEW_REQUIRED",
            "state": "CHATGPT_REVIEW_REQUIRED",
            "provider": "ChatGPT",
            "review_kind": kind,
            "repository": binding.repository,
            "pr": binding.pr_number,
            "base": binding.base,
            "base_sha": binding.base_sha,
            "head_sha": binding.head_sha,
            "head_branch": binding.head_branch,
            "handoff": handoff,
            "handoff_bytes": len(handoff.encode()),
            "handoff_sha256": hashlib.sha256(handoff.encode()).hexdigest(),
            "expected_marker": {
                "provider": "ChatGPT",
                "kind": kind.lower(),
                "head_sha": binding.head_sha,
                "status": "PASS",
                "blocking_findings": 0,
            },
            "verdict_authority": False,
            "rerun": {
                "argv": [
                    "python3",
                    "scripts/repository_delivery.py",
                    "trusted-pr-transition",
                ],
                "command": "python3 scripts/repository_delivery.py trusted-pr-transition",
                "controller_source": "exact-pr-base-sha",
                "after_valid_marker": True,
            },
        }

    def request(self, kind="CODE", *, binding=None):
        return self.structured_request(kind, binding=binding)

    def structured_request(self, kind="CODE", *, binding=None):
        binding = binding or self.binding
        request = self.legacy_request(kind, binding=binding)
        payload = pr_monitor.build_handoff(
            repository=binding.repository,
            pr=binding.pr_number,
            review_kind=kind,
            base_sha=binding.base_sha,
            head_sha=binding.head_sha,
            tree_sha=TREE_SHA,
            changed_files=["scripts/repoctl.py"],
            qualification_status="PASS",
            qualification_evidence_digest=EVIDENCE_DIGEST,
            previous_validated_verdict="CODE_PASS" if kind == "SECURITY" else None,
            previous_head=binding.head_sha if kind == "SECURITY" else None,
        )
        self.set_structured_text(request, payload)
        return request

    @staticmethod
    def set_structured_text(request, payload, *, update_internal=False):
        if update_internal:
            unsigned = {
                key: value for key, value in payload.items() if key != "handoff_sha256"
            }
            payload["handoff_sha256"] = hashlib.sha256(
                json.dumps(
                    unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode()
            ).hexdigest()
        text = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        request["handoff"] = text
        request["handoff_bytes"] = len(text.encode())
        request["handoff_sha256"] = hashlib.sha256(text.encode()).hexdigest()

    def proof(self, kind, *, binding=None):
        binding = binding or self.binding
        return {
            "provider": "ChatGPT",
            "kind": kind.lower(),
            "head_sha": binding.head_sha,
            "status": "PASS",
            "blocking_findings": 0,
            "pr": binding.pr_number,
            "repository": binding.repository,
            "owner_login": "dst-red-Wire",
            "author_login": "dst-red-Wire",
            "comment_id": 100 if kind == "CODE" else 101,
            "created_at": "2026-09-30T12:00:00Z",
            "updated_at": "2026-09-30T12:00:00Z",
            "is_latest_for_kind": True,
        }

    def dispatch(self, request, *, binding=None, **overrides):
        arguments = {
            "binding": binding or self.binding,
            "outbox_root": self.outbox,
            "binding_revalidator": lambda value: value,
        }
        arguments.update(overrides)
        return dispatcher.dispatch_review_request(request, **arguments)

    @staticmethod
    def bootstrap_binding():
        return ExactPRBinding(
            REPOSITORY,
            172,
            "main",
            "ced96d663c1dca1c885d450104f344c10431738d",
            "feat/controller-compat-bootstrap",
            HEAD_SHA,
        )

    def test_legacy_handoff_is_rejected_without_explicit_bootstrap_binding(self):
        transport = FakeTransport()
        for binding in (self.binding, self.bootstrap_binding()):
            with (
                self.subTest(binding=binding),
                self.assertRaisesRegex(
                    dispatcher.ReviewDispatchError, "explicit exact bootstrap"
                ),
            ):
                self.dispatch(
                    self.legacy_request(binding=binding),
                    binding=binding,
                    transport=transport,
                )
        self.assertFalse(self.outbox.exists())
        self.assertEqual([], transport.submissions)

    def test_explicit_bootstrap_is_idempotent_but_outbox_never_grants_opt_in(self):
        binding = self.bootstrap_binding()
        consent = f"{binding.base_sha}:{binding.head_sha}"
        request = self.legacy_request(binding=binding)
        transport = FakeTransport()
        first = self.dispatch(
            request,
            binding=binding,
            legacy_bootstrap_binding=consent,
            transport=transport,
        )
        second = self.dispatch(
            request,
            binding=binding,
            legacy_bootstrap_binding=consent,
            transport=transport,
        )
        self.assertEqual("legacy-bootstrap", first["handoff_protocol"])
        self.assertEqual(consent, first["legacy_bootstrap_binding"])
        self.assertIs(first["verdict_authority"], False)
        self.assertEqual(first["identity"], second["identity"])
        self.assertEqual(1, len(transport.submissions))
        self.assertEqual(["job-one"], transport.polls)
        artifact = Path(first["outbox_path"])
        saved = artifact.read_bytes()
        with self.assertRaisesRegex(
            dispatcher.ReviewDispatchError, "explicit exact bootstrap"
        ):
            self.dispatch(request, binding=binding, transport=transport)
        self.assertEqual(saved, artifact.read_bytes())
        self.assertEqual(1, len(transport.submissions))
        self.assertEqual(["job-one"], transport.polls)
        status = dispatcher.dispatch_status(
            binding,
            "CODE",
            outbox_root=self.outbox,
            binding_revalidator=lambda value: value,
        )
        self.assertIs(status["verdict_authority"], False)
        self.assertEqual(consent, status["records"][0]["legacy_bootstrap_binding"])

    def test_bootstrap_exception_rejects_wrong_scope_or_stale_exact_pair(self):
        binding = self.bootstrap_binding()
        consent = f"{binding.base_sha}:{binding.head_sha}"
        wrong_fields = (
            {"repository": "other/ecommerce-1"},
            {"pr_number": 171},
            {"base": "release"},
            {"base_sha": BASE_SHA},
            {"head_branch": "feature/other"},
            {"head_sha": NEXT_HEAD_SHA},
        )
        for change in wrong_fields:
            changed = ExactPRBinding(**{**binding.as_dict(), **change})
            with (
                self.subTest(change=change),
                self.assertRaises(dispatcher.ReviewDispatchError),
            ):
                self.dispatch(
                    self.legacy_request(binding=changed),
                    binding=changed,
                    legacy_bootstrap_binding=consent,
                )
        for value in (None, "", HEAD_SHA, consent.upper(), True, consent + " "):
            with (
                self.subTest(value=value),
                self.assertRaises(dispatcher.ReviewDispatchError),
            ):
                dispatcher.validate_legacy_bootstrap_binding(value, binding)
        new_base = ExactPRBinding(
            REPOSITORY, 172, "main", BASE_SHA, binding.head_branch, HEAD_SHA
        )
        with self.assertRaises(dispatcher.ReviewDispatchError):
            dispatcher.validate_legacy_bootstrap_binding(
                f"{BASE_SHA}:{HEAD_SHA}", new_base
            )
        self.assertFalse(self.outbox.exists())

    def test_bootstrap_exception_cannot_hide_malformed_structured_handoff(self):
        binding = self.bootstrap_binding()
        request = self.structured_request(binding=binding)
        payload = json.loads(request["handoff"])
        payload["qualification"]["status"] = "FAIL"
        self.set_structured_text(request, payload, update_internal=True)
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(
                request,
                binding=binding,
                legacy_bootstrap_binding=f"{binding.base_sha}:{binding.head_sha}",
            )
        self.assertFalse(self.outbox.exists())

    def test_bootstrap_exception_requires_live_unchanged_binding(self):
        binding = self.bootstrap_binding()
        transport = FakeTransport()
        for reason in ("HEAD_CHANGED", "BASE_CHANGED"):
            with self.subTest(reason=reason):
                revalidate = mock.Mock(
                    side_effect=ExactPRBindingChanged(
                        reason, current_head_sha=NEXT_HEAD_SHA
                    )
                )
                arguments = {
                    "binding": binding,
                    "legacy_bootstrap_binding": f"{binding.base_sha}:{binding.head_sha}",
                    "binding_revalidator": revalidate,
                    "transport": transport,
                }
                if reason == "HEAD_CHANGED":
                    result = self.dispatch(
                        self.legacy_request(binding=binding), **arguments
                    )
                    self.assertEqual("SUPERSEDED", result["state"])
                else:
                    with self.assertRaises(dispatcher.ReviewDispatchError):
                        self.dispatch(self.legacy_request(binding=binding), **arguments)
                self.assertFalse(self.outbox.exists())
        self.assertEqual([], transport.submissions)

    def test_bootstrap_security_requires_exact_owner_code_pass(self):
        binding = self.bootstrap_binding()
        request = self.legacy_request("SECURITY", binding=binding)
        consent = f"{binding.base_sha}:{binding.head_sha}"
        transport = FakeTransport()
        result = self.dispatch(
            request,
            binding=binding,
            legacy_bootstrap_binding=consent,
            transport=transport,
        )
        self.assertEqual("WAITING_CODE_REVIEW", result["reason"])
        self.assertEqual([], transport.submissions)
        result = self.dispatch(
            request,
            binding=binding,
            legacy_bootstrap_binding=consent,
            transport=transport,
            owner_marker_lookup=lambda _, kind: (
                self.proof("CODE", binding=binding) if kind == "code" else None
            ),
        )
        self.assertEqual("REQUESTED", result["state"])
        self.assertEqual(1, len(transport.submissions))

    def test_bootstrap_protocol_trace_tampering_fails_closed(self):
        binding = self.bootstrap_binding()
        consent = f"{binding.base_sha}:{binding.head_sha}"
        request = self.legacy_request(binding=binding)
        result = self.dispatch(
            request, binding=binding, legacy_bootstrap_binding=consent
        )
        path = Path(result["outbox_path"])
        original = json.loads(path.read_text())
        for update in (
            {"handoff_protocol": "structured-v1"},
            {"legacy_bootstrap_binding": None},
            {"legacy_bootstrap_binding": f"{binding.base_sha}:{NEXT_HEAD_SHA}"},
        ):
            with self.subTest(update=update):
                path.write_text(json.dumps({**original, **update}))
                with self.assertRaises(dispatcher.ReviewDispatchError):
                    self.dispatch(
                        request, binding=binding, legacy_bootstrap_binding=consent
                    )
        for missing in ("handoff_protocol", "legacy_bootstrap_binding"):
            with self.subTest(missing=missing):
                partial = {
                    key: value for key, value in original.items() if key != missing
                }
                path.write_text(json.dumps(partial))
                with self.assertRaises(dispatcher.ReviewDispatchError):
                    self.dispatch(
                        request, binding=binding, legacy_bootstrap_binding=consent
                    )

    def test_structured_head_supersedes_historical_legacy_outbox(self):
        binding = self.bootstrap_binding()
        old = self.dispatch(
            self.legacy_request(binding=binding),
            binding=binding,
            legacy_bootstrap_binding=f"{binding.base_sha}:{binding.head_sha}",
        )
        path = Path(old["outbox_path"])
        historical = json.loads(path.read_text())
        historical.pop("handoff_protocol")
        historical.pop("legacy_bootstrap_binding")
        path.write_text(json.dumps(historical))
        new_binding = ExactPRBinding(**{**binding.as_dict(), "head_sha": NEXT_HEAD_SHA})
        request = self.structured_request(binding=new_binding)
        current = self.dispatch(request, binding=new_binding)
        self.assertEqual("structured-v1", current["handoff_protocol"])
        saved_old = json.loads(path.read_text())
        self.assertEqual("SUPERSEDED", saved_old["state"])
        self.assertEqual(NEXT_HEAD_SHA, saved_old["superseded_by_head_sha"])
        self.assertEqual("legacy-historical", saved_old["handoff_protocol"])
        self.assertIsNone(saved_old["legacy_bootstrap_binding"])
        self.assertIs(saved_old["verdict_authority"], False)
        repeated = self.dispatch(request, binding=new_binding)
        self.assertEqual(current["identity"], repeated["identity"])
        self.assertEqual(saved_old, json.loads(path.read_text()))

    def test_historical_legacy_adoption_requires_fresh_opt_in_without_resubmit(self):
        binding = self.bootstrap_binding()
        consent = f"{binding.base_sha}:{binding.head_sha}"
        request = self.legacy_request(binding=binding)
        transport = FakeTransport()
        first = self.dispatch(
            request,
            binding=binding,
            legacy_bootstrap_binding=consent,
            transport=transport,
        )
        path = Path(first["outbox_path"])
        historical = json.loads(path.read_text())
        historical.pop("handoff_protocol")
        historical.pop("legacy_bootstrap_binding")
        path.write_text(json.dumps(historical))
        saved = path.read_bytes()
        with self.assertRaisesRegex(
            dispatcher.ReviewDispatchError, "explicit exact bootstrap"
        ):
            self.dispatch(request, binding=binding, transport=transport)
        self.assertEqual(saved, path.read_bytes())
        self.assertEqual(1, len(transport.submissions))
        self.assertEqual([], transport.polls)
        status = dispatcher.dispatch_status(
            binding,
            "CODE",
            outbox_root=self.outbox,
            binding_revalidator=lambda value: value,
        )
        self.assertEqual("legacy-historical", status["records"][0]["handoff_protocol"])
        self.assertIsNone(status["records"][0]["legacy_bootstrap_binding"])
        self.assertIs(status["verdict_authority"], False)
        self.assertEqual(saved, path.read_bytes())
        adopted = self.dispatch(
            request,
            binding=binding,
            legacy_bootstrap_binding=consent,
            transport=transport,
        )
        self.assertEqual(first["identity"], adopted["identity"])
        self.assertEqual(first["submission_id"], adopted["submission_id"])
        self.assertEqual("RUNNING", adopted["state"])
        self.assertEqual("legacy-bootstrap", adopted["handoff_protocol"])
        self.assertEqual(consent, adopted["legacy_bootstrap_binding"])
        self.assertEqual(1, len(transport.submissions))
        self.assertEqual(["job-one"], transport.polls)
        stored = json.loads(path.read_text())
        self.assertEqual(consent, stored["legacy_bootstrap_binding"])
        self.assertIs(stored["verdict_authority"], False)

    def test_historical_structured_outbox_needs_no_bootstrap_exception(self):
        request = self.request()
        result = self.dispatch(request)
        path = Path(result["outbox_path"])
        original = json.loads(path.read_text())
        original.pop("handoff_protocol")
        original.pop("legacy_bootstrap_binding")
        path.write_text(json.dumps(original))
        result = self.dispatch(request)
        self.assertEqual("structured-v1", result["handoff_protocol"])
        self.assertIsNone(result["legacy_bootstrap_binding"])
        self.assertIs(result["verdict_authority"], False)

    def test_no_transport_creates_non_authoritative_blocked_outbox(self):
        request = self.request()
        result = self.dispatch(request)
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("BLOCKED_EXTERNAL_REVIEW_TRANSPORT", result["reason"])
        self.assertIs(result["verdict_authority"], False)
        self.assertEqual("", result["submission_id"])
        self.assertEqual(request["handoff_sha256"], result["handoff_sha256"])
        self.assertTrue(Path(result["outbox_path"]).is_file())
        self.assertEqual(result["identity"], Path(result["outbox_path"]).stem)
        artifact = json.loads(Path(result["outbox_path"]).read_text(encoding="utf-8"))
        self.assertEqual(request, artifact["request"])
        self.assertEqual(result["identity"], self.dispatch(request)["identity"])

    def test_structured_v1_is_dispatched_and_outboxed_with_transport_digest(self):
        request = self.structured_request()
        payload = json.loads(request["handoff"])
        transport = FakeTransport()
        result = self.dispatch(request, transport=transport)
        self.assertEqual("REQUESTED", result["state"])
        self.assertEqual(request, transport.submissions[0][0])
        self.assertEqual(request["handoff_sha256"], result["handoff_sha256"])
        self.assertNotEqual(payload["handoff_sha256"], result["handoff_sha256"])
        artifact = json.loads(Path(result["outbox_path"]).read_text(encoding="utf-8"))
        self.assertEqual(request, artifact["request"])

    def test_structured_v1_rejects_tampering_even_with_recomputed_outer_digest(self):
        for field, value, repair_internal in (
            ("handoff_sha256", "0" * 64, False),
            ("head_sha", NEXT_HEAD_SHA, True),
            ("review_kind", "SECURITY", True),
            ("changed_files", ["../unsafe.py"], True),
            ("delta", {"changed_file_count": True}, True),
            ("qualification", {"status": "PASS", "evidence_digest": "wrong"}, True),
        ):
            with self.subTest(field=field):
                request = self.structured_request()
                payload = json.loads(request["handoff"])
                payload[field] = value
                self.set_structured_text(
                    request, payload, update_internal=repair_internal
                )
                with self.assertRaises(dispatcher.ReviewDispatchError):
                    self.dispatch(request)
        self.assertFalse(self.outbox.exists())

    def test_structured_v1_rejects_over_budget_before_outbox(self):
        request = self.structured_request()
        payload = json.loads(request["handoff"])
        payload["changed_files"] = [
            f"tests/{index:03d}-" + "x" * 35 + ".py" for index in range(220)
        ]
        payload["delta"]["changed_file_count"] = 220
        self.set_structured_text(request, payload, update_internal=True)
        self.assertGreater(request["handoff_bytes"], 8192)
        with self.assertRaisesRegex(dispatcher.ReviewDispatchError, "byte budget"):
            self.dispatch(request)
        self.assertFalse(self.outbox.exists())

    def test_structured_v1_security_still_requires_exact_owner_code_marker(self):
        request = self.structured_request("SECURITY")
        transport = FakeTransport()
        waiting = self.dispatch(request, transport=transport)
        self.assertEqual("WAITING_CODE_REVIEW", waiting["reason"])
        self.assertEqual([], transport.submissions)
        result = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lambda binding, kind: (
                self.proof("CODE") if kind == "code" else None
            ),
        )
        self.assertEqual("REQUESTED", result["state"])
        self.assertEqual(request, transport.submissions[0][0])

    def test_tampered_request_artifact_cannot_be_reused_or_reported(self):
        request = self.request()
        record = self.dispatch(request)
        path = Path(record["outbox_path"])
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["request"]["expected_marker"] = ["malformed"]
        path.write_text(json.dumps(artifact), encoding="utf-8")
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(request)
        with self.assertRaises(dispatcher.ReviewDispatchError):
            dispatcher.dispatch_status(
                self.binding,
                "CODE",
                outbox_root=self.outbox,
                binding_revalidator=lambda value: value,
            )

    def test_code_then_security_requires_exact_owner_marker(self):
        transport = FakeTransport()
        code = self.dispatch(self.request(), transport=transport)
        self.assertEqual("REQUESTED", code["state"])
        self.assertEqual(1, len(transport.submissions))
        security = self.dispatch(self.request("SECURITY"), transport=transport)
        self.assertEqual("BLOCKED", security["state"])
        self.assertEqual("WAITING_CODE_REVIEW", security["reason"])
        self.assertEqual(1, len(transport.submissions))
        code_proof = lambda binding, kind: (
            self.proof("CODE") if kind == "code" else None
        )
        security = self.dispatch(
            self.request("SECURITY"),
            transport=transport,
            owner_marker_lookup=code_proof,
        )
        self.assertEqual("REQUESTED", security["state"])
        self.assertEqual(2, len(transport.submissions))
        both = lambda binding, kind: self.proof(kind.upper())
        verified = self.dispatch(
            self.request("SECURITY"),
            owner_marker_lookup=both,
        )
        self.assertEqual("PASS", verified["state"])
        self.assertEqual("OWNER_MARKER_VERIFIED", verified["reason"])
        self.assertEqual(101, verified["owner_comment_id"])
        self.assertIs(verified["verdict_authority"], False)

    def test_duplicate_submission_uses_same_identity_and_does_not_submit_again(self):
        request = self.request()
        transport = FakeTransport()
        first = self.dispatch(request, transport=transport)
        second = self.dispatch(request, transport=transport)
        self.assertEqual(first["identity"], second["identity"])
        self.assertEqual("RUNNING", second["state"])
        self.assertEqual(1, len(transport.submissions))
        self.assertEqual(["job-one"], transport.polls)

    def test_poll_only_never_submits_when_outbox_is_absent(self):
        request = self.request()
        transport = FakeTransport()
        blocked = self.dispatch(request, transport=transport, allow_submit=False)
        self.assertEqual("BLOCKED", blocked["state"])
        self.assertEqual("SUBMIT_NOT_ALLOWED", blocked["reason"])
        self.assertEqual("", blocked["submission_id"])
        self.assertEqual([], transport.submissions)
        self.assertEqual([], transport.polls)
        self.assertEqual([], transport.results)
        submitted = self.dispatch(request, transport=transport, allow_submit=True)
        self.assertEqual("REQUESTED", submitted["state"])
        self.assertEqual(1, len(transport.submissions))
        self.assertEqual(blocked["identity"], submitted["identity"])

    def test_poll_only_resumes_existing_submission_by_id(self):
        request = self.request()
        transport = FakeTransport()
        submitted = self.dispatch(request, transport=transport)
        resumed = self.dispatch(request, transport=transport, allow_submit=False)
        self.assertEqual("RUNNING", resumed["state"])
        self.assertEqual(submitted["submission_id"], resumed["submission_id"])
        self.assertEqual(1, len(transport.submissions))
        self.assertEqual(["job-one"], transport.polls)

    def test_poll_only_accepts_existing_owner_proof_without_submission(self):
        request = self.request()
        transport = FakeTransport()
        verified = self.dispatch(
            request,
            transport=transport,
            allow_submit=False,
            owner_marker_lookup=lambda _, kind: (
                self.proof("CODE") if kind == "code" else None
            ),
        )
        self.assertEqual("PASS", verified["state"])
        self.assertEqual("OWNER_MARKER_VERIFIED", verified["reason"])
        self.assertEqual([], transport.submissions)

    def test_poll_only_rejects_corrupt_outbox_without_transport_call(self):
        request = self.request()
        blocked = self.dispatch(request, allow_submit=False)
        path = Path(blocked["outbox_path"])
        record = json.loads(path.read_text())
        record["request"]["head_sha"] = NEXT_HEAD_SHA
        path.write_text(json.dumps(record))
        transport = FakeTransport()
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(request, transport=transport, allow_submit=False)
        self.assertEqual([], transport.submissions)
        self.assertEqual([], transport.polls)

    def test_poll_only_flag_must_be_boolean(self):
        transport = FakeTransport()
        with self.assertRaisesRegex(
            dispatcher.ReviewDispatchError, "allow_submit must be a boolean"
        ):
            self.dispatch(self.request(), transport=transport, allow_submit="false")
        self.assertFalse(self.outbox.exists())
        self.assertEqual([], transport.submissions)

    def test_transport_completion_never_becomes_review_authority(self):
        request = self.request()
        transport = FakeTransport()
        self.dispatch(request, transport=transport)
        transport.state = "COMPLETED"
        result = self.dispatch(request, transport=transport)
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("AWAITING_OWNER_MARKER", result["reason"])
        self.assertTrue(result["result_sha256"])
        self.assertIs(result["verdict_authority"], False)
        self.assertEqual("AWAITING_OWNER_MARKER", self.dispatch(request)["reason"])

    def test_malformed_transport_result_blocks_and_keeps_no_result_digest(self):
        request = self.request()
        transport = FakeTransport()
        self.dispatch(request, transport=transport)
        transport.state = "COMPLETED"
        transport.bad_result = True
        result = self.dispatch(request, transport=transport)
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("BLOCKED_EXTERNAL_REVIEW_RESULT", result["reason"])
        self.assertEqual("", result["result_sha256"])

    def test_transport_result_requires_bound_kind_and_consistent_verdict(self):
        record = {
            "submission_id": "job-one",
            "identity": "d" * 64,
            "review_kind": "CODE",
            "repository": REPOSITORY,
            "pr": PR,
            "head_sha": HEAD_SHA,
        }
        response = {
            "submission_id": "job-one",
            "identity": "d" * 64,
            "provider": "ChatGPT",
            "repository": REPOSITORY,
            "kind": "code",
            "pr": PR,
            "head_sha": HEAD_SHA,
            "status": "PASS",
            "blocking_findings": 0,
            "output": "reviewed exact SHA",
        }
        self.assertEqual(64, len(dispatcher._transport_result(response, record)))
        for changes in (
            {"repository": "wrong/repository"},
            {"pr": PR + 1},
            {"head_sha": NEXT_HEAD_SHA},
            {"kind": "security"},
            {"identity": "e" * 64},
            {"submission_id": "wrong-job"},
            {"status": "PASS", "blocking_findings": 1},
            {"status": "FAIL", "blocking_findings": 0},
            {"provider": "Codex"},
            {"output": "x" * 8193},
            {"output": ""},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaises(dispatcher.ReviewResultError),
            ):
                dispatcher._transport_result({**response, **changes}, record)

    def test_queued_and_running_resume_without_fetch_or_resubmit(self):
        request = self.request()
        transport = FakeTransport()
        self.dispatch(request, transport=transport)
        transport.state = "QUEUED"
        queued = self.dispatch(request, transport=transport)
        self.assertEqual("REQUESTED", queued["state"])
        transport.state = "RUNNING"
        running = self.dispatch(request, transport=transport)
        self.assertEqual("RUNNING", running["state"])
        self.assertEqual(1, len(transport.submissions))
        self.assertEqual(["job-one", "job-one"], transport.polls)
        self.assertEqual([], transport.results)

    def test_bound_fail_requires_owner_marker_and_blocks_security(self):
        request = self.request()
        transport = FakeTransport()
        transport.review_status = "FAIL"
        transport.blocking_findings = 2
        published = []

        def lookup(_, kind):
            if not published or kind != "code":
                return None
            proof = self.proof("CODE")
            proof["status"] = "FAIL"
            proof["blocking_findings"] = 2
            return proof

        self.dispatch(request, transport=transport, owner_marker_lookup=lookup)
        transport.state = "COMPLETED"
        failed = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lookup,
            owner_marker_publisher=lambda *args: published.append(args),
        )
        self.assertEqual("FAIL", failed["state"])
        self.assertEqual("OWNER_MARKER_VERIFIED", failed["reason"])
        self.assertEqual("FAIL", failed["result_status"])
        self.assertEqual(2, failed["result_blocking_findings"])
        self.assertIs(failed["verdict_authority"], False)
        self.assertEqual([(self.binding, "code", "FAIL", 2)], published)
        waiting = self.dispatch(
            self.request("SECURITY"),
            transport=transport,
            owner_marker_lookup=lookup,
        )
        self.assertEqual("CODE_REVIEW_FAILED", waiting["reason"])
        self.assertEqual(1, len(transport.submissions))

    def test_bound_fail_without_owner_marker_remains_blocked(self):
        request = self.request()
        transport = FakeTransport()
        transport.review_status = "FAIL"
        transport.blocking_findings = 3
        self.dispatch(request, transport=transport)
        transport.state = "COMPLETED"
        result = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lambda *_: None,
            owner_marker_publisher=lambda *_: False,
        )
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("AWAITING_OWNER_MARKER", result["reason"])
        self.assertEqual("FAIL", result["result_status"])
        self.assertEqual(3, result["result_blocking_findings"])

    def test_security_result_publishes_only_after_code_and_owner_lookup(self):
        request = self.request("SECURITY")
        transport = FakeTransport()
        published = []

        def lookup(_, kind):
            if kind == "code":
                return self.proof("CODE")
            return self.proof("SECURITY") if published else None

        def publish(*args):
            published.append(args)
            return True

        submitted = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lookup,
            owner_marker_publisher=publish,
        )
        self.assertEqual("REQUESTED", submitted["state"])
        transport.state = "COMPLETED"
        verified = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lookup,
            owner_marker_publisher=publish,
        )
        self.assertEqual("PASS", verified["state"])
        self.assertEqual("OWNER_MARKER_VERIFIED", verified["reason"])
        self.assertEqual([(self.binding, "security", "PASS", 0)], published)
        self.assertEqual(101, verified["owner_comment_id"])
        self.assertEqual(100, verified["code_comment_id"])

    def test_owner_marker_must_match_fetched_verdict(self):
        request = self.request()
        transport = FakeTransport()
        published = []

        def lookup(_, kind):
            if not published or kind != "code":
                return None
            proof = self.proof("CODE")
            proof["status"] = "FAIL"
            proof["blocking_findings"] = 1
            return proof

        self.dispatch(request, transport=transport, owner_marker_lookup=lookup)
        transport.state = "COMPLETED"
        result = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lookup,
            owner_marker_publisher=lambda *args: published.append(args),
        )
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("OWNER_MARKER_RESULT_MISMATCH", result["reason"])
        self.assertNotIn("owner_comment_id", result)

    def test_bound_pass_publishes_once_and_requires_fresh_owner_lookup(self):
        request = self.request()
        transport = FakeTransport()
        published = []

        def lookup(_, kind):
            return self.proof("CODE") if published and kind == "code" else None

        def publish(binding, kind, status, blockers):
            published.append((binding, kind, status, blockers))
            return True

        self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lookup,
            owner_marker_publisher=publish,
        )
        transport.state = "COMPLETED"
        verified = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lookup,
            owner_marker_publisher=publish,
        )
        self.assertEqual("PASS", verified["state"])
        self.assertEqual("OWNER_MARKER_VERIFIED", verified["reason"])
        self.assertEqual(100, verified["owner_comment_id"])
        self.assertEqual([(self.binding, "code", "PASS", 0)], published)
        self.assertEqual(1, len(transport.submissions))
        self.assertEqual(["job-one"], transport.polls)
        self.assertEqual(["job-one"], transport.results)
        restarted = self.dispatch(request, owner_marker_lookup=lookup)
        self.assertEqual("PASS", restarted["state"])
        self.assertEqual([(self.binding, "code", "PASS", 0)], published)

    def test_lost_post_response_reuses_visible_owner_marker(self):
        request = self.request()
        transport = FakeTransport()
        published = []

        def lookup(_, kind):
            return self.proof("CODE") if published and kind == "code" else None

        def publish(*args):
            published.append(args)
            raise OSError("POST response lost after GitHub accepted comment")

        self.dispatch(request, transport=transport, owner_marker_lookup=lookup)
        transport.state = "COMPLETED"
        verified = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lookup,
            owner_marker_publisher=publish,
        )
        self.assertEqual("PASS", verified["state"])
        self.assertEqual("OWNER_MARKER_VERIFIED", verified["reason"])
        self.assertEqual(1, len(published))
        restarted = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lookup,
            owner_marker_publisher=publish,
        )
        self.assertEqual("PASS", restarted["state"])
        self.assertEqual(1, len(published))
        self.assertEqual(1, len(transport.submissions))

    def test_transport_pass_without_owner_marker_never_becomes_pass(self):
        request = self.request()
        transport = FakeTransport()
        self.dispatch(request, transport=transport)
        transport.state = "COMPLETED"
        awaiting = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lambda *_: None,
            owner_marker_publisher=lambda *_: False,
        )
        self.assertEqual("BLOCKED", awaiting["state"])
        self.assertEqual("AWAITING_OWNER_MARKER", awaiting["reason"])
        self.assertEqual("PASS", awaiting["result_status"])
        self.assertIs(awaiting["verdict_authority"], False)
        restarted = self.dispatch(request, owner_marker_lookup=lambda *_: None)
        self.assertEqual("AWAITING_OWNER_MARKER", restarted["reason"])

    def test_head_change_before_marker_publish_supersedes_without_comment(self):
        request = self.request()
        transport = FakeTransport()
        self.dispatch(request, transport=transport)
        transport.state = "COMPLETED"
        calls = 0
        published = []

        def revalidate(value):
            nonlocal calls
            calls += 1
            if calls <= 2:
                return value
            raise ExactPRBindingChanged("HEAD_CHANGED", current_head_sha=NEXT_HEAD_SHA)

        stale = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lambda *_: None,
            owner_marker_publisher=lambda *args: published.append(args),
            binding_revalidator=revalidate,
        )
        self.assertEqual("SUPERSEDED", stale["state"])
        self.assertEqual(3, calls)
        self.assertEqual([], published)

    def test_head_change_after_marker_publish_cannot_return_pass(self):
        request = self.request()
        transport = FakeTransport()
        self.dispatch(request, transport=transport)
        transport.state = "COMPLETED"
        calls = 0
        published = []

        def revalidate(value):
            nonlocal calls
            calls += 1
            if calls <= 3:
                return value
            raise ExactPRBindingChanged("HEAD_CHANGED", current_head_sha=NEXT_HEAD_SHA)

        stale = self.dispatch(
            request,
            transport=transport,
            owner_marker_lookup=lambda *_: None,
            owner_marker_publisher=lambda *args: published.append(args),
            binding_revalidator=revalidate,
        )
        self.assertEqual("SUPERSEDED", stale["state"])
        self.assertEqual(4, calls)
        self.assertEqual([(self.binding, "code", "PASS", 0)], published)

    def test_publisher_requires_authenticated_owner_and_live_binding(self):
        user = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps({"login": "review-bot"}), stderr=""
        )
        with mock.patch.object(dispatcher.subprocess, "run", return_value=user) as run:
            self.assertFalse(
                dispatcher.github_owner_marker_publish(self.binding, "code", "PASS", 0)
            )
        self.assertEqual(1, run.call_count)
        owner = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({"login": "dst-red-Wire"}),
            stderr="",
        )
        posted = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="{}", stderr=""
        )
        with (
            mock.patch.object(
                dispatcher, "revalidate_exact_open_pr", return_value=self.binding
            ),
            mock.patch.object(
                dispatcher.subprocess, "run", side_effect=[owner, posted]
            ) as run,
        ):
            self.assertTrue(
                dispatcher.github_owner_marker_publish(self.binding, "code", "PASS", 0)
            )
        self.assertEqual(2, run.call_count)
        argv = run.call_args_list[1].args[0]
        self.assertEqual("POST", argv[3])
        self.assertEqual(f"repos/{REPOSITORY}/issues/{PR}/comments", argv[4])
        self.assertIn(f'"head_sha":"{HEAD_SHA}"', argv[-1])
        with (
            mock.patch.object(
                dispatcher,
                "revalidate_exact_open_pr",
                side_effect=ExactPRBindingChanged(
                    "HEAD_CHANGED", current_head_sha=NEXT_HEAD_SHA
                ),
            ),
            mock.patch.object(dispatcher.subprocess, "run", return_value=owner) as run,
        ):
            self.assertFalse(
                dispatcher.github_owner_marker_publish(self.binding, "code", "PASS", 0)
            )
        self.assertEqual(1, run.call_count)

    def test_invalid_owner_proof_never_verifies_review(self):
        forged = self.proof("CODE")
        forged["updated_at"] = "2026-09-30T12:01:00Z"
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(self.request(), owner_marker_lookup=lambda *_: forged)

    def test_wrong_provider_pr_head_base_and_digest_fail_before_outbox(self):
        changes = {
            "provider": "Codex",
            "pr": PR + 1,
            "head_sha": NEXT_HEAD_SHA,
            "base_sha": NEXT_HEAD_SHA,
            "handoff_sha256": "0" * 64,
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                request = self.request()
                request[key] = value
                with self.assertRaises(dispatcher.ReviewDispatchError):
                    self.dispatch(request)
        self.assertFalse(self.outbox.exists())

    def test_handoff_content_and_size_are_checked_not_only_sha(self):
        changes = [
            lambda r: r.update(handoff_bytes=r["handoff_bytes"] + 1),
            lambda r: r.update(
                handoff="forged",
                handoff_bytes=6,
                handoff_sha256=hashlib.sha256(b"forged").hexdigest(),
            ),
            lambda r: r.update(
                handoff=r["handoff"].replace(
                    '"head_sha":"' + HEAD_SHA + '"',
                    '"head_sha":"' + NEXT_HEAD_SHA + '"',
                ),
                handoff_sha256=hashlib.sha256(
                    r["handoff"]
                    .replace(
                        '"head_sha":"' + HEAD_SHA + '"',
                        '"head_sha":"' + NEXT_HEAD_SHA + '"',
                    )
                    .encode()
                ).hexdigest(),
            ),
        ]
        for mutate in changes:
            request = self.request()
            mutate(request)
            with self.assertRaises(dispatcher.ReviewDispatchError):
                self.dispatch(request)

    def test_security_marker_must_follow_code_marker_in_creation_order(self):
        code = self.proof("CODE")
        security = self.proof("SECURITY")
        code["created_at"] = code["updated_at"] = "2026-09-30T12:01:00Z"
        for created_at, comment_id in (
            ("2026-09-30T12:00:00Z", 101),
            ("2026-09-30T12:01:00Z", 99),
        ):
            with self.subTest(created_at=created_at, comment_id=comment_id):
                security["created_at"] = security["updated_at"] = created_at
                security["comment_id"] = comment_id
                result = self.dispatch(
                    self.request("SECURITY"),
                    owner_marker_lookup=lambda _, kind: (
                        code if kind == "code" else security
                    ),
                )
                self.assertEqual("BLOCKED", result["state"])
                self.assertEqual("SECURITY_REVIEW_PREDATES_CODE", result["reason"])
                self.assertNotIn("owner_comment_id", result)

    def test_head_change_under_lock_does_not_supersede_newer_head(self):
        old = self.dispatch(self.request())
        new_binding = ExactPRBinding(
            REPOSITORY, PR, "main", BASE_SHA, "feature/reviews", NEXT_HEAD_SHA
        )
        new = self.dispatch(self.request(binding=new_binding), binding=new_binding)
        calls = 0

        def revalidate(binding):
            nonlocal calls
            calls += 1
            if calls == 1:
                return binding
            raise ExactPRBindingChanged("HEAD_CHANGED", current_head_sha=NEXT_HEAD_SHA)

        stale = self.dispatch(self.request(), binding_revalidator=revalidate)
        self.assertEqual("SUPERSEDED", stale["state"])
        self.assertEqual(2, calls)
        self.assertEqual(
            "SUPERSEDED", json.loads(Path(old["outbox_path"]).read_text())["state"]
        )
        self.assertEqual(
            "BLOCKED", json.loads(Path(new["outbox_path"]).read_text())["state"]
        )

    def test_head_change_after_lookup_prevents_transport_submit(self):
        transport = FakeTransport()
        calls = 0

        def revalidate(binding):
            nonlocal calls
            calls += 1
            if calls <= 2:
                return binding
            raise ExactPRBindingChanged("HEAD_CHANGED", current_head_sha=NEXT_HEAD_SHA)

        result = self.dispatch(
            self.request(),
            transport=transport,
            owner_marker_lookup=lambda *_: None,
            binding_revalidator=revalidate,
        )
        self.assertEqual("SUPERSEDED", result["state"])
        self.assertEqual(3, calls)
        self.assertEqual([], transport.submissions)
        self.assertEqual(
            "SUPERSEDED",
            json.loads(Path(result["outbox_path"]).read_text())["state"],
        )

    def test_new_head_supersedes_old_outbox_and_stale_binding_cannot_submit(self):
        old = self.dispatch(self.request())
        new_binding = ExactPRBinding(
            REPOSITORY, PR, "main", BASE_SHA, "feature/reviews", NEXT_HEAD_SHA
        )
        new = self.dispatch(self.request(binding=new_binding), binding=new_binding)
        self.assertEqual("BLOCKED", new["state"])
        self.assertEqual("BLOCKED_EXTERNAL_REVIEW_TRANSPORT", new["reason"])
        self.assertEqual(
            "SUPERSEDED", json.loads(Path(old["outbox_path"]).read_text())["state"]
        )
        stale = self.dispatch(
            self.request(),
            binding_revalidator=lambda _: (_ for _ in ()).throw(
                ExactPRBindingChanged("HEAD_CHANGED", current_head_sha=NEXT_HEAD_SHA)
            ),
        )
        self.assertEqual("SUPERSEDED", stale["state"])

    def test_unknown_schema_field_and_rerun_execution_metadata_rejected(self):
        request = self.request()
        request["marker_is_pass"] = True
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(request)
        request = self.request()
        request["rerun"]["after_valid_marker"] = False
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(request)

    def github_comment(
        self,
        comment_id,
        status,
        blockers,
        *,
        author="dst-red-Wire",
        head=HEAD_SHA,
        kind="code",
        edited=False,
    ):
        marker = json.dumps(
            {
                "provider": "ChatGPT",
                "kind": kind,
                "head_sha": head,
                "status": status,
                "blocking_findings": blockers,
            },
            separators=(",", ":"),
        )
        return {
            "id": comment_id,
            "created_at": f"2026-09-30T12:{comment_id:02d}:00Z",
            "updated_at": f"2026-09-30T12:{comment_id + int(edited):02d}:00Z",
            "user": {"login": author},
            "body": f"CODE review\n<!-- chatgpt-exact-sha-review:v1 {marker} -->",
        }

    def github_lookup(self, comments):
        response = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps([comments]),
            stderr="",
        )
        with mock.patch.object(
            dispatcher.subprocess, "run", return_value=response
        ) as run:
            proof = dispatcher.github_owner_marker_lookup(self.binding, "code")
        self.assertEqual(
            [
                "gh",
                "api",
                "--paginate",
                "--slurp",
                f"repos/{REPOSITORY}/issues/{PR}/comments?per_page=100",
            ],
            run.call_args.args[0],
        )
        return proof

    def test_github_owner_lookup_uses_latest_unedited_exact_marker(self):
        proof = self.github_lookup(
            [
                self.github_comment(1, "PASS", 0),
                self.github_comment(2, "PASS", 0, author="other-user"),
                self.github_comment(3, "PASS", 0, head=NEXT_HEAD_SHA),
                self.github_comment(4, "BLOCKED", 2),
            ]
        )
        self.assertEqual(4, proof["comment_id"])
        self.assertEqual("BLOCKED", proof["status"])
        result = self.dispatch(self.request(), owner_marker_lookup=lambda *_: proof)
        self.assertEqual("FAIL", result["state"])
        self.assertIs(result["verdict_authority"], False)

    def test_edited_latest_owner_marker_blocks_older_pass(self):
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.github_lookup(
                [
                    self.github_comment(1, "PASS", 0),
                    self.github_comment(2, "PASS", 0, edited=True),
                ]
            )

    def test_multiple_markers_in_owner_comment_are_rejected(self):
        comment = self.github_comment(1, "PASS", 0)
        comment["body"] += "\n" + comment["body"].splitlines()[-1]
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.github_lookup([comment])

    def test_security_does_not_start_after_failed_code_marker(self):
        transport = FakeTransport()
        failed_code = self.proof("CODE")
        failed_code.update(status="BLOCKED", blocking_findings=1)
        result = self.dispatch(
            self.request("SECURITY"),
            transport=transport,
            owner_marker_lookup=lambda _, kind: failed_code if kind == "code" else None,
        )
        self.assertEqual("BLOCKED", result["state"])
        self.assertEqual("CODE_REVIEW_FAILED", result["reason"])
        self.assertEqual([], transport.submissions)

    def test_policy_change_fails_closed_before_creating_outbox(self):
        policy = Path(self.temporary.name) / "policy.yaml"
        policy.write_text(
            dispatcher.POLICY_PATH.read_text(encoding="utf-8").replace(
                "verdict_authority: false", "verdict_authority: true"
            ),
            encoding="utf-8",
        )
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(self.request(), policy_path=policy)
        self.assertFalse(self.outbox.exists())

    def test_nonowner_marker_does_not_supply_proof(self):
        self.assertIsNone(
            self.github_lookup(
                [
                    self.github_comment(1, "PASS", 0, author="codex-bot"),
                ]
            )
        )

    def test_duplicate_json_key_in_owner_marker_is_rejected(self):
        comment = self.github_comment(1, "PASS", 0)
        comment["body"] = comment["body"].replace(
            '"status":"PASS"',
            '"status":"BLOCKED","status":"PASS"',
        )
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.github_lookup([comment])

    def test_read_only_status_reports_outbox_without_granting_authority(self):
        empty = dispatcher.dispatch_status(
            self.binding,
            "CODE",
            outbox_root=self.outbox,
            binding_revalidator=lambda value: value,
        )
        self.assertEqual("NOT_REQUESTED", empty["state"])
        self.assertFalse(self.outbox.exists())
        dispatched = self.dispatch(self.request())
        current = dispatcher.dispatch_status(
            self.binding,
            "CODE",
            outbox_root=self.outbox,
            binding_revalidator=lambda value: value,
        )
        self.assertEqual("BLOCKED", current["state"])
        self.assertEqual("BLOCKED_EXTERNAL_REVIEW_TRANSPORT", current["reason"])
        self.assertEqual(dispatched["identity"], current["records"][0]["identity"])
        self.assertIs(current["verdict_authority"], False)

    def test_read_only_status_detects_head_supersession(self):
        state = dispatcher.dispatch_status(
            self.binding,
            "CODE",
            outbox_root=self.outbox,
            binding_revalidator=lambda _: (_ for _ in ()).throw(
                ExactPRBindingChanged("HEAD_CHANGED", current_head_sha=NEXT_HEAD_SHA)
            ),
        )
        self.assertEqual("SUPERSEDED", state["state"])
        self.assertEqual(NEXT_HEAD_SHA, state["current_head_sha"])
        self.assertFalse(self.outbox.exists())

    def test_symlinked_outbox_parent_is_rejected(self):
        target = Path(self.temporary.name) / "target"
        target.mkdir()
        link = Path(self.temporary.name) / "link"
        link.symlink_to(target, target_is_directory=True)
        self.outbox = link / "review-dispatch"
        with self.assertRaises(dispatcher.ReviewDispatchError):
            self.dispatch(self.request())
        self.assertEqual([], list(target.iterdir()))


if __name__ == "__main__":
    unittest.main()
