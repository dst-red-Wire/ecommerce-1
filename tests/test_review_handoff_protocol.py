from __future__ import annotations

import hashlib
import json
import unittest

from scripts.pr_monitor import (
    MAX_HANDOFF_BYTES,
    ReviewHandoffError,
    build_handoff,
)

REPOSITORY = "dst-red-Wire/ecommerce-1"
BASE = "a" * 40
HEAD = "b" * 40
TREE = "c" * 40
EVIDENCE = "sha256:" + "d" * 64


def request(**changes):
    inputs = {
        "repository": REPOSITORY,
        "pr": 171,
        "review_kind": "CODE",
        "base_sha": BASE,
        "head_sha": HEAD,
        "tree_sha": TREE,
        "changed_files": ["scripts/repoctl.py", "tests/test_repoctl.py"],
        "qualification_status": "PASS",
        "qualification_evidence_digest": EVIDENCE,
    }
    inputs.update(changes)
    return build_handoff(**inputs)


def canonical_bytes(payload):
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


class ReviewHandoffProtocolTests(unittest.TestCase):
    def test_exact_metadata_is_canonical_deterministic_and_bounded(self):
        first = request(
            changed_files=["tests/test_repoctl.py", "scripts/repoctl.py"],
            delta={"open_finding_count": 9, "resolved_finding_count": 0},
        )
        second = request(
            changed_files=["scripts/repoctl.py", "tests/test_repoctl.py"],
            delta={"resolved_finding_count": 0, "open_finding_count": 9},
        )
        self.assertEqual(first, second)
        self.assertEqual("CHATGPT_REVIEW_REQUIRED", first["event"])
        self.assertEqual("ChatGPT", first["provider"])
        self.assertIs(first["verdict_authority"], False)
        self.assertEqual(REPOSITORY, first["repository"])
        self.assertEqual(171, first["pr"])
        self.assertIs(first["exact_head_verified"], True)
        self.assertEqual(
            (BASE, HEAD, TREE),
            (first["base_sha"], first["head_sha"], first["tree_sha"]),
        )
        self.assertEqual(
            {"status": "PASS", "evidence_digest": EVIDENCE}, first["qualification"]
        )
        self.assertEqual(2, first["delta"]["changed_file_count"])
        unsigned = {
            key: value for key, value in first.items() if key != "handoff_sha256"
        }
        self.assertEqual(
            hashlib.sha256(canonical_bytes(unsigned)).hexdigest(),
            first["handoff_sha256"],
        )
        self.assertLessEqual(len(canonical_bytes(first)), MAX_HANDOFF_BYTES)
        self.assertNotIn("timestamp", first)
        self.assertNotIn("transport", first)
        self.assertNotIn("status", first)
        self.assertNotIn("expected_marker", first)

    def test_security_requires_exact_head_code_pass(self):
        accepted = request(
            review_kind="SECURITY",
            previous_validated_verdict="CODE_PASS",
            previous_head=HEAD,
        )
        self.assertEqual("SECURITY", accepted["review_kind"])
        for changes in (
            {"previous_validated_verdict": None, "previous_head": None},
            {"previous_validated_verdict": "READY", "previous_head": HEAD},
            {"previous_validated_verdict": "CODE_PASS", "previous_head": BASE},
        ):
            with self.subTest(changes=changes), self.assertRaises(ReviewHandoffError):
                request(review_kind="SECURITY", **changes)

    def test_rejects_invalid_identity_and_unverified_qualification(self):
        invalid = (
            {"repository": "other/repo"},
            {"pr": True},
            {"pr": 0},
            {"review_kind": "COMBINED"},
            {"review_kind": "code"},
            {"review_kind": []},
            {"base_sha": BASE.upper()},
            {"head_sha": "b" * 39},
            {"tree_sha": "z" * 40},
            {"head_sha": BASE},
            {"qualification_status": "MISSING"},
            {"qualification_status": "SUPERSEDED"},
            {"qualification_status": object()},
            {"qualification_evidence_digest": "d" * 64},
            {"qualification_evidence_digest": "sha256:" + "Z" * 64},
            {"previous_validated_verdict": "CODE_PASS"},
            {"previous_validated_verdict": "FAIL", "previous_head": BASE},
            {"previous_head": "bad"},
        )
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(ReviewHandoffError):
                request(**change)

    def test_rejects_unsafe_paths_without_silent_truncation(self):
        invalid_paths = (
            [],
            ["../secrets"],
            ["/etc/passwd"],
            ["C:\\secrets"],
            ["scripts//file.py"],
            ["scripts/./file.py"],
            ["scripts/../file.py"],
            ["scripts/file.py/"],
            ["scripts/file.py\nsecret"],
            ["scripts/file.py", "scripts/file.py"],
            ["a" * 513],
            [" scripts/file.py"],
            [123],
            ["\ud800"],
        )
        for files in invalid_paths:
            with self.subTest(files=files), self.assertRaises(ReviewHandoffError):
                request(changed_files=files)

    def test_delta_is_numeric_metadata_only(self):
        for invalid in (
            {"patch": "SECRET_SOURCE_TEXT"},
            {"open_finding_count": "9"},
            {"open_finding_count": True},
            {"open_finding_count": -1},
            {"open_finding_count": 1_000_001},
            {"changed_file_count": 1},
            ["not-a-mapping"],
        ):
            with self.subTest(delta=invalid), self.assertRaises(ReviewHandoffError):
                request(delta=invalid)
        payload = request(delta={"open_finding_count": 9})
        self.assertNotIn("SECRET_SOURCE_TEXT", canonical_bytes(payload).decode())
        self.assertEqual(
            {"changed_file_count": 2, "open_finding_count": 9}, payload["delta"]
        )

    def test_refuses_oversized_complete_file_inventory(self):
        files = [f"tests/{index:03d}-" + "x" * 42 + ".py" for index in range(180)]
        with self.assertRaisesRegex(ReviewHandoffError, "8192"):
            request(changed_files=files)
        with self.assertRaisesRegex(ReviewHandoffError, "bounded sequence"):
            request(changed_files=[f"tests/{index}.py" for index in range(257)])

    def test_digest_changes_with_head_and_verified_evidence(self):
        initial = request()
        self.assertNotEqual(
            initial["handoff_sha256"], request(head_sha="e" * 40)["handoff_sha256"]
        )
        self.assertNotEqual(
            initial["handoff_sha256"],
            request(qualification_evidence_digest="sha256:" + "f" * 64)[
                "handoff_sha256"
            ],
        )


if __name__ == "__main__":
    unittest.main()
