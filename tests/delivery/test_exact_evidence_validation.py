import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repoctl_evidence_validation_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class ExactEvidenceValidationTest(unittest.TestCase):
    def evidence(self):
        return {
            "schema_version": 5,
            "status": "PASS",
            "exact_commit_evidence": True,
            "head_sha": "h",
            "base_sha": "b",
            "head_tree_sha": "t",
            "changed_paths": ["x"],
            "qualification_identity": "identity",
            "created_at_epoch": time.time(),
            "gates": [{"gate": "governance", "status": "PASS"}],
        }

    def validate(self, evidence):
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory)
            path = context / "evidence" / "h.json"
            path.parent.mkdir()
            path.write_text(json.dumps(evidence))
            values = {
                ("rev-parse", "h"): "h",
                ("rev-parse", "HEAD"): "h",
                ("status", "--porcelain", "--untracked-files=all"): "",
                ("rev-parse", "base"): "b",
                ("rev-parse", "h^{tree}"): "t",
            }
            with (
                mock.patch.object(REPOCTL, "CONTEXT", context),
                mock.patch.object(REPOCTL, "git", side_effect=lambda *args: values[args]),
                mock.patch.object(REPOCTL, "changed_paths", return_value=["x"]),
                mock.patch.object(REPOCTL, "qualification_identity", return_value="identity"),
            ):
                return REPOCTL._valid_exact_evidence("base", "h")

    def test_accepts_current_exact_identity(self):
        self.assertIsNotNone(self.validate(self.evidence()))

    def test_rejects_stale_or_tampered_evidence(self):
        for field, value in (
            ("created_at_epoch", time.time() - 90000),
            ("qualification_identity", "tampered"),
            ("head_tree_sha", "wrong"),
            ("base_sha", "wrong"),
            ("gates", [{"status": "FAIL"}]),
        ):
            with self.subTest(field=field):
                evidence = self.evidence()
                evidence[field] = value
                self.assertIsNone(self.validate(evidence))

    def test_rejects_malformed_nonfinite_and_future_timestamps(self):
        for value in (
            None,
            "bad",
            "123",
            {},
            True,
            float("nan"),
            float("inf"),
            -float("inf"),
            10**400,
            time.time() + 60,
        ):
            with self.subTest(value=value):
                evidence = self.evidence()
                evidence["created_at_epoch"] = value
                self.assertIsNone(self.validate(evidence))

    def test_prepush_requalifies_rejected_evidence(self):
        with (
            mock.patch.object(REPOCTL, "git", return_value="h"),
            mock.patch.object(REPOCTL, "_valid_exact_evidence", return_value=None) as validate,
            mock.patch.object(REPOCTL, "verify_change", return_value=1) as verify,
        ):
            self.assertEqual(1, REPOCTL.prepush())
            validate.assert_called_once_with("origin/main", "h")
            verify.assert_called_once_with("origin/main", "h")

    def test_prepush_reuses_only_canonical_validation(self):
        path = ROOT / ".context/evidence/h.json"
        with (
            mock.patch.object(REPOCTL, "git", return_value="h"),
            mock.patch.object(REPOCTL, "_valid_exact_evidence", return_value=path) as validate,
            mock.patch.object(REPOCTL, "verify_change") as verify,
        ):
            self.assertEqual(0, REPOCTL.prepush())
            validate.assert_called_once_with("origin/main", "h")
            verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
