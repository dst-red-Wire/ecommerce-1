import pathlib
import tempfile
import unittest
from unittest import mock

from scripts import repoctl


class DiagnosticTests(unittest.TestCase):
    def test_existing_failure_log_is_compacted_without_reexecution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            logs = root / ".context/logs"
            logs.mkdir(parents=True)
            (logs / "test.log").write_text(
                "\n".join(["repeated noise"] * 30 + ["test_product FAILED: token=topsecret"] +
                          ["details"] * 100), encoding="utf-8")
            budget = {"failure_context_max_lines": 80, "failure_context_max_bytes": 12000}
            class Policy:
                @staticmethod
                def redact_sensitive(value, _cfg):
                    return value.replace("topsecret", "[REDACTED]")
            with mock.patch.object(repoctl, "ROOT", root), mock.patch.object(
                repoctl, "CONTEXT", root / ".context"
            ), mock.patch.object(repoctl, "_codex_token_budget_contract", return_value=budget), mock.patch.object(
                repoctl, "_diagnostic_policy", return_value=(Policy, {})
            ), mock.patch.object(repoctl, "run", side_effect=AssertionError("must not rerun")):
                self.assertEqual(0, repoctl.failure_context("test", ""))
            output = (root / ".context/failure-test.md").read_text(encoding="utf-8")
            self.assertIn("test_product FAILED", output)
            self.assertIn("EXIT_CODE: UNKNOWN", output)
            self.assertIn("log lines omitted", output)
            self.assertNotIn("topsecret", output)
            self.assertEqual(0o600, (root / ".context/failure-test.md").stat().st_mode & 0o777)

    def test_diff_omits_forbidden_content_and_keeps_full_redacted_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / ".context").mkdir()
            budget = {"diff_context_max_bytes": 12288}
            class Policy:
                @staticmethod
                def redact_sensitive(value, _cfg):
                    return value.replace("token=topsecret", "[REDACTED]")
            cfg = {"agent_data_access": {"forbidden_path_patterns": [r"(^|/)secret.key$"]}}
            def git(*args):
                self.assertNotIn("secret.key", args)
                return "token=topsecret\n" if "--unified=1" in args else "safe.py | 1 +"
            with mock.patch.object(repoctl, "ROOT", root), mock.patch.object(
                repoctl, "CONTEXT", root / ".context"
            ), mock.patch.object(repoctl, "_codex_token_budget_contract", return_value=budget), mock.patch.object(
                repoctl, "_diagnostic_policy", return_value=(Policy, cfg)
            ), mock.patch.object(repoctl, "changed_paths", return_value=["safe.py", "secret.key"]), mock.patch.object(
                repoctl, "git", side_effect=git
            ):
                self.assertEqual(0, repoctl.diff_context("base"))
            compact = (root / ".context/diff.md").read_text(encoding="utf-8")
            full = (root / ".context/diff-full.md").read_text(encoding="utf-8")
            self.assertIn("sensitive paths: contents omitted", compact)
            self.assertNotIn("topsecret", compact + full)
            self.assertEqual(0o600, (root / ".context/diff-full.md").stat().st_mode & 0o777)


if __name__ == "__main__":
    unittest.main()
