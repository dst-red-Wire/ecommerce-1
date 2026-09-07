from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repoctl_incremental_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class IncrementalDeliveryTests(unittest.TestCase):
    BASE = "1" * 40
    PARENT = "2" * 40
    HEAD = "3" * 40

    def parent_evidence(self):
        return {
            "schema_version": 2,
            "base_sha": self.BASE,
            "head_sha": self.PARENT,
            "status": "PASS",
            "exact_commit_evidence": True,
            "gates": [
                {"gate": "frontend:storefront", "status": "PASS"},
                {"gate": "platform:terraform", "status": "PASS"},
                {"gate": "system", "status": "PASS"},
            ],
        }

    def fake_git(self, *args, check=True):
        if args == ("rev-parse", "feature-head"):
            return self.HEAD + "\n"
        if args == ("rev-parse", "HEAD"):
            return self.HEAD + "\n"
        if args == ("rev-list", "--parents", "-n", "1", self.HEAD):
            return f"{self.HEAD} {self.PARENT}\n"
        if args == ("rev-parse", "origin/main"):
            return self.BASE + "\n"
        if args == ("status", "--porcelain", "--untracked-files=all"):
            return ""
        raise AssertionError(f"unexpected git call: {args}")

    def test_reuses_unchanged_component_passes(self):
        executed = []
        captured = {}
        full_components = ["frontend:storefront", "global", "platform:terraform", "system"]
        delta_components = ["global"]

        with tempfile.TemporaryDirectory() as tmp:
            context = Path(tmp)
            evidence_dir = context / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / f"{self.PARENT}.json").write_text(
                json.dumps(self.parent_evidence()), encoding="utf-8"
            )

            def fake_changed_paths(base, head):
                if base == "origin/main":
                    return ["frontend/apps/storefront/app/page.tsx", "platform/terraform/main.tf", "scripts/resource-sizing.rb"]
                if base == self.PARENT:
                    return ["scripts/resource-sizing.rb"]
                raise AssertionError((base, head))

            def fake_affected(base, head, *, strict_unknown=False):
                if base == "origin/main":
                    self.assertFalse(strict_unknown)
                    return full_components
                if base == self.PARENT:
                    self.assertTrue(strict_unknown)
                    return delta_components
                raise AssertionError((base, head, strict_unknown))

            def fake_run_gate(name, command, records, env=None):
                executed.append(name)
                records.append({"gate": name, "status": "PASS", "exit_code": 0, "duration_seconds": 0.01})
                return True

            def fake_write(base, head, paths, components, records, verification=None):
                captured["records"] = list(records)
                captured["verification"] = verification
                return context / "evidence" / "current.json"

            with mock.patch.object(REPOCTL, "CONTEXT", context), \
                 mock.patch.object(REPOCTL, "git", side_effect=self.fake_git), \
                 mock.patch.object(REPOCTL, "changed_paths", side_effect=fake_changed_paths), \
                 mock.patch.object(REPOCTL, "affected", side_effect=fake_affected), \
                 mock.patch.object(REPOCTL, "_run_gate", side_effect=fake_run_gate), \
                 mock.patch.object(REPOCTL, "write_evidence", side_effect=fake_write):
                self.assertEqual(0, REPOCTL.verify_change("origin/main", "feature-head"))

        self.assertEqual(
            ["governance", "runtime-efficiency", "contracts", "automation", "security"],
            executed,
        )
        records = {record["gate"]: record for record in captured["records"]}
        for gate in ["frontend:storefront", "platform:terraform", "system"]:
            self.assertEqual(self.PARENT, records[gate]["reused_from_sha"])
        self.assertEqual("incremental", captured["verification"]["mode"])
        self.assertEqual(["global"], captured["verification"]["delta_components"])

    def test_exact_verification_refuses_a_different_checked_out_head(self):
        checked_out = "4" * 40

        def mismatched_git(*args, check=True):
            if args == ("rev-parse", "feature-head"):
                return self.HEAD + "\n"
            if args == ("rev-parse", "HEAD"):
                return checked_out + "\n"
            raise AssertionError(f"unexpected git call before fail-closed mismatch: {args}")

        with mock.patch.object(REPOCTL, "git", side_effect=mismatched_git), \
             mock.patch.object(REPOCTL, "_run_gate") as run_gate:
            self.assertEqual(2, REPOCTL.verify_change("origin/main", "feature-head"))
        run_gate.assert_not_called()

    def test_wrong_base_parent_evidence_is_not_reused(self):
        evidence = self.parent_evidence()
        evidence["base_sha"] = "9" * 40
        with tempfile.TemporaryDirectory() as tmp:
            context = Path(tmp)
            (context / "evidence").mkdir()
            (context / "evidence" / f"{self.PARENT}.json").write_text(json.dumps(evidence), encoding="utf-8")
            with mock.patch.object(REPOCTL, "CONTEXT", context), \
                 mock.patch.object(REPOCTL, "git", side_effect=self.fake_git):
                parent, data = REPOCTL._incremental_parent_evidence("origin/main", "feature-head")
        self.assertIsNone(parent)
        self.assertIsNone(data)

    def test_worktree_never_reuses_commit_evidence(self):
        parent, data = REPOCTL._incremental_parent_evidence("origin/main", "WORKTREE")
        self.assertIsNone(parent)
        self.assertIsNone(data)


if __name__ == "__main__":
    unittest.main()
