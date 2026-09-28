import json
import pathlib
import tempfile
import unittest
from unittest import mock

import scripts.codex_budget as codex_budget


class CodexBudgetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "config/contracts").mkdir(parents=True)
        (self.root / ".context").mkdir()
        contract = {
            "status": "enforced",
            "context_level_max_bytes": {"L0": 4096, "L1": 8192, "L2": 12288},
            "context_cache": {"state_directory": ".context/codex-budget"},
        }
        self.contract_path = self.root / "config/contracts/codex-token-budget.json"
        self.contract_path.write_text(json.dumps(contract), encoding="utf-8")
        self.root_patch = mock.patch.object(codex_budget, "ROOT", self.root)
        self.contract_patch = mock.patch.object(codex_budget, "CONTRACT", self.contract_path)
        self.root_patch.start()
        self.contract_patch.start()
        self.manifest = self.root / ".context/codex-context.json"
        self.manifest.write_text(
            json.dumps(
                {
                    "route": "L0",
                    "actual_bytes": 1000,
                    "max_bytes": 4096,
                    "cache_key": "a" * 64,
                    "head_sha": "b" * 40,
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self):
        self.contract_patch.stop()
        self.root_patch.stop()
        self.tmp.cleanup()

    def test_cache_miss_requires_ai(self):
        result = codex_budget.decide(self.manifest)
        self.assertTrue(result["should_invoke_ai"])
        self.assertEqual("exact_input_cache_miss", result["reason"])

    def test_exact_marked_result_is_reused_and_content_change_invalidates_it(self):
        result_path = self.root / ".context/result.txt"
        result_path.write_text("validated result", encoding="utf-8")
        codex_budget.mark(self.manifest, ".context/result.txt")
        hit = codex_budget.decide(self.manifest)
        self.assertFalse(hit["should_invoke_ai"])
        self.assertEqual("exact_input_cache_hit", hit["reason"])
        self.assertEqual(".context/result.txt", hit["cached_result"])

        result_path.write_text("changed result", encoding="utf-8")
        miss = codex_budget.decide(self.manifest)
        self.assertTrue(miss["should_invoke_ai"])

    def test_result_outside_context_is_rejected(self):
        outside = self.root / "outside.txt"
        outside.write_text("no", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must remain under .context"):
            codex_budget.mark(self.manifest, "outside.txt")

    def test_manifest_cannot_exceed_route_budget(self):
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        value["actual_bytes"] = 5000
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "context budget violation"):
            codex_budget.decide(self.manifest)


if __name__ == "__main__":
    unittest.main()
