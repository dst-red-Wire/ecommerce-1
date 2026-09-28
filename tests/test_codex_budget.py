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
        self.pack = self.root / ".context/codex-context.md"
        self.pack.write_text("bounded context", encoding="utf-8")
        self.manifest = self.root / ".context/codex-context.json"
        self.current_patch = mock.patch.object(codex_budget, "_verify_current", return_value=None)
        self.current_patch.start()
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "route": "L0",
                    "actual_bytes": len(self.pack.read_bytes()),
                    "max_bytes": 4096,
                    "cache_key": "a" * 64,
                    "head_sha": "b" * 40,
                    "pack_path": ".context/codex-context.md",
                    "pack_sha256": __import__("hashlib").sha256(self.pack.read_bytes()).hexdigest(),
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self):
        self.current_patch.stop()
        self.contract_patch.stop()
        self.root_patch.stop()
        self.tmp.cleanup()

    def test_run_hit_intercepts_before_model_transport(self):
        import types
        result_path = self.root / ".context/result.txt"
        result_path.write_text("reused answer", encoding="utf-8")
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            self.assertIn("context-pack.py", argv[1])
            pack = self.root / argv[argv.index("--output") + 1]
            manifest = self.root / argv[argv.index("--manifest") + 1]
            pack.parent.mkdir(parents=True, exist_ok=True)
            pack.write_text("task pack", encoding="utf-8")
            manifest.write_text(json.dumps({"route": "L0", "actual_bytes": 9,
                "estimated_input_tokens": 3}), encoding="utf-8")
            return types.SimpleNamespace(returncode=0, stderr="")

        args = types.SimpleNamespace(task="static summary", since="", staged=False,
            paths=[], profile="ecommerce-minimal", model="", effort="",
            expect="answer", cacheable=True, timeout=30)
        with mock.patch.object(codex_budget, "ROOT", self.root), mock.patch.object(
            codex_budget.subprocess, "run", side_effect=fake_run
        ), mock.patch.object(codex_budget, "effective_identity", return_value={"model":"test-model","effort":"low"}), mock.patch.object(
            codex_budget, "decide", return_value={"should_invoke_ai": False,
                "reason": "exact_input_cache_hit", "cached_result": ".context/result.txt"}
        ):
            self.assertEqual(0, codex_budget.run_task(args))
        self.assertEqual(1, len(calls))
        metrics = list((self.root / ".context/codex-budget/metrics").glob("*.json"))
        self.assertEqual(1, len(metrics))
        self.assertEqual(0, json.loads(metrics[0].read_text())["calls"])

    def test_real_entrypoint_hit_miss_and_invalidation_without_model(self):
        import os
        import subprocess
        root = pathlib.Path(__file__).resolve().parents[1]
        fixture = root / ".context/codex-budget-test-input.txt"
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = pathlib.Path(tmp)
            counter = bin_dir / "calls"
            fake = bin_dir / "codex"
            fake.write_text(
                f"#!{__import__('sys').executable}\n"
                "import json, os, pathlib, sys\n"
                "sys.stdin.read()\n"
                "p=pathlib.Path(os.environ['FAKE_CODEX_COUNT'])\n"
                "p.write_text(str(int(p.read_text() or '0')+1) if p.exists() else '1')\n"
                "for event in ["
                "{'type':'turn.started'},"
                "{'type':'item.completed','item':{'type':'agent_message','text':'answer'}},"
                "{'type':'turn.completed','usage':{'input_tokens':100,'cached_input_tokens':20,'output_tokens':10}}"
                "]: print(json.dumps(event))\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}",
                       FAKE_CODEX_COUNT=str(counter))
            argv = [__import__('sys').executable, "scripts/codex_budget.py", "run",
                    "--task", f"summarize fixture {bin_dir.name}", "--paths",
                    ".context/codex-budget-test-input.txt", "--cacheable",
                    "--expect", "answer"]
            try:
                fixture.write_text("version one", encoding="utf-8")
                first = subprocess.run(argv, cwd=root, env=env, text=True, capture_output=True)
                self.assertEqual(0, first.returncode, first.stderr)
                self.assertEqual("1", counter.read_text())
                second = subprocess.run(argv, cwd=root, env=env, text=True, capture_output=True)
                self.assertEqual(0, second.returncode, second.stderr)
                self.assertEqual("1", counter.read_text())
                fixture.write_text("version two", encoding="utf-8")
                third = subprocess.run(argv, cwd=root, env=env, text=True, capture_output=True)
                self.assertEqual(0, third.returncode, third.stderr)
                self.assertEqual("2", counter.read_text())
            finally:
                fixture.unlink(missing_ok=True)

    def test_cache_miss_requires_ai(self):
        result = codex_budget.decide(self.manifest)
        self.assertTrue(result["should_invoke_ai"])
        self.assertEqual("exact_input_cache_miss", result["reason"])

    def test_exact_marked_result_is_reused_and_content_change_invalidates_it(self):
        result_path = self.root / ".context/result.txt"
        result_path.write_text("validated result", encoding="utf-8")
        codex_budget.mark(self.manifest, ".context/result.txt", validated=True, read_only=True)
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
            codex_budget.mark(self.manifest, "outside.txt", validated=True, read_only=True)

    def test_manifest_cannot_exceed_route_budget(self):
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        value["actual_bytes"] = 5000
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "context budget violation"):
            codex_budget.decide(self.manifest)


    def test_unvalidated_or_stale_result_never_hits(self):
        result_path = self.root / ".context/result.txt"
        result_path.write_text("validated result", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "validated read-only"):
            codex_budget.mark(self.manifest, ".context/result.txt")
        codex_budget.mark(self.manifest, ".context/result.txt", validated=True, read_only=True)
        with mock.patch.object(codex_budget, "_verify_current", side_effect=ValueError("stale")):
            decision = codex_budget.decide(self.manifest)
        self.assertTrue(decision["should_invoke_ai"])
        self.assertIn("current_input_unverified", decision["reason"])

    def test_usage_subsets_and_duplicate_events(self):
        events = [
            {"type": "turn.started"},
            {"type": "turn.completed", "usage": {"input_tokens": 100,
                "cached_input_tokens": 40, "output_tokens": 20,
                "reasoning_output_tokens": 5}},
            {"type": "turn.completed", "usage": {"input_tokens": 100,
                "cached_input_tokens": 40, "output_tokens": 20,
                "reasoning_output_tokens": 5}},
        ]
        usage = codex_budget.normalize_usage(events)
        self.assertEqual(100, usage["input_tokens"])
        self.assertEqual(40, usage["cached_input_tokens"])
        self.assertEqual(20, usage["output_tokens"])
        self.assertEqual(5, usage["reasoning_output_tokens"])
        self.assertEqual(1, usage["turns"])

    def test_context_pack_tamper_is_rejected(self):
        self.pack.write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "context pack integrity mismatch"):
            codex_budget.decide(self.manifest)


if __name__ == "__main__":
    unittest.main()
