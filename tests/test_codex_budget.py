import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
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
        self.identity = {
            "model": "test-model",
            "effort": "low",
            "verified": True,
            "scope": "local-static-read-only",
        }
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "route": "L0",
                    "actual_bytes": len(self.pack.read_bytes()),
                    "max_bytes": 4096,
                    "cache_key": "a" * 64,
                    "head_sha": "b" * 40,
                    "scope_ambiguous": False,
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
        ), mock.patch.object(codex_budget, "effective_identity", return_value=dict(self.identity)), mock.patch.object(
            codex_budget, "decide", return_value={"should_invoke_ai": False,
                "reason": "exact_input_cache_hit", "cached_result": ".context/result.txt"}
        ):
            self.assertEqual(0, codex_budget.run_task(args))
        self.assertEqual(1, len(calls))
        metrics = list((self.root / ".context/codex-budget/metrics").glob("*.json"))
        self.assertEqual(1, len(metrics))
        self.assertEqual(0, json.loads(metrics[0].read_text())["calls"])

    def test_cacheable_entrypoint_overrides_permissive_config_and_blocks_side_effects(self):
        import os
        import subprocess
        root = pathlib.Path(__file__).resolve().parents[1]
        fixture = root / ".context/codex-budget-test-input.txt"
        fixture.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = pathlib.Path(tmp)
            counter = bin_dir / "calls"
            attempted_write = bin_dir / "forbidden-write"
            argv_log = bin_dir / "argv.json"
            codex_home = bin_dir / "codex-home"
            codex_home.mkdir()
            (codex_home / "config.toml").write_text(
                'model = "test-model"\n'
                'model_reasoning_effort = "low"\n'
                'sandbox_mode = "danger-full-access"\n'
                'approval_policy = "never"\n'
                'web_search = "live"\n'
                'notify = ["side-effect"]\n'
                '[features]\n'
                'apps = true\n'
                'hooks = true\n'
                'remote_plugin = true\n'
                '[mcp_servers.side_effect]\n'
                'command = "side-effect"\n'
                '[plugins.side_effect]\n'
                'enabled = true\n',
                encoding="utf-8",
            )
            (codex_home / "AGENTS.md").write_text(
                "stable global instructions\n", encoding="utf-8"
            )
            fake = bin_dir / "codex"
            fake.write_text(
                f"#!{__import__('sys').executable}\n"
                "import json, os, pathlib, sys\n"
                "args=sys.argv[1:]\n"
                "if 'mcp' in args and 'list' in args:\n"
                " overrides={args[i+1] for i,v in enumerate(args[:-1]) if v in ('--config','-c')}\n"
                " disabled='mcp_servers={\\\"side_effect\\\"={enabled=false}}' in overrides\n"
                " print(json.dumps([{'name':'side_effect','enabled':not disabled}]))\n"
                " raise SystemExit(0)\n"
                "sys.stdin.read()\n"
                "pathlib.Path(os.environ['FAKE_CODEX_ARGV']).write_text(json.dumps(args))\n"
                "overrides={args[i+1] for i,v in enumerate(args[:-1]) if v in ('--config','-c')}\n"
                "required={'approval_policy=\\\"never\\\"','web_search=\\\"disabled\\\"',"
                "'features.apps=false',"
                "'features.hooks=false','features.plugins=false','features.remote_plugin=false',"
                "'mcp_servers={\\\"side_effect\\\"={enabled=false}}',"
                "'notify=[]'}\n"
                "read_only='--sandbox' in args and args[args.index('--sandbox')+1]=='read-only'\n"
                "if not read_only or not required.issubset(overrides):\n"
                " pathlib.Path(os.environ['FAKE_FORBIDDEN_WRITE']).write_text('mutated')\n"
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
            env = dict(
                os.environ,
                PATH=f"{bin_dir}:{os.environ['PATH']}",
                CODEX_HOME=str(codex_home),
                FAKE_CODEX_ARGV=str(argv_log),
                FAKE_CODEX_COUNT=str(counter),
                FAKE_FORBIDDEN_WRITE=str(attempted_write),
            )
            argv = [__import__('sys').executable, "scripts/codex_budget.py", "run",
                    "--task", f"summarize fixture {bin_dir.name}", "--paths",
                    ".context/codex-budget-test-input.txt", "--cacheable",
                    "--expect", "answer"]
            try:
                fixture.write_text("version one", encoding="utf-8")
                first = subprocess.run(argv, cwd=root, env=env, text=True, capture_output=True)
                self.assertEqual(0, first.returncode, first.stderr)
                self.assertEqual("1", counter.read_text())
                self.assertFalse(attempted_write.exists())
                built = json.loads(argv_log.read_text())
                self.assertEqual("read-only", built[built.index("--sandbox") + 1])
                self.assertIn("--ephemeral", built)
                second = subprocess.run(argv, cwd=root, env=env, text=True, capture_output=True)
                self.assertEqual(0, second.returncode, second.stderr)
                self.assertEqual("1", counter.read_text())
                (codex_home / "AGENTS.override.md").write_text(
                    "priority global instructions\n", encoding="utf-8"
                )
                third = subprocess.run(argv, cwd=root, env=env, text=True, capture_output=True)
                self.assertEqual(0, third.returncode, third.stderr)
                self.assertEqual("2", counter.read_text())
                fourth = subprocess.run(argv, cwd=root, env=env, text=True, capture_output=True)
                self.assertEqual(0, fourth.returncode, fourth.stderr)
                self.assertEqual("2", counter.read_text())
            finally:
                fixture.unlink(missing_ok=True)

    def test_ambiguous_scope_rejected_from_generation_through_cache_lookup(self):
        source = pathlib.Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            checkout = pathlib.Path(tmp) / "checkout"
            subprocess.run(["git", "clone", "-q", "--shared", str(source), str(checkout)], check=True)
            for relative in (
                "scripts/context-pack.py",
                "scripts/codex_budget.py",
                "scripts/codex_instruction_identity.py",
            ):
                target = checkout / relative
                shutil.copy2(source / relative, target)
                with target.open("a", encoding="utf-8") as stream:
                    stream.write("\n# ambiguous scope fixture\n")

            pack = checkout / ".context/ambiguous.md"
            manifest_path = checkout / ".context/ambiguous.json"
            generated = subprocess.run(
                [sys.executable, "scripts/context-pack.py", "--task", "summarize",
                 "--output", ".context/ambiguous.md", "--manifest", ".context/ambiguous.json"],
                cwd=checkout, text=True, capture_output=True,
            )
            self.assertEqual(0, generated.returncode, generated.stderr)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(3, manifest["candidate_paths"])
            self.assertEqual([], manifest["relevant_paths"])
            self.assertTrue(manifest["scope_ambiguous"])
            self.assertFalse(manifest["truncated"])
            self.assertIn("SCOPE_UNRESOLVED", pack.read_text(encoding="utf-8"))

            result = checkout / ".context/answer.txt"
            result.write_text("validated answer", encoding="utf-8")
            with mock.patch.object(codex_budget, "ROOT", checkout), mock.patch.object(
                codex_budget, "CONTRACT", checkout / "config/contracts/codex-token-budget.json"
            ):
                identity = codex_budget.effective_identity(
                    "ecommerce-minimal", "", "", ""
                )
                identity["scope"] = "local-static-read-only"
                marker_path = codex_budget._cache_path(manifest["cache_key"], identity)
            recorded = subprocess.run(
                [sys.executable, "scripts/codex_budget.py", "mark",
                 "--manifest", str(manifest_path), "--result", ".context/answer.txt",
                 "--validated", "--read-only"],
                cwd=checkout, text=True, capture_output=True,
            )
            self.assertNotEqual(0, recorded.returncode)
            self.assertIn("ambiguous context scope", recorded.stderr)
            self.assertFalse(marker_path.exists())

            marker_path.parent.mkdir(parents=True, exist_ok=True)
            marker_path.write_text(json.dumps({
                "schema_version": 2, "status": "COMPLETE_VALIDATED",
                "cache_key": manifest["cache_key"], "identity": identity,
                "head_sha": manifest["head_sha"], "result_path": ".context/answer.txt",
                "result_sha256": hashlib.sha256(result.read_bytes()).hexdigest(),
            }), encoding="utf-8")
            lookup = subprocess.run(
                [sys.executable, "scripts/codex_budget.py", "decide",
                 "--manifest", str(manifest_path)],
                cwd=checkout, text=True, capture_output=True,
            )
            self.assertEqual(0, lookup.returncode, lookup.stderr)
            decision = json.loads(lookup.stdout)
            self.assertTrue(decision["should_invoke_ai"])
            self.assertEqual("ambiguous_scope", decision["reason"])
            self.assertEqual("", decision["cached_result"])

            binary = pathlib.Path(tmp) / "bin"
            binary.mkdir()
            fake_codex = binary / "codex"
            fake_codex.write_text(
                f"#!{sys.executable}\n"
                "import json, sys\n"
                "sys.stdin.read()\n"
                "if 'mcp' in sys.argv and 'list' in sys.argv:\n"
                " print('[]')\n"
                " raise SystemExit(0)\n"
                "for event in ({'type':'turn.started'},"
                "{'type':'item.completed','item':{'type':'agent_message','text':'answer'}},"
                "{'type':'turn.completed','usage':{'input_tokens':1,'output_tokens':1}}):"
                " print(json.dumps(event))\n",
                encoding="utf-8",
            )
            fake_codex.chmod(0o755)
            env = dict(os.environ, PATH=f"{binary}:{os.environ['PATH']}")
            run = subprocess.run(
                [sys.executable, "scripts/codex_budget.py", "run",
                 "--task", "summarize", "--cacheable", "--expect", "answer"],
                cwd=checkout, env=env, text=True, capture_output=True,
            )
            self.assertEqual(0, run.returncode, run.stderr)
            metrics = list((checkout / ".context/codex-budget/metrics").glob("*.json"))
            self.assertEqual(1, len(metrics))
            self.assertEqual("ambiguous_scope", json.loads(metrics[0].read_text())["cache"])
            self.assertEqual([marker_path], list(marker_path.parent.glob("*.json")))

    def test_missing_ambiguity_signal_is_not_cacheable(self):
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        value.pop("scope_ambiguous")
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        self.assertEqual(
            "ambiguous_scope",
            codex_budget.decide(self.manifest, self.identity)["reason"],
        )
        result = self.root / ".context/result.txt"
        result.write_text("answer", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "ambiguous context scope"):
            codex_budget.mark(
                self.manifest,
                ".context/result.txt",
                identity=self.identity,
                validated=True,
                read_only=True,
            )

    def test_project_config_changes_identity_and_precedes_profile(self):
        home = self.root / "home"
        user_dir = home / ".codex"
        project_dir = self.root / ".codex"
        user_dir.mkdir(parents=True)
        project_dir.mkdir()
        (user_dir / "config.toml").write_text(
            f'model = "user-model"\n[projects."{self.root}"]\ntrust_level = "trusted"\n',
            encoding="utf-8",
        )
        (user_dir / "ecommerce-minimal.config.toml").write_text(
            'model = "profile-model"\nmodel_reasoning_effort = "low"\n', encoding="utf-8"
        )
        project = project_dir / "config.toml"
        project.write_text('model = "project-model"\nmodel_reasoning_effort = "high"\n', encoding="utf-8")
        with mock.patch.object(pathlib.Path, "home", return_value=home):
            first = codex_budget.effective_identity("ecommerce-minimal", "", "", "answer")
            project.write_text('model = "project-model"\nmodel_reasoning_effort = "high"\ntool_output_token_limit = 1000\n', encoding="utf-8")
            second = codex_budget.effective_identity("ecommerce-minimal", "", "", "answer")
            explicit = codex_budget.effective_identity("ecommerce-minimal", "cli-model", "medium", "answer")
        self.assertEqual(("project-model", "high"), (first["model"], first["effort"]))
        self.assertNotEqual(first["config_digest"], second["config_digest"])
        self.assertEqual(("cli-model", "medium"), (explicit["model"], explicit["effort"]))
        self.assertTrue(first["verified"])

    def test_alternate_codex_home_changes_effective_identity(self):
        codex_home = self.root / "alternate-codex-home"
        codex_home.mkdir()
        config = codex_home / "config.toml"
        config.write_text(
            'model = "base-model"\nmodel_reasoning_effort = "low"\n',
            encoding="utf-8",
        )
        profile = codex_home / "ecommerce-minimal.config.toml"
        profile.write_text('model = "first-model"\n', encoding="utf-8")
        instructions = codex_home / "AGENTS.md"
        instructions.write_text("first instructions\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
            first = codex_budget.effective_identity("ecommerce-minimal", "", "", "answer")
            profile.write_text('model = "second-model"\n', encoding="utf-8")
            instructions.write_text("second instructions\n", encoding="utf-8")
            second = codex_budget.effective_identity("ecommerce-minimal", "", "", "answer")
        self.assertEqual("first-model", first["model"])
        self.assertEqual("second-model", second["model"])
        self.assertNotEqual(first["config_digest"], second["config_digest"])
        self.assertNotEqual(first["instruction_digest"], second["instruction_digest"])
        self.assertTrue(first["verified"])

    def test_effective_identity_tracks_global_override_lifecycle(self):
        codex_home = self.root / "codex-home"
        codex_home.mkdir()
        (codex_home / "config.toml").write_text(
            'model = "test-model"\nmodel_reasoning_effort = "low"\n',
            encoding="utf-8",
        )
        normal = codex_home / "AGENTS.md"
        override = codex_home / "AGENTS.override.md"
        normal.write_text("normal instructions\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
            normal_identity = codex_budget.effective_identity(
                "ecommerce-minimal", "", "", "answer"
            )
            override.write_text("override one\n", encoding="utf-8")
            created_identity = codex_budget.effective_identity(
                "ecommerce-minimal", "", "", "answer"
            )
            override.write_text("override two\n", encoding="utf-8")
            modified_identity = codex_budget.effective_identity(
                "ecommerce-minimal", "", "", "answer"
            )
            override.unlink()
            removed_identity = codex_budget.effective_identity(
                "ecommerce-minimal", "", "", "answer"
            )
        self.assertNotEqual(
            normal_identity["instruction_digest"], created_identity["instruction_digest"]
        )
        self.assertNotEqual(
            created_identity["instruction_digest"], modified_identity["instruction_digest"]
        )
        self.assertNotEqual(
            modified_identity["instruction_digest"], removed_identity["instruction_digest"]
        )
        self.assertEqual(
            normal_identity["instruction_digest"], removed_identity["instruction_digest"]
        )

    def test_invalid_instruction_fallback_configuration_is_not_verified(self):
        codex_home = self.root / "codex-home"
        codex_home.mkdir()
        (codex_home / "config.toml").write_text(
            'model = "test-model"\n'
            'model_reasoning_effort = "low"\n'
            'project_doc_fallback_filenames = "TEAM_GUIDE.md"\n',
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
            identity = codex_budget.effective_identity(
                "ecommerce-minimal", "", "", "answer"
            )
        self.assertFalse(identity["verified"])
        self.assertEqual("UNVERIFIED", identity["instruction_digest"])

    def test_unknown_identity_cannot_be_marked_or_reused(self):
        codex_home = self.root / "empty-codex-home"
        codex_home.mkdir()
        with (
            mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}),
            mock.patch.object(codex_budget, "_read_toml", return_value={}),
        ):
            unknown = codex_budget.effective_identity(
                "ecommerce-minimal", "", "", "answer"
            )
        self.assertFalse(unknown["verified"])
        decision = codex_budget.decide(self.manifest, unknown)
        self.assertTrue(decision["should_invoke_ai"])
        self.assertEqual("unverified_identity", decision["reason"])
        result = self.root / ".context/result.txt"
        result.write_text("answer", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unverified Codex identity"):
            codex_budget.mark(
                self.manifest,
                ".context/result.txt",
                identity=unknown,
                validated=True,
                read_only=True,
            )

    def test_only_cacheable_runs_force_read_only_and_disable_external_tools(self):
        import types

        reusable = types.SimpleNamespace(
            profile="ecommerce-minimal", model="", effort="", cacheable=True
        )
        normal = types.SimpleNamespace(
            profile="ecommerce-minimal", model="", effort="", cacheable=False
        )
        mcp_overrides = ('mcp_servers."side.effect".enabled=false',)
        reusable_argv = codex_budget.codex_exec_argv(
            reusable, mcp_disable_overrides=mcp_overrides
        )
        normal_argv = codex_budget.codex_exec_argv(normal)
        self.assertEqual(
            "read-only",
            reusable_argv[reusable_argv.index("--sandbox") + 1],
        )
        self.assertIn("--ephemeral", reusable_argv)
        overrides = {
            reusable_argv[index + 1]
            for index, value in enumerate(reusable_argv[:-1])
            if value == "--config"
        }
        self.assertEqual(
            {*codex_budget.CACHEABLE_CODEX_OVERRIDES, *mcp_overrides}, overrides
        )
        self.assertNotIn("mcp_servers={}", overrides)
        self.assertNotIn("--sandbox", normal_argv)
        self.assertNotIn("--ephemeral", normal_argv)

    def test_cacheable_argv_requires_verified_mcp_catalog(self):
        import types

        reusable = types.SimpleNamespace(
            profile="ecommerce-minimal", model="", effort="", cacheable=True
        )
        with self.assertRaisesRegex(ValueError, "verified MCP catalog"):
            codex_budget.codex_exec_argv(reusable)

    def test_installed_codex_loader_disables_inherited_mcp_server(self):
        codex = shutil.which("codex")
        self.assertIsNotNone(codex, "managed Codex CLI is required")
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = pathlib.Path(tmp)
            (codex_home / "config.toml").write_text(
                '[mcp_servers."inherited.probe"]\n'
                'command = "/bin/false"\n'
                'enabled = true\n',
                encoding="utf-8",
            )
            (codex_home / "ecommerce-minimal.config.toml").write_text(
                "# synthetic profile\n", encoding="utf-8"
            )
            with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
                inherited = codex_budget._mcp_catalog("ecommerce-minimal")
                empty_table = codex_budget._mcp_catalog(
                    "ecommerce-minimal", ("mcp_servers={}",)
                )
                overrides = codex_budget.verified_mcp_disable_overrides(
                    "ecommerce-minimal"
                )
                disabled = codex_budget._mcp_catalog(
                    "ecommerce-minimal", overrides
                )
        self.assertEqual({"inherited.probe": True}, inherited)
        self.assertEqual({"inherited.probe": True}, empty_table)
        self.assertEqual(
            ('mcp_servers={"inherited.probe"={enabled=false}}',), overrides
        )
        self.assertEqual({"inherited.probe": False}, disabled)

    def test_indeterminate_mcp_catalog_blocks_cacheable_run_before_model(self):
        import types

        args = types.SimpleNamespace(
            task="static summary", since="", staged=False, paths=[],
            profile="ecommerce-minimal", model="", effort="", expect="answer",
            cacheable=True, timeout=30,
        )

        def prepare(argv, **_kwargs):
            pack = self.root / argv[argv.index("--output") + 1]
            manifest = self.root / argv[argv.index("--manifest") + 1]
            pack.parent.mkdir(parents=True, exist_ok=True)
            pack.write_text("task pack", encoding="utf-8")
            manifest.write_text(json.dumps({
                "route": "L0", "actual_bytes": 9, "estimated_input_tokens": 3,
            }), encoding="utf-8")
            return types.SimpleNamespace(returncode=0, stderr="")

        with mock.patch.object(
            codex_budget.subprocess, "run", side_effect=prepare
        ) as run, mock.patch.object(
            codex_budget, "effective_identity", return_value=dict(self.identity)
        ), mock.patch.object(
            codex_budget, "decide", return_value={
                "should_invoke_ai": True, "reason": "exact_input_cache_miss",
            }
        ), mock.patch.object(
            codex_budget, "verified_mcp_disable_overrides",
            side_effect=RuntimeError("Codex MCP catalog is indeterminate"),
        ):
            with self.assertRaisesRegex(RuntimeError, "indeterminate"):
                codex_budget.run_task(args)
        self.assertEqual(1, run.call_count)

    def test_line_truncated_pack_cannot_be_cached(self):
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        value["truncated"] = True
        value["omitted_diff_lines"] = 40
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        decision = codex_budget.decide(self.manifest, self.identity)
        self.assertTrue(decision["should_invoke_ai"])
        self.assertEqual("incomplete_context", decision["reason"])
        result = self.root / ".context/result.txt"
        result.write_text("answer", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "truncated context"):
            codex_budget.mark(
                self.manifest,
                ".context/result.txt",
                identity=self.identity,
                validated=True,
                read_only=True,
            )

    def test_cache_miss_requires_ai(self):
        result = codex_budget.decide(self.manifest, self.identity)
        self.assertTrue(result["should_invoke_ai"])
        self.assertEqual("exact_input_cache_miss", result["reason"])

    def test_exact_marked_result_is_reused_and_content_change_invalidates_it(self):
        result_path = self.root / ".context/result.txt"
        result_path.write_text("validated result", encoding="utf-8")
        codex_budget.mark(
            self.manifest,
            ".context/result.txt",
            identity=self.identity,
            validated=True,
            read_only=True,
        )
        hit = codex_budget.decide(self.manifest, self.identity)
        self.assertFalse(hit["should_invoke_ai"])
        self.assertEqual("exact_input_cache_hit", hit["reason"])
        self.assertEqual(".context/result.txt", hit["cached_result"])

        result_path.write_text("changed result", encoding="utf-8")
        miss = codex_budget.decide(self.manifest, self.identity)
        self.assertTrue(miss["should_invoke_ai"])

    def test_result_outside_context_is_rejected(self):
        outside = self.root / "outside.txt"
        outside.write_text("no", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must remain under .context"):
            codex_budget.mark(
                self.manifest,
                "outside.txt",
                identity=self.identity,
                validated=True,
                read_only=True,
            )

    def test_manifest_cannot_exceed_route_budget(self):
        value = json.loads(self.manifest.read_text(encoding="utf-8"))
        value["actual_bytes"] = 5000
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "context budget violation"):
            codex_budget.decide(self.manifest, self.identity)


    def test_unvalidated_or_stale_result_never_hits(self):
        result_path = self.root / ".context/result.txt"
        result_path.write_text("validated result", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "validated read-only"):
            codex_budget.mark(
                self.manifest,
                ".context/result.txt",
                identity=self.identity,
            )
        codex_budget.mark(
            self.manifest,
            ".context/result.txt",
            identity=self.identity,
            validated=True,
            read_only=True,
        )
        with mock.patch.object(codex_budget, "_verify_current", side_effect=ValueError("stale")):
            decision = codex_budget.decide(self.manifest, self.identity)
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
            codex_budget.decide(self.manifest, self.identity)


if __name__ == "__main__":
    unittest.main()
