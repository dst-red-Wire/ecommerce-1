import importlib.util
from pathlib import Path
from unittest import mock
import unittest


ROOT = Path(__file__).resolve().parents[2]


class FastFailureContractTest(unittest.TestCase):
    def test_preflight_precedes_expensive_governance(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        gates = source.split("def _global_gate_commands", 1)[1].split("\ndef ", 1)[0]
        self.assertLess(gates.index('("preflight"'), gates.index('("governance"'))

    def test_preflight_checks_capabilities_and_changed_syntax(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        body = source.split("def preflight", 1)[1].split("\ndef ", 1)[0]
        for marker in ('"gitleaks"', '"go"', '"terraform"', 'requirements["ansible"]', '"py_compile"', '"ruby", "-c"'):
            self.assertIn(marker, body)

    def test_missing_global_contract_tool_fails_before_source_checks(self):
        spec = importlib.util.spec_from_file_location("preflight_closure_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        def require(name):
            if name == "oasdiff":
                raise RuntimeError("missing oasdiff")

        with (
            mock.patch.object(module, "_reject_staged_symlinks", return_value=0),
            mock.patch.object(module, "affected", return_value=["global"]),
            mock.patch.object(module, "require", side_effect=require),
            mock.patch.object(module, "changed_paths", return_value=[]),
            mock.patch.object(module, "run") as commands,
        ):
            with self.assertRaisesRegex(RuntimeError, "missing oasdiff"):
                module.preflight("base", "head")
            commands.assert_not_called()

    def test_missing_ansible_galaxy_is_detected_from_component_contract(self):
        spec = importlib.util.spec_from_file_location("preflight_ansible_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        def require(name):
            if name == "ansible-galaxy":
                raise RuntimeError("missing ansible-galaxy")

        with (
            mock.patch.object(module, "_reject_staged_symlinks", return_value=0),
            mock.patch.object(module, "affected", return_value=["platform:ansible"]),
            mock.patch.object(module, "changed_paths", return_value=[]),
            mock.patch.object(module, "require", side_effect=require),
        ):
            with self.assertRaisesRegex(RuntimeError, "missing ansible-galaxy"):
                module.preflight("base", "head")

    def test_frontend_preflight_uses_declared_runner_contract(self):
        import json
        import tempfile

        spec = importlib.util.spec_from_file_location("preflight_frontend_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for standalone in (False, True):
            with self.subTest(standalone=standalone), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                contract = json.loads((ROOT / "config/toolchain/capabilities.json").read_text())
                contract["gate_requirements"].pop("frontend", None)
                if standalone:
                    contract["gate_requirements"]["frontend"] = ["go", "gofmt", "cc", "templ"]
                path = root / "config/toolchain/capabilities.json"
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(contract))
                with (
                    mock.patch.object(module, "ROOT", root),
                    mock.patch.object(module, "_reject_staged_symlinks", return_value=0),
                    mock.patch.object(module, "affected", return_value=["frontend:all"]),
                    mock.patch.object(module, "changed_paths", return_value=[]),
                    mock.patch.object(module, "require") as require,
                    mock.patch.object(module, "run", return_value=mock.Mock(returncode=0)),
                ):
                    self.assertEqual(0, module.preflight("base", "head"))
                commands = {call.args[0] for call in require.call_args_list}
                self.assertEqual(standalone, "templ" in commands)
                self.assertTrue({"go", "gofmt", "cc"}.issubset(commands))

    def test_corepack_pnpm_provider_does_not_require_a_pnpm_executable(self):
        spec = importlib.util.spec_from_file_location("preflight_provider_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        def require(name):
            if name == "pnpm":
                raise RuntimeError("no standalone pnpm")
            return name

        for code in (0, 1):
            with (
                self.subTest(code=code),
                mock.patch.object(module, "_reject_staged_symlinks", return_value=0),
                mock.patch.object(module, "affected", return_value=["global"]),
                mock.patch.object(module, "changed_paths", return_value=[]),
                mock.patch.object(module, "require", side_effect=require),
                mock.patch.object(module, "run", return_value=mock.Mock(returncode=code)) as probe,
            ):
                if code:
                    with self.assertRaisesRegex(RuntimeError, "through its provider"):
                        module.preflight("base", "head")
                else:
                    self.assertEqual(0, module.preflight("base", "head"))
                self.assertTrue(any(call.args[0] == ["corepack", "pnpm", "--version"] for call in probe.call_args_list))

    def test_service_prerequisites_follow_sqlc_and_container_usage(self):
        import tempfile

        spec = importlib.util.spec_from_file_location("preflight_service_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for sqlc, containers in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(sqlc=sqlc, containers=containers), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = root / "config/toolchain/capabilities.json"
                config.parent.mkdir(parents=True)
                config.write_bytes((ROOT / "config/toolchain/capabilities.json").read_bytes())
                service = root / "services/billing"
                service.mkdir(parents=True)
                (service / "go.mod").touch()
                if sqlc:
                    (service / "sqlc.yaml").touch()
                if containers:
                    (service / "container_test.go").write_text("// testcontainers\n")
                with (
                    mock.patch.object(module, "ROOT", root),
                    mock.patch.object(module, "_reject_staged_symlinks", return_value=0),
                    mock.patch.object(module, "affected", return_value=["service:billing"]),
                    mock.patch.object(module, "changed_paths", return_value=[]),
                    mock.patch.object(module, "run", return_value=mock.Mock(returncode=0)),
                    mock.patch.object(module, "require") as require,
                ):
                    self.assertEqual(0, module.preflight("base", "head"))
                required = {call.args[0] for call in require.call_args_list}
                for name in ("sqlc", "diff"):
                    self.assertEqual(sqlc, name in required)
                for name in ("docker", "sysctl"):
                    self.assertEqual(containers, name in required)

    def test_diff_context_serializes_non_utf8_paths_and_output(self):
        import os
        import tempfile

        spec = importlib.util.spec_from_file_location("binary_context_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        raw = os.fsdecode(b"scripts/bad\xff.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(module, "ROOT", root),
                mock.patch.object(module, "CONTEXT", root / ".context"),
                mock.patch.object(module, "changed_paths", return_value=[raw]),
                mock.patch.object(module, "git", return_value=raw),
            ):
                self.assertEqual(0, module.diff_context("base"))
            self.assertIn("\\udcff", (root / ".context/diff.md").read_text(encoding="utf-8"))

    def test_changed_paths_preserve_literal_newlines(self):
        spec = importlib.util.spec_from_file_location("preflight_nul_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        name = "scripts/line\nbreak.py"
        for head in ("HEAD", "WORKTREE"):
            with self.subTest(head=head), mock.patch.object(module, "git", return_value=name + "\0") as git:
                self.assertEqual([name], module.changed_paths("base", head))
                self.assertTrue(all("-z" in call.args for call in git.call_args_list))

    def test_subprocess_preserves_non_utf8_git_path_bytes(self):
        import os
        import sys

        spec = importlib.util.spec_from_file_location("preflight_binary_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        raw = b"scripts/bad\xff.py\0"
        result = module.run([sys.executable, "-c", f"import sys; sys.stdout.buffer.write({raw!r})"], capture=True)
        with mock.patch.object(module, "git", return_value=result.stdout):
            self.assertEqual([raw[:-1]], [os.fsencode(path) for path in module.changed_paths("base", "WORKTREE")])

    def test_source_diagnostics_never_escape_preflight(self):
        import subprocess
        import sys
        import tempfile

        probe = """import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('preflight_log_probe', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.ROOT = Path(sys.argv[2])
module._reject_staged_symlinks = lambda: 0
module.affected = lambda *args: ['global']
module.changed_paths = lambda *args: [sys.argv[3]]
module.require = lambda name: name
try:
    module.preflight('base', 'WORKTREE')
except RuntimeError as error:
    print(error, file=sys.stderr)
    sys.exit(1)
"""
        for name in ("source.py", "source.rb"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                contract = root / "config/toolchain/capabilities.json"
                contract.parent.mkdir(parents=True)
                contract.write_bytes((ROOT / "config/toolchain/capabilities.json").read_bytes())
                sentinel = "NOT_A_REAL_SECRET"
                (root / name).write_text(f'value = "{sentinel}" +\n')
                result = subprocess.run(
                    [sys.executable, "-c", probe, str(ROOT / "scripts/repoctl.py"), str(root), name],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(1, result.returncode, result.stdout + result.stderr)
                self.assertIn("source diagnostics suppressed", result.stderr)
                self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_tofu_only_runner_passes_preflight(self):
        spec = importlib.util.spec_from_file_location("preflight_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with (
            mock.patch.object(module, "affected", return_value=["platform:terraform"]),
            mock.patch.object(module, "changed_paths", return_value=[]),
            mock.patch.object(module.shutil, "which", side_effect=lambda name: "/bin/tofu" if name == "tofu" else None),
            mock.patch.object(module, "require") as require,
        ):
            self.assertEqual(0, module.preflight("base", "head"))
            self.assertIn(mock.call("tofu"), require.call_args_list)
            self.assertNotIn(mock.call("terraform"), require.call_args_list)

    def test_tekton_classification_depends_on_preflight(self):
        import yaml

        task = yaml.safe_load((ROOT / "platform/tekton/tasks/affected-components.yaml").read_text())
        self.assertEqual(["preflight", "classify"], [step["name"] for step in task["spec"]["steps"]])
        pipeline = yaml.safe_load((ROOT / "platform/tekton/pipelines/affected.yaml").read_text())
        for task in pipeline["spec"]["tasks"]:
            if task["name"] in ("global-gates", "affected-component-gates"):
                self.assertEqual(["classify"], task["runAfter"])

    def test_preflight_is_in_global_timing_inventory(self):
        spec = importlib.util.spec_from_file_location("preflight_perf_test", ROOT / "scripts/performance_audit.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        timing = module.tekton_critical_path(
            [
                {"gate": "preflight", "status": "PASS", "duration_seconds": 7},
                {"gate": "governance", "status": "PASS", "duration_seconds": 5},
                {"gate": "system", "status": "PASS", "duration_seconds": 10},
            ]
        )
        self.assertEqual(7, timing["preflight_serial_seconds"])
        self.assertEqual(5, timing["global_branch_seconds"])
        self.assertEqual(17, timing["critical_path_estimate_seconds"])

    def test_recorded_preflight_is_counted_once_and_rejects_wrong_identity(self):
        import json
        import tempfile

        spec = importlib.util.spec_from_file_location("preflight_record_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        executed = []

        def gate(name, command, records, env):
            executed.append(name)
            records.append({"gate": name, "status": "PASS", "duration_seconds": 7 if name == "preflight" else 1})
            return True

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                module.os.environ, {"CI_PREFLIGHT_RUN_ID": "run-1", "CI_RUNNER_IMAGE": "runner@sha256:abc"}
            ),
            mock.patch.object(module, "_require_clean_exact_checkout", return_value=("head-sha", "head-sha")),
            mock.patch.object(
                module, "git", side_effect=lambda *args: "tree-sha" if args[-1].endswith("^{tree}") else "base-sha"
            ),
            mock.patch.object(module, "_run_gate", side_effect=gate),
        ):
            self.assertEqual(0, module.ci_preflight("base", "head", directory))
            with mock.patch.object(module.time, "time", return_value=-36000):
                self.assertEqual(0, module.ci_global("base", "head", directory))
            self.assertEqual(1, executed.count("preflight"))
            records = json.loads((Path(directory) / "global.json").read_text())["records"]
            self.assertEqual(1, sum(row["gate"] == "preflight" for row in records))
            self.assertEqual(7, records[0]["duration_seconds"])
            path = Path(directory) / "preflight.json"
            original = json.loads(path.read_text())
            for field in ("head_sha", "base_sha", "head_tree_sha", "pipeline_run_id", "runner_image"):
                with self.subTest(field=field):
                    path.write_text(json.dumps({**original, field: "wrong"}))
                    executed.clear()
                    self.assertEqual(1, module.ci_global("base", "head", directory))
                    self.assertEqual([], executed)
            path.write_text('{"records": null}')
            self.assertEqual(1, module.ci_global("base", "head", directory))
            path.unlink()
            self.assertEqual(0, module.ci_global("base", "head", directory))
            self.assertEqual(1, executed.count("preflight"))

    def test_syntax_paths_are_literal_and_external_symlinks_are_rejected(self):
        import tempfile

        spec = importlib.util.spec_from_file_location("preflight_paths_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory)
            contract = root / "config/toolchain/capabilities.json"
            contract.parent.mkdir(parents=True)
            contract.write_bytes((ROOT / "config/toolchain/capabilities.json").read_bytes())
            for name, content in (
                ("-eexit;#.rb", "def broken(\n"),
                ("--stdin-filename=x.py", "undefined_name()\n"),
                ("line\nbreak.py", "def broken(\n"),
            ):
                with self.subTest(name=name):
                    (root / name).write_text(content)
                    with (
                        mock.patch.object(module, "ROOT", root),
                        mock.patch.object(module, "_reject_staged_symlinks", return_value=0),
                        mock.patch.object(module, "affected", return_value=["global"]),
                        mock.patch.object(module, "changed_paths", return_value=[name]),
                    ):
                        with self.assertRaises(RuntimeError):
                            module.preflight("base", "head")
            target = Path(external) / "private.py"
            target.write_text("private_fixture\n")
            (root / "link.py").symlink_to(target)
            with (
                mock.patch.object(module, "ROOT", root),
                mock.patch.object(module, "_reject_staged_symlinks", return_value=0),
                mock.patch.object(module, "affected", return_value=["global"]),
                mock.patch.object(module, "changed_paths", return_value=["link.py"]),
                mock.patch.object(module, "run") as run,
            ):
                self.assertEqual(1, module.preflight("base", "head"))
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
