import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_m1_review", ROOT / "scripts/repoctl.py")
REPOCTL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(REPOCTL)


class M1ReviewClosureTests(unittest.TestCase):
    def test_ansible_codegen_uses_supported_go_target(self):
        tasks = (ROOT / "platform/ansible/roles/api_codegen/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("api-generate, --target, go", tasks)
        self.assertNotIn("api-generate, --target, all", tasks)

    def test_contract_generation_propagates_codegen_failure(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        contracts = source[source.index("def contracts(") : source.index("def repository_shell_paths(")]
        self.assertIn('result = api_generate("go")', contracts)
        self.assertIn("if result:\n            return result", contracts)
        self.assertNotIn('api_generate("all")', contracts)

        with (
            mock.patch.object(REPOCTL, "require"),
            mock.patch.object(REPOCTL, "run"),
            mock.patch.object(REPOCTL, "run_ruby_tests"),
            mock.patch.object(REPOCTL, "api_generate", return_value=23) as generate,
        ):
            self.assertEqual(23, REPOCTL.contracts(generate=True))
        generate.assert_called_once_with("go")

    def test_frontend_gate_reconciles_go_and_checks_templ_drift_in_temporary_tree(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        frontend = source[source.index("def frontend(") : source.index("def site(")]
        self.assertIn('ensure_developer("go,cgo")', frontend)
        self.assertIn("TemporaryDirectory", frontend)
        self.assertIn("frontend templ generated code is stale", frontend)

    def test_templ_generation_and_drift_use_canonical_pin(self):
        versions = REPOCTL.pinned_versions()
        self.assertEqual("0.3.1020", versions["TEMPL_VERSION"])
        makefile = (ROOT / "frontend/Makefile").read_text(encoding="utf-8")
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        frontend = source[source.index("def frontend(") : source.index("def site(")]
        self.assertIn("TEMPL_VERSION :=", makefile)
        self.assertIn("templ@v$(TEMPL_VERSION)", makefile)
        self.assertIn('pinned_versions().get("TEMPL_VERSION")', frontend)
        self.assertNotIn("templ@v0.", makefile + frontend)

    def test_frontend_tests_cover_shared_packages_once(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        frontend = source[source.index("def frontend(") : source.index("def site(")]
        self.assertIn('["go", "test", "-race", "./..."]', frontend)
        self.assertNotIn('["go", "test", "-race", f"./apps/{target}"]', frontend)

    def test_service_capabilities_follow_selected_workload(self):
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        for service, expected in (("cart", "go,cgo"), ("product", "go,cgo,sqlc,docker")):
            with (
                self.subTest(service=service),
                mock.patch.object(REPOCTL, "canonical_services", return_value=[service]),
                mock.patch.object(REPOCTL, "ensure_developer") as ensure,
                mock.patch.object(REPOCTL, "require"),
                mock.patch.object(
                    REPOCTL,
                    "ruby_yaml",
                    return_value={"sql": [{"gen": {"go": {"out": "internal/infrastructure/postgres/sqlcgen"}}}]},
                ),
                mock.patch.object(REPOCTL, "run", return_value=completed),
            ):
                self.assertEqual(0, REPOCTL.service_check(service))
                ensure.assert_called_once_with(expected)

    def test_site_builds_and_terminates_exact_binaries(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        site = source[source.index("def site(") : source.index("def forbidden_frontend_artifacts(")]
        self.assertIn('["go", "build", "-o"', site)
        self.assertNotIn('"go", "run"', site)
        self.assertIn("process.terminate()", site)
        self.assertIn("signal.SIGTERM", site)

    def test_site_terminates_survivor_when_peer_fails(self):
        class Process:
            def __init__(self, returncode):
                self.returncode = returncode
                self.terminated = False

            def poll(self):
                return self.returncode

            def terminate(self):
                self.terminated = True
                self.returncode = -REPOCTL.signal.SIGTERM

            def wait(self):
                return self.returncode

        storefront = Process(None)
        admin = Process(17)
        with (
            mock.patch.object(REPOCTL, "ensure_developer"),
            mock.patch.object(REPOCTL, "run"),
            mock.patch.object(REPOCTL.subprocess, "Popen", side_effect=[storefront, admin]),
            mock.patch.object(REPOCTL.signal, "signal", return_value=REPOCTL.signal.SIG_DFL),
        ):
            self.assertEqual(17, REPOCTL.site())
        self.assertTrue(storefront.terminated)
        self.assertFalse(admin.terminated)

    def test_site_assigns_distinct_addresses(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        site = source[source.index("def site(") : source.index("def forbidden_frontend_artifacts(")]
        self.assertIn('os.environ.get("STOREFRONT_HTTP_ADDR", ":8080")', site)
        self.assertIn('os.environ.get("ADMIN_HTTP_ADDR", ":8081")', site)
        self.assertIn("env=dict(env, HTTP_ADDR=address)", site)

    def test_frontend_lint_failure_is_propagated(self):
        with (
            mock.patch.object(REPOCTL, "require"),
            mock.patch.object(
                REPOCTL,
                "run",
                return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=""),
            ),
            mock.patch.object(REPOCTL, "automation_policy", return_value=0),
            mock.patch.object(REPOCTL, "frontend", return_value=7),
        ):
            self.assertEqual(7, REPOCTL.lint_all())

    def test_frontend_servers_have_bounded_header_timeouts(self):
        for app in ("storefront", "admin"):
            source = (ROOT / "frontend" / "apps" / app / "main.go").read_text(encoding="utf-8")
            self.assertIn("http.Server{", source)
            self.assertIn("ReadHeaderTimeout: 5 * time.Second", source)
            self.assertNotIn("http.ListenAndServe(", source)

    def test_tekton_component_gate_uses_capability_aware_service_gate(self):
        task = (ROOT / "platform/tekton/tasks/component-gates.yaml").read_text(encoding="utf-8")
        self.assertIn("ci-component", task)
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        service = source[source.index("def service_check(") : source.index("def security(")]
        self.assertNotIn('ensure_developer("go,cgo,sqlc,docker")', service)


if __name__ == "__main__":
    unittest.main()
