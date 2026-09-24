import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl", ROOT / "scripts/repoctl.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class DeveloperStateFastPathTest(unittest.TestCase):
    def test_ruby_runner_prerequisite_present_is_returned(self):
        with mock.patch.object(MOD.shutil, "which", return_value="/usr/bin/ruby"):
            self.assertEqual("/usr/bin/ruby", MOD.require("ruby"))

    def test_missing_ruby_raises_blocked_runner_prerequisite(self):
        with mock.patch.object(MOD.shutil, "which", return_value=None):
            with self.assertRaisesRegex(MOD.MissingRunnerPrerequisite, "runner prerequisite missing: ruby"):
                MOD.require("ruby")

    def test_terraform_check_prefers_tofu_when_both_providers_exist(self):
        calls = []
        policy = {
            "formatter": {
                "executable_preference": ["tofu", "terraform"],
                "args": ["fmt", "-check", "-recursive", "-diff"],
                "drift_exit_codes": [3],
            },
            "validation": {
                "provider_lock_authority": "architecture.lock.yaml#machine_contracts.terraform_provider_lock",
            },
        }
        provider_lock = {
            "providers": {
                "hcloud": {
                    "source": "registry.terraform.io/hetznercloud/hcloud",
                    "version": "1.68.0",
                    "constraints": "1.68.0",
                    "hashes": ["h1:test", "zh:test"],
                }
            },
            "qualification": {
                "init_args": ["init", "-backend=false", "-input=false", "-lockfile=readonly"],
                "validate_args": ["validate"],
                "provider_plugin_cache": {},
                "repository_context_paths": ["config/infrastructure"],
            },
        }

        def fake_which(command):
            return {"tofu": "/opt/bin/tofu", "terraform": "/opt/bin/terraform"}.get(command)

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        with (
            mock.patch.object(
                pathlib.Path,
                "rglob",
                return_value=[MOD.ROOT / "platform/terraform/example.tf"],
            ),
            mock.patch.object(MOD, "source_quality_adapter", return_value=policy),
            mock.patch.object(MOD, "terraform_provider_lock_contract", return_value=provider_lock),
            mock.patch.object(MOD, "terraform_provider_plugin_cache_dir", return_value=None),
            mock.patch.object(MOD.shutil, "which", side_effect=fake_which),
            mock.patch.object(MOD, "run", side_effect=fake_run),
        ):
            self.assertEqual(0, MOD.terraform_check())

        self.assertTrue(calls)
        self.assertTrue(all(call[0] == "/opt/bin/tofu" for call in calls))

    def test_terraform_provider_lock_is_central_and_exact(self):
        contract = MOD.terraform_provider_lock_contract()
        self.assertEqual("architecture.lock.yaml", contract["architecture_authority"])
        self.assertEqual("platform/terraform", contract["scope"])
        self.assertEqual("exact", contract["status"])

        provider = contract["providers"]["hcloud"]
        self.assertEqual("registry.terraform.io/hetznercloud/hcloud", provider["source"])
        self.assertEqual("1.68.0", provider["version"])
        self.assertEqual("1.68.0", provider["constraints"])
        self.assertTrue(any(value.startswith("h1:") for value in provider["hashes"]))
        self.assertTrue(any(value.startswith("zh:") for value in provider["hashes"]))

        qualification = contract["qualification"]
        self.assertEqual("non-authoritative", qualification["repository_lockfiles"]["authority"])
        self.assertFalse(qualification["repository_lockfiles"]["qualification_input"])
        self.assertIn("-lockfile=readonly", qualification["init_args"])
        self.assertEqual(["config/infrastructure"], qualification["repository_context_paths"])

    def test_terraform_native_lockfile_is_generated_from_central_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".terraform.lock.hcl"
            MOD.write_terraform_provider_lock(path)
            text = path.read_text(encoding="utf-8")

        self.assertIn('provider "registry.terraform.io/hetznercloud/hcloud"', text)
        self.assertIn('version     = "1.68.0"', text)
        self.assertIn('constraints = "1.68.0"', text)
        self.assertIn("h1:KOFp1JbzZ6Xj2K80QL7HGJM6oG+oEo7tx3lIx3d5POM=", text)


    def test_source_quality_policy_is_central_repository_authority(self):
        policy = MOD.source_quality_policy()
        self.assertEqual("architecture.lock.yaml", policy["architecture_authority"])
        self.assertEqual("entire-repository", policy["scope"])
        self.assertEqual("advisory", policy["principles"]["formatter_drift"])
        self.assertEqual("blocking", policy["principles"]["syntax_validation"])
        self.assertEqual("blocking", policy["principles"]["semantic_validation"])
        self.assertEqual("forbidden", policy["principles"]["file_specific_quality_exceptions"])
        self.assertEqual(
            "delegated-to-repository-authority-model",
            policy["principles"]["parallel_local_quality_policy"],
        )

        pre_commit = policy["orchestration_adapters"]["pre_commit"]
        self.assertEqual(".pre-commit-config.yaml", pre_commit["path"])
        self.assertIn(
            pre_commit["required_delegate"],
            (ROOT / pre_commit["path"]).read_text(encoding="utf-8"),
        )

        advisory = set(policy["adapters"]["ansible"]["lint"]["advisory_rules"])
        self.assertTrue(
            {"partial-become", "latest[git]", "no-handler", "yaml[empty-lines]"}.issubset(advisory)
        )
        self.assertEqual(
            "architecture.lock.yaml#machine_contracts.terraform_provider_lock",
            policy["adapters"]["terraform"]["validation"]["provider_lock_authority"],
        )

    def test_repository_maximal_authority_model_is_root(self):
        model = MOD.repository_authority_model()
        self.assertEqual("architecture.lock.yaml", model["architecture_authority"])
        self.assertEqual("entire-repository", model["scope"])
        self.assertEqual("architecture.lock.yaml", model["principle"]["one_root_authority"])
        self.assertEqual("central-contract-only", model["principle"]["cross_cutting_policy"])

        domains = model["domains"]
        self.assertEqual("source_quality_policy", domains["source_quality"]["machine_contract"])
        self.assertEqual("toolchain_lock", domains["toolchain"]["machine_contract"])
        self.assertEqual("cache_policy", domains["qualification_cache"]["machine_contract"])
        self.assertEqual("qualification_execution_policy", domains["qualification_execution"]["machine_contract"])
        self.assertEqual("roadmap_policy", domains["roadmap"]["machine_contract"])
        self.assertEqual("engineering_metrics_policy", domains["engineering_metrics"]["machine_contract"])
        self.assertEqual("security_scan_policy", domains["security_scan"]["machine_contract"])
        self.assertEqual("terraform_provider_lock", domains["terraform_provider"]["machine_contract"])
        self.assertEqual("context_router", domains["context_routing"]["machine_contract"])
        self.assertEqual("workstation_policy", domains["workstation"]["machine_contract"])

        forbidden = set(model["forbidden_parallel_policy_files"])
        for relative in (
            ".ansible-lint",
            "ruff.toml",
            ".gitleaks.toml",
            ".golangci.yml",
            ".yamllint",
            ".tflint.hcl",
        ):
            self.assertIn(relative, forbidden)
            self.assertFalse((ROOT / relative).exists(), relative)

        self.assertEqual(0, MOD.repository_authority_check())

    def test_toolchain_versions_are_central_and_native_files_are_projections(self):
        contract = MOD.json.loads((ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(contract["versions"], MOD.pinned_versions())
        self.assertEqual("generated-projection", contract["projections"]["versions_env"]["mode"])
        self.assertEqual("generated-projection", contract["projections"]["ansible_collections"]["mode"])
        self.assertEqual("operational-projection", contract["projections"]["capability_graph"]["mode"])
        self.assertEqual("forbidden", contract["rules"]["floating_versions"])
        self.assertEqual("required", contract["rules"]["executable_sha256_cache_identity"])

    def test_workstation_native_files_are_central_projections(self):
        policy = MOD.workstation_policy()
        self.assertEqual("architecture.lock.yaml", policy["architecture_authority"])
        self.assertEqual("developer-workstation", policy["scope"])
        MOD.validate_workstation_projections(policy)

    def test_terraform_repository_lockfiles_project_central_provider(self):
        MOD.validate_terraform_lockfile_projections()
        provider = MOD.terraform_provider_lock_contract()["providers"]["hcloud"]
        self.assertEqual("1.68.0", provider["version"])

    def test_security_scan_policy_generates_native_config(self):
        policy = MOD.security_scan_policy()
        self.assertEqual("architecture.lock.yaml", policy["architecture_authority"])
        self.assertEqual("gitleaks", policy["scanner"]["name"])
        self.assertEqual("forbidden", policy["scanner"]["local_config"])
        self.assertFalse((ROOT / ".gitleaks.toml").exists())

        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "gitleaks.toml"
            MOD.write_gitleaks_policy_config(config, policy)
            text = config.read_text(encoding="utf-8")
        self.assertIn("useDefault = true", text)
        self.assertIn("tests/fixtures/", text)
        self.assertIn("node_modules/", text)

    def test_security_routes_configuration_changes_to_supported_trivy_config_command(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        with (
            mock.patch.object(MOD, "require", return_value="/managed/tool"),
            mock.patch.object(
                MOD,
                "changed_paths",
                return_value=["platform/tekton/tasks/product-supply-chain.yaml"],
            ),
            mock.patch.object(MOD, "run", side_effect=fake_run),
            mock.patch.dict(os.environ, {"BASE": "origin/main", "HEAD": "HEAD"}, clear=False),
        ):
            self.assertEqual(0, MOD.security())

        trivy_calls = [call for call in calls if call[:2] == ["trivy", "config"]]
        self.assertEqual(1, len(trivy_calls))
        self.assertNotIn("--scanners", trivy_calls[0])
        self.assertEqual("platform/tekton/tasks", trivy_calls[0][-1])

    def test_security_scans_every_go_module_when_workspace_changes(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs.get("cwd")))
            return subprocess.CompletedProcess(argv, 0, "", "")

        with (
            mock.patch.object(MOD, "require", return_value="/managed/tool"),
            mock.patch.object(MOD, "changed_paths", return_value=["go.work"]),
            mock.patch.object(MOD, "run", side_effect=fake_run),
            mock.patch.dict(os.environ, {"BASE": "origin/main", "HEAD": "HEAD"}, clear=False),
        ):
            self.assertEqual(0, MOD.security())

        modules = {
            path
            for path in [MOD.ROOT / "frontend", *sorted((MOD.ROOT / "services").glob("*"))]
            if (path / "go.mod").is_file()
        }
        gosec_modules = {cwd for argv, cwd in calls if argv[:1] == ["gosec"]}
        govulncheck_modules = {cwd for argv, cwd in calls if argv[:1] == ["govulncheck"]}
        self.assertEqual(modules, gosec_modules)
        self.assertEqual(modules, govulncheck_modules)

    def test_ruff_adapter_config_is_derived_from_central_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ruff.toml"
            MOD.write_ruff_policy_config(path)
            text = path.read_text(encoding="utf-8")
        self.assertIn('target-version = "py312"', text)
        self.assertIn("line-length = 120", text)
        self.assertIn('"E9"', text)
        self.assertIn('"F82"', text)

    def test_declared_formatter_drift_is_advisory_but_execution_errors_block(self):
        command = ["terraform", "fmt", "-check", "-recursive", "-diff"]
        drift = subprocess.CompletedProcess(command, 3, "format diff", "")
        with mock.patch.object(MOD, "run", return_value=drift):
            MOD.advisory_exit_check("terraform fmt", command, drift_exit_codes=[3])

        failure = subprocess.CompletedProcess(command, 2, "", "formatter crashed")
        with mock.patch.object(MOD, "run", return_value=failure):
            with self.assertRaisesRegex(RuntimeError, "formatter crashed"):
                MOD.advisory_exit_check("terraform fmt", command, drift_exit_codes=[3])

    def test_exact_state_skips_ansible_startup(self):
        with (
            mock.patch.object(MOD, "developer_state_ready", return_value=True),
            mock.patch.object(MOD, "require", side_effect=AssertionError("Ansible must not start")),
        ):
            MOD.ensure_developer("go,cgo,sqlc,docker")

    def test_shell_policy_uses_effective_worktree_not_stale_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)

            legacy = repo / "legacy.sh"
            legacy.write_text("#!/bin/sh\n", encoding="utf-8")
            subprocess.run(["git", "add", "legacy.sh"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repo, check=True)
            self.assertEqual(["legacy.sh"], MOD.repository_shell_paths(repo))

            # Migration deletes tracked Shell files before staging/commit. The gate
            # must evaluate WORKTREE and therefore accept this deletion immediately.
            legacy.unlink()
            self.assertEqual([], MOD.repository_shell_paths(repo))

            # A new untracked Shell helper must still fail closed.
            new_shell = repo / "new-helper.sh"
            new_shell.write_text("#!/bin/sh\n", encoding="utf-8")
            self.assertEqual(["new-helper.sh"], MOD.repository_shell_paths(repo))

            # Ignored dependency/cache content is outside repository policy scope.
            (repo / ".gitignore").write_text("ignored.sh\n", encoding="utf-8")
            (repo / "ignored.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            self.assertEqual(["new-helper.sh"], MOD.repository_shell_paths(repo))

    def test_exact_managed_go_pair_is_detected_without_ansible(self):
        pins = {"NODE_VERSION": "24.20.0", "GO_VERSION": "1.26.6", "SQLC_VERSION": "1.31.1"}
        commands = {
            "node": "/bin/node",
            "corepack": "/bin/corepack",
            "cc": "/bin/cc",
            "sqlc": "/bin/sqlc",
            "docker": "/bin/docker",
        }

        def fake_which(name):
            return commands.get(name)

        def fake_run(cmd, **kwargs):
            if cmd[0] == "/bin/node":
                return subprocess.CompletedProcess(cmd, 0, "v24.20.0\n", "")
            if cmd[0].endswith("/.local/bin/go"):
                return subprocess.CompletedProcess(cmd, 0, "go version go1.26.6 linux/amd64\n", "")
            if cmd[0] == "/bin/sqlc":
                return subprocess.CompletedProcess(cmd, 0, "v1.31.1\n", "")
            if cmd[0] == "/bin/docker":
                return subprocess.CompletedProcess(cmd, 0, "", "")
            raise AssertionError(cmd)

        with tempfile.TemporaryDirectory() as home:
            managed = Path(home) / ".local" / "bin"
            managed.mkdir(parents=True)
            for name in ("go", "gofmt"):
                (managed / name).touch(mode=0o755)
            with (
                mock.patch.object(MOD.Path, "home", return_value=Path(home)),
                mock.patch.object(MOD, "pinned_versions", return_value=pins),
                mock.patch.object(MOD.shutil, "which", side_effect=fake_which),
                mock.patch.object(MOD, "run", side_effect=fake_run),
            ):
                self.assertTrue(MOD.developer_state_ready("node,go,cgo,sqlc,docker"))

    def test_stale_managed_go_is_rejected_even_when_system_go_is_correct(self):
        with tempfile.TemporaryDirectory() as home:
            managed = Path(home) / ".local" / "bin"
            managed.mkdir(parents=True)
            for name in ("go", "gofmt"):
                (managed / name).touch(mode=0o755)

            def fake_run(command, **_kwargs):
                self.assertEqual(str(managed / "go"), command[0])
                return subprocess.CompletedProcess(command, 0, "go version go1.25.0 linux/amd64\n", "")

            with (
                mock.patch.object(MOD.Path, "home", return_value=Path(home)),
                mock.patch.object(MOD, "pinned_versions", return_value={"GO_VERSION": "1.26.6"}),
                mock.patch.object(MOD.shutil, "which", return_value="/usr/bin/go"),
                mock.patch.object(MOD, "run", side_effect=fake_run),
            ):
                self.assertFalse(MOD.developer_state_ready("go"))


if __name__ == "__main__":
    unittest.main()
