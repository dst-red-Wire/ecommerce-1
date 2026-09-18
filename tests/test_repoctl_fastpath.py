import importlib.util
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
                    "constraints": "= 1.68.0",
                    "hashes": ["h1:test", "zh:test"],
                }
            },
            "qualification": {
                "init_args": ["init", "-backend=false", "-input=false", "-lockfile=readonly"],
                "validate_args": ["validate"],
                "provider_plugin_cache": {},
            },
        }

        def fake_which(command):
            return {"tofu": "/opt/bin/tofu", "terraform": "/opt/bin/terraform"}.get(command)

        with (
            mock.patch.object(
                pathlib.Path,
                "rglob",
                return_value=[MOD.ROOT / "platform/terraform/example.tf"],
            ),
            mock.patch.object(MOD, "source_quality_adapter", return_value=policy),
            mock.patch.object(MOD, "terraform_provider_lock_contract", return_value=provider_lock),
            mock.patch.object(MOD, "_run_cached_static_gate", return_value=0) as cached_gate,
            mock.patch.object(MOD.shutil, "which", side_effect=fake_which),
        ):
            self.assertEqual(0, MOD.terraform_check())

        cached_gate.assert_called_once()
        self.assertEqual("platform:terraform", cached_gate.call_args.args[0])
        self.assertEqual("/opt/bin/tofu", cached_gate.call_args.args[1]["selected_tool"])

    def test_terraform_provider_lock_is_central_and_exact(self):
        contract = MOD.terraform_provider_lock_contract()
        self.assertEqual("architecture.lock.yaml", contract["architecture_authority"])
        self.assertEqual("platform/terraform", contract["scope"])
        self.assertEqual("exact", contract["status"])

        provider = contract["providers"]["hcloud"]
        self.assertEqual("registry.terraform.io/hetznercloud/hcloud", provider["source"])
        self.assertEqual("1.68.0", provider["version"])
        self.assertEqual("= 1.68.0", provider["constraints"])
        self.assertTrue(any(value.startswith("h1:") for value in provider["hashes"]))
        self.assertTrue(any(value.startswith("zh:") for value in provider["hashes"]))

        qualification = contract["qualification"]
        self.assertEqual("non-authoritative", qualification["repository_lockfiles"]["authority"])
        self.assertFalse(qualification["repository_lockfiles"]["qualification_input"])
        self.assertIn("-lockfile=readonly", qualification["init_args"])

    def test_terraform_native_lockfile_is_generated_from_central_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".terraform.lock.hcl"
            MOD.write_terraform_provider_lock(path)
            text = path.read_text(encoding="utf-8")

        self.assertIn('provider "registry.terraform.io/hetznercloud/hcloud"', text)
        self.assertIn('version     = "1.68.0"', text)
        self.assertIn('constraints = "= 1.68.0"', text)
        self.assertIn("h1:KOFp1JbzZ6Xj2K80QL7HGJM6oG+oEo7tx3lIx3d5POM=", text)


    def test_source_quality_policy_is_central_repository_authority(self):
        policy = MOD.source_quality_policy()
        self.assertEqual("architecture.lock.yaml", policy["architecture_authority"])
        self.assertEqual("entire-repository", policy["scope"])
        self.assertEqual("advisory", policy["principles"]["formatter_drift"])
        self.assertEqual("blocking", policy["principles"]["syntax_validation"])
        self.assertEqual("blocking", policy["principles"]["semantic_validation"])
        self.assertEqual("forbidden", policy["principles"]["file_specific_quality_exceptions"])

        forbidden_policies = set(policy["parallel_policy_files"]["forbidden"])
        self.assertIn(".ansible-lint", forbidden_policies)
        self.assertIn("ruff.toml", forbidden_policies)
        for relative in forbidden_policies:
            self.assertFalse((ROOT / relative).exists(), relative)

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

    def test_static_gate_cache_hit_skips_producer(self):
        producer = mock.Mock(side_effect=AssertionError("producer must not run on cache hit"))
        with (
            mock.patch.object(MOD, "_static_gate_cache_key", return_value=("cache-key", "a" * 40)),
            mock.patch.object(
                MOD.qualification_cache,
                "load_success",
                return_value={"duration_seconds": 12.5},
            ),
        ):
            self.assertEqual(0, MOD._run_cached_static_gate("governance", {}, producer))
        producer.assert_not_called()

    def test_static_gate_cache_key_changes_with_scoped_inputs(self):
        approved = {
            "consumers": {
                "repoctl_global_static_gates": {
                    "gates": {
                        "automation": {
                            "inputs": ["**/*.sh", "platform/tekton/**/*"],
                        }
                    },
                }
            }
        }
        with (
            mock.patch.object(MOD.qualification_cache, "contract", return_value=approved),
            mock.patch.object(MOD.qualification_cache, "digest_paths", return_value="validator"),
            mock.patch.object(
                MOD.qualification_cache,
                "executable_identity",
                side_effect=lambda executable: {"path": executable, "sha256": "tool"},
            ),
            mock.patch.object(
                MOD.qualification_cache,
                "digest_globs",
                side_effect=["a" * 64, "b" * 64],
            ),
        ):
            first, _ = MOD._static_gate_cache_key("automation", {})
            second, _ = MOD._static_gate_cache_key("automation", {})
        self.assertNotEqual(first, second)

    def test_static_gate_cache_ignores_files_outside_declared_scope(self):
        approved = {
            "consumers": {
                "repoctl_global_static_gates": {
                    "gates": {
                        "governance": {
                            "inputs": ["architecture.lock.yaml", "config/contracts/**/*"],
                        }
                    },
                }
            }
        }
        with (
            mock.patch.object(MOD.qualification_cache, "contract", return_value=approved),
            mock.patch.object(MOD.qualification_cache, "digest_paths", return_value="validator"),
            mock.patch.object(MOD.qualification_cache, "digest_globs", return_value="c" * 64),
            mock.patch.object(
                MOD.qualification_cache,
                "executable_identity",
                side_effect=lambda executable: {"path": executable, "sha256": "tool"},
            ),
        ):
            first, _ = MOD._static_gate_cache_key("governance", {})
            second, _ = MOD._static_gate_cache_key("governance", {})
        self.assertEqual(first, second)

    def test_platform_ansible_component_cache_is_centrally_approved(self):
        approved = {
            "consumers": {
                "repoctl_component_static_gates": {
                    "gates": {
                        "platform:ansible": {
                            "inputs": [
                                "config/contracts/source-quality-policy.yaml",
                                "platform/ansible/**/*",
                            ],
                            "tools": ["ansible-lint", "ansible-playbook", "ansible-galaxy"],
                        }
                    }
                }
            }
        }
        with (
            mock.patch.object(MOD.qualification_cache, "contract", return_value=approved),
            mock.patch.object(MOD.qualification_cache, "digest_paths", return_value="validator"),
            mock.patch.object(MOD.qualification_cache, "digest_globs", return_value="d" * 64),
            mock.patch.object(
                MOD.qualification_cache,
                "executable_identity",
                side_effect=lambda executable: {"path": str(executable), "sha256": "tool"},
            ),
        ):
            key, digest = MOD._static_gate_cache_key(
                "platform:ansible",
                {"collection_versions": {"community.docker": "3.7.0"}},
            )
        self.assertEqual("d" * 64, digest)
        self.assertEqual(64, len(key))

    def test_platform_terraform_component_cache_is_centrally_approved(self):
        approved = {
            "consumers": {
                "repoctl_component_static_gates": {
                    "gates": {
                        "platform:terraform": {
                            "inputs": [
                                "config/contracts/terraform-provider-lock.yaml",
                                "platform/terraform/**/*.tf",
                                "platform/terraform/**/*.tftpl",
                            ],
                            "tools": ["tofu", "terraform"],
                        }
                    }
                }
            }
        }
        with (
            mock.patch.object(MOD.qualification_cache, "contract", return_value=approved),
            mock.patch.object(MOD.qualification_cache, "digest_paths", return_value="validator"),
            mock.patch.object(MOD.qualification_cache, "digest_globs", return_value="e" * 64),
            mock.patch.object(
                MOD.qualification_cache,
                "executable_identity",
                side_effect=lambda executable: {"path": str(executable), "sha256": "tool"},
            ),
        ):
            key, digest = MOD._static_gate_cache_key(
                "platform:terraform",
                {
                    "selected_tool": "/opt/bin/terraform",
                    "provider_versions": {"hcloud": "1.68.0"},
                },
            )

        self.assertEqual("e" * 64, digest)
        self.assertEqual(64, len(key))

    def test_platform_terraform_cache_inputs_include_provider_lock(self):
        contract = MOD.qualification_cache.contract()
        patterns = (
            contract["consumers"]["repoctl_component_static_gates"]["gates"]["platform:terraform"]["inputs"]
        )
        self.assertIn("config/contracts/terraform-provider-lock.yaml", patterns)
        self.assertIn("platform/terraform/**/*.tf", patterns)
        self.assertIn("platform/terraform/**/*.tftpl", patterns)


    def test_security_gate_is_never_cacheable(self):
        approved = {
            "consumers": {
                "repoctl_global_static_gates": {
                    "gates": {
                        "governance": {"inputs": ["architecture.lock.yaml"]},
                        "runtime-efficiency": {"inputs": ["config/contracts/runtime-efficiency.yaml"]},
                        "contracts": {"inputs": ["contracts/openapi/**/*"]},
                        "automation": {"inputs": ["**/*.sh"]},
                    },
                }
            }
        }
        with mock.patch.object(MOD.qualification_cache, "contract", return_value=approved):
            with self.assertRaisesRegex(RuntimeError, "not approved"):
                MOD._static_gate_cache_key("security", {})

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
