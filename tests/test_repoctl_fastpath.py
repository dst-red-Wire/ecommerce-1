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
    def test_bare_base_resolution_prefers_origin_tracking_ref(self):
        remote_sha = "1" * 40
        local_sha = "2" * 40
        calls = []

        def fake_run(command, **_kwargs):
            calls.append(command)
            candidate = command[-1] if command[:3] == ["git", "rev-parse", "--verify"] else ""
            if candidate == "origin/stacked-base^{commit}":
                return subprocess.CompletedProcess(command, 0, remote_sha + "\n", "")
            if candidate == "stacked-base^{commit}":
                return subprocess.CompletedProcess(command, 0, local_sha + "\n", "")
            if command == ["git", "rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(command, 0, "3" * 40 + "\n", "")
            if command[:3] == ["git", "merge-base", "--is-ancestor"]:
                return subprocess.CompletedProcess(command, 0, "", "")
            raise AssertionError(command)

        with mock.patch.object(MOD, "run", side_effect=fake_run):
            ref, sha = MOD.resolve_base_ref("stacked-base", head="HEAD")

        self.assertEqual("origin/stacked-base", ref)
        self.assertEqual(remote_sha, sha)
        self.assertEqual("origin/stacked-base^{commit}", calls[0][-1])

    def test_head_base_preserves_local_git_special_ref(self):
        head_sha = "3" * 40
        calls = []

        def fake_run(command, **_kwargs):
            calls.append(command)
            if command == ["git", "rev-parse", "--verify", "HEAD^{commit}"]:
                return subprocess.CompletedProcess(command, 0, head_sha + "\n", "")
            if command == ["git", "merge-base", "--is-ancestor", head_sha, "HEAD"]:
                return subprocess.CompletedProcess(command, 0, "", "")
            raise AssertionError(command)

        with (
            mock.patch.object(MOD, "run", side_effect=fake_run),
            mock.patch.object(MOD, "git", return_value=head_sha + "\n"),
        ):
            ref, sha = MOD.resolve_base_ref("HEAD", head="WORKTREE")

        self.assertEqual("HEAD", ref)
        self.assertEqual(head_sha, sha)
        self.assertNotIn(
            ["git", "rev-parse", "--verify", "origin/HEAD^{commit}"],
            calls,
        )

    def test_exact_base_must_be_strict_ancestor(self):
        head_sha = "4" * 40

        def fake_run(command, **_kwargs):
            if command == ["git", "rev-parse", "--verify", f"{head_sha}^{{commit}}"]:
                return subprocess.CompletedProcess(command, 0, head_sha + "\n", "")
            if command == ["git", "merge-base", "--is-ancestor", head_sha, head_sha]:
                return subprocess.CompletedProcess(command, 0, "", "")
            raise AssertionError(command)

        with (
            mock.patch.object(MOD, "run", side_effect=fake_run),
            mock.patch.object(MOD, "git", return_value=head_sha + "\n"),
        ):
            with self.assertRaisesRegex(RuntimeError, "strict ancestor"):
                MOD.resolve_base_ref(head_sha, head=head_sha)

    def test_qualification_entrypoints_use_canonical_environment(self):
        import inspect

        self.assertIn(
            "resolve_base_ref(base, head=head)",
            inspect.getsource(MOD.contracts),
        )
        self.assertIn(
            'resolve_base_ref(base, head="WORKTREE")',
            inspect.getsource(MOD.diff_context),
        )
        self.assertIn(
            'qualification_environment({"BASE": base, "HEAD": head})',
            inspect.getsource(MOD.verify_change),
        )
        self.assertIn(
            'qualification_environment({"BASE": base, "HEAD": head})',
            inspect.getsource(MOD.ci_component),
        )
        self.assertIn(
            'qualification_environment(\n            {"GIT_INDEX_FILE": str(temporary_index)}\n        )',
            inspect.getsource(MOD.worktree_tree_sha),
        )

    def test_qualification_environment_is_canonical_and_git_isolated(self):
        inherited = {
            "GIT_DIR": "/tmp/parent/.git",
            "GIT_WORK_TREE": "/tmp/parent",
            "GIT_INDEX_FILE": "/tmp/parent/.git/index",
            "GIT_ASKPASS": "/tmp/askpass",
            "KEEP_ME": "yes",
        }

        policy = {
            "qualification_isolation": {
                "git": {
                    "drop_inherited_prefixes": ["GIT_"],
                    "system_config": "disabled",
                    "global_config": "disabled",
                    "nested_hooks": "disabled",
                    "hooks_path": "/dev/null",
                }
            }
        }

        with (
            mock.patch.dict(MOD.os.environ, inherited, clear=True),
            mock.patch.object(
                MOD,
                "execution_environment_policy",
                return_value=policy,
            ),
        ):
            env = MOD.qualification_environment(
                {"BASE": "base-sha", "HEAD": "head-sha"}
            )

        self.assertFalse(any(name.startswith("GIT_") for name in inherited if name in env))
        self.assertEqual("yes", env["KEEP_ME"])
        self.assertEqual("1", env["GIT_CONFIG_NOSYSTEM"])
        self.assertEqual(MOD.os.devnull, env["GIT_CONFIG_GLOBAL"])
        self.assertEqual("1", env["GIT_CONFIG_COUNT"])
        self.assertEqual("core.hooksPath", env["GIT_CONFIG_KEY_0"])
        self.assertEqual("/dev/null", env["GIT_CONFIG_VALUE_0"])
        self.assertEqual("base-sha", env["BASE"])
        self.assertEqual("head-sha", env["HEAD"])

    def test_qualification_environment_prevents_nested_git_from_mutating_parent(self):
        before_index = MOD.output(["git", "write-tree"]).strip()

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "nested"
            repo.mkdir()

            env = MOD.qualification_environment()

            subprocess.run(
                ["git", "init", "-q"],
                cwd=repo,
                env=env,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=repo,
                env=env,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Test"],
                cwd=repo,
                env=env,
                check=True,
            )

            legacy = repo / "legacy.sh"
            legacy.write_text("#!/bin/sh\n", encoding="utf-8")

            subprocess.run(
                ["git", "add", "legacy.sh"],
                cwd=repo,
                env=env,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "nested"],
                cwd=repo,
                env=env,
                check=True,
            )

        after_index = MOD.output(["git", "write-tree"]).strip()

        self.assertEqual(before_index, after_index)
        self.assertFalse((MOD.ROOT / "legacy.sh").exists())

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
                "source_projection": {
                    "preserve_repository_relative_paths": True,
                    "roots": ["platform/terraform"],
                    "ignored_names": [".terraform", ".terraform.lock.hcl"],
                },
                "provider_plugin_cache": {},
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
            mock.patch.object(MOD, "qualification_environment", return_value={}),
            mock.patch.object(
                MOD,
                "materialize_repository_projection",
                side_effect=lambda destination, roots, **_kwargs: (
                    destination / "platform" / "terraform"
                ).mkdir(parents=True, exist_ok=True),
            ),
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
