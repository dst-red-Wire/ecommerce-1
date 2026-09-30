from __future__ import annotations

import contextlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "repository_delivery_native_test", ROOT / "scripts/repository_delivery.py"
)
assert SPEC and SPEC.loader
RD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RD)

BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
CAMPAIGN = "20260930T080000Z-123456789abc"
VM_ID = "12345678-1234-1234-1234-123456789abc"


class TrustedNativeUacTests(unittest.TestCase):
    def _roots(self, directory: str) -> tuple[Path, Path, Path, Path]:
        root = Path(directory)
        trusted = root / "trusted"
        target = root / "target"
        for checkout in (trusted, target):
            (checkout / "scripts").mkdir(parents=True)
        wrapper = trusted / "scripts/repository_delivery.py"
        controller = trusted / "scripts/repoctl.py"
        wrapper.write_text("# trusted wrapper\n", encoding="utf-8")
        controller.write_text(
            "from pathlib import Path\n"
            "import os\n"
            "Path('base_called').write_text(os.environ.get("
            "'REPOCTL_TRUSTED_NATIVE_UAC', ''))\n"
            "raise SystemExit(23)\n",
            encoding="utf-8",
        )
        (target / "scripts/repoctl.py").write_text(
            "from pathlib import Path\n"
            "Path('head_sentinel').write_text('executed')\n"
            "raise SystemExit(0)\n",
            encoding="utf-8",
        )
        return trusted, target, wrapper, controller

    def _reviewed_mocks(self, trusted: Path, target: Path, wrapper: Path, controller: Path):
        binding = SimpleNamespace(pr_number=169)
        patches = [
            mock.patch.object(RD, "_native_verify_controller", return_value=(BASE_SHA, wrapper, controller)),
            mock.patch.object(RD, "_native_checkout_root", side_effect=lambda path, **_: path),
            mock.patch.object(RD, "_native_clean_checkout", return_value=(HEAD_SHA, "feature/native-uac")),
            mock.patch.object(RD, "_native_verify_base_tree"),
            mock.patch.object(RD, "_native_runner_manifest", return_value="c" * 64),
            mock.patch("managed_gh.resolve_managed_gh", return_value=("/tmp/gh", "2.101.0", "d" * 64)),
            mock.patch("exact_pr_binding.resolve_exact_open_pr", return_value=binding),
            mock.patch("exact_pr_binding.revalidate_exact_open_pr", return_value=binding),
        ]
        return patches

    def test_reviewed_transition_executes_only_base_controller(self):
        with tempfile.TemporaryDirectory() as directory:
            trusted, target, wrapper, controller = self._roots(directory)
            patches = self._reviewed_mocks(trusted, target, wrapper, controller)
            with contextlib.ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                result = RD.trusted_native_uac(
                    trusted, target, "Prepare", CAMPAIGN, VM_ID, 169, sys.executable
                )
            self.assertEqual(23, result)
            self.assertEqual("1", (target / "base_called").read_text())
            self.assertFalse((target / "head_sentinel").exists())

    def test_missing_exact_pr_denies_before_controller_or_uac(self):
        with tempfile.TemporaryDirectory() as directory:
            trusted, target, wrapper, controller = self._roots(directory)
            patches = self._reviewed_mocks(trusted, target, wrapper, controller)
            with contextlib.ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                stack.enter_context(mock.patch(
                    "exact_pr_binding.resolve_exact_open_pr",
                    side_effect=RuntimeError("missing exact PR"),
                ))
                with mock.patch.object(RD.subprocess, "run") as run:
                    with self.assertRaisesRegex(RuntimeError, "missing exact PR"):
                        RD.trusted_native_uac(
                            trusted, target, "Prepare", CAMPAIGN, VM_ID, 169,
                            sys.executable,
                        )
                    run.assert_not_called()
            self.assertFalse((target / "base_called").exists())
            self.assertFalse((target / "head_sentinel").exists())

    def test_pr_head_wrapper_cannot_impersonate_base_without_controller(self):
        with tempfile.TemporaryDirectory() as directory:
            trusted, target, _, _ = self._roots(directory)
            with (
                mock.patch.object(RD, "_native_checkout_root", return_value=trusted),
                self.assertRaisesRegex(RuntimeError, "not executing from its trusted checkout"),
            ):
                RD._native_verify_controller(trusted, environment={})
            self.assertFalse((target / "head_sentinel").exists())

    def test_runner_manifest_rejects_tampered_head_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            subprocess.run(["git", "init", "-q", "-b", "feature/test"], cwd=target, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=target, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=target, check=True)
            (target / ".gitattributes").write_text(
                "*.ps1 text eol=crlf\n*.psm1 text eol=lf\n", encoding="utf-8"
            )
            for relative in RD._NATIVE_RUNNER_PATHS:
                source = target / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(("runner " + relative + "\n").encode("ascii"))
            subprocess.run(["git", "add", "."], cwd=target, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qm", "runner"], cwd=target, check=True)
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
            environment = RD._native_child_environment()
            digest = RD._native_runner_manifest(target, head, environment=environment)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            source = target / RD._NATIVE_RUNNER_PATHS[0]
            raw_crlf = source.read_bytes().replace(b"\n", b"\r\n")
            source.write_bytes(raw_crlf)
            self.assertEqual(
                raw_crlf,
                RD._native_git_file_bytes(
                    target, head, RD._NATIVE_RUNNER_PATHS[0],
                    environment=environment,
                ),
            )
            self.assertNotEqual(
                digest, RD._native_runner_manifest(target, head, environment=environment)
            )
            source.write_bytes(b"tampered\n")
            with self.assertRaisesRegex(RuntimeError, "differs from Git"):
                RD._native_runner_manifest(target, head, environment=environment)

    def test_offline_recovery_uses_base_controller_without_pr_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            trusted, target, wrapper, controller = self._roots(directory)
            with (
                mock.patch.object(RD, "_native_verify_controller", return_value=(BASE_SHA, wrapper, controller)),
                mock.patch.object(RD, "_native_checkout_root", return_value=target),
                mock.patch("exact_pr_binding.resolve_exact_open_pr", side_effect=AssertionError("GitHub used")),
            ):
                result = RD.trusted_native_uac(
                    trusted, target, "Recover", CAMPAIGN, "", None, sys.executable
                )
            self.assertEqual(23, result)
            self.assertFalse((target / "head_sentinel").exists())

    def test_verify_post_uac_rechecks_binding_with_base_controller(self):
        with tempfile.TemporaryDirectory() as directory:
            trusted, target, wrapper, controller = self._roots(directory)
            patches = self._reviewed_mocks(trusted, target, wrapper, controller)
            with contextlib.ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                run = stack.enter_context(
                    mock.patch.object(RD.subprocess, "run", wraps=subprocess.run)
                )
                result = RD.trusted_native_uac(
                    trusted, target, "Verify", CAMPAIGN, VM_ID, 169, sys.executable,
                    head_sha=HEAD_SHA, base_sha=BASE_SHA,
                    runner_manifest_sha256="c" * 64,
                    qualification_sha256="e" * 64,
                )
            self.assertEqual(23, result)
            command = run.call_args.args[0]
            self.assertIn("lab-network-native-boot-authority-check", command)
            self.assertIn("--qualification-sha256", command)
            self.assertIn("e" * 64, command)
            self.assertEqual("1", (target / "base_called").read_text())
            self.assertFalse((target / "head_sentinel").exists())

    def test_verify_changed_head_denies_before_authority_check(self):
        with tempfile.TemporaryDirectory() as directory:
            trusted, target, wrapper, controller = self._roots(directory)
            patches = self._reviewed_mocks(trusted, target, wrapper, controller)
            with contextlib.ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                with mock.patch.object(RD.subprocess, "run") as run:
                    with self.assertRaisesRegex(RuntimeError, "changed during UAC"):
                        RD.trusted_native_uac(
                            trusted, target, "Verify", CAMPAIGN, VM_ID, 169,
                            sys.executable, head_sha="f" * 40, base_sha=BASE_SHA,
                            runner_manifest_sha256="c" * 64,
                            qualification_sha256="e" * 64,
                        )
                    run.assert_not_called()
            self.assertFalse((target / "base_called").exists())
            self.assertFalse((target / "head_sentinel").exists())

    def test_unpinned_psm1_eol_and_bare_cr_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            (root / ".gitattributes").write_text(
                "*.ps1 text eol=crlf\n*.psm1 text eol=lf\n", encoding="utf-8"
            )
            ps1 = root / "runner.ps1"
            psm1 = root / "module.psm1"
            ps1.write_bytes(b"first\nsecond\n")
            psm1.write_bytes(b"first\nsecond\n")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qm", "base"], cwd=root, check=True)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            environment = RD._native_child_environment()
            ps1.write_bytes(b"first\rsecond\r\n")
            with self.assertRaisesRegex(RuntimeError, "unsafe EOL"):
                RD._native_git_file_bytes(root, sha, "runner.ps1", environment=environment)
            psm1.write_bytes(b"first\r\nsecond\r\n")
            with self.assertRaisesRegex(RuntimeError, "differs from Git"):
                RD._native_git_file_bytes(root, sha, "module.psm1", environment=environment)

    def test_hidden_base_policy_edit_is_detected_by_exact_tree_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            (root / ".gitattributes").write_text(
                "*.ps1 text eol=crlf\n", encoding="utf-8"
            )
            policy = root / "architecture.lock.yaml"
            policy.write_text("trusted-policy\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qm", "base"], cwd=root, check=True)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            environment = RD._native_child_environment()
            RD._native_verify_base_tree(root, sha, environment=environment)
            subprocess.run(["git", "update-index", "--skip-worktree", "--", policy.name], cwd=root, check=True)
            policy.write_text("attacker-policy\n", encoding="utf-8")
            status = subprocess.check_output(
                ["git", "status", "--porcelain=v1"], cwd=root, text=True
            )
            self.assertEqual("", status)
            with self.assertRaisesRegex(RuntimeError, "differs from Git"):
                RD._native_verify_base_tree(root, sha, environment=environment)

    def test_native_git_uses_only_the_system_binary(self):
        with mock.patch.dict(os.environ, {"PATH": "/tmp/attacker"}):
            environment = RD._native_child_environment()
        self.assertEqual("/usr/bin:/bin:/usr/local/bin", environment["PATH"])
        with mock.patch.object(RD.shutil, "which", return_value="/tmp/attacker/git"):
            with mock.patch.object(RD.subprocess, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "trusted native Git executable"):
                    RD._native_git_bytes(ROOT, "rev-parse", "HEAD", environment=environment)
                run.assert_not_called()
        with mock.patch.object(RD.shutil, "which", return_value="/usr/bin/git"):
            with mock.patch.object(
                RD.subprocess, "run",
                return_value=subprocess.CompletedProcess([], 0, b"ok", b""),
            ) as run:
                self.assertEqual(
                    b"ok", RD._native_git_bytes(
                        ROOT, "rev-parse", "HEAD", environment=environment
                    ),
                )
            self.assertEqual("git", run.call_args.args[0][0])
            self.assertIs(environment, run.call_args.kwargs["env"])

    def test_caller_cannot_skip_runtime_lock_through_environment(self):
        with mock.patch.dict(os.environ, {
            "ECOMMERCE_RUNTIME_ORCHESTRATED": "1",
            "REPOCTL_TRUSTED_NATIVE_UAC": "1",
            "GIT_CONFIG_COUNT": "1",
            "PYTHONPATH": "/tmp/head",
            "LD_PRELOAD": "/tmp/head.so",
            "GH_HOST": "attacker.invalid",
            "HTTPS_PROXY": "https://attacker.invalid:443",
            "http_proxy": "http://attacker.invalid:80",
            "ALL_PROXY": "socks5://attacker.invalid:9050",
            "SSL_CERT_FILE": "/tmp/attacker.pem",
            "CURL_CA_BUNDLE": "/tmp/attacker.pem",
            "RUBYOPT": "-r/tmp/attacker.rb",
            "RUBYLIB": "/tmp/attacker",
            "XDG_CONFIG_HOME": "/tmp/attacker-gh",
            "GIT_NO_REPLACE_OBJECTS": "0",
        }):
            environment = RD._native_child_environment()
        self.assertNotIn("ECOMMERCE_RUNTIME_ORCHESTRATED", environment)
        self.assertNotIn("REPOCTL_TRUSTED_NATIVE_UAC", environment)
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("LD_PRELOAD", environment)
        for name in (
            "HTTPS_PROXY", "http_proxy", "ALL_PROXY", "SSL_CERT_FILE",
            "CURL_CA_BUNDLE", "RUBYOPT", "RUBYLIB", "XDG_CONFIG_HOME",
        ):
            self.assertNotIn(name, environment)
        self.assertEqual("1", environment["GIT_NO_REPLACE_OBJECTS"])
        self.assertEqual(str(Path.home()), environment["HOME"])
        self.assertEqual("github.com", environment["GH_HOST"])
        self.assertEqual("1", environment["GH_PROMPT_DISABLED"])
        with mock.patch.dict(os.environ, {"GH_HOST": "attacker.invalid"}):
            seen_host = RD._native_with_environment(
                lambda: os.environ["GH_HOST"], environment
            )
            self.assertEqual("attacker.invalid", os.environ["GH_HOST"])
        self.assertEqual("github.com", seen_host)


if __name__ == "__main__":
    unittest.main()
