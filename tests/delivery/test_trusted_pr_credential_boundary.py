from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


REPOCTL = module("repoctl_credential_boundary", ROOT / "scripts/repoctl.py")
CONSUMER = module("consumer_credential_boundary", ROOT / "scripts/trusted_pr_event_consumer.py")
SECRETS = {
    "GH_TOKEN": "github-secret",
    "GITHUB_TOKEN": "github-secret",
    "GITHUB_REPOSITORY": CONSUMER.REPOSITORY,
    "TRUSTED_PR_WEBHOOK_SECRET": "webhook-secret-32-characters-long!",
    "CI_EVIDENCE_COSIGN_KEY": "cosign-private-key",
    "CI_EVIDENCE_REPOSITORY": "registry.example/private-evidence",
    "REGISTRY_PASSWORD": "registry-password",
    "HARBOR_TOKEN": "harbor-token",
    "SUPER_SECRET_NEW_VARIABLE": "should-not-leak",
}


class CredentialBoundaryTests(unittest.TestCase):
    def test_real_head_script_receives_no_runner_secret_after_hmac(self):
        with tempfile.TemporaryDirectory() as tmp:
            head = Path(tmp)
            scripts = head / "scripts"
            scripts.mkdir()
            output = head / "observed.json"
            (scripts / "signing_rotation.py").write_text(
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "Path(sys.argv[1]).write_text(json.dumps(dict(os.environ)))\n",
                encoding="utf-8",
            )
            raw = json.dumps({"repository": {"full_name": CONSUMER.REPOSITORY}, "action": "closed", "pull_request": {"number": 163}}).encode()
            signature = "sha256=" + hmac.new(SECRETS["TRUSTED_PR_WEBHOOK_SECRET"].encode(), raw, hashlib.sha256).hexdigest()
            with mock.patch.dict(REPOCTL.os.environ, {**SECRETS, "REPOCTL_TRUSTED_WRAPPER": "/trusted/wrapper", "REPOCTL_TRUSTED_CONTROLLER": "/trusted/repoctl.py", "REPOCTL_TRUSTED_GH_PATH": sys.executable, "REPOCTL_TRUSTED_GIT_PATH": shutil.which("git")}):
                self.assertIsNone(CONSUMER.authenticated_event_pr(raw, signature, "pull_request"))
                self.assertNotIn("TRUSTED_PR_WEBHOOK_SECRET", os.environ)
                result = REPOCTL.run([sys.executable, "scripts/signing_rotation.py", str(output)], cwd=head, check=False)
            self.assertEqual(0, result.returncode)
            observed = json.loads(output.read_text(encoding="utf-8"))
            self.assertIn("PATH", observed)
            for name in (*SECRETS, "REPOCTL_TRUSTED_WRAPPER", "REPOCTL_TRUSTED_CONTROLLER"):
                self.assertNotIn(name, observed, name)

    def test_trusted_github_command_keeps_token_but_head_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gh = root / "gh"
            gh.write_text(
                "#!" + sys.executable + "\n"
                "import json, os\n"
                "print(json.dumps({'GH_TOKEN': os.environ.get('GH_TOKEN'), 'GITHUB_TOKEN': os.environ.get('GITHUB_TOKEN'), 'random': os.environ.get('SUPER_SECRET_NEW_VARIABLE')}))\n",
                encoding="utf-8",
            )
            gh.chmod(0o755)
            with mock.patch.dict(REPOCTL.os.environ, {**SECRETS, "REPOCTL_TRUSTED_WRAPPER": "/trusted/wrapper", "REPOCTL_TRUSTED_GH_PATH": str(gh), "REPOCTL_TRUSTED_GIT_PATH": shutil.which("git")}):
                result = REPOCTL.run([str(gh)], cwd=root, capture=True)
            observed = json.loads(result.stdout)
            self.assertEqual("github-secret", observed["GH_TOKEN"])
            self.assertEqual("github-secret", observed["GITHUB_TOKEN"])
            self.assertIsNone(observed["random"])

    def test_head_toolchain_lock_cannot_inject_credentialed_gh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            head = root / "head"
            runner_bin = root / "runner-bin"
            malicious_bin = head / "attacker" / "bin"
            (head / "config/contracts").mkdir(parents=True)
            runner_bin.mkdir()
            malicious_bin.mkdir(parents=True)
            subprocess.run([shutil.which("git"), "init", str(head)], check=True, capture_output=True)
            (head / "config/contracts/toolchain-lock.json").write_text(json.dumps({
                "capability_policy": {"managed_install_root": {
                    "environment": "ATTACKER_TOOL_ROOT", "fallback": "/nonexistent", "bin_subdirectory": "bin",
                }},
                "native_tool_configs": {"ansible": {"collections_install_root": ".ansible/collections"}},
                "projections": {"ansible_config": {"path": "platform/ansible/ansible.cfg"}},
            }), encoding="utf-8")
            real_gh = runner_bin / "gh"
            fake_gh = malicious_bin / "gh"
            marker = root / "stolen-token"
            real_gh.write_text(
                f"#!{sys.executable}\nimport os\nprint('TRUSTED:' + os.environ.get('GH_TOKEN', ''))\n",
                encoding="utf-8",
            )
            fake_gh.write_text(
                f"#!{sys.executable}\nimport os\nfrom pathlib import Path\n"
                f"Path({str(marker)!r}).write_text(os.environ.get('GH_TOKEN', ''))\n",
                encoding="utf-8",
            )
            real_gh.chmod(0o755)
            fake_gh.chmod(0o755)
            driver = root / "probe.py"
            driver.write_text(
                "import importlib.util, os, sys\n"
                "spec = importlib.util.spec_from_file_location('trusted_repoctl', sys.argv[1])\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(module)\n"
                "assert os.environ['PATH'].split(os.pathsep)[0] == sys.argv[2]\n"
                "assert module._github_cli() == sys.argv[3]\n"
                "result = module.run(['gh', 'api', 'user'], capture=True)\n"
                "assert result.stdout.strip() == 'TRUSTED:github-secret'\n"
                "try:\n"
                "    module.run([sys.argv[4], 'api', 'user'], capture=True)\n"
                "except RuntimeError as exc:\n"
                "    assert 'untrusted GitHub CLI executable' in str(exc)\n"
                "else:\n"
                "    raise AssertionError('injected gh was accepted')\n",
                encoding="utf-8",
            )
            environment = {
                "PATH": f"{runner_bin}{os.pathsep}{os.environ['PATH']}",
                "GH_TOKEN": "github-secret",
                "REPOCTL_TRUSTED_WRAPPER": str(root / "trusted-wrapper.py"),
                "REPOCTL_TRUSTED_GH_PATH": str(real_gh),
                "REPOCTL_TRUSTED_GIT_PATH": shutil.which("git"),
                "ATTACKER_TOOL_ROOT": str(head / "attacker"),
            }
            result = subprocess.run(
                [sys.executable, "-I", str(driver), str(ROOT / "scripts/repoctl.py"), str(runner_bin), str(real_gh), str(fake_gh)],
                cwd=head, env=environment, text=True, capture_output=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(marker.exists(), "HEAD-injected gh must not receive the GitHub token")

    def test_credentialed_push_uses_pinned_git_and_pinned_gh_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gh = root / "trusted-gh"
            gh.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            gh.chmod(0o755)
            git = str(Path(shutil.which("git")).resolve())
            with (
                mock.patch.dict(REPOCTL.os.environ, {**SECRETS, "REPOCTL_TRUSTED_WRAPPER": "/trusted/wrapper", "REPOCTL_TRUSTED_GH_PATH": str(gh), "REPOCTL_TRUSTED_GIT_PATH": git}),
                mock.patch.object(REPOCTL.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as execute,
            ):
                REPOCTL.run(["git", "push", "origin", "HEAD"])
            command = execute.call_args.args[0]
            environment = execute.call_args.kwargs["env"]
            self.assertEqual([git, "push", "origin", "HEAD"], command)
            self.assertEqual("github-secret", environment["GH_TOKEN"])
            self.assertEqual("", environment["GIT_CONFIG_VALUE_1"])
            self.assertEqual(f"!{gh} auth git-credential", environment["GIT_CONFIG_VALUE_2"])

    def test_evidence_phase_is_separate_from_github_and_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, head = root / "base", root / "head"
            base.mkdir()
            head.mkdir()
            evidence_seen = {}
            audit_seen = {}

            class BaseDelivery:
                @staticmethod
                def fetch_evidence(_base, context, sha):
                    evidence_seen.update(os.environ)
                    return context / "evidence" / f"{sha}.json"

            def fake_run(_command, *, cwd, env, **_kwargs):
                self.assertEqual(head, cwd)
                audit_seen.update(env)
                return mock.Mock(returncode=0)

            config = {**SECRETS, "CI_EVIDENCE_COSIGN_PUBLIC_KEY": "/trusted/public.pub", "DOCKER_CONFIG": "/trusted/registry-read-only"}
            with (
                mock.patch.dict(CONSUMER.os.environ, config),
                mock.patch.object(CONSUMER, "trusted_delivery_module", return_value=BaseDelivery),
                mock.patch.object(CONSUMER, "run", side_effect=fake_run),
                mock.patch.object(CONSUMER, "live_binding", return_value=("a" * 40, "b" * 40)),
            ):
                CONSUMER.prepare_qualification(base, head, 163, "a" * 40, "b" * 40)
            self.assertEqual(config["CI_EVIDENCE_REPOSITORY"], evidence_seen["CI_EVIDENCE_REPOSITORY"])
            self.assertEqual(config["DOCKER_CONFIG"], evidence_seen["DOCKER_CONFIG"])
            for name in ("GH_TOKEN", "GITHUB_TOKEN", "TRUSTED_PR_WEBHOOK_SECRET", "CI_EVIDENCE_COSIGN_KEY", "SUPER_SECRET_NEW_VARIABLE"):
                self.assertNotIn(name, evidence_seen)
            for name in SECRETS:
                self.assertNotIn(name, audit_seen)

    def test_finish_pr_executes_base_rotation_not_tampered_head_rotation(self):
        class StopAfterRotation(Exception):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, head = root / "base", root / "head"
            for checkout, label in ((base, "base"), (head, "head")):
                scripts = checkout / "scripts"
                scripts.mkdir(parents=True)
                (scripts / "signing_rotation.py").write_text(
                    "from pathlib import Path\n"
                    f"Path({str(root / (label + '-ran'))!r}).write_text('ran')\n",
                    encoding="utf-8",
                )
            with (
                mock.patch.dict(REPOCTL.os.environ, {**SECRETS, "REPOCTL_TRUSTED_WRAPPER": str(base / "scripts/repository_delivery.py"), "REPOCTL_TRUSTED_CONTROLLER": str(base / "scripts/repoctl.py"), "REPOCTL_TRUSTED_GH_PATH": sys.executable, "REPOCTL_TRUSTED_GIT_PATH": shutil.which("git")}),
                mock.patch.object(REPOCTL, "ROOT", head),
                mock.patch.object(REPOCTL, "_require_trusted_pr_execution", return_value={"trusted_root": base}),
                mock.patch.object(REPOCTL, "toolchain_closure", return_value=0),
                mock.patch.object(REPOCTL, "repository_delivery_policy", side_effect=StopAfterRotation),
            ):
                with self.assertRaises(StopAfterRotation):
                    REPOCTL.finish_pr("main")
            self.assertTrue((root / "base-ran").exists())
            self.assertFalse((root / "head-ran").exists())


if __name__ == "__main__":
    unittest.main()
