from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
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
            with mock.patch.dict(REPOCTL.os.environ, {**SECRETS, "REPOCTL_TRUSTED_WRAPPER": "/trusted/wrapper", "REPOCTL_TRUSTED_CONTROLLER": "/trusted/repoctl.py"}):
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
            with mock.patch.dict(REPOCTL.os.environ, {**SECRETS, "REPOCTL_TRUSTED_WRAPPER": "/trusted/wrapper"}):
                result = REPOCTL.run([str(gh)], cwd=root, capture=True)
            observed = json.loads(result.stdout)
            self.assertEqual("github-secret", observed["GH_TOKEN"])
            self.assertEqual("github-secret", observed["GITHUB_TOKEN"])
            self.assertIsNone(observed["random"])

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
                mock.patch.dict(REPOCTL.os.environ, {**SECRETS, "REPOCTL_TRUSTED_WRAPPER": str(base / "scripts/repository_delivery.py"), "REPOCTL_TRUSTED_CONTROLLER": str(base / "scripts/repoctl.py")}),
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
