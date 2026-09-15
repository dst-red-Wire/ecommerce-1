"""Keep templ audit, gate readiness and actual Ansible repair on the same pin."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import capability_bootstrap as bootstrap
import repoctl as ctl


class TemplExactVersion(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="templ-exact-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.version = bootstrap.load_versions()["TEMPL_VERSION"]
        self.binary = self.home / f".local/share/ecommerce-1/tools/templ/{self.version}/linux-amd64/templ"
        self.binary.parent.mkdir(parents=True)
        self.contract = bootstrap.load_contract()
        self.item = next(item for item in self.contract["capabilities"] if item["name"] == "templ")

    def fixture(self, stdout, stderr="", rc=0):
        self.binary.write_text(
            f"#!{sys.executable}\nimport sys\n"
            f"sys.stdout.write({stdout!r})\nsys.stderr.write({stderr!r})\nsys.exit({rc})\n"
        )
        self.binary.chmod(0o755)

    def assert_state(self, expected):
        with mock.patch.object(Path, "home", return_value=self.home):
            auditor = bootstrap.Auditor(self.contract, which=lambda _: None)
            self.assertEqual("PASS" if expected else "FAIL", auditor.check(self.item, "templ").state)
            self.assertEqual(expected, ctl.developer_state_ready("templ"))

    def test_audit_and_readiness_use_complete_output(self):
        for stdout, stderr, rc, accepted in (
            (f"v{self.version}\n", "", 0, True),
            (f"v{self.version}0\n", "", 0, False),
            ("v0.0.0\n", "", 0, False),
            ("(devel)\n", "", 0, False),
            (f"templ version v{self.version}\n", "", 0, False),
            (f"v{self.version}\nv0.0.0\n", "", 0, False),
            (f"v{self.version}\n", "v0.0.0\n", 0, False),
            (f"v{self.version}\n", "", 1, False),
        ):
            with self.subTest(stdout=stdout, stderr=stderr, rc=rc):
                self.fixture(stdout, stderr, rc)
                self.assert_state(accepted)

    def test_real_ansible_repair_then_reuse_without_compilation(self):
        self.fixture(f"v{self.version}0\n")
        self.assert_state(False)
        variables = {
            "repo_root": str(ROOT),
            "local_bin": str(self.home / "bin"),
            "local_share": str(self.home / ".local/share/ecommerce-1"),
            "local_cache": str(self.home / "cache"),
            "resolved_executables": {"go": str(Path.home() / ".local/bin/go")},
        }
        command = [
            str(ROOT / ".venv/qualification/bin/ansible-playbook"),
            "-i",
            "localhost,",
            "-c",
            "local",
            "platform/ansible/developer.yml",
            "--tags",
            "templ",
            "-e",
            json.dumps(variables),
        ]
        env = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / "platform/ansible/ansible.cfg"))
        for attempt in range(2):
            result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=240)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assert_state(True)
            self.assertEqual([], list(self.binary.parent.glob(".candidate-*")))
            state = (self.binary.stat().st_ino, self.binary.stat().st_mtime_ns, self.binary.read_bytes())
            if attempt == 0:
                repaired = state
            else:
                self.assertEqual(repaired, state, "a conforming templ must not be recompiled")
        with (
            mock.patch.object(Path, "home", return_value=self.home),
            mock.patch.object(ctl, "require", side_effect=AssertionError("warm path must not require Ansible")),
        ):
            ctl.ensure_developer("templ")
