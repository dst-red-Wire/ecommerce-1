"""Keep templ audit, gate readiness and actual Ansible repair on the same pin."""

from pathlib import Path
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
        self.binary = self.home / ".local/bin/templ"
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
            auditor = bootstrap.Auditor(self.contract, which=lambda _: str(self.binary))
            self.assertEqual(
                "PASS" if expected else "FAIL",
                auditor.check({**self.item, "resolved_executable": str(self.binary)}, "templ").state,
            )
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
