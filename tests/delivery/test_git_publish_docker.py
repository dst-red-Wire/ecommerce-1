import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENSURE = ROOT / "scripts" / "ensure-docker-daemon.sh"
PUBLISH = ROOT / "scripts" / "git-publish.sh"


class DockerPublishBoundaryTest(unittest.TestCase):
    def make_executable(self, path: Path, text: str) -> None:
        path.write_text(text)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def run_ensure(self, docker_body: str, desktop_body: str):
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            state = temp / "state"
            desktop_called = temp / "desktop-called"
            docker = temp / "docker"
            desktop = temp / "docker.exe"
            self.make_executable(docker, docker_body)
            self.make_executable(desktop, desktop_body)
            env = os.environ.copy()
            env.update(
                {
                    "DOCKER_CLI": str(docker),
                    "DOCKER_DESKTOP_CLI": str(desktop),
                    "DOCKER_WAIT_ATTEMPTS": "3",
                    "DOCKER_WAIT_SECONDS": "0",
                    "DOCKER_DISABLE_POWERSHELL_FALLBACK": "1",
                    "TEST_STATE": str(state),
                    "TEST_DESKTOP_CALLED": str(desktop_called),
                }
            )
            result = subprocess.run(
                [str(ENSURE)],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            return result, state.exists(), desktop_called.exists()

    def test_reachable_daemon_does_not_start_desktop(self):
        result, _, desktop_called = self.run_ensure(
            "#!/bin/sh\n[ \"$1\" = info ] && exit 0\nexit 1\n",
            "#!/bin/sh\ntouch \"$TEST_DESKTOP_CALLED\"\nexit 0\n",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(desktop_called)
        self.assertIn("already reachable", result.stdout)

    def test_unreachable_daemon_is_started_and_rechecked(self):
        result, state_exists, desktop_called = self.run_ensure(
            "#!/bin/sh\n[ \"$1\" = info ] || exit 1\n[ -f \"$TEST_STATE\" ]\n",
            "#!/bin/sh\n"
            "[ \"$1\" = desktop ] && [ \"$2\" = start ] || exit 1\n"
            "touch \"$TEST_DESKTOP_CALLED\" \"$TEST_STATE\"\n",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(state_exists)
        self.assertTrue(desktop_called)
        self.assertIn("after automatic start", result.stdout)

    def test_powershell_fallback_documents_shellcheck_literal(self):
        text = ENSURE.read_text()
        self.assertIn(
            "# PowerShell variables must expand in PowerShell, not in Bash.\n"
            "  # shellcheck disable=SC2016\n"
            "  if powershell.exe -NoLogo -NoProfile -NonInteractive -Command",
            text,
        )

    def test_publish_reconciles_docker_before_doctor(self):
        text = PUBLISH.read_text()
        ensure_pos = text.index("./scripts/ensure-docker-daemon.sh")
        doctor_pos = text.index("make workstation-doctor")
        self.assertLess(ensure_pos, doctor_pos)


if __name__ == "__main__":
    unittest.main()
