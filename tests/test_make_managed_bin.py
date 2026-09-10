import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / "Makefile"
MAKE = shutil.which("make")


@unittest.skipUnless(MAKE, "make is required")
class MakeManagedBinTest(unittest.TestCase):
    def _write_tool(self, directory: Path, name: str, log: Path) -> None:
        executable = directory / name
        executable.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            f"with pathlib.Path({str(log)!r}).open('a', encoding='utf-8') as output:\n"
            f"    output.write({name!r} + ' ' + ' '.join(sys.argv[1:]) + '\\n')\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)

    def _run_format_check(self, home: Path, system_bin: Path, makefile: Path = MAKEFILE):
        environment = os.environ.copy()
        environment.update({"HOME": str(home), "PATH": str(system_bin)})
        return subprocess.run(
            [MAKE, "--no-print-directory", "-f", str(makefile), "format-check"],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def _write_version_tool(
        self, directory: Path, name: str, version: str, log: Path
    ) -> None:
        executable = directory / name
        executable.write_text(
            f"#!{sys.executable}\n"
            "import pathlib\n"
            f"with pathlib.Path({str(log)!r}).open('a', encoding='utf-8') as output:\n"
            f"    output.write({str(executable)!r} + '\\n')\n"
            f"print('ansible [core {version}]')\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)

    def _run_env_check(self, home: Path, system_bin: Path, makefile: Path = MAKEFILE):
        environment = os.environ.copy()
        environment.update({"HOME": str(home), "PATH": str(system_bin)})
        return subprocess.run(
            [MAKE, "--no-print-directory", "-f", str(makefile), "env-check"],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def _prepare_ansible_providers(
        self, root: Path, managed_version: str, runner_version: str
    ) -> tuple[Path, Path, Path]:
        home = root / "home"
        managed_bin = home / ".local" / "bin"
        system_bin = root / "system-bin"
        log = root / "ansible.log"
        managed_bin.mkdir(parents=True)
        system_bin.mkdir()
        (system_bin / "python3").symlink_to(sys.executable)
        for name in ("ansible", "ansible-playbook", "ansible-galaxy"):
            self._write_version_tool(managed_bin, name, managed_version, log)
            self._write_version_tool(system_bin, name, runner_version, log)
        return home, system_bin, log

    def test_format_check_prefers_tools_from_managed_bin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            managed_bin = home / ".local" / "bin"
            system_bin = root / "system-bin"
            log = root / "tools.log"
            managed_bin.mkdir(parents=True)
            system_bin.mkdir()
            self._write_tool(managed_bin, "ruff", log)
            self._write_tool(managed_bin, "oxfmt", log)

            result = self._run_format_check(home, system_bin)

            self.assertEqual(0, result.returncode, result.stdout)
            self.assertEqual(
                [
                    "ruff format --check scripts tests",
                    "oxfmt --check frontend/apps frontend/packages frontend/e2e",
                ],
                log.read_text(encoding="utf-8").splitlines(),
            )

    def test_old_makefile_without_managed_path_cannot_find_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            managed_bin = home / ".local" / "bin"
            system_bin = root / "system-bin"
            log = root / "tools.log"
            managed_bin.mkdir(parents=True)
            system_bin.mkdir()
            self._write_tool(managed_bin, "ruff", log)
            self._write_tool(managed_bin, "oxfmt", log)
            mutated_makefile = root / "Makefile"
            source = MAKEFILE.read_text(encoding="utf-8")
            mutation = "format format-check: export PATH := $(MANAGED_BIN):$(PATH)\n\n"
            self.assertIn(mutation, source)
            mutated_makefile.write_text(source.replace(mutation, "", 1), encoding="utf-8")

            result = self._run_format_check(home, system_bin, mutated_makefile)

            self.assertNotEqual(0, result.returncode, result.stdout)
            self.assertIn("ruff", result.stdout)
            self.assertFalse(log.exists(), "the managed tool must remain unreachable after mutation")

    def test_format_check_fails_when_managed_tool_is_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            managed_bin = home / ".local" / "bin"
            system_bin = root / "system-bin"
            log = root / "tools.log"
            managed_bin.mkdir(parents=True)
            system_bin.mkdir()
            self._write_tool(managed_bin, "oxfmt", log)

            result = self._run_format_check(home, system_bin)

            self.assertNotEqual(0, result.returncode, result.stdout)
            self.assertIn("ruff", result.stdout)
            self.assertFalse(log.exists(), "the later formatter must not mask the missing tool")

    def test_env_check_preserves_compatible_runner_ansible(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, system_bin, log = self._prepare_ansible_providers(
                Path(tmp), "1.0.0", self._ansible_version()
            )

            result = self._run_env_check(home, system_bin)

            self.assertIn("PASS        ansible-core", result.stdout)
            calls = log.read_text(encoding="utf-8").splitlines()
            self.assertIn(str(system_bin / "ansible"), calls)
            self.assertNotIn(str(home / ".local/bin/ansible"), calls)
            self.assertIn(str(system_bin / "ansible-playbook"), calls)

    def test_global_managed_path_prepend_selects_stale_ansible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, system_bin, log = self._prepare_ansible_providers(
                root, "1.0.0", self._ansible_version()
            )
            mutated_makefile = root / "Makefile"
            source = MAKEFILE.read_text(encoding="utf-8")
            targeted = "format format-check: export PATH := $(MANAGED_BIN):$(PATH)\n\n"
            self.assertIn(targeted, source)
            mutated_makefile.write_text(
                source.replace(targeted, "PATH := $(MANAGED_BIN):$(PATH)\nexport PATH\n\n", 1),
                encoding="utf-8",
            )

            result = self._run_env_check(home, system_bin, mutated_makefile)

            self.assertIn("FAIL        ansible-core", result.stdout)
            calls = log.read_text(encoding="utf-8").splitlines()
            self.assertIn(str(home / ".local/bin/ansible"), calls)
            self.assertNotIn(str(system_bin / "ansible"), calls)

    def test_env_check_rejects_stale_managed_and_runner_ansible(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, system_bin, log = self._prepare_ansible_providers(
                Path(tmp), "1.0.0", "1.0.0"
            )

            result = self._run_env_check(home, system_bin)

            self.assertIn("FAIL        ansible-core", result.stdout)
            calls = log.read_text(encoding="utf-8").splitlines()
            self.assertIn(str(system_bin / "ansible"), calls)

    @staticmethod
    def _ansible_version() -> str:
        for line in (ROOT / "config/toolchain/versions.env").read_text(
            encoding="utf-8"
        ).splitlines():
            if line.startswith("ANSIBLE_CORE_VERSION="):
                return line.partition("=")[2]
        raise AssertionError("ANSIBLE_CORE_VERSION is missing")
