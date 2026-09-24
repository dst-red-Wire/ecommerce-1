import json
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
    def _prepare_controller_prerequisites(self, system_bin: Path) -> None:
        for name in ("git", "python3", "ruby"):
            resolved = shutil.which(name)
            self.assertIsNotNone(resolved, f"{name} is required for repoctl format-check tests")
            (system_bin / name).symlink_to(resolved)

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

    def _write_version_tool(self, directory: Path, name: str, version: str, log: Path) -> None:
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
            self._prepare_controller_prerequisites(system_bin)
            self._write_tool(managed_bin, "ruff", log)
            self._write_tool(managed_bin, "gofmt", log)
            self._write_tool(managed_bin, "tofu", log)

            result = self._run_format_check(home, system_bin)

            self.assertEqual(0, result.returncode, result.stdout)
            invoked = [line.split()[0] for line in log.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(["ruff", "gofmt", "tofu"], invoked)

    def test_format_check_fails_closed_when_gofmt_is_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            managed_bin = home / ".local" / "bin"
            system_bin = root / "system-bin"
            log = root / "tools.log"
            managed_bin.mkdir(parents=True)
            system_bin.mkdir()
            self._prepare_controller_prerequisites(system_bin)
            self._write_tool(managed_bin, "ruff", log)
            self._write_tool(managed_bin, "tofu", log)

            result = self._run_format_check(home, system_bin)

            self.assertNotEqual(0, result.returncode, result.stdout)
            self.assertIn("gofmt", result.stdout)

    def test_format_check_preserves_gofmt_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            managed_bin = home / ".local" / "bin"
            system_bin = root / "system-bin"
            log = root / "tools.log"
            managed_bin.mkdir(parents=True)
            system_bin.mkdir()
            self._prepare_controller_prerequisites(system_bin)
            self._write_tool(managed_bin, "ruff", log)
            self._write_tool(managed_bin, "tofu", log)
            gofmt = managed_bin / "gofmt"
            gofmt.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(19)\n", encoding="utf-8")
            gofmt.chmod(0o755)

            result = self._run_format_check(home, system_bin)

            self.assertNotEqual(0, result.returncode, result.stdout)
            self.assertIn("gofmt", result.stdout)
            self.assertIn("19", result.stdout)

    def test_format_check_resolves_managed_tools_without_makefile_path_policy(self):
        source = MAKEFILE.read_text(encoding="utf-8")
        self.assertNotIn("MANAGED_BIN", source)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            managed_bin = home / ".local" / "bin"
            system_bin = root / "system-bin"
            log = root / "tools.log"
            managed_bin.mkdir(parents=True)
            system_bin.mkdir()
            self._prepare_controller_prerequisites(system_bin)
            for name in ("ruff", "gofmt", "tofu"):
                self._write_tool(managed_bin, name, log)

            result = self._run_format_check(home, system_bin)

            self.assertEqual(0, result.returncode, result.stdout)
            invoked = [line.split()[0] for line in log.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(["ruff", "gofmt", "tofu"], invoked)

    def test_format_check_fails_when_managed_tool_is_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            managed_bin = home / ".local" / "bin"
            system_bin = root / "system-bin"
            log = root / "tools.log"
            managed_bin.mkdir(parents=True)
            system_bin.mkdir()
            self._prepare_controller_prerequisites(system_bin)
            self._write_tool(managed_bin, "gofmt", log)
            self._write_tool(managed_bin, "tofu", log)

            result = self._run_format_check(home, system_bin)

            self.assertNotEqual(0, result.returncode, result.stdout)
            self.assertIn("ruff", result.stdout)
            self.assertFalse(log.exists(), "the later formatter must not mask the missing tool")

    def test_env_check_uses_the_hash_locked_qualification_provider(self):
        source = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn('PATH="$(QUALIFICATION_BIN):$$PATH" $(QUALIFICATION_PYTHON)', source)
        self.assertIn("config/python/requirements.lock", (ROOT / "scripts/capability_bootstrap.py").read_text())

    @staticmethod
    def _ansible_version() -> str:
        lock = json.loads((ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8"))
        version = lock.get("versions", {}).get("ANSIBLE_CORE_VERSION")
        if not version:
            raise AssertionError("ANSIBLE_CORE_VERSION is missing from central toolchain lock")
        return str(version)
