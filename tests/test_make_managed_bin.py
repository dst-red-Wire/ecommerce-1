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
            mutation = "MANAGED_BIN := $(HOME)/.local/bin\nPATH := $(MANAGED_BIN):$(PATH)\nexport PATH\n"
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
