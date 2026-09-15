"""Real locked seed recovery, with every mutation isolated from persistent caches."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SeedRepairReal(unittest.TestCase):
    def test_corrupt_active_seed_repairs_once_and_serializes_writers(self):
        with tempfile.TemporaryDirectory(prefix="pr86-seed-") as directory:
            root = Path(directory)
            reference = root / "checkout/.venv/qualification"
            runner = root / "seed.py"
            runner.write_text(
                "import sys\nfrom pathlib import Path\n"
                f"sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
                "import capability_bootstrap as b\n"
                f"b.LOCAL_SEED_VENV = Path({str(reference)!r})\n"
                "raise SystemExit(b.seed_environment())\n"
            )
            env = dict(os.environ, ECOMMERCE_TOOL_HOME=str(root / "tools"))

            def invoke(python):
                return subprocess.run([str(python), str(runner)], env=env, text=True, capture_output=True, timeout=240)

            cold = invoke(sys.executable)
            self.assertEqual(0, cold.returncode, cold.stdout + cold.stderr)
            old = reference.resolve()
            python = old / "bin/python"
            package = next(old.glob("lib/python*/site-packages/ansible_core-*.dist-info/METADATA"))
            original = package.read_text()
            package.write_text(original.replace("Version: 2.20.3", "Version: 0.0.0", 1))
            # A failed preparation must leave the published reference usable.
            failed_runner = root / "failed.py"
            failed_runner.write_text(
                runner.read_text().replace(
                    "raise SystemExit(b.seed_environment())",
                    "from unittest import mock\n"
                    "real_run = b.subprocess.run\n"
                    "def fail(command, **kwargs):\n"
                    "    if '-m' in command and 'venv' in command: raise RuntimeError('controlled preparation failure')\n"
                    "    return real_run(command, **kwargs)\n"
                    "with mock.patch.object(b.subprocess, 'run', side_effect=fail): b.seed_environment()",
                )
            )
            failed = subprocess.run(
                [str(python), str(failed_runner)], env=env, capture_output=True, text=True, timeout=60
            )
            self.assertNotEqual(0, failed.returncode)
            self.assertEqual(old, reference.resolve())
            self.assertTrue(python.exists())
            first = subprocess.Popen(
                [str(python), str(runner)], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            second = subprocess.Popen(
                [str(python), str(runner)], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            for process in (first, second):
                output, error = process.communicate(timeout=240)
                self.assertEqual(0, process.returncode, output + error)
            repaired = reference.resolve()
            self.assertNotEqual(old, repaired)
            self.assertTrue(python.exists(), "running consumers retain their original generation")
            self.assertTrue(package.exists())
            warm = invoke(reference / "bin/python")
            self.assertEqual(0, warm.returncode, warm.stdout + warm.stderr)
            self.assertIn("REUSE qualification seed", warm.stdout)
            self.assertNotIn("PREPARE qualification seed", warm.stdout)
            self.assertEqual(repaired, reference.resolve())
            for command in (
                [str(reference / "bin/python"), "-m", "pip", "check"],
                [str(reference / "bin/ansible-playbook"), "--version"],
            ):
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
