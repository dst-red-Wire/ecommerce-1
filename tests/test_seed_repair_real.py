"""Real locked seed recovery, with every mutation isolated from persistent caches."""

import os
from pathlib import Path
import shutil
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
                "raise SystemExit(b.main(['seed']))\n"
            )
            ambient = root / "ambient"
            ambient.mkdir()
            marker = root / "ambient-executed"
            (ambient / "sitecustomize.py").write_text(f"from pathlib import Path; Path({str(marker)!r}).touch()\n")
            env = dict(os.environ, ECOMMERCE_TOOL_HOME=str(root / "tools"), PYTHONPATH=str(ambient))

            def invoke(python):
                return subprocess.run(
                    [str(python), "-I", str(runner)], env=env, text=True, capture_output=True, timeout=240
                )

            cold = invoke(sys.executable)
            self.assertEqual(0, cold.returncode, cold.stdout + cold.stderr)
            self.assertFalse(marker.exists(), "seed child imported ambient sitecustomize")
            old = reference.resolve()
            # Exercise the public seed entry point before any candidate creation.
            # Every mutated path belongs to this dedicated temporary tool home.
            external = root / "external"
            external.mkdir()
            sentinel = external / "keep"
            sentinel.write_bytes(b"external data must remain untouched")
            before = (sentinel.read_bytes(), sentinel.stat().st_mtime_ns, external.stat().st_mtime_ns)
            for boundary in (old.parent, root / "tools/python"):
                saved = root / "saved-boundary"
                boundary.rename(saved)
                boundary.symlink_to(external, target_is_directory=True)
                refused = invoke(sys.executable)
                self.assertEqual(1, refused.returncode, refused.stdout + refused.stderr)
                self.assertIn("FAIL seed generation root", refused.stderr)
                self.assertNotIn("Traceback", refused.stderr)
                self.assertEqual([sentinel], list(external.iterdir()))
                self.assertEqual(
                    before, (sentinel.read_bytes(), sentinel.stat().st_mtime_ns, external.stat().st_mtime_ns)
                )
                boundary.unlink()
                saved.rename(boundary)
                restored = invoke(sys.executable)
                self.assertEqual(0, restored.returncode, restored.stdout + restored.stderr)
                self.assertIn("REUSE qualification seed", restored.stdout)
                self.assertEqual(old, reference.resolve())
            # Recover a polluted reference and a non-executable entrypoint
            # with acquisition disabled. Only trusted compatible wheels survive.
            wheels = next((root / "tools/python").glob("*.wheels"))
            original_wheels = len(list(wheels.glob("*.whl")))
            wheel = next(wheels.glob("*.whl"))
            parts = wheel.name.split("-")
            duplicate = wheels / "-".join([*parts[:2], "1", *parts[2:]])
            shutil.copyfile(wheel, duplicate)
            (wheels / "unexpected-1.0.0-py3-none-any.whl").write_bytes(b"untrusted")
            (old / "bin/ansible").chmod(0o644)
            env["PIP_NO_INDEX"] = "1"
            repaired_reference = invoke(sys.executable)
            self.assertEqual(0, repaired_reference.returncode, repaired_reference.stdout + repaired_reference.stderr)
            self.assertIn("PREPARE qualification seed", repaired_reference.stdout)
            self.assertNotEqual(old, reference.resolve())
            self.assertTrue((old / "bin/python").exists())
            self.assertEqual(original_wheels, len(list(wheels.glob("*.whl"))))
            self.assertTrue(os.access(reference / "bin/ansible", os.X_OK))
            old = reference.resolve()
            python = old / "bin/python"
            package = next(old.glob("lib/python*/site-packages/ansible/__init__.py"))
            original = package.read_text()
            package.write_text(original + "\n# corrupted payload without metadata changes\n")
            # A failed preparation must leave the published reference usable.
            failed_runner = root / "failed.py"
            failed_runner.write_text(
                runner.read_text().replace(
                    "raise SystemExit(b.main(['seed']))",
                    "from unittest import mock\n"
                    "real_run = b.subprocess.run\n"
                    "def fail(command, **kwargs):\n"
                    "    if '-m' in command and 'venv' in command: raise RuntimeError('controlled preparation failure')\n"
                    "    return real_run(command, **kwargs)\n"
                    "with mock.patch.object(b.subprocess, 'run', side_effect=fail): b.seed_environment()",
                )
            )
            generations_before = set(old.parent.iterdir())
            failed = subprocess.run(
                [str(python), "-I", str(failed_runner)], env=env, capture_output=True, text=True, timeout=60
            )
            self.assertNotEqual(0, failed.returncode)
            self.assertEqual(old, reference.resolve())
            self.assertTrue(python.exists())
            self.assertEqual(generations_before, set(old.parent.iterdir()))
            first = subprocess.Popen(
                [str(python), "-I", str(runner)], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            second = subprocess.Popen(
                [str(python), "-I", str(runner)], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
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
            duplicate_info = next(repaired.glob("lib/python*/site-packages")) / "ansible_core-0.0.0.dist-info"
            duplicate_info.mkdir()
            (duplicate_info / "METADATA").write_text("Name: Ansible_Core\nVersion: 0.0.0\n")
            duplicate_repair = invoke(reference / "bin/python")
            self.assertEqual(0, duplicate_repair.returncode, duplicate_repair.stdout + duplicate_repair.stderr)
            self.assertIn("PREPARE qualification seed", duplicate_repair.stdout)
            self.assertNotEqual(repaired, reference.resolve())
            self.assertTrue(duplicate_info.exists(), "published readers retain the old generation")
            warm = invoke(reference / "bin/python")
            self.assertEqual(0, warm.returncode, warm.stdout + warm.stderr)
            self.assertIn("REUSE qualification seed", warm.stdout)
            self.assertFalse(marker.exists(), "seed child imported ambient sitecustomize")
            for command in (
                [str(reference / "bin/python"), "-m", "pip", "check"],
                [str(reference / "bin/ansible-playbook"), "--version"],
            ):
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
