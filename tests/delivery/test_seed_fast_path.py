import importlib.util
import importlib.metadata
from pathlib import Path
import tempfile
import os
import subprocess
import sys
from unittest import mock
import unittest


ROOT = Path(__file__).resolve().parents[2]


class SeedFastPathContractTest(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX system interpreter regression")
    def test_make_seed_never_executes_the_unvalidated_cached_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Makefile").write_bytes((ROOT / "Makefile").read_bytes())
            scripts = root / "scripts"
            scripts.mkdir()
            marker = root / "validated"
            (scripts / "capability_bootstrap.py").write_text(
                "import sys; from pathlib import Path\n"
                "assert sys.flags.isolated and sys.flags.no_site\n"
                f"Path({str(marker)!r}).touch()\n"
            )
            cached = root / ".venv/qualification/bin"
            cached.mkdir(parents=True)
            for name in ("python", "python3"):
                (cached / name).write_text("invalid executable must never run")
                (cached / name).chmod(0o755)
            trusted = root / "provisioned-python"
            trusted.mkdir()
            selected = root / "selected-provisioned-python"
            base = getattr(sys, "_base_executable", sys.executable)
            shim = trusted / "python3"
            shim.write_text(
                f"#!{base}\nimport os, sys\nfrom pathlib import Path\n"
                f"Path({str(selected)!r}).touch()\n"
                f"os.execv({base!r}, [{base!r}, *sys.argv[1:]])\n"
            )
            shim.chmod(0o755)
            env = dict(os.environ, PATH=os.pathsep.join([str(cached), str(trusted), os.environ["PATH"]]))
            env.pop("OS", None)
            result = subprocess.run(["make", "seed"], cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertTrue(marker.exists())
            self.assertTrue(selected.exists(), "use the contracted PATH interpreter, not a hard-coded OS path")

    def test_seed_uses_lock_digest_and_pip_integrity_check(self):
        source = (ROOT / "scripts/capability_bootstrap.py").read_text(encoding="utf-8")
        body = source.split("def seed_environment", 1)[1].split("\ndef main", 1)[0]
        self.assertIn("lock_sha256", body)
        self.assertIn("check_seed_reference(wheels, seed_root)", body)
        self.assertIn("validate_seed_lock", body)
        self.assertIn('"--require-hashes"', body)
        self.assertLess(body.index("if valid():"), body.index('"install"'))

    def test_context_tools_parent_is_created_by_ansible(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn('- "{{ local_share }}/tools"', tasks)

    def test_duplicate_canonical_names_reject_warm_seed_even_when_pip_check_passes(self):
        import sys

        spec = importlib.util.spec_from_file_location("seed_duplicate_test", ROOT / "scripts/capability_bootstrap.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "requirements.lock"
            lock.write_text("demo-package==1.0\n")
            for second_version in ("1.0", "9.9"):
                with (
                    self.subTest(second_version=second_version),
                    mock.patch.object(importlib.metadata, "version", return_value="1.0"),
                    mock.patch.object(
                        importlib.metadata,
                        "distributions",
                        return_value=[
                            mock.Mock(metadata={"Name": "demo-package"}, version="1.0"),
                            mock.Mock(metadata={"Name": "Demo_Package"}, version=second_version),
                        ],
                    ),
                    mock.patch.object(module.subprocess, "run", return_value=mock.Mock(returncode=0)) as run,
                ):
                    self.assertFalse(module.validate_seed_lock(str(lock)))
                    with self.assertRaisesRegex(ValueError, "duplicate canonical"):
                        module.seed_unlocked_distributions(str(lock))
                    run.assert_not_called()

    def test_compatible_but_unlocked_dependency_is_rejected(self):
        spec = importlib.util.spec_from_file_location("seed_inventory_test", ROOT / "scripts/capability_bootstrap.py")
        module = importlib.util.module_from_spec(spec)
        import sys

        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "requirements.lock"
            lock.write_text("jinja2==3.1.6\npyyaml==6.0.2\n")
            with (
                mock.patch.object(
                    importlib.metadata, "version", side_effect=lambda name: {"jinja2": "3.1.7", "pyyaml": "6.0.2"}[name]
                ),
                mock.patch.object(module.subprocess, "run") as run,
            ):
                self.assertFalse(module.validate_seed_lock(str(lock)))
                run.assert_not_called()
            with (
                mock.patch.object(
                    importlib.metadata, "version", side_effect=lambda name: {"jinja2": "3.1.6", "pyyaml": "6.0.2"}[name]
                ),
                mock.patch.object(
                    importlib.metadata,
                    "distributions",
                    return_value=[mock.Mock(metadata={"Name": name}) for name in ("Jinja2", "PyYAML", "pip")],
                ),
                mock.patch.object(module.subprocess, "run", return_value=mock.Mock(returncode=0)),
            ):
                self.assertTrue(module.validate_seed_lock(str(lock)))
            with (
                mock.patch.object(
                    importlib.metadata, "version", side_effect=lambda name: {"jinja2": "3.1.6", "pyyaml": "6.0.2"}[name]
                ),
                mock.patch.object(
                    importlib.metadata,
                    "distributions",
                    return_value=[
                        mock.Mock(metadata={"Name": name}) for name in ("Jinja2", "PyYAML", "pip", "extra-compatible")
                    ],
                ),
                mock.patch.object(module.subprocess, "run") as run,
            ):
                self.assertEqual(["extra-compatible"], module.seed_unlocked_distributions(str(lock)))
                self.assertFalse(module.validate_seed_lock(str(lock)))
                run.assert_not_called()
            with mock.patch.object(importlib.metadata, "version", side_effect=importlib.metadata.PackageNotFoundError):
                self.assertFalse(module.validate_seed_lock(str(lock)))


if __name__ == "__main__":
    unittest.main()
