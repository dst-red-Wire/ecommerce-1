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


def seed_fixture(root):
    (root / "Makefile").write_bytes((ROOT / "Makefile").read_bytes())
    (root / "scripts").mkdir()
    (root / "scripts/capability_bootstrap.py").write_text(
        "import sys; from pathlib import Path\n"
        "assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode\n"
        "if sys.argv[1] == 'select-seed-python':\n"
        f"    sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
        "    from capability_bootstrap import main\n"
        "    raise SystemExit(main(['select-seed-python']))\n"
        "Path('validated').touch()\n"
    )


class SeedFastPathContractTest(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX OS interpreter regression")
    def test_make_seed_never_executes_the_unvalidated_cached_python(self):
        import shutil

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed_fixture(root)
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
            env = dict(os.environ, PATH=os.pathsep.join([str(cached), str(trusted)]))
            env.pop("OS", None)
            result = subprocess.run([shutil.which("make"), "seed"], cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertTrue((root / "validated").exists())
            self.assertTrue(selected.exists(), "select the validated provisioned PATH interpreter")

    @unittest.skipIf(os.name == "nt", "POSIX executable fixtures")
    def test_make_seed_excludes_relative_and_aliased_cache_roots(self):
        import shutil

        for alias in (False, True):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                seed_fixture(root)
                cache = root / "cache"
                cache.mkdir()
                cached = cache / "python3"
                cached.write_text("invalid cached executable must never run")
                cached.chmod(0o755)
                (root / "alias").symlink_to(cache, target_is_directory=True)
                trusted = root / "trusted"
                trusted.mkdir()
                (trusted / "python3").symlink_to(getattr(sys, "_base_executable", sys.executable))
                env = dict(os.environ, PATH=f"{cache}:{trusted}", ECOMMERCE_TOOL_HOME="alias" if alias else "cache")
                env.pop("OS", None)
                result = subprocess.run(
                    [shutil.which("make"), "seed"], cwd=root, env=env, capture_output=True, text=True
                )
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertTrue((root / "validated").exists())

    @unittest.skipIf(os.name == "nt", "Linux GNU Make fixture simulates Windows override; no native Windows claim")
    def test_windows_make_requires_explicit_provisioned_python_exe(self):
        import shutil

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed_fixture(root)
            cache = root / "MixedCache"
            cache.mkdir()
            (cache / "python.exe").write_text("untrusted executable must never run")
            (cache / "python.exe").chmod(0o755)
            trusted = root / "trusted"
            trusted.mkdir()
            provisioned = trusted / "python.exe"
            provisioned.symlink_to(getattr(sys, "_base_executable", sys.executable))
            env = dict(os.environ, OS="Windows_NT", PATH=f"{cache};{trusted}", ECOMMERCE_TOOL_HOME=str(cache).upper())
            refused = subprocess.run([shutil.which("make"), "seed"], cwd=root, env=env, capture_output=True, text=True)
            self.assertNotEqual(0, refused.returncode)
            self.assertIn("Automatic Windows seed discovery is unsupported", refused.stderr)
            self.assertFalse((root / "validated").exists())
            explicit = subprocess.run(
                [shutil.which("make"), "seed", f"SEED_PYTHON={provisioned}"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, explicit.returncode, explicit.stdout + explicit.stderr)
            self.assertTrue((root / "validated").exists())

    @unittest.skipIf(os.name == "nt", "Native POSIX writable-path refusal")
    def test_make_seed_skips_externally_writable_path_candidates_without_execution(self):
        import shutil

        for permission_target in ("directory", "sticky-directory", "ancestor", "file", "alias"):
            with self.subTest(permission_target=permission_target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                seed_fixture(root)
                external = root / "external"
                untrusted = external / "bin"
                untrusted.mkdir(parents=True)
                marker = root / "untrusted-executed"
                executable = untrusted / "python3"
                executable.write_text(f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n")
                executable.chmod(0o755)
                if permission_target == "file":
                    executable.chmod(0o777)
                elif permission_target == "ancestor":
                    external.chmod(0o777)
                else:
                    untrusted.chmod(0o1777 if permission_target == "sticky-directory" else 0o777)
                first = untrusted
                if permission_target == "alias":
                    first = root / "alias"
                    first.symlink_to(untrusted, target_is_directory=True)
                trusted = root / "trusted"
                trusted.mkdir()
                (trusted / "python3").symlink_to(getattr(sys, "_base_executable", sys.executable))
                env = dict(os.environ, PATH=f"{first}:{trusted}")
                env.pop("OS", None)
                result = subprocess.run(
                    [shutil.which("make"), "seed"], cwd=root, env=env, capture_output=True, text=True
                )
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertTrue((root / "validated").exists())
                self.assertFalse(marker.exists())

    @unittest.skipIf(os.name == "nt", "Native POSIX executability and directory checks")
    def test_make_seed_skips_nonexecutables_directories_and_cyclic_candidates(self):
        import shutil

        for kind in ("nonexecutable", "directory", "cycle"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                seed_fixture(root)
                first = root / "first"
                first.mkdir()
                unusable = first / "python3"
                if kind == "nonexecutable":
                    unusable.write_text("not executable")
                    unusable.chmod(0o644)
                elif kind == "directory":
                    unusable.mkdir()
                else:
                    unusable.symlink_to(unusable.name)
                trusted = root / "trusted"
                trusted.mkdir()
                (trusted / "python3").symlink_to(getattr(sys, "_base_executable", sys.executable))
                env = dict(os.environ, PATH=f"{first}:{trusted}")
                env.pop("OS", None)
                result = subprocess.run(
                    [shutil.which("make"), "seed"], cwd=root, env=env, capture_output=True, text=True
                )
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertTrue((root / "validated").exists())

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
