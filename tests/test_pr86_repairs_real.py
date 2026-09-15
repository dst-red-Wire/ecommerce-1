"""Real Ansible/Galaxy repairs in dedicated temporary destinations (no daemon changes)."""

import json
import hashlib
import io
import tarfile
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class DockerClientRepairReal(unittest.TestCase):
    def test_real_client_repairs_and_concurrent_candidates(self):
        pins = dict(
            line.split("=", 1)
            for line in (ROOT / "config/toolchain/versions.env").read_text().splitlines()
            if "=" in line and not line.startswith("#")
        )
        version = pins["DOCKER_CLIENT_VERSION"]
        archive = Path.home() / f".cache/ecommerce-1/docker-{version}.tgz"
        with tempfile.TemporaryDirectory(prefix="pr86-docker-repair-") as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            cached = cache / archive.name
            if archive.is_file():
                shutil.copyfile(archive, cached)
            before_archive = cached.stat().st_mtime_ns if cached.exists() else None
            variables = {
                "repo_root": str(ROOT),
                "local_bin": str(root / "bin"),
                "local_share": str(root / "share"),
                "local_cache": str(cache),
                "terraform_plugin_cache": str(root / "terraform"),
            }
            arguments = [
                str(ROOT / ".venv/qualification/bin/ansible-playbook"),
                "-i",
                "localhost,",
                "-c",
                "local",
                "platform/ansible/developer.yml",
                "--tags",
                "docker_client",
                "-e",
                json.dumps(variables),
            ]
            env = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / "platform/ansible/ansible.cfg"))
            binary = root / f"share/tools/docker-{version}/docker"

            def check(result):
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn(
                    f"Docker version {version},", subprocess.check_output([str(binary), "--version"], text=True)
                )
                self.assertEqual([], list(binary.parent.glob(".candidate-*")))
                if before_archive is not None:
                    self.assertEqual(before_archive, cached.stat().st_mtime_ns)

            def run():
                return subprocess.run(arguments, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)

            def corrupt(content):
                replacement = binary.with_name("corrupt-fixture")
                replacement.write_bytes(content)
                replacement.chmod(0o755)
                os.replace(replacement, binary)

            for case in ("absent", "truncated", "inexecutable", "wrong-version"):
                if case == "truncated":
                    corrupt(b"broken executable")
                if case == "inexecutable":
                    binary.chmod(0o644)
                if case == "wrong-version":
                    corrupt(b'#!/usr/bin/python3\nprint("Docker version 1.0.0, build fixture")\n')
                    binary.chmod(0o755)
                check(run())
                before_archive = cached.stat().st_mtime_ns
                print(f"PASS real Docker repair {case}")
            before = binary.stat().st_ino
            check(run())
            self.assertEqual(before, binary.stat().st_ino)
            corrupt(b"concurrent repair")
            first = subprocess.Popen(
                arguments, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            second = subprocess.Popen(
                arguments, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            results = []
            for process in (first, second):
                stdout, stderr = process.communicate(timeout=120)
                results.append(subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr))
            for result in results:
                check(result)
            print("PASS real Docker concurrent candidates and warm reuse")
            # Simulate an invalid candidate from an isolated test archive, retaining
            # a working older client. Production still consumes only canonical pins.
            older = b'#!/usr/bin/python3\nprint("Docker version 1.0.0, build old")\n'
            corrupt(older)
            with tarfile.open(cached, "w:gz") as bundle:
                info = tarfile.TarInfo("docker/docker")
                invalid = b"not an executable"
                info.size = len(invalid)
                info.mode = 0o755
                bundle.addfile(info, io.BytesIO(invalid))
            bad_variables = {**variables, "docker_client_sha256": hashlib.sha256(cached.read_bytes()).hexdigest()}
            failed = subprocess.run(
                [*arguments[:-1], json.dumps(bad_variables)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=120,
            )
            self.assertNotEqual(0, failed.returncode)
            self.assertEqual(older, binary.read_bytes())
            self.assertEqual([], list(binary.parent.glob(".candidate-*")))


class CollectionsRepairReal(unittest.TestCase):
    def test_real_offline_repair_and_concurrent_generation_readers(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import ansible_collections as collections

        original_archives = collections.paths()[0]
        with tempfile.TemporaryDirectory(prefix="pr86-collections-repair-") as directory:
            root = Path(directory)
            shutil.copytree(original_archives, root / "ansible/archives")
            env = dict(
                os.environ,
                ECOMMERCE_TOOL_HOME=str(root),
                PATH=str(ROOT / ".venv/qualification/bin") + os.pathsep + os.environ.get("PATH", ""),
            )
            command = [
                str(ROOT / ".venv/qualification/bin/python"),
                "scripts/ansible_collections.py",
                "prepare",
                "--offline",
            ]
            cold = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=180)
            self.assertEqual(0, cold.returncode, cold.stdout + cold.stderr)
            selector = root / f"ansible/collections/{collections.identity()}.current"
            old = selector.resolve()
            # Loading a real collection filter through a canonical consumer must
            # leave the verified generation reusable (including its inventory).
            import capability_bootstrap as bootstrap

            playbook = root / "consume.yml"
            playbook.write_text(
                json.dumps(
                    [
                        {
                            "hosts": "localhost",
                            "gather_facts": False,
                            "tasks": [
                                {
                                    "name": "Import a collection filter",
                                    "ansible.builtin.assert": {
                                        "that": ["([('a', 1)] | community.general.dict).a == 1"]
                                    },
                                }
                            ],
                        }
                    ]
                )
            )
            with mock.patch.object(collections, "TOOL_HOME", root), mock.patch.dict(os.environ, env):
                consumer = bootstrap.default_runner(
                    [
                        str(ROOT / ".venv/qualification/bin/ansible-playbook"),
                        "-i",
                        "localhost,",
                        "-c",
                        "local",
                        str(playbook),
                    ]
                )
            self.assertEqual(0, consumer.returncode, consumer.stdout + consumer.stderr)
            after_consumer = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=90)
            self.assertEqual(0, after_consumer.returncode, after_consumer.stdout + after_consumer.stderr)
            self.assertIn("REUSE collections", after_consumer.stdout)
            self.assertNotIn("PUBLISH", after_consumer.stdout)
            self.assertEqual(old, selector.resolve())
            payload = old / "ansible_collections/ansible/posix/plugins/modules/mount.py"
            late_file = old / "ansible_collections/community/docker/plugins/modules/docker_container.py"
            late_contents = late_file.read_bytes()
            payload.unlink()
            start = time.monotonic()
            processes = [
                subprocess.Popen(command, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for _ in range(2)
            ]
            outputs = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=180)
                self.assertEqual(0, process.returncode, stdout + stderr)
                outputs.append(stdout)
                self.assertEqual(late_contents, late_file.read_bytes())
            self.assertEqual(1, sum("PUBLISH collections" in output for output in outputs))
            self.assertNotEqual(old, selector.resolve())
            self.assertTrue(old.is_dir())
            print(f"PASS real offline concurrent Galaxy repair seconds={time.monotonic() - start:.3f}")
            start = time.monotonic()
            warm = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=90)
            self.assertEqual(0, warm.returncode, warm.stdout + warm.stderr)
            self.assertIn("REUSE collections", warm.stdout)
            self.assertNotIn("ACQUIRE", warm.stdout)
            self.assertNotIn("PUBLISH", warm.stdout)
            print(f"PASS real complete closure warm verification seconds={time.monotonic() - start:.3f}")
