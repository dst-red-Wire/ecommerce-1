"""Trusted controller static validators must read one target data tree coherently."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import capability_bootstrap as bootstrap

ROOT = Path(__file__).resolve().parents[1]
PROJECTIONS = (
    "config/contracts/toolchain-lock.json",
    "config/toolchain/versions.env",
    "config/toolchain/capabilities.json",
    "config/python/requirements.lock",
    "platform/ansible/requirements.yml",
    "platform/ansible/ansible.cfg",
    ".bazelversion",
    ".bazelrc",
)


class TrustedToolchainProjectionTest(unittest.TestCase):
    def setUp(self):
        clean_environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("REPOCTL_TRUSTED_", "GIT_"))
        }
        self.environment = mock.patch.dict(os.environ, clean_environment, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    @staticmethod
    def git(target: Path, *arguments: str) -> str:
        return subprocess.run(
            [
                "git",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "user.name=Projection Fixture",
                "-c",
                "user.email=projection-fixture@example.invalid",
                "-C",
                str(target),
                *arguments,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()

    def commit_fixture(self, target: Path) -> str:
        self.git(target, "init", "-q")
        self.git(target, "add", ".")
        self.git(target, "commit", "-qm", "Projection fixture")
        return self.git(target, "rev-parse", "HEAD")

    @staticmethod
    def trusted_context(target: Path, sha: str, *, policy: bool = False):
        return mock.patch.dict(
            os.environ,
            {
                "REPOCTL_TRUSTED_POLICY_ROOT"
                if policy
                else "REPOCTL_TRUSTED_TARGET_ROOT": str(target),
                "REPOCTL_TRUSTED_BASE_SHA"
                if policy
                else "REPOCTL_TRUSTED_HEAD_SHA": sha,
            },
        )

    def fixture(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        directory = tempfile.TemporaryDirectory()
        target = Path(directory.name)
        for relative in PROJECTIONS:
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        return directory, target

    @staticmethod
    def contract(target: Path) -> dict:
        return json.loads(
            (target / "config/contracts/toolchain-lock.json").read_text(
                encoding="utf-8"
            )
        )

    def test_coherent_target_versions_are_checked_in_target_tree(self):
        directory, target = self.fixture()
        try:
            lock = self.contract(target)
            old_version = lock["versions"]["RUFF_VERSION"]
            new_version = "0.0.0"
            self.assertNotEqual(old_version, new_version)
            lock["versions"]["RUFF_VERSION"] = new_version
            (target / "config/contracts/toolchain-lock.json").write_text(
                json.dumps(lock), encoding="utf-8"
            )
            versions = target / "config/toolchain/versions.env"
            versions.write_text(
                versions.read_text(encoding="utf-8").replace(
                    f"RUFF_VERSION={old_version}", f"RUFF_VERSION={new_version}", 1
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                old_version, bootstrap.load_toolchain_lock()["versions"]["RUFF_VERSION"]
            )
            bootstrap.validate_toolchain_projections(lock, root=target)
        finally:
            directory.cleanup()

    def test_each_target_projection_drift_fails_closed(self):
        cases = {
            "versions": (
                "config/toolchain/versions.env",
                "RUFF_VERSION=",
                "RUFF_VERSION=0.0.0 #",
            ),
            "ansible_collections": ("platform/ansible/requirements.yml", None, None),
            "command_capabilities": (
                "config/toolchain/capabilities.json",
                '"tofu": "opentofu"',
                '"tofu": "go"',
            ),
            "ansible_config": (
                "platform/ansible/ansible.cfg",
                "[defaults]",
                "[defaults]\ndrift = true",
            ),
            "bazel_version": (".bazelversion", None, "0.0.0\n"),
            "bazelrc": (".bazelrc", None, "--drift\n"),
            "seed_lock": ("config/python/requirements.lock", None, None),
        }
        for name, (relative, old, new) in cases.items():
            with self.subTest(name=name):
                directory, target = self.fixture()
                try:
                    path = target / relative
                    source = path.read_text(encoding="utf-8")
                    if name == "seed_lock":
                        pin = self.contract(target)["versions"]["PYYAML_VERSION"]
                        changed = re.sub(
                            rf"(?im)^pyyaml=={re.escape(pin)}",
                            "PyYAML==0.0.0",
                            source,
                            count=1,
                        )
                    elif name == "ansible_collections":
                        changed = re.sub(
                            r"(?m)^(\s*version:\s*)[^\s#]+",
                            r"\g<1>0.0.0",
                            source,
                            count=1,
                        )
                    elif old is None:
                        changed = new if name == "bazel_version" else source + new
                    else:
                        changed = source.replace(old, new, 1)
                    self.assertNotEqual(source, changed)
                    path.write_text(changed, encoding="utf-8")
                    with self.assertRaises((ValueError, OSError)):
                        bootstrap.validate_toolchain_projections(
                            self.contract(target), root=target
                        )
                finally:
                    directory.cleanup()

    def test_each_projection_rejects_symlinks_with_matching_external_bytes(self):
        for relative in PROJECTIONS:
            with self.subTest(relative=relative):
                directory, target = self.fixture()
                with directory, tempfile.TemporaryDirectory() as external_directory:
                    bootstrap.validate_toolchain_projections(root=target)
                    path = target / relative
                    external = Path(external_directory) / "matching-projection"
                    external.write_bytes(path.read_bytes())
                    path.unlink()
                    path.symlink_to(external)
                    with self.assertRaises((ValueError, OSError)):
                        bootstrap.validate_toolchain_projections(root=target)

    def test_symlinked_repository_root_or_projection_parent_is_rejected(self):
        directory, target = self.fixture()
        with directory, tempfile.TemporaryDirectory() as links_directory:
            bootstrap.validate_toolchain_projections(root=target)
            linked_root = Path(links_directory) / "repository"
            linked_root.symlink_to(target, target_is_directory=True)
            with self.assertRaises((ValueError, OSError)):
                bootstrap.validate_toolchain_projections(root=linked_root)
            (target / "config").rename(target / "real-config")
            (target / "config").symlink_to(
                target / "real-config", target_is_directory=True
            )
            with self.assertRaises((ValueError, OSError)):
                bootstrap.validate_toolchain_projections(root=target)

    def test_repository_data_rejects_parent_traversal_and_external_absolute_path(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "repository"
            target.mkdir()
            outside = parent / "outside.txt"
            outside.write_text("valid data", encoding="utf-8")
            inside = target / "inside.txt"
            inside.write_text("valid data", encoding="utf-8")
            self.assertEqual(
                "valid data", bootstrap.read_repository_text(inside, root=target)
            )
            for path in (
                target / ".." / "outside.txt",
                outside,
                target / "nested" / ".." / "inside.txt",
            ):
                with (
                    self.subTest(path=path),
                    self.assertRaises((ValueError, OSError)),
                ):
                    bootstrap.read_repository_text(path, root=target)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO regression requires POSIX")
    def test_repository_data_rejects_fifo_and_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            fifo = target / "fifo"
            os.mkfifo(fifo)
            folder = target / "directory"
            folder.mkdir()
            for path in (fifo, folder):
                with (
                    self.subTest(path=path),
                    self.assertRaises((ValueError, OSError)),
                ):
                    bootstrap.read_repository_text(path, root=target)

    def test_repository_data_read_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            path = target / "oversized.txt"
            with path.open("wb") as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            with self.assertRaises((ValueError, OSError)):
                bootstrap.read_repository_text(path, root=target)

    def test_trusted_projection_reads_require_exact_blob_despite_clean_git_status(self):
        for policy in (False, True):
            with self.subTest(policy=policy):
                directory, target = self.fixture()
                with directory:
                    sha = self.commit_fixture(target)
                    path = target / ".bazelversion"
                    committed = path.read_text(encoding="utf-8")
                    with self.trusted_context(target, sha, policy=policy):
                        bootstrap.validate_toolchain_projections(root=target)
                        self.assertEqual(
                            committed,
                            bootstrap.read_repository_text(path, root=target),
                        )
                        self.git(
                            target,
                            "update-index",
                            "--assume-unchanged",
                            ".bazelversion",
                        )
                        path.write_text(committed + "\n", encoding="utf-8")
                        self.assertEqual("", self.git(target, "status", "--porcelain"))
                        with self.assertRaises((ValueError, OSError)):
                            bootstrap.validate_toolchain_projections(root=target)
                    # The changed bytes still represent a valid ordinary working tree.
                    bootstrap.validate_toolchain_projections(root=target)

    def test_trusted_windows_projection_accepts_only_exact_crlf_conversion(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            windows = target / "scripts" / "windows"
            windows.mkdir(parents=True)
            (target / ".gitattributes").write_text(
                "*.ps1 text eol=crlf\n*.bat text eol=crlf\n*.cmd text eol=crlf\n",
                encoding="utf-8",
            )
            source = "echo baseline\necho completed\n"
            paths = [
                windows / f"projection{suffix}" for suffix in (".ps1", ".bat", ".cmd")
            ]
            for path in paths:
                path.write_bytes(source.encode("utf-8"))
            json_path = target / "contract.json"
            json_source = '{"version":1}\n'
            json_path.write_bytes(json_source.encode("utf-8"))
            sha = self.commit_fixture(target)
            with self.trusted_context(target, sha):
                for path in paths:
                    with self.subTest(suffix=path.suffix):
                        checkout = source.replace("\n", "\r\n")
                        path.write_bytes(checkout.encode("utf-8"))
                        self.assertEqual(
                            source, bootstrap.read_repository_text(path, root=target)
                        )
                        for changed in (
                            checkout.replace("baseline", "baselinX", 1),
                            checkout + "echo extra\r\n",
                        ):
                            with self.subTest(changed=changed):
                                path.write_bytes(changed.encode("utf-8"))
                                with self.assertRaises(ValueError):
                                    bootstrap.read_repository_text(path, root=target)
                        path.write_bytes(checkout.encode("utf-8"))
                self.assertEqual(
                    json_source,
                    bootstrap.read_repository_text(json_path, root=target),
                )
                json_path.write_bytes(json_source.replace("\n", "\r\n").encode("utf-8"))
                with self.assertRaises(ValueError):
                    bootstrap.read_repository_text(json_path, root=target)

    def test_incomplete_trusted_binding_fails_outside_native_worktree_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            path = target / "data.txt"
            path.write_text("committed data\n", encoding="utf-8")
            sha = self.commit_fixture(target)
            contexts = (
                {"REPOCTL_TRUSTED_TARGET_ROOT": str(target)},
                {"REPOCTL_TRUSTED_HEAD_SHA": sha},
                {"REPOCTL_TRUSTED_POLICY_ROOT": str(target)},
                {"REPOCTL_TRUSTED_BASE_SHA": sha},
            )
            self.assertNotIn("REPOCTL_TRUSTED_NATIVE_UAC", os.environ)
            for context in contexts:
                with (
                    self.subTest(context=context),
                    mock.patch.dict(os.environ, context),
                    self.assertRaises(ValueError),
                ):
                    bootstrap.read_repository_text(path, root=target)

    def test_nested_trusted_checkout_uses_its_own_base_blob(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            target_data = target / "data.txt"
            target_data.write_text("target-only data\n", encoding="utf-8")
            head_sha = self.commit_fixture(target)
            policy = target / ".context" / "trusted-base"
            policy.mkdir(parents=True)
            policy_data = policy / "data.txt"
            policy_data.write_text("base-only data\n", encoding="utf-8")
            base_sha = self.commit_fixture(policy)
            self.assertNotEqual(head_sha, base_sha)
            with mock.patch.dict(
                os.environ,
                {
                    "REPOCTL_TRUSTED_TARGET_ROOT": str(target),
                    "REPOCTL_TRUSTED_HEAD_SHA": head_sha,
                    "REPOCTL_TRUSTED_POLICY_ROOT": str(policy),
                    "REPOCTL_TRUSTED_BASE_SHA": base_sha,
                },
            ):
                self.assertEqual(
                    "target-only data\n",
                    bootstrap.read_repository_text(target_data, root=target),
                )
                self.assertEqual(
                    "base-only data\n",
                    bootstrap.read_repository_text(policy_data, root=policy),
                )
                # A target consumer cannot borrow the nested base namespace.
                with self.assertRaises(ValueError):
                    bootstrap.read_repository_text(policy_data, root=target)
                policy_data.write_bytes(target_data.read_bytes())
                with self.assertRaises(ValueError):
                    bootstrap.read_repository_text(policy_data, root=policy)

    def test_committed_symlink_mode_rejected_even_when_worktree_file_is_regular(self):
        directory, target = self.fixture()
        with directory:
            path = target / ".bazelversion"
            valid_bytes = path.read_bytes()
            path.unlink()
            # A symlink blob is its target text. Keep that blob identical to the
            # eventual regular file so rejection depends on Git mode 120000.
            path.symlink_to(valid_bytes.decode("utf-8"))
            sha = self.commit_fixture(target)
            self.assertTrue(
                self.git(target, "ls-tree", sha, "--", ".bazelversion").startswith(
                    "120000 blob "
                )
            )
            self.git(target, "update-index", "--assume-unchanged", ".bazelversion")
            path.unlink()
            path.write_bytes(valid_bytes)
            self.assertFalse(path.is_symlink())
            self.assertEqual(
                self.git(target, "rev-parse", f"{sha}:.bazelversion"),
                self.git(target, "hash-object", ".bazelversion"),
            )
            self.assertEqual("", self.git(target, "status", "--porcelain"))
            with (
                self.trusted_context(target, sha),
                self.assertRaises((ValueError, OSError)),
            ):
                bootstrap.validate_toolchain_projections(root=target)

    def optional_fixture(self) -> tuple[tempfile.TemporaryDirectory, Path, dict, dict]:
        directory, target = self.fixture()
        lock = self.contract(target)
        graph = json.loads(
            (target / "config/toolchain/capabilities.json").read_text(encoding="utf-8")
        )
        if "optional-tooling" not in lock["capability_policy"]["requirements"]:
            lock["capability_policy"]["requirements"].append("optional-tooling")
        next(item for item in graph["capabilities"] if item["name"] == "nx")[
            "requirement"
        ] = "optional-tooling"
        for gate, commands in graph["gate_requirements"].items():
            if gate != "optional-agent-tooling" and "nx" in commands:
                commands.remove("nx")
        optional = graph["gate_requirements"].setdefault("optional-agent-tooling", [])
        if "nx" not in optional:
            optional.append("nx")
        script = target / "scripts/malicious.py"
        script.parent.mkdir(parents=True)
        script.write_text(
            'raise RuntimeError("HEAD script was executed")\n'
            "def registered_command():\n"
            '    run(["nx", "--version"])\n',
            encoding="utf-8",
        )
        graph["gate_sources"] = ["scripts/malicious.py"]
        return directory, target, lock, graph

    def test_optional_tooling_is_data_only_and_head_script_is_not_executed(self):
        directory, target, lock, graph = self.optional_fixture()
        try:
            bootstrap.validate_contract(
                graph,
                lock["versions"],
                root=target,
                allowed_requirements=lock["capability_policy"]["requirements"],
            )
        finally:
            directory.cleanup()

    def test_gate_source_symlink_is_rejected_even_with_valid_external_ast(self):
        directory, target, lock, graph = self.optional_fixture()
        with directory, tempfile.TemporaryDirectory() as external_directory:
            source = target / graph["gate_sources"][0]
            external = Path(external_directory) / "matching-source.py"
            external.write_bytes(source.read_bytes())
            source.unlink()
            source.symlink_to(external)
            with self.assertRaises((ValueError, OSError)):
                bootstrap.validate_contract(
                    graph,
                    lock["versions"],
                    root=target,
                    allowed_requirements=lock["capability_policy"]["requirements"],
                )

    def test_committed_gate_source_is_parsed_without_executing_head_code(self):
        directory, target, lock, graph = self.optional_fixture()
        with directory:
            source = target / graph["gate_sources"][0]
            marker = target / "head-code-executed"
            source.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
                + source.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (target / "config/contracts/toolchain-lock.json").write_text(
                json.dumps(lock), encoding="utf-8"
            )
            (target / "config/toolchain/capabilities.json").write_text(
                json.dumps(graph), encoding="utf-8"
            )
            sha = self.commit_fixture(target)
            with self.trusted_context(target, sha):
                bootstrap.validate_contract(
                    graph,
                    lock["versions"],
                    root=target,
                    allowed_requirements=lock["capability_policy"]["requirements"],
                )
            self.assertFalse(marker.exists())

    def test_optional_tooling_cannot_enter_real_gate_or_dependency(self):
        directory, target, lock, graph = self.optional_fixture()
        try:
            graph["gate_requirements"]["lint"].append("nx")
            with self.assertRaisesRegex(
                ValueError, "optional tooling cannot enter a real gate"
            ):
                bootstrap.validate_contract(
                    graph,
                    lock["versions"],
                    root=target,
                    allowed_requirements=lock["capability_policy"]["requirements"],
                )
            graph["gate_requirements"]["lint"].remove("nx")
            graph["capabilities"].append(
                {
                    "name": "qualification-proxy",
                    "classification": "conditional",
                    "requirement": "required-static",
                    "command": "qualification-proxy",
                    "requires": ["nx"],
                }
            )
            graph["gate_requirements"]["lint"].append("qualification-proxy")
            with self.assertRaisesRegex(
                ValueError, "optional tooling cannot enter a real gate"
            ):
                bootstrap.validate_contract(
                    graph,
                    lock["versions"],
                    root=target,
                    allowed_requirements=lock["capability_policy"]["requirements"],
                )
        finally:
            directory.cleanup()

    def test_target_cannot_define_new_requirement_semantics(self):
        directory, target, lock, graph = self.optional_fixture()
        try:
            lock["capability_policy"]["requirements"].append("head-defined-exemption")
            with self.assertRaisesRegex(
                ValueError, "unsupported capability requirement"
            ):
                bootstrap.validate_contract(
                    graph,
                    lock["versions"],
                    root=target,
                    allowed_requirements=lock["capability_policy"]["requirements"],
                )
            with self.assertRaisesRegex(ValueError, "requirements must be a list"):
                bootstrap.validate_contract(
                    graph,
                    lock["versions"],
                    root=target,
                    allowed_requirements={"required-static": True},
                )
        finally:
            directory.cleanup()


if __name__ == "__main__":
    unittest.main()
