"""Trusted controller static validators must read one target data tree coherently."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest

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
