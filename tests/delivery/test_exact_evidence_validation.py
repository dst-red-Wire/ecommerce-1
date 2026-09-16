import os
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("repoctl_evidence_validation_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class ExactEvidenceValidationTest(unittest.TestCase):
    def evidence(self):
        return {
            "schema_version": 5,
            "status": "PASS",
            "exact_commit_evidence": True,
            "head_sha": "h",
            "base_sha": "b",
            "head_tree_sha": "t",
            "changed_paths": ["x"],
            "qualification_identity": "identity",
            "created_at_epoch": time.time(),
            "gates": [{"gate": name, "status": "PASS"} for name, _ in REPOCTL._global_gate_commands("base", "h")],
        }

    def validate(self, evidence):
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory)
            path = context / "evidence" / "h.json"
            path.parent.mkdir()
            path.write_text(json.dumps(evidence))
            values = {
                ("rev-parse", "h"): "h",
                ("rev-parse", "HEAD"): "h",
                ("status", "--porcelain", "--untracked-files=all"): "",
                ("rev-parse", "base"): "b",
                ("rev-parse", "h^{tree}"): "t",
            }
            with (
                mock.patch.object(REPOCTL, "CONTEXT", context),
                mock.patch.object(REPOCTL, "git", side_effect=lambda *args: values[args]),
                mock.patch.object(REPOCTL, "changed_paths", return_value=["x"]),
                mock.patch.object(REPOCTL, "affected", return_value=["global"]),
                mock.patch.object(REPOCTL, "qualification_identity", return_value="identity"),
            ):
                return REPOCTL._valid_exact_evidence("base", "h")

    def test_accepts_current_exact_identity(self):
        self.assertIsNotNone(self.validate(self.evidence()))

    def test_rejects_stale_or_tampered_evidence(self):
        for field, value in (
            ("created_at_epoch", time.time() - 90000),
            ("qualification_identity", "tampered"),
            ("head_tree_sha", "wrong"),
            ("base_sha", "wrong"),
            ("gates", [{"status": "FAIL"}]),
        ):
            with self.subTest(field=field):
                evidence = self.evidence()
                evidence[field] = value
                self.assertIsNone(self.validate(evidence))

    def test_rejects_malformed_nonfinite_and_future_timestamps(self):
        for value in (
            None,
            "bad",
            "123",
            {},
            True,
            float("nan"),
            float("inf"),
            -float("inf"),
            10**400,
            time.time() + 60,
        ):
            with self.subTest(value=value):
                evidence = self.evidence()
                evidence["created_at_epoch"] = value
                self.assertIsNone(self.validate(evidence))

    def test_rejects_malformed_schema_without_aborting_validation(self):
        for value in (None, "5", {}, [], True, False, 5.0, float("nan"), float("inf"), 10**400, 6):
            with self.subTest(value=value):
                evidence = self.evidence()
                evidence["schema_version"] = value
                self.assertIsNone(self.validate(evidence))
                self.assertFalse(REPOCTL._supported_evidence_schema(evidence, 4))
                self.assertFalse(REPOCTL._supported_evidence_schema(evidence, 5))

    def test_tool_identity_changes_with_provider_bytes_and_ansible_version(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "ansible-playbook"
            executable.write_bytes(b"entrypoint")
            with (
                mock.patch.object(
                    REPOCTL.shutil,
                    "which",
                    side_effect=lambda name: str(executable) if name == "ansible-playbook" else None,
                ),
                mock.patch.object(
                    REPOCTL,
                    "run",
                    return_value=mock.Mock(returncode=0, stdout="ansible-playbook [core 2.20.3]", stderr=""),
                ) as probe,
            ):
                initial = REPOCTL.qualification_identity()
                probe.return_value.stdout = "ansible-playbook [core 2.16.3]"
                self.assertNotEqual(initial, REPOCTL.qualification_identity())
                probe.return_value.stdout = "ansible-playbook [core 2.20.3]"
                executable.write_bytes(b"changed entrypoint")
                self.assertNotEqual(initial, REPOCTL.qualification_identity())

    def test_identity_binds_actual_trusted_controller(self):
        with tempfile.TemporaryDirectory() as directory:
            controller = Path(directory) / "trusted.py"
            controller.write_bytes((ROOT / "scripts/repoctl.py").read_bytes())
            with mock.patch.object(REPOCTL.shutil, "which", return_value=None):
                candidate = REPOCTL.qualification_identity()
                with mock.patch.dict(os.environ, {"REPOCTL_TRUSTED_CONTROLLER": str(controller)}):
                    self.assertEqual(candidate, REPOCTL.qualification_identity())
                    controller.write_bytes(b"# different gate implementation\n")
                    self.assertNotEqual(candidate, REPOCTL.qualification_identity())

    def test_all_declared_gate_tools_and_provider_dependencies_are_bound(self):
        commands, _probes = REPOCTL._qualification_toolchain()
        contract = json.loads((ROOT / "config/toolchain/capabilities.json").read_text())
        declared = {name for names in contract["gate_requirements"].values() for name in names}
        self.assertTrue(declared <= commands.keys())
        for command in ("git", "cc", "docker", "sysctl", "ansible-galaxy", "diff", "tar", "ruby"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                executable = Path(directory) / command
                executable.write_bytes(b"original tool")
                with (
                    mock.patch.object(
                        REPOCTL.shutil, "which", side_effect=lambda name: str(executable) if name == command else None
                    ),
                    mock.patch.object(
                        REPOCTL, "run", return_value=mock.Mock(returncode=0, stdout='{"ServerVersion": "1"}', stderr="")
                    ),
                    mock.patch.object(REPOCTL, "output", return_value="version 1"),
                ):
                    original = REPOCTL.qualification_identity()
                    executable.write_bytes(b"changed tool")
                    self.assertNotEqual(original, REPOCTL.qualification_identity())

    def test_new_contract_tool_and_transitive_provider_are_discovered(self):
        contract = json.loads((ROOT / "config/toolchain/capabilities.json").read_text())
        contract["gate_requirements"]["test"].append("new-tool")
        contract["capabilities"] += [
            {"name": "new-tool", "provider": "new-provider", "probe": ["launcher", "new-tool", "--version"]},
            {"name": "new-provider", "command": "launcher", "version_args": ["version"], "requires": ["new-helper"]},
            {"name": "new-helper", "command": "helper", "version_args": ["--version"]},
        ]
        with mock.patch.object(REPOCTL.json, "loads", return_value=contract):
            commands, probes = REPOCTL._qualification_toolchain()
        self.assertEqual(["version"], commands["launcher"])
        self.assertIn("helper", commands)
        self.assertIn((("launcher", "new-tool", "--version"), False), probes)

    def test_runtime_identity_binds_daemon_configuration_not_container_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config/toolchain/capabilities.json"
            config.parent.mkdir(parents=True)
            config.write_bytes((ROOT / "config/toolchain/capabilities.json").read_bytes())
            with mock.patch.object(REPOCTL, "ROOT", root):
                _commands, probes = REPOCTL._qualification_toolchain()
                self.assertNotIn((("docker", "info"), True), probes)
                service = root / "services/product"
                service.mkdir(parents=True)
                (service / "integration_test.go").write_text("// testcontainers\n")
                _commands, probes = REPOCTL._qualification_toolchain()
                self.assertIn((("docker", "info"), True), probes)
                self.assertIn((("sysctl", "-n", "net.ipv4.ip_forward"), True), probes)
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "docker"
            executable.write_bytes(b"docker client")
            state = {"ServerVersion": "1", "ID": "daemon-a", "Containers": 1}

            def run(command, **kwargs):
                return mock.Mock(returncode=0, stdout=json.dumps(state) if "info" in command else "client 1", stderr="")

            with (
                mock.patch.object(
                    REPOCTL,
                    "_qualification_toolchain",
                    return_value=({"docker": ["--version"]}, {(("docker", "info"), True)}),
                ),
                mock.patch.object(
                    REPOCTL.shutil, "which", side_effect=lambda name: str(executable) if name == "docker" else None
                ),
                mock.patch.object(REPOCTL, "run", side_effect=run),
            ):
                original = REPOCTL.qualification_identity()
                state["Containers"] = 2
                self.assertEqual(original, REPOCTL.qualification_identity())
                state["ServerVersion"] = "2"
                self.assertNotEqual(original, REPOCTL.qualification_identity())
                with mock.patch.object(REPOCTL, "run", return_value=mock.Mock(returncode=1, stdout="", stderr="")):
                    with self.assertRaisesRegex(RuntimeError, "runtime identity probe failed"):
                        REPOCTL.qualification_identity()

    def test_requires_each_gate_once_and_does_not_skip_required_checks(self):
        gates = self.evidence()["gates"]
        for rows in (
            [],
            gates[:-1],
            gates + [gates[0]],
            gates + [{"gate": "unexpected", "status": "PASS"}],
            [{**row, "status": "SKIP"} for row in gates],
            [None],
        ):
            with self.subTest(rows=rows):
                evidence = self.evidence()
                evidence["gates"] = rows
                self.assertIsNone(self.validate(evidence))

    def test_dispatcher_version_changes_invalidate_identity(self):
        for command in ("ruff", "pnpm"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                shim = Path(directory) / command
                shim.write_bytes(b"unchanged dispatcher")
                with (
                    mock.patch.object(
                        REPOCTL.shutil, "which", side_effect=lambda name: str(shim) if name == command else None
                    ),
                    mock.patch.object(
                        REPOCTL, "run", return_value=mock.Mock(returncode=0, stdout="1.0.0", stderr="")
                    ) as probe,
                ):
                    before = REPOCTL.qualification_identity()
                    probe.return_value.stdout = "2.0.0"
                    self.assertNotEqual(before, REPOCTL.qualification_identity())

    def test_prepush_requalifies_rejected_evidence(self):
        with (
            mock.patch.object(REPOCTL, "git", return_value="h"),
            mock.patch.object(REPOCTL, "_valid_exact_evidence", return_value=None) as validate,
            mock.patch.object(REPOCTL, "verify_change", return_value=1) as verify,
        ):
            self.assertEqual(1, REPOCTL.prepush())
            validate.assert_called_once_with("origin/main", "h")
            verify.assert_called_once_with("origin/main", "h")

    def test_prepush_reuses_only_canonical_validation(self):
        path = ROOT / ".context/evidence/h.json"
        with (
            mock.patch.object(REPOCTL, "git", return_value="h"),
            mock.patch.object(REPOCTL, "_valid_exact_evidence", return_value=path) as validate,
            mock.patch.object(REPOCTL, "verify_change") as verify,
        ):
            self.assertEqual(0, REPOCTL.prepush())
            validate.assert_called_once_with("origin/main", "h")
            verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
