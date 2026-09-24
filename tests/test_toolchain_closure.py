from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_toolchain_closure", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class ToolchainClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads((ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8"))
        self.graph = json.loads((ROOT / "config/toolchain/capabilities.json").read_text(encoding="utf-8"))

    def violations(self, lock=None, graph=None, *, doctor_expected=None):
        return MOD.toolchain_closure_violations(
            lock or copy.deepcopy(self.lock),
            graph or copy.deepcopy(self.graph),
            root=ROOT,
            check_projections=False,
            doctor_expected=doctor_expected,
        )

    def assertViolation(self, violations, text):
        self.assertTrue(any(text in violation for violation in violations), violations)

    def test_canonical_toolchain_is_closed(self):
        self.assertEqual([], self.violations())

    def test_active_tool_without_consumer_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["active"]["packer"].pop("consumers")
        self.assertViolation(self.violations(lock), "active tool packer has no executable consumer")

    def test_active_tool_without_capability_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["active"]["packer"].pop("capability")
        self.assertViolation(self.violations(lock), "active tool packer has no capability")

    def test_active_managed_tool_without_installer_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["active"]["packer"].pop("provision")
        self.assertViolation(self.violations(lock), "active managed tool packer has no installer")

    def test_doctor_cannot_require_unregistered_tool(self):
        expected = MOD.centrally_derived_doctor_set(self.lock, self.graph) | {"syft"}
        self.assertViolation(self.violations(doctor_expected=expected), "doctor requires undeclared tool: syft")

    def test_doctor_is_derived_from_active_required_capabilities(self):
        expected = MOD.centrally_derived_doctor_set(self.lock, self.graph)
        self.assertIn("gitleaks", expected)
        self.assertIn("git", expected)
        self.assertNotIn("molecule", expected)
        self.assertNotIn("kube-bench", expected)
        self.assertNotIn("syft", expected)
        self.assertEqual([], self.violations(doctor_expected=expected))

    def test_deferred_tool_cannot_be_installed(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["deferred"]["ansible-builder"]["provision"] = {"type": "pipx"}
        self.assertViolation(self.violations(lock), "deferred tool ansible-builder is provisioned")

    def test_deferred_tool_cannot_be_required_by_gate(self):
        graph = copy.deepcopy(self.graph)
        graph["gate_requirements"]["security"].append("ansible-builder")
        self.assertViolation(self.violations(graph=graph), "gate executes undeclared or inactive tool: ansible-builder")

    def test_security_policy_status_must_match_tool_lifecycle(self):
        lock = copy.deepcopy(self.lock)
        kube_bench = lock["tool_lifecycle"]["active"].pop("kube-bench")
        lock["tool_lifecycle"]["rejected"]["kube-bench"] = kube_bench
        self.assertViolation(self.violations(lock), "security policy lifecycle drift: kube-bench")

    def test_rejected_tool_cannot_be_installed(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["rejected"]["hyperfine"]["install"] = {"type": "binary"}
        self.assertViolation(self.violations(lock), "rejected tool hyperfine is provisioned")

    def test_rejected_tool_cannot_be_executed(self):
        graph = copy.deepcopy(self.graph)
        graph["gate_requirements"]["test"].append("hyperfine")
        self.assertViolation(self.violations(graph=graph), "gate executes undeclared or inactive tool: hyperfine")

    def test_platform_provided_tool_requires_probe(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["platform-provided"]["git"].pop("probe")
        self.assertViolation(self.violations(lock), "platform-provided tool git requires deterministic probe")

    def test_platform_provided_static_probe_requires_real_marker(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["platform-provided"]["syft"]["probe"][1] = "missing-syft-marker"
        self.assertViolation(
            self.violations(lock),
            "platform-provided tool syft static probe does not prove the capability",
        )

    def test_required_scenario_cannot_be_missing(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["active"]["cosign"]["proofs"] = []
        self.assertViolation(self.violations(lock), "active tool cosign has no scenario or proof")

    def test_external_system_scenario_requires_existing_proof_path(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["active"]["skopeo"]["proofs"] = ["does/not/exist"]
        self.assertViolation(self.violations(lock), "active tool skopeo has no scenario or proof")

    def test_orphan_version_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["versions"]["ORPHAN_VERSION"] = "1.2.3"
        self.assertViolation(self.violations(lock), "orphan toolchain version: ORPHAN_VERSION")

    def test_version_owner_must_reference_matching_lifecycle_tool(self):
        lock = copy.deepcopy(self.lock)
        lock["version_owners"]["PACKER_VERSION"]["owner"] = "invented-owner"
        self.assertViolation(self.violations(lock), "version owner does not match lifecycle: PACKER_VERSION")

    def test_orphan_checksum_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["versions"]["ORPHAN_SHA256_LINUX_AMD64"] = "a" * 64
        self.assertViolation(self.violations(lock), "orphan toolchain checksum: ORPHAN_SHA256_LINUX_AMD64")

    def test_active_tool_cannot_borrow_another_checksum_authority(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["active"]["packer"]["checksum_ref"] = "TRIVY_SHA256_LINUX_AMD64"
        self.assertViolation(
            self.violations(lock),
            "active tool packer checksum authority mismatch: TRIVY_SHA256_LINUX_AMD64",
        )

    def test_downloaded_tool_without_checksum_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["tools"]["packer"].pop("sha256_ref")
        self.assertViolation(self.violations(lock), "downloaded tool without checksum: packer")

    def test_gate_cannot_execute_undeclared_tool(self):
        graph = copy.deepcopy(self.graph)
        graph["gate_requirements"]["security"].append("mystery-scanner")
        self.assertViolation(self.violations(graph=graph), "gate executes undeclared or inactive tool: mystery-scanner")

    def test_installer_cannot_provision_unknown_tool(self):
        graph = copy.deepcopy(self.graph)
        graph["capabilities"].append(
            {
                "name": "mystery-installer",
                "requires": [],
                "command": "mystery-installer",
                "version_args": ["--version"],
                "version_key": "PACKER_VERSION",
                "provision": {"type": "ansible", "tags": "mystery"},
                "classification": "managed",
                "requirement": "required-static",
            }
        )
        self.assertViolation(self.violations(graph=graph), "capability has no central lifecycle status: mystery-installer")

    def test_projection_drift_is_rejected(self):
        graph = copy.deepcopy(self.graph)
        graph["command_capabilities"]["new-command"] = "go"
        self.assertViolation(self.violations(graph=graph), "capability graph command projection drift")

    def test_unknown_capability_dependency_is_rejected(self):
        graph = copy.deepcopy(self.graph)
        graph["capabilities"][0]["requires"] = ["missing-capability"]
        self.assertViolation(
            self.violations(graph=graph),
            "capability python requires unknown capability: missing-capability",
        )

    def test_capability_dependency_cycle_is_rejected(self):
        graph = copy.deepcopy(self.graph)
        by_name = {item["name"]: item for item in graph["capabilities"]}
        by_name["python"]["requires"] = ["ruby"]
        by_name["ruby"]["requires"] = ["python"]
        self.assertViolation(self.violations(graph=graph), "capability dependency cycle:")

    def test_each_ansible_provision_tag_must_select_an_installer_task(self):
        lock = copy.deepcopy(self.lock)
        graph = copy.deepcopy(self.graph)
        lock["tool_lifecycle"]["active"]["trivy"]["provision"]["tags"] = "trivyy"
        by_name = {item["name"]: item for item in graph["capabilities"]}
        by_name["trivy"]["provision"]["tags"] = "trivyy"
        self.assertViolation(
            self.violations(lock, graph),
            "active tool trivy provision tag selects no installer task: trivyy",
        )

    def test_molecule_active_without_scenario_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["deferred"].pop("molecule")
        lock["tool_lifecycle"]["active"]["molecule"] = {
            "capability": "molecule",
            "version_ref": "MOLECULE_VERSION",
            "provision": {"type": "pipx", "package": "molecule", "tags": "molecule"},
            "scenario_policy": "required",
            "proofs": [],
        }
        self.assertViolation(self.violations(lock), "active tool molecule has no scenario or proof")

    def test_ansible_builder_deferred_but_installed_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["tool_lifecycle"]["deferred"]["ansible-builder"]["install"] = "pipx"
        self.assertViolation(self.violations(lock), "deferred tool ansible-builder is provisioned")

    def test_removing_gosec_security_consumer_is_rejected(self):
        graph = copy.deepcopy(self.graph)
        graph["gate_requirements"]["security"].remove("gosec")
        self.assertViolation(self.violations(graph=graph), "active tool gosec has no executable consumer")


if __name__ == "__main__":
    unittest.main()
