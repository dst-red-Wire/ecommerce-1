import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("capability_bootstrap", ROOT / "scripts/capability_bootstrap.py")
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def contract(items):
    normalized = []
    for item in items:
        item = dict(item)
        item.setdefault("classification", "conditional")
        normalized.append(item)
    commands = [item["command"] for item in normalized if item.get("command")]
    return {
        "supported": {"os": ["linux"], "arch": ["amd64"]},
        "capabilities": normalized,
        "gate_requirements": {"test": commands or ["python3"]},
        "seed_prerequisites": ([{"command": "python3", "justification": "test seed"}] if not commands else []),
    }


class CapabilityGraphTest(unittest.TestCase):
    def test_graph_is_acyclic_and_topologically_sorted(self):
        graph = MOD.Graph([{"name": "kind", "requires": ["docker"]}, {"name": "docker", "requires": []}])
        self.assertLess(graph.order().index("docker"), graph.order().index("kind"))

    def test_cycle_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "cycle"):
            MOD.Graph([{"name": "a", "requires": ["b"]}, {"name": "b", "requires": ["a"]}]).order()

    def test_missing_dependency_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing dependencies"):
            MOD.Graph([{"name": "a", "requires": ["missing"]}])


class CapabilityAuditTest(unittest.TestCase):
    def runner(self, outcomes):
        def run(argv):
            rc, output = outcomes.get(argv[0], (0, "1.0"))
            return subprocess.CompletedProcess(argv, rc, output, "")
        return run

    def auditor(self, items, outcomes, present=None):
        present = present if present is not None else {item.get("command") for item in items}
        return MOD.Auditor(contract(items), runner=self.runner(outcomes), which=lambda cmd: f"/bin/{cmd}" if cmd in present else None)

    def test_failure_and_skip_propagate_only_to_real_dependants(self):
        items = [
            {"name": "docker", "requires": [], "probe": ["docker", "info"], "external_failure": True},
            {"name": "kind", "requires": ["docker"], "command": "kind"},
            {"name": "oasdiff", "requires": [], "command": "oasdiff"},
            {"name": "ansible", "requires": [], "command": "ansible-playbook"},
            {"name": "terraform", "requires": [], "command": "terraform"},
            {"name": "kubectl", "requires": [], "command": "kubectl"},
        ]
        results = self.auditor(items, {"docker": (1, "daemon unavailable")}).run(bootstrap=False, os_name="linux", arch="amd64")
        self.assertEqual("BLOCKED", results["docker"].state)
        self.assertEqual("SKIP", results["kind"].state)
        for independent in ("oasdiff", "ansible", "terraform", "kubectl"):
            self.assertEqual("PASS", results[independent].state)

    def test_absent_tool_and_wrong_version_fail(self):
        items = [{"name": "missing", "requires": [], "command": "missing"}]
        result = self.auditor(items, {}, present=set()).run(bootstrap=False, os_name="linux", arch="amd64")
        self.assertEqual("FAIL", result["missing"].state)
        item = {"name": "go", "requires": [], "command": "fakego", "version_key": "GO_VERSION"}
        result = self.auditor([item], {"fakego": (0, "go0.1")}).run(bootstrap=False, os_name="linux", arch="amd64")
        self.assertEqual("FAIL", result["go"].state)

    def test_unknown_os_and_arch_are_unsupported(self):
        auditor = self.auditor([{"name": "x", "requires": [], "command": "x"}], {})
        self.assertEqual("UNSUPPORTED", auditor.run(bootstrap=False, os_name="plan9", arch="amd64")["x"].state)
        self.assertEqual("UNSUPPORTED", auditor.run(bootstrap=False, os_name="linux", arch="mips")["x"].state)

    def test_idempotence_and_resume_after_blockage(self):
        item = {"name": "tool", "requires": [], "command": "tool", "provision": {"type": "ansible", "tags": "tool"}}
        calls = []
        def ready(argv):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "1.0", "")
        auditor = MOD.Auditor(contract([item]), runner=ready, which=lambda _: "/bin/tool")
        self.assertEqual("PASS", auditor.run(bootstrap=True, os_name="linux", arch="amd64")["tool"].state)
        self.assertEqual(1, len(calls), "compliant capability must not be reinstalled")
        outcomes = iter([(1, "wrong version"), (1, "proxy blocked"), (0, "1.0")])
        auditor.runner = lambda argv: subprocess.CompletedProcess(argv, *(next(outcomes)), stderr="")
        self.assertEqual("BLOCKED", auditor.run(bootstrap=True, os_name="linux", arch="amd64")["tool"].state)
        self.assertEqual("PASS", auditor.run(bootstrap=True, os_name="linux", arch="amd64")["tool"].state)

    def test_env_check_has_no_provision_side_effect(self):
        item = {"name": "tool", "requires": [], "command": "tool", "provision": {"type": "ansible", "tags": "tool"}}
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        auditor = MOD.Auditor(contract([item]), runner=runner, which=lambda _: None)
        auditor.run(bootstrap=False, os_name="linux", arch="amd64")
        runner.assert_not_called()

    def test_pip_is_provisioned_from_python_ensurepip_and_rechecked(self):
        items = [
            {"name": "python", "requires": [], "command": "python3"},
            {"name": "pip", "requires": ["python"], "probe": ["python3", "-m", "pip", "--version"],
             "provision": {"type": "ensurepip"}, "provision_authority": "PIP_PROVISION_AUTHORITY"},
            {"name": "ansible", "requires": ["pip"], "command": "ansible"},
            {"name": "independent", "requires": [], "command": "independent"},
        ]
        calls = []
        pip_probes = iter([subprocess.CompletedProcess([], 1, "", "No module named pip"),
                           subprocess.CompletedProcess([], 0, "pip 26.1", "")])
        def runner(argv):
            calls.append(argv)
            if argv[1:4] == ["-m", "pip", "--version"]:
                return next(pip_probes)
            return subprocess.CompletedProcess(argv, 0, "ready", "")
        auditor = MOD.Auditor(contract(items), runner=runner, which=lambda command: f"/bin/{command}")
        results = auditor.run(bootstrap=True, os_name="linux", arch="amd64")
        self.assertEqual("PASS", results["pip"].state)
        self.assertIn([sys.executable, "-m", "ensurepip", "--user"], calls)
        self.assertEqual("PASS", results["ansible"].state)

    def test_failed_pip_provision_skips_only_dependants_without_false_pass(self):
        items = [
            {"name": "python", "requires": [], "command": "python3"},
            {"name": "pip", "requires": ["python"], "probe": ["python3", "-m", "pip", "--version"],
             "provision": {"type": "ensurepip"}, "provision_authority": "PIP_PROVISION_AUTHORITY"},
            {"name": "ansible", "requires": ["pip"], "command": "ansible"},
            {"name": "cosign", "requires": [], "command": "cosign"},
        ]
        def runner(argv):
            if "pip" in argv or "ensurepip" in argv:
                return subprocess.CompletedProcess(argv, 1, "", "unavailable")
            return subprocess.CompletedProcess(argv, 0, "ready", "")
        results = MOD.Auditor(contract(items), runner=runner, which=lambda command: f"/bin/{command}").run(
            bootstrap=True, os_name="linux", arch="amd64"
        )
        self.assertEqual("BLOCKED", results["pip"].state)
        self.assertEqual("SKIP", results["ansible"].state)
        self.assertEqual("PASS", results["cosign"].state)

    def test_managed_user_bin_resolves_fresh_ansible_entry_points(self):
        items = [
            {"name": "ansible-core", "requires": [], "command": "ansible"},
            {"name": "ansible-playbook", "requires": ["ansible-core"], "command": "ansible-playbook"},
            {"name": "next", "requires": [], "provision_requires": ["ansible-playbook"], "command": "next",
             "provision": {"type": "ansible", "tags": "next"}},
        ]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(MOD, "MANAGED_BIN_DIRS", (Path(tmp),)):
            for command in ("ansible", "ansible-playbook"):
                executable = Path(tmp, command); executable.write_text("#!/bin/true\n"); executable.chmod(0o755)
            calls = []
            def runner(argv):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, "ready", "")
            auditor = MOD.Auditor(contract(items), runner=runner, which=lambda _: None)
            results = auditor.run(bootstrap=True, os_name="linux", arch="amd64")
        self.assertEqual("PASS", results["ansible-core"].state)
        self.assertEqual("PASS", results["ansible-playbook"].state)
        self.assertEqual(str(Path(tmp, "ansible-playbook")), calls[-2][0])

    def test_checksum_invalid_is_rejected_by_existing_ansible_mechanism(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text()
        self.assertIn('checksum: "sha256:{{ oasdiff_sha256 }}"', tasks)
        self.assertNotIn("ignore_errors: true", tasks)

    def test_single_version_authority_and_no_global_docker_dependency(self):
        values = MOD.load_versions()
        self.assertIn("ANSIBLE_CORE_VERSION", values)
        canonical = MOD.load_contract()
        names = {item["name"]: item for item in canonical["capabilities"]}
        for name in ("oasdiff", "ansible-playbook", "terraform", "kubectl", "helm", "kustomize"):
            self.assertNotIn("docker", names[name].get("requires", []))
        self.assertEqual(["docker"], names["kind"]["requires"])


class CapabilityClosureTest(unittest.TestCase):
    def test_canonical_gate_closure_is_complete(self):
        canonical = MOD.load_contract()
        MOD.validate_contract(canonical)
        names = {item["name"] for item in canonical["capabilities"]}
        for name in ("cosign", "gitleaks", "oasdiff", "oapi-codegen", "kubectl", "helm", "terraform", "kustomize"):
            self.assertIn(name, names)

    def test_unknown_gate_command_is_rejected(self):
        canonical = MOD.load_contract()
        canonical["gate_requirements"]["security"].append("new-tool")
        with self.assertRaisesRegex(ValueError, "undeclared commands: new-tool"):
            MOD.validate_contract(canonical)

    def test_removed_required_capability_is_rejected(self):
        canonical = MOD.load_contract()
        canonical["capabilities"] = [item for item in canonical["capabilities"] if item["name"] != "gitleaks"]
        with self.assertRaisesRegex(ValueError, "undeclared commands: gitleaks"):
            MOD.validate_contract(canonical)

    def test_delivery_without_cosign_is_rejected(self):
        canonical = MOD.load_contract()
        canonical["gate_requirements"]["delivery"].remove("cosign")
        with self.assertRaisesRegex(ValueError, "cosign"):
            MOD.validate_contract(canonical)

    def test_require_command_wrapper_is_audited(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp, "wrapper.py")
            source.write_text('require_command("unknown-tool")\n')
            canonical = MOD.load_contract()
            canonical["gate_sources"] = ["wrapper.py"]
            with mock.patch.object(MOD, "ROOT", Path(tmp)):
                with self.assertRaisesRegex(ValueError, "unknown-tool"):
                    MOD.validate_contract(canonical)

    def test_seed_prerequisite_requires_justification(self):
        canonical = MOD.load_contract()
        canonical["seed_prerequisites"].append({"command": "sed"})
        with self.assertRaisesRegex(ValueError, "contractual justification"):
            MOD.validate_contract(canonical)

    def test_missing_version_authority_is_rejected(self):
        canonical = MOD.load_contract()
        next(item for item in canonical["capabilities"] if item["name"] == "gitleaks")["version_key"] = "MISSING_VERSION"
        with self.assertRaisesRegex(ValueError, "missing version authority"):
            MOD.validate_contract(canonical)

    def test_invalid_checksum_authority_is_rejected(self):
        canonical = MOD.load_contract()
        versions = MOD.load_versions()
        versions["GITLEAKS_SHA256_LINUX_AMD64"] = "not-a-checksum"
        with self.assertRaisesRegex(ValueError, "invalid checksum authority"):
            MOD.validate_contract(canonical, versions)

    def test_new_gate_tools_have_checksums_and_linux_amd64_support(self):
        canonical = MOD.load_contract()
        names = {item["name"]: item for item in canonical["capabilities"]}
        versions = MOD.load_versions()
        for name in ("cosign", "gitleaks", "kubectl", "helm", "terraform", "kustomize"):
            self.assertEqual(["linux/amd64"], names[name]["platforms"])
            self.assertIn(f"{name.upper()}_SHA256_LINUX_AMD64", versions)

    def test_docker_blockage_does_not_skip_independent_gate_tools(self):
        names = ("cosign", "gitleaks", "oasdiff", "oapi-codegen", "kubectl", "helm", "terraform", "kustomize")
        items = [{"name": "docker", "requires": [], "probe": ["docker", "info"], "external_failure": True}]
        items += [{"name": name, "requires": [], "command": name} for name in names]
        items += [{"name": "kind", "requires": ["docker"], "command": "kind"}]
        results = CapabilityAuditTest().auditor(items, {"docker": (1, "daemon unavailable")}).run(
            bootstrap=False, os_name="linux", arch="amd64"
        )
        self.assertEqual("SKIP", results["kind"].state)
        for name in names:
            self.assertEqual("PASS", results[name].state)

    def test_terraform_runtime_accepts_each_pinned_alternative(self):
        item = dict(next(item for item in MOD.load_contract()["capabilities"] if item["name"] == "terraform"))
        item.pop("provision_requires")
        item.pop("provision")
        versions = MOD.load_versions()
        for present, output in (({"terraform"}, versions["TERRAFORM_VERSION"]), ({"tofu"}, versions["OPENTOFU_VERSION"])):
            result = CapabilityAuditTest().auditor([item], {"/bin/" + next(iter(present)): (0, output)}, present=present).run(
                bootstrap=False, os_name="linux", arch="amd64"
            )["terraform"]
            self.assertEqual("PASS", result.state)

    def test_valid_tofu_wins_when_terraform_is_invalid(self):
        item = dict(next(item for item in MOD.load_contract()["capabilities"] if item["name"] == "terraform"))
        item.pop("provision_requires")
        item.pop("provision")
        versions = MOD.load_versions()
        results = CapabilityAuditTest().auditor(
            [item], {"/bin/terraform": (0, "Terraform v0.1"), "/bin/tofu": (0, "OpenTofu " + versions["OPENTOFU_VERSION"])},
            present={"terraform", "tofu"},
        ).run(bootstrap=False, os_name="linux", arch="amd64")
        self.assertEqual("PASS", results["terraform"].state)


if __name__ == "__main__":
    unittest.main()
