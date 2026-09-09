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
    return {"supported": {"os": ["linux"], "arch": ["amd64"]}, "capabilities": items}


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


if __name__ == "__main__":
    unittest.main()
