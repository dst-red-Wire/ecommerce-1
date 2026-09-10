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

    def test_ubuntu_pip_is_provisioned_from_apt_and_rechecked(self):
        items = [
            {"name": "python", "requires": [], "command": "python3"},
            {"name": "pip", "requires": ["python"], "probe": ["python3", "-m", "pip", "--version"],
             "provision": {"type": "debian-package", "package": "python3-pip", "distributions": ["ubuntu", "debian"]},
             "provision_authority": "PIP_PROVISION_AUTHORITY"},
            {"name": "ansible", "requires": ["pip"], "command": "ansible"},
            {"name": "independent", "requires": [], "command": "independent"},
        ]
        calls = []
        pip_probes = iter([subprocess.CompletedProcess([], 1, "", "No module named pip"),
                           subprocess.CompletedProcess([], 0, "pip 26.1", ""),
                           subprocess.CompletedProcess([], 0, "pip 26.1", "")])
        def runner(argv):
            calls.append(argv)
            if argv[1:4] == ["-m", "pip", "--version"]:
                return next(pip_probes)
            return subprocess.CompletedProcess(argv, 0, "ready", "")
        auditor = MOD.Auditor(contract(items), runner=runner, which=lambda command: f"/bin/{command}",
                              distribution=lambda: "ubuntu")
        results = auditor.run(bootstrap=True, os_name="linux", arch="amd64")
        self.assertEqual("PASS", results["pip"].state)
        self.assertIn(["/bin/apt-get", "install", "-y", "python3-pip"], calls)
        self.assertFalse(any("ensurepip" in call for call in calls))
        self.assertEqual("PASS", results["ansible"].state)
        second_results = auditor.run(bootstrap=True, os_name="linux", arch="amd64")
        self.assertEqual("PASS", second_results["pip"].state)
        self.assertEqual(1, calls.count(["/bin/apt-get", "install", "-y", "python3-pip"]))

    def test_ubuntu_ensurepip_only_mutation_is_rejected(self):
        canonical = MOD.load_contract()
        pip = next(item for item in canonical["capabilities"] if item["name"] == "pip")
        pip["provision"] = {"type": "ensurepip"}
        canonical["provision_owners"]["pip"] = "ensurepip"
        with self.assertRaisesRegex(ValueError, "requires Ubuntu/Debian package provisioning"):
            MOD.validate_contract(canonical)

    def test_failed_pip_provision_skips_only_dependants_without_false_pass(self):
        items = [
            {"name": "python", "requires": [], "command": "python3"},
            {"name": "pip", "requires": ["python"], "probe": ["python3", "-m", "pip", "--version"],
             "provision": {"type": "debian-package", "package": "python3-pip", "distributions": ["ubuntu", "debian"]},
             "provision_authority": "PIP_PROVISION_AUTHORITY"},
            {"name": "ansible", "requires": ["pip"], "command": "ansible"},
            {"name": "cosign", "requires": [], "command": "cosign"},
        ]
        def runner(argv):
            if "pip" in argv or argv[0].endswith("apt-get"):
                return subprocess.CompletedProcess(argv, 1, "", "unavailable")
            return subprocess.CompletedProcess(argv, 0, "ready", "")
        results = MOD.Auditor(contract(items), runner=runner, which=lambda command: f"/bin/{command}",
                              distribution=lambda: "ubuntu").run(
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

    def test_ansible_entrypoints_are_bound_to_validated_core_provider(self):
        versions = MOD.load_versions()
        items = [
            {"name": "ansible-core", "requires": [], "command": "ansible", "version_key": "ANSIBLE_CORE_VERSION"},
            {"name": "ansible-playbook", "requires": ["ansible-core"], "provider": "ansible-core",
             "command": "ansible-playbook"},
            {"name": "next", "requires": [], "provision_requires": ["ansible-playbook"], "command": "next",
             "provision": {"type": "ansible", "tags": "next"}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            system_bin = Path(tmp, "usr", "bin")
            managed_bin = Path(tmp, "home", "test", ".local", "bin")
            system_bin.mkdir(parents=True)
            managed_bin.mkdir(parents=True)
            for directory in (system_bin, managed_bin):
                for command in ("ansible", "ansible-playbook"):
                    executable = directory / command
                    executable.write_text("#!/bin/true\n")
                    executable.chmod(0o755)

            calls = []
            installed = set()

            def runner(argv):
                calls.append(argv)
                if argv[0] == str(system_bin / "ansible"):
                    return subprocess.CompletedProcess(argv, 0, "ansible [core 1.0.0]", "")
                if argv[0] == str(managed_bin / "ansible"):
                    return subprocess.CompletedProcess(argv, 0, f"ansible [core {versions['ANSIBLE_CORE_VERSION']}]", "")
                if "platform/ansible/developer.yml" in argv:
                    installed.add("next")
                return subprocess.CompletedProcess(argv, 0, "ready", "")

            def which(command):
                if command in ("ansible", "ansible-playbook"):
                    return str(system_bin / command)
                return str(Path(tmp, command)) if command in installed else None

            with mock.patch.object(MOD, "MANAGED_BIN_DIRS", (managed_bin,)):
                auditor = MOD.Auditor(contract(items), runner=runner, which=which)
                results = auditor.run(bootstrap=True, os_name="linux", arch="amd64")

                self.assertEqual("PASS", results["ansible-core"].state)
                self.assertEqual("PASS", results["ansible-playbook"].state)
                self.assertEqual(str(managed_bin / "ansible"), auditor.resolved_executables["ansible-core"])
                self.assertEqual(str(managed_bin / "ansible-playbook"), auditor.resolved_executables["ansible-playbook"])
                provision_call = next(call for call in calls if "platform/ansible/developer.yml" in call)
                self.assertEqual(str(managed_bin / "ansible-playbook"), provision_call[0])

                mutated = MOD.Auditor(contract([{**item, **({"provider": None} if item["name"] == "ansible-playbook" else {})}
                                                for item in items]), runner=runner, which=which)
                mutated.run(bootstrap=False, os_name="linux", arch="amd64")
                self.assertNotEqual(
                    Path(mutated.resolved_executables["ansible-core"]).parent,
                    Path(mutated.resolved_executables["ansible-playbook"]).parent,
                    "independent PATH resolution must expose the stale-provider mutation",
                )

    def test_ansible_entrypoint_missing_from_provider_does_not_fall_back_to_path(self):
        items = [
            {"name": "ansible-core", "requires": [], "command": "ansible"},
            {"name": "ansible-playbook", "requires": ["ansible-core"], "provider": "ansible-core",
             "command": "ansible-playbook"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            managed_bin = Path(tmp, "managed")
            system_bin = Path(tmp, "system")
            managed_bin.mkdir(); system_bin.mkdir()
            for executable in (managed_bin / "ansible", system_bin / "ansible-playbook"):
                executable.write_text("#!/bin/true\n"); executable.chmod(0o755)
            which = lambda command: str(managed_bin / "ansible") if command == "ansible" else str(system_bin / command)
            auditor = MOD.Auditor(contract(items), runner=self.runner({}), which=which)
            results = auditor.run(bootstrap=False, os_name="linux", arch="amd64")
        self.assertEqual("PASS", results["ansible-core"].state)
        self.assertEqual("FAIL", results["ansible-playbook"].state)
        self.assertIn("entry point absent from provider ansible-core", results["ansible-playbook"].detail)

    def test_pep668_ansible_uses_isolated_provider_and_is_idempotent(self):
        version = MOD.load_versions()["ANSIBLE_CORE_VERSION"]
        items = [
            {"name": "ansible-core", "requires": [], "command": "ansible", "version_key": "ANSIBLE_CORE_VERSION",
             "isolated": True,
             "provision": {"type": "python-venv", "package": "ansible-core",
                           "entry_points": ["ansible", "ansible-playbook", "ansible-galaxy"]}},
            {"name": "ansible-playbook", "requires": ["ansible-core"], "provider": "ansible-core",
             "command": "ansible-playbook"},
            {"name": "ansible-galaxy", "requires": ["ansible-core"], "provider": "ansible-core",
             "command": "ansible-galaxy"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            system_bin = root / "usr" / "bin"
            managed_bin = root / "home" / ".local" / "bin"
            venv = root / "home" / ".local" / "share" / "ecommerce-1" / "venvs" / "ansible-core"
            system_bin.mkdir(parents=True)
            for entry_point in ("ansible", "ansible-playbook", "ansible-galaxy"):
                executable = system_bin / entry_point
                executable.write_text("#!/bin/true\n")
                executable.chmod(0o755)
            calls = []

            def runner(argv):
                calls.append(argv)
                if argv[1:3] == ["-m", "venv"]:
                    (venv / "bin").mkdir(parents=True)
                    (venv / "bin" / "python").write_text("#!/bin/true\n")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if argv[:4] == [str(venv / "bin" / "python"), "-m", "pip", "install"]:
                    for entry_point in ("ansible", "ansible-playbook", "ansible-galaxy"):
                        executable = venv / "bin" / entry_point
                        executable.write_text("#!/bin/true\n")
                        executable.chmod(0o755)
                    return subprocess.CompletedProcess(argv, 0, "installed", "")
                if str(managed_bin) in argv[0]:
                    return subprocess.CompletedProcess(argv, 0, f"ansible [core {version}]", "")
                return subprocess.CompletedProcess(argv, 0, "ansible [core 1.0.0]", "")

            with mock.patch.object(MOD, "MANAGED_BIN_DIRS", (managed_bin,)), \
                    mock.patch.object(MOD, "ANSIBLE_CORE_VENV", venv):
                auditor = MOD.Auditor(contract(items), runner=runner,
                                      which=lambda command: str(system_bin / command))
                first = auditor.run(bootstrap=True, os_name="linux", arch="amd64")
                second = auditor.run(bootstrap=True, os_name="linux", arch="amd64")

            self.assertTrue(all(result.state == "PASS" for result in first.values()))
            self.assertTrue(all(result.state == "PASS" for result in second.values()))
            self.assertEqual(1, sum(call[1:3] == ["-m", "venv"] for call in calls))
            self.assertEqual(1, sum(call[:4] == [str(venv / "bin" / "python"), "-m", "pip", "install"]
                                    for call in calls))
            self.assertFalse(any("--user" in call for call in calls),
                             "PEP 668 bootstrap must never install into distro-managed Python")
            provider_dir = Path(auditor.resolved_executables["ansible-core"]).parent
            self.assertEqual(provider_dir, Path(auditor.resolved_executables["ansible-playbook"]).parent)
            self.assertEqual(provider_dir, Path(auditor.resolved_executables["ansible-galaxy"]).parent)

    def test_pep668_pip_user_mutation_is_rejected(self):
        canonical = MOD.load_contract()
        ansible = next(item for item in canonical["capabilities"] if item["name"] == "ansible-core")
        ansible["provision"] = {"type": "pip", "package": "ansible-core", "arguments": ["--user"]}
        canonical["provision_owners"]["ansible-core"] = "pip"
        with self.assertRaisesRegex(ValueError, "isolated Python virtual environment"):
            MOD.validate_contract(canonical)

    def test_failed_ansible_venv_creation_blocks_only_real_dependants(self):
        items = [
            {"name": "ansible-core", "requires": [], "command": "ansible", "version_key": "ANSIBLE_CORE_VERSION",
             "isolated": True,
             "provision": {"type": "python-venv", "package": "ansible-core",
                           "entry_points": ["ansible", "ansible-playbook", "ansible-galaxy"]}},
            {"name": "ansible-playbook", "requires": ["ansible-core"], "provider": "ansible-core",
             "command": "ansible-playbook"},
            {"name": "independent", "requires": [], "command": "independent"},
        ]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(MOD, "ANSIBLE_CORE_VENV", Path(tmp) / "venv"):
            def runner(argv):
                if argv[1:3] == ["-m", "venv"]:
                    return subprocess.CompletedProcess(argv, 1, "", "ensurepip unavailable")
                return subprocess.CompletedProcess(argv, 0, "ready", "")
            auditor = MOD.Auditor(contract(items), runner=runner,
                                  which=lambda command: "/bin/independent" if command == "independent" else None)
            results = auditor.run(bootstrap=True, os_name="linux", arch="amd64")
        self.assertEqual("BLOCKED", results["ansible-core"].state)
        self.assertEqual("SKIP", results["ansible-playbook"].state)
        self.assertEqual("PASS", results["independent"].state)

    def test_ansible_lint_is_provisioned_only_through_ansible_and_rechecked(self):
        canonical = MOD.load_contract()
        item = next(item for item in canonical["capabilities"] if item["name"] == "ansible-lint")
        installed = set()
        calls = []

        def runner(argv):
            calls.append(argv)
            if "platform/ansible/developer.yml" in argv:
                installed.add("ansible-lint")
                return subprocess.CompletedProcess(argv, 0, "reconciled", "")
            return subprocess.CompletedProcess(argv, 0, "ansible-lint " + MOD.load_versions()["ANSIBLE_LINT_VERSION"], "")

        auditor = MOD.Auditor(canonical, runner=runner, which=lambda command: (
            f"/opt/bin/{command}" if command == "ansible-playbook" or command in installed else None
        ))
        auditor.resolved_executables["ansible-playbook"] = "/opt/bin/ansible-playbook"
        self.assertEqual("PASS", auditor.provision(item).state)
        provision_call = calls[0]
        self.assertIn("platform/ansible/developer.yml", provision_call)
        self.assertIn("ansible_lint", provision_call)
        self.assertNotIn("pip", provision_call)

    def test_go_provider_selected_by_capability_is_forwarded_to_ansible(self):
        items = [
            {"name": "go", "requires": [], "command": "go", "version_key": "GO_VERSION"},
            {"name": "ansible-playbook", "requires": [], "command": "ansible-playbook"},
            {"name": "oapi-codegen", "requires": [], "provision_requires": ["go", "ansible-playbook"],
             "command": "oapi-codegen", "version_key": "OAPI_CODEGEN_VERSION",
             "provision": {"type": "ansible", "tags": "oapi_codegen"}},
        ]
        installed = set()
        calls = []
        versions = MOD.load_versions()

        def which(command):
            if command == "go":
                return "/opt/custom-go/bin/go"
            if command == "ansible-playbook":
                return "/usr/bin/ansible-playbook"
            return f"/opt/bin/{command}" if command in installed else None

        def runner(argv):
            calls.append(argv)
            if argv[0] == "/opt/custom-go/bin/go":
                return subprocess.CompletedProcess(argv, 0, "go version go" + versions["GO_VERSION"] + " linux/amd64", "")
            if "platform/ansible/developer.yml" in argv:
                installed.add("oapi-codegen")
                return subprocess.CompletedProcess(argv, 0, "reconciled", "")
            if argv[0].endswith("oapi-codegen"):
                return subprocess.CompletedProcess(argv, 0, "oapi-codegen version v" + versions["OAPI_CODEGEN_VERSION"], "")
            return subprocess.CompletedProcess(argv, 0, "ready", "")

        auditor = MOD.Auditor(contract(items), runner=runner, which=which)
        with mock.patch.object(MOD, "MANAGED_BIN_DIRS", ()):
            results = auditor.run(bootstrap=True, os_name="linux", arch="amd64")
        self.assertEqual("PASS", results["go"].state)
        self.assertEqual("PASS", results["oapi-codegen"].state)
        ansible_call = next(call for call in calls if "platform/ansible/developer.yml" in call)
        self.assertIn('resolved_executables={"go": "/opt/custom-go/bin/go", "ansible-playbook": "/usr/bin/ansible-playbook"}', ansible_call)
        self.assertNotIn(str(Path.home() / ".local/bin/go"), " ".join(ansible_call))
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text()
        self.assertIn('GOROOT: ""', tasks)

    def test_exact_installed_version_rejects_update_warning_substring_and_prerelease(self):
        item = {"name": "terraform", "requires": [], "command": "terraform", "version_key": "TERRAFORM_VERSION"}
        expected = MOD.load_versions()["TERRAFORM_VERSION"]
        mutations = (
            f"Terraform v1.15.0\nYour version is out of date! The latest version is {expected}",
            f"Terraform v{expected}0",
            f"Terraform v{expected}-rc1",
        )
        for output in mutations:
            with self.subTest(output=output):
                result = self.auditor([item], {"/bin/terraform": (0, output)}).run(
                    bootstrap=False, os_name="linux", arch="amd64"
                )["terraform"]
                self.assertEqual("FAIL", result.state)
        exact = self.auditor([item], {"/bin/terraform": (0, "Terraform v" + expected)}).run(
            bootstrap=False, os_name="linux", arch="amd64"
        )["terraform"]
        self.assertEqual("PASS", exact.state)

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
    def test_ansible_owner_rejects_direct_pip_mutation(self):
        canonical = MOD.load_contract()
        ansible_lint = next(item for item in canonical["capabilities"] if item["name"] == "ansible-lint")
        ansible_lint["provision"] = {"type": "pip", "package": "ansible-lint"}
        with self.assertRaisesRegex(ValueError, "canonical provision owner is ansible, not pip"):
            MOD.validate_contract(canonical)

    def test_standalone_tools_select_all_without_overselecting_targeted_tags(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text()
        expected = {"gitleaks", "helm", "terraform", "kustomize"}
        self.assertEqual(4, tasks.count("'all' in ansible_run_tags or item.tag in ansible_run_tags"))
        select = lambda run_tags: {tag for tag in expected if "all" in run_tags or tag in run_tags}
        self.assertEqual(expected, select(["all"]))
        self.assertEqual({"terraform"}, select(["terraform"]))
        # Exact old predicate mutation: under Ansible's implicit `all`, every item vanished.
        old_select = lambda run_tags: {tag for tag in expected if tag in run_tags}
        self.assertNotEqual(expected, old_select(["all"]))
        self.assertEqual(set(), old_select(["all"]))

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
        canonical["provision_owners"].pop("gitleaks")
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
