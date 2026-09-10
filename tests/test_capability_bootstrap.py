import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
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

    def quality_provision(self, requested, tags=None, failures=()):
        tags = tags or {name: name for name in ("ruff", "oxfmt", "oxlint")}
        items = [
            {"name": "ansible-playbook", "requires": [], "command": "ansible-playbook"},
            *[
                {"name": name, "requires": [], "command": name,
                 "provision": {"type": "ansible", "tags": tags[name]}}
                for name in ("ruff", "oxfmt", "oxlint")
            ],
        ]
        installed = {"ruff", "oxfmt", "oxlint"} - {requested}
        calls = []

        def runner(argv):
            calls.append(argv)
            if "platform/ansible/developer.yml" in argv:
                selected_tag = argv[argv.index("--tags") + 1]
                for name in ("oxlint", "oxfmt", "ruff"):
                    if tags[name] != selected_tag:
                        continue
                    installed.add(name)
                    if name in failures:
                        return subprocess.CompletedProcess(argv, 1, "", f"{name} download failed")
                return subprocess.CompletedProcess(argv, 0, "reconciled", "")
            return subprocess.CompletedProcess(argv, 0, "1.0", "")

        with mock.patch.object(MOD, "validate_contract") if len(set(tags.values())) != 3 else mock.patch.object(
                MOD, "validate_contract", wraps=MOD.validate_contract):
            auditor = MOD.Auditor(contract(items), runner=runner,
                                  which=lambda command: f"/bin/{command}" if command == "ansible-playbook" or command in installed else None)
        result = auditor.provision(next(item for item in items if item["name"] == requested))
        return result, calls

    def test_ruff_provisioning_is_positive_and_targeted(self):
        result, calls = self.quality_provision("ruff")
        self.assertEqual("PASS", result.state)
        self.assertEqual("ruff", calls[0][calls[0].index("--tags") + 1])

    def test_oxfmt_provisioning_is_positive_and_targeted(self):
        result, calls = self.quality_provision("oxfmt")
        self.assertEqual("PASS", result.state)
        self.assertEqual("oxfmt", calls[0][calls[0].index("--tags") + 1])

    def test_oxlint_provisioning_is_positive_and_targeted(self):
        result, calls = self.quality_provision("oxlint")
        self.assertEqual("PASS", result.state)
        self.assertEqual("oxlint", calls[0][calls[0].index("--tags") + 1])

    def test_quality_provisioning_failures_are_isolated(self):
        oxlint, _ = self.quality_provision("oxlint", failures={"ruff", "oxfmt"})
        ruff, _ = self.quality_provision("ruff", failures={"oxfmt"})
        self.assertEqual("PASS", oxlint.state)
        self.assertEqual("PASS", ruff.state)

    def test_shared_quality_tag_mutation_contaminates_requested_tool(self):
        shared = {name: "quality_tools" for name in ("ruff", "oxfmt", "oxlint")}
        result, _ = self.quality_provision("oxlint", tags=shared, failures={"oxfmt"})
        self.assertEqual("BLOCKED", result.state)
        isolated, _ = self.quality_provision("oxlint", failures={"ruff", "oxfmt"})
        self.assertEqual("PASS", isolated.state)

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

    def test_compatible_runner_ansible_continues_project_provisioning_without_self_install(self):
        version = MOD.load_versions()["ANSIBLE_CORE_VERSION"]
        items = [
            {"name": "ansible-core", "requires": [], "command": "ansible", "version_args": ["--version"], "version_key": "ANSIBLE_CORE_VERSION",
             "classification": "seed-prerequisite"},
            {"name": "ansible-playbook", "requires": ["ansible-core"], "provider": "ansible-core",
             "command": "ansible-playbook"},
            {"name": "ansible-galaxy", "requires": ["ansible-core"], "provider": "ansible-core",
             "command": "ansible-galaxy", "version_key": "ANSIBLE_CORE_VERSION"},
            {"name": "project-tool", "requires": [], "provision_requires": ["ansible-playbook"],
             "command": "project-tool", "provision": {"type": "ansible", "tags": "project_tool"}},
        ]
        calls = []
        installed = set()
        def runner(argv):
            calls.append(argv)
            if "platform/ansible/developer.yml" in argv:
                installed.add("project-tool")
                return subprocess.CompletedProcess(argv, 0, "reconciled", "")
            output = f"ansible [core {version}]" if Path(argv[0]).name.startswith("ansible") else "ready"
            return subprocess.CompletedProcess(argv, 0, output, "")
        with tempfile.TemporaryDirectory() as tmp:
            runner_bin = Path(tmp, "runner", "bin")
            runner_bin.mkdir(parents=True)
            for command in ("ansible", "ansible-playbook", "ansible-galaxy"):
                executable = runner_bin / command
                executable.write_text("#!/bin/true\n")
                executable.chmod(0o755)
            def which(command):
                return str(runner_bin / command) if command.startswith("ansible") else (f"/opt/bin/{command}" if command in installed else None)
            results = MOD.Auditor(contract(items), runner=runner, which=which).run(
                bootstrap=True, os_name="linux", arch="amd64"
            )
        self.assertTrue(all(result.state == "PASS" for result in results.values()))
        self.assertTrue(any("platform/ansible/developer.yml" in call for call in calls))
        self.assertFalse(any("pip" in call or "apt" in call or "venv" in call for call in calls))

    def test_missing_runner_ansible_fails_without_install_and_keeps_independent_audit(self):
        items = [
            {"name": "ansible-core", "requires": [], "command": "ansible", "version_args": ["--version"], "version_key": "ANSIBLE_CORE_VERSION",
             "classification": "seed-prerequisite"},
            {"name": "ansible-playbook", "requires": ["ansible-core"], "provider": "ansible-core", "command": "ansible-playbook"},
            {"name": "ansible-galaxy", "requires": ["ansible-core"], "provider": "ansible-core", "command": "ansible-galaxy"},
            {"name": "ansible-owned", "requires": [], "provision_requires": ["ansible-playbook"], "command": "owned",
             "provision": {"type": "ansible", "tags": "owned"}},
            {"name": "independent", "requires": [], "command": "independent"},
        ]
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "ready", ""))
        results = MOD.Auditor(contract(items), runner=runner,
                              which=lambda command: "/bin/independent" if command == "independent" else None).run(
            bootstrap=True, os_name="linux", arch="amd64"
        )
        self.assertEqual("FAIL", results["ansible-core"].state)
        self.assertIn("runner prerequisite missing: ansible-core", results["ansible-core"].detail)
        self.assertEqual("SKIP", results["ansible-playbook"].state)
        self.assertEqual("SKIP", results["ansible-owned"].state)
        self.assertEqual("PASS", results["independent"].state)
        self.assertEqual(1, runner.call_count)

    def test_stale_runner_ansible_fails_with_pinned_authority_and_is_not_provisioned(self):
        items = [
            {"name": "ansible-core", "requires": [], "command": "ansible", "version_args": ["--version"], "version_key": "ANSIBLE_CORE_VERSION",
             "classification": "seed-prerequisite"},
            {"name": "ansible-playbook", "requires": ["ansible-core"], "provider": "ansible-core", "command": "ansible-playbook"},
            {"name": "ansible-galaxy", "requires": ["ansible-core"], "provider": "ansible-core", "command": "ansible-galaxy"},
        ]
        calls = []
        def runner(argv):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "ansible [core 1.0.0]", "")
        results = MOD.Auditor(contract(items), runner=runner, which=lambda command: f"/usr/bin/{command}").run(
            bootstrap=True, os_name="linux", arch="amd64"
        )
        self.assertEqual("FAIL", results["ansible-core"].state)
        self.assertIn("expected " + MOD.load_versions()["ANSIBLE_CORE_VERSION"], results["ansible-core"].detail)
        self.assertEqual([["/usr/bin/ansible", "--version"]], calls)

    def test_ansible_runner_prerequisite_rejects_repository_provisioner_mutation(self):
        for provision in ({"type": "pip", "package": "ansible-core"},
                          {"type": "python-venv", "package": "ansible-core"},
                          {"type": "debian-package", "package": "ansible-core"}):
            canonical = MOD.load_contract()
            next(item for item in canonical["capabilities"] if item["name"] == "ansible-core")["provision"] = provision
            with self.subTest(provision=provision), self.assertRaisesRegex(
                    ValueError, "runner prerequisite must not have a repository provisioner"):
                MOD.validate_contract(canonical)

    def test_capability_bootstrap_contains_no_ansible_self_bootstrap_path(self):
        source = (ROOT / "scripts/capability_bootstrap.py").read_text()
        forbidden = ("pip install ansible-core", "python-venv", "ANSIBLE_CORE_VENV",
                     "apt install ansible", "apt install ansible-core")
        for fragment in forbidden:
            self.assertNotIn(fragment, source)

    def test_ansible_entrypoints_are_bound_to_validated_core_provider(self):
        versions = MOD.load_versions()
        items = [
            {"name": "ansible-core", "requires": [], "command": "ansible", "version_key": "ANSIBLE_CORE_VERSION",
             "classification": "seed-prerequisite"},
            {"name": "ansible-playbook", "requires": ["ansible-core"], "provider": "ansible-core",
             "command": "ansible-playbook"},
            {"name": "ansible-galaxy", "requires": ["ansible-core"], "provider": "ansible-core",
             "command": "ansible-galaxy"},
            {"name": "next", "requires": [], "provision_requires": ["ansible-playbook"], "command": "next",
             "provision": {"type": "ansible", "tags": "next"}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            system_bin = Path(tmp, "usr", "bin")
            managed_bin = Path(tmp, "home", "test", ".local", "bin")
            system_bin.mkdir(parents=True)
            managed_bin.mkdir(parents=True)
            for directory in (system_bin, managed_bin):
                for command in ("ansible", "ansible-playbook", "ansible-galaxy"):
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
                if command in ("ansible", "ansible-playbook", "ansible-galaxy"):
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

                mutated_contract = contract([
                    {**item, **({"provider": None} if item["name"] == "ansible-playbook" else {})}
                    for item in items
                ])
                with self.assertRaisesRegex(ValueError, "must be bound to the ansible-core provider"):
                    MOD.validate_contract(mutated_contract)

    def test_ansible_entrypoint_missing_from_provider_does_not_fall_back_to_path(self):
        items = [
            {"name": "ansible-core", "requires": [], "command": "ansible", "classification": "seed-prerequisite"},
            {"name": "ansible-playbook", "requires": ["ansible-core"], "provider": "ansible-core",
             "command": "ansible-playbook"},
            {"name": "ansible-galaxy", "requires": ["ansible-core"], "provider": "ansible-core",
             "command": "ansible-galaxy"},
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
    @staticmethod
    def terraform_archive_run(source, selected_tag, unzip_present, sudo_available=True):
        probe = re.search(
            r"- name: Detect Terraform archive extraction prerequisite\n(?P<body>.*?)(?=\n- name:)",
            source,
            re.DOTALL,
        )
        prerequisite = re.search(
            r"- name: Ensure Terraform archive extraction prerequisite\n(?P<body>.*?)(?=\n- name:)",
            source,
            re.DOTALL,
        )
        extraction = re.search(
            r"- name: Extract pinned standalone gate tools\n(?P<body>.*?)(?=\n- name:)",
            source,
            re.DOTALL,
        )
        if probe is None or prerequisite is None or extraction is None:
            return False, [], 0

        events = []
        privileged_installs = 0
        probe_selected = selected_tag in re.findall(
            r"^  tags: \[([^]]+)\]$", probe.group("body"), re.MULTILINE
        )[0].split(", ")
        if probe_selected:
            events.append("probe-unzip")
        prerequisite_selected = selected_tag in re.findall(
            r"^  tags: \[([^]]+)\]$", prerequisite.group("body"), re.MULTILINE
        )[0].split(", ")
        guarded_by_probe = "when: terraform_unzip_probe.rc != 0" in prerequisite.group("body")
        if prerequisite_selected and (not guarded_by_probe or not unzip_present):
            events.append("privileged-unzip-install")
            privileged_installs += 1
            if not sudo_available:
                return False, events, privileged_installs
            if not unzip_present:
                unzip_present = True

        extraction_selected = (
            selected_tag in {"gitleaks", "helm", "terraform", "kustomize"}
            and f"tag: {selected_tag}" in extraction.group("body")
        )
        if extraction_selected:
            events.append(f"extract-{selected_tag}")
            if selected_tag == "terraform" and not unzip_present:
                return False, events, privileged_installs
        return True, events, privileged_installs

    def test_terraform_target_installs_missing_unzip_before_archive_extraction(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text()
        passed, events, installs = self.terraform_archive_run(tasks, "terraform", unzip_present=False)
        self.assertTrue(passed)
        self.assertEqual(["probe-unzip", "privileged-unzip-install", "extract-terraform"], events)
        self.assertEqual(1, installs)

    def test_terraform_target_with_unzip_present_never_attempts_sudo_and_is_idempotent(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text()
        for _ in range(2):
            passed, events, privileged_installs = self.terraform_archive_run(
                tasks, "terraform", unzip_present=True, sudo_available=False
            )
            self.assertTrue(passed)
            self.assertEqual(["probe-unzip", "extract-terraform"], events)
            self.assertEqual(0, privileged_installs)

    def test_unconditional_privileged_install_mutation_fails_then_restored_passes(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text()
        guard = "  when: terraform_unzip_probe.rc != 0\n"
        self.assertEqual(1, tasks.count(guard))
        mutated = tasks.replace(guard, "", 1)
        mutated_passed, mutated_events, mutated_installs = self.terraform_archive_run(
            mutated, "terraform", unzip_present=True, sudo_available=False
        )
        self.assertFalse(mutated_passed)
        self.assertEqual(["probe-unzip", "privileged-unzip-install"], mutated_events)
        self.assertEqual(1, mutated_installs)
        restored_passed, restored_events, restored_installs = self.terraform_archive_run(
            tasks, "terraform", unzip_present=True, sudo_available=False
        )
        self.assertTrue(restored_passed)
        self.assertEqual(["probe-unzip", "extract-terraform"], restored_events)
        self.assertEqual(0, restored_installs)

    def test_missing_terraform_prerequisite_tag_mutation_fails_then_restored_passes(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text()
        prerequisite = re.search(
            r"(- name: Ensure Terraform archive extraction prerequisite\n.*?  tags: )\[terraform\]",
            tasks,
            re.DOTALL,
        )
        self.assertIsNotNone(prerequisite)
        mutated = tasks[:prerequisite.start()] + prerequisite.group(1) + "[toolchain]" + tasks[prerequisite.end():]
        mutated_passed, mutated_events, _ = self.terraform_archive_run(mutated, "terraform", unzip_present=False)
        self.assertFalse(mutated_passed)
        self.assertEqual(["probe-unzip", "extract-terraform"], mutated_events)
        restored_passed, _, _ = self.terraform_archive_run(tasks, "terraform", unzip_present=False)
        self.assertTrue(restored_passed)

    def test_independent_archive_capabilities_do_not_select_terraform_unzip_setup(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text()
        for capability in ("helm", "kustomize"):
            passed, events, installs = self.terraform_archive_run(tasks, capability, unzip_present=False)
            self.assertTrue(passed)
            self.assertEqual([f"extract-{capability}"], events)
            self.assertEqual(0, installs)

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

    def test_quality_capabilities_have_distinct_provisioning_tags(self):
        canonical = MOD.load_contract()
        names = {item["name"]: item for item in canonical["capabilities"]}
        tags = {name: names[name]["provision"]["tags"] for name in ("ruff", "oxfmt", "oxlint")}
        self.assertEqual({"ruff": "ruff", "oxfmt": "oxfmt", "oxlint": "oxlint"}, tags)

        for name in tags:
            names[name]["provision"]["tags"] = "quality_tools"
        with self.assertRaisesRegex(ValueError, "independent quality capabilities must use distinct"):
            MOD.validate_contract(canonical)

    def test_quality_tasks_select_all_tools_for_full_reconciliation(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/quality.yml").read_text()
        main_tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text()
        expected = {"ruff", "oxfmt", "oxlint"}

        def prepared_tools(source, run_tags):
            preparation = source.split("- name: Download pinned Oxlint archive", 1)[0]
            predicate = re.search(r'^  when: "(.+)"$', preparation, re.MULTILINE).group(1)
            return {
                tag
                for tag in re.findall(r"tag: (ruff|oxfmt|oxlint)}", preparation)
                if eval(
                    predicate,
                    {"__builtins__": {}},
                    {"ansible_run_tags": run_tags, "item": SimpleNamespace(tag=tag)},
                )
            }

        select = lambda run_tags: {
            tag
            for tag in expected
            if "all" in run_tags or "toolchain" in run_tags or "quality_tools" in run_tags or tag in run_tags
        }
        self.assertEqual(expected, select(["all"]))
        self.assertEqual(expected, select(["quality_tools"]))
        self.assertEqual(expected, select(["toolchain"]))
        for tag in expected:
            self.assertEqual({tag}, select([tag]))
            self.assertIn(f"tags: [toolchain, quality_tools, {tag}]", tasks)

        for aggregate in ("all", "quality_tools", "toolchain"):
            self.assertEqual(expected, prepared_tools(tasks, [aggregate]))
        for individual in expected:
            self.assertEqual({individual}, prepared_tools(tasks, [individual]))

        shared_setup = main_tasks.split("- name: Install native build prerequisites", 1)[0]
        for selector in ("all", "quality_tools", "toolchain", *expected):
            with self.subTest(shared_directory_selector=selector):
                self.assertTrue(selector == "all" or selector in shared_setup)

        # Exact finding mutation: without the individual tags, targeted Oxlint
        # provisioning cannot select the shared cache and binary directories.
        mutated_setup = shared_setup
        for tag in expected:
            mutated_setup = mutated_setup.replace(f", {tag}", "")
        self.assertNotIn("oxlint", mutated_setup)
        self.assertIn("oxlint", shared_setup)

        self.assertEqual(
            2,
            tasks.count(
                "'all' in ansible_run_tags or 'toolchain' in ansible_run_tags "
                "or 'quality_tools' in ansible_run_tags "
                "or item.tag in ansible_run_tags"
            ),
        )
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("quality-tools: ## Reconcile pinned Oxlint, Oxfmt and Ruff binaries", makefile)
        self.assertIn("@$(ANSIBLE_LOCAL) --tags quality_tools", makefile)
        self.assertIn("--tags toolchain,node,agent_tools,context_tools", makefile)

        # Exact regression mutation: tasks still carry `toolchain`, but the old
        # predicate omits every per-tool directory needed before extraction.
        mutated_tasks = tasks.replace("or 'toolchain' in ansible_run_tags ", "")
        self.assertEqual(set(), prepared_tools(mutated_tasks, ["toolchain"]))
        self.assertEqual(expected, prepared_tools(tasks, ["toolchain"]))

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
