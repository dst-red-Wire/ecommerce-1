import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
ANSIBLE_CFG = (ROOT / "platform/ansible/ansible.cfg").read_text(encoding="utf-8")
WORKSTATION_TASKS = (ROOT / "platform/ansible/roles/developer_workstation/tasks/main.yml").read_text(encoding="utf-8")
SPEC = importlib.util.spec_from_file_location("repoctl", ROOT / "scripts/repoctl.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class AnsibleCollectionResolutionTest(unittest.TestCase):
    @staticmethod
    def write_manifest(root: pathlib.Path, name: str, version: str) -> None:
        namespace, collection = name.split(".", 1)
        manifest = root / "ansible_collections" / namespace / collection / "MANIFEST.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({"collection_info": {"version": version}}), encoding="utf-8")

    def test_requirements_are_exact_and_complete(self):
        self.assertEqual(
            {
                "ansible.posix": "1.5.4",
                "community.general": "8.3.0",
                "community.docker": "3.7.0",
                "community.crypto": "2.17.1",
                "community.sops": "1.6.7",
                "containers.podman": "1.11.0",
                "hetzner.hcloud": "2.4.1",
                "kubernetes.core": "2.4.0",
            },
            MOD.required_ansible_collections(),
        )

    def test_project_path_detects_effective_version_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write_manifest(root, "community.docker", "5.2.2")
            self.assertEqual("5.2.2", MOD.resolved_ansible_collection_version("community.docker", root))
            self.assertNotEqual("3.7.0", MOD.resolved_ansible_collection_version("community.docker", root))

    def test_missing_project_collection_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(MOD.resolved_ansible_collection_version("community.docker", pathlib.Path(tmp)))

    def test_exact_system_collection_does_not_satisfy_missing_project_collection(self):
        with tempfile.TemporaryDirectory() as project_tmp, tempfile.TemporaryDirectory() as system_tmp:
            self.write_manifest(pathlib.Path(system_tmp), "community.docker", "3.7.0")
            self.assertIsNone(MOD.resolved_ansible_collection_version("community.docker", pathlib.Path(project_tmp)))

    def test_exact_project_collection_wins_over_concurrent_user_version(self):
        with tempfile.TemporaryDirectory() as project_tmp, tempfile.TemporaryDirectory() as user_tmp:
            self.write_manifest(pathlib.Path(project_tmp), "community.docker", "3.7.0")
            self.write_manifest(pathlib.Path(user_tmp), "community.docker", "5.2.2")
            self.assertEqual(
                "3.7.0", MOD.resolved_ansible_collection_version("community.docker", pathlib.Path(project_tmp))
            )

    def test_bootstrap_repairs_only_when_project_collections_drift(self):
        self.assertIn("Identify project-owned Ansible collection drift", WORKSTATION_TASKS)
        self.assertIn("when: developer_collection_drift | length > 0", WORKSTATION_TASKS)
        self.assertIn("- --force", WORKSTATION_TASKS)
        self.assertNotIn("Reconcile pinned project Ansible collections", WORKSTATION_TASKS)

    def test_exact_project_pins_make_the_second_bootstrap_a_no_op(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name, version in MOD.required_ansible_collections().items():
                self.write_manifest(root, name, version)
                self.assertEqual(version, MOD.resolved_ansible_collection_version(name, root))
        self.assertIn("when: developer_collection_drift | length > 0", WORKSTATION_TASKS)

    def test_make_entrypoints_export_project_ansible_configuration(self):
        self.assertIn("ANSIBLE_CONFIG := $(CURDIR)/platform/ansible/ansible.cfg", MAKEFILE)
        self.assertIn("export ANSIBLE_CONFIG", MAKEFILE)
        self.assertIn("collections_scan_sys_path = False", ANSIBLE_CFG)

    def test_ansible_gate_reconciles_missing_project_collections_once(self):
        with mock.patch.object(MOD, "ansible_collections_ready", side_effect=[False, True]):
            with mock.patch.object(MOD, "require") as require_mock:
                with mock.patch.object(MOD, "run") as run_mock:
                    MOD.reconcile_ansible_collections()
        require_mock.assert_any_call("ansible-playbook")
        require_mock.assert_any_call("ansible-galaxy")
        command = run_mock.call_args.args[0]
        self.assertIn("platform/ansible/developer.yml", command)
        self.assertEqual("ansible_collections", command[command.index("--tags") + 1])

        with mock.patch.object(MOD, "ansible_collections_ready", return_value=True):
            with mock.patch.object(MOD, "run") as second_run:
                MOD.reconcile_ansible_collections()
        second_run.assert_not_called()

    def test_bootstrap_uses_only_the_ansible_core_stdout_callback(self):
        self.assertNotIn("stdout_callback = yaml", ANSIBLE_CFG)
        self.assertNotIn("stdout_callback = community.general.yaml", ANSIBLE_CFG)
        self.assertIn("stdout_callback = default", ANSIBLE_CFG)
        self.assertIn("callback_result_format = yaml", ANSIBLE_CFG)
        self.assertIn("collections_path = ../../.ansible/collections", ANSIBLE_CFG)


if __name__ == "__main__":
    unittest.main()
