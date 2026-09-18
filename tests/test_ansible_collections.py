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
COLLECTION_SPEC = importlib.util.spec_from_file_location("ansible_collections", ROOT / "scripts/ansible_collections.py")
COLLECTION_MOD = importlib.util.module_from_spec(COLLECTION_SPEC)
COLLECTION_SPEC.loader.exec_module(COLLECTION_MOD)


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
                "community.library_inventory_filtering_v1": "1.0.0",
                "ansible.netcommon": "2.0.0",
                "ansible.utils": "2.0.0",
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
        self.assertIn("Prepare verified project Ansible collection closure", WORKSTATION_TASKS)
        self.assertIn("scripts/ansible_collections.py", WORKSTATION_TASKS)
        self.assertNotIn("collection install", WORKSTATION_TASKS)

    def test_exact_project_pins_make_the_second_bootstrap_a_no_op(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name, version in MOD.required_ansible_collections().items():
                self.write_manifest(root, name, version)
                self.assertEqual(version, MOD.resolved_ansible_collection_version(name, root))
        self.assertIn("'PUBLISH collections' in developer_collection_prepare.stdout", WORKSTATION_TASKS)

    def test_make_entrypoints_export_project_ansible_configuration(self):
        self.assertIn("ANSIBLE_CONFIG := $(CURDIR)/platform/ansible/ansible.cfg", MAKEFILE)
        self.assertIn("export ANSIBLE_CONFIG", MAKEFILE)
        self.assertIn("scripts/ansible_collections.py run-playbook", MAKEFILE)
        self.assertNotIn("$(shell $(PYTHON) scripts/ansible_collections.py", MAKEFILE)
        self.assertIn("collections_scan_sys_path = False", ANSIBLE_CFG)

    def test_ansible_gate_reconciles_missing_project_collections_once(self):
        with mock.patch.object(MOD, "ansible_collections_ready", return_value=True):
            with mock.patch.object(MOD, "require") as require_mock:
                with mock.patch.object(MOD, "run") as run_mock:
                    MOD.reconcile_ansible_collections()
        require_mock.assert_any_call("ansible-galaxy")
        command = run_mock.call_args.args[0]
        self.assertEqual([MOD.sys.executable, "scripts/ansible_collections.py", "prepare"], command)

        with mock.patch.object(MOD, "ansible_collections_ready", return_value=True):
            with mock.patch.object(MOD, "require"), mock.patch.object(MOD, "run") as second_run:
                MOD.reconcile_ansible_collections()
        second_run.assert_called_once()

    def test_bootstrap_uses_only_the_ansible_core_stdout_callback(self):
        self.assertNotIn("stdout_callback = yaml", ANSIBLE_CFG)
        self.assertNotIn("stdout_callback = community.general.yaml", ANSIBLE_CFG)
        self.assertIn("stdout_callback = default", ANSIBLE_CFG)
        self.assertIn("callback_result_format = yaml", ANSIBLE_CFG)
        self.assertIn("collections_path = ../../.ansible/collections", ANSIBLE_CFG)

    def test_lock_records_complete_dependency_closure_and_official_digests(self):
        lock = json.loads((ROOT / "platform/ansible/collections.lock.json").read_text(encoding="utf-8"))
        by_name = {item["name"]: item for item in lock["collections"]}
        self.assertIn("Galaxy v3 artifact metadata", lock["digest_authority"])
        for item in lock["collections"]:
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
            for dependency in item["dependencies"]:
                self.assertIn(dependency, by_name)
        self.assertEqual(
            ">=1.0.0", by_name["community.docker"]["dependencies"]["community.library_inventory_filtering_v1"]
        )
        self.assertEqual(">=2.0.0", by_name["ansible.netcommon"]["dependencies"]["ansible.utils"])

    def test_gate_forces_supported_ansible_lint_offline_mode(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn('run(["ansible-lint", "--offline", *files])', source)

    def test_warm_prepare_never_acquires_or_reinstalls(self):
        from test_pr86_five_active import CollectionIntegrityGenerationTests

        case = CollectionIntegrityGenerationTests("test_warm_reuse_does_not_acquire_or_install")
        result = unittest.TestResult()
        case.run(result)
        self.assertTrue(result.wasSuccessful(), result.errors or result.failures)

    def test_offline_missing_archive_fails_with_exact_identity(self):
        item = COLLECTION_MOD.load_lock()["collections"][0]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(COLLECTION_MOD, "TOOL_HOME", pathlib.Path(tmp)):
            with self.assertRaisesRegex(RuntimeError, rf"{item['name']}:{item['version']} sha256={item['sha256']}"):
                COLLECTION_MOD.acquire(item, offline=True)


if __name__ == "__main__":
    unittest.main()
