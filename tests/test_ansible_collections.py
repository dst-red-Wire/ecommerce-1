import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl", ROOT / "scripts/repoctl.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class AnsibleCollectionResolutionTest(unittest.TestCase):
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
            manifest = root / "ansible_collections/community/docker/MANIFEST.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({"collection_info": {"version": "5.2.2"}}), encoding="utf-8")
            self.assertEqual("5.2.2", MOD.resolved_ansible_collection_version("community.docker", root))
            self.assertNotEqual("3.7.0", MOD.resolved_ansible_collection_version("community.docker", root))

    def test_missing_project_collection_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(MOD.resolved_ansible_collection_version("community.docker", pathlib.Path(tmp)))


if __name__ == "__main__":
    unittest.main()
