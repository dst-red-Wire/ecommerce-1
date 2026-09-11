import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class AgentEfficiencyContractTest(unittest.TestCase):
    def test_delivery_consumes_exact_evidence_not_hardcoded_pass_claims(self):
        text = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn("exact_commit_evidence", text)
        self.assertIn(".context/evidence/", text)
        self.assertNotIn("- governance: PASS", text)

    def test_native_frontend_and_tekton_authority(self):
        topology = (ROOT / "config/contracts/ci-topology.yaml").read_text(encoding="utf-8")
        self.assertIn("ci: tekton", topology)
        self.assertFalse((ROOT / "frontend/package.json").exists())
        self.assertFalse((ROOT / "scripts/nx-graph.py").exists())

    def test_ansible_does_not_reconcile_node_tooling(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8").lower()
        self.assertNotIn("nodejs.org", tasks)
        self.assertNotIn("corepack", tasks)
        self.assertNotIn("pnpm", tasks)

    def test_prepush_reuses_evidence_only_for_current_base(self):
        text = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn('base_sha = git("rev-parse", "origin/main").strip()', text)
        self.assertIn('data.get("base_sha") == base_sha', text)

    def test_ansible_first_replaces_shell_automation(self):
        self.assertFalse(list((ROOT / "scripts").glob("*.sh")))
        self.assertTrue((ROOT / "platform/ansible/developer.yml").is_file())
        controller = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn("Stateful workstation and", controller)

    def test_oasdiff_checksum_matches_downloaded_tarball_asset(self):
        versions = (ROOT / "config/toolchain/versions.env").read_text(encoding="utf-8")
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("OASDIFF_VERSION=1.28.0", versions)
        self.assertIn(
            "OASDIFF_SHA256_LINUX_AMD64_TARGZ=e0ef076f2cf953d922addc04be9c3851cf3ec18f7678d2b94d44cea23dca51b5",
            versions,
        )
        self.assertIn("oasdiff_{{ oasdiff_version }}_linux_amd64.tar.gz", tasks)
        self.assertIn('checksum: "sha256:{{ oasdiff_sha256 }}"', tasks)


if __name__ == "__main__":
    unittest.main()
