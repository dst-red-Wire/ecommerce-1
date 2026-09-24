from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config/infrastructure/kratix-platform.yaml"
BUNDLE = ROOT / "platform/fleet/bundles/kratix"
EXPECTED_COMMIT = "d50cebceb33defc1f6b9882a009bb1436f0aa3f4"
EXPECTED_DIGEST = (
    "sha256:0810b20ca820c627ce176c58798c41c9858b85917daeb474f904348cc41ce0e7"
)


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class KratixPlatformContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = load_yaml(CONTRACT_PATH)
        cls.lock = load_yaml(ROOT / "architecture.lock.yaml")
        cls.bootstrap = load_yaml(ROOT / "config/infrastructure/mgmt-bootstrap.yaml")
        cls.waves = load_yaml(ROOT / "config/infrastructure/deployment-waves.yaml")
        cls.toolchain = json.loads(
            (ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8")
        )
        cls.kustomization_text = (BUNDLE / "kustomization.yaml").read_text(
            encoding="utf-8"
        )
        cls.state_store_text = (BUNDLE / "git-state-store.yaml").read_text(
            encoding="utf-8"
        )

    def test_exact_upstream_commit_and_multi_arch_image_digest(self):
        self.assertEqual(EXPECTED_COMMIT, self.contract["upstream"]["commit"])
        image = self.contract["controller_image"]
        self.assertEqual(EXPECTED_DIGEST, image["index_digest"])
        self.assertEqual(f"{image['repository']}@{EXPECTED_DIGEST}", image["reference"])
        self.assertRegex(image["platforms"]["linux_amd64"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(image["platforms"]["linux_arm64"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual("forbidden", image["mutable_tags"])

    def test_root_authority_registers_single_kratix_contract(self):
        self.assertEqual(
            "config/infrastructure/kratix-platform.yaml",
            self.lock["machine_contracts"]["kratix_platform"],
        )
        orchestrator = self.lock["developer_platform"]["platform_orchestrator"]
        self.assertEqual("kratix-oss", orchestrator["implementation"])
        self.assertEqual("rancher-fleet", orchestrator["deployment_authority"])
        self.assertEqual("gitea-gitstatestore", orchestrator["state_store"])

    def test_kustomize_and_helm_reuse_central_toolchain_versions(self):
        installation = self.contract["installation"]
        packaging = self.contract["promise_packaging"]
        self.assertEqual("kustomize", installation["composition"])
        self.assertEqual("KUSTOMIZE_VERSION", installation["kustomize_version_key"])
        self.assertEqual("helm", packaging["format"])
        self.assertEqual("HELM_VERSION", packaging["helm_version_key"])
        self.assertRegex(
            self.toolchain["versions"]["KUSTOMIZE_VERSION"], r"^\d+\.\d+\.\d+$"
        )
        self.assertRegex(self.toolchain["versions"]["HELM_VERSION"], r"^\d+\.\d+\.\d+$")

    def test_fleet_kustomization_pins_source_and_both_image_consumers(self):
        self.assertIn(f"?ref={EXPECTED_COMMIT}", self.kustomization_text)
        self.assertEqual(2, self.kustomization_text.count(EXPECTED_DIGEST))
        self.assertNotRegex(self.kustomization_text, r":(?:latest|dev)(?:\s|$)")
        kustomization = load_yaml(BUNDLE / "kustomization.yaml")
        self.assertEqual("Kustomization", kustomization["kind"])
        self.assertEqual(EXPECTED_DIGEST, kustomization["images"][0]["digest"])

    def test_gitea_state_store_and_fleet_reader_are_least_privilege_separated(self):
        documents = list(yaml.safe_load_all(self.state_store_text))
        state_stores = [
            document for document in documents if document["kind"] == "GitStateStore"
        ]
        destinations = [
            document for document in documents if document["kind"] == "Destination"
        ]
        git_repos = [
            document for document in documents if document["kind"] == "GitRepo"
        ]
        self.assertEqual(1, len(state_stores))
        self.assertEqual(
            {"lab", "preprod", "prod"},
            {item["metadata"]["name"] for item in destinations},
        )
        self.assertEqual(
            {"kratix-state-lab", "kratix-state-preprod", "kratix-state-prod"},
            {item["metadata"]["name"] for item in git_repos},
        )
        state_store = state_stores[0]
        self.assertEqual("ssh", state_store["spec"]["authMethod"])
        self.assertEqual(
            "kratix-gitea-writer", state_store["spec"]["secretRef"]["name"]
        )
        for git_repo in git_repos:
            self.assertEqual("fleet-default", git_repo["metadata"]["namespace"])
            self.assertEqual(
                "kratix-gitea-reader", git_repo["spec"]["clientSecretName"]
            )
            self.assertNotEqual(
                state_store["spec"]["secretRef"]["name"],
                git_repo["spec"]["clientSecretName"],
            )
            self.assertEqual(state_store["spec"]["url"], git_repo["spec"]["repo"])
        self.assertNotIn("kind: Secret", self.state_store_text)

    def test_fleet_remains_sole_reconciler_and_quick_start_is_forbidden(self):
        reconciliation = self.contract["reconciliation"]
        self.assertEqual("rancher-fleet", reconciliation["sole_gitops_authority"])
        self.assertEqual("forbidden", reconciliation["direct_kratix_deploy"])
        self.assertEqual("forbidden", reconciliation["bundled_flux"])
        self.assertEqual("forbidden", reconciliation["bundled_object_store"])
        combined = self.kustomization_text + self.state_store_text
        self.assertIsNone(
            re.search(r"fluxcd|flux-system|seaweedfs", combined, re.IGNORECASE)
        )

    def test_known_upstream_cve_keeps_fleet_paused_and_activation_blocked(self):
        security = self.contract["security_qualification"]
        self.assertEqual("BLOCK", security["final_result"])
        self.assertFalse(security["deployment_permitted"])
        self.assertEqual("forbidden", security["automatic_exception"])
        self.assertEqual(
            {"CVE-2026-93990"},
            {finding["id"] for finding in security["blocking_findings"]},
        )
        self.assertTrue(self.contract["installation"]["fleet_bundle_paused"])
        fleet = load_yaml(BUNDLE / "fleet.yaml")
        self.assertTrue(fleet["paused"])
        self.assertTrue(
            security["resolution"]["replacement_must_pass_current_cve_policy"]
        )
        self.assertTrue(
            security["resolution"]["fleet_unpause_requires_reviewed_pull_request"]
        )

    def test_multi_cluster_destinations_match_portal_flow(self):
        destinations = self.contract["destinations"]
        self.assertEqual({"lab", "preprod", "prod"}, set(destinations))
        self.assertEqual("virtualbox-example", destinations["lab"]["substrate"])
        self.assertEqual(
            "canonical-prod-a-and-prod-b", destinations["prod"]["substrate"]
        )
        self.assertTrue(
            all(item["runtime"] == "rke2" for item in destinations.values())
        )

    def test_bootstrap_and_deployment_wave_preserve_dependencies(self):
        service = self.bootstrap["platform_bootstrap"]["services"]["kratix"]
        self.assertEqual("rancher-fleet", service["deployment_owner"])
        self.assertEqual(
            {
                "gitea",
                "rancher-fleet",
                "cert-manager",
                "openbao-bootstrap",
                "external-secrets",
            },
            set(service["activation_dependencies"]),
        )
        waves = {wave["id"]: wave for wave in self.waves["waves"]}
        self.assertEqual(
            ["40-secrets-registry-ci"],
            waves["45-developer-platform-orchestration"]["requires"],
        )
        self.assertEqual(
            ["45-developer-platform-orchestration"],
            waves["50-observability"]["requires"],
        )


if __name__ == "__main__":
    unittest.main()
