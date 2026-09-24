from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "platform/fleet/bundles/product"


class ProductGoldenServiceContractTest(unittest.TestCase):
    def test_product_event_names_match_canonical_registry(self) -> None:
        registry = yaml.safe_load(
            (ROOT / "config/contracts/event-contracts.yaml").read_text(encoding="utf-8")
        )
        source = (ROOT / "services/product/internal/application/service.go").read_text(
            encoding="utf-8"
        )
        expected = {
            "product.ProductCreated.v1",
            "product.ProductUpdated.v1",
            "product.SKUUpdated.v1",
        }
        self.assertTrue(expected.issubset(registry["events"]))
        for event_name in expected:
            self.assertIn(f'"{event_name}"', source)

    def test_fleet_chart_renders_restricted_digest_only_workload(self) -> None:
        helm = shutil.which("helm")
        if helm is None:
            self.skipTest("helm is not installed")
        digest = "sha256:" + ("a" * 64)
        command = [
            helm,
            "template",
            "product",
            str(CHART),
            "--namespace",
            "product",
            "--set-string",
            "image.repository=harbor.invalid/ecommerce/product",
            "--set-string",
            f"image.digest={digest}",
            "--set-string",
            "runtime.homeSite=preprod-a",
            "--set-string",
            "runtime.kafkaBrokers=kafka.invalid:9092",
            "--set-string",
            "runtime.otlpEndpoint=http://rotel.invalid:4317",
            "--set-string",
            "runtime.oidcIssuer=https://keycloak.invalid/realms/ecommerce",
        ]
        rendered = subprocess.run(
            command, cwd=ROOT, check=True, text=True, capture_output=True
        ).stdout
        documents = [document for document in yaml.safe_load_all(rendered) if document]
        by_kind = {
            document["kind"]: document
            for document in documents
            if document["kind"] != "NetworkPolicy"
        }
        self.assertTrue(
            {
                "Namespace",
                "ServiceAccount",
                "ConfigMap",
                "Deployment",
                "Service",
                "HorizontalPodAutoscaler",
                "PodDisruptionBudget",
                "Job",
            }.issubset(by_kind)
        )

        namespace = by_kind["Namespace"]
        self.assertEqual(
            namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"],
            "restricted",
        )
        deployment = by_kind["Deployment"]
        pod_spec = deployment["spec"]["template"]["spec"]
        container = pod_spec["containers"][0]
        self.assertFalse(pod_spec["automountServiceAccountToken"])
        self.assertTrue(pod_spec["securityContext"]["runAsNonRoot"])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
        self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertEqual(
            container["image"], f"harbor.invalid/ecommerce/product@{digest}"
        )
        self.assertEqual(container["livenessProbe"]["httpGet"]["path"], "/healthz")
        self.assertEqual(container["readinessProbe"]["httpGet"]["path"], "/readyz")
        self.assertIn("requests", container["resources"])
        self.assertIn("limits", container["resources"])

        policies = [
            document for document in documents if document["kind"] == "NetworkPolicy"
        ]
        default_deny = next(
            policy
            for policy in policies
            if policy["metadata"]["name"] == "product-default-deny"
        )
        self.assertEqual(default_deny["spec"]["podSelector"], {})
        self.assertEqual(default_deny["spec"]["policyTypes"], ["Ingress", "Egress"])
        self.assertNotIn("PRODUCT_DATABASE_URL", by_kind["ConfigMap"]["data"])
        self.assertEqual(
            by_kind["ConfigMap"]["data"]["PRODUCT_KAFKA_TLS_CA_FILE"],
            "/var/run/secrets/product-kafka/ca.crt",
        )
        kafka_volume = next(
            volume for volume in pod_spec["volumes"] if volume["name"] == "kafka-tls"
        )
        self.assertEqual(kafka_volume["secret"]["secretName"], "product-kafka-tls")
        self.assertEqual(kafka_volume["secret"]["defaultMode"], 0o440)

        migration = by_kind["Job"]
        self.assertEqual(
            "pre-install,pre-upgrade",
            migration["metadata"]["annotations"]["helm.sh/hook"],
        )
        self.assertEqual(3, migration["spec"]["backoffLimit"])
        migration_pod = migration["spec"]["template"]["spec"]
        self.assertEqual("OnFailure", migration_pod["restartPolicy"])
        self.assertFalse(migration_pod["automountServiceAccountToken"])
        migration_container = migration_pod["containers"][0]
        self.assertEqual(["/product-migrate"], migration_container["command"])
        self.assertEqual(
            f"harbor.invalid/ecommerce/product@{digest}", migration_container["image"]
        )
        self.assertTrue(
            migration_container["securityContext"]["readOnlyRootFilesystem"]
        )

    def test_product_image_contains_explicit_migration_binary(self) -> None:
        containerfile = (ROOT / "services/product/Containerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn('"/out/product-migrate", "./cmd/product-migrate"', containerfile)
        self.assertIn("/out/product-migrate /product-migrate", containerfile)
        self.assertEqual(1, containerfile.count('ENTRYPOINT ["/product-api"]'))

    def test_tekton_product_release_is_supply_chain_only(self) -> None:
        pipeline_path = ROOT / "platform/tekton/pipelines/product-release.yaml"
        task_path = ROOT / "platform/tekton/tasks/product-supply-chain.yaml"
        pipeline = yaml.safe_load(pipeline_path.read_text(encoding="utf-8"))
        tasks = list(yaml.safe_load_all(task_path.read_text(encoding="utf-8")))
        source = pipeline_path.read_text(encoding="utf-8") + task_path.read_text(
            encoding="utf-8"
        )

        self.assertEqual(pipeline["metadata"]["name"], "ecommerce-product-release")
        task_names = [task["name"] for task in pipeline["spec"]["tasks"]]
        self.assertEqual(
            task_names,
            [
                "source-checkout",
                "product-gates",
                "build-push",
                "scan-sbom",
                "sign-attest",
            ],
        )
        self.assertNotIn("script:", source)
        self.assertNotIn("latest", source)
        self.assertNotIn("kubectl", source)
        commands = {
            step["command"][0] for task in tasks for step in task["spec"]["steps"]
        }
        self.assertTrue(
            {
                "python3",
                "buildctl-daemonless.sh",
                "skopeo",
                "trivy",
                "syft",
                "cosign",
            }.issubset(commands)
        )
        self.assertNotIn("buildah", commands)
        self.assertIn("govulncheck-scan", source)
        self.assertIn("vulnerability-evaluate", source)
        self.assertNotIn("cve-evaluate", source)
        self.assertIn(
            "$(params.image-repository)@$(tasks.build-push.results.image-digest)",
            source,
        )


if __name__ == "__main__":
    unittest.main()
