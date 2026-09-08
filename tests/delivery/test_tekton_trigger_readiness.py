from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "tekton_trigger_readiness.py"
spec = importlib.util.spec_from_file_location("tekton_trigger_readiness", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class FakeExecutor:
    def __init__(self, *, missing_crd: bool = False, missing_quota: bool = False, runner_resources: bool = True):
        self.commands: list[list[str]] = []
        self.missing_crd = missing_crd
        self.missing_quota = missing_quota
        self.runner_resources = runner_resources
        self.runner = "harbor.internal/ecommerce/ci-runner@sha256:" + "a" * 64

    def done(self, cmd: list[str], code: int = 0, out: str = "", err: str = ""):
        return subprocess.CompletedProcess(cmd, code, stdout=out, stderr=err)

    def __call__(self, cmd: list[str]):
        self.commands.append(cmd)
        if cmd[:2] == ["kustomize", "build"]:
            return self.done(cmd, out="apiVersion: tekton.dev/v1\nkind: Pipeline\n")
        if cmd[:3] != ["kubectl", "--context", "mgmt"]:
            return self.done(cmd, 1, err="unexpected command")
        args = cmd[3:]
        if args[:3] == ["auth", "can-i", "*"]:
            return self.done(cmd, out="no\n")
        if args[:3] == ["auth", "can-i", "create"]:
            resource = args[3]
            if resource == "clusterrolebindings.rbac.authorization.k8s.io":
                return self.done(cmd, out="no\n")
            if resource == "pipelineruns.tekton.dev":
                return self.done(cmd, out="yes\n")
        if args[:2] == ["get", "crd"]:
            name = args[2]
            if self.missing_crd and name.startswith("eventlisteners"):
                return self.done(cmd, 1, err="NotFound")
            return self.done(cmd, out=json.dumps({"spec": {"versions": [{"name": "v1beta1", "served": True}]}}))
        if args[:2] == ["get", "namespace"]:
            return self.done(cmd, out=json.dumps({"status": {"phase": "Active"}}))
        if args[:2] == ["get", "serviceaccount"]:
            return self.done(cmd, out=json.dumps({"metadata": {"name": args[2]}}))
        if args[:3] == ["get", "resourcequota", "ci-budget"]:
            if self.missing_quota:
                return self.done(cmd, 1, err="NotFound")
            return self.done(
                cmd,
                out=json.dumps(
                    {
                        "status": {
                            "hard": {
                                "requests.cpu": "4",
                                "requests.memory": "8Gi",
                                "limits.cpu": "8",
                                "limits.memory": "16Gi",
                            }
                        }
                    }
                ),
            )
        if args[:3] == ["get", "pod", "runner-proof"]:
            resources = (
                {
                    "requests": {"cpu": "250m", "memory": "256Mi"},
                    "limits": {"cpu": "1", "memory": "1Gi"},
                }
                if self.runner_resources
                else {}
            )
            return self.done(
                cmd,
                out=json.dumps(
                    {
                        "metadata": {"annotations": {"ecommerce-1.io/readiness-proof": "runner-image-pull"}},
                        "spec": {"containers": [{"name": "runner", "image": self.runner, "resources": resources}]},
                        "status": {
                            "phase": "Succeeded",
                            "containerStatuses": [
                                {
                                    "name": "runner",
                                    "imageID": "docker-pullable://harbor.internal/ecommerce/ci-runner@sha256:"
                                    + "a" * 64,
                                }
                            ],
                        },
                    }
                ),
            )
        if args[:3] == ["get", "pod", "network-proof"]:
            return self.done(
                cmd,
                out=json.dumps(
                    {
                        "metadata": {
                            "annotations": {
                                "ecommerce-1.io/readiness-proof": "network-egress",
                                "ecommerce-1.io/readiness-targets": "gitea,harbor,kubernetes-api",
                            }
                        },
                        "status": {"phase": "Succeeded"},
                    }
                ),
            )
        if args[:2] == ["get", "externalsecrets.external-secrets.io"]:
            return self.done(
                cmd,
                out=json.dumps(
                    {
                        "spec": {
                            "target": {"name": "webhook-signing"},
                            "secretStoreRef": {"name": "openbao", "kind": "SecretStore"},
                        },
                        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
                    }
                ),
            )
        if args[:2] == ["get", "secretstores.external-secrets.io"]:
            return self.done(
                cmd, out=json.dumps({"spec": {"provider": {"vault": {"server": "https://openbao.internal"}}}})
            )
        if args[:3] == ["get", "secret", "webhook-signing"]:
            return self.done(cmd, out=json.dumps({"data": {"hmac": "SUPERSECRET"}}))
        if args[:2] == ["get", "ingress.networking.k8s.io"]:
            return self.done(
                cmd,
                out=json.dumps(
                    {
                        "spec": {
                            "tls": [{"secretName": "trigger-tls"}],
                            "rules": [{"http": {"paths": [{"backend": {"service": {"name": "el-gitea"}}}]}}],
                        }
                    }
                ),
            )
        if args[:2] == ["get", "networkpolicy.networking.k8s.io"]:
            return self.done(
                cmd,
                out=json.dumps(
                    {"spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}}
                ),
            )
        return self.done(cmd, 1, err="unhandled fake kubectl call")


class TektonTriggerReadinessTests(unittest.TestCase):
    def runtime_config(self):
        return {
            "kube_context": "mgmt",
            "namespace": "ecommerce-ci-trigger",
            "runner_image": "harbor.internal/ecommerce/ci-runner@sha256:" + "a" * 64,
            "event_listener_service_account": "tekton-eventlistener",
            "pipeline_service_account": "tekton-pipeline",
            "execution_budget": {
                "resource_quota_name": "ci-budget",
            },
            "webhook": {
                "external_secret_name": "gitea-webhook-signing",
                "secret_name": "webhook-signing",
                "secret_key": "hmac",
            },
            "network": {
                "ingress_name": "gitea-tekton",
                "event_listener_service": "el-gitea",
                "tls_secret_name": "trigger-tls",
                "default_deny_policy": "default-deny",
            },
            "proofs": {
                "runner_pull_pod": "runner-proof",
                "network_probe_pod": "network-proof",
            },
        }

    def test_mutable_runner_image_is_rejected(self):
        config = self.runtime_config()
        config["runner_image"] = "harbor.internal/ecommerce/ci-runner:latest"
        with self.assertRaisesRegex(ValueError, "immutable"):
            module.validate_runtime_config(config)

    def test_all_seven_live_proofs_pass_and_evidence_is_redacted(self):
        fake = FakeExecutor()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "platform" / "tekton").mkdir(parents=True)
            evidence = root / ".context" / "runtime" / "readiness.json"
            rc = module.run_readiness(root, self.runtime_config(), evidence, executor=fake)
            self.assertEqual(0, rc)
            data = json.loads(evidence.read_text())
            self.assertEqual("PASS", data["status"])
            self.assertEqual(7, len(data["proofs"]))
            self.assertTrue(all(p["status"] == "PASS" for p in data["proofs"].values()))
            self.assertFalse(data["mutation_performed"])
            self.assertNotIn("SUPERSECRET", evidence.read_text())

            contract = (ROOT / "config" / "contracts" / "tekton-trigger-runtime.yaml").read_text(encoding="utf-8")
            proof_block = contract.split("  required_proofs:\n", 1)[1].split("  static_contract_is_runtime_proof:", 1)[
                0
            ]
            required = [line.strip()[2:] for line in proof_block.splitlines() if line.strip().startswith("- ")]
            self.assertEqual(set(required), set(data["proofs"]))

        forbidden = module.FORBIDDEN_MUTATING_KUBECTL
        for cmd in fake.commands:
            if cmd and cmd[0] == "kubectl":
                self.assertNotIn(cmd[3], forbidden, cmd)

    def test_missing_live_proof_returns_blocked_not_pass(self):
        fake = FakeExecutor(missing_crd=True)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "platform" / "tekton").mkdir(parents=True)
            evidence = root / "readiness.json"
            rc = module.run_readiness(root, self.runtime_config(), evidence, executor=fake)
            self.assertEqual(module.BLOCKED_EXIT, rc)
            data = json.loads(evidence.read_text())
            self.assertEqual("BLOCKED", data["status"])
            self.assertEqual("BLOCKED", data["proofs"]["triggers-crds-present"]["status"])

    def test_missing_execution_budget_proof_returns_blocked_not_pass(self):
        fake = FakeExecutor(missing_quota=True)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "platform" / "tekton").mkdir(parents=True)
            evidence = root / "readiness.json"
            rc = module.run_readiness(root, self.runtime_config(), evidence, executor=fake)
            self.assertEqual(module.BLOCKED_EXIT, rc)
            data = json.loads(evidence.read_text())
            self.assertEqual("BLOCKED", data["status"])
            self.assertEqual("BLOCKED", data["proofs"]["bounded-execution-budget-proven"]["status"])

    def test_runner_without_resources_blocks_execution_budget_proof(self):
        fake = FakeExecutor(runner_resources=False)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "platform" / "tekton").mkdir(parents=True)
            evidence = root / "readiness.json"
            rc = module.run_readiness(root, self.runtime_config(), evidence, executor=fake)
            self.assertEqual(module.BLOCKED_EXIT, rc)
            data = json.loads(evidence.read_text())
            self.assertEqual("BLOCKED", data["proofs"]["bounded-execution-budget-proven"]["status"])

    def test_static_render_is_kustomize_only_and_no_helm_is_invented(self):
        fake = FakeExecutor()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "platform" / "tekton").mkdir(parents=True)
            module.run_readiness(root, self.runtime_config(), root / "evidence.json", executor=fake)
        self.assertTrue(any(cmd[:2] == ["kustomize", "build"] for cmd in fake.commands))
        self.assertFalse(any(cmd and cmd[0] == "helm" for cmd in fake.commands))

    def test_runtime_config_is_one_non_secret_input_document(self):
        config = module.validate_runtime_config(self.runtime_config())
        self.assertEqual("mgmt", config["kube_context"])
        self.assertEqual("ecommerce-ci-trigger", config["namespace"])
        self.assertNotIn("secret_value", json.dumps(config))

    def test_repository_wiring_keeps_readiness_explicit_and_out_of_normal_ci(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        repoctl = (ROOT / "scripts" / "repoctl.py").read_text(encoding="utf-8")
        contract = (ROOT / "config" / "contracts" / "tekton-trigger-runtime.yaml").read_text(encoding="utf-8")
        self.assertIn("tekton-trigger-readiness:", makefile)
        self.assertIn("--runtime-config", makefile)
        self.assertIn('sub.add_parser("tekton-trigger-readiness")', repoctl)
        self.assertIn("readiness_gate:", contract)
        self.assertIn("mode: read-only", contract)
        self.assertIn("blocked_exit_code: 3", contract)
        ci_head = makefile.split("ci:", 1)[1].split("ci-full:", 1)[0]
        self.assertNotIn("tekton-trigger-readiness", ci_head)


if __name__ == "__main__":
    unittest.main()
