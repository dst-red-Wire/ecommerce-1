import subprocess
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class TektonRuntimeWiringTests(unittest.TestCase):
    def read(self, path: str) -> str:
        return (ROOT / path).read_text(encoding="utf-8")

    def test_checkout_rejects_credentials_embedded_in_repo_url(self):
        task = yaml.safe_load(self.read("platform/tekton/tasks/source-checkout.yaml"))
        steps = task["spec"]["steps"]
        guard_index = next(
            i
            for i, step in enumerate(steps)
            if step["name"] == "require-credential-free-repo-url"
        )
        origin_index = next(
            i for i, step in enumerate(steps) if step["name"] == "configure-origin"
        )
        self.assertLess(guard_index, origin_index)
        guard = steps[guard_index]
        self.assertEqual(guard["command"], ["python3", "-I", "-c"])
        for url, allowed in (
            ("https://github.com/dst-red-Wire/ecommerce-1.git", True),
            ("https://token@example.com/owner/repo.git", False),
            ("https://example.com/owner/repo.git?token=secret", False),
            ("http://example.com/owner/repo.git", False),
        ):
            with self.subTest(url=url):
                result = subprocess.run(
                    [sys.executable, "-I", "-c", guard["args"][0], url],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, allowed)
                self.assertNotIn("secret", result.stderr)
                self.assertNotIn("token@example", result.stderr)

    def test_pr_classifier_has_no_credentials_and_forces_full_gates(self):
        task = yaml.safe_load(
            self.read("platform/tekton/tasks/affected-components.yaml")
        )
        params = {entry["name"] for entry in task["spec"]["params"]}
        self.assertEqual(params, {"runner-image", "base", "head", "record-dir"})
        self.assertNotIn("volumes", task["spec"])
        step = task["spec"]["steps"][0]
        self.assertNotIn("volumeMounts", step)
        self.assertNotIn("envFrom", step)
        env = {entry["name"]: entry["value"] for entry in step["env"]}
        self.assertEqual(env["ECOMMERCE_FORCE_FULL_QUALIFICATION"], "1")
        self.assertEqual(env["CI_EVIDENCE_REPOSITORY"], "")
        self.assertEqual(env["GITEA_TOKEN"], "")
        self.assertEqual(env["GITHUB_TOKEN"], "")

    def test_pr_finalizer_cannot_publish_signed_evidence_or_remote_status(self):
        task = yaml.safe_load(self.read("platform/tekton/tasks/finalize-evidence.yaml"))
        params = {entry["name"] for entry in task["spec"]["params"]}
        self.assertEqual(params, {"runner-image", "base", "head", "record-dir"})
        self.assertNotIn("volumes", task["spec"])
        step = task["spec"]["steps"][0]
        self.assertNotIn("volumeMounts", step)
        self.assertNotIn("envFrom", step)
        env = {entry["name"]: entry["value"] for entry in step["env"]}
        for name in (
            "CI_EVIDENCE_REPOSITORY",
            "CI_EVIDENCE_COSIGN_KEY",
            "COSIGN_PASSWORD",
            "GITEA_TOKEN",
            "GITHUB_TOKEN",
        ):
            self.assertEqual(env[name], "")

    def test_affected_pipeline_has_no_secret_parameters(self):
        pipeline = yaml.safe_load(self.read("platform/tekton/pipelines/affected.yaml"))
        params = {entry["name"] for entry in pipeline["spec"]["params"]}
        self.assertEqual(
            params,
            {"runner-image", "repo-url", "base", "head", "max-workers"},
        )
        for task in pipeline["spec"]["tasks"] + pipeline["spec"]["finally"]:
            task_params = {entry["name"] for entry in task["params"]}
            self.assertTrue(
                task_params.isdisjoint(
                    {
                        "evidence-repository",
                        "evidence-signing-secret",
                        "registry-auth-secret",
                        "status-secret",
                    }
                )
            )

    def test_product_signing_uses_private_digest_sbom_without_pr_workspace(self):
        tasks = list(
            yaml.safe_load_all(
                self.read("platform/tekton/tasks/product-supply-chain.yaml")
            )
        )
        sign = next(
            task
            for task in tasks
            if task["metadata"]["name"] == "ecommerce-product-sign-attest"
        )
        self.assertNotIn("workspaces", sign["spec"])
        self.assertEqual(
            next(
                volume
                for volume in sign["spec"]["volumes"]
                if volume["name"] == "attestation"
            )["emptyDir"],
            {},
        )
        steps = {step["name"]: step for step in sign["spec"]["steps"]}
        syft = steps["generate-attestation-sbom"]
        self.assertEqual(syft["command"], ["syft"])
        self.assertIn("$(params.image-reference)", syft["args"])
        self.assertNotIn(
            "signing-key", {mount["name"] for mount in syft["volumeMounts"]}
        )
        attest = steps["attest-sbom"]
        self.assertIn("/var/run/attestation/sbom.spdx.json", attest["args"])
        self.assertNotIn(".context/", " ".join(attest["args"]))
        pipeline = yaml.safe_load(
            self.read("platform/tekton/pipelines/product-release.yaml")
        )
        sign_call = next(
            task for task in pipeline["spec"]["tasks"] if task["name"] == "sign-attest"
        )
        self.assertNotIn("workspaces", sign_call)
        self.assertIn("syft-image", {param["name"] for param in sign_call["params"]})

    def test_legacy_runtime_proof_blocks_before_cluster_access(self):
        playbook = yaml.safe_load(self.read("platform/ansible/tekton-proof.yml"))[0]
        pre_tasks = playbook["pre_tasks"]
        guard_index = next(
            i for i, task in enumerate(pre_tasks) if "ansible.builtin.fail" in task
        )
        guard = pre_tasks[guard_index]
        self.assertIn("BLOCKED_POLICY", guard["ansible.builtin.fail"]["msg"])
        checks_before_guard = str(pre_tasks[:guard_index])
        self.assertIn("proof_base_sha", checks_before_guard)
        self.assertIn("proof_parent_sha", checks_before_guard)
        self.assertIn("proof_head_sha", checks_before_guard)
        self.assertNotIn("kubernetes.core.", checks_before_guard)
        self.assertLess(
            guard_index,
            next(
                i
                for i, task in enumerate(pre_tasks)
                if "kubernetes.core.k8s_info" in task
            ),
        )

    def test_documented_invocation_includes_exact_parent_sha(self):
        doc = self.read("docs/project/TEKTON_RUNTIME_PROOF.md")
        self.assertIn("PARENT_SHA=<full-parent-sha>", doc)
        self.assertIn("BASE_SHA -> PARENT_SHA -> HEAD_SHA", doc)
        normalized_doc = " ".join(doc.split())
        self.assertIn("retries require no manual resource deletion", normalized_doc)
        self.assertIn("BLOCKED_POLICY", doc)

    def test_make_exposes_one_thin_runtime_proof_launcher(self):
        makefile = self.read("Makefile")
        repoctl = self.read("scripts/repoctl.py")
        self.assertIn("tekton-proof:", makefile)
        self.assertIn("scripts/repoctl.py tekton-proof", makefile)
        self.assertIn("platform/ansible/tekton-proof.yml", repoctl)
        self.assertIn("BASE_SHA", makefile)
        self.assertIn("PARENT_SHA", makefile)
        self.assertIn("HEAD_SHA", makefile)
        self.assertIn("RUNTIME_CONFIG", makefile)


if __name__ == "__main__":
    unittest.main()
