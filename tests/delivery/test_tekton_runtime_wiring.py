from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TektonRuntimeWiringTests(unittest.TestCase):
    def read(self, path: str) -> str:
        return (ROOT / path).read_text(encoding="utf-8")

    def test_classifier_can_fetch_authenticated_parent_evidence(self):
        task = self.read("platform/tekton/tasks/affected-components.yaml")
        self.assertIn("name: evidence-repository", task)
        self.assertIn("name: evidence-signing-secret", task)
        self.assertIn("name: registry-auth-secret", task)
        self.assertIn("name: CI_EVIDENCE_REPOSITORY", task)
        self.assertIn("name: CI_EVIDENCE_COSIGN_PUBLIC_KEY", task)
        self.assertIn("/var/run/ecommerce-evidence/cosign.pub", task)
        self.assertIn("key: .dockerconfigjson", task)
        self.assertIn("path: config.json", task)
        self.assertIn("mountPath: /tekton/home/.docker", task)
        self.assertIn("name: HOME", task)

    def test_finalizer_signs_publishes_and_exports_exact_status(self):
        task = self.read("platform/tekton/tasks/finalize-evidence.yaml")
        self.assertIn("name: CI_EVIDENCE_REPOSITORY", task)
        self.assertIn("name: CI_EVIDENCE_COSIGN_KEY", task)
        self.assertIn("name: COSIGN_PASSWORD", task)
        self.assertIn("name: status-secret", task)
        self.assertIn("envFrom:", task)
        self.assertIn("name: $(params.status-secret)", task)
        self.assertIn("key: .dockerconfigjson", task)
        self.assertIn("mountPath: /tekton/home/.docker", task)
        self.assertIn("name: HOME", task)
        self.assertNotIn("GITHUB_TOKEN: ", task)
        self.assertNotIn("GITEA_TOKEN: ", task)

    def test_pipeline_passes_runtime_auth_only_to_the_tasks_that_need_it(self):
        pipeline = self.read("platform/tekton/pipelines/affected.yaml")
        for name in ("evidence-repository", "evidence-signing-secret", "registry-auth-secret", "status-secret"):
            self.assertIn(f"name: {name}", pipeline)
        classify = pipeline.split("- name: classify", 1)[1].split("- name: global-gates", 1)[0]
        self.assertIn("evidence-repository", classify)
        self.assertIn("evidence-signing-secret", classify)
        self.assertIn("registry-auth-secret", classify)
        self.assertNotIn("status-secret", classify)
        finalizer = pipeline.split("- name: finalize-evidence", 1)[1]
        self.assertIn("status-secret", finalizer)

    def test_runtime_proof_is_ansible_owned_and_exact_sha_bound(self):
        playbook = self.read("platform/ansible/tekton-proof.yml")
        self.assertIn("kubernetes.core.k8s:", playbook)
        self.assertIn("kubernetes.core.k8s_info:", playbook)
        self.assertIn("proof_base_sha", playbook)
        self.assertIn("proof_parent_sha", playbook)
        self.assertIn("proof_head_sha", playbook)
        self.assertIn("proof_head_parents", playbook)
        self.assertIn("proof_parent_parents", playbook)
        self.assertIn("rev-list", playbook)
        self.assertIn("difference(['Task', 'Pipeline'])", playbook)
        self.assertIn("ecommerce-proof-parent-", playbook)
        self.assertIn("ecommerce-proof-child-", playbook)
        self.assertIn("kubernetes.core.k8s_exec:", playbook)
        self.assertIn("evidence-fetch --sha", playbook)
        self.assertIn("service:product", playbook)
        self.assertIn("reused_from_sha", playbook)
        self.assertIn("kustomize", playbook)
        self.assertNotIn("ansible.builtin.shell", playbook)
        self.assertNotIn("kubectl apply", playbook)
        self.assertNotIn("force", playbook.lower())
        self.assertIn("'GITEA_REPOSITORY' not in", playbook)
        self.assertIn("'GITEA_TOKEN' not in", playbook)
        self.assertIn("'GITHUB_TOKEN' not in", playbook)

    def test_runtime_proof_recovery_is_exact_and_automation_owned(self):
        playbook = self.read("platform/ansible/tekton-proof.yml")
        self.assertIn("ecommerce-1.io/proof-controller", playbook)
        self.assertIn("Recycle only a failed automation-owned exact parent proof run", playbook)
        self.assertIn("Recycle only a failed automation-owned exact child proof run", playbook)
        self.assertIn("Require any existing parent proof run to be automation-owned and exact", playbook)
        self.assertIn("Require any existing child proof run to be automation-owned and exact", playbook)
        self.assertIn("Remove only an automation-owned stale verifier Pod before a clean retry", playbook)
        self.assertIn("wait_timeout: 120", playbook)
        self.assertIn("status.conditions[0].status == 'False'", playbook)

    def test_documented_invocation_includes_exact_parent_sha(self):
        doc = self.read("docs/project/TEKTON_RUNTIME_PROOF.md")
        self.assertIn("PARENT_SHA=<full-parent-sha>", doc)
        self.assertIn("BASE_SHA -> PARENT_SHA -> HEAD_SHA", doc)
        normalized_doc = " ".join(doc.split())
        self.assertIn("retries require no manual resource deletion", normalized_doc)

    def test_make_exposes_one_thin_runtime_proof_launcher(self):
        makefile = self.read("Makefile")
        self.assertIn("tekton-proof:", makefile)
        self.assertIn("platform/ansible/tekton-proof.yml", makefile)
        self.assertIn("BASE_SHA", makefile)
        self.assertIn("PARENT_SHA", makefile)
        self.assertIn("HEAD_SHA", makefile)
        self.assertIn("RUNTIME_CONFIG", makefile)


if __name__ == "__main__":
    unittest.main()
