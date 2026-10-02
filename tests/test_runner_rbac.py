from __future__ import annotations

import importlib.util
import json
import subprocess
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "runner_rbac", ROOT / "scripts" / "runner_rbac.py"
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

NAMESPACE = "ecommerce-runner"
OTHER_NAMESPACE = "default"


def role(name: str, rules: list[dict], *, namespace: str = NAMESPACE) -> dict:
    return {"metadata": {"name": name, "namespace": namespace}, "rules": rules}


def binding(
    name: str, role_name: str, subject: str, *, namespace: str = NAMESPACE
) -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": role_name,
        },
        "subjects": [
            {"kind": "ServiceAccount", "name": subject, "namespace": NAMESPACE}
        ],
    }


def add_tekton_info(fake: FakeKubectl) -> None:
    labels = {
        "app.kubernetes.io/instance": "default",
        "app.kubernetes.io/part-of": "tekton-pipelines",
    }
    fake.roles.append(
        {
            "metadata": {
                "name": "tekton-pipelines-info",
                "namespace": "tekton-pipelines",
                "labels": labels.copy(),
            },
            "rules": [
                {
                    "apiGroups": [""],
                    "resourceNames": ["pipelines-info"],
                    "resources": ["configmaps"],
                    "verbs": ["get"],
                }
            ],
        }
    )
    fake.rolebindings.append(
        {
            "metadata": {
                "name": "tekton-pipelines-info",
                "namespace": "tekton-pipelines",
                "labels": labels.copy(),
            },
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "tekton-pipelines-info",
            },
            "subjects": [
                {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Group",
                    "name": "system:authenticated",
                }
            ],
        }
    )


def add_cluster_trust_bundle_default(fake: FakeKubectl) -> None:
    labels = {"kubernetes.io/bootstrapping": "rbac-defaults"}
    name = "system:cluster-trust-bundle-discovery"
    fake.clusterroles.append(
        {
            "metadata": {"name": name, "labels": labels.copy()},
            "rules": [
                {
                    "apiGroups": ["certificates.k8s.io"],
                    "resources": ["clustertrustbundles"],
                    "verbs": ["get", "list", "watch"],
                }
            ],
        }
    )
    fake.clusterrolebindings.append(
        {
            "metadata": {"name": name, "labels": labels.copy()},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": name,
            },
            "subjects": [
                {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Group",
                    "name": "system:serviceaccounts",
                }
            ],
        }
    )


class FakeKubectl:
    def __init__(self):
        self.commands: list[list[str]] = []
        self.roles = [
            role(
                "runner-authority-pipelineruns",
                [
                    {
                        "apiGroups": ["tekton.dev"],
                        "resources": ["pipelineruns"],
                        "verbs": ["create", "get", "list", "watch"],
                    }
                ],
            )
        ]
        self.rolebindings = [
            binding(
                "runner-authority-pipelineruns",
                "runner-authority-pipelineruns",
                "runner-authority",
            )
        ]
        self.clusterroles: list[dict] = []
        self.clusterrolebindings: list[dict] = []
        self.overrides: dict[tuple[str, str, str, str], bool] = {}
        self.error_kind: str | None = None
        self.bad_auth_response = False
        self.automount = {"runner-authority": True, "runner-workload": False}
        self.workload_secrets: list[dict] = []
        self.workload_image_pull_secrets: list[dict] = []
        self.pipeline_runs: list[dict] = []
        self.task_runs: list[dict] = []

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if command[:3] != ["kubectl", "--context", "mgmt"]:
            return subprocess.CompletedProcess(command, 1, "", "wrong context")
        args = command[3:]
        if args[:2] == ["auth", "can-i"]:
            if self.bad_auth_response:
                return subprocess.CompletedProcess(command, 0, "maybe\n", "")
            verb, resource, subject, namespace = args[2], args[3], args[5], args[7]
            name = subject.rsplit(":", 1)[-1]
            allowed = (
                name == "runner-authority"
                and namespace == NAMESPACE
                and (verb, resource) in module.REQUIRED
            )
            allowed = self.overrides.get((name, verb, resource, namespace), allowed)
            return subprocess.CompletedProcess(
                command, 0 if allowed else 1, "yes\n" if allowed else "no\n", ""
            )
        if args[0] != "get":
            return subprocess.CompletedProcess(command, 1, "", "mutation attempted")
        kind = args[1]
        if kind == self.error_kind:
            return subprocess.CompletedProcess(command, 1, "", "forbidden")
        if kind == "serviceaccount":
            name = args[2]
            doc = {
                "metadata": {
                    "name": name,
                    "namespace": NAMESPACE,
                    "uid": f"uid-{name}",
                },
                "automountServiceAccountToken": self.automount[name],
                "secrets": self.workload_secrets if name == "runner-workload" else None,
                "imagePullSecrets": self.workload_image_pull_secrets
                if name == "runner-workload"
                else None,
            }
        else:
            values = {
                "roles": self.roles,
                "rolebindings": self.rolebindings,
                "clusterroles": self.clusterroles,
                "clusterrolebindings": self.clusterrolebindings,
                "pipelineruns.tekton.dev": self.pipeline_runs,
                "taskruns.tekton.dev": self.task_runs,
            }
            doc = {"items": values[kind], "metadata": {}}
        return subprocess.CompletedProcess(command, 0, json.dumps(doc), "")


def assess(fake: FakeKubectl) -> dict:
    return module.verify_rbac("mgmt", NAMESPACE, executor=fake)


class RunnerRbacTests(unittest.TestCase):
    def test_live_matrix_and_inventory_pass_without_mutation_or_formal_proof(self):
        fake = FakeKubectl()
        fake.clusterroles.append(
            {
                "metadata": {"name": "system:basic-user"},
                "rules": [
                    {
                        "apiGroups": ["authorization.k8s.io"],
                        "resources": ["selfsubjectaccessreviews"],
                        "verbs": ["create"],
                    }
                ],
            }
        )
        fake.clusterrolebindings.append(
            {
                "metadata": {"name": "system:basic-user"},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "system:basic-user",
                },
                "subjects": [{"kind": "Group", "name": "system:authenticated"}],
            }
        )
        result = assess(fake)
        self.assertEqual(module.PASS, result["assessment"], result.get("detail"))
        self.assertFalse(result["formal_proof"])
        self.assertFalse(result["mutation_performed"])
        self.assertFalse(result["workload_execution_observed"])
        self.assertEqual("NOT_OBSERVED", result["workload_execution"]["status"])
        self.assertEqual(
            ["WORKLOAD_EXECUTION_NOT_OBSERVED"], result["formal_proof_blockers"]
        )
        self.assertEqual(
            {"runner-authority", "runner-workload"}, set(result["service_account_uids"])
        )
        observed = {
            (c["subject"], c["verb"], c["resource"], c["namespace"], c["observed"])
            for c in result["checks"]
        }
        self.assertIn(
            (
                "runner-authority",
                "create",
                "pipelineruns.tekton.dev",
                NAMESPACE,
                "ALLOWED",
            ),
            observed,
        )
        self.assertIn(
            ("runner-authority", "get", "secrets", NAMESPACE, "DENIED"), observed
        )
        self.assertIn(
            (
                "runner-workload",
                "create",
                "pipelineruns.tekton.dev",
                NAMESPACE,
                "DENIED",
            ),
            observed,
        )
        self.assertIn(
            (
                "runner-authority",
                "create",
                "pipelineruns.tekton.dev",
                OTHER_NAMESPACE,
                "DENIED",
            ),
            observed,
        )
        for command in fake.commands:
            self.assertEqual("kubectl", command[0])
            self.assertTrue(
                command[3] == "get" or command[3:5] == ["auth", "can-i"], command
            )
            if command[3:5] == ["auth", "can-i"]:
                self.assertIn("system:authenticated", command)
                self.assertIn("system:serviceaccounts", command)
                self.assertIn(f"system:serviceaccounts:{NAMESPACE}", command)

    def test_exact_tekton_info_read_is_accepted_as_builtin_baseline(self):
        fake = FakeKubectl()
        add_tekton_info(fake)
        result = assess(fake)
        self.assertEqual(module.PASS, result["assessment"], result.get("detail"))
        self.assertIn(
            "tekton-pipelines/tekton-pipelines-info->tekton-pipelines-info",
            result["bindings_inspected"],
        )

    def test_tekton_info_exception_rejects_broader_rule_or_different_binding(self):
        def change_verbs(fake):
            fake.roles[-1]["rules"][0]["verbs"].append("list")

        def change_resources(fake):
            fake.roles[-1]["rules"][0]["resources"].append("secrets")

        def change_resource_names(fake):
            fake.roles[-1]["rules"][0]["resourceNames"].append("other")

        def remove_resource_name(fake):
            del fake.roles[-1]["rules"][0]["resourceNames"]

        def change_binding_name(fake):
            fake.rolebindings[-1]["metadata"]["name"] = "other-tekton-info"

        def change_namespace(fake):
            fake.rolebindings[-1]["metadata"]["namespace"] = "other-tekton"
            fake.roles[-1]["metadata"]["namespace"] = "other-tekton"

        def change_subject(fake):
            fake.rolebindings[-1]["subjects"][0]["name"] = "system:serviceaccounts"

        def remove_release_label(fake):
            del fake.rolebindings[-1]["metadata"]["labels"]["app.kubernetes.io/part-of"]

        for name, mutate in (
            ("verbs", change_verbs),
            ("resources", change_resources),
            ("resourceNames", change_resource_names),
            ("missing resourceName", remove_resource_name),
            ("binding name", change_binding_name),
            ("namespace", change_namespace),
            ("subject", change_subject),
            ("release label", remove_release_label),
        ):
            with self.subTest(case=name):
                fake = FakeKubectl()
                add_tekton_info(fake)
                mutate(fake)
                result = assess(fake)
                self.assertEqual(
                    module.FAIL_POLICY, result["assessment"], result.get("detail")
                )
                self.assertIn("excessive RBAC rule", result["detail"])

    def test_safe_discovery_url_accepts_single_trailing_slash_only(self):
        rule = {
            "nonResourceURLs": [
                "/.well-known/openid-configuration",
                "/.well-known/openid-configuration/",
                "/openid/v1/jwks",
                "/openid/v1/jwks/",
            ],
            "verbs": ["get"],
        }
        self.assertTrue(module._safe_baseline_rule(rule))
        for unsafe in ("/metrics", "/openid/v1/jwks//", "/openid/v1/jwks/secret"):
            with self.subTest(url=unsafe):
                changed = deepcopy(rule)
                changed["nonResourceURLs"].append(unsafe)
                self.assertFalse(module._safe_baseline_rule(changed))

    def test_exact_kubernetes_cluster_trust_bundle_default_is_accepted(self):
        fake = FakeKubectl()
        add_cluster_trust_bundle_default(fake)
        result = assess(fake)
        self.assertEqual(module.PASS, result["assessment"], result.get("detail"))
        self.assertIn(
            "cluster/system:cluster-trust-bundle-discovery->system:cluster-trust-bundle-discovery",
            result["bindings_inspected"],
        )

    def test_cluster_trust_bundle_default_rejects_broader_or_different_binding(self):
        def add_verb(fake):
            fake.clusterroles[-1]["rules"][0]["verbs"].append("patch")

        def add_resource(fake):
            fake.clusterroles[-1]["rules"][0]["resources"].append("secrets")

        def add_resource_name(fake):
            fake.clusterroles[-1]["rules"][0]["resourceNames"] = ["other"]

        def change_name(fake):
            fake.clusterrolebindings[-1]["metadata"]["name"] = "other"

        def change_subject(fake):
            fake.clusterrolebindings[-1]["subjects"][0]["name"] = "system:authenticated"

        def remove_bootstrap_label(fake):
            del fake.clusterroles[-1]["metadata"]["labels"][
                "kubernetes.io/bootstrapping"
            ]

        for name, mutate in (
            ("verb", add_verb),
            ("resource", add_resource),
            ("resourceName", add_resource_name),
            ("binding name", change_name),
            ("subject", change_subject),
            ("bootstrap label", remove_bootstrap_label),
        ):
            with self.subTest(case=name):
                fake = FakeKubectl()
                add_cluster_trust_bundle_default(fake)
                mutate(fake)
                result = assess(fake)
                self.assertEqual(
                    module.FAIL_POLICY, result["assessment"], result.get("detail")
                )

    def test_duplicate_tekton_info_binding_is_not_accepted(self):
        fake = FakeKubectl()
        add_tekton_info(fake)
        duplicate = deepcopy(fake.rolebindings[-1])
        duplicate["metadata"]["name"] = "tekton-pipelines-info-copy"
        fake.rolebindings.append(duplicate)
        result = assess(fake)
        self.assertEqual(module.FAIL_POLICY, result["assessment"])

    def test_missing_required_operation_fails_closed(self):
        fake = FakeKubectl()
        fake.overrides[
            ("runner-authority", "create", "pipelineruns.tekton.dev", NAMESPACE)
        ] = False
        result = assess(fake)
        self.assertEqual(module.FAIL_POLICY, result["assessment"])
        self.assertIn("expected ALLOWED", result["detail"])

    def test_sensitive_permissions_are_denied_for_both_identities(self):
        cases = [
            ("get", "secrets", NAMESPACE),
            ("create", "pods", NAMESPACE),
            ("create", "clusterroles.rbac.authorization.k8s.io", NAMESPACE),
            ("create", "clusterrolebindings.rbac.authorization.k8s.io", NAMESPACE),
            (
                "patch",
                "validatingwebhookconfigurations.admissionregistration.k8s.io",
                NAMESPACE,
            ),
            ("create", "pipelineruns.tekton.dev", OTHER_NAMESPACE),
            ("patch", "secrets", OTHER_NAMESPACE),
        ]
        for account in ("runner-authority", "runner-workload"):
            for verb, resource, namespace in cases:
                with self.subTest(
                    account=account, verb=verb, resource=resource, namespace=namespace
                ):
                    fake = FakeKubectl()
                    fake.overrides[(account, verb, resource, namespace)] = True
                    result = assess(fake)
                    self.assertEqual(module.FAIL_POLICY, result["assessment"])
                    self.assertIn("expected DENIED", result["detail"])

    def test_workload_token_automount_is_forbidden(self):
        fake = FakeKubectl()
        fake.automount["runner-workload"] = True
        result = assess(fake)
        self.assertEqual(module.FAIL_POLICY, result["assessment"])
        self.assertIn("automountServiceAccountToken", result["detail"])

    def test_workload_service_account_has_no_attached_credentials(self):
        for attribute, field in (
            ("workload_secrets", "secrets"),
            ("workload_image_pull_secrets", "imagePullSecrets"),
        ):
            with self.subTest(field=field):
                fake = FakeKubectl()
                setattr(fake, attribute, [{"name": "credential"}])
                result = assess(fake)
                self.assertEqual(module.FAIL_POLICY, result["assessment"])
                self.assertIn(field, result["detail"])

    def test_observed_pipeline_and_task_runs_use_workload_identity(self):
        fake = FakeKubectl()
        fake.pipeline_runs.append(
            {
                "metadata": {"name": "qualified-head", "namespace": NAMESPACE},
                "spec": {"taskRunTemplate": {"serviceAccountName": "runner-workload"}},
            }
        )
        fake.task_runs.append(
            {
                "metadata": {"name": "qualified-head-step", "namespace": NAMESPACE},
                "spec": {"serviceAccountName": "runner-workload"},
            }
        )
        result = assess(fake)
        self.assertEqual(module.PASS, result["assessment"], result.get("detail"))
        self.assertTrue(result["workload_execution_observed"])
        self.assertEqual("OBSERVED", result["workload_execution"]["status"])
        self.assertEqual([], result["formal_proof_blockers"])
        self.assertFalse(result["formal_proof"])

    def test_tekton_run_cannot_use_or_override_trusted_identity(self):
        cases = [
            (
                "pipeline default",
                {
                    "metadata": {"name": "bad", "namespace": NAMESPACE},
                    "spec": {
                        "taskRunTemplate": {"serviceAccountName": "runner-authority"}
                    },
                },
                None,
            ),
            (
                "pipeline override",
                {
                    "metadata": {"name": "bad", "namespace": NAMESPACE},
                    "spec": {
                        "taskRunTemplate": {"serviceAccountName": "runner-workload"},
                        "taskRunSpecs": [{"serviceAccountName": "runner-authority"}],
                    },
                },
                None,
            ),
            (
                "task",
                None,
                {
                    "metadata": {"name": "bad", "namespace": NAMESPACE},
                    "spec": {"serviceAccountName": "runner-authority"},
                },
            ),
        ]
        for label, pipeline, task in cases:
            with self.subTest(case=label):
                fake = FakeKubectl()
                if pipeline:
                    fake.pipeline_runs.append(pipeline)
                if task:
                    fake.task_runs.append(task)
                result = assess(fake)
                self.assertEqual(module.FAIL_POLICY, result["assessment"])
                self.assertIn("ServiceAccount", result["detail"])

    def test_unreadable_run_inventory_does_not_claim_execution_proof(self):
        fake = FakeKubectl()
        fake.error_kind = "taskruns.tekton.dev"
        result = assess(fake)
        self.assertEqual(module.PASS, result["assessment"])
        self.assertFalse(result["workload_execution_observed"])
        self.assertEqual("UNAVAILABLE", result["workload_execution"]["status"])
        self.assertEqual(
            ["WORKLOAD_EXECUTION_INVENTORY_UNAVAILABLE"],
            result["formal_proof_blockers"],
        )

    def test_excessive_direct_and_inherited_rules_fail_even_when_can_i_matrix_is_clean(
        self,
    ):
        cases = [
            {"apiGroups": ["tekton.dev"], "resources": ["*"], "verbs": ["create"]},
            {
                "apiGroups": ["tekton.dev"],
                "resources": ["pipelineruns"],
                "verbs": ["*"],
            },
            {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]},
            {
                "apiGroups": ["tekton.dev"],
                "resources": ["pipelineruns"],
                "verbs": ["delete"],
            },
        ]
        for extra in cases:
            with self.subTest(rule=extra):
                fake = FakeKubectl()
                fake.roles[0]["rules"].append(extra)
                result = assess(fake)
                self.assertEqual(module.FAIL_POLICY, result["assessment"])
                self.assertIn("excessive RBAC rule", result["detail"])

        fake = FakeKubectl()
        fake.clusterroles.append(
            {
                "metadata": {"name": "bad-authenticated"},
                "rules": [
                    {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}
                ],
            }
        )
        fake.clusterrolebindings.append(
            {
                "metadata": {"name": "bad-authenticated"},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "bad-authenticated",
                },
                "subjects": [{"kind": "Group", "name": "system:authenticated"}],
            }
        )
        self.assertEqual(module.FAIL_POLICY, assess(fake)["assessment"])

    def test_malformed_bound_rule_fails_closed(self):
        fake = FakeKubectl()
        fake.roles[0]["rules"].append(
            {"apiGroups": ["tekton.dev"], "resources": ["pipelineruns"], "verbs": [{}]}
        )
        result = assess(fake)
        self.assertEqual(module.FAIL_POLICY, result["assessment"])

    def test_cross_namespace_binding_fails_even_if_it_grants_only_required_verbs(self):
        fake = FakeKubectl()
        fake.roles.append(
            role("external", fake.roles[0]["rules"], namespace=OTHER_NAMESPACE)
        )
        fake.rolebindings.append(
            binding(
                "external", "external", "runner-authority", namespace=OTHER_NAMESPACE
            )
        )
        result = assess(fake)
        self.assertEqual(module.FAIL_POLICY, result["assessment"])
        self.assertIn("outside dedicated namespace", result["detail"])

    def test_cluster_wide_direct_binding_fails(self):
        fake = FakeKubectl()
        fake.clusterroles.append(
            {"metadata": {"name": "pipeline-reader"}, "rules": fake.roles[0]["rules"]}
        )
        fake.clusterrolebindings.append(
            {
                "metadata": {"name": "pipeline-reader"},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "pipeline-reader",
                },
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": "runner-authority",
                        "namespace": NAMESPACE,
                    }
                ],
            }
        )
        result = assess(fake)
        self.assertEqual(module.FAIL_POLICY, result["assessment"])
        self.assertIn("outside dedicated namespace", result["detail"])

    def test_workload_binding_and_missing_authority_binding_fail(self):
        fake = FakeKubectl()
        fake.rolebindings.append(
            binding(
                "workload-grant", "runner-authority-pipelineruns", "runner-workload"
            )
        )
        self.assertEqual(module.FAIL_POLICY, assess(fake)["assessment"])
        fake = FakeKubectl()
        fake.rolebindings.clear()
        result = assess(fake)
        self.assertEqual(module.FAIL_POLICY, result["assessment"])
        self.assertIn("lacks a direct", result["detail"])

    def test_binding_without_subjects_has_no_effect_but_malformed_subjects_block(self):
        fake = FakeKubectl()
        fake.clusterrolebindings.append({"metadata": {"name": "system:node"}})
        self.assertEqual(module.PASS, assess(fake)["assessment"])
        fake.clusterrolebindings[-1]["subjects"] = {
            "kind": "Group",
            "name": "system:authenticated",
        }
        self.assertEqual(module.BLOCKED_RUNTIME, assess(fake)["assessment"])

    def test_unreadable_inventory_and_ambiguous_auth_are_blocked_runtime(self):
        fake = FakeKubectl()
        fake.error_kind = "clusterrolebindings"
        self.assertEqual(module.BLOCKED_RUNTIME, assess(fake)["assessment"])
        fake = FakeKubectl()
        fake.bad_auth_response = True
        self.assertEqual(module.BLOCKED_RUNTIME, assess(fake)["assessment"])

    def test_invalid_configuration_fails_before_cluster_call(self):
        fake = FakeKubectl()
        result = module.verify_rbac("mgmt", "default", executor=fake)
        self.assertEqual(module.FAIL_POLICY, result["assessment"])
        self.assertEqual([], fake.commands)


if __name__ == "__main__":
    unittest.main()
