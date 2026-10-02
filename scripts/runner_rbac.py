#!/usr/bin/env python3
"""Read-only live RBAC assessment for the independent runner identities.

The trusted runner controller may create and observe PipelineRuns only in its
dedicated namespace. PR code runs as a separate ServiceAccount with token
automount disabled and no application RBAC grants. This assessor does not
create resources or constitute a formal, authority-bound proof by itself.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Callable
from typing import Any

PASS = "PASS"
FAIL_POLICY = "FAIL_POLICY"
BLOCKED_RUNTIME = "BLOCKED_RUNTIME"
REQUIRED = frozenset(
    (verb, "pipelineruns.tekton.dev") for verb in ("create", "get", "list", "watch")
)
DENIED = (
    ("*", "*"),
    ("get", "secrets"),
    ("list", "secrets"),
    ("watch", "secrets"),
    ("create", "secrets"),
    ("create", "pods"),
    ("patch", "pods"),
    ("delete", "pods"),
    ("create", "jobs.batch"),
    ("patch", "deployments.apps"),
    ("create", "roles.rbac.authorization.k8s.io"),
    ("create", "rolebindings.rbac.authorization.k8s.io"),
    ("create", "clusterroles.rbac.authorization.k8s.io"),
    ("create", "clusterrolebindings.rbac.authorization.k8s.io"),
    ("patch", "validatingwebhookconfigurations.admissionregistration.k8s.io"),
    ("update", "nodes"),
    ("impersonate", "serviceaccounts"),
)
CROSS_NAMESPACE_DENIED = (
    ("create", "pipelineruns.tekton.dev"),
    ("create", "pods"),
    ("patch", "secrets"),
    ("create", "rolebindings.rbac.authorization.k8s.io"),
)
SAFE_DISCOVERY_URLS = frozenset(
    (
        "/api",
        "/apis",
        "/healthz",
        "/livez",
        "/openapi",
        "/readyz",
        "/version",
        "/version/",
        "/.well-known/openid-configuration",
        "/openid/v1/jwks",
    )
)
SAFE_SELF_REVIEWS = frozenset(
    (
        ("authorization.k8s.io", "selfsubjectaccessreviews"),
        ("authorization.k8s.io", "selfsubjectrulesreviews"),
        ("authentication.k8s.io", "selfsubjectreviews"),
    )
)
NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
Executor = Callable[[list[str]], subprocess.CompletedProcess[str]]


class RuntimeBlocked(Exception):
    """Live API or inspection capability is unavailable."""


class PolicyViolation(Exception):
    """The observed identity has an unsafe or insufficient permission."""


def _valid_name(value: str) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 63
        and bool(NAME_RE.fullmatch(value))
    )


def _default_executor(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, capture_output=True, text=True, timeout=20, check=False
    )


class ReadOnlyKubectl:
    def __init__(self, context: str, executor: Executor):
        self.context = context
        self.executor = executor
        self.commands: list[list[str]] = []

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[0] != "get" and args[:2] != ["auth", "can-i"]:
            raise RuntimeBlocked("kubectl operation outside read-only allowlist")
        command = ["kubectl", "--context", self.context, *args]
        self.commands.append(command)
        try:
            return self.executor(command)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            raise RuntimeBlocked(
                f"kubectl unavailable for {args[0]}: {type(exc).__name__}"
            ) from exc

    def get(
        self,
        kind: str,
        *,
        name: str | None = None,
        namespace: str | None = None,
        all_namespaces: bool = False,
    ) -> dict[str, Any]:
        args = ["get", kind]
        if name is not None:
            args.append(name)
        if namespace is not None:
            args.extend(["-n", namespace])
        if all_namespaces:
            args.append("--all-namespaces")
        args.extend(["-o", "json"])
        result = self._run(args)
        if result.returncode != 0:
            raise RuntimeBlocked(f"cannot read Kubernetes {kind} inventory")
        try:
            data = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeBlocked(f"invalid Kubernetes {kind} JSON") from exc
        if not isinstance(data, dict):
            raise RuntimeBlocked(f"Kubernetes {kind} response is not an object")
        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            raise RuntimeBlocked(f"invalid Kubernetes {kind} metadata")
        if metadata.get("continue"):
            raise RuntimeBlocked(f"incomplete Kubernetes {kind} inventory")
        return data

    def can_i(
        self,
        service_account: str,
        namespace: str,
        verb: str,
        resource: str,
        target_namespace: str,
    ) -> bool:
        subject = f"system:serviceaccount:{namespace}:{service_account}"
        result = self._run(
            [
                "auth",
                "can-i",
                verb,
                resource,
                "--as",
                subject,
                "-n",
                target_namespace,
                "--as-group",
                "system:authenticated",
                "--as-group",
                "system:serviceaccounts",
                "--as-group",
                f"system:serviceaccounts:{namespace}",
            ]
        )
        answer = result.stdout.strip().lower()
        if answer == "yes" and result.returncode == 0:
            return True
        if answer == "no" and result.returncode in (0, 1):
            return False
        raise RuntimeBlocked(
            f"cannot evaluate {service_account} {verb} {resource} in {target_namespace}"
        )


def _items(doc: dict[str, Any], label: str) -> list[dict[str, Any]]:
    items = doc.get("items")
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise RuntimeBlocked(f"invalid Kubernetes {label} inventory")
    return items


def _identity(
    kube: ReadOnlyKubectl, namespace: str, name: str, *, automount: bool
) -> str:
    doc = kube.get("serviceaccount", name=name, namespace=namespace)
    metadata = doc.get("metadata")
    if not isinstance(metadata, dict):
        raise RuntimeBlocked(f"ServiceAccount {name} lacks metadata")
    if metadata.get("name") != name or metadata.get("namespace") != namespace:
        raise PolicyViolation(
            f"ServiceAccount {name} identity does not match the dedicated namespace"
        )
    uid = metadata.get("uid")
    if not isinstance(uid, str) or not uid:
        raise RuntimeBlocked(f"ServiceAccount {name} lacks a live UID")
    if doc.get("automountServiceAccountToken") is not automount:
        raise PolicyViolation(
            f"ServiceAccount {name} automountServiceAccountToken must be {str(automount).lower()}"
        )
    if not automount:
        for field in ("secrets", "imagePullSecrets"):
            if doc.get(field) not in (None, []):
                raise PolicyViolation(f"ServiceAccount {name} must not carry {field}")
    return uid


def _role_index(
    items: list[dict[str, Any]], *, namespaced: bool
) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for item in items:
        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            raise RuntimeBlocked("RBAC role has invalid metadata")
        name = metadata.get("name")
        namespace = metadata.get("namespace") if namespaced else ""
        if not isinstance(name, str) or not name or not isinstance(namespace, str):
            raise RuntimeBlocked("RBAC role inventory has incomplete identity")
        key = (namespace, name)
        if key in index:
            raise RuntimeBlocked("RBAC role inventory has duplicate identity")
        index[key] = item
    return index


def _target_subjects(
    binding: dict[str, Any], namespace: str, names: tuple[str, str]
) -> dict[str, str]:
    subjects = binding.get("subjects")
    if subjects is None:
        return {}
    if not isinstance(subjects, list):
        raise RuntimeBlocked("RBAC binding has invalid subjects")
    binding_namespace = binding.get("metadata", {}).get("namespace", "")
    matched: dict[str, str] = {}
    for subject in subjects:
        if not isinstance(subject, dict):
            raise RuntimeBlocked("RBAC binding has malformed subject")
        kind, name = subject.get("kind"), subject.get("name")
        if kind == "Group" and name in {
            "system:authenticated",
            "system:serviceaccounts",
            f"system:serviceaccounts:{namespace}",
        }:
            for target in names:
                matched.setdefault(target, "group")
        elif kind == "User":
            for target in names:
                if name == f"system:serviceaccount:{namespace}:{target}":
                    matched[target] = "direct"
        elif kind == "ServiceAccount":
            for target in names:
                if (
                    name == target
                    and subject.get("namespace", binding_namespace) == namespace
                ):
                    matched[target] = "direct"
                elif (
                    name == target
                    and not subject.get("namespace")
                    and not binding_namespace
                ):
                    raise RuntimeBlocked(
                        "cluster binding ServiceAccount subject lacks namespace"
                    )
    return matched


def _safe_baseline_rule(rule: dict[str, Any]) -> bool:
    verbs = rule.get("verbs")
    if (
        not isinstance(verbs, list)
        or not verbs
        or not all(isinstance(verb, str) for verb in verbs)
    ):
        return False
    if set(verbs) == {"get"}:
        urls = rule.get("nonResourceURLs")
        if (
            not isinstance(urls, list)
            or not urls
            or rule.get("resources")
            or rule.get("apiGroups")
        ):
            return False
        return all(
            isinstance(url, str)
            and url.removesuffix("/*").removesuffix("/") in SAFE_DISCOVERY_URLS
            for url in urls
        )
    if set(verbs) != {"create"}:
        return False
    groups, resources = rule.get("apiGroups"), rule.get("resources")
    return (
        isinstance(groups, list)
        and isinstance(resources, list)
        and bool(groups)
        and bool(resources)
        and all(isinstance(group, str) for group in groups)
        and all(isinstance(resource, str) for resource in resources)
        and not rule.get("nonResourceURLs")
        and not rule.get("resourceNames")
        and all(
            (group, resource) in SAFE_SELF_REVIEWS
            for group in groups
            for resource in resources
        )
    )


def _allowed_authority_rule(rule: dict[str, Any]) -> bool:
    verbs = rule.get("verbs")
    return (
        rule.get("apiGroups") == ["tekton.dev"]
        and rule.get("resources") == ["pipelineruns"]
        and isinstance(verbs, list)
        and bool(verbs)
        and all(isinstance(verb, str) for verb in verbs)
        and set(verbs) <= {verb for verb, _ in REQUIRED}
        and not rule.get("resourceNames")
        and not rule.get("nonResourceURLs")
    )


def _exact_tekton_info_baseline(
    binding: dict[str, Any], role: dict[str, Any], *, cluster_scoped: bool
) -> bool:
    # Tekton Pipelines v1.15.0 grants all authenticated identities read access
    # to one non-secret installation-info ConfigMap. No other API read grant is
    # treated as a default baseline.
    name = "tekton-pipelines-info"
    namespace = "tekton-pipelines"
    labels = {
        "app.kubernetes.io/instance": "default",
        "app.kubernetes.io/part-of": "tekton-pipelines",
    }
    if cluster_scoped:
        return False
    for document in (binding, role):
        metadata = document.get("metadata")
        if not isinstance(metadata, dict):
            return False
        if metadata.get("name") != name or metadata.get("namespace") != namespace:
            return False
        observed_labels = metadata.get("labels")
        if not isinstance(observed_labels, dict) or any(
            observed_labels.get(key) != value for key, value in labels.items()
        ):
            return False
    return (
        binding.get("roleRef")
        == {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name}
        and binding.get("subjects")
        == [
            {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Group",
                "name": "system:authenticated",
            }
        ]
        and role.get("rules")
        == [
            {
                "apiGroups": [""],
                "resourceNames": ["pipelines-info"],
                "resources": ["configmaps"],
                "verbs": ["get"],
            }
        ]
    )


def _exact_cluster_trust_bundle_baseline(
    binding: dict[str, Any], role: dict[str, Any], *, cluster_scoped: bool
) -> bool:
    # Kubernetes grants all ServiceAccounts read-only ClusterTrustBundle
    # discovery by default. Accept only the bootstrapped binding and rule.
    name = "system:cluster-trust-bundle-discovery"
    if not cluster_scoped:
        return False
    for document in (binding, role):
        metadata = document.get("metadata")
        if not isinstance(metadata, dict):
            return False
        if metadata.get("name") != name or metadata.get("namespace") not in (None, ""):
            return False
        labels = metadata.get("labels")
        if (
            not isinstance(labels, dict)
            or labels.get("kubernetes.io/bootstrapping") != "rbac-defaults"
        ):
            return False
    return (
        binding.get("roleRef")
        == {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": name,
        }
        and binding.get("subjects")
        == [
            {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Group",
                "name": "system:serviceaccounts",
            }
        ]
        and role.get("rules")
        == [
            {
                "apiGroups": ["certificates.k8s.io"],
                "resources": ["clustertrustbundles"],
                "verbs": ["get", "list", "watch"],
            }
        ]
    )


def _audit_inventory(
    kube: ReadOnlyKubectl, namespace: str, authority: str, workload: str
) -> list[str]:
    roles = _role_index(
        _items(kube.get("roles", all_namespaces=True), "roles"), namespaced=True
    )
    cluster_roles = _role_index(
        _items(kube.get("clusterroles"), "clusterroles"), namespaced=False
    )
    role_bindings = _items(
        kube.get("rolebindings", all_namespaces=True), "rolebindings"
    )
    cluster_bindings = _items(kube.get("clusterrolebindings"), "clusterrolebindings")
    inspected: list[str] = []
    direct_authority = False

    for cluster_scoped, bindings in ((False, role_bindings), (True, cluster_bindings)):
        for binding in bindings:
            metadata = binding.get("metadata")
            if not isinstance(metadata, dict) or not isinstance(
                metadata.get("name"), str
            ):
                raise RuntimeBlocked("RBAC binding has incomplete identity")
            binding_namespace = "" if cluster_scoped else metadata.get("namespace")
            if not isinstance(binding_namespace, str):
                raise RuntimeBlocked("RBAC RoleBinding lacks namespace")
            targets = _target_subjects(binding, namespace, (authority, workload))
            if not targets:
                continue
            ref = binding.get("roleRef")
            if (
                not isinstance(ref, dict)
                or ref.get("apiGroup") != "rbac.authorization.k8s.io"
            ):
                raise RuntimeBlocked("bound RBAC roleRef is incomplete")
            role_name = ref.get("name")
            role_kind = ref.get("kind")
            if not isinstance(role_name, str) or not role_name:
                raise RuntimeBlocked("bound RBAC roleRef lacks name")
            if role_kind == "Role" and not cluster_scoped:
                role = roles.get((binding_namespace, role_name))
            elif role_kind == "ClusterRole":
                role = cluster_roles.get(("", role_name))
            else:
                raise PolicyViolation("invalid or cluster-wide RoleBinding reference")
            if role is None:
                raise RuntimeBlocked(
                    f"bound RBAC role {role_name} could not be inspected"
                )
            if role.get("aggregationRule"):
                raise PolicyViolation(
                    f"bound RBAC role {role_name} has dynamic aggregation"
                )
            rules = role.get("rules", [])
            if not isinstance(rules, list) or not all(
                isinstance(rule, dict) for rule in rules
            ):
                raise RuntimeBlocked(f"bound RBAC role {role_name} has invalid rules")

            reference = (
                f"{binding_namespace or 'cluster'}/{metadata['name']}->{role_name}"
            )
            inspected.append(reference)
            if _exact_tekton_info_baseline(
                binding, role, cluster_scoped=cluster_scoped
            ) or _exact_cluster_trust_bundle_baseline(
                binding, role, cluster_scoped=cluster_scoped
            ):
                continue
            for target, source in targets.items():
                if source == "direct" and (
                    cluster_scoped or binding_namespace != namespace
                ):
                    raise PolicyViolation(
                        f"{target} has binding outside dedicated namespace: {reference}"
                    )
                for rule in rules:
                    if source == "group":
                        valid = _safe_baseline_rule(rule)
                    elif target == authority:
                        valid = _allowed_authority_rule(rule)
                        direct_authority = direct_authority or valid
                    else:
                        valid = False
                    if not valid:
                        raise PolicyViolation(
                            f"{target} has excessive RBAC rule via {reference}"
                        )
    if not direct_authority:
        raise PolicyViolation(
            f"{authority} lacks a direct namespace-scoped PipelineRun RoleBinding"
        )
    return sorted(set(inspected))


def _observe_workload_execution(
    kube: ReadOnlyKubectl, namespace: str, workload: str
) -> dict[str, Any]:
    observed: dict[str, Any] = {
        "status": "NOT_OBSERVED",
        "pipeline_runs": [],
        "task_runs": [],
    }
    for resource, kind, output_key in (
        ("pipelineruns.tekton.dev", "PipelineRun", "pipeline_runs"),
        ("taskruns.tekton.dev", "TaskRun", "task_runs"),
    ):
        items = _items(kube.get(resource, namespace=namespace), resource)
        for item in items:
            metadata = item.get("metadata")
            spec = item.get("spec")
            if not isinstance(metadata, dict) or not isinstance(spec, dict):
                raise RuntimeBlocked(f"invalid {kind} inventory item")
            name = metadata.get("name")
            if (
                not isinstance(name, str)
                or not name
                or metadata.get("namespace") != namespace
            ):
                raise RuntimeBlocked(f"{kind} inventory identity is incomplete")
            if kind == "PipelineRun":
                template = spec.get("taskRunTemplate", {})
                if not isinstance(template, dict):
                    raise RuntimeBlocked(
                        f"PipelineRun {name} has invalid taskRunTemplate"
                    )
                service_account = template.get("serviceAccountName")
                overrides = spec.get("taskRunSpecs", [])
                if not isinstance(overrides, list) or not all(
                    isinstance(entry, dict) for entry in overrides
                ):
                    raise RuntimeBlocked(f"PipelineRun {name} has invalid taskRunSpecs")
                if any(
                    entry.get("serviceAccountName") not in (None, workload)
                    for entry in overrides
                ):
                    raise PolicyViolation(
                        f"PipelineRun {name} overrides the workload ServiceAccount"
                    )
            else:
                service_account = spec.get("serviceAccountName")
            if service_account != workload:
                raise PolicyViolation(
                    f"{kind} {name} uses ServiceAccount {service_account or 'default'} instead of {workload}"
                )
            observed[output_key].append(name)
    if observed["pipeline_runs"] and observed["task_runs"]:
        observed["status"] = "OBSERVED"
    return observed


def verify_rbac(
    context: str,
    namespace: str,
    *,
    authority: str = "runner-authority",
    workload: str = "runner-workload",
    cross_namespace: str = "default",
    executor: Executor = _default_executor,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "assessment": BLOCKED_RUNTIME,
        "formal_proof": False,
        "mode": "read-only",
        "mutation_performed": False,
        "namespace": namespace,
        "authority_service_account": authority,
        "workload_service_account": workload,
        "checks": [],
        "bindings_inspected": [],
        "workload_execution_observed": False,
        "workload_execution": {"status": "NOT_ASSESSED"},
        "formal_proof_blockers": [],
    }
    try:
        if not isinstance(context, str) or not context.strip():
            raise PolicyViolation("explicit kube context is required")
        if not all(
            _valid_name(value)
            for value in (namespace, authority, workload, cross_namespace)
        ):
            raise PolicyViolation(
                "namespace and ServiceAccount names must be valid DNS labels"
            )
        if namespace in {"default", "kube-system", "kube-public", "kube-node-lease"}:
            raise PolicyViolation("runner namespace must be dedicated")
        if namespace == cross_namespace or authority == workload:
            raise PolicyViolation(
                "runner identities and cross-namespace probe must be distinct"
            )

        kube = ReadOnlyKubectl(context, executor)
        identities = {
            authority: _identity(kube, namespace, authority, automount=True),
            workload: _identity(kube, namespace, workload, automount=False),
        }
        report["service_account_uids"] = identities

        for name in (authority, workload):
            expected = REQUIRED if name == authority else frozenset()
            cases = [
                (verb, resource, namespace, True) for verb, resource in sorted(expected)
            ]
            cases += [(verb, resource, namespace, False) for verb, resource in DENIED]
            if name == workload:
                cases += [
                    (verb, resource, namespace, False)
                    for verb, resource in sorted(REQUIRED)
                ]
            cases += [
                (verb, resource, cross_namespace, False)
                for verb, resource in CROSS_NAMESPACE_DENIED
            ]
            for verb, resource, target_namespace, expected_allowed in cases:
                allowed = kube.can_i(name, namespace, verb, resource, target_namespace)
                report["checks"].append(
                    {
                        "subject": name,
                        "verb": verb,
                        "resource": resource,
                        "namespace": target_namespace,
                        "expected": "ALLOWED" if expected_allowed else "DENIED",
                        "observed": "ALLOWED" if allowed else "DENIED",
                    }
                )
                if allowed != expected_allowed:
                    raise PolicyViolation(
                        f"{name} {verb} {resource} in {target_namespace}: "
                        f"expected {'ALLOWED' if expected_allowed else 'DENIED'}"
                    )

        report["bindings_inspected"] = _audit_inventory(
            kube, namespace, authority, workload
        )
        try:
            observation = _observe_workload_execution(kube, namespace, workload)
        except RuntimeBlocked as exc:
            observation = {"status": "UNAVAILABLE", "detail": str(exc)}
        report["workload_execution"] = observation
        report["workload_execution_observed"] = observation["status"] == "OBSERVED"
        if not report["workload_execution_observed"]:
            report["formal_proof_blockers"] = [
                "WORKLOAD_EXECUTION_INVENTORY_UNAVAILABLE"
                if observation["status"] == "UNAVAILABLE"
                else "WORKLOAD_EXECUTION_NOT_OBSERVED"
            ]
        report["assessment"] = PASS
        report["detail"] = (
            "live RBAC matrix and complete bound-role inventory satisfy the runner policy"
        )
    except PolicyViolation as exc:
        report["assessment"] = FAIL_POLICY
        report["detail"] = str(exc)
    except RuntimeBlocked as exc:
        report["assessment"] = BLOCKED_RUNTIME
        report["detail"] = str(exc)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--authority-service-account", default="runner-authority")
    parser.add_argument("--workload-service-account", default="runner-workload")
    parser.add_argument("--cross-namespace", default="default")
    args = parser.parse_args(argv)
    report = verify_rbac(
        args.context,
        args.namespace,
        authority=args.authority_service_account,
        workload=args.workload_service_account,
        cross_namespace=args.cross_namespace,
    )
    print(json.dumps(report, sort_keys=True))
    return {PASS: 0, FAIL_POLICY: 2, BLOCKED_RUNTIME: 3}[report["assessment"]]


if __name__ == "__main__":
    raise SystemExit(main())
