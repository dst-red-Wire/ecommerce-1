#!/usr/bin/env python3
"""Read-only live readiness checks for the Gitea -> Tekton trigger boundary.

The module never creates, patches, deletes, applies, rolls out, or otherwise mutates
Kubernetes resources. It inspects runtime prerequisites declared by
config/contracts/tekton-trigger-runtime.yaml and writes a redacted JSON evidence file.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Callable

PASS = "PASS"
BLOCKED = "BLOCKED"
FAIL = "FAIL"
BLOCKED_EXIT = 3
FAIL_EXIT = 2
RUNNER_DIGEST_RE = re.compile(r"@sha256:([0-9a-f]{64})$")
FORBIDDEN_MUTATING_KUBECTL = {
    "apply",
    "create",
    "delete",
    "edit",
    "patch",
    "replace",
    "rollout",
    "scale",
    "set",
}

Executor = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _default_executor(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _compact(text: str, limit: int = 240) -> str:
    text = " ".join((text or "").strip().split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _result(status: str, detail: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"status": status, "detail": detail}
    payload.update(extra)
    return payload


def _require_string(mapping: dict[str, Any], key: str, prefix: str = "") -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        label = f"{prefix}.{key}" if prefix else key
        raise ValueError(f"runtime config requires non-empty {label}")
    return value.strip()


def validate_runtime_config(config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ValueError("runtime config must be a mapping")
    normalized: dict[str, Any] = {
        "kube_context": _require_string(config, "kube_context"),
        "namespace": _require_string(config, "namespace"),
        "runner_image": _require_string(config, "runner_image"),
        "event_listener_service_account": _require_string(config, "event_listener_service_account"),
        "pipeline_service_account": _require_string(config, "pipeline_service_account"),
    }
    if not RUNNER_DIGEST_RE.search(normalized["runner_image"]):
        raise ValueError("runner_image must be an immutable @sha256:<64-hex> reference")

    webhook = config.get("webhook")
    if not isinstance(webhook, dict):
        raise ValueError("runtime config requires webhook mapping")
    normalized["webhook"] = {
        "external_secret_name": _require_string(webhook, "external_secret_name", "webhook"),
        "secret_name": _require_string(webhook, "secret_name", "webhook"),
        "secret_key": _require_string(webhook, "secret_key", "webhook"),
    }

    network = config.get("network")
    if not isinstance(network, dict):
        raise ValueError("runtime config requires network mapping")
    normalized["network"] = {
        "ingress_name": _require_string(network, "ingress_name", "network"),
        "event_listener_service": _require_string(network, "event_listener_service", "network"),
        "tls_secret_name": _require_string(network, "tls_secret_name", "network"),
        "default_deny_policy": _require_string(network, "default_deny_policy", "network"),
    }

    execution_budget = config.get("execution_budget")
    if not isinstance(execution_budget, dict):
        raise ValueError("runtime config requires execution_budget mapping")
    normalized["execution_budget"] = {
        "resource_quota_name": _require_string(execution_budget, "resource_quota_name", "execution_budget"),
    }

    proofs = config.get("proofs")
    if not isinstance(proofs, dict):
        raise ValueError("runtime config requires proofs mapping")
    normalized["proofs"] = {
        "runner_pull_pod": _require_string(proofs, "runner_pull_pod", "proofs"),
        "network_probe_pod": _require_string(proofs, "network_probe_pod", "proofs"),
    }
    return normalized


class ReadOnlyKubectl:
    def __init__(self, context: str, executor: Executor):
        self.context = context
        self.executor = executor
        self.commands: list[list[str]] = []

    def run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        if args and args[0] in FORBIDDEN_MUTATING_KUBECTL:
            raise RuntimeError(f"mutating kubectl verb forbidden in readiness gate: {args[0]}")
        cmd = ["kubectl", "--context", self.context, *args]
        self.commands.append(cmd)
        return self.executor(cmd)

    def json(self, args: list[str]) -> tuple[dict[str, Any] | None, str]:
        proc = self.run([*args, "-o", "json"])
        if proc.returncode:
            return None, _compact(proc.stderr or proc.stdout)
        try:
            value = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            return None, f"invalid kubectl JSON: {exc}"
        if not isinstance(value, dict):
            return None, "kubectl JSON response is not an object"
        return value, ""

    def text(self, args: list[str]) -> tuple[str | None, str]:
        proc = self.run(args)
        if proc.returncode:
            return None, _compact(proc.stderr or proc.stdout)
        return (proc.stdout or "").strip(), ""


def _check_kustomize(root: Path, executor: Executor) -> dict[str, Any]:
    if not shutil.which("kustomize") and executor is _default_executor:
        return _result(FAIL, "required command missing: kustomize")
    proc = executor(["kustomize", "build", str(root / "platform" / "tekton")])
    if proc.returncode:
        return _result(FAIL, f"kustomize build failed: {_compact(proc.stderr or proc.stdout)}")
    return _result(PASS, "platform/tekton renders successfully with kustomize")


def _check_crds(kube: ReadOnlyKubectl) -> dict[str, Any]:
    expected = {
        "eventlisteners.triggers.tekton.dev": "v1beta1",
        "triggerbindings.triggers.tekton.dev": "v1beta1",
        "triggertemplates.triggers.tekton.dev": "v1beta1",
    }
    observed: dict[str, str] = {}
    for crd, version in expected.items():
        doc, err = kube.json(["get", "crd", crd])
        if doc is None:
            return _result(BLOCKED, f"missing/unreadable CRD {crd}: {err}")
        versions = doc.get("spec", {}).get("versions", [])
        served = [v for v in versions if isinstance(v, dict) and v.get("name") == version and v.get("served") is True]
        if not served:
            return _result(BLOCKED, f"CRD {crd} does not serve required {version}")
        observed[crd] = version
    return _result(PASS, "required Tekton Trigger CRDs are present and served", crds=observed)


def _check_namespace(kube: ReadOnlyKubectl, namespace: str) -> dict[str, Any]:
    doc, err = kube.json(["get", "namespace", namespace])
    if doc is None:
        return _result(BLOCKED, f"namespace {namespace} unavailable: {err}")
    phase = doc.get("status", {}).get("phase")
    if phase != "Active":
        return _result(BLOCKED, f"namespace {namespace} phase is {phase!r}, expected Active")
    if namespace in {"default", "kube-system", "kube-public", "kube-node-lease"}:
        return _result(BLOCKED, f"namespace {namespace} is not dedicated")
    return _result(PASS, f"dedicated namespace {namespace} exists and is Active")


def _check_runner_pull(kube: ReadOnlyKubectl, namespace: str, runner_image: str, pod_name: str) -> dict[str, Any]:
    doc, err = kube.json(["get", "pod", pod_name, "-n", namespace])
    if doc is None:
        return _result(BLOCKED, f"runner pull proof pod {pod_name} unavailable: {err}")
    annotations = doc.get("metadata", {}).get("annotations", {}) or {}
    if annotations.get("ecommerce-1.io/readiness-proof") != "runner-image-pull":
        return _result(BLOCKED, f"runner pull proof pod {pod_name} lacks canonical readiness annotation")
    phase = doc.get("status", {}).get("phase")
    if phase not in {"Running", "Succeeded"}:
        return _result(BLOCKED, f"runner pull proof pod {pod_name} phase is {phase!r}")
    containers = doc.get("spec", {}).get("containers", []) or []
    names = {c.get("name") for c in containers if isinstance(c, dict) and c.get("image") == runner_image}
    if not names:
        return _result(BLOCKED, "runner pull proof pod does not use the exact configured runner digest")
    digest = RUNNER_DIGEST_RE.search(runner_image).group(1)
    statuses = doc.get("status", {}).get("containerStatuses", []) or []
    pulled = []
    for status in statuses:
        if not isinstance(status, dict) or status.get("name") not in names:
            continue
        image_id = str(status.get("imageID", ""))
        if image_id.endswith(f"@sha256:{digest}") or f"sha256:{digest}" in image_id:
            pulled.append(status.get("name"))
    if not pulled:
        return _result(BLOCKED, "kubelet imageID does not prove the configured runner digest was pulled")
    return _result(PASS, "exact Harbor runner digest has live kubelet pull evidence", pod=pod_name)


ZERO_QUANTITY_RE = re.compile(
    r"^[+-]?0+(?:\.0+)?(?:e[+-]?\d+)?(?:[EPTGMK]i?|m|u|n)?$",
    re.IGNORECASE,
)


def _positive_resource_quantity(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text) and ZERO_QUANTITY_RE.fullmatch(text) is None


def _check_execution_budget(
    kube: ReadOnlyKubectl,
    namespace: str,
    quota_name: str,
    runner_image: str,
    pod_name: str,
) -> dict[str, Any]:
    quota, err = kube.json(["get", "resourcequota", quota_name, "-n", namespace])
    if quota is None:
        return _result(BLOCKED, f"execution ResourceQuota {quota_name} unavailable: {err}")
    hard = quota.get("status", {}).get("hard", {}) or {}
    required_hard = {"requests.cpu", "requests.memory", "limits.cpu", "limits.memory"}
    missing_hard = sorted(key for key in required_hard if not _positive_resource_quantity(hard.get(key)))
    if missing_hard:
        return _result(
            BLOCKED,
            f"execution ResourceQuota {quota_name} lacks positive hard limits for {missing_hard}",
        )

    pod, err = kube.json(["get", "pod", pod_name, "-n", namespace])
    if pod is None:
        return _result(BLOCKED, f"runner resource proof pod {pod_name} unavailable: {err}")
    containers = [
        item
        for item in (pod.get("spec", {}).get("containers", []) or [])
        if isinstance(item, dict) and item.get("image") == runner_image
    ]
    if not containers:
        return _result(BLOCKED, "runner resource proof pod does not use the exact configured runner digest")
    for container in containers:
        resources = container.get("resources", {}) or {}
        requests = resources.get("requests", {}) or {}
        limits = resources.get("limits", {}) or {}
        missing = [
            name
            for name, value in (
                ("requests.cpu", requests.get("cpu")),
                ("requests.memory", requests.get("memory")),
                ("limits.cpu", limits.get("cpu")),
                ("limits.memory", limits.get("memory")),
            )
            if not _positive_resource_quantity(value)
        ]
        if not missing:
            return _result(
                PASS,
                "namespace ResourceQuota and runner proof pod enforce a positive CPU/memory execution budget",
                resource_quota=quota_name,
                runner_pod=pod_name,
                required_hard_keys=sorted(required_hard),
            )
    return _result(
        BLOCKED,
        f"runner resource proof pod {pod_name} lacks positive requests/limits for {missing}",
    )


def _can_i(
    kube: ReadOnlyKubectl, namespace: str, service_account: str, verb: str, resource: str
) -> tuple[bool | None, str]:
    subject = f"system:serviceaccount:{namespace}:{service_account}"
    text, err = kube.text(["auth", "can-i", verb, resource, "--as", subject, "-n", namespace])
    if text is None:
        return None, err
    value = text.strip().lower()
    if value == "yes":
        return True, ""
    if value == "no":
        return False, ""
    return None, f"unexpected kubectl auth can-i response: {value!r}"


def _check_rbac(kube: ReadOnlyKubectl, namespace: str, event_sa: str, pipeline_sa: str) -> dict[str, Any]:
    for name in (event_sa, pipeline_sa):
        doc, err = kube.json(["get", "serviceaccount", name, "-n", namespace])
        if doc is None:
            return _result(BLOCKED, f"service account {name} unavailable: {err}")
    for name in (event_sa, pipeline_sa):
        wildcard, err = _can_i(kube, namespace, name, "*", "*")
        if wildcard is None:
            return _result(BLOCKED, f"cannot prove RBAC for {name}: {err}")
        if wildcard:
            return _result(BLOCKED, f"service account {name} has wildcard namespace permissions")
        cluster_admin, err = _can_i(kube, namespace, name, "create", "clusterrolebindings.rbac.authorization.k8s.io")
        if cluster_admin is None:
            return _result(BLOCKED, f"cannot prove cluster RBAC boundary for {name}: {err}")
        if cluster_admin:
            return _result(BLOCKED, f"service account {name} can create ClusterRoleBindings")
    create_pr, err = _can_i(kube, namespace, event_sa, "create", "pipelineruns.tekton.dev")
    if create_pr is None:
        return _result(BLOCKED, f"cannot prove EventListener PipelineRun permission: {err}")
    if not create_pr:
        return _result(BLOCKED, f"EventListener service account {event_sa} cannot create PipelineRuns")
    return _result(
        PASS, "service accounts exist, wildcard privilege is absent, and EventListener has bounded PipelineRun creation"
    )


def _condition_ready(doc: dict[str, Any]) -> bool:
    for condition in doc.get("status", {}).get("conditions", []) or []:
        if (
            isinstance(condition, dict)
            and condition.get("type") == "Ready"
            and str(condition.get("status")).lower() == "true"
        ):
            return True
    return False


def _check_webhook_secret(kube: ReadOnlyKubectl, namespace: str, webhook: dict[str, str]) -> dict[str, Any]:
    ext_name = webhook["external_secret_name"]
    secret_name = webhook["secret_name"]
    secret_key = webhook["secret_key"]
    ext, err = kube.json(["get", "externalsecrets.external-secrets.io", ext_name, "-n", namespace])
    if ext is None:
        return _result(BLOCKED, f"ExternalSecret {ext_name} unavailable: {err}")
    if not _condition_ready(ext):
        return _result(BLOCKED, f"ExternalSecret {ext_name} is not Ready")
    target = ext.get("spec", {}).get("target", {}).get("name")
    if target != secret_name:
        return _result(BLOCKED, f"ExternalSecret target {target!r} does not match configured secret {secret_name!r}")
    store_ref = ext.get("spec", {}).get("secretStoreRef", {}) or {}
    store_name = store_ref.get("name")
    store_kind = store_ref.get("kind", "SecretStore")
    if not store_name:
        return _result(BLOCKED, "ExternalSecret has no secretStoreRef.name")
    if store_kind == "ClusterSecretStore":
        store, err = kube.json(["get", "clustersecretstores.external-secrets.io", store_name])
    else:
        store, err = kube.json(["get", "secretstores.external-secrets.io", store_name, "-n", namespace])
    if store is None:
        return _result(BLOCKED, f"ESO store {store_kind}/{store_name} unavailable: {err}")
    provider = store.get("spec", {}).get("provider", {}) or {}
    if "vault" not in provider:
        return _result(BLOCKED, f"ESO store {store_kind}/{store_name} is not Vault/OpenBao-compatible")
    secret, err = kube.json(["get", "secret", secret_name, "-n", namespace])
    if secret is None:
        return _result(BLOCKED, f"synced Kubernetes Secret {secret_name} unavailable: {err}")
    keys = sorted((secret.get("data") or {}).keys())
    if secret_key not in keys:
        return _result(BLOCKED, f"synced Kubernetes Secret {secret_name} is missing required key {secret_key}")
    # Never put secret data into readiness evidence. Only names/keys/status are recorded.
    return _result(
        PASS,
        "ESO reports Ready through a Vault/OpenBao-compatible store and the target key exists",
        external_secret=ext_name,
        secret=secret_name,
        key=secret_key,
    )


def _ingress_backends(doc: dict[str, Any]) -> set[str]:
    services: set[str] = set()
    default = doc.get("spec", {}).get("defaultBackend", {}).get("service", {}).get("name")
    if default:
        services.add(str(default))
    for rule in doc.get("spec", {}).get("rules", []) or []:
        for path in (rule.get("http", {}) or {}).get("paths", []) or []:
            name = (path.get("backend", {}) or {}).get("service", {}).get("name")
            if name:
                services.add(str(name))
    return services


def _check_network(kube: ReadOnlyKubectl, namespace: str, network: dict[str, str], proof_pod: str) -> dict[str, Any]:
    ingress, err = kube.json(["get", "ingress.networking.k8s.io", network["ingress_name"], "-n", namespace])
    if ingress is None:
        return _result(BLOCKED, f"trigger ingress {network['ingress_name']} unavailable: {err}")
    tls = ingress.get("spec", {}).get("tls", []) or []
    tls_secrets = {entry.get("secretName") for entry in tls if isinstance(entry, dict) and entry.get("secretName")}
    if network["tls_secret_name"] not in tls_secrets:
        return _result(BLOCKED, f"trigger ingress does not reference TLS secret {network['tls_secret_name']}")
    backends = _ingress_backends(ingress)
    if backends != {network["event_listener_service"]}:
        return _result(BLOCKED, f"trigger ingress backends {sorted(backends)} are not EventListener-only")

    policy, err = kube.json(["get", "networkpolicy.networking.k8s.io", network["default_deny_policy"], "-n", namespace])
    if policy is None:
        return _result(BLOCKED, f"default-deny NetworkPolicy unavailable: {err}")
    spec = policy.get("spec", {}) or {}
    if spec.get("podSelector") != {}:
        return _result(BLOCKED, "default-deny NetworkPolicy must select every pod")
    types = set(spec.get("policyTypes", []) or [])
    if not {"Ingress", "Egress"}.issubset(types):
        return _result(BLOCKED, "default-deny NetworkPolicy must cover both Ingress and Egress")
    if spec.get("ingress", []) not in ([], None) or spec.get("egress", []) not in ([], None):
        return _result(BLOCKED, "default-deny NetworkPolicy contains allow rules")

    probe, err = kube.json(["get", "pod", proof_pod, "-n", namespace])
    if probe is None:
        return _result(BLOCKED, f"network proof pod {proof_pod} unavailable: {err}")
    annotations = probe.get("metadata", {}).get("annotations", {}) or {}
    if annotations.get("ecommerce-1.io/readiness-proof") != "network-egress":
        return _result(BLOCKED, f"network proof pod {proof_pod} lacks canonical readiness annotation")
    targets = {
        item.strip() for item in str(annotations.get("ecommerce-1.io/readiness-targets", "")).split(",") if item.strip()
    }
    if targets != {"gitea", "harbor", "kubernetes-api"}:
        return _result(BLOCKED, f"network proof targets are {sorted(targets)}, expected gitea/harbor/kubernetes-api")
    if probe.get("status", {}).get("phase") != "Succeeded":
        return _result(BLOCKED, f"network proof pod {proof_pod} has not Succeeded")
    return _result(
        PASS,
        "TLS ingress is EventListener-only, namespace is default-deny, and canonical egress proof succeeded",
        ingress=network["ingress_name"],
        proof_pod=proof_pod,
    )


def run_readiness(root: Path, config: dict[str, Any], evidence_path: Path, executor: Executor | None = None) -> int:
    executor = executor or _default_executor
    try:
        runtime = validate_runtime_config(config)
    except ValueError as exc:
        print(f"FAIL tekton-trigger-readiness config: {exc}")
        return FAIL_EXIT

    static = _check_kustomize(root, executor)
    if static["status"] == FAIL:
        print(f"FAIL {static['detail']}")
        return FAIL_EXIT

    if not shutil.which("kubectl") and executor is _default_executor:
        print("FAIL tekton-trigger-readiness: required command missing: kubectl")
        return FAIL_EXIT

    kube = ReadOnlyKubectl(runtime["kube_context"], executor)
    namespace = runtime["namespace"]
    proofs: dict[str, dict[str, Any]] = {
        "triggers-crds-present": _check_crds(kube),
        "dedicated-namespace-provisioned": _check_namespace(kube, namespace),
        "runner-image-digest-pullable": _check_runner_pull(
            kube, namespace, runtime["runner_image"], runtime["proofs"]["runner_pull_pod"]
        ),
        "bounded-execution-budget-proven": _check_execution_budget(
            kube,
            namespace,
            runtime["execution_budget"]["resource_quota_name"],
            runtime["runner_image"],
            runtime["proofs"]["runner_pull_pod"],
        ),
        "least-privilege-rbac-proven": _check_rbac(
            kube, namespace, runtime["event_listener_service_account"], runtime["pipeline_service_account"]
        ),
        "webhook-secret-synced-from-openbao-via-eso": _check_webhook_secret(kube, namespace, runtime["webhook"]),
        "ingress-tls-and-network-policy-proven": _check_network(
            kube, namespace, runtime["network"], runtime["proofs"]["network_probe_pod"]
        ),
    }

    overall = PASS if all(item["status"] == PASS for item in proofs.values()) else BLOCKED
    evidence = {
        "schema_version": 1,
        "status": overall,
        "mode": "read-only",
        "contract": "config/contracts/tekton-trigger-runtime.yaml",
        "kube_context": runtime["kube_context"],
        "namespace": namespace,
        "runner_image": runtime["runner_image"],
        "static": {"kustomize": static},
        "proofs": proofs,
        "mutation_performed": False,
    }
    destination = evidence_path if evidence_path.is_absolute() else root / evidence_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for name, item in proofs.items():
        print(f"{item['status']} {name}: {item['detail']}")
    print(f"EVIDENCE {destination}")
    if overall == PASS:
        print("PASS Tekton trigger runtime readiness")
        return 0
    missing = sum(1 for item in proofs.values() if item["status"] != PASS)
    print(f"BLOCKED Tekton trigger runtime readiness: {missing}/{len(proofs)} required proofs are not satisfied")
    return BLOCKED_EXIT
