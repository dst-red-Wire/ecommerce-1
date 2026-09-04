#!/usr/bin/env python3
"""Validate the closed PipelineRun admission contract and its Kyverno mirror."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

import yaml


class AdmissionError(Exception):
    pass


def named_items(items: object, label: str, key: str = "name") -> dict[str, dict]:
    if not isinstance(items, list):
        raise AdmissionError(f"{label} must be a list")
    result: dict[str, dict] = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get(key), str):
            raise AdmissionError(f"invalid {label} entry")
        name = item[key]
        if name in result:
            raise AdmissionError(f"duplicate {label} entry: {name}")
        result[name] = item
    return result


def validate_workspace(name: str, actual: dict, expected: dict) -> None:
    kind = expected["kind"]
    allowed = {"name", kind}
    if set(actual) != allowed:
        raise AdmissionError(f"workspace {name} contains an unapproved volume source or field")
    if kind == "emptyDir":
        if actual[kind] != {}:
            raise AdmissionError(f"workspace {name} must use an empty emptyDir source")
    elif kind == "persistentVolumeClaim":
        if actual[kind] != {"claimName": expected["claimName"]}:
            raise AdmissionError(f"workspace {name} uses an unapproved PVC")
    elif kind == "configMap":
        if actual[kind] != {"name": expected["name"]}:
            raise AdmissionError(f"workspace {name} uses caller-controlled trust material")
    elif kind == "secret":
        if actual[kind] != {"secretName": expected["secretName"]}:
            raise AdmissionError(f"workspace {name} uses an unapproved Secret")
    else:
        raise AdmissionError(f"unsupported workspace source kind in contract: {kind}")


def validate_params(pipeline: str, params: dict[str, dict], expected_names: list[str]) -> None:
    if set(params) != set(expected_names):
        raise AdmissionError(f"unexpected or missing parameters for {pipeline}")
    values = {name: item.get("value") for name, item in params.items()}
    if any(set(item) != {"name", "value"} or not isinstance(item.get("value"), str) for item in params.values()):
        raise AdmissionError("parameters must be scalar strings with no extra fields")
    if values["repository-url"] != "https://github.com/dst-red-Wire/ecommerce-1.git":
        raise AdmissionError("repository-url is not canonical")
    sha_pattern = re.compile(r"^[0-9a-f]{40}$")
    if pipeline == "build-and-publish":
        revision = values["source-revision"]
        service = values["service-context"]
        dockerfile = values["dockerfile"]
        if not sha_pattern.fullmatch(revision):
            raise AdmissionError("source-revision must be a full SHA")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", service):
            raise AdmissionError("service-context is not a safe service identifier")
        path = PurePosixPath(dockerfile)
        if path.is_absolute() or ".." in path.parts or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", dockerfile):
            raise AdmissionError("dockerfile is not a safe relative path")
        if values["image-repository"] != f"ghcr.io/dst-red-wire/ecommerce-1/{service}":
            raise AdmissionError("image repository does not match service-context")
        if values["image-tag"] != revision:
            raise AdmissionError("image-tag must equal the immutable source revision")
    else:
        if values["environment"] not in {"integration", "preproduction", "production"}:
            raise AdmissionError("unknown promotion environment")
        if not sha_pattern.fullmatch(values["expected-main-sha"]):
            raise AdmissionError("expected-main-sha must be a full SHA")


def validate_task_specs(run: dict, pipeline_contract: dict) -> None:
    default_template = run.get("spec", {}).get("taskRunTemplate")
    expected_template = {
        "serviceAccountName": pipeline_contract["defaultServiceAccountName"],
        "podTemplate": {
            "securityContext": {"fsGroup": 65532, "fsGroupChangePolicy": "OnRootMismatch"}
        },
    }
    if default_template != expected_template:
        raise AdmissionError("default ServiceAccount or pod security template differs from contract")

    actual = named_items(run["spec"].get("taskRunSpecs"), "taskRunSpecs", "pipelineTaskName")
    expected = pipeline_contract["taskServiceAccounts"]
    if set(actual) != set(expected):
        raise AdmissionError("taskRunSpecs are incomplete or contain an unknown task")
    for task_name, service_account in expected.items():
        item = actual[task_name]
        allowed = {"pipelineTaskName", "serviceAccountName"}
        if task_name == "build":
            allowed.add("podTemplate")
            expected_pod = {
                "nodeSelector": {"ecommerce.dev/workload": "ci-build"},
                "tolerations": [
                    {
                        "key": "ecommerce.dev/ci-build",
                        "operator": "Equal",
                        "value": "true",
                        "effect": "NoSchedule",
                    }
                ],
            }
            if item.get("podTemplate") != expected_pod:
                raise AdmissionError("BuildKit node isolation differs from contract")
        if set(item) != allowed or item.get("serviceAccountName") != service_account:
            raise AdmissionError(f"unapproved ServiceAccount or taskRunSpec fields for {task_name}")


def validate_run(run: dict, contract: dict) -> None:
    if run.get("apiVersion") != "tekton.dev/v1" or run.get("kind") != "PipelineRun":
        raise AdmissionError("only tekton.dev/v1 PipelineRun objects are accepted")
    metadata = run.get("metadata", {})
    if metadata.get("namespace") != contract["namespace"]:
        raise AdmissionError("PipelineRun namespace is outside the contract")
    spec = run.get("spec")
    if not isinstance(spec, dict):
        raise AdmissionError("PipelineRun spec is required")
    if "pipelineSpec" in spec:
        raise AdmissionError("inline pipelineSpec is forbidden")
    pipeline_ref = spec.get("pipelineRef")
    if not isinstance(pipeline_ref, dict) or set(pipeline_ref) != {"name"}:
        raise AdmissionError("resolver and non-local pipelineRef fields are forbidden")
    pipeline = pipeline_ref["name"]
    if pipeline not in contract["pipelines"]:
        raise AdmissionError("pipelineRef is not allowlisted")
    pipeline_contract = contract["pipelines"][pipeline]
    params = named_items(spec.get("params"), "params")
    validate_params(pipeline, params, pipeline_contract["params"])
    workspaces = named_items(spec.get("workspaces"), "workspaces")
    if set(workspaces) != set(pipeline_contract["workspaces"]):
        raise AdmissionError("workspaces are incomplete or contain an unknown binding")
    for name, expected in pipeline_contract["workspaces"].items():
        validate_workspace(name, workspaces[name], expected)
    validate_task_specs(run, pipeline_contract)


def verify_repository_contract(root: Path, contract_path: Path) -> dict:
    raw = contract_path.read_bytes()
    contract = json.loads(raw)
    policy_path = root / "gitops/infrastructure/policies/kyverno/tekton-run-contracts.yaml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    expected_hash = hashlib.sha256(raw).hexdigest()
    actual_hash = policy.get("metadata", {}).get("annotations", {}).get(
        "ecommerce.dev/admission-contract-sha256"
    )
    if actual_hash != expected_hash:
        raise AdmissionError("Kyverno policy is not bound to the current admission contract")
    if policy.get("spec", {}).get("validationFailureAction") != "Audit":
        raise AdmissionError("this repository phase must keep Kyverno in Audit")
    if policy.get("spec", {}).get("background") is not False:
        raise AdmissionError("request identity rules require background=false")
    policy_text = policy_path.read_text(encoding="utf-8")
    required_tokens = [
        "deny-direct-user-taskruns",
        "deny-unsupported-pipelinerun-shapes",
        "pipelineSpec",
        "resolver",
        "github-git-write",
        "promotion-trust-root",
    ]
    for pipeline, details in contract["pipelines"].items():
        required_tokens.append(pipeline)
        required_tokens.extend(details["params"])
        required_tokens.extend(details["workspaces"])
        required_tokens.extend(details["taskServiceAccounts"].values())
    missing = [token for token in required_tokens if token not in policy_text]
    if missing:
        raise AdmissionError(f"Kyverno policy omits contract tokens: {sorted(set(missing))}")

    integration = (root / "gitops/clusters/integration/kustomization.yaml").read_text(encoding="utf-8")
    if "../../infrastructure/policies/kyverno" not in integration:
        raise AdmissionError("integration overlay does not include the Kyverno policy")
    for rbac_path in (root / "gitops").rglob("*.yaml"):
        for document in yaml.safe_load_all(rbac_path.read_text(encoding="utf-8")):
            if not isinstance(document, dict) or document.get("kind") not in {"RoleBinding", "ClusterRoleBinding"}:
                continue
            role_ref = document.get("roleRef", {})
            if role_ref.get("name") == "tekton-approved-run-submitter":
                raise AdmissionError("run submitter Role is bound before Enforce validation")
    return contract


def apply_mutation(document: dict, mutation: dict) -> None:
    path = mutation["path"]
    current: object = document
    for part in path[:-1]:
        current = current[part] if isinstance(part, int) else current[part]  # type: ignore[index]
    final = path[-1]
    if mutation["op"] == "set":
        current[final] = mutation["value"]  # type: ignore[index]
    elif mutation["op"] == "delete":
        del current[final]  # type: ignore[index]
    elif mutation["op"] == "append":
        current[final].append(mutation["value"])  # type: ignore[index,union-attr]
    else:
        raise AdmissionError(f"unknown fixture mutation: {mutation['op']}")


def validate_fixture_suite(path: Path, contract: dict) -> None:
    suite = json.loads(path.read_text(encoding="utf-8"))
    valid_runs = suite["validRuns"]
    for name, run in valid_runs.items():
        try:
            validate_run(run, contract)
        except AdmissionError as exc:
            raise AdmissionError(f"ALLOW fixture {name} was rejected: {exc}") from exc
    for case in suite["denyCases"]:
        run = copy.deepcopy(valid_runs[case["base"]])
        apply_mutation(run, case["mutation"])
        try:
            validate_run(run, contract)
        except AdmissionError:
            continue
        raise AdmissionError(f"DENY fixture was accepted: {case['name']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pipeline_runs", nargs="*", type=Path)
    parser.add_argument("--fixture-suite", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--contract",
        type=Path,
        default=Path("contracts/supply-chain/tekton-admission-policy.json"),
    )
    args = parser.parse_args()
    root = args.root.resolve()
    contract_path = args.contract if args.contract.is_absolute() else root / args.contract
    try:
        contract = verify_repository_contract(root, contract_path)
        for path in args.pipeline_runs:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            validate_run(document, contract)
        if args.fixture_suite:
            validate_fixture_suite(args.fixture_suite, contract)
        print("Tekton admission contract validated")
        return 0
    except (AdmissionError, OSError, ValueError, yaml.YAMLError, json.JSONDecodeError) as exc:
        print(f"Tekton admission rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
