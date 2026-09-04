#!/usr/bin/env python3
"""Resolve local Tekton Pipeline/Task/RunContract relationships statically."""

from __future__ import annotations

import argparse
import copy
import re
import sys
from pathlib import Path

import yaml


TASK_RESULT_REF = re.compile(r"\$\(tasks\.([a-z0-9-]+)\.results\.([A-Za-z0-9_-]+)\)")
PIPELINE_PARAM_REF = re.compile(r"\$\(params\.([a-z0-9-]+)\)")
PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
EXPECTED_IDENTITIES = {
    "build-and-publish": {
        "clone": "tekton-source-read",
        "test": "tekton-test",
        "source-security": "tekton-source-scan",
        "build": "tekton-image-push",
        "scan-image": "tekton-image-read",
        "generate-sbom": "tekton-image-read",
        "create-evidence": "tekton-evidence",
    },
    "promote-image": {
        "verify-proof": "tekton-evidence-verifier",
        "propose-git-change": "tekton-git-promotion",
    },
}


class ContractError(Exception):
    pass


def load_single(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractError(f"expected one YAML object in {path}")
    return value


def unique(items: list[dict], key: str, label: str) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for item in items:
        name = item.get(key)
        if not isinstance(name, str) or name in result:
            raise ContractError(f"invalid or duplicate {label}: {name}")
        result[name] = item
    return result


def load_repository(tekton_root: Path) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    tasks: dict[str, dict] = {}
    for path in sorted((tekton_root / "tasks").glob("*.yaml")):
        task = load_single(path)
        if task.get("kind") != "Task":
            continue
        name = task.get("metadata", {}).get("name")
        if name in tasks:
            raise ContractError(f"duplicate Task {name}")
        tasks[name] = task
    pipelines: dict[str, dict] = {}
    for path in sorted((tekton_root / "pipelines").glob("*.yaml")):
        pipeline = load_single(path)
        if pipeline.get("kind") != "Pipeline":
            continue
        name = pipeline.get("metadata", {}).get("name")
        if name in pipelines:
            raise ContractError(f"duplicate Pipeline {name}")
        pipelines[name] = pipeline
    contracts: dict[str, dict] = {}
    for path in sorted((tekton_root / "contracts").glob("*.run-contract.yaml")):
        contract = load_single(path)
        name = contract.get("spec", {}).get("pipelineRef")
        if name in contracts:
            raise ContractError(f"duplicate RunContract {name}")
        contracts[name] = contract
    return tasks, pipelines, contracts


def all_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        result: list[str] = []
        for nested in value.values():
            result.extend(all_strings(nested))
        return result
    if isinstance(value, list):
        result = []
        for nested in value:
            result.extend(all_strings(nested))
        return result
    return []


def has_path(graph: dict[str, set[str]], start: str, target: str) -> bool:
    pending = list(graph[start])
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current == target:
            return True
        if current not in visited:
            visited.add(current)
            pending.extend(graph[current])
    return False


def validate_task_sources(tasks: dict[str, dict]) -> None:
    for name, task in tasks.items():
        spec = task.get("spec", {})
        unique(spec.get("params", []), "name", f"Task {name} param")
        unique(spec.get("workspaces", []), "name", f"Task {name} workspace")
        unique(spec.get("results", []), "name", f"Task {name} result")
        steps = unique(spec.get("steps", []), "name", f"Task {name} step")
        for step_name, step in steps.items():
            image = step.get("image")
            if not isinstance(image, str) or not PINNED_IMAGE.fullmatch(image):
                raise ContractError(f"Task {name} step {step_name} image is not digest-pinned")
            security = step.get("securityContext", {})
            if security.get("privileged") is True:
                raise ContractError(f"privileged Task step is forbidden: {name}/{step_name}")
            if security.get("allowPrivilegeEscalation") is not False:
                raise ContractError(f"Task step does not disable privilege escalation: {name}/{step_name}")


def validate_pipeline(name: str, pipeline: dict, tasks: dict[str, dict], contract: dict) -> None:
    spec = pipeline.get("spec", {})
    pipeline_params = unique(spec.get("params", []), "name", f"Pipeline {name} param")
    pipeline_workspaces = unique(spec.get("workspaces", []), "name", f"Pipeline {name} workspace")
    pipeline_results = unique(spec.get("results", []), "name", f"Pipeline {name} result")
    pipeline_tasks = unique(spec.get("tasks", []), "name", f"Pipeline {name} task")
    graph: dict[str, set[str]] = {task_name: set() for task_name in pipeline_tasks}

    for pipeline_task_name, pipeline_task in pipeline_tasks.items():
        if "taskSpec" in pipeline_task or "pipelineSpec" in pipeline_task:
            raise ContractError(f"inline task in Pipeline {name}/{pipeline_task_name}")
        task_ref = pipeline_task.get("taskRef")
        if not isinstance(task_ref, dict) or set(task_ref) != {"name"}:
            raise ContractError(f"non-local TaskRef in Pipeline {name}/{pipeline_task_name}")
        task_name = task_ref["name"]
        if task_name not in tasks:
            raise ContractError(f"unknown TaskRef {task_name} in Pipeline {name}")
        task_spec = tasks[task_name]["spec"]
        declared_params = unique(task_spec.get("params", []), "name", f"Task {task_name} param")
        supplied_params = unique(pipeline_task.get("params", []), "name", f"PipelineTask {pipeline_task_name} param")
        unknown_params = set(supplied_params) - set(declared_params)
        required_params = {key for key, value in declared_params.items() if "default" not in value}
        missing_params = required_params - set(supplied_params)
        if unknown_params or missing_params:
            raise ContractError(
                f"param mismatch for {name}/{pipeline_task_name}: missing={sorted(missing_params)} extra={sorted(unknown_params)}"
            )
        task_workspaces = unique(task_spec.get("workspaces", []), "name", f"Task {task_name} workspace")
        mapped_workspaces = unique(
            pipeline_task.get("workspaces", []), "name", f"PipelineTask {pipeline_task_name} workspace"
        )
        required_workspaces = {key for key, value in task_workspaces.items() if not value.get("optional", False)}
        if set(mapped_workspaces) != required_workspaces:
            raise ContractError(
                f"workspace mismatch for {name}/{pipeline_task_name}: expected={sorted(required_workspaces)} actual={sorted(mapped_workspaces)}"
            )
        for workspace_name, mapping in mapped_workspaces.items():
            target = mapping.get("workspace")
            if set(mapping) != {"name", "workspace"} or target not in pipeline_workspaces:
                raise ContractError(f"invalid workspace mapping for {name}/{pipeline_task_name}/{workspace_name}")
        for dependency in pipeline_task.get("runAfter", []):
            if dependency not in pipeline_tasks or dependency == pipeline_task_name:
                raise ContractError(f"invalid runAfter in {name}/{pipeline_task_name}: {dependency}")
            graph[pipeline_task_name].add(dependency)
        for string in all_strings(pipeline_task.get("params", [])):
            for param_ref in PIPELINE_PARAM_REF.findall(string):
                if param_ref not in pipeline_params:
                    raise ContractError(f"unknown Pipeline param result reference: {param_ref}")
            for producer, result in TASK_RESULT_REF.findall(string):
                if producer not in pipeline_tasks:
                    raise ContractError(f"unknown result producer {producer} in {name}/{pipeline_task_name}")
                producer_task_name = pipeline_tasks[producer]["taskRef"]["name"]
                producer_results = unique(
                    tasks[producer_task_name].get("spec", {}).get("results", []),
                    "name",
                    f"Task {producer_task_name} result",
                )
                if result not in producer_results:
                    raise ContractError(f"unknown result {producer}.{result} in Pipeline {name}")
                graph[pipeline_task_name].add(producer)

    for consumer in graph:
        if has_path(graph, consumer, consumer):
            raise ContractError(f"dependency cycle in Pipeline {name} at {consumer}")

    for result in pipeline_results.values():
        for producer, task_result in TASK_RESULT_REF.findall(str(result.get("value", ""))):
            if producer not in pipeline_tasks:
                raise ContractError(f"unknown Pipeline result producer {producer} in {name}")
            producer_task = pipeline_tasks[producer]["taskRef"]["name"]
            declared = unique(tasks[producer_task]["spec"].get("results", []), "name", "Task result")
            if task_result not in declared:
                raise ContractError(f"unknown Pipeline result {producer}.{task_result} in {name}")

    run_spec = contract.get("spec", {})
    task_identities = unique(run_spec.get("taskRunSpecs", []), "pipelineTaskName", "RunContract task")
    if set(task_identities) != set(pipeline_tasks):
        raise ContractError(f"RunContract task identity coverage mismatch for Pipeline {name}")
    if run_spec.get("defaultServiceAccountName") != "tekton-test":
        raise ContractError(f"unapproved default ServiceAccount for Pipeline {name}")
    actual_identities = {
        task_name: item.get("serviceAccountName") for task_name, item in task_identities.items()
    }
    if actual_identities != EXPECTED_IDENTITIES[name]:
        raise ContractError(f"ServiceAccount mapping differs from the closed contract for Pipeline {name}")
    contract_workspaces = unique(run_spec.get("requiredWorkspaces", []), "name", "RunContract workspace")
    if set(contract_workspaces) != set(pipeline_workspaces):
        raise ContractError(f"RunContract workspace coverage mismatch for Pipeline {name}")
    if name == "build-and-publish":
        build_identity = task_identities["build"]
        if build_identity.get("serviceAccountName") != "tekton-image-push":
            raise ContractError("build task lacks the dedicated image-push ServiceAccount")
        pod = build_identity.get("podTemplate", {})
        if pod.get("nodeSelector") != {"ecommerce.dev/workload": "ci-build"}:
            raise ContractError("BuildKit nodeSelector differs from contract")
        tolerations = pod.get("tolerations", [])
        if not any(item.get("key") == "ecommerce.dev/ci-build" for item in tolerations):
            raise ContractError("BuildKit toleration differs from contract")


def validate_source_immutability(tasks: dict[str, dict], pipelines: dict[str, dict]) -> None:
    pipeline = pipelines["build-and-publish"]
    pipeline_tasks = unique(pipeline["spec"]["tasks"], "name", "build pipeline task")
    mappings = {
        name: {item["name"]: item["workspace"] for item in task.get("workspaces", [])}
        for name, task in pipeline_tasks.items()
    }
    if mappings["clone"] != {"source": "source", "source-snapshot": "source-snapshot"}:
        raise ContractError("clone does not exclusively populate source and source-snapshot")
    if mappings["test"] != {"source": "source"}:
        raise ContractError("test can access a workspace other than source")
    if mappings["source-security"] != {"source": "source", "evidence": "evidence"}:
        raise ContractError("source-security workspace contract is invalid")
    if mappings["build"] != {"source-snapshot": "source-snapshot"}:
        raise ContractError("BuildKit does not exclusively consume source-snapshot")
    if not unique(tasks["go-test"]["spec"]["workspaces"], "name", "workspace")["source"].get("readOnly"):
        raise ContractError("go-test source workspace is writable")
    if not unique(tasks["source-security"]["spec"]["workspaces"], "name", "workspace")["source"].get("readOnly"):
        raise ContractError("source-security source workspace is writable")
    if not unique(tasks["build-push"]["spec"]["workspaces"], "name", "workspace")["source-snapshot"].get("readOnly"):
        raise ContractError("build source snapshot is writable")
    promotion_workspaces = unique(
        tasks["gitops-propose-promotion"]["spec"]["workspaces"], "name", "workspace"
    )
    if not promotion_workspaces["git-auth"].get("readOnly"):
        raise ContractError("Git credential workspace is writable")
    build_steps = unique(tasks["build-push"]["spec"]["steps"], "name", "build step")
    build_mounts = unique(build_steps["build-and-push"].get("volumeMounts", []), "name", "volume mount")
    if not build_mounts.get("build-context", {}).get("readOnly"):
        raise ContractError("BuildKit build context volume is writable")


def validate_all(tekton_root: Path) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    tasks, pipelines, contracts = load_repository(tekton_root)
    validate_task_sources(tasks)
    if set(pipelines) != set(contracts):
        raise ContractError("every Pipeline must have exactly one RunContract")
    for name, pipeline in pipelines.items():
        validate_pipeline(name, pipeline, tasks, contracts[name])
    validate_source_immutability(tasks, pipelines)
    return tasks, pipelines, contracts


def self_test(tekton_root: Path) -> None:
    tasks, pipelines, contracts = validate_all(tekton_root)
    mutations = []

    extra_workspace = copy.deepcopy(pipelines)
    extra_workspace["build-and-publish"]["spec"]["tasks"][0]["workspaces"].append(
        {"name": "evidence", "workspace": "evidence"}
    )
    mutations.append(("extra workspace", tasks, extra_workspace, contracts))

    missing_workspace = copy.deepcopy(pipelines)
    missing_workspace["build-and-publish"]["spec"]["tasks"][2]["workspaces"] = [
        {"name": "source", "workspace": "source"}
    ]
    mutations.append(("missing workspace", tasks, missing_workspace, contracts))

    unknown_task = copy.deepcopy(pipelines)
    unknown_task["build-and-publish"]["spec"]["tasks"][0]["taskRef"]["name"] = "missing-task"
    mutations.append(("unknown TaskRef", tasks, unknown_task, contracts))

    unknown_result = copy.deepcopy(pipelines)
    unknown_result["build-and-publish"]["spec"]["results"][0]["value"] = "$(tasks.clone.results.UNKNOWN)"
    mutations.append(("unknown Result", tasks, unknown_result, contracts))

    bad_run_after = copy.deepcopy(pipelines)
    bad_run_after["build-and-publish"]["spec"]["tasks"][1]["runAfter"] = ["missing"]
    mutations.append(("unknown runAfter", tasks, bad_run_after, contracts))

    bad_identity = copy.deepcopy(contracts)
    bad_identity["build-and-publish"]["spec"]["taskRunSpecs"][1]["serviceAccountName"] = "tekton-image-push"
    mutations.append(("privileged ServiceAccount on test", tasks, pipelines, bad_identity))

    for label, mutated_tasks, mutated_pipelines, mutated_contracts in mutations:
        try:
            validate_task_sources(mutated_tasks)
            for name, pipeline in mutated_pipelines.items():
                validate_pipeline(name, pipeline, mutated_tasks, mutated_contracts[name])
            validate_source_immutability(mutated_tasks, mutated_pipelines)
        except ContractError:
            continue
        raise ContractError(f"self-test mutation was accepted: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--tekton-root",
        type=Path,
        default=Path("gitops/infrastructure/tekton-ci"),
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test(args.tekton_root)
        else:
            validate_all(args.tekton_root)
        print("Tekton Pipeline/Task/RunContract graph validated")
        return 0
    except (ContractError, OSError, yaml.YAMLError, KeyError, TypeError) as exc:
        print(f"Tekton contract validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
