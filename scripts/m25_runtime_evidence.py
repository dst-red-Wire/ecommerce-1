"""Derive M2.5 lab proof only from retained exact-source runtime results."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

try:
    import rocky_box_catalog
    import qualification_steps
except ModuleNotFoundError:
    from scripts import rocky_box_catalog, qualification_steps


VM_NAME = re.compile(r"^ecommerce-mgmt-test-[a-z0-9-]+$")
UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
OUTPUT = Path(".context/evidence/roadmap/M2-5-persistent-mgmt-bootstrap.json")
IMAGE = Path(".context/evidence/rocky-image/rocky-10.2/windows")
NETWORK_SMOKE = Path(".context/evidence/network-smoke/current.json")
NETWORK_RUNNER_FILES = (
    "LabNetworkSmoke.ps1", "RockyImagePipeline.psm1", "NativeVagrantSshSmoke.ps1",
    "LabNetworkSeed.ps1", "LabSshIdentity.ps1", "local-services-seed-server.ps1",
)


def _paths(vm_name: str) -> dict[str, Path]:
    if not VM_NAME.fullmatch(vm_name):
        raise ValueError("invalid M2.5 fixture name")
    state = Path(".context/mgmt-offline-vm") / vm_name
    return {
        "image_build": IMAGE / "build.json",
        "image_qualification": IMAGE / "qualification.json",
        "image_release": IMAGE / "release.json",
        "native_import": IMAGE / "native-import.json",
        "native_result": IMAGE / "native-result.json",
        "image_reuse": IMAGE / "reuse.json",
        "current_network_smoke": NETWORK_SMOKE,
        "backend_probe": state / "backend-probe.json",
        "vm_preflight": state / "preflight.json",
        "server_source": state / "server-source.json",
        "rke2_result": state / "rke2-result.json",
        "cold_role_result": state / "cold-role-result.json",
        "role_result": state / "role-result.json",
        "tamper_result": state / "tamper-result.json",
        "campaign_result": state / "campaign-result.json",
    }


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _sources(root: Path, evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    vm_name = evidence.get("vm_name")
    _require(isinstance(vm_name, str), "M2.5 VM name missing")
    refs = evidence.get("source_evidence")
    _require(isinstance(refs, dict), "M2.5 source evidence missing")
    expected = _paths(vm_name)
    _require(set(refs) == set(expected), "M2.5 source evidence set is incomplete")
    values = {}
    for name, relative in expected.items():
        ref = refs[name]
        _require(isinstance(ref, dict) and ref.get("path") == relative.as_posix(),
                 f"M2.5 {name} path differs from canonical fixture")
        path = root / relative
        _require(path.resolve().is_relative_to(root.resolve())
                 and path.is_file() and not path.is_symlink(),
                 f"M2.5 {name} is missing or escapes the repository")
        _require(ref.get("sha256") == _digest(path), f"M2.5 {name} digest differs")
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"M2.5 {name} is not JSON") from exc
        _require(isinstance(payload, dict), f"M2.5 {name} is not an object")
        values[name] = payload
    return values


def validate_current_smoke(root: Path, smoke: dict[str, Any], head: str, manifest: dict[str, Any]) -> None:
    """Require the exact current runner and its native guest-security result."""
    runner_files = smoke.get("resume_runner_files")
    _require(isinstance(runner_files, dict) and set(runner_files) == set(NETWORK_RUNNER_FILES),
             "M2.5 current network runner inventory is incomplete")
    for name in NETWORK_RUNNER_FILES:
        runner = root / "scripts/windows" / name
        _require(runner.is_file() and runner_files[name] == _digest(runner),
                 f"M2.5 current network runner bytes differ: {name}")
    smoke_checks = smoke.get("network_smoke")
    smoke_packer = smoke.get("packer")
    smoke_cleanup = smoke.get("cleanup")
    smoke_checkpoints = smoke.get("checkpoints")
    smoke_vm = smoke.get("vm_name")
    _require(isinstance(smoke.get("campaign_id"), str)
             and re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}", smoke["campaign_id"]) is not None
             and isinstance(smoke_vm, str)
             and re.fullmatch(r"ecommerce-rocky-10-2-smoke-[0-9a-f]{12}", smoke_vm) is not None
             and smoke.get("resume_runner_source_sha") == head
             and smoke.get("status") == "PASS"
             and smoke.get("virtualbox_backend") == "NATIVE_VTX"
             and smoke.get("box_digest_verified") == "PASS"
             and smoke.get("box_digest") == manifest["box_sha256"]
             and isinstance(smoke_packer, dict)
             and smoke_packer.get("inputs_digest") == manifest["inputs_digest"]
             and smoke.get("guest_security") == "PASS"
             and smoke.get("vm_recreate") == "NOT_REQUIRED"
             and isinstance(smoke_cleanup, dict)
             and smoke_cleanup.get("vm_preserved") is True
             and smoke_cleanup.get("vm_name") == smoke_vm
             and isinstance(smoke_cleanup.get("vm_id"), str)
             and UUID.fullmatch(smoke_cleanup["vm_id"]) is not None
             and isinstance(smoke_checkpoints, dict)
             and all(smoke_checkpoints.get(name) == "PASS" for name in (
                 "03-vm-smoke", "04-network-ssh", "05-rocky-runtime"))
             and isinstance(smoke_checks, dict)
             and smoke_checks.get("vm_name") == smoke_vm
             and smoke_checks.get("tcp_22_ready") == "PASS"
             and smoke_checks.get("ssh_auth_ready") == "PASS"
             and smoke_checks.get("remote_command_ready") == "PASS"
             and smoke_checks.get("rocky_runtime") == "PASS"
             and smoke_checks.get("rocky_version") == "10.2",
             "M2.5 current-head native network and guest-security smoke is incomplete")


def validate(root: Path, evidence: dict[str, Any], head: str, tree: str) -> None:
    """Raise on any missing, stale-by-identity, or contradictory runtime source."""
    _require(evidence.get("head_sha") == head and evidence.get("head_tree_sha") == tree,
             "M2.5 proof has wrong source SHA or tree")
    identity = evidence.get("runtime_identity")
    _require(isinstance(identity, dict) and identity.get("kind") == "virtualbox-vm"
             and isinstance(identity.get("id"), str) and UUID.fullmatch(identity["id"]) is not None,
             "M2.5 VM runtime identity is invalid")
    _require(evidence.get("ready_for_real_provisioning") is True
             and evidence.get("deployment_state") == "NOT_DEPLOYED"
             and evidence.get("paid_resources_created") == 0
             and evidence.get("six_node_rocky_rke2") == "pending-real-target-and-service-inputs",
             "M2.5 deployment boundary is invalid")
    image = yaml.safe_load((root / "config/contracts/machine-image-lock.yaml").read_text(encoding="utf-8"))["packer_image"]
    version = str(image["os"]["version"])
    filename = str(image["outputs"]["rke2"]["virtualbox"])
    vbox_version = str(image["build"]["virtualbox"]["version"])
    _require(version == "10.2" and filename == "rocky-10.2-rke2-virtualbox.box",
             "M2.5 requires the current Rocky 10.2 image contract")
    _require(evidence.get("rocky_version") == version
             and evidence.get("virtualbox_version") == vbox_version
             and evidence.get("native_vtx") == "PASS"
             and evidence.get("nem_detected") is False,
             "M2.5 image identity or native VT-x proof is invalid")
    box = rocky_box_catalog.find_matching_box(head)
    manifest = rocky_box_catalog.verify(box, head)
    current_inputs = rocky_box_catalog.build_inputs(head)
    _require(current_inputs["inputs_digest"] == manifest["inputs_digest"]
             and current_inputs["packer_template_digest"] == manifest["packer_template_digest"],
             "M2.5 semantic image inputs differ from the native artifact")
    _require(evidence.get("box_sha256") == manifest["box_sha256"]
             and evidence.get("inputs_digest") == manifest["inputs_digest"],
             "M2.5 Rocky box digest or semantic inputs differ")
    sources = _sources(root, evidence)
    original_sha = manifest["source_sha"]
    original_tree = rocky_box_catalog.source_tree(original_sha)
    _require(manifest["source_tree_sha"] == original_tree,
             "M2.5 original image source tree differs")
    binding = sources["image_reuse"]
    qualification_steps.validate_checkpoint(
        binding, source_sha=head, input_digest=manifest["inputs_digest"]
    )
    _require(binding["qualification"] == "m2.5" and binding["step"] == "image"
             and binding["status"] == "SKIPPED_REUSED_VERIFIED"
             and binding["artifact_digest"] == manifest["box_sha256"]
             and binding["reused_from"] == {
                 "source_sha": original_sha,
                 "input_digest": manifest["inputs_digest"],
                 "artifact_digest": manifest["box_sha256"],
             }, "M2.5 current image reuse has invalid execution provenance")
    smoke = sources["current_network_smoke"]
    validate_current_smoke(root, smoke, head, manifest)
    build = sources["image_build"]
    qualified = sources["image_qualification"]
    release = sources["image_release"]
    native_import = sources["native_import"]
    native_result = sources["native_result"]
    qualification_sha = build.get("source_sha")
    _require(isinstance(qualification_sha, str)
             and rocky_box_catalog.GIT_SHA.fullmatch(qualification_sha) is not None,
             "M2.5 native image qualification source SHA is invalid")
    qualification_tree = rocky_box_catalog.source_tree(qualification_sha)
    for name, payload in (("image build", build), ("image qualification", qualified),
                          ("image release", release)):
        _require(payload.get("status") == "PASS" and payload.get("source_sha") == qualification_sha,
                 f"M2.5 {name} does not belong to the native image qualification")
    packer_mode = build.get("packer_build")
    native_packer = native_result.get("packer")
    _require(isinstance(native_packer, dict), "M2.5 native Packer result is absent")
    if packer_mode == "PASS":
        _require(qualification_sha == original_sha and native_packer.get("build") == "PASS"
                 and native_result.get("staging_manifest_sha256") == manifest["staging_manifest_sha256"],
                 "M2.5 original Packer execution differs from its immutable manifest")
    elif packer_mode == "REUSED":
        _require(qualification_sha != original_sha
                 and build.get("reuse_source_sha") == original_sha
                 and build.get("packer_inputs_digest") == manifest["inputs_digest"]
                 and native_packer.get("build") == "REUSED"
                 and native_packer.get("reuse_source_sha") == original_sha
                 and native_packer.get("inputs_digest") == manifest["inputs_digest"],
                 "M2.5 native image reuse has invalid original execution provenance")
    else:
        raise ValueError("M2.5 Packer mode is neither an original execution nor verified reuse")
    _require(build.get("source_tree") == qualification_tree and build.get("sha256") == manifest["box_sha256"]
             and build.get("artifact") == filename and build.get("virtualbox_backend") == "NATIVE_VTX"
             and build.get("virtualbox_version") == vbox_version
             and build.get("packer_build") == native_packer.get("build"),
             "M2.5 native image qualification differs from its build result")
    required_image_checks = {"boot", "ssh", "rocky_release", "kernel", "systemd",
                             "rke2_prerequisites", "security", "cleanup", "key_cleanup",
                             "swap_absent", "rpm_profile"}
    image_checks = qualified.get("qualification")
    _require(qualified.get("artifact_sha256") == manifest["box_sha256"]
             and qualified.get("artifact") == filename
             and isinstance(image_checks, dict)
             and all(image_checks.get(key) == "PASS" for key in required_image_checks),
             "M2.5 image qualification is incomplete")
    release_checks = release.get("checks")
    _require(release.get("artifact_sha256") == manifest["box_sha256"]
             and release.get("artifact") == filename
             and isinstance(release_checks, dict)
             and all(release_checks.get(key) == "PASS" for key in (
                 "exact_source_sha", "build_evidence", "checksum", "qualification_evidence",
                 "cleanup", "ephemeral_key_absent", "sbom", "package_manifest", "profile_inventory")),
             "M2.5 image release is incomplete")
    _require(native_import.get("status") == "PASS"
             and native_import.get("source_git_sha") == qualification_sha
             and native_import.get("source_tree_sha") == qualification_tree
             and native_import.get("artifact_sha256") == manifest["box_sha256"]
             and native_import.get("staging_manifest_sha256") == native_result.get("staging_manifest_sha256")
             and native_import.get("virtualbox_backend") == "NATIVE_VTX"
             and native_import.get("wsl2_restored") == "PASS"
             and native_import.get("bcd_restored") == "PASS",
             "M2.5 native import is incomplete")
    _require(native_result.get("status") == "PASS"
             and native_result.get("source_git_sha") == qualification_sha
             and native_result.get("source_tree_sha") == qualification_tree
             and native_result.get("artifact_sha256") == manifest["box_sha256"]
             and re.fullmatch(r"[0-9a-f]{64}", str(native_result.get("staging_manifest_sha256", "")))
             and native_result.get("native_vtx") == "PASS"
             and native_result.get("nem_detected") is False
             and native_result.get("virtualbox_backend") == "NATIVE_VTX"
             and native_packer.get("build") == packer_mode
             and native_result.get("vagrant_smoke", {}).get("rocky_version") == "PASS"
             and "Rocky Linux release 10.2" in str(native_result.get("observations", {}).get("rocky_version", "")),
             "M2.5 original native Rocky 10.2 execution proof is invalid")
    source = sources["server_source"]
    preflight = sources["vm_preflight"]
    rke2 = sources["rke2_result"]
    cold_role = sources["cold_role_result"]
    role = sources["role_result"]
    tamper = sources["tamper_result"]
    campaign = sources["campaign_result"]
    backend_probe = sources["backend_probe"]
    lock = json.loads((root / "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json").read_text(encoding="utf-8"))
    backend_policy = yaml.safe_load(
        (root / "config/contracts/qualification-execution-policy.yaml").read_text(encoding="utf-8")
    )["workflows"]["rke2_local_virtualbox"]["virtualbox_backend_policy"]
    _require(backend_policy == {
        "image_execution_required": "NATIVE_VTX",
        "rke2_functional_allowed": ["NATIVE_VTX", "NEM"],
        "observed_backend_evidence": ".context/mgmt-offline-vm/<name>/backend-probe.json",
    }, "M2.5 VirtualBox backend policy is invalid")
    _require(backend_probe.get("schema_version") == 1 and backend_probe.get("status") == "PASS"
             and backend_probe.get("head_sha") == head
             and backend_probe.get("head_tree_sha") == tree
             and backend_probe.get("box_sha256") == manifest["box_sha256"]
             and backend_probe.get("vm_uuid") == identity["id"]
             and backend_probe.get("virtualbox_backend") in backend_policy["rke2_functional_allowed"]
             and str(backend_probe.get("virtualbox_version", "")).startswith(vbox_version + "r")
             and type(backend_probe.get("hypervisor_present")) is bool
             and (backend_probe["virtualbox_backend"] != "NATIVE_VTX"
                  or backend_probe["hypervisor_present"] is False)
             and (backend_probe["virtualbox_backend"] != "NEM"
                  or backend_probe["hypervisor_present"] is True)
             and type(backend_probe.get("host_logical_processors")) is int
             and backend_probe["host_logical_processors"] >= 4
             and backend_probe.get("vm_cpus") == 4
             and type(campaign.get("vm_memory_mib")) is int
             and 4096 <= campaign["vm_memory_mib"] <= 16384
             and backend_probe.get("vm_memory_mib") == campaign["vm_memory_mib"]
             and re.fullmatch(r"[0-9a-f]{64}", str(backend_probe.get("virtualbox_log_sha256", ""))),
             "M2.5 observed RKE2 VirtualBox backend or host capacity is invalid")
    _require(source.get("git_sha") == head, "M2.5 RKE2 source SHA differs")
    _require(preflight.get("rocky_release") == "Rocky Linux release 10.2 (Red Quartz)"
             and isinstance(preflight.get("kernel"), str) and bool(preflight["kernel"])
             and preflight.get("systemd") == "running"
             and preflight.get("selinux") == "Enforcing"
             and preflight.get("online_cpus") == 4
             and type(preflight.get("memory_kib")) is int
             and preflight["memory_kib"] >= campaign["vm_memory_mib"] * 1024 * 85 // 100
             and preflight.get("nft_policies") == {"output": "drop", "forward": "drop"}
             and preflight.get("public_connect_errno") == 101
             and preflight.get("cold_artifact_target") is True,
             "M2.5 cold Rocky VM preflight is incomplete")
    _require(role.get("exit_code") == 0
             and role.get("vm_uuid") == identity["id"]
             and role.get("bundle_manifest_sha256") == lock["approved_manifest_sha256"],
             "M2.5 offline role or VM identity differs")
    cold_trial = cold_role.get("trial")
    _require(cold_role.get("exit_code") == 0
             and cold_role.get("vm_uuid") == identity["id"]
             and cold_role.get("bundle_manifest_sha256") == lock["approved_manifest_sha256"]
             and isinstance(cold_trial, dict)
             and cold_trial.get("vm_uuid") == identity["id"]
             and cold_trial.get("boot_id") == preflight.get("boot_id")
             and cold_trial.get("cold_trial") is True
             and cold_trial.get("previous_attempt") is False,
             "M2.5 initial cold offline installation is not preserved")
    _require(rke2.get("node_ready") is True and rke2.get("cilium_ready") == 1
             and rke2.get("rke2_service") == "active"
             and rke2.get("selinux") == "Enforcing"
             and rke2.get("nft_policies") == {"output": "drop", "forward": "drop"}
             and rke2.get("public_connect_error") is not None
             and lock["rke2_version"] in str(rke2.get("rke2_version", "")),
             "M2.5 RKE2/Cilium runtime proof is incomplete")
    mutation = tamper.get("mutation")
    _require(tamper.get("blocked_task") == "Revalidate every staged byte immediately before privileged installation"
             and tamper.get("rke2_service") in {"inactive", "failed", "unknown"}
             and isinstance(mutation, dict)
             and all(isinstance(mutation.get(key), str)
                     and re.fullmatch(r"[0-9a-f]{64}", mutation[key]) for key in ("before_sha256", "after_sha256"))
             and mutation["before_sha256"] != mutation["after_sha256"],
             "M2.5 tampered artifact was not rejected")
    actions = campaign.get("actions")
    _require(campaign.get("schema_version") == 1 and campaign.get("status") == "PASS"
             and campaign.get("head_sha") == head and campaign.get("head_tree_sha") == tree
             and campaign.get("vm_uuid") == identity["id"]
             and campaign.get("box_sha256") == manifest["box_sha256"]
             and campaign.get("virtualbox_backend") == backend_probe["virtualbox_backend"]
             and campaign.get("manifest_sha256") == lock["approved_manifest_sha256"]
             and isinstance(actions, list)
             and [item.get("action") for item in actions if isinstance(item, dict)] == [
                 "validate", "create", "diagnostics", "test", "server", "server", "restage",
                 "tamper", "restage", "server", "destroy",
             ]
             and len(actions) == 11
             and all(item.get("status") == "PASS"
                     and isinstance(item.get("duration_seconds"), (int, float))
                     and item["duration_seconds"] >= 0 for item in actions),
             "M2.5 RKE2 campaign sequence is incomplete")
    servers = [item for item in actions if item["action"] == "server"]
    _require([item.get("install_required") for item in servers] == [True, False, True]
             and all(item.get("vm_uuid") == identity["id"] for item in servers),
             "M2.5 RKE2 replay is not idempotent on the same VM")
    max_age = yaml.safe_load((root / "config/contracts/roadmap-policy.yaml").read_text(encoding="utf-8"))[
        "status_derivation"]["evidence_max_age_seconds"]
    campaign_epoch = campaign.get("created_at_epoch")
    current_epoch = int(datetime.now(timezone.utc).timestamp())
    _require(type(max_age) is int and max_age > 0
             and type(campaign_epoch) is int
             and evidence.get("created_at_epoch") == campaign_epoch
             and 0 <= current_epoch - campaign_epoch <= max_age,
             "M2.5 source campaign is stale or has been re-dated")
    try:
        smoke_time = datetime.fromisoformat(str(smoke.get("completed_at", "")).replace("Z", "+00:00"))
        _require(smoke_time.tzinfo is not None, "M2.5 current smoke completion time lacks timezone")
        smoke_epoch = int(smoke_time.timestamp())
    except (TypeError, ValueError) as exc:
        raise ValueError("M2.5 current smoke completion time is invalid") from exc
    _require(campaign_epoch - max_age <= smoke_epoch <= campaign_epoch,
             "M2.5 current smoke is stale or later than the RKE2 campaign")


def create(root: Path, head: str, tree: str, vm_name: str) -> Path:
    paths = _paths(vm_name)
    refs = {name: {"path": path.as_posix(), "sha256": _digest(root / path)}
            for name, path in paths.items()}
    role = json.loads((root / paths["role_result"]).read_text(encoding="utf-8"))
    campaign = json.loads((root / paths["campaign_result"]).read_text(encoding="utf-8"))
    manifest = rocky_box_catalog.verify(rocky_box_catalog.find_matching_box(head), head)
    payload = {
        "schema_version": 1, "status": "PASS", "exact_commit_evidence": True,
        "runtime_execution": True, "head_sha": head, "head_tree_sha": tree,
        "created_at_epoch": campaign["created_at_epoch"],
        "milestone": "M2.5", "environment": "lab",
        "runtime_identity": {"kind": "virtualbox-vm", "id": role["vm_uuid"]},
        "outcome": "PASS", "vm_name": vm_name, "source_evidence": refs,
        "rocky_version": manifest["rocky_version"],
        "virtualbox_version": manifest["virtualbox_version"],
        "box_sha256": manifest["box_sha256"], "inputs_digest": manifest["inputs_digest"],
        "native_vtx": manifest["native_vtx"], "nem_detected": manifest["nem_detected"],
        "ready_for_real_provisioning": True, "deployment_state": "NOT_DEPLOYED",
        "paid_resources_created": 0,
        "six_node_rocky_rke2": "pending-real-target-and-service-inputs",
    }
    validate(root, payload, head, tree)
    destination = root / OUTPUT
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination
