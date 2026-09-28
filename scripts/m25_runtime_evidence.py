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
except ModuleNotFoundError:
    from scripts import rocky_box_catalog


VM_NAME = re.compile(r"^ecommerce-mgmt-test-[a-z0-9-]+$")
UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
OUTPUT = Path(".context/evidence/roadmap/M2-5-persistent-mgmt-bootstrap.json")
IMAGE = Path(".context/evidence/rocky-image/rocky-10.2/windows")


def _paths(vm_name: str) -> dict[str, Path]:
    if not VM_NAME.fullmatch(vm_name):
        raise ValueError("invalid M2.5 fixture name")
    state = Path(".context/mgmt-offline-vm") / vm_name
    return {
        "image_build": IMAGE / "build.json",
        "image_qualification": IMAGE / "qualification.json",
        "image_release": IMAGE / "release.json",
        "native_import": IMAGE / "native-import.json",
        "server_source": state / "server-source.json",
        "rke2_result": state / "rke2-result.json",
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
    _require(evidence.get("box_sha256") == manifest["box_sha256"]
             and evidence.get("inputs_digest") == manifest["inputs_digest"],
             "M2.5 Rocky box digest or semantic inputs differ")
    sources = _sources(root, evidence)
    build = sources["image_build"]
    qualified = sources["image_qualification"]
    release = sources["image_release"]
    native_import = sources["native_import"]
    for name, payload in (("image build", build), ("image qualification", qualified),
                          ("image release", release)):
        _require(payload.get("status") == "PASS" and payload.get("source_sha") == head,
                 f"M2.5 {name} is not exact PASS")
    _require(build.get("source_tree") == tree and build.get("sha256") == manifest["box_sha256"]
             and build.get("artifact") == filename and build.get("virtualbox_backend") == "NATIVE_VTX"
             and build.get("virtualbox_version") == vbox_version
             and build.get("packer_build") in {"PASS", "REUSED"},
             "M2.5 image build is not the exact native box")
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
             and native_import.get("source_git_sha") == head
             and native_import.get("source_tree_sha") == tree
             and native_import.get("artifact_sha256") == manifest["box_sha256"]
             and native_import.get("virtualbox_backend") == "NATIVE_VTX"
             and native_import.get("wsl2_restored") == "PASS"
             and native_import.get("bcd_restored") == "PASS",
             "M2.5 native import is incomplete")
    source = sources["server_source"]
    rke2 = sources["rke2_result"]
    role = sources["role_result"]
    tamper = sources["tamper_result"]
    campaign = sources["campaign_result"]
    lock = json.loads((root / "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json").read_text(encoding="utf-8"))
    _require(source.get("git_sha") == head, "M2.5 RKE2 source SHA differs")
    _require(role.get("exit_code") == 0
             and role.get("vm_uuid") == identity["id"]
             and role.get("bundle_manifest_sha256") == lock["approved_manifest_sha256"],
             "M2.5 offline role or VM identity differs")
    _require(rke2.get("node_ready") is True and rke2.get("cilium_ready") == 1
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
             and campaign.get("manifest_sha256") == lock["approved_manifest_sha256"]
             and isinstance(actions, list)
             and [item.get("action") for item in actions if isinstance(item, dict)] == [
                 "validate", "create", "test", "server", "server", "restage",
                 "tamper", "restage", "server", "destroy",
             ]
             and len(actions) == 10
             and all(item.get("status") == "PASS"
                     and isinstance(item.get("duration_seconds"), (int, float))
                     and item["duration_seconds"] >= 0 for item in actions),
             "M2.5 RKE2 campaign sequence is incomplete")
    servers = [item for item in actions if item["action"] == "server"]
    _require([item.get("install_required") for item in servers] == [True, False, True]
             and all(item.get("vm_uuid") == identity["id"] for item in servers),
             "M2.5 RKE2 replay is not idempotent on the same VM")


def create(root: Path, head: str, tree: str, vm_name: str) -> Path:
    paths = _paths(vm_name)
    refs = {name: {"path": path.as_posix(), "sha256": _digest(root / path)}
            for name, path in paths.items()}
    role = json.loads((root / paths["role_result"]).read_text(encoding="utf-8"))
    manifest = rocky_box_catalog.verify(rocky_box_catalog.find_matching_box(head), head)
    payload = {
        "schema_version": 1, "status": "PASS", "exact_commit_evidence": True,
        "runtime_execution": True, "head_sha": head, "head_tree_sha": tree,
        "created_at_epoch": int(datetime.now(timezone.utc).timestamp()),
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
