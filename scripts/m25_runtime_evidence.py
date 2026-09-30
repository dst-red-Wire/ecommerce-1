"""Derive M2.5 lab proof only from retained exact-source runtime results."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any

import yaml

try:
    import rocky_box_catalog
    import qualification_steps
    import rke2_virtualbox_backend
except ModuleNotFoundError:
    from scripts import rocky_box_catalog, qualification_steps, rke2_virtualbox_backend


VM_NAME = re.compile(r"^ecommerce-mgmt-test-[a-z0-9-]+$")
UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
OUTPUT = Path(".context/evidence/roadmap/M2-5-persistent-mgmt-bootstrap.json")
IMAGE = Path(".context/evidence/rocky-image/rocky-10.2/windows")
NETWORK_SMOKE = Path(".context/evidence/network-smoke/current.json")
SHADOW_ROOT = Path("/mnt/c/Program Files/EcommerceNativeSmoke")
SHADOW_WINDOWS_ROOT = PureWindowsPath(r"C:\Program Files\EcommerceNativeSmoke")
NETWORK_RUNNER_FILES = (
    "LabNativeBoot.ps1", "LabNetworkSmoke.ps1", "RockyImagePipeline.psm1", "NativeVagrantSshSmoke.ps1",
    "LabNetworkSeed.ps1", "LabSshIdentity.ps1", "local-services-seed-server.ps1",
)
RKE2_SERVER_SOURCE_FILES = (
    "platform/ansible/tests/mgmt_offline_vm/server.yml",
    "platform/ansible/tests/mgmt_offline_vm/rke2_probe.py",
    "platform/ansible/tests/mgmt_offline_vm/private_interface.py",
    "platform/ansible/tests/mgmt_offline_vm/virtualbox_probe.py",
    "platform/ansible/roles/rke2_server/tasks/main.yml",
    "platform/ansible/roles/mgmt_private_network/templates/mgmt-egress.nft.j2",
    "scripts/mgmt_airgap.py",
)
IMAGE_CHECKS = (
    "rocky_release", "kernel", "architecture_cpu", "memory", "disk", "xfs",
    "lvm_absent", "swap_absent", "rpm_profile", "systemd", "network",
    "fundamental_tools", "rke2_prerequisites", "security", "package_inventory",
    "supply_chain",
)


def _paths(vm_name: str) -> dict[str, Path]:
    if not VM_NAME.fullmatch(vm_name):
        raise ValueError("invalid M2.5 fixture name")
    state = Path(".context/mgmt-offline-vm") / vm_name
    return {
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
        try:
            data = path.read_bytes()
            _require(ref.get("sha256") == hashlib.sha256(data).hexdigest(),
                     f"M2.5 {name} digest differs")
            payload = json.loads(data.decode("utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"M2.5 {name} is not JSON") from exc
        _require(isinstance(payload, dict), f"M2.5 {name} is not an object")
        values[name] = payload
    return values


def validate_protected_smoke(
    root: Path, smoke: dict[str, Any], smoke_digest: str, head: str, tree: str,
    manifest: dict[str, Any],
) -> None:
    """Bind the imported result to the recovered, protected native boot run."""
    campaign = smoke["campaign_id"]
    shadow = SHADOW_ROOT / f"{campaign}-{head}"
    boot_path = shadow / "native-boot.json"
    result_path = shadow / "evidence/network-smoke" / campaign / "result.json"
    runner_path = shadow / f"runner-{head}" / "runner.json"
    _require(SHADOW_ROOT.is_dir() and not SHADOW_ROOT.is_symlink(),
             "M2.5 protected native smoke root is absent")
    resolved_root = SHADOW_ROOT.resolve(strict=True)
    for path in (shadow, boot_path, result_path, runner_path):
        _require(not path.is_symlink() and path.resolve().is_relative_to(resolved_root),
                 "M2.5 protected native smoke path is redirected")
    _require(shadow.is_dir() and all(path.is_file() for path in (boot_path, result_path, runner_path)),
             "M2.5 protected native smoke proof is missing")
    try:
        boot = json.loads(boot_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("M2.5 protected native boot state is malformed") from exc
    _require(isinstance(boot, dict), "M2.5 protected native boot state is not an object")
    expected_shadow = SHADOW_WINDOWS_ROOT / f"{campaign}-{head}"
    _require(boot.get("mode") == "NETWORK_SMOKE_NATIVE"
             and boot.get("phase") == "RECOVERED" and boot.get("run_status") == "PASS"
             and boot.get("campaign_id") == campaign
             and boot.get("source_sha") == head and boot.get("source_tree_sha") == tree
             and boot.get("vm_name") == smoke["vm_name"]
             and boot.get("vm_id") == smoke["cleanup"]["vm_id"]
             and boot.get("box_sha256") == manifest["box_sha256"]
             and PureWindowsPath(str(boot.get("shadow_root", ""))) == expected_shadow
             and boot.get("result_sha256") == smoke_digest == _digest(result_path)
             and boot.get("runner_manifest_sha256") == _digest(runner_path),
             "M2.5 current smoke differs from its protected recovered native run")
    qualification = smoke.get("image_qualification")
    _require(isinstance(qualification, dict)
             and qualification.get("status") == "PASS"
             and qualification.get("source_sha") == head
             and qualification.get("source_tree_sha") == tree
             and qualification.get("box_sha256") == manifest["box_sha256"]
             and qualification.get("vm_id") == smoke["cleanup"]["vm_id"]
             and qualification.get("virtualbox_backend") == "NATIVE_VTX",
             "M2.5 current-head native image qualification identity is invalid")
    checks = qualification.get("checks")
    observations = qualification.get("observations")
    _require(isinstance(checks, dict) and set(checks) == set(IMAGE_CHECKS)
             and all(checks[name] == "PASS" for name in IMAGE_CHECKS)
             and isinstance(observations, dict) and set(observations) == set(IMAGE_CHECKS),
             "M2.5 native image qualification checks are incomplete")
    for name in IMAGE_CHECKS:
        observation = observations[name]
        _require(isinstance(observation, dict)
                 and observation.get("status") == "PASS"
                 and type(observation.get("exit_code")) is int
                 and observation["exit_code"] == 0
                 and isinstance(observation.get("stdout"), str)
                 and bool(observation["stdout"])
                 and isinstance(observation.get("stderr"), str)
                 and type(observation.get("stdout_truncated")) is bool,
                 f"M2.5 native image qualification observation is invalid: {name}")
    package_lock = root / "config/artifacts/rocky-10.2-base-packages.lock.json"
    _require(qualification.get("package_lock_sha256") == _digest(package_lock),
             "M2.5 native image package lock differs from current source")
    lock = json.loads(package_lock.read_text(encoding="utf-8"))
    profiles = lock.get("profiles") if isinstance(lock, dict) else None
    base = profiles.get("base") if isinstance(profiles, dict) else None
    rke2_profile = profiles.get("rke2") if isinstance(profiles, dict) else None
    base_roots = base.get("roots") if isinstance(base, dict) else None
    rke2_roots = rke2_profile.get("roots") if isinstance(rke2_profile, dict) else None
    _require(isinstance(base_roots, list) and isinstance(rke2_roots, list),
             "M2.5 current image package roots are malformed")
    roots = base_roots + rke2_roots
    _require(isinstance(roots, list) and len(roots) >= 10
             and all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9+_.-]+", name)
                     for name in roots)
             and len(set(roots)) == len(roots),
             "M2.5 current image package roots are invalid")
    supply = qualification.get("supply_chain")
    _require(isinstance(supply, dict) and supply.get("artifact_sha256") == manifest["box_sha256"],
             "M2.5 native image supply-chain artifact is invalid")
    package_manifest = supply.get("package_manifest")
    profile = supply.get("profile_inventory")
    sbom = supply.get("sbom")
    _require(isinstance(package_manifest, dict)
             and package_manifest.get("format") == "rpm-nevra-v1"
             and isinstance(profile, dict) and profile.get("profile") == "rke2"
             and isinstance(sbom, dict) and sbom.get("bomFormat") == "CycloneDX"
             and sbom.get("specVersion") == "1.5"
             and type(sbom.get("version")) is int and sbom["version"] == 1,
             "M2.5 native image supply-chain format is invalid")
    required = profile.get("required_packages")
    packages = package_manifest.get("packages")
    components = sbom.get("components")
    _require(isinstance(required, list) and len(required) == len(roots)
             and all(isinstance(name, str) for name in required)
             and set(required) == set(roots)
             and isinstance(packages, list) and len(packages) >= 50
             and all(isinstance(line, str) for line in packages)
             and len(set(packages)) == len(packages)
             and isinstance(components, list) and len(components) == len(packages),
             "M2.5 native image RPM inventory is invalid")
    installed: set[str] = set()
    for line, component in zip(packages, components, strict=True):
        _require(isinstance(line, str), "M2.5 native image RPM entry is malformed")
        entry = re.fullmatch(r"([A-Za-z0-9+_.-]+)\|([^\s|]+)", line)
        _require(entry is not None and isinstance(component, dict)
                 and component.get("type") == "library"
                 and component.get("name") == entry.group(1)
                 and component.get("version") == entry.group(2),
                 "M2.5 native image SBOM differs from its RPM inventory")
        installed.add(entry.group(1))
    _require(set(roots) <= installed, "M2.5 native image required RPMs are absent")
    metadata = sbom.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    hashes = component.get("hashes") if isinstance(component, dict) else None
    _require(isinstance(component, dict) and component.get("type") == "file"
             and component.get("name") == "rocky-10.2-rke2-virtualbox.box"
             and isinstance(hashes, list) and len(hashes) == 1
             and isinstance(hashes[0], dict) and hashes[0] == {
                 "alg": "SHA-256", "content": manifest["box_sha256"]},
             "M2.5 native image SBOM artifact binding is invalid")
    relative_log = qualification.get("virtualbox_log_relative")
    _require(isinstance(relative_log, str)
             and re.fullmatch(r"logs/ssh-resume-[0-9]{8}T[0-9]{6}Z/VBox\.log", relative_log),
             "M2.5 native VirtualBox log path is invalid")
    log_path = shadow / campaign / relative_log
    _require(not log_path.is_symlink() and log_path.resolve().is_relative_to(shadow.resolve())
             and log_path.is_file() and log_path.stat().st_size <= 16 * 1024 * 1024
             and qualification.get("virtualbox_log_sha256") == _digest(log_path),
             "M2.5 native VirtualBox log digest is invalid")
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    _require(re.search(r"Attempting fall back to NEM|\bNEM:|WHvCapabilityCodeHypervisorPresent",
                       log_text, re.IGNORECASE | re.MULTILINE) is None
             and re.search(r"\bHM:.*(?:VT-x|AMD-V)", log_text,
                           re.IGNORECASE | re.MULTILINE) is not None,
             "M2.5 native VirtualBox log does not prove VT-x")


def validate_current_smoke(root: Path, smoke: dict[str, Any], head: str, manifest: dict[str, Any]) -> None:
    """Require the exact current runner and its native guest-security result."""
    _require(isinstance(smoke, dict), "M2.5 current network smoke is malformed")
    runner_files = smoke.get("resume_runner_files")
    _require(isinstance(runner_files, dict) and set(runner_files) == set(NETWORK_RUNNER_FILES),
             "M2.5 current network runner inventory is incomplete")
    for name in NETWORK_RUNNER_FILES:
        runner = root / "scripts/windows" / name
        _require(runner.is_file() and runner_files[name] == _digest(runner),
                 f"M2.5 current network runner bytes differ: {name}")
    vagrantfile = root / "platform/vagrant/rocky-image-smoke/Vagrantfile"
    _require(vagrantfile.is_file()
             and smoke.get("resume_vagrantfile_sha256") == _digest(vagrantfile),
             "M2.5 retained VM Vagrantfile differs from the current source")
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
             and smoke_packer.get("status") == "REUSED"
             and smoke_packer.get("build") == "NOT_EXECUTED"
             and smoke_packer.get("inputs_digest") == manifest["inputs_digest"]
             and smoke.get("guest_security") == "PASS"
             and smoke.get("vm_recreate") == "NOT_REQUIRED"
             and smoke.get("vm_restart") in {"NOT_REQUIRED", "EXECUTED_EXISTING_VM"}
             and smoke.get("resume_seed_server") in {"PASS", "NOT_REQUIRED"}
             and (smoke.get("vm_restart") != "EXECUTED_EXISTING_VM"
                  or smoke.get("resume_seed_server") == "PASS")
             and isinstance(smoke_cleanup, dict)
             and smoke_cleanup.get("status") == "PASS"
             and smoke_cleanup.get("seed_server") == "PASS"
             and smoke_cleanup.get("lock") == "PASS"
             and smoke_cleanup.get("vm_preserved") is True
             and smoke_cleanup.get("vm_name") == smoke_vm
             and isinstance(smoke_cleanup.get("vm_id"), str)
             and UUID.fullmatch(smoke_cleanup["vm_id"]) is not None
             and isinstance(smoke_checkpoints, dict)
             and all(smoke_checkpoints.get(name) == "PASS" for name in (
                 "03-vm-smoke", "04-network-ssh", "05-rocky-runtime",
                 "06-image-qualification"))
             and smoke.get("resume_from") == "downstream-qualification"
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
    _require(type(evidence.get("schema_version")) is int and evidence["schema_version"] == 1
             and evidence.get("status") == "PASS"
             and evidence.get("milestone") == "M2.5" and evidence.get("environment") == "lab"
             and evidence.get("outcome") == "PASS"
             and evidence.get("exact_commit_evidence") is True
             and evidence.get("runtime_execution") is True,
             "M2.5 lab evidence identity or outcome is invalid")
    _require(evidence.get("head_sha") == head and evidence.get("head_tree_sha") == tree,
             "M2.5 proof has wrong source SHA or tree")
    identity = evidence.get("runtime_identity")
    _require(isinstance(identity, dict) and identity.get("kind") == "virtualbox-vm"
             and isinstance(identity.get("id"), str) and UUID.fullmatch(identity["id"]) is not None,
             "M2.5 VM runtime identity is invalid")
    _require(evidence.get("ready_for_real_provisioning") is True
             and evidence.get("deployment_state") == "NOT_DEPLOYED"
             and type(evidence.get("paid_resources_created")) is int
             and evidence["paid_resources_created"] == 0
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
    validate_protected_smoke(
        root, smoke, evidence["source_evidence"]["current_network_smoke"]["sha256"],
        head, tree, manifest,
    )
    execution = evidence.get("original_image_execution")
    _require(isinstance(execution, dict) and execution == {
        "source_sha": original_sha,
        "source_tree_sha": original_tree,
        "packer_build": "PASS",
        "packer_log_sha256": manifest["packer_log_sha256"],
    } and manifest["packer_build"] == "PASS"
             and manifest["native_vtx"] == "PASS" and manifest["nem_detected"] is False,
             "M2.5 original Packer/native execution provenance is invalid")
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
    _require(type(backend_probe.get("schema_version")) is int
             and backend_probe["schema_version"] == 1
             and backend_probe.get("status") == "PASS"
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
    backend_log = root / ".context/mgmt-offline-vm" / evidence["vm_name"] / "backend-VBox.log"
    _require(backend_log.is_file() and not backend_log.is_symlink()
             and backend_log.resolve().is_relative_to(root.resolve())
             and 0 < backend_log.stat().st_size <= 16 * 1024 * 1024,
             "M2.5 RKE2 VirtualBox backend log snapshot is missing or redirected")
    backend_log_bytes = backend_log.read_bytes()
    _require(hashlib.sha256(backend_log_bytes).hexdigest() == backend_probe["virtualbox_log_sha256"],
             "M2.5 RKE2 VirtualBox backend log digest differs")
    _require(rke2_virtualbox_backend.classify_log(
        backend_log_bytes.decode("utf-8", errors="replace")) == backend_probe["virtualbox_backend"],
        "M2.5 RKE2 VirtualBox backend log classification differs")
    _require(source.get("git_sha") == head, "M2.5 RKE2 source SHA differs")
    expected_server_hashes = [
        f"{_digest(root / relative)}  {(root / relative).resolve()}"
        for relative in RKE2_SERVER_SOURCE_FILES
    ]
    _require(source.get("source_sha256") == expected_server_hashes,
             "M2.5 RKE2 server source bytes differ from their recorded execution")
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
    _require(type(role.get("exit_code")) is int and role["exit_code"] == 0
             and role.get("vm_uuid") == identity["id"]
             and role.get("bundle_manifest_sha256") == lock["approved_manifest_sha256"],
             "M2.5 offline role or VM identity differs")
    cold_trial = cold_role.get("trial")
    _require(type(cold_role.get("exit_code")) is int and cold_role["exit_code"] == 0
             and cold_role.get("vm_uuid") == identity["id"]
             and cold_role.get("bundle_manifest_sha256") == lock["approved_manifest_sha256"]
             and isinstance(cold_trial, dict)
             and cold_trial.get("vm_uuid") == identity["id"]
             and cold_trial.get("boot_id") == preflight.get("boot_id")
             and cold_trial.get("cold_trial") is True
             and cold_trial.get("previous_attempt") is False,
             "M2.5 initial cold offline installation is not preserved")
    for result in (cold_role, role):
        qualification_steps.validate_transfer_record(
            result.get("transfer"), approved_manifest=lock["approved_manifest_sha256"]
        )
    public_error = rke2.get("public_connect_error")
    _require(rke2.get("node_ready") is True
             and type(rke2.get("cilium_ready")) is int and rke2["cilium_ready"] == 1
             and rke2.get("pending_pods") == []
             and rke2.get("rke2_service") == "active"
             and rke2.get("selinux") == "Enforcing"
             and rke2.get("nft_policies") == {"output": "drop", "forward": "drop"}
             and ((type(public_error) is int and public_error in {1, 101, 110, 113})
                  or public_error == "TimeoutError")
             and lock["rke2_version"] in str(rke2.get("rke2_version", "")),
             "M2.5 RKE2/Cilium runtime proof is incomplete")
    mutation = tamper.get("mutation")
    _require(tamper.get("blocked_task") == "Revalidate every staged byte immediately before privileged installation"
             and tamper.get("rke2_service") in {"inactive", "failed", "unknown"}
             and isinstance(mutation, dict)
             and all(isinstance(mutation.get(key), str)
                     and re.fullmatch(r"[0-9a-f]{64}", mutation[key]) for key in ("before_sha256", "after_sha256"))
             and mutation["before_sha256"] == lock["release_artifacts"]["binary"]["sha256"]
             and mutation["before_sha256"] != mutation["after_sha256"],
             "M2.5 tampered artifact was not rejected")
    actions = campaign.get("actions")
    _require(type(campaign.get("schema_version")) is int
             and campaign["schema_version"] == 1
             and campaign.get("status") == "PASS"
             and campaign.get("head_sha") == head and campaign.get("head_tree_sha") == tree
             and campaign.get("vm_uuid") == identity["id"]
             and campaign.get("box_sha256") == manifest["box_sha256"]
             and campaign.get("virtualbox_backend") == backend_probe["virtualbox_backend"]
             and campaign.get("manifest_sha256") == lock["approved_manifest_sha256"]
             and isinstance(actions, list)
             and [item.get("action") for item in actions if isinstance(item, dict)] == [
                 "validate", "create", "test", "diagnostics", "server", "server", "restage",
                 "tamper", "restage", "server", "destroy",
             ]
             and len(actions) == 11
             and all(item.get("status") == "PASS"
                     and type(item.get("duration_seconds")) in (int, float)
                     and math.isfinite(item["duration_seconds"])
                     and item["duration_seconds"] >= 0 for item in actions),
             "M2.5 RKE2 campaign sequence is incomplete")
    transfers = [item for item in actions if item["action"] in {"test", "restage"}]
    _require(len(transfers) == 3, "M2.5 cold and recovery transfer decisions are incomplete")
    for item in transfers:
        qualification_steps.validate_transfer_record(
            item.get("transfer"), approved_manifest=lock["approved_manifest_sha256"]
        )
    _require(transfers[0]["transfer"] == cold_role["transfer"]
             and transfers[-1]["transfer"] == role["transfer"],
             "M2.5 retained transfer decisions differ from role executions")
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
    _require(0 <= current_epoch - smoke_epoch <= max_age,
             "M2.5 current smoke is stale or future-dated")


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
        "original_image_execution": {
            "source_sha": manifest["source_sha"],
            "source_tree_sha": manifest["source_tree_sha"],
            "packer_build": manifest["packer_build"],
            "packer_log_sha256": manifest["packer_log_sha256"],
        },
        "ready_for_real_provisioning": True, "deployment_state": "NOT_DEPLOYED",
        "paid_resources_created": 0,
        "six_node_rocky_rke2": "pending-real-target-and-service-inputs",
    }
    validate(root, payload, head, tree)
    destination = root / OUTPUT
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination
