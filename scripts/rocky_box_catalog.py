"""Bind a retained Rocky VirtualBox box to immutable build inputs and its digest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

import yaml


ROOT = Path(__file__).resolve().parents[1]
BUILD_FILES = (
    "platform/packer/rocky-10.2/rocky-10.2.pkr.hcl",
    "platform/packer/rocky-10.2/variables.pkr.hcl",
    "platform/packer/rocky-10.2/http/rocky-10.2.ks",
    "config/artifacts/rocky-10.2-base-packages.lock.json",
    "config/contracts/toolchain-lock.json",
    "scripts/render_packer_vars.py",
    "scripts/materialize_packer_rpm_repo.py",
    "scripts/install_packer_tools.py",
)
TOOLCHAIN_LOCK = "config/contracts/toolchain-lock.json"
IMAGE_TOOL_PROFILES = ("base", "rke2", "admin-qualification")
WINDOWS_BUILD_TOOLS = ("packer", "virtualbox", "vagrant")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
NETWORK_RUNNER_FILES = (
    "scripts/windows/LabNativeBoot.ps1",
    "scripts/windows/LabNetworkSmoke.ps1",
    "scripts/windows/LabSshIdentity.ps1",
    "scripts/windows/LabNetworkSeed.ps1",
    "scripts/windows/NativeVagrantSshSmoke.ps1",
    "scripts/windows/RockyImagePipeline.psm1",
    "scripts/windows/local-services-seed-server.ps1",
    "platform/vagrant/rocky-image-smoke/Vagrantfile",
    "config/artifacts/rocky-10.2-base-packages.lock.json",
)


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_file(source_sha: str, relative: str) -> bytes:
    if not GIT_SHA.fullmatch(source_sha):
        raise ValueError("source SHA must be a full Git SHA")
    return subprocess.run(
        ["git", "show", f"{source_sha}:{relative}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def source_tree(source_sha: str) -> str:
    if not GIT_SHA.fullmatch(source_sha):
        raise ValueError("source SHA must be a full Git SHA")
    return subprocess.run(
        ["git", "rev-parse", f"{source_sha}^{{tree}}"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _image(source_sha: str) -> dict:
    contract = _mapping(
        yaml.safe_load(source_file(source_sha, "config/contracts/machine-image-lock.yaml")),
        "machine image contract",
    )
    return _mapping(contract.get("packer_image"), "Packer image")


def image_identity(source_sha: str) -> tuple[str, str, str]:
    image = _image(source_sha)
    return (
        str(_mapping(image.get("os"), "image OS")["version"]),
        str(_mapping(_mapping(image.get("outputs"), "image outputs").get("rke2"),
                     "RKE2 outputs")["virtualbox"]),
        str(_mapping(_mapping(image.get("build"), "image build").get("virtualbox"),
                     "VirtualBox build")["version"]),
    )


def _build_file_digests(source_sha: str) -> dict[str, str]:
    files = {path: hashlib.sha256(source_file(source_sha, path)).hexdigest() for path in BUILD_FILES}
    image = _image(source_sha)
    selected = {
        key: image[key]
        for key in (
            "id", "os", "source", "packages", "external_tools", "profiles",
            "hypervisors", "kernel", "security", "networking", "services",
            "kubernetes_prerequisites",
        )
    }
    selected["build"] = {
        key: value for key, value in _mapping(image.get("build"), "image build").items()
        if key != "credential"
    }
    files["contracted_image_build"] = hashlib.sha256(
        json.dumps(selected, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return files


def _input_digests(files: dict[str, str]) -> dict[str, str]:
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "packer_template_digest": hashlib.sha256(
            json.dumps({path: files[path] for path in BUILD_FILES[:3]}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "inputs_digest": hashlib.sha256(canonical).hexdigest(),
    }


def build_inputs(source_sha: str) -> dict[str, str]:
    """Return the original v1 input digest used by immutable box manifests."""
    return _input_digests(_build_file_digests(source_sha))


def _version_references(value: object) -> set[str]:
    """Collect the lock keys read by the selected tool definitions."""
    if isinstance(value, dict):
        references: set[str] = set()
        for key, item in value.items():
            if key.endswith("_ref"):
                if not isinstance(item, str) or not item:
                    raise ValueError(f"selected tool {key} must name a version lock key")
                references.add(item)
        for item in value.values():
            references.update(_version_references(item))
        return references
    if isinstance(value, list):
        references: set[str] = set()
        for item in value:
            references.update(_version_references(item))
        return references
    return set()


def _consumed_toolchain(source_sha: str) -> dict[str, object]:
    """Select values read by the image materializer and Windows preflight."""
    image = _image(source_sha)
    lock = _mapping(json.loads(source_file(source_sha, TOOLCHAIN_LOCK)), "toolchain lock")
    profiles = _mapping(image.get("profiles"), "image profiles")
    profile_tools: set[str] = set()
    for profile in IMAGE_TOOL_PROFILES:
        definition = _mapping(profiles.get(profile), f"image profile {profile}")
        names = definition.get("external_tools")
        if not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names):
            raise ValueError(f"image profile {profile} external tools must be names")
        profile_tools.update(names)
    names = sorted(profile_tools.union(WINDOWS_BUILD_TOOLS))
    definitions = _mapping(lock.get("tools"), "toolchain tools")
    tools = {name: _mapping(definitions.get(name), f"toolchain tool {name}") for name in names}
    references = set().union(*(_version_references(tool) for tool in tools.values()))
    versions = _mapping(lock.get("versions"), "toolchain versions")
    lifecycle = _mapping(lock.get("tool_lifecycle"), "tool lifecycle")
    active = _mapping(lifecycle.get("active"), "active tool lifecycle")
    return {
        "tools": tools,
        "versions": {name: versions[name] for name in sorted(references)},
        "windows_build_lifecycle": {
            name: _mapping(active.get(name), f"Windows tool lifecycle {name}")
            for name in WINDOWS_BUILD_TOOLS
        },
    }


def semantic_build_inputs(source_sha: str) -> dict[str, str]:
    """Compare actual build dependencies without changing the historical v1 digest."""
    files = _build_file_digests(source_sha)
    toolchain = _consumed_toolchain(source_sha)
    files[TOOLCHAIN_LOCK] = hashlib.sha256(
        json.dumps(toolchain, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return _input_digests(files)


def verify_staging(stage: Path, expected_manifest_sha256: str) -> None:
    manifest_path = stage / "SHA256SUMS"
    if digest_file(manifest_path) != expected_manifest_sha256:
        raise ValueError("staging manifest digest differs from native result")
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if not separator or not SHA256.fullmatch(digest):
            raise ValueError("invalid staged SHA256SUMS line")
        candidate = (stage / relative).resolve()
        if not candidate.is_relative_to(stage.resolve()) or not candidate.is_file():
            raise ValueError("staging manifest path is missing or escapes the stage")
        if digest_file(candidate) != digest:
            raise ValueError(f"staging input digest differs: {relative}")


def adopt(result_path: Path, stage: Path, box: Path) -> dict[str, object]:
    result = json.loads(result_path.read_text(encoding="utf-8-sig"))
    source_sha = result.get("source_git_sha")
    if not isinstance(source_sha, str) or not GIT_SHA.fullmatch(source_sha):
        raise ValueError("native result lacks an exact source SHA")
    if (result.get("status") != "PASS"
        or result.get("precheck") != "PASS"
        or result.get("packer", {}).get("build") != "PASS"
        or result.get("native_vtx") != "PASS"
        or result.get("nem_detected") is not False
        or result.get("virtualbox_backend") != "NATIVE_VTX"):
        raise ValueError("native Packer build and VT-x evidence are not PASS")
    rocky_version, box_filename, virtualbox_version = image_identity(source_sha)
    if (rocky_version != "10.2" or box.name != box_filename
        or result.get("source_tree_sha") != source_tree(source_sha)):
        raise ValueError("native result has the wrong Rocky image or source tree")
    if result.get("artifact_sha256") != digest_file(box) or result.get("artifact_size_bytes") != box.stat().st_size:
        raise ValueError("box bytes differ from the native result")
    if PureWindowsPath(str(result.get("artifact", ""))).name != box.name:
        raise ValueError("box name differs from the native result")
    verify_staging(stage, str(result["staging_manifest_sha256"]))
    packer_log = stage / "logs" / "packer-build.log"
    if not packer_log.is_file() or not packer_log.stat().st_size:
        raise ValueError("Packer build log is absent")
    bindings = build_inputs(source_sha)
    artifact_root = box.parent
    packer_target = artifact_root / "packer.log"
    if not packer_target.is_file():
        shutil.copyfile(packer_log, packer_target)
    if digest_file(packer_target) != digest_file(packer_log):
        raise ValueError("Packer log copy differs")
    manifest = {
        "schema": 1,
        "source_sha": source_sha,
        "source_tree_sha": result["source_tree_sha"],
        "packer_template_digest": bindings["packer_template_digest"],
        "inputs_digest": bindings["inputs_digest"],
        "rocky_version": rocky_version,
        "virtualbox_version": virtualbox_version,
        "native_vtx": "PASS",
        "nem_detected": False,
        "packer_build": "PASS",
        "build_timestamp": result["milestones"]["T13_ARTIFACT_EXPORT_COMPLETE"],
        "box_sha256": result["artifact_sha256"],
        "box_size_bytes": result["artifact_size_bytes"],
        "box_filename": box.name,
        "staging_manifest_sha256": result["staging_manifest_sha256"],
        "packer_log_sha256": digest_file(packer_target),
    }
    path = artifact_root / "manifest.json"
    if path.is_file() and json.loads(path.read_text(encoding="utf-8")) != manifest:
        raise ValueError("existing box manifest differs; refusing overwrite")
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (artifact_root / "SHA256SUMS").write_text(f"{manifest['box_sha256']}  {box.name}\n", encoding="utf-8")
    return manifest


def verify(box: Path, source_sha: str) -> dict[str, object]:
    manifest_path = box.parent / "manifest.json"
    manifest = _mapping(json.loads(manifest_path.read_text(encoding="utf-8")), "box manifest")
    rocky_version, box_filename, virtualbox_version = image_identity(source_sha)
    if (rocky_version != "10.2" or manifest.get("schema") != 1
        or manifest.get("box_filename") != box.name or box.name != box_filename):
        raise ValueError("box manifest schema or name is invalid")
    if (
        not GIT_SHA.fullmatch(str(manifest.get("source_sha", "")))
        or not GIT_SHA.fullmatch(str(manifest.get("source_tree_sha", "")))
        or manifest.get("source_tree_sha") != source_tree(str(manifest.get("source_sha", "")))
        or manifest.get("rocky_version") != rocky_version
        or manifest.get("virtualbox_version") != virtualbox_version
        or manifest.get("native_vtx") != "PASS"
        or manifest.get("nem_detected") is not False
        or manifest.get("packer_build") != "PASS"
        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", str(manifest.get("build_timestamp", "")))
        or not SHA256.fullmatch(str(manifest.get("staging_manifest_sha256", "")))
        or not SHA256.fullmatch(str(manifest.get("packer_log_sha256", "")))
    ):
        raise ValueError("box provenance is incomplete or invalid")
    actual = digest_file(box)
    if actual != manifest.get("box_sha256") or not SHA256.fullmatch(actual):
        raise ValueError("box digest is invalid")
    if box.stat().st_size != manifest.get("box_size_bytes"):
        raise ValueError("box size differs from manifest")
    if (box.parent / "SHA256SUMS").read_text(encoding="utf-8") != f"{actual}  {box.name}\n":
        raise ValueError("box checksum file differs")
    if digest_file(box.parent / "packer.log") != manifest.get("packer_log_sha256"):
        raise ValueError("Packer log differs from manifest")
    original_sha = str(manifest["source_sha"])
    original = build_inputs(original_sha)
    if original != {key: manifest.get(key) for key in original}:
        raise ValueError("Packer image inputs changed; rebuild required")
    if semantic_build_inputs(original_sha) != semantic_build_inputs(source_sha):
        raise ValueError("Packer image inputs changed; rebuild required")
    return manifest


def find_matching_box(source_sha: str, artifact_root: Path = Path("/mnt/c/ecommerce-lab/artifacts")) -> Path:
    """Find an immutable local artifact by semantic build inputs, then verify its bytes."""
    semantic_build_inputs(source_sha)
    matches: list[Path] = []
    for manifest_path in sorted(artifact_root.glob("*/manifest.json")):
        try:
            manifest = _mapping(json.loads(manifest_path.read_text(encoding="utf-8")), "box manifest")
            filename = manifest.get("box_filename")
            if not isinstance(filename, str) or Path(filename).name != filename:
                continue
            box = manifest_path.parent / filename
            verify(box, source_sha)
            matches.append(box)
        except (FileNotFoundError, NotADirectoryError, KeyError, TypeError, ValueError,
                subprocess.CalledProcessError):
            continue
    if len(matches) != 1:
        raise ValueError(f"expected exactly one verified matching box; found {len(matches)}")
    return matches[0]


def prepare_smoke(box: Path, source_sha: str, expected_sha256: str, keep_failed_vm: bool, deadline: int,
                  retain_vm: bool = False, diagnostic_nem: bool = False) -> dict[str, str]:
    if deadline < 30 or deadline > 1800:
        raise ValueError("network smoke global deadline must be between 30 and 1800 seconds")
    if expected_sha256 and (not SHA256.fullmatch(expected_sha256) or digest_file(box) != expected_sha256):
        raise ValueError("requested box SHA-256 differs from artifact bytes")
    status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, check=True, capture_output=True, text=True)
    if status.stdout.strip():
        raise ValueError("network smoke staging requires a clean exact-SHA worktree")
    actual_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    if source_sha != actual_head:
        raise ValueError("network smoke source SHA differs from current HEAD")
    manifest = verify(box, source_sha)
    campaign = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    stage = Path("/mnt/c/ecommerce-lab/network-smoke") / campaign
    stage.mkdir(parents=True, exist_ok=False)
    for relative in NETWORK_RUNNER_FILES:
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    toolchain = json.loads((ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8"))["versions"]
    box_windows = subprocess.run(["wslpath", "-w", str(box.resolve())], check=True, capture_output=True, text=True).stdout.strip()
    stage_windows = subprocess.run(["wslpath", "-w", str(stage.resolve())], check=True, capture_output=True, text=True).stdout.strip()
    prepared = {
        "schema": 1,
        "status": "PREPARED",
        "campaign_id": campaign,
        "source_sha": source_sha,
        "source_tree_sha": tree,
        "box_path": box_windows,
        "box_sha256": manifest["box_sha256"],
        "box_manifest_sha256": digest_file(box.parent / "manifest.json"),
        "inputs_digest": manifest["inputs_digest"],
        "global_deadline_seconds": deadline,
        "keep_failed_vm": keep_failed_vm,
        "retain_vm": retain_vm,
        "diagnostic_nem": diagnostic_nem,
        "vagrant_version": toolchain["VAGRANT_VERSION"],
        "virtualbox_version": toolchain["VIRTUALBOX_VERSION"],
    }
    (stage / "prepared.json").write_text(json.dumps(prepared, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    entries = [*NETWORK_RUNNER_FILES, "prepared.json"]
    (stage / "SHA256SUMS").write_text("".join(f"{digest_file(stage / relative)}  {relative}\n" for relative in sorted(entries)), encoding="utf-8")
    return {
        "status": "PREPARED",
        "packer": "REUSED",
        "campaign_id": campaign,
        "box_sha256": manifest["box_sha256"],
        "native_command": f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{stage_windows}\\scripts\\windows\\LabNetworkSmoke.ps1" -Action Run -StageRoot "{stage_windows}"',
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("adopt", "verify", "prepare-smoke"))
    parser.add_argument("--box", type=Path, required=True)
    parser.add_argument("--source-sha", default="")
    parser.add_argument("--result", type=Path)
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--box-sha256", default="")
    parser.add_argument("--keep-failed-vm", action="store_true")
    parser.add_argument("--retain-vm", action="store_true")
    parser.add_argument("--diagnostic-nem", action="store_true")
    parser.add_argument("--global-deadline", type=int, default=900)
    args = parser.parse_args()
    try:
        if args.action == "adopt":
            if args.result is None or args.stage is None:
                raise ValueError("adopt requires --result and --stage")
            manifest = adopt(args.result, args.stage, args.box)
        elif args.action == "verify":
            manifest = verify(args.box, args.source_sha)
        else:
            print(json.dumps(prepare_smoke(args.box, args.source_sha, args.box_sha256, args.keep_failed_vm, args.global_deadline, args.retain_vm, args.diagnostic_nem), sort_keys=True))
            return 0
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError, yaml.YAMLError) as exc:
        parser.exit(1, f"BOX_REUSE=FAIL reason={exc}\n")
    print(json.dumps({"box_reuse": "REUSED", "box_sha256": manifest["box_sha256"], "source_sha": manifest["source_sha"], "inputs_digest": manifest["inputs_digest"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
