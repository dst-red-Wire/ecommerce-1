#!/usr/bin/env python3
"""Render non-secret Packer variables from the central machine-image contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

import yaml


def _digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def _windows_path(path: Path) -> str:
    rendered = subprocess.check_output(
        ["wslpath", "-w", str(path)], text=True, timeout=15
    ).strip()
    if not re.fullmatch(r"[A-Za-z]:\\[^\r\n]+", rendered):
        raise ValueError("Packer Windows staging path is not a local drive path")
    return rendered


def _bounded_contract_integer(
    values: dict, key: str, *, minimum: int, maximum: int
) -> int:
    value = values.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"Packer resource {key} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(
            f"Packer resource {key} must be between {minimum} and {maximum}"
        )
    return value


def render(
    contract_path: Path,
    bundle: Path,
    build_public_key_file: Path,
    build_private_key_file: Path,
    output: Path,
    *,
    target_platform: str = "linux",
    artifact_dir: Path | None = None,
    runtime_contract_output: Path | None = None,
) -> None:
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    image = contract["packer_image"]
    source = image["source"]
    if image["id"] != "rocky-10.2-base" or source.get("mutable_aliases") != "forbidden":
        raise ValueError("unsupported or mutable Packer image contract")
    checksum = str(source["sha256"])
    if len(checksum) != 64 or any(
        character not in "0123456789abcdef" for character in checksum
    ):
        raise ValueError("Packer ISO SHA256 is invalid")
    resources = image["build"]["resources"]
    if resources.get("authority") != "shared-all-hypervisors":
        raise ValueError("Packer resources must have one shared hypervisor authority")
    vm_cpus = _bounded_contract_integer(resources, "vcpus", minimum=1, maximum=64)
    vm_memory_mib = _bounded_contract_integer(
        resources, "memory_mib", minimum=2048, maximum=262144
    )
    vm_disk_mib = _bounded_contract_integer(
        resources, "disk_mib", minimum=16384, maximum=1048576
    )
    vm_headless = resources.get("headless")
    if not isinstance(vm_headless, bool):
        raise TypeError("Packer resource headless must be a boolean")
    storage = image["build"]["storage"]
    if storage.get("authority") != "shared-all-hypervisors":
        raise ValueError("Packer storage must have one shared hypervisor authority")
    if storage.get("firmware") != "bios":
        raise ValueError("Packer storage firmware must be bios")
    if storage.get("partition_table") != "gpt":
        raise ValueError("Packer storage partition table must be gpt")
    if storage.get("root_filesystem") != "xfs":
        raise ValueError("Packer root filesystem must be xfs")
    if storage.get("lvm") != "forbidden" or storage.get("swap") != "forbidden":
        raise ValueError("Packer LVM and swap must be forbidden")
    vm_bios_boot_mib = _bounded_contract_integer(
        storage, "bios_boot_mib", minimum=1, maximum=16
    )
    vm_boot_mib = _bounded_contract_integer(
        storage, "boot_mib", minimum=2048, maximum=16384
    )
    vm_root_min_mib = _bounded_contract_integer(
        storage, "root_min_mib", minimum=10240, maximum=1048576
    )
    if vm_bios_boot_mib + vm_boot_mib + vm_root_min_mib >= vm_disk_mib:
        raise ValueError("Packer partitions must leave growable space on the disk")
    timeouts = image["build"]["timeouts"]
    if timeouts.get("authority") != "shared-all-hypervisors":
        raise ValueError("Packer timeouts must have one shared hypervisor authority")
    vm_ssh_timeout_seconds = _bounded_contract_integer(
        timeouts, "ssh_seconds", minimum=1800, maximum=7200
    )
    virtualbox = image["build"]["virtualbox"]
    acceleration = virtualbox.get("acceleration")
    if acceleration != {
        "required": "native-vtx",
        "forbidden": ["nem"],
        "hyper_v_present": False,
    }:
        raise ValueError("VirtualBox native VT-x acceleration contract is invalid")
    virtualbox_network_adapter = image["hypervisors"]["virtualbox"].get(
        "network_adapter"
    )
    if virtualbox_network_adapter != "virtio":
        raise ValueError("VirtualBox network adapter must be virtio")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("output must be a new path below an existing directory")
    iso = bundle / "iso" / source["iso"]
    required = (
        iso,
        bundle / "evidence.json",
        bundle / "rpms/base/SHA256SUMS",
        bundle / "tools/base/SHA256SUMS",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise ValueError(f"incomplete offline Packer bundle: {missing}")
    if _digest(iso) != checksum:
        raise ValueError("offline Packer ISO digest mismatch")
    if not build_public_key_file.is_file() or not build_private_key_file.is_file():
        raise ValueError("temporary Packer SSH key pair is incomplete")
    public_key = build_public_key_file.read_text(encoding="utf-8").strip()
    if (
        re.fullmatch(
            r"ssh-(?:ed25519|rsa) [A-Za-z0-9+/]+={0,3}(?: [A-Za-z0-9._@-]+)?",
            public_key,
        )
        is None
    ):
        raise ValueError("temporary Packer SSH public key is invalid")
    if target_platform == "windows":
        if artifact_dir is None or not artifact_dir.is_dir():
            raise ValueError("Windows Packer artifact directory must already exist")
        iso_path = _windows_path(iso.resolve())
        iso_url = "file:///" + iso_path.replace("\\", "/")
        bundle_path = _windows_path(bundle.resolve())
        private_key_path = _windows_path(build_private_key_file.resolve())
        artifact_path = _windows_path(artifact_dir.resolve())
    elif target_platform == "linux":
        if artifact_dir is None:
            artifact_dir = output.parent / "artifacts"
            artifact_dir.mkdir(exist_ok=True)
        iso_url = iso.resolve().as_uri()
        bundle_path = str(bundle.resolve())
        private_key_path = str(build_private_key_file.resolve())
        artifact_path = str(artifact_dir.resolve())
    else:
        raise ValueError(f"unsupported Packer target platform: {target_platform}")
    body = (
        f"iso_url      = {json.dumps(iso_url)}\n"
        f"iso_checksum = {json.dumps(checksum)}\n"
        f"offline_bundle_dir = {json.dumps(bundle_path)}\n"
        f"artifact_dir = {json.dumps(artifact_path)}\n"
        f"vm_cpus = {vm_cpus}\n"
        f"vm_memory_mib = {vm_memory_mib}\n"
        f"vm_disk_mib = {vm_disk_mib}\n"
        f"vm_headless = {str(vm_headless).lower()}\n"
        f"vm_firmware = {json.dumps(storage['firmware'])}\n"
        f"vm_partition_table = {json.dumps(storage['partition_table'])}\n"
        f"vm_bios_boot_mib = {vm_bios_boot_mib}\n"
        f"vm_boot_mib = {vm_boot_mib}\n"
        f"vm_root_min_mib = {vm_root_min_mib}\n"
        f"vm_root_filesystem = {json.dumps(storage['root_filesystem'])}\n"
        f"vm_ssh_timeout_seconds = {vm_ssh_timeout_seconds}\n"
        f"vm_virtualbox_nic_type = {json.dumps(virtualbox_network_adapter)}\n"
        f"virtualbox_serial_log_file = {json.dumps(str(Path(artifact_path) / 'virtualbox-serial.log'))}\n"
        f"build_ssh_public_key = {json.dumps(public_key)}\n"
        f"build_ssh_private_key_file = {json.dumps(private_key_path)}\n"
    )
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output.parent,
        prefix=output.name + ".",
        delete=False,
    ) as temporary:
        temporary.write(body)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, output)
    if runtime_contract_output is not None:
        if (
            runtime_contract_output.exists()
            or runtime_contract_output.is_symlink()
            or not runtime_contract_output.parent.is_dir()
        ):
            raise ValueError(
                "runtime contract output must be a new path below an existing directory"
            )
        runtime_contract = {
            "schema": 1,
            "authority": "config/contracts/machine-image-lock.yaml",
            "resources": {
                "vcpus": vm_cpus,
                "memory_mib": vm_memory_mib,
                "disk_mib": vm_disk_mib,
                "headless": vm_headless,
            },
            "storage": {
                "firmware": storage["firmware"],
                "partition_table": storage["partition_table"],
                "root_filesystem": storage["root_filesystem"],
                "lvm": storage["lvm"],
                "swap": storage["swap"],
            },
            "timeouts": {"ssh_seconds": vm_ssh_timeout_seconds},
            "virtualbox": {"network_adapter": virtualbox_network_adapter},
            "rpm_profile_roots": image["profiles"]["base"]["rpm_packages"]
            + image["profiles"]["rke2"]["rpm_packages"],
        }
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=runtime_contract_output.parent,
            prefix=runtime_contract_output.name + ".",
            delete=False,
        ) as runtime_temporary:
            json.dump(runtime_contract, runtime_temporary, indent=2, sort_keys=True)
            runtime_temporary.write("\n")
            runtime_temporary_path = Path(runtime_temporary.name)
        os.replace(runtime_temporary_path, runtime_contract_output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--build-public-key-file", required=True, type=Path)
    parser.add_argument("--build-private-key-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--target-platform", choices=("linux", "windows"), default="linux"
    )
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--runtime-contract-output", type=Path)
    args = parser.parse_args()
    render(
        args.contract.resolve(),
        args.bundle.resolve(),
        args.build_public_key_file.resolve(),
        args.build_private_key_file.resolve(),
        args.output.resolve(),
        target_platform=args.target_platform,
        artifact_dir=args.artifact_dir.resolve() if args.artifact_dir else None,
        runtime_contract_output=(
            args.runtime_contract_output.resolve()
            if args.runtime_contract_output
            else None
        ),
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
