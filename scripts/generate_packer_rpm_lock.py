#!/usr/bin/env python3
"""Generate profile-separated Rocky 10.2 RPM closures for the Packer bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
import uuid
from pathlib import Path

import generate_mgmt_rpm_lock as rpm_source
import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "config/contracts/machine-image-lock.yaml"


def profile_roots(contract: dict) -> dict[str, list[str]]:
    image = contract["packer_image"]
    profiles = image["profiles"]
    roots = {
        "base": profiles["base"]["rpm_packages"],
        "rke2": profiles["rke2"]["rpm_packages"],
        "qemu-kvm": image["hypervisors"]["qemu_kvm"]["rpm_packages"],
        "admin-qualification": profiles["admin-qualification"]["rpm_packages"],
    }
    seen: dict[str, str] = {}
    for profile, packages in roots.items():
        if not packages or len(packages) != len(set(packages)):
            raise ValueError(f"profile {profile} has an empty or duplicate RPM root")
        for package in packages:
            previous = seen.setdefault(package, profile)
            if previous != profile:
                raise ValueError(
                    f"RPM root {package} is owned by both {previous} and {profile}"
                )
    return roots


def _collect(container: str, directory: Path, mount: str) -> list[dict]:
    rpms = sorted(directory.glob("*.rpm"))
    query = rpm_source.run(
        "docker",
        "exec",
        container,
        "rpm",
        "-qp",
        "--qf",
        "%{NAME}\n%{EPOCHNUM}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n",
        *(f"{mount}/{rpm.name}" for rpm in rpms),
        capture=True,
    ).splitlines()
    if len(query) != len(rpms) * 5:
        raise RuntimeError(
            f"unexpected RPM metadata count for profile directory {directory.name}"
        )
    metadata = [
        (
            rpm,
            query[index * 5],
            query[index * 5 + 1],
            query[index * 5 + 2],
            query[index * 5 + 3],
            query[index * 5 + 4],
        )
        for index, rpm in enumerate(rpms)
    ]
    unsupported = [
        rpm.name
        for rpm, _, _, _, _, arch in metadata
        if arch not in {"x86_64", "noarch"}
    ]
    if unsupported:
        raise RuntimeError(
            f"unsupported RPM architecture in {directory.name}: {unsupported}"
        )
    nevras = [
        f"{package}-{epoch}:{version}-{release}.{arch}"
        for _, package, epoch, version, release, arch in metadata
    ]
    locations = rpm_source.run(
        "docker",
        "exec",
        container,
        "dnf",
        *rpm_source.ROCKY_REPO_OPTIONS,
        "-q",
        "repoquery",
        "--location",
        *nevras,
        capture=True,
    ).splitlines()
    urls_by_name = {
        location.rsplit("/", 1)[-1]: location
        for location in locations
        if location.startswith("https://")
    }
    records = []
    for rpm, package, epoch, version, release, arch in metadata:
        url = urls_by_name.get(rpm.name)
        if url is None:
            raise RuntimeError(f"expected one HTTPS URL for {rpm.name}")
        signer = (
            rpm_source.EPEL_KEY
            if url.startswith(rpm_source.EPEL_REPO)
            else rpm_source.ROCKY_KEY
        )
        records.append(
            {
                "category": "rpm",
                "file": rpm.name,
                "epoch": epoch,
                "version": version,
                "release": release,
                "architecture": arch,
                "package": package,
                "sha256": rpm_source.sha256(rpm),
                "signer_fingerprint": signer["fingerprint"],
                "url": url,
            }
        )
    return records


def generate(contract_path: Path, destination: Path) -> dict:
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    image = contract["packer_image"]
    roots = profile_roots(contract)
    container = "ecommerce-packer-lock-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="ecommerce-packer-rpms-") as directory:
        output = Path(directory)
        for profile in roots:
            (output / profile).mkdir()
        rpm_source.run(
            "docker",
            "create",
            "--name",
            container,
            "--mount",
            f"type=bind,src={output},dst=/profiles",
            rpm_source.ROCKY_IMAGE,
            "sleep",
            "infinity",
        )
        try:
            rpm_source.run("docker", "start", container)
            rpm_source.run(
                "docker", "exec", container, "dnf", "-qy", "install", "dnf-plugins-core"
            )
            rpm_source.run(
                "docker",
                "exec",
                container,
                "dnf",
                "config-manager",
                "--add-repo",
                rpm_source.EPEL_REPO,
            )
            for profile, packages in roots.items():
                rpm_source.run(
                    "docker",
                    "exec",
                    container,
                    "dnf",
                    *rpm_source.ROCKY_REPO_OPTIONS,
                    "-qy",
                    "download",
                    "--resolve",
                    "--alldeps",
                    "--destdir",
                    f"/profiles/{profile}",
                    *packages,
                )
            resolved = {
                profile: _collect(container, output / profile, f"/profiles/{profile}")
                for profile in roots
            }
        finally:
            subprocess.run(
                ["docker", "rm", "--force", container],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    base_files = {entry["file"] for entry in resolved["base"]}
    for profile in ("rke2", "qemu-kvm", "admin-qualification"):
        resolved[profile] = [
            entry for entry in resolved[profile] if entry["file"] not in base_files
        ]

    profiles = {}
    for profile, packages in resolved.items():
        body = {"roots": roots[profile], "packages": packages}
        canonical = json.dumps(body, sort_keys=True, indent=2) + "\n"
        body["approved_manifest_sha256"] = hashlib.sha256(
            canonical.encode()
        ).hexdigest()
        profiles[profile] = body
    document = {
        "schema_version": 2,
        "image": image["id"],
        "architecture": image["os"]["architecture"],
        "source_contract": str(contract_path.relative_to(ROOT)),
        "dependency_closure": "complete-per-profile",
        "rpm_signing_keys": [rpm_source.ROCKY_KEY, rpm_source.EPEL_KEY],
        "profiles": profiles,
    }
    canonical = json.dumps(document, sort_keys=True, indent=2) + "\n"
    document["approved_manifest_sha256"] = hashlib.sha256(
        canonical.encode()
    ).hexdigest()
    destination.write_text(
        json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "profiles": {name: len(value["packages"]) for name, value in profiles.items()},
        "manifest_sha256": document["approved_manifest_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            generate(args.contract.resolve(), args.output.resolve()), sort_keys=True
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
