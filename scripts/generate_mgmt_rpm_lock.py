#!/usr/bin/env python3
"""Regenerate the exact Rocky 10.2 RPM closure in the MGMT air-gap lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
import uuid
from pathlib import Path

import yaml

ROCKY_IMAGE = "quay.io/rockylinux/rockylinux@sha256:e372170ca8630f0f03e9b70fdd0bf4a3ce3426b0de7cdba615f06337389de176"
RANCHER_REPO = "https://rpm.rancher.io/rke2/stable/common/centos/10/noarch"
ROOT = Path(__file__).resolve().parents[1]
MACHINE_IMAGE_CONTRACT = yaml.safe_load(
    (ROOT / "config/contracts/machine-image-lock.yaml").read_text(encoding="utf-8")
)
PACKAGE_SOURCES = MACHINE_IMAGE_CONTRACT["packer_image"]["packages"]["sources"]
ROCKY_SOURCE = PACKAGE_SOURCES["rocky"]
EPEL_SOURCE = PACKAGE_SOURCES["epel"]
EPEL_REPO = EPEL_SOURCE["repository"]
PACKAGES = (
    "bash-completion",
    "bat",
    "bind-utils",
    "ca-certificates",
    "chrony",
    "conntrack-tools",
    "container-selinux",
    "curl-minimal",
    "ethtool",
    "fd-find",
    "file",
    "firewalld",
    "fzf",
    "gzip",
    "iproute",
    "iptables-nft",
    "iputils",
    "jq",
    "kernel",
    "kernel-core",
    "kernel-modules",
    "kernel-modules-extra",
    "kmod",
    "less",
    "libnftnl",
    "libselinux-utils",
    "lsof",
    "NetworkManager",
    "nftables",
    "openssh-server",
    "policycoreutils",
    "python3",
    "qemu-guest-agent",
    "ripgrep",
    "rke2-selinux",
    "rsync",
    "selinux-policy",
    "selinux-policy-targeted",
    "sudo",
    "tar",
    "tcpdump",
    "tmux",
    "tree",
    "unzip",
    "which",
    "xz",
    "yq",
)
ROCKY_REPO_OPTIONS = (
    "--setopt=baseos.mirrorlist=",
    f"--setopt=baseos.baseurl={ROCKY_SOURCE['repositories']['baseos']}",
    "--setopt=appstream.mirrorlist=",
    f"--setopt=appstream.baseurl={ROCKY_SOURCE['repositories']['appstream']}",
    "--setopt=extras.mirrorlist=",
    f"--setopt=extras.baseurl={ROCKY_SOURCE['repositories']['extras']}",
)
ROCKY_KEY = dict(ROCKY_SOURCE["signing_key"])
RANCHER_KEY = {
    "category": "rpm-signing-key",
    "file": "rancher-public.asc",
    "fingerprint": "C8CFF216455126E9B9C918BE925EA29AE257814A",
    "sha256": "7d2415f7fc532c365c8874bfad966566daaa0d04a9a5ba14d1db6080a9c12629",
    "url": "https://rpm.rancher.io/public.key",
}
EPEL_KEY = dict(EPEL_SOURCE["signing_key"])


def run(*args: str, capture: bool = False) -> str:
    result = subprocess.run(
        args, check=True, text=True, capture_output=capture, timeout=1800
    )
    return result.stdout.strip() if capture else ""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_from_lock(lock: dict) -> dict:
    artifacts = []
    for entry in lock["rpm_signing_keys"]:
        artifacts.append({key: value for key, value in entry.items() if key != "url"})
    for entry in lock["rpms"]:
        artifacts.append({key: value for key, value in entry.items() if key != "url"})
    for entry in lock["release_artifacts"].values():
        artifacts.append(
            {
                key: value
                for key, value in entry.items()
                if key not in {"url", "compressed_file", "compressed_sha256"}
            }
        )
    return {
        "architecture": "amd64",
        "artifacts": sorted(artifacts, key=lambda item: item["file"]),
        "image_inventory": lock["image_inventory"],
        "os": "rocky-10.2",
        "rke2_version": lock["rke2_version"],
        "rpm_dependency_closure": "complete",
        "schema_version": 1,
    }


def generate(path: Path) -> dict:
    lock = json.loads(path.read_text(encoding="utf-8"))
    container = "ecommerce-rocky10-lock-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="ecommerce-rocky10-rpms-") as directory:
        output = Path(directory)
        run(
            "docker",
            "create",
            "--name",
            container,
            "--mount",
            f"type=bind,src={output},dst=/out",
            ROCKY_IMAGE,
            "sleep",
            "infinity",
        )
        try:
            run("docker", "start", container)
            run(
                "docker", "exec", container, "dnf", "-qy", "install", "dnf-plugins-core"
            )
            run(
                "docker",
                "exec",
                container,
                "dnf",
                "config-manager",
                "--add-repo",
                RANCHER_REPO,
            )
            run(
                "docker",
                "exec",
                container,
                "dnf",
                "config-manager",
                "--add-repo",
                EPEL_REPO,
            )
            run(
                "docker",
                "exec",
                container,
                "dnf",
                *ROCKY_REPO_OPTIONS,
                "-qy",
                "download",
                "--resolve",
                "--alldeps",
                "--destdir",
                "/out",
                *PACKAGES,
            )

            def collect(directory: Path, mount: str) -> list[dict]:
                metadata = []
                for rpm in sorted(directory.glob("*.rpm")):
                    query = run(
                        "docker",
                        "exec",
                        container,
                        "rpm",
                        "-qp",
                        "--qf",
                        "%{NAME}\n%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}",
                        mount + "/" + rpm.name,
                        capture=True,
                    ).splitlines()
                    package, nevra = query
                    metadata.append((rpm, package, nevra))
                locations = run(
                    "docker",
                    "exec",
                    container,
                    "dnf",
                    *ROCKY_REPO_OPTIONS,
                    "-q",
                    "repoquery",
                    "--location",
                    *(item[2] for item in metadata),
                    capture=True,
                ).splitlines()
                urls_by_name = {
                    location.rsplit("/", 1)[-1]: location
                    for location in locations
                    if location.startswith("https://")
                }
                records = []
                for rpm, package, nevra in metadata:
                    url = urls_by_name.get(rpm.name)
                    if url is None:
                        raise RuntimeError(f"expected one HTTPS URL for {nevra}")
                    if package == "rke2-selinux":
                        signer = RANCHER_KEY
                    elif url.startswith(EPEL_REPO):
                        signer = EPEL_KEY
                    else:
                        signer = ROCKY_KEY
                    records.append(
                        {
                            "category": "rpm",
                            "file": rpm.name,
                            "nevra": nevra,
                            "package": package,
                            "sha256": sha256(rpm),
                            "signer_fingerprint": signer["fingerprint"],
                            "url": url,
                        }
                    )
                return records

            rpms = collect(output, "/out")
        finally:
            subprocess.run(
                ["docker", "rm", "--force", container],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    lock["target"] = {"architecture": "amd64", "os": "rocky-10.2"}
    lock["preparer_image"] = ROCKY_IMAGE
    lock["rpm_signing_keys"] = [RANCHER_KEY, ROCKY_KEY, EPEL_KEY]
    lock["rpms"] = rpms
    manifest = json.dumps(manifest_from_lock(lock), sort_keys=True, indent=2) + "\n"
    lock["approved_manifest_sha256"] = hashlib.sha256(manifest.encode()).hexdigest()
    path.write_text(json.dumps(lock, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {"rpms": len(rpms), "manifest_sha256": lock["approved_manifest_sha256"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(generate(args.lock.resolve()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
