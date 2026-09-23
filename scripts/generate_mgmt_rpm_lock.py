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


ROCKY_IMAGE = "quay.io/rockylinux/rockylinux@sha256:e372170ca8630f0f03e9b70fdd0bf4a3ce3426b0de7cdba615f06337389de176"
RANCHER_REPO = "https://rpm.rancher.io/rke2/stable/common/centos/10/noarch"
EPEL_REPO = "https://dl.fedoraproject.org/pub/epel/10.2/Everything/x86_64/"
PACKAGES = (
    "bash-completion", "bat", "bind-utils", "ca-certificates", "chrony", "conntrack-tools",
    "container-selinux", "curl-minimal", "ethtool", "fd-find", "file", "firewalld", "fzf",
    "gzip", "iproute", "iptables-nft", "iputils", "jq", "kernel", "kernel-core",
    "kernel-modules", "kernel-modules-extra", "kmod", "less", "libnftnl", "libselinux-utils",
    "lsof", "NetworkManager", "nftables", "openssh-server", "policycoreutils", "python3",
    "qemu-guest-agent", "ripgrep", "rke2-selinux", "rsync", "selinux-policy",
    "selinux-policy-targeted", "sudo", "tar", "tcpdump", "tmux", "tree", "unzip",
    "which", "xz", "yq",
)
IMAGE_PACKAGES = frozenset({
    "bash-completion", "bat", "bind-utils", "ca-certificates", "chrony", "conntrack-tools",
    "container-selinux", "curl", "ethtool", "fd-find", "file", "fzf", "gzip", "iproute",
    "iptables-nft", "iputils", "jq", "kernel", "kernel-core", "kernel-modules",
    "kernel-modules-extra", "kmod", "less", "libnftnl", "libselinux-utils", "lsof",
    "NetworkManager", "nftables", "openssh-server", "policycoreutils", "python3",
    "qemu-guest-agent", "ripgrep", "rsync", "selinux-policy", "selinux-policy-targeted",
    "sudo", "tar", "tcpdump", "tmux", "tree", "unzip", "which", "xz", "yq",
})
ROCKY_REPO_OPTIONS = (
    "--setopt=baseos.mirrorlist=",
    "--setopt=baseos.baseurl=https://download.rockylinux.org/pub/rocky/10.2/BaseOS/x86_64/os/",
    "--setopt=appstream.mirrorlist=",
    "--setopt=appstream.baseurl=https://download.rockylinux.org/pub/rocky/10.2/AppStream/x86_64/os/",
    "--setopt=extras.mirrorlist=",
    "--setopt=extras.baseurl=https://download.rockylinux.org/pub/rocky/10.2/extras/x86_64/os/",
)
ROCKY_KEY = {
    "category": "rpm-signing-key",
    "file": "rocky-10-public.asc",
    "fingerprint": "FC226859C0860BF0DDB95B085B106C736FEDFC85",
    "sha256": "be8c4f070b696e64d8ce40e59a95a57e8b5c776f0015c2fd64e14b896622bdb4",
    "url": "https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-10",
}
RANCHER_KEY = {
    "category": "rpm-signing-key",
    "file": "rancher-public.asc",
    "fingerprint": "C8CFF216455126E9B9C918BE925EA29AE257814A",
    "sha256": "7d2415f7fc532c365c8874bfad966566daaa0d04a9a5ba14d1db6080a9c12629",
    "url": "https://rpm.rancher.io/public.key",
}
EPEL_KEY = {
    "category": "rpm-signing-key",
    "file": "epel-10-public.asc",
    "fingerprint": "7D8D15CBFC4E62688591FB2633D98517E37ED158",
    "sha256": "de390fc168eae5ab2852e9e93d34a0b9ddf05cf9ce90ee28d97de26a4b1f6b93",
    "url": "https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-10",
}


def run(*args: str, capture: bool = False) -> str:
    result = subprocess.run(args, check=True, text=True, capture_output=capture, timeout=1800)
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
        artifacts.append({
            key: value for key, value in entry.items()
            if key not in {"url", "compressed_file", "compressed_sha256"}
        })
    return {
        "architecture": "amd64",
        "artifacts": sorted(artifacts, key=lambda item: item["file"]),
        "image_inventory": lock["image_inventory"],
        "os": "rocky-10.2",
        "rke2_version": lock["rke2_version"],
        "rpm_dependency_closure": "complete",
        "schema_version": 1,
    }


def write_image_package_lock(lock: dict, source: Path, destination: Path,
                             image_rpms: list[dict] | None = None) -> None:
    image_rpms = image_rpms or [
        entry for entry in lock["rpms"] if entry["package"] in IMAGE_PACKAGES
    ]
    missing = sorted(IMAGE_PACKAGES - {entry["package"] for entry in image_rpms})
    if missing:
        raise RuntimeError(f"base image package lock is incomplete: {missing}")
    package_document = {
        "schema_version": 1,
        "image": "rocky-10.2-base",
        "architecture": "x86_64-v3",
        "source_lock": "config/artifacts/" + source.name,
        "dependency_closure": "complete",
        "rpm_signing_keys": [ROCKY_KEY, EPEL_KEY],
        "packages": image_rpms,
    }
    package_manifest = json.dumps(package_document, sort_keys=True, indent=2) + "\n"
    package_document["approved_manifest_sha256"] = hashlib.sha256(
        package_manifest.encode()
    ).hexdigest()
    destination.write_text(
        json.dumps(package_document, sort_keys=True, indent=2) + "\n", encoding="utf-8",
    )


def generate(path: Path, image_package_lock: Path | None) -> dict:
    lock = json.loads(path.read_text(encoding="utf-8"))
    container = "ecommerce-rocky10-lock-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="ecommerce-rocky10-rpms-") as directory, \
            tempfile.TemporaryDirectory(prefix="ecommerce-rocky10-image-rpms-") as image_directory:
        output = Path(directory)
        image_output = Path(image_directory)
        run("docker", "create", "--name", container,
            "--mount", f"type=bind,src={output},dst=/out",
            "--mount", f"type=bind,src={image_output},dst=/image", ROCKY_IMAGE,
            "sleep", "infinity")
        try:
            run("docker", "start", container)
            run("docker", "exec", container, "dnf", "-qy", "install", "dnf-plugins-core")
            run("docker", "exec", container, "dnf", "config-manager", "--add-repo", RANCHER_REPO)
            run("docker", "exec", container, "dnf", "config-manager", "--add-repo", EPEL_REPO)
            run("docker", "exec", container, "dnf", *ROCKY_REPO_OPTIONS,
                "-qy", "download", "--resolve", "--alldeps",
                "--destdir", "/out", *PACKAGES)
            run("docker", "exec", container, "dnf", *ROCKY_REPO_OPTIONS,
                "-qy", "download", "--resolve", "--alldeps",
                "--destdir", "/image", *sorted(IMAGE_PACKAGES))

            def collect(directory: Path, mount: str) -> list[dict]:
                metadata = []
                for rpm in sorted(directory.glob("*.rpm")):
                    query = run("docker", "exec", container, "rpm", "-qp", "--qf",
                                "%{NAME}\n%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}",
                                mount + "/" + rpm.name, capture=True).splitlines()
                    package, nevra = query
                    metadata.append((rpm, package, nevra))
                locations = run("docker", "exec", container, "dnf", *ROCKY_REPO_OPTIONS,
                                "-q", "repoquery", "--location",
                                *(item[2] for item in metadata), capture=True).splitlines()
                urls_by_name = {
                    location.rsplit("/", 1)[-1]: location
                    for location in locations if location.startswith("https://")
                }
                records = []
                for rpm, package, nevra in metadata:
                    url = urls_by_name.get(rpm.name)
                    if url is None:
                        raise RuntimeError(f"expected one HTTPS URL for {nevra}")
                    if package == "rke2-selinux":
                        signer = RANCHER_KEY
                    elif "/epel/10.2/" in url:
                        signer = EPEL_KEY
                    else:
                        signer = ROCKY_KEY
                    records.append({
                        "category": "rpm", "file": rpm.name, "nevra": nevra,
                        "package": package, "sha256": sha256(rpm),
                        "signer_fingerprint": signer["fingerprint"], "url": url,
                    })
                return records

            rpms = collect(output, "/out")
            image_rpms = collect(image_output, "/image")
        finally:
            subprocess.run(["docker", "rm", "--force", container], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    lock["target"] = {"architecture": "amd64", "os": "rocky-10.2"}
    lock["preparer_image"] = ROCKY_IMAGE
    lock["rpm_signing_keys"] = [RANCHER_KEY, ROCKY_KEY, EPEL_KEY]
    lock["rpms"] = rpms
    manifest = json.dumps(manifest_from_lock(lock), sort_keys=True, indent=2) + "\n"
    lock["approved_manifest_sha256"] = hashlib.sha256(manifest.encode()).hexdigest()
    path.write_text(json.dumps(lock, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if image_package_lock is not None:
        write_image_package_lock(lock, path, image_package_lock, image_rpms)
    return {"rpms": len(rpms), "manifest_sha256": lock["approved_manifest_sha256"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--image-package-lock", type=Path)
    parser.add_argument("--project-existing", action="store_true")
    args = parser.parse_args()
    if args.project_existing:
        if args.image_package_lock is None:
            parser.error("--project-existing requires --image-package-lock")
        source = args.lock.resolve()
        write_image_package_lock(
            json.loads(source.read_text(encoding="utf-8")),
            source,
            args.image_package_lock.resolve(),
        )
        print(json.dumps({"projected": str(args.image_package_lock.resolve())}, sort_keys=True))
        return 0
    print(json.dumps(generate(
        args.lock.resolve(),
        args.image_package_lock.resolve() if args.image_package_lock else None,
    ), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
